"""CLI: versioned offline Setup, AKeyGen, datasets, isolated benchmark trials."""
import argparse
import csv
import hashlib
import json
import math
import os
import random
import sqlite3
import statistics
import subprocess
import sys
import time
from pathlib import Path

from hecate_core import (
    PROFILE, canonical, ser, write_bytes, write_json, read_receiver_binding,
    make_setup, save_setup, load_setup, verify_setup, make_alliance,
    validate_alliance, build_repository, environment, stamp, elapsed, owner_address,
)

DEFAULT_B = [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096]
BENCH_OWNER = '0x0000000000000000000000000000000000000001'


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError('Must be positive')
    return number


def nonnegative(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError('Must be nonnegative')
    return number


def create_dataset(args):
    destination = Path(args.out)
    destination.mkdir(parents=True, exist_ok=False)
    entries = []
    for i in range(args.count):
        # Reproducible public test data ONLY. Never used as cryptographic entropy.
        prefix = b'HECATE-RD-V1\x00' + i.to_bytes(8, 'big')
        if args.size < len(prefix):
            raise ValueError('Synthetic record size must be at least 21 bytes')
        body = hashlib.shake_256(ser('SYNTHETIC-RD', args.seed.encode(), i.to_bytes(8, 'big'))).digest(args.size - len(prefix))
        content = prefix + body
        name = 'record-%06d.bin' % i
        write_bytes(destination / name, content, private=True)
        entries.append({'file': name, 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()})
    write_json(destination / 'dataset.json', {'format': 'hecate-rd-v1', 'source': 'synthetic',
               'seed': args.seed, 'record_bytes': args.size, 'records': entries}, private=True)
    print('Dataset:', destination.resolve(), flush=True)


def import_dataset(args):
    source = Path(args.source).resolve()
    destination = Path(args.out).resolve()
    if not source.is_dir() or destination == source or destination.is_relative_to(source):
        raise ValueError('Output must be a new directory outside the source tree')
    candidates = sorted(p for p in source.rglob('*') if p.is_file() and not p.is_symlink())
    candidates = [p for p in candidates if args.min_bytes <= p.stat().st_size <= args.max_bytes]
    random.Random(args.seed).shuffle(candidates)
    if args.count > len(candidates):
        raise ValueError('Fewer eligible files than --count')
    destination.mkdir(parents=True, exist_ok=False)
    entries = []
    for i, path in enumerate(candidates[:args.count]):
        content = path.read_bytes()
        name = 'record-%06d.bin' % i
        write_bytes(destination / name, content, private=True)
        entries.append({'file': name, 'source_relative_path': path.relative_to(source).as_posix(),
                        'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()})
    write_json(destination / 'dataset.json', {'format': 'hecate-rd-v1', 'source': args.label,
               'sampling_seed': args.seed, 'records': entries}, private=True)
    print('Dataset imported:', destination, flush=True)


def setup_command(args):
    receiver_id = read_receiver_binding(args.receiver_params)
    manifest, raw, metrics = make_setup(args.B, receiver_id)
    location, disk = save_setup(args.out, manifest, raw)
    metrics['persist_wall_ms'] = disk['wall_ms']
    write_json(location / 'metrics.json', metrics)
    print('setup_id:', manifest['setup_id'])
    print('Setup directory:', location.resolve())
    print('Run verify-setup on this directory before creating an operational alliance.')


def akeygen_command(args):
    manifest = verify_setup(args.setup)
    if manifest['receiver_params_id'] is None:
        raise ValueError('Operational AKeyGen requires Setup bound to existing receiver parameters')
    if args.owner:
        owner = owner_address(args.owner)
    else:
        accounts = json.loads(Path(args.accounts).read_text('utf-8'))
        owner = owner_address(accounts['node6'])
    destination = Path(args.out)
    destination.mkdir(parents=True, mode=0o700, exist_ok=False)
    public, private, metrics = make_alliance(manifest['setup_id'], owner)
    validate_alliance(public, private)
    write_json(destination / 'public.json', public)
    write_json(destination / 'secret.json', private, private=True)
    metrics.update(build_repository(args.dataset, destination / 'repository.sqlite'))
    metrics['akeygen_compute_wall_ms'] = (metrics['keygen_wall_ms'] + metrics['hash_wall_ms'] + metrics['g2_wall_ms'])
    metrics['akeygen_key_and_repository_wall_ms'] = metrics['keygen_wall_ms'] + metrics['repository_wall_ms']
    write_json(destination / 'metrics.json', metrics, private=True)
    # A missing READY file means incomplete output; do not use a partially built repository.
    write_json(destination / 'READY.json', {'key_id': public['key_id'], 'setup_id': public['setup_id']}, private=True)
    print('AKeyGen complete:', public['key_id'])
    print('Private state:', destination.resolve())
    print('public.json is ready for future authenticated registration; no chain transaction was sent.')


def peak_rss():
    if sys.platform.startswith('linux'):
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    return None


def trial(args):
    jobfile = Path(args.job)
    job = json.loads(jobfile.read_text('utf-8'))
    # Warm crypto libraries outside the measured operation, including native EC startup.
    from hecate_core import G1, G2, multiply, sig_public
    multiply(G1, 1234567)
    multiply(G2, 1234567)
    sig_public(1234567)
    meta = {'case': job['case'], 'repeat': job['repeat'], 'kind': job['kind'],
            'profile': PROFILE, 'process_startup_included': False}
    if job['kind'] == 'setup':
        manifest, raw, metrics = make_setup(job['B'], job['receiver_params_id'])
        # Benchmark outputs are not saved as operational setup versions.
        metrics.update({'setup_id': manifest['setup_id'], 'status': 'ok'})
    else:
        # B does not enter AKeyGen mathematics. A fixed benchmark-only ID avoids
        # repeating Setup and avoids accidentally registering experimental keys.
        public, private, metrics = make_alliance('0x' + '00' * 32, BENCH_OWNER)
        database = jobfile.parent / (jobfile.stem + '.sqlite')
        try:
            metrics.update(build_repository(job['dataset'], database))
            if metrics['dataset_manifest_sha256'] != job['dataset_manifest_sha256']:
                raise ValueError('Dataset manifest changed after experiment plan was created')
            metrics['akeygen_compute_wall_ms'] = (metrics['keygen_wall_ms'] + metrics['hash_wall_ms'] + metrics['g2_wall_ms'])
            metrics['akeygen_key_and_repository_wall_ms'] = metrics['keygen_wall_ms'] + metrics['repository_wall_ms']
            # Verification outside measured computation and repository times.
            validate_alliance(public, private)
            metrics['status'] = 'ok'
        finally:
            # Only this trial's explicitly created database; never touch source data.
            if database.exists():
                database.unlink()
            journal = Path(str(database) + '-journal')
            if journal.exists():
                journal.unlink()
        del private
    metrics['peak_process_rss_bytes'] = peak_rss()
    write_json(jobfile.with_suffix('.result.json'), dict(meta, **metrics))


def append_csv(path, row, columns):
    first = not path.exists()
    with path.open('a', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction='raise')
        if first:
            writer.writeheader()
        writer.writerow(row)
        handle.flush()
        os.fsync(handle.fileno())


def t975(df):
    # Student-t two-sided 95% critical values (conservative lookup for unlisted df).
    values = {1:12.706, 2:4.303, 3:3.182, 4:2.776, 5:2.571, 6:2.447,
              7:2.365, 8:2.306, 9:2.262, 10:2.228, 11:2.201, 12:2.179,
              13:2.160, 14:2.145, 15:2.132, 16:2.120, 17:2.110, 18:2.101,
              19:2.093, 20:2.086, 21:2.080, 22:2.074, 23:2.069, 24:2.064,
              25:2.060, 26:2.056, 27:2.052, 28:2.048, 29:2.045, 30:2.043,
              40:2.022, 60:2.000, 120:1.980}
    return values[max(k for k in values if k <= df)]


def summarize(csvpath):
    csvpath = Path(csvpath)
    with csvpath.open(encoding='utf-8', newline='') as handle:
        rows = list(csv.DictReader(handle))
    output = []
    for case in sorted({r['case'] for r in rows}):
        group = [r for r in rows if r['case'] == case]
        for field in group[0]:
            if not field.endswith(('_ms', '_bytes', '_count')) and field != 'B':
                continue
            data = [float(r[field]) for r in group if r[field] not in ('', None)]
            if not data:
                continue
            mean = statistics.mean(data)
            sd = statistics.stdev(data) if len(data) > 1 else None
            half = t975(len(data)-1) * sd / math.sqrt(len(data)) if sd is not None else None
            output.append({'case': case, 'metric': field, 'runs': len(data), 'mean': mean,
                           'stddev': sd, 'median': statistics.median(data), 'min': min(data),
                           'max': max(data), 'mean_ci95_low': mean-half if half is not None else None,
                           'mean_ci95_high': mean+half if half is not None else None})
    destination = csvpath.with_name('summary.csv')
    with destination.open('w', encoding='utf-8', newline='') as handle:
        if output:
            writer = csv.DictWriter(handle, fieldnames=list(output[0]))
            writer.writeheader()
            writer.writerows(output)
    print('Summary:', destination.resolve(), flush=True)


def bench(args):
    destination = Path(args.out)
    destination.mkdir(parents=True, exist_ok=False)
    workers = destination / 'trials'
    workers.mkdir()
    meta = environment()
    meta.update({'repeats': args.repeats, 'warmups_per_case': args.warmups,
                 'shuffle_seed': args.seed, 'cache_policy': 'OS caches uncontrolled; no cold-cache claim',
                 'network_measurement': 'payload byte counts only, no network traffic or gas measured'})
    write_json(destination / 'environment.json', meta)
    if args.command == 'bench-setup':
        binding = read_receiver_binding(args.receiver_params)
        cases = [{'kind': 'setup', 'case': 'B=%d' % value, 'B': value,
                  'receiver_params_id': binding} for value in args.values]
    else:
        cases = []
        for dataset in args.datasets:
            path = Path(dataset).resolve()
            doc = json.loads((path / 'dataset.json').read_text('utf-8'))
            cases.append({'kind': 'akeygen', 'case': path.name, 'dataset': str(path),
                          'dataset_manifest_sha256': hashlib.sha256(canonical(doc)).hexdigest()})
    if len({c['case'] for c in cases}) != len(cases):
        raise ValueError('Duplicate case names')
    jobs = []
    rng = random.Random(args.seed)
    for r in range(-args.warmups, args.repeats):
        order = list(cases)
        rng.shuffle(order)
        jobs.extend(dict(c, repeat=r) for c in order)
    write_json(destination / 'plan.json', jobs)
    columns = None
    for i, job in enumerate(jobs):
        print('[%d/%d] %s repeat=%d%s' % (i+1, len(jobs), job['case'], job['repeat'],
              ' (warmup excluded)' if job['repeat'] < 0 else ''), flush=True)
        jobfile = workers / ('%05d.job.json' % i)
        write_json(jobfile, job)
        completed = subprocess.run([sys.executable, str(Path(__file__).resolve()), '_trial', '--job', str(jobfile.resolve())],
                                   capture_output=True, text=True)
        write_bytes(workers / ('%05d.log' % i), (completed.stdout + completed.stderr).encode('utf-8'))
        if completed.returncode:
            raise RuntimeError('Trial failed; completed raw rows preserved. See ' + str(workers / ('%05d.log' % i)))
        row = json.loads(jobfile.with_suffix('.result.json').read_text('utf-8'))
        if job['repeat'] >= 0:
            if columns is None:
                columns = sorted(row)
            append_csv(destination / 'raw.csv', row, columns)
    summarize(destination / 'raw.csv')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('dataset', help='Create reproducible synthetic records outside timed region')
    p.add_argument('--count', type=nonnegative, required=True)
    p.add_argument('--size', type=positive, required=True, help='Bytes per record')
    p.add_argument('--seed', default='hecate-rd-2026-v1')
    p.add_argument('--out', required=True)
    p.set_defaults(func=create_dataset)
    p = sub.add_parser('import-rd', help='Copy a deterministic sample of real files without parsing them')
    p.add_argument('--source', required=True)
    p.add_argument('--out', required=True)
    p.add_argument('--label', required=True)
    p.add_argument('--count', type=positive, required=True)
    p.add_argument('--min-bytes', type=int, default=1)
    p.add_argument('--max-bytes', type=positive, default=16*1024*1024)
    p.add_argument('--seed', type=int, default=2026)
    p.set_defaults(func=import_dataset)
    p = sub.add_parser('setup')
    p.add_argument('--B', type=positive, required=True)
    p.add_argument('--receiver-params', required=True)
    p.add_argument('--out', required=True, help='Parent directory; content-derived setup ID appended')
    p.set_defaults(func=setup_command)
    p = sub.add_parser('verify-setup')
    p.add_argument('--setup', required=True)
    p.set_defaults(func=lambda args: print('Verified:', verify_setup(args.setup)['setup_id']))
    p = sub.add_parser('akeygen')
    p.add_argument('--setup', required=True)
    p.add_argument('--dataset', required=True)
    p.add_argument('--out', required=True, help='New private directory, never overwritten')
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--owner')
    group.add_argument('--accounts', help='Existing blockchain-geth/accounts.json; reads node6 public address only')
    p.set_defaults(func=akeygen_command)
    for name in ['bench-setup', 'bench-akeygen']:
        p = sub.add_parser(name)
        p.add_argument('--out', required=True)
        p.add_argument('--repeats', type=positive, default=10)
        p.add_argument('--warmups', type=int, default=1)
        p.add_argument('--seed', type=int, default=2026)
        if name == 'bench-setup':
            p.add_argument('--values', type=positive, nargs='+', default=DEFAULT_B)
            p.add_argument('--receiver-params')
        else:
            p.add_argument('--datasets', nargs='+', required=True)
        p.set_defaults(func=bench)
    p = sub.add_parser('summarize')
    p.add_argument('--csv', required=True)
    p.set_defaults(func=lambda args: summarize(args.csv))
    p = sub.add_parser('_trial', help=argparse.SUPPRESS)
    p.add_argument('--job', required=True)
    p.set_defaults(func=trial)
    args = parser.parse_args()
    if hasattr(args, 'warmups') and args.warmups < 0:
        parser.error('--warmups must be nonnegative')
    args.func(args)


if __name__ == '__main__':
    main()
