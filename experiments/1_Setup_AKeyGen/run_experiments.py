"""Generate the controlled RD workloads, then run a chosen experiment group."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SIZES = [256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216]
COUNTS = [0, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096]


def run(*parts):
    subprocess.run([sys.executable, str(ROOT / 'hecate_init.py'), *map(str, parts)], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('group', choices=['prepare', 'setup', 'rd-count', 'rd-size', 'rd-total'])
    parser.add_argument('--data-root', default=str(ROOT / 'datasets'))
    parser.add_argument('--out', help='New results directory, required except for prepare')
    parser.add_argument('--repeats', type=int, default=10)
    parser.add_argument('--warmups', type=int, default=1)
    parser.add_argument('--receiver-params')
    args = parser.parse_args()
    data = Path(args.data_root).resolve()
    groups = {
        'rd-count': [(n, 4096) for n in COUNTS],
        'rd-size': [(32, size) for size in SIZES],
        'rd-total': [(n, 64*1024*1024//n) for n in [8, 32, 128, 512, 2048, 4096]],
    }
    def location(n, size):
        return data / ('N%d_L%d' % (n, size))
    if args.group == 'prepare':
        conditions = sorted(set(sum(groups.values(), [])))
        for n, size in conditions:
            path = location(n, size)
            if path.exists():
                manifest = json.loads((path / 'dataset.json').read_text('utf-8'))
                if (manifest.get('source') != 'synthetic' or manifest.get('seed') != 'hecate-rd-2026-v1'
                        or len(manifest['records']) != n or manifest.get('record_bytes') != size):
                    raise ValueError('Existing dataset conflicts: ' + str(path))
                print('Reuse:', path, flush=True)
            else:
                run('dataset', '--count', n, '--size', size, '--out', path)
        return
    if not args.out:
        parser.error('--out is required for experiments')
    options = ['--out', args.out, '--repeats', args.repeats, '--warmups', args.warmups]
    if args.group == 'setup':
        if args.receiver_params:
            options += ['--receiver-params', args.receiver_params]
        run('bench-setup', *options)
    else:
        paths = [location(n, size) for n, size in groups[args.group]]
        if not all((p / 'dataset.json').exists() for p in paths):
            parser.error('Run prepare first')
        run('bench-akeygen', '--datasets', *paths, *options)


if __name__ == '__main__':
    main()
