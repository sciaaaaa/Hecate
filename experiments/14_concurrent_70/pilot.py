"""AWS pilot adapter. Existing cryptographic implementations and contracts are reused.

RPC uses the private network. File delivery and RD lookup use new SSH sessions;
their timers are end-to-end request/acknowledgment times, NOT one-way latency.
"""
import argparse
from parallel import run_parallel
import contextlib
import csv
import hashlib
import importlib
import json
import os
from pathlib import Path
import random
import re
import shlex
import sqlite3
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace as NS


def need(ok, message):
    if not ok:
        raise ValueError(message)


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()


def read(path):
    return json.loads(Path(path).read_text('utf-8-sig'))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def ms(start):
    return (time.perf_counter_ns() - start) / 1e6


def save_bytes(path, data):
    """Immutable content, atomic final publication. Never overwrite a different run."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        need(path.read_bytes() == data, 'Existing output differs: ' + str(path))
        return
    fd, tmp = tempfile.mkstemp(prefix='.pilot-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        # link publishes without replacing a concurrently-created destination.
        try:
            os.link(tmp, path)
        except FileExistsError:
            need(path.read_bytes() == data, 'Concurrent output differs')
    finally:
        os.unlink(tmp)


def save(path, obj):
    save_bytes(path, canonical(obj))


class Pilot:
    def __init__(self, config):
        self.config_path = Path(config).resolve()
        self.c = read(config)
        self.root = Path(self.c['root']).resolve()
        self.label = self.c['experiment']
        need(re.fullmatch(r'[A-Za-z0-9_-]{1,40}', self.label), 'Invalid experiment label')
        self.work = self.root / 'private/aws-concurrent' / self.label
        self.script = self.root / 'aws-concurrent-v8/pilot.py'
        self.n = len(self.c['receivers']) * self.c['records_per_receiver']
        self.r = len(self.c['receivers'])
        self.s = self.r * self.c['authorized_per_receiver']
        need((self.n, self.r, self.s) == (70, 35, 35) and
             self.c['records_per_receiver'] == 2 and self.c['authorized_per_receiver'] == 1,
             'This package validates 70/35/35; do not change counts without a tested driver')
        need(len(set(self.c['receivers'])) == self.r and
             all(re.fullmatch(r'[A-Za-z0-9_-]{1,32}', x) for x in self.c['receivers']), 'Receiver labels')
        os.environ['HECATE_RPC_HOST'] = self.c['rpc_host']
        self.work.mkdir(parents=True, exist_ok=True, mode=0o700)
        save(self.work / 'spec.json', self.c)

    def role(self, role):
        # Prevent accidentally running a business phase on a full backup of another host.
        import socket
        expected = self.c['hosts'][role]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((self.c['rpc_host'], 18545))
            actual = s.getsockname()[0]
        need(actual == expected, f'Run this phase on {role} ({expected}), detected {actual}')

    def modules(self):
        sys.path[:0] = [str(self.root / d) for d in
                       ('adec-v1', 'authorization-v2', 'aenc-chain-v1', 'batch-v1', 'ppk-v1')]
        return importlib.import_module('aenc_chain'), importlib.import_module('authorize'), importlib.import_module('adec')

    def args(self, **kw):
        values = dict(root=str(self.root), batch=self.label,
                      confirmations=self.c['confirmations'], timeout=self.c['timeout'])
        values.update(kw)
        return NS(**values)

    def call(self, file, *args):
        cmd = [self.c['python'], '-u', str(self.root / file), *map(str, args)]
        print('RUN', shlex.join(cmd), flush=True)
        start = time.perf_counter_ns()
        result = subprocess.run(cmd)
        with (self.work / 'commands.jsonl').open('a', encoding='utf-8') as f:
            f.write(json.dumps({'command': cmd, 'wall_ms': ms(start), 'returncode': result.returncode}) + '\n')
        need(result.returncode == 0, 'Command failed; preserve journals and do not change the experiment label to hide partial results')

    def ssh(self, role, action, data=None, extra=()):
        remote = [self.c['python'], str(self.script), '--config', str(self.config_path), action, *extra]
        cmd = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'ConnectTimeout=10', '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
               '-o', 'IdentitiesOnly=yes', '-i', self.c['ssh_key'],
               self.c['ssh_user'] + '@' + self.c['hosts'][role], shlex.join(remote)]
        start = time.perf_counter_ns()
        result = subprocess.run(cmd, input=data, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=self.c['timeout'])
        elapsed = ms(start)
        need(result.returncode == 0, 'Remote helper failed: ' + result.stderr.decode(errors='replace')[-3000:])
        return result.stdout, elapsed

    def push(self, role, name, data):
        result, elapsed = self.ssh(role, 'receive', data,
                                   ('--name', name, '--spec-hash', sha(canonical(self.c))))
        ack = json.loads(result)
        need(ack['sha256'] == sha(data) and ack['bytes'] == len(data), 'Remote acknowledgment mismatch')
        return dict(transfer_roundtrip_ms=elapsed, payload_bytes=len(data),
                    remote_store_ms=ack['store_ms'], sha256=ack['sha256'],
                    note='New SSH connection + authentication + remote Python startup + transfer + durable file write + hash acknowledgment; not pure network latency or cryptographic acceptance')

    def snapshot(self):
        return read(self.work / 'batch.json')

    def receiver_manifest(self):
        return read(self.work / 'receivers.json')

    def run_name(self, name):
        return self.label + '-' + name

    def receivers(self):
        self.role('node5')
        app, az, ad = self.modules()
        pp = importlib.import_module('publish_ppk')
        hb = importlib.import_module('hecate_batch')
        system, ppk, chains, height, bh = hb.environment(self.args(), self.root, pp)
        rr = read(self.root / 'deployment/receiver_registry.json')
        need(rr['address'].lower() == system['config']['receiver_registry'].lower(), 'Receiver registry mismatch')
        rows = []
        for name in self.c['receivers']:
            path = self.root / 'private/node5' / name / 'secret.json'
            need(path.is_file(), 'Missing existing receiver secret: ' + str(path))
            secret = read(path)
            need(secret['receiver_name'] == name and secret['params_id'] == system['config']['receiver_params_id'], 'Receiver secret profile mismatch')
            observations = []
            for w in chains:
                need(pp.hx(w.keccak(w.eth.get_code(rr['address'], height))) == rr['runtime_code_hash'], 'Receiver runtime mismatch')
                contract = w.eth.contract(address=rr['address'], abi=rr['abi'])
                need(pp.hx(contract.functions.paramsId().call(block_identifier=height)) == system['config']['receiver_params_id'], 'Receiver params mismatch')
                rid = bytes(contract.functions.receiverId(w.to_checksum_address(secret['owner_eth_address']), name).call(block_identifier=height))
                owner, pk = contract.functions.getReceiver(rid).call(block_identifier=height)
                observations.append((rid.hex(), owner.lower(), bytes(pk).hex()))
            need(all(x == observations[0] for x in observations), 'Receiver RPC disagreement')
            rid, owner, pk = observations[0]
            need(owner == secret['owner_eth_address'].lower(), f'{name} not registered to expected owner')
            ad.load_secret(path, 'secret_scalar_hex', 'hex', app.core, bytes.fromhex(pk))
            rows.append(dict(name=name, receiver_id=rid, receiver_public_key_hex=pk))
            del secret
        need(len({x['receiver_id'] for x in rows}) == self.r and len({x['receiver_public_key_hex'] for x in rows}) == self.r, 'Receivers must be independent')
        need(all(pp.hx(w.eth.get_block(height)['hash']) == bh for w in chains), 'Pinned block changed')
        doc = {'spec_hash': sha(canonical(self.c)), 'receivers': rows}
        save(self.work / 'receivers.json', doc)
        for role in ('node4', 'node6'):
            self.push(role, 'receivers.json', canonical(doc))
        print('All thirty-five existing receiver keys match chain. Public receiver manifest delivered; no secret transferred.')

    def batch(self):
        self.role('node6')
        self.receiver_manifest()
        self.call('batch-v1/hecate_batch.py', 'preflight', '--root', self.root)
        self.call('batch-v1/hecate_batch.py', 'generate', '--root', self.root,
                  '--batch', self.label, '--planned-records', self.n)
        self.call('batch-v1/hecate_batch.py', 'publish', '--root', self.root,
                  '--batch', self.label, '--timeout', self.c['timeout'],
                  '--confirmations', self.c['confirmations'])
        app, az, ad = self.modules()
        _, e, d, stores = az.environment(self.args())
        az.auth_stores(app, e, d)  # Must reuse compatible v2 deployment; never silently redeploy.
        for row in self.receiver_manifest()['receivers']:
            need(az.receiver_info(app, e, row['receiver_id'])['receiver_public_key_hex'] == row['receiver_public_key_hex'], 'Receiver changed')
        doc = {'spec_hash': sha(canonical(self.c)), 't': e.batch['t'],
               'setup_id': e.system['config']['setup_id'], 'key_id': e.system['config']['key_id'],
               'store': d['address'], 'chain_id': e.system['chain_id'], 'genesis_hash': e.system['genesis_hash']}
        save(self.work / 'batch.json', doc)
        for role in ('node4', 'node5'):
            self.push(role, 'batch.json', canonical(doc))
        pre = self.root / 'private/node6/alliance-v1/repository.sqlite'
        subset = self.work / 'input-rd.sqlite'
        if not subset.exists():
            with contextlib.closing(sqlite3.connect(pre.resolve().as_uri() + '?mode=ro', uri=True)) as db:
                ids = [bytes(x[0]) for x in db.execute('SELECT idx FROM records ORDER BY idx')]
                need(len(ids) >= self.n, 'Insufficient RD records')
                chosen = random.Random(self.c['seed']).sample(ids, self.n)
                fd, tmp = tempfile.mkstemp(dir=self.work)
                os.close(fd)
                try:
                    with contextlib.closing(sqlite3.connect(tmp)) as dest, dest:
                        dest.execute('CREATE TABLE records (idx BLOB PRIMARY KEY, content BLOB NOT NULL)')
                        for idx in chosen:
                            rd = bytes(db.execute('SELECT content FROM records WHERE idx=?', (idx,)).fetchone()[0])
                            need(app.core.enc_g2(app.core.multiply(app.core.G2, app.core.h_id(app.core.ser('RD', rd)))) == idx, 'RD repository index mismatch')
                            dest.execute('INSERT INTO records VALUES (?,?)', (idx, rd))
                    save_bytes(subset, Path(tmp).read_bytes())
                finally:
                    os.unlink(tmp)
        self.push('node4', 'input-rd.sqlite', subset.read_bytes())
        print('New batch published; only selected RD input fixture delivered to node4. Setup/AKeyGen reused.')

    def aenc_args(self, receiver, i):
        return ['--root', self.root, '--batch', self.label, '--round', self.label,
                '--run', self.run_name(receiver['name']), '--receiver-id', '0x' + receiver['receiver_id'],
                '--start', i * 2 + 1, '--count', 2, '--timeout', self.c['timeout'],
                '--confirmations', self.c['confirmations']]

    def prepare(self):
        self.role('node4')
        snap = self.snapshot()
        app, az, ad = self.modules()
        pool = self.root / 'private/node4/senders-round01'
        # Validate identities, then reserve fresh alpha per sender. Existing reservation resumes.
        app.keys.check_base(pool, self.n)
        fixture = self.random_inputs()
        app.keys.reserve_round(pool, self.n, self.label)
        records = []
        for i, receiver in enumerate(self.receiver_manifest()['receivers']):
            args = self.aenc_args(receiver, i)
            args += ['--im-source', fixture/receiver['name'], '--pre', self.work / 'input-rd.sqlite', '--seed', self.c['seed'] + i,
                     '--min-im-bytes', self.c['min_im_bytes'], '--max-im-bytes', self.c['max_im_bytes'], '--em', self.c['em']]
            if self.c['im_with_replacement']:
                args += ['--im-with-replacement']
            self.call('aenc-chain-v1/aenc_chain.py', 'prepare', *args)
            folder = self.root / 'private/node4/aenc-runs' / self.run_name(receiver['name'])
            ready = read(folder / 'READY.json')
            need(ready['batch'] == snap['t'], 'Batch mismatch')
            plan = {x['sender']: x for x in read(folder / 'plan-private.json')}
            for j, row in enumerate(ready['records']):
                p = plan[row['sender']]
                records.append(dict(row, run=self.run_name(receiver['name']), receiver=receiver['name'],
                                    receiver_id=receiver['receiver_id'], authorized=j < 1,
                                    im_sha256=p['im_sha256'], rd_sha256=p['rd_sha256']))
            # READY has no secret fields; authorization v2 consumes it at this legacy path.
            self.push('node6', 'ready-' + receiver['name'] + '.json', canonical(ready))
        need(len(records) == self.n and len({r['id'] for r in records}) == self.n and
             len({r['address'].lower() for r in records}) == self.n and len({r['pk_ds_hex'] for r in records}) == self.n, 'Expected 70 independent records')
        need(len({r['im_sha256'] for r in records})==self.n,'Expected seventy distinct saved random im files')
        catalog = {'spec_hash': sha(canonical(self.c)), 'batch': snap['t'], 'records': records}
        save(self.work / 'catalog.json', catalog)
        for role in ('node5', 'node6'):
            self.push(role, 'catalog.json', canonical(catalog))
        print('Exactly 70 saved ciphertexts; hashes only exported as correctness references. No extra warmup aEnc.')

    def fund(self, amount):
        self.role('node6')
        need(amount is not None, 'fund requires --amount-eth (test ETH to each of 70 senders)')
        from web3 import Web3
        app, az, ad = self.modules()
        _, e, d, _ = az.environment(self.args())
        value = Web3.to_wei(amount, 'ether')
        need(value > 0, 'Positive funding required')
        signer = e.pp.reg.ethereum_account(self.root, e.system['config']['owner'])
        w = e.chains[0]
        for row in read(self.work / 'catalog.json')['records']:
            addr = row['address']
            class Transfer:
                def estimate_gas(self, params):
                    return w.eth.estimate_gas(dict(params, to=addr, value=value))
                def build_transaction(self, params):
                    return dict(params, to=addr, value=value, data='0x')
            e.pp.transact(e.chains, signer, Transfer(), self.work / 'funding', row['sender'],
                          {'to': addr, 'value': str(value), 'batch': e.batch['t']}, self.c['timeout'], self.c['confirmations'])

    def upload(self):
        self.role('node4')
        report_path = self.work/'node4-report.json'
        if report_path.exists():
            for role in ('node5','node6'):
                self.push(role, report_path.name, report_path.read_bytes())
            return
        catalog = read(self.work/'catalog.json')['records']
        app, _, _ = self.modules()
        pool = self.root/'private/node4/senders-round01'
        resumed = any((self.root/'private/node4/aenc-runs'/r['run']/'transactions'/r['sender']).exists() for r in catalog)
        def job(row):
            command = [self.c['python'], '-u', str(self.script), '--config', str(self.config_path),
                       'upload-one', '--name', row['sender']]
            logs = self.work/'upload-logs'
            logs.mkdir(exist_ok=True)
            path = logs/(row['sender']+'-'+str(time.time_ns())+'.log')
            with path.open('wb') as log:
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
            print(row['sender'], 'upload child exit', result.returncode, 'log:', path, flush=True)
            need(result.returncode == 0, 'Upload child failed: '+str(path))
            return row['sender']
        # Protect against simultaneous legacy prepare/upload commands for this pool.
        pp = importlib.import_module('publish_ppk')
        with pp.reg.deployment_lock(pool/'.aenc.lock'):
            _, parallel = run_parallel(self.work, 'cipher_upload', catalog, job,
                lambda row:row['sender'], lambda row:row['wire_bytes'], resumed=resumed)
        verify_start = time.perf_counter_ns()
        for i, receiver in enumerate(self.receiver_manifest()['receivers']):
            self.call('aenc-chain-v1/aenc_chain.py', 'check', *self.aenc_args(receiver, i))
        verification_ms = ms(verify_start)
        rows = []
        for row in read(self.work / 'catalog.json')['records']:
            folder = self.root / 'private/node4/aenc-runs' / row['run']
            receipts = [read(p) for p in sorted((folder / 'transactions' / row['sender']).glob('*.receipt.json'))]
            need(len(receipts) == row['chunks'] + 2, 'Missing transaction receipts')
            rows.append(dict(sender=row['sender'], id=row['id'], receiver=row['receiver'],
                             encryption=read(folder / 'metrics' / (row['sender'] + '.json')), receipts=receipts))
        report = {'records': rows, 'verified': True, 'batch': self.snapshot()['t'],
                  'parallel': parallel, 'upload_readback_verify_ms': verification_ms,
                  'phase_attempts':self.phase_history()}
        save(self.work / 'node4-report.json', report)
        for role in ('node5', 'node6'):
            self.push(role, 'node4-report.json', canonical(report))

    def authorize(self):
        self.role('node6')
        need(read(self.work / 'node4-report.json')['verified'], 'Complete upload/check first')
        rows = read(self.work / 'catalog.json')['records']
        selection = [{'run': r['run'], 'sender': r['sender']} for r in rows if r['authorized']]
        need(len(selection) == self.s, 'Global S must contain 35 records')
        save(self.work / 'selection.json', selection)
        for action in ('preflight', 'digest', 'publish', 'check-digest', 'compute-key'):
            if action == 'publish':
                self.auth_gas()
            if action == 'compute-key':
                self.timed_compute_key()
                continue
            self.call('authorization-v2/authorize.py', action, '--root', self.root,
                      '--batch', self.label, '--selection', self.work / 'selection.json',
                      '--timeout', self.c['timeout'], '--confirmations', self.c['confirmations'])
        t = self.snapshot()['t'][2:]
        folder = self.root / 'private/node6/authorizations' / t
        measured = self.work/'delivery-complete.json'
        if measured.exists():
            delivery = read(measured)
            deliveries, parallel = delivery['deliveries'], delivery['parallel']
        else:
            def deliver(receiver):
                name = receiver['name']
                envelope = folder/'recipients'/receiver['receiver_id']/'capability-envelope.json'
                return dict(receiver=name, **self.push('node5','envelope-'+name+'.json',envelope.read_bytes()))
            recipients = self.receiver_manifest()['receivers']
            deliveries, parallel = run_parallel(self.work, 'capability_delivery', recipients, deliver,
                lambda r:r['name'], lambda r:(folder/'recipients'/r['receiver_id']/'capability-envelope.json').stat().st_size)
            save(measured, dict(deliveries=deliveries, parallel=parallel))
        save(self.work / 'node6-report.json', dict(batch=self.snapshot()['t'],
             digest=read(folder / 'digest_metrics.json'), computekey=read(folder / 'computekey_metrics.json'),
             publication=read(folder / 'publication/publish.receipt.json'), deliveries=deliveries, parallel=parallel,
             key_stage=read(self.work/'key-stage.json')))
        print('One global capability pair, separately encrypted for thirty-five receivers; all byte/hash delivery acknowledgments received.')

    def fetch_record(self, app, e, d, stores, row):
        start = time.perf_counter_ns()
        raw = lambda x: bytes.fromhex(x.removeprefix('0x'))
        key = e.chains[0].keccak(raw(row['address']) + raw(e.batch['t']) + raw(row['id']))
        meta = [c.functions.get(key).call(block_identifier=e.height) for c in stores]
        need(all(x == meta[0] for x in meta), 'Record metadata disagrees')
        r = meta[0]
        need(r[9] and r[0].lower() == row['address'].lower() and bytes(r[1]) == raw(e.batch['t']) and
             bytes(r[2]).hex() == row['id'] and bytes(r[3]).hex() == row['receiver_id'] and
             bytes(r[4]).hex() == row['pk_ds_hex'], 'Cipher metadata binding')
        need(r[5] == row['wire_bytes'] and r[6] == row['chunks'] and 0 < r[5] <= 64*1024*1024, 'Cipher length')
        payloads = [b''.join(bytes(c.functions.getChunk(key, i).call(block_identifier=e.height)) for i in range(r[6])) for c in stores]
        need(all(x == payloads[0] for x in payloads), 'Cipher bytes disagree')
        data = payloads[0]
        need(len(data) == r[5] and sha(data) == row['sha256'] and app.commitment(data) == bytes(r[7]) == bytes(r[8]), 'Cipher integrity')
        tx = json.loads(data)
        need(tx['pk_ds_hex'] == row['pk_ds_hex'] and tx['id_hex'] == row['id'], 'Cipher body mismatch')
        return tx, ms(start)

    def receive_all(self):
        self.role('node5')
        app, az, ad = self.modules()
        dc = importlib.import_module('adec_crypto')
        need(read(self.work / 'node4-report.json')['verified'], 'No verified upload')
        result = self.work / 'node5-report.json'
        if result.exists():
            self.push('node6', result.name, result.read_bytes())
            print('Existing completed measurements redelivered; no repeated decryption.')
            return
        catalog = read(self.work / 'catalog.json')
        records, receivers, requests = [], [], []
        receiver_started_unix = time.time()
        decrypt_start = time.perf_counter_ns()
        # A failed attempt is kept. Choose a new local attempt directory, never erase it.
        attempt = self.work / ('receiver-attempt-' + str(time.time_ns()))
        for receiver in self.receiver_manifest()['receivers']:
            name, rid = receiver['name'], receiver['receiver_id']
            receiver_start = time.perf_counter_ns()
            out = attempt / name
            a = self.args(receiver_id='0x'+rid, receiver_name=name,
                          secret_file=str(self.root/'private/node5'/name/'secret.json'),
                          secret_field='secret_scalar_hex', secret_encoding='hex',
                          envelope=str(self.work/('envelope-'+name+'.json')))
            # Existing receiver code authenticates grant, capability, receiver secret, and SRS.
            app, e, ac, intent, cap, srs, cached, pkdr, secret, bootstrap = ad.acquire(a, out)
            expected = {r['id'] for r in catalog['records'] if r['authorized']}
            need(set(intent['ids']) == expected, 'Actual global S differs from pilot selection')
            need(e.batch['t'] == self.snapshot()['t'], 'Batch changed')
            auth, shared = dc.verify_shared(app.core, app.bc, ac, e.context, e.system['config'], self.label, e.batch, intent, cap, srs)
            d, stores = app.store(e)
            receiver_rows = [r for r in catalog['records'] if r['receiver'] == name]
            need(len(receiver_rows) == 2, 'Receiver must have two records')
            for row in receiver_rows:
                tx, fetch_ms = self.fetch_record(app, e, d, stores, row)
                save(out/'all-assigned-ciphertexts'/(row['id']+'.json'), tx)
                binding = dict(app.bindings(e, d, row['address']), receiver_id=rid)
                # verify_record combines membership and signature checks. For integrity-only
                # validation of nonmembers, pass a temporary allowed-ID list, never to decrypt.
                checkset = dict(auth, ids=auth['ids'] + ([int(row['id'],16)] if int(row['id'],16) not in auth['ids'] else []))
                checked, verify_ms = dc.verify_record(app.core, app.engine, e.batch, tx, binding, pkdr, secret, checkset)
                metric = dict(sender=row['sender'], receiver=name, id=row['id'], authorized=row['authorized'],
                              chain_fetch_validate_ms=fetch_ms, signature_context_verify_ms=verify_ms)
                start = time.perf_counter_ns()
                member = int(row['id'],16) in auth['ids']
                metric['membership_check_ms'] = ms(start)
                need(member == row['authorized'], 'Unexpected authorization result')
                if not member:
                    # Also verify the production rejection path. No attempted decryption/RD lookup.
                    try:
                        dc.verify_record(app.core, app.engine, e.batch, tx, binding, pkdr, secret, auth)
                    except ValueError as exc:
                        need(str(exc) == 'Not authorized by finalized S', 'Unexpected rejection reason')
                    else:
                        raise ValueError('Nonmember accepted')
                    metric['status'] = 'rejected_not_in_S'
                else:
                    im, theta, overt_ms = dc.open_overt(app.core, app.engine, ac, checked, auth, srs)
                    em, index, hidden_ms = dc.open_hidden(app.core, app.engine, checked, auth, theta)
                    start = time.perf_counter_ns()
                    need(sha(im) == row['im_sha256'] and em == self.c['em'].encode().ljust(16,b'\0'), 'Recovered im/em differs')
                    metric.update(overt_decrypt_ms=overt_ms, hidden_incremental_ms=hidden_ms,
                                  im_em_reference_check_ms=ms(start), im_bytes=len(im))
                    save_bytes(out/'recovered'/row['id']/'im.bin', im)
                    save(out/'recovered'/row['id']/'hidden.json', {'em_hex':em.hex(),'ind_star_hex':index.hex()})
                    requests.append(dict(row=row, index=index, out=out, metric=metric,
                        payload=canonical(dict(spec_hash=sha(canonical(self.c)), id=row['id'], receiver_id=rid, index=index.hex()))))
                    metric['status'] = 'authorized_decrypted_pending_rd'
                records.append(metric)
            need(all(e.pp.hx(w.eth.get_block(e.height)['hash']) == e.bh for w in e.chains), 'Pinned block changed')
            own = [r for r in records if r['receiver'] == name]
            totals = dict(receiver_crypto_phase_wall_ms=ms(receiver_start),
                          verification_total_ms=shared['shared_verify_ms'] + sum(r['signature_context_verify_ms']+r['membership_check_ms'] for r in own),
                          overt_total_ms=sum(r.get('overt_decrypt_ms',0) for r in own),
                          hidden_increment_total_ms=sum(r.get('hidden_incremental_ms',0) for r in own),
                          rd_request_total_ms=sum(r.get('rd_request_roundtrip_ms',0) for r in own),
                          rd_verify_total_ms=sum(r.get('rd_verify_ms',0) for r in own))
            receivers.append(dict(receiver=name, bootstrap=bootstrap, shared=shared, totals=totals))
            del secret, cap
        decrypt_wall_ms = ms(decrypt_start)
        need(len(requests) == self.s, 'Expected thirty-five authorized RD requests')
        def query(item):
            response, elapsed = self.ssh('node6','rd-query',item['payload'])
            return response, elapsed
        replies, parallel = run_parallel(self.work, 'rd_query', requests, query,
            lambda x:x['row']['sender'], lambda x:len(x['payload']))
        verify_start = time.perf_counter_ns()
        response_bytes = 0
        for item, (response, elapsed) in zip(requests, replies):
            header_bytes, rd = response.split(b'\n',1)
            header = json.loads(header_bytes)
            start = time.perf_counter_ns()
            need(header['bytes'] == len(rd) and header['sha256'] == sha(rd), 'RD transfer integrity')
            actual_index = app.core.enc_g2(app.core.multiply(app.core.G2, app.core.h_id(app.core.ser('RD',rd))))
            need(actual_index == item['index'] and sha(rd) == item['row']['rd_sha256'], 'RD verification failed')
            item['metric'].update(rd_request_roundtrip_ms=elapsed,rd_server_lookup_ms=header['lookup_ms'],
                rd_verify_ms=ms(start),rd_bytes=len(rd),rd_request_bytes=len(item['payload']),
                rd_response_bytes=len(response),status='authorized_recovered_rd_verified')
            save_bytes(item['out']/'recovered'/item['row']['id']/'rd.bin',rd)
            response_bytes += len(response)
        rd_verify_wall_ms = ms(verify_start)
        parallel['summary']['response_bytes'] = response_bytes
        parallel['summary']['response_goodput_bytes_per_s'] = response_bytes / (parallel['summary']['makespan_ms']/1000)
        for receiver in receivers:
            own = [r for r in records if r['receiver'] == receiver['receiver']]
            receiver['totals']['rd_request_total_ms'] = sum(r.get('rd_request_roundtrip_ms',0) for r in own)
            receiver['totals']['rd_verify_total_ms'] = sum(r.get('rd_verify_ms',0) for r in own)
        need(sum(r['status']=='authorized_recovered_rd_verified' for r in records) == self.s and
             sum(r['status']=='rejected_not_in_S' for r in records) == self.n-self.s, 'Incomplete receiver checks')
        report = {'batch':self.snapshot()['t'],'records':records,'receivers':receivers,'complete':True, 'parallel':parallel,
                  'decrypt_phase_wall_ms':decrypt_wall_ms,'rd_verify_phase_wall_ms':rd_verify_wall_ms,
                  'receiver_started_unix':receiver_started_unix,'receiver_ended_unix':time.time(),
                  'phase_attempts':self.phase_history(),
                  'note':'Nonmember rejection is an application authorization test, not a cryptographic impossibility proof. SSH RD access authenticates the experiment host, not an individual receiver account.'}
        save(result, report)
        self.push('node6', result.name, result.read_bytes())
        print('70 ciphertexts checked; 35 authorized im/em/index recovered and original RD queried/verified; 35 nonmembers rejected.')

    def rd_query(self, request=None):
        self.role('node6')
        req = json.loads(sys.stdin.buffer.read(8192)) if request is None else request
        need(req['spec_hash'] == sha(canonical(self.c)), 'Different experiment configuration')
        index = bytes.fromhex(req['index'])
        need(len(index) == 96, 'Invalid index length')
        match = [r for r in read(self.work/'catalog.json')['records'] if r['id']==req['id'] and r['receiver_id']==req['receiver_id'] and r['authorized']]
        need(len(match) == 1 and (self.work/'node6-report.json').exists(), 'RD query outside completed pilot authorization')
        pre = self.root/'private/node6/alliance-v1/repository.sqlite'
        start = time.perf_counter_ns()
        with contextlib.closing(sqlite3.connect(pre.resolve().as_uri()+'?mode=ro', uri=True)) as con:
            row = con.execute('SELECT content FROM records WHERE idx=?', (index,)).fetchone()
        lookup_ms = ms(start)
        need(row is not None, 'Recovered index not found in original RD repository')
        data = bytes(row[0])
        need(sha(data) == match[0]['rd_sha256'], 'Wrong RD for this pilot record')
        response = canonical(dict(bytes=len(data),sha256=sha(data),lookup_ms=lookup_ms)) + b'\n' + data
        if request is not None:
            return response
        sys.stdout.buffer.write(response)

    def receive(self, name, spec_hash):
        need(spec_hash == sha(canonical(self.c)), 'Remote pilot.json differs; distribute identical config first')
        common = {'receivers.json':('node4','node6'), 'batch.json':('node4','node5'),
                  'input-rd.sqlite':('node4',), 'catalog.json':('node5','node6'),
                  'node4-report.json':('node5','node6'), 'node5-report.json':('node6',)}
        for r in self.c['receivers']:
            common['ready-'+r+'.json'] = ('node6',)
            common['envelope-'+r+'.json'] = ('node5',)
        need(name in common, 'Transfer name not allowed')
        matched = False
        for role in common[name]:
            try:
                self.role(role)
                matched = True
                break
            except ValueError:
                pass
        need(matched, 'Wrong destination host')
        data = sys.stdin.buffer.read(256*1024*1024+1)
        need(len(data) <= 256*1024*1024, 'Transfer too large')
        start = time.perf_counter_ns()
        save_bytes(self.work/name, data)
        if name.startswith('ready-'):
            recipient = name[len('ready-'):-len('.json')]
            save_bytes(self.root/'private/node4/aenc-runs'/self.run_name(recipient)/'READY.json', data)
        print(json.dumps({'sha256':sha(data),'bytes':len(data),'store_ms':ms(start)}))

    def collect(self):
        self.role('node6')
        completed = self.work/'SUCCESS.json'
        if completed.exists():
            result = read(completed)
            need(result['batch']==self.snapshot()['t'] and
                 result['csv_sha256']==sha((self.work/'all_metrics.csv').read_bytes()),'Completed CSV changed')
            print('Existing COMPLETE:',self.work/'all_metrics.csv')
            return
        catalog = read(self.work/'catalog.json')['records']
        r4 = read(self.work/'node4-report.json')
        r5 = read(self.work/'node5-report.json')
        r6 = read(self.work/'node6-report.json')
        need(r4['verified'] and r5['complete'] and r4['batch']==r5['batch']==r6['batch']==self.snapshot()['t'], 'Incomplete/mixed reports')
        need({r['id'] for r in r4['records']} == {r['id'] for r in r5['records']} == {r['id'] for r in catalog}, 'Record report mismatch')
        rows = []
        def emit(scope, entity, metric, value, unit='', **extra):
            rows.append(dict(experiment=self.label,batch=self.snapshot()['t'],scope=scope,entity=entity,
                             metric=metric,value=value,unit=unit,**extra))
        def fields(scope, entity, values, **extra):
            for k,v in values.items():
                if isinstance(v,(int,float)) and not isinstance(v,bool):
                    unit = 'tx/s' if k=='confirmed_transactions_per_s' else 'records/s' if k=='records_per_s' else 'tasks/s' if k.endswith('_tasks_per_s') else 'bytes/s' if k.endswith('_bytes_per_s') else 'ms' if k.endswith('_ms') else 's' if k.endswith('_s') else 'wei' if k.endswith('_wei') else 'bytes' if k.endswith('_bytes') else ''
                    emit(scope,entity,k,v,unit,**extra)
        all_tx = []
        for r in r4['records']:
            extra = dict(sender=r['sender'],receiver=r['receiver'],id=r['id'])
            fields('aenc',r['sender'],r['encryption'],**extra)
            for tx in r['receipts']:
                fields('cipher_transaction',r['sender']+'/'+tx['action'],tx,tx_hash=tx['tx_hash'],**extra)
                need(tx['gas_used'] > 0 and tx['transaction_fee_wei'] % tx['gas_used'] == 0, 'Invalid fee/gas receipt')
                fields('cipher_transaction',r['sender']+'/'+tx['action'],
                       {'effective_gas_price_wei':tx['transaction_fee_wei']//tx['gas_used']},tx_hash=tx['tx_hash'],**extra)
                all_tx.append(tx)
            for key in ('gas_used','transaction_fee_wei','input_bytes','signed_transaction_bytes','first_attempt_to_confirmations_s'):
                fields('cipher_sender_total',r['sender'],{key:sum(t[key] for t in r['receipts'])},**extra)
        for r in r5['records']:
            fields('receiver_record',r['sender'],r,sender=r['sender'],receiver=r['receiver'],id=r['id'])
            emit('receiver_record',r['sender'],'status',r['status'],sender=r['sender'],receiver=r['receiver'],id=r['id'])
        for r in r5['receivers']:
            fields('receiver_bootstrap',r['receiver'],r['bootstrap'],receiver=r['receiver'])
            fields('receiver_shared_verify',r['receiver'],r['shared'],receiver=r['receiver'])
            fields('receiver_totals',r['receiver'],r['totals'],receiver=r['receiver'])
        fields('digest','global',r6['digest'])
        fields('computekey','global',r6['computekey'])
        fields('digest_transaction','global',r6['publication'],tx_hash=r6['publication']['tx_hash'])
        for delivery in r6['deliveries']:
            fields('capability_delivery',delivery['receiver'],delivery,receiver=delivery['receiver'])
        t = self.snapshot()['t'][2:]
        fields('batchgen','global',read(self.root/'public/batches'/t/'metrics.json'))
        batch_tx = read(self.root/'deployment/batch_upload'/t/'publish.receipt.json')
        fields('batch_transaction','global',batch_tx,tx_hash=batch_tx['tx_hash'])
        for p in sorted((self.work/'funding').glob('*.receipt.json')):
            tx=read(p)
            fields('funding_excluded',p.stem,tx,tx_hash=tx['tx_hash'])
        for key in ('gas_used','transaction_fee_wei','input_bytes','signed_transaction_bytes'):
            fields('experiment_chain_total','global',{key:sum(t[key] for t in all_tx+[batch_tx,r6['publication']])})
        emit('experiment','global','aenc_count',self.n,'count')
        emit('experiment','global','authorized_count',self.s,'count')
        emit('experiment','global','receiver_count',self.r,'count')
        fields('experiment_compute_total','global',{
            'aenc_wall_ms':sum(r['encryption']['aenc_wall_ms'] for r in r4['records']),
            'aenc_compute_wall_ms':sum(r['encryption']['compute_wall_ms'] for r in r4['records']),
            'verification_total_ms':sum(r['totals']['verification_total_ms'] for r in r5['receivers']),
            'overt_total_ms':sum(r['totals']['overt_total_ms'] for r in r5['receivers']),
            'hidden_increment_total_ms':sum(r['totals']['hidden_increment_total_ms'] for r in r5['receivers']),
            'capability_delivery_total_ms':sum(r['transfer_roundtrip_ms'] for r in r6['deliveries']),
            'rd_request_total_ms':sum(r['totals']['rd_request_total_ms'] for r in r5['receivers']),
            'rd_verify_total_ms':sum(r['totals']['rd_verify_total_ms'] for r in r5['receivers'])})
        for scope, report in [('cipher_upload',r4),('capability_delivery',r6),('rd_query',r5)]:
            parallel = report['parallel']
            fields(scope+'_batch','global',parallel['summary'])
            emit(scope+'_batch','global','resumed',parallel['resumed'])
            for task in parallel['tasks']:
                fields(scope+'_task',task['entity'],task)
                emit(scope+'_task',task['entity'],'status',task['status'])
        fields('receiver_phases','global',{k:v for k,v in r5.items() if k.endswith('_ms')})
        if 'key_stage' in r6:
            fields('key_stage','global',r6['key_stage'])
            emit('key_stage','global','capability_reused',r6['key_stage']['capability_reused'])
            for envelope in r6['key_stage']['envelopes']:
                fields('envelope_seal',envelope['receiver_id'],envelope)
        chain_seconds = r4['parallel']['summary']['makespan_ms']/1000
        fields('cipher_upload_batch','global',{
            'confirmed_transactions_per_s':len(all_tx)/chain_seconds,
            'calldata_bytes_per_s':sum(t['input_bytes'] for t in all_tx)/chain_seconds,
            'signed_transaction_bytes_per_s':sum(t['signed_transaction_bytes'] for t in all_tx)/chain_seconds})
        fields('upload_readback','global',{'wall_ms':r4['upload_readback_verify_ms']})
        crypto_ms = sum(r['encryption']['aenc_wall_ms'] for r in r4['records'])
        fields('aenc_batch','global',{'algorithm_total_ms':crypto_ms,'records_per_s':self.n/(crypto_ms/1000)})
        for host, attempts in [('node4',r4.get('phase_attempts',[])),('node5',r5.get('phase_attempts',[])),('node6',self.phase_history())]:
            for index, attempt in enumerate(attempts):
                entity = host+'/'+attempt['phase']+'/'+str(index+1)
                fields('phase_attempt',entity,attempt)
                emit('phase_attempt',entity,'status',attempt['status'])
                if host=='node4' and attempt['phase']=='prepare' and attempt['status']=='success':
                    fields('prepare_attempt',entity,{'records_per_s':self.n/(attempt['wall_ms']/1000)})
        gas_path = self.work/'authorization-gas.json'
        if gas_path.exists():
            fields('authorization_gas_preflight','global',read(gas_path))
        emit('experiment','global','im_input_bytes',32768,'bytes')
        import io
        buf=io.StringIO(newline='')
        writer=csv.DictWriter(buf,['experiment','batch','scope','entity','sender','receiver','id','tx_hash','metric','value','unit'])
        writer.writeheader()
        writer.writerows(rows)
        save_bytes(self.work/'all_metrics.csv',buf.getvalue().encode('utf-8-sig'))
        save(self.work/'SUCCESS.json',{'batch':self.snapshot()['t'],'records':self.n,'authorized':self.s,'receivers':self.r,'csv_sha256':sha((self.work/'all_metrics.csv').read_bytes()),
            'fresh_parallel_measurements':not any(r['parallel']['resumed'] for r in (r4,r5,r6)),
            'note':'Correctness success. Inspect phase_attempt rows and key_stage reuse flag before treating this as a fresh performance trial.'})
        print('COMPLETE:',self.work/'all_metrics.csv')

    def random_inputs(self):
        """Persist two independent random inputs per receiver before reserving alpha."""
        fixture = self.work/'random-im'
        manifest_path = fixture/'manifest.json'
        if manifest_path.exists():
            manifest = read(manifest_path)
            need(manifest['spec_hash']==sha(canonical(self.c)),'Input manifest config mismatch')
            for row in manifest['files']:
                path = fixture/row['path']
                need(path.is_file() and path.stat().st_size==32768 and
                     sha(path.read_bytes())==row['sha256'],'Saved random input missing or changed: '+str(path))
            need(len(manifest['files'])==self.n,'Random input count mismatch')
            return fixture
        need(not any((self.root/'private/node4/aenc-runs'/self.run_name(name)/'run-private.json').exists()
                     for name in self.c['receivers']), 'Input manifest missing after preparation started; stop and inspect')
        files=[]
        for name in self.c['receivers']:
            for index in range(2):
                path=fixture/name/(str(index+1)+'.bin')
                if not path.exists():
                    save_bytes(path,os.urandom(32768))
                need(path.stat().st_size==32768,'Incomplete random input')
                files.append({'path':path.relative_to(fixture).as_posix(),'sha256':sha(path.read_bytes()),'bytes':32768})
        need(len({row['sha256'] for row in files})==self.n,'Duplicate random inputs')
        save(manifest_path,{'spec_hash':sha(canonical(self.c)),'files':files})
        return fixture

    def phase_history(self):
        return [read(p) for p in sorted(self.work.glob('phase-attempt-*.json')) if read(p)['phase']!='collect']

    def upload_one(self, name):
        self.role('node4')
        rows = [r for r in read(self.work/'catalog.json')['records'] if r['sender']==name]
        need(len(rows)==1, 'Unknown or duplicate sender')
        row = rows[0]
        app, _, _ = self.modules()
        args = self.args(receiver_id='0x'+row['receiver_id'])
        e = app.env(args)
        pool = self.root/'private/node4/senders-round01'
        folder = self.root/'private/node4/aenc-runs'/row['run']
        original_read = app.read
        def filtered(path):
            doc = original_read(path)
            if Path(path).resolve() == (folder/'READY.json').resolve():
                selected = [r for r in doc['records'] if r['sender']==name]
                need(len(selected)==1 and selected[0]['id']==row['id'], 'Worker selection mismatch')
                return dict(doc,records=selected)
            return doc
        with e.pp.reg.deployment_lock(folder/('upload-'+name+'.lock')):
            app.read = filtered
            try:
                app.upload(args,e,pool,folder)
            finally:
                app.read = original_read

    def timed_compute_key(self):
        path = self.work/'key-stage.json'
        app, az, _ = self.modules()
        args = self.args(selection=str(self.work/'selection.json'))
        app,e,d,stores = az.environment(args)
        if path.exists():
            az.compute_key(args,app,e,d,stores)
            return
        original = az.ac.seal
        envelopes = []
        reused = (az.paths(e)/'capability-private.json').exists()
        def measured(core,binding,*rest,**kw):
            start = time.perf_counter_ns()
            result = original(core,binding,*rest,**kw)
            envelopes.append(dict(receiver_id=binding['receiver_id'],seal_wall_ms=ms(start),
                                  serialized_bytes=len(canonical(result))))
            return result
        start = time.perf_counter_ns()
        az.ac.seal = measured
        try:
            az.compute_key(args,app,e,d,stores)
        finally:
            az.ac.seal = original
        save(path,dict(compute_key_command_wall_ms=ms(start),capability_reused=reused,
                       envelopes=envelopes,seal_wall_total_ms=sum(x['seal_wall_ms'] for x in envelopes)))

    def doctor(self):
        checks = read(Path(__file__).with_name('dependencies.json'))
        for relative, expected in checks.items():
            path = self.root/relative
            need(path.is_file() and sha(path.read_bytes())==expected,
                 'Dependency differs from tested source: '+str(path)+'; do not overwrite it, inspect the difference.')
        import requests
        from web3 import Web3
        from web3.middleware import ExtraDataToPOAMiddleware
        for port in (18545,18546,18547):
            session = requests.Session()
            session.trust_env = False
            w = Web3(Web3.HTTPProvider('http://'+self.c['rpc_host']+':'+str(port),session=session,request_kwargs={'timeout':10}))
            w.middleware_onion.inject(ExtraDataToPOAMiddleware,layer=0)
            need(w.is_connected() and w.eth.chain_id==20261005,'RPC unavailable or wrong chain: '+str(port))
            print('RPC',port,'block',w.eth.block_number,flush=True)
        role = None
        for candidate in self.c['hosts']:
            try:
                self.role(candidate)
                role = candidate
                break
            except ValueError:
                pass
        need(role is not None,'Unrecognized business host')
        destinations = {'node4':['node5','node6'],'node5':['node4','node6'],'node6':['node4','node5']}[role]
        for target in destinations:
            data,_ = self.ssh(target,'hello')
            need(json.loads(data)['spec_hash']==sha(canonical(self.c)),'Remote config differs')
            print('SSH helper/config verified:',role,'->',target,flush=True)
        print('Doctor passed: source versions, RPC and SSH helpers. No transaction sent.')

    def auth_gas(self):
        self.role('node6')
        app, az, _ = self.modules()
        app,e,d,stores = az.environment(self.args())
        auth, contracts = az.auth_stores(app,e,d)
        intent = az.load_intent(app,e,d,auth)
        if contracts[0].functions.get(az.ac.raw(e.batch['t'])).call()[0]:
            az.verify_grant(app,e,d)
            print('Authorization already published; preserving original gas preflight.')
            return
        signer = e.pp.reg.ethereum_account(self.root,e.system['config']['owner'])
        w = e.chains[0]
        price = max(w.eth.gas_price,2*w.eth.get_block('latest').get('baseFeePerGas',0)+10**9)
        op = contracts[0].functions.publish(az.ac.raw(e.batch['t']),intent['senders'],
            [az.ac.raw(i) for i in intent['ids']],az.ac.raw(intent['digest_hex']))
        try:
            estimate = op.estimate_gas({'from':signer.address,'gasPrice':price})
        except Exception as exc:
            save(self.work/('gas-estimation-failure-'+str(time.time_ns())+'.json'),
                 {'error':str(exc),'note':'Estimation failure may be a contract revert, balance or RPC issue; it does not prove a gas-limit violation.'})
            raise
        budget = int(estimate*1.15)+10000
        limit = min(w.eth.get_block('latest')['gasLimit'] for w in e.chains)
        report = dict(estimated_gas=estimate,budget_gas=budget,block_gas_limit=limit,
                      budget_fraction=budget/limit,authorized_count=len(intent['ids']))
        save(self.work/('gas-preflight-'+str(time.time_ns())+'.json'),report)
        print('Authorization gas:',report,flush=True)
        need(budget < limit,'Authorization budget exceeds block gas limit; stop. Existing contract cannot automatically split this immutable grant.')
        if budget/limit >= .8:
            print('WARNING: authorization gas budget is at least 80% of block limit.',flush=True)
        path = self.work/'authorization-gas.json'
        if not path.exists():
            save(path,report)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',default=str(Path(__file__).with_name('pilot.json')))
    parser.add_argument('command',choices=['doctor','hello','receivers','batch','prepare','fund','upload','upload-one','auth-gas','authorize','receive-all','collect','receive','rd-query'])
    parser.add_argument('--amount-eth')
    parser.add_argument('--name')
    parser.add_argument('--spec-hash')
    args=parser.parse_args()
    p=Pilot(args.config)
    if args.command=='hello':
        print(json.dumps({'spec_hash':sha(canonical(p.c))}))
    elif args.command=='receive':
        p.receive(args.name,args.spec_hash)
    elif args.command=='upload-one':
        p.upload_one(args.name)
    elif args.command=='rd-query':
        p.rd_query()
    else:
        import fcntl
        with (p.work/'phase.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            start = time.perf_counter_ns()
            record = {'phase':args.command,'status':'failed','started_unix':time.time()}
            try:
                if args.command=='fund':p.fund(args.amount_eth)
                else:getattr(p,args.command.replace('-','_'))()
                record['status'] = 'success'
            finally:
                record['wall_ms'] = ms(start)
                record['ended_unix'] = time.time()
                save(p.work/('phase-attempt-'+str(time.time_ns())+'.json'),record)


if __name__=='__main__':
    main()

