"""Publish an existing Hecate Setup, with resumable transactions and verified reads.

No Setup/key generation. The fetch path never reads node6's local parameters.
"""
import argparse
import csv
import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys
import time

import solcx
from eth_account import Account
from web3 import Web3
from web3.exceptions import TransactionNotFound
import registry_support as reg

HERE = Path(__file__).resolve().parent
require, read, hx, save_new = reg.require, reg.read, reg.hx, reg.save_new


def sha(data):
    return hashlib.sha256(data).hexdigest()


def core_module(root):
    sys.path.insert(0, str(root / 'init-v1'))
    return importlib.import_module('hecate_core')


def common_height(chains, confirmations):
    height = min(w.eth.block_number for w in chains) - confirmations
    require(height >= 0, 'Wait for more blocks')
    hashes = [hx(w.eth.get_block(height)['hash']) for w in chains]
    require(len(set(hashes)) == 1, 'Nodes disagree at the common height; retry after synchronization')
    return height, hashes[0]


def system_check(chains, system, confirmations):
    height, block_hash = common_height(chains, confirmations)
    for w in chains:
        require(w.eth.chain_id == system['chain_id'], 'Chain ID mismatch')
        require(hx(w.eth.get_block(0)['hash']) == system['genesis_hash'], 'Genesis mismatch')
        address = Web3.to_checksum_address(system['address'])
        code = w.eth.get_code(address, height)
        require(code and hx(Web3.keccak(code)) == system['runtime_code_hash'], 'System registry code mismatch')
        c = w.eth.contract(address=address, abi=system['abi'])
        require(reg.same_config(c.functions.getConfig().call(block_identifier=height), system['config']),
                'System registry configuration mismatch')
    return height, block_hash


def compile_store(binary):
    version = subprocess.check_output([str(binary), '--version'], text=True)
    require('0.8.24+commit.e11b9ed9' in version, 'Expected native solc 0.8.24')
    result = solcx.compile_source((HERE / 'HecatePPKStore.sol').read_text('utf-8'),
                                 output_values=['abi', 'bin'], solc_binary=str(binary),
                                 evm_version='london', optimize=True, optimize_runs=200)
    return result['<stdin>:HecatePPKStore']


def transact(chains, account, operation, journal_dir, action, context, timeout, confirmations):
    """Persist signed bytes BEFORE broadcasting. Resume the identical transaction."""
    w = chains[0]
    path = journal_dir / (action + '.pending.json')
    if path.exists():
        pending = read(path)
        require(pending['context'] == context, 'Journal input mismatch: ' + str(path))
    else:
        price = max(w.eth.gas_price, 2 * w.eth.get_block('latest').get('baseFeePerGas', 0) + 10**9)
        estimate = operation.estimate_gas({'from': account.address, 'gasPrice': price})
        gas = int(estimate * 1.15) + 10000
        require(gas < w.eth.get_block('latest')['gasLimit'],
                'Operation exceeds current block gas limit: ' + action)
        require(w.eth.get_balance(account.address) >= gas * price, 'Insufficient node6 test ETH')
        tx = operation.build_transaction({'from': account.address, 'chainId': w.eth.chain_id,
             'nonce': w.eth.get_transaction_count(account.address, 'pending'), 'gasPrice': price, 'gas': gas})
        signed = account.sign_transaction(tx)
        pending = {'context': context, 'tx_hash': hx(signed.hash),
                   'raw_transaction': hx(signed.raw_transaction), 'first_attempt_unix': time.time(),
                   'gas_limit': gas, 'nonce': tx['nonce'],
                   'input_bytes': len(Web3.to_bytes(hexstr=tx['data'])),
                   'signed_transaction_bytes': len(signed.raw_transaction)}
        save_new(path, pending)
    raw = Web3.to_bytes(hexstr=pending['raw_transaction'])
    require(hx(Web3.keccak(raw)) == pending['tx_hash'], 'Saved transaction hash mismatch')
    require(Account.recover_transaction(raw).lower() == account.address.lower(), 'Saved transaction signer mismatch')
    try:
        w.eth.get_transaction(pending['tx_hash'])
    except TransactionNotFound:
        # If a different transaction consumed this nonce, do not replace/redeploy automatically.
        require(w.eth.get_transaction_count(account.address, 'latest') <= pending['nonce'],
                'Saved nonce was consumed by another transaction; inspect journal before continuing')
        w.eth.send_raw_transaction(raw)
    print(action + ': ' + pending['tx_hash'], flush=True)
    deadline = time.monotonic() + timeout
    while True:
        receipts = []
        try:
            receipts = [node.eth.get_transaction_receipt(pending['tx_hash']) for node in chains]
        except TransactionNotFound:
            pass
        if len(receipts) == len(chains):
            require(all(r['status'] == 1 for r in receipts), 'Transaction reverted: ' + action)
            if min(node.eth.block_number for node in chains) >= max(r['blockNumber'] for r in receipts) + confirmations:
                break
        if time.monotonic() > deadline:
            raise TimeoutError('Receipt wait timed out. Run the same publish command to resume; keep the journals.')
        time.sleep(2)
    require(len({hx(r['blockHash']) for r in receipts}) == 1, 'Receipt block disagreement')
    for node, r in zip(chains, receipts):
        require(node.eth.get_block(r['blockNumber'])['hash'] == r['blockHash'], 'Transaction was reorganized')
    receipt = receipts[0]
    record = {'action': action, 'tx_hash': pending['tx_hash'], 'gas_used': receipt['gasUsed'],
              'block_number': receipt['blockNumber'], 'block_hash': hx(receipt['blockHash']),
              'input_bytes': pending['input_bytes'], 'signed_transaction_bytes': pending['signed_transaction_bytes'],
              'transaction_fee_wei': receipt['gasUsed'] * receipt['effectiveGasPrice'],
              'first_attempt_to_confirmations_s': time.time() - pending['first_attempt_unix']}
    result_path = journal_dir / (action + '.receipt.json')
    if result_path.exists():
        saved = read(result_path)
        require(saved['tx_hash'] == record['tx_hash'] and saved['block_hash'] == record['block_hash'],
                'Saved receipt is no longer canonical; inspect journal')
    else:
        save_new(result_path, record)
    return receipt


def checked_store(w, state, system, height):
    require(state['system_registry'].lower() == system['address'].lower(), 'Wrong parent registry')
    require(state['chain_id'] == system['chain_id'] and state['genesis_hash'] == system['genesis_hash'],
            'Deployment chain identity mismatch')
    address = Web3.to_checksum_address(state['address'])
    code = w.eth.get_code(address, height)
    require(code and hx(Web3.keccak(code)) == state['runtime_code_hash'], 'PPK contract code mismatch')
    c = w.eth.contract(address=address, abi=state['abi'])
    call = lambda f: f.call(block_identifier=height)
    config = system['config']
    require(call(c.functions.systemRegistry()).lower() == system['address'].lower(), 'Parent registry mismatch')
    require(call(c.functions.owner()).lower() == config['owner'].lower(), 'PPK owner mismatch')
    require(hx(call(c.functions.setupId())) == config['setup_id'], 'Setup ID mismatch')
    require(hx(call(c.functions.expectedSrsHash())) == config['srs_sha256'], 'SRS commitment mismatch')
    require(call(c.functions.capacity()) == config['B'], 'Capacity mismatch')
    require(call(c.functions.POINTS_PER_CHUNK()) == 64, 'Unsupported chunk size')
    require(call(c.functions.chunkCount()) == (config['B'] + 63) // 64, 'Chunk count mismatch')
    require(hx(call(c.functions.manifestHash())) == state['manifest_sha256'], 'Manifest hash mismatch')
    return c


def download(w, c, height, core, config):
    """Only chain reads. No local node6/Setup/Pre dependency."""
    call = lambda f: f.call(block_identifier=height)
    require(call(c.functions.finalized()), 'PPK is not finalized; finish publish first')
    manifest_bytes = bytes(call(c.functions.getManifest()))
    require(sha(manifest_bytes) == bytes(call(c.functions.manifestHash())).hex(), 'Manifest bytes mismatch')
    manifest = json.loads(manifest_bytes)
    payload = {k: v for k, v in manifest.items() if k != 'setup_id'}
    calculated = '0x' + sha(core.ser('SETUP-ID', core.canonical(payload)))
    require(calculated == manifest['setup_id'] == config['setup_id'], 'Manifest setup ID mismatch')
    require(manifest['B'] == config['B'] and manifest['receiver_params_id'] == config['receiver_params_id'],
            'Manifest configuration mismatch')
    parts = []
    for i in range((config['B'] + 63) // 64):
        part = bytes(call(c.functions.getG1Chunk(i)))
        require(len(part) == min(64, config['B'] - i * 64) * 48, 'Truncated G1 chunk')
        parts.append(part)
    tau2 = bytes(call(c.functions.getTauG2()))
    require(len(tau2) == 96, 'Truncated tau G2')
    raw = b''.join(parts) + tau2
    require(sha(raw) == manifest['srs_sha256'] == config['srs_sha256'][2:], 'Downloaded SRS hash mismatch')
    return manifest_bytes, raw


def publish(args, root, chains, system):
    config, receiver, setup_dir = reg.local_configuration(root)
    require(config == system['config'], 'Local formal Setup/AKeyGen differs from registered system')
    core = core_module(root)
    manifest, raw = core.load_setup(setup_dir)
    manifest_bytes = (setup_dir / 'manifest.json').read_bytes()
    require(0 < len(manifest_bytes) <= 32768, 'Manifest too large for this contract')
    chunks = [raw[i:min(i+3072, config['B'] * 48)] for i in range(0, config['B'] * 48, 3072)]
    if config['B'] == 4096:
        require(min(w.eth.get_block('latest')['gasLimit'] for w in chains) >= 18000000,
                'B=4096 finalization needs an 18,000,000 block gas budget including margin. '
                'Stop here and inspect the current block gas limit; do not reset genesis.')
    print('Existing Setup:', config['setup_id'], '\nB:', config['B'],
          '\nSRS bytes:', len(raw), '\nManifest bytes:', len(manifest_bytes),
          '\nG1 chunks:', len(chunks), '\nTau G2 bytes: 96', flush=True)
    if args.command == 'preflight':
        print('Preflight passed. No transactions sent. publish also verifies every SRS point before writing.')
        return
    print('Checking SRS points and power relations; B=4096 may take several minutes...', flush=True)
    core.verify_setup(setup_dir)
    state_path = root / 'deployment/ppk_registry.json'
    journal_dir = root / 'deployment/ppk_upload' / config['setup_id'][2:]
    context = {'system_registry': system['address'], 'setup_id': config['setup_id'],
               'srs_sha256': config['srs_sha256'], 'manifest_sha256': '0x' + sha(manifest_bytes),
               'chain_id': system['chain_id'], 'genesis_hash': system['genesis_hash'],
               'source_sha256': reg.digest(HERE / 'HecatePPKStore.sol')}
    account = reg.ethereum_account(root, config['owner'])
    w = chains[0]
    with reg.deployment_lock(root / 'deployment/ppk_upload.lock'):
        if state_path.exists():
            state = read(state_path)
            require(state['context'] == context, 'Existing PPK deployment belongs to different inputs')
        else:
            build_path = journal_dir / 'build.json'
            if build_path.exists():
                build = read(build_path)
                require(build['context'] == context, 'Build inputs changed')
            else:
                build = {'context': context, 'artifact': compile_store(Path(args.solc))}
                save_new(build_path, build)
            artifact = build['artifact']
            operation = w.eth.contract(abi=artifact['abi'], bytecode=artifact['bin']).constructor(
                Web3.to_checksum_address(system['address']), manifest_bytes, raw[-96:])
            receipt = transact(chains, account, operation, journal_dir, 'deploy', context, args.timeout, args.confirmations)
            address = receipt['contractAddress']
            require(address is not None, 'Missing PPK deployment address')
            state = dict(context, context=context, address=address, abi=artifact['abi'],
                         runtime_code_hash=hx(Web3.keccak(w.eth.get_code(address))),
                         deployment_tx=hx(receipt['transactionHash']), compiler='0.8.24', evm_version='london')
            save_new(state_path, state)
        height, _ = system_check(chains, system, args.confirmations)
        contracts = [checked_store(node, state, system, height) for node in chains]
        c = contracts[0]
        for i, chunk in enumerate(chunks):
            action = 'chunk-%04d' % i
            expected = hashlib.sha256(chunk).digest()
            observed = bytes(c.functions.chunkHash(i).call())
            require(observed in (bytes(32), expected), 'Conflicting existing chunk: ' + str(i))
            # Reconcile existing signed transaction even if its content is already visible.
            if observed == bytes(32) or (journal_dir / (action + '.pending.json')).exists():
                transact(chains, account, c.functions.uploadChunk(i, chunk), journal_dir, action,
                         dict(context, address=state['address'], action=action, chunk_sha256=expected.hex()),
                         args.timeout, args.confirmations)
            else:
                print(action + ': identical content already present', flush=True)
        if not c.functions.finalized().call() or (journal_dir / 'finalize.pending.json').exists():
            transact(chains, account, c.functions.finalize(), journal_dir, 'finalize',
                     dict(context, address=state['address'], action='finalize'), args.timeout, args.confirmations)
        check(args, root, chains, system)
        receipts = [read(p) for p in sorted(journal_dir.glob('*.receipt.json'))]
        summary = {'contract': state['address'], 'setup_id': config['setup_id'], 'B': config['B'],
                   'srs_bytes': len(raw), 'manifest_bytes': len(manifest_bytes),
                   'public_payload_bytes': len(raw) + len(manifest_bytes),
                   'recorded_transactions': len(receipts), 'expected_fresh_transactions': len(chunks) + 2,
                   'complete_transaction_measurement': len(receipts) == len(chunks) + 2,
                   'total_gas_used': sum(r['gas_used'] for r in receipts),
                   'total_input_bytes': sum(r['input_bytes'] for r in receipts),
                   'total_signed_transaction_bytes': sum(r['signed_transaction_bytes'] for r in receipts),
                   'total_transaction_fee_wei': sum(r['transaction_fee_wei'] for r in receipts),
                   'note': 'Payload and transaction sizes exclude RPC/TCP/P2P overhead; latency includes confirmation waits and interruptions.'}
        metrics = journal_dir / 'summary.json'
        if not metrics.exists():
            save_new(metrics, summary)
        csv_path = journal_dir / 'transactions.csv'
        if not csv_path.exists() and receipts:
            with csv_path.open('x', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=list(receipts[0]))
                writer.writeheader()
                writer.writerows(receipts)
        print('Publication complete. Metrics:', metrics, flush=True)


def check(args, root, chains, system):
    state = read(root / 'deployment/ppk_registry.json')
    core = core_module(root)
    height, block_hash = system_check(chains, system, args.confirmations)
    first = None
    for port, w in zip(reg.PORTS, chains):
        c = checked_store(w, state, system, height)
        result = download(w, c, height, core, system['config'])
        if first is None:
            first = result
        require(result == first, 'Nodes returned different PPK bytes')
        print('RPC %d: finalized; SRS=%d bytes; SHA256=%s' % (port, len(result[1]), sha(result[1])), flush=True)
    print('All three nodes agree at block %d (%s)' % (height, block_hash))
    require(all(hx(w.eth.get_block(height)['hash']) == block_hash for w in chains),
            'Pinned block changed during download; retry check')


def fetch(args, root, chains, system):
    out = Path(args.out).resolve()
    # Existing files are never silently replaced or assumed trustworthy.
    require(not out.exists(), 'Output already exists. Choose a new cache directory; do not overwrite existing Setup.')
    state = read(root / 'deployment/ppk_registry.json')
    core = core_module(root)
    height, block_hash = system_check(chains, system, args.confirmations)
    w = chains[reg.PORTS.index(args.rpc_port)]
    c = checked_store(w, state, system, height)
    start = time.perf_counter()
    manifest_bytes, raw = download(w, c, height, core, system['config'])
    download_s = time.perf_counter() - start
    out.mkdir(parents=True, exist_ok=False)
    (out / 'manifest.json').write_bytes(manifest_bytes)
    (out / 'srs.bin').write_bytes(raw)
    print('Downloaded from chain. Verifying curve/subgroup/power relations; please wait...', flush=True)
    start = time.perf_counter()
    core.verify_setup(out)
    verify_s = time.perf_counter() - start
    # Recheck the pinned block after potentially long cryptographic verification.
    require(hx(w.eth.get_block(height)['hash']) == block_hash, 'Pinned block was reorganized; cache is not verified')
    save_new(out / 'CHAIN_VERIFIED.json', {'setup_id': system['config']['setup_id'], 'contract': state['address'],
        'system_registry': system['address'], 'chain_id': system['chain_id'], 'genesis_hash': system['genesis_hash'],
        'block_number': height, 'block_hash': block_hash, 'rpc_port': args.rpc_port,
        'srs_sha256': sha(raw), 'srs_bytes': len(raw), 'manifest_bytes': len(manifest_bytes),
        'download_wall_s': download_s, 'cryptographic_verification_wall_s': verify_s})
    print('Verified chain cache:', out, '\nTau G2 bytes:', len(raw[-96:]), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['preflight', 'publish', 'check', 'fetch'])
    parser.add_argument('--root', default='/home/Hecate_2/hecate-app')
    parser.add_argument('--solc', default='/home/Hecate_2/hecate-app/tools/solc-0.8.24')
    parser.add_argument('--confirmations', type=int, default=2)
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--rpc-port', type=int, choices=reg.PORTS, default=18545)
    parser.add_argument('--out')
    args = parser.parse_args()
    require(args.confirmations >= 0 and args.timeout > 0, 'Invalid confirmation/timeout value')
    require(args.command != 'fetch' or args.out, 'fetch requires --out')
    root = Path(args.root).resolve()
    system = read(root / 'deployment/system_registry.json')
    chains = reg.clients()
    system_check(chains, system, args.confirmations)
    if args.command in ('preflight', 'publish'):
        publish(args, root, chains, system)
    elif args.command == 'check':
        check(args, root, chains, system)
    else:
        fetch(args, root, chains, system)


if __name__ == '__main__':
    main()
