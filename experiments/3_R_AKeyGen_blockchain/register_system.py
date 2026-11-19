"""Register existing Hecate public configuration. Never generate Hecate secrets.

Uses the existing local solc 0.8.24, targeting London for Geth 1.13.15.
Commands: preflight (read-only), deploy (one transaction), check (read-only).
"""
import argparse
from contextlib import contextmanager
import hashlib
import importlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

import requests
import solcx
from eth_account import Account
from web3 import Web3
from web3.exceptions import TransactionNotFound, TimeExhausted
from web3.middleware import ExtraDataToPOAMiddleware

PORTS = [18545, 18546, 18547]
PARAM_ABI = [{"inputs": [], "name": "paramsId", "outputs": [{"type": "bytes32"}],
              "stateMutability": "view", "type": "function"}]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def hx(value):
    return Web3.to_hex(value)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save_new(path, document):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write complete bytes, then publish without overwriting an existing record.
    tmp = path.with_name(path.name + '.tmp-' + str(os.getpid()))
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(document, handle, sort_keys=True, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.link(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


@contextmanager
def deployment_lock(path):
    # Target is Ubuntu. Kernel releases the lock if the process exits/crashes.
    import fcntl
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError('Another registration process is running') from error
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def local_configuration(root):
    sys.path.insert(0, str(root / 'init-v1'))
    core = importlib.import_module('hecate_core')
    alliance = root / 'private/node6/alliance-v1'
    ready = read(alliance / 'READY.json')
    public = read(alliance / 'public.json')
    setup_id = ready['setup_id']
    require(len(setup_id) == 66 and setup_id.startswith('0x'), 'Invalid setup ID')
    int(setup_id[2:], 16)  # Must be a hex identifier, never a filesystem path.
    setup_dir = root / 'public/setups' / setup_id[2:]
    manifest, raw = core.load_setup(setup_dir)
    require(manifest['setup_id'] == setup_id == public['setup_id'], 'Setup binding mismatch')
    require(ready['key_id'] == public['key_id'], 'READY/public key ID mismatch')
    payload = {k: v for k, v in public.items() if k != 'key_id'}
    expected = '0x' + hashlib.sha256(core.ser('ALLIANCE-ID', core.canonical(payload))).hexdigest()
    require(expected == public['key_id'], 'Alliance public record hash mismatch')
    require(public['format'] == 'hecate-alliance-v1' and public['profile'] == core.PROFILE,
            'Unexpected alliance profile')
    # Read actual nested receiver profile; do not rely on the earlier flat-format reader.
    receiver_params = read(root / 'config/receiver_params.json')
    body = receiver_params.get('profile')
    if not isinstance(body, dict):
        body = {k: v for k, v in receiver_params.items() if k != 'params_id'}
    expected = '0x' + hashlib.sha256(b'HECATE-RECEIVER-PARAMS-v1\x00' + core.canonical(body)).hexdigest()
    require(expected == receiver_params['params_id'] == manifest['receiver_params_id'],
            'Receiver parameters binding mismatch')
    require(body['curve'] == 'BLS12-381' and body['receiver_public_key_group'] == 'G2', 'Wrong receiver group')
    require(body['scalar_order_decimal'] == str(core.curve_order), 'Wrong receiver scalar field')
    require(body['g2_generator_hex'].removeprefix('0x') == core.enc_g2(core.G2).hex(), 'Wrong receiver generator')
    require(body['g2_encoding'] == 'py_ecc.compress_G2:z1_be48||z2_be48', 'Wrong receiver encoding')
    core.dec_g2(bytes.fromhex(public['pairing_public_key_hex']))
    from cryptography.hazmat.primitives.asymmetric import ec
    signature_key = bytes.fromhex(public['schnorr_public_key_hex'])
    require(len(signature_key) == 33 and signature_key[0] in (2, 3), 'Invalid compressed signing key')
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), signature_key)
    receiver = read(root / 'deployment/receiver_registry.json')
    require(receiver['params_id'] == manifest['receiver_params_id'], 'Receiver deployment profile mismatch')
    owner = core.owner_address(public['owner_eth_address'])
    accounts = read(root.parent / 'blockchain-geth/accounts.json')
    require(owner == accounts['node6'].lower(), 'Node6 Ethereum owner mismatch')
    require((alliance / 'repository.sqlite').is_file(), 'Missing operational Pre database')
    # Open read-only: never create or modify a repository during registration.
    con = sqlite3.connect((alliance / 'repository.sqlite').resolve().as_uri() + '?mode=ro', uri=True)
    try:
        rows = con.execute('SELECT count(*) FROM records').fetchone()[0]
    finally:
        con.close()
    config = {'setup_id': setup_id, 'key_id': public['key_id'],
              'receiver_params_id': manifest['receiver_params_id'],
              'srs_sha256': '0x' + manifest['srs_sha256'], 'B': manifest['B'],
              'owner': Web3.to_checksum_address(owner),
              'receiver_registry': Web3.to_checksum_address(receiver['address']),
              'pairing_key': public['pairing_public_key_hex'],
              'schnorr_key': public['schnorr_public_key_hex']}
    require(config['B'] == 4096, 'This deployment expects the selected B=4096')
    print('Local checks passed: B=4096; Pre unique records=%d (not published)' % rows, flush=True)
    return config, receiver, setup_dir


def clients():
    result = []
    for port in PORTS:
        session = requests.Session()
        session.trust_env = False
        w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:%d' % port,
                                  request_kwargs={'timeout': 15}, session=session))
        w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        require(w3.is_connected(), 'Cannot connect to RPC port %d; check Geth processes' % port)
        result.append(w3)
    return result


def verify_receiver(chains, receiver):
    height = min(w.eth.block_number for w in chains)
    hashes = [hx(w.eth.get_block(height)['hash']) for w in chains]
    require(len(set(hashes)) == 1, 'Nodes disagree at common block; wait and rerun')
    for w in chains:
        require(w.eth.chain_id == receiver['chain_id'] == 20261005, 'Wrong chain ID')
        require(hx(w.eth.get_block(0)['hash']).lower() == receiver['genesis_hash'].lower(), 'Wrong genesis')
        code = w.eth.get_code(Web3.to_checksum_address(receiver['address']), height)
        require(code and hx(Web3.keccak(code)).lower() == receiver['runtime_code_hash'].lower(), 'Receiver contract code mismatch')
        c = w.eth.contract(address=Web3.to_checksum_address(receiver['address']), abi=PARAM_ABI)
        require(hx(c.functions.paramsId().call(block_identifier=height)).lower() == receiver['params_id'].lower(),
                'On-chain receiver parameter ID mismatch')
    return hashes[0]


def compile_contract(binary):
    version = subprocess.check_output([str(binary), '--version'], text=True)
    require('0.8.24+commit.e11b9ed9' in version, 'Expected the existing solc 0.8.24 binary')
    source = Path(__file__).with_name('HecateSystemRegistry.sol').read_text('utf-8')
    compiled = solcx.compile_source(source, output_values=['abi', 'bin'], solc_binary=str(binary),
                                    evm_version='london', optimize=True, optimize_runs=200)
    return compiled['<stdin>:HecateSystemRegistry']


def arguments(config):
    ids = [bytes.fromhex(config[k][2:]) for k in ('setup_id', 'key_id', 'receiver_params_id', 'srs_sha256')]
    return (ids, config['B'], config['receiver_registry'], bytes.fromhex(config['pairing_key']),
            bytes.fromhex(config['schnorr_key']))


def same_config(onchain, config):
    ids, B, owner, registry, pairing_key, signing_key = onchain
    return (list(ids) == arguments(config)[0] and B == config['B']
            and owner.lower() == config['owner'].lower()
            and registry.lower() == config['receiver_registry'].lower()
            and bytes(pairing_key).hex() == config['pairing_key']
            and bytes(signing_key).hex() == config['schnorr_key'])


def check_deployed(chains, record, config, confirmations, timeout):
    deadline = time.monotonic() + timeout
    while True:
        receipts = []
        try:
            receipts = [w.eth.get_transaction_receipt(record['tx_hash']) for w in chains]
        except TransactionNotFound:
            pass
        if len(receipts) == len(chains):
            require(all(r['status'] == 1 for r in receipts), 'Registration transaction reverted; do not auto-redeploy')
            if min(w.eth.block_number for w in chains) >= max(r['blockNumber'] for r in receipts) + confirmations:
                break
        if time.monotonic() > deadline:
            raise TimeoutError('Receipt/confirmation wait timed out. Rerun deploy; saved transaction will be reused.')
        time.sleep(2)
    require(len({hx(r['blockHash']) for r in receipts}) == 1, 'Deployment receipts disagree')
    height = min(w.eth.block_number for w in chains) - confirmations
    require(len({hx(w.eth.get_block(height)['hash']) for w in chains}) == 1, 'Common block hash mismatch')
    address = receipts[0]['contractAddress']
    require(address is not None and all(r['contractAddress'] == address for r in receipts), 'Contract address mismatch')
    codes = []
    for i, w in enumerate(chains):
        r = receipts[i]
        require(w.eth.get_block(r['blockNumber'])['hash'] == r['blockHash'], 'Deployment block is no longer canonical')
        code = w.eth.get_code(address, height)
        require(bool(code), 'No deployed runtime code')
        codes.append(hx(Web3.keccak(code)))
        contract = w.eth.contract(address=address, abi=record['abi'])
        require(same_config(contract.functions.getConfig().call(block_identifier=height), config), 'On-chain configuration mismatch')
        print('RPC %d: configuration verified at block %d' % (PORTS[i], height), flush=True)
    require(len(set(codes)) == 1, 'Contract runtime code differs across nodes')
    if 'runtime_code_hash' in record:
        require(record['runtime_code_hash'] == codes[0] and record['address'] == address, 'Saved contract identity mismatch')
    return address, codes[0], receipts[0], height


def ethereum_account(root, expected):
    node = root.parent / 'blockchain-geth/node6'
    keys = list((node / 'keystore').glob('UTC--*'))
    require(len(keys) == 1, 'Expected exactly one node6 Ethereum keystore; resolve explicitly if multiple')
    account = Account.from_key(Account.decrypt(read(keys[0]), (node / 'password.txt').read_text().strip()))
    require(account.address.lower() == expected.lower(), 'Keystore account does not match alliance owner')
    return account


def deploy(args, root, config, receiver, chains, state, pending):
    fingerprint = {'config': config, 'chain_id': receiver['chain_id'], 'genesis_hash': receiver['genesis_hash'],
                   'source_sha256': digest(Path(__file__).with_name('HecateSystemRegistry.sol'))}
    if state.exists():
        saved = read(state)
        require(all(saved[k] == v for k, v in fingerprint.items()), 'Existing deployment is for different inputs')
        check_deployed(chains, saved, config, args.confirmations, args.timeout)
        print('Already registered:', saved['address'])
        return
    if pending.exists():
        journal = read(pending)
        require(all(journal[k] == v for k, v in fingerprint.items()), 'Pending deployment is for different inputs')
        require(hx(Web3.keccak(bytes.fromhex(journal['raw_transaction'][2:]))) == journal['tx_hash'], 'Saved transaction hash mismatch')
        require(Account.recover_transaction(journal['raw_transaction']).lower() == config['owner'].lower(), 'Saved signer mismatch')
        print('Resuming the saved transaction:', journal['tx_hash'], flush=True)
    else:
        artifact = compile_contract(Path(args.solc))
        w3 = chains[0]
        signer = ethereum_account(root, config['owner'])
        gas_price = max(w3.eth.gas_price, 2 * w3.eth.get_block('latest').get('baseFeePerGas', 0) + 10**9)
        constructor = w3.eth.contract(abi=artifact['abi'], bytecode=artifact['bin']).constructor(*arguments(config))
        gas = int(constructor.estimate_gas({'from': signer.address, 'gasPrice': gas_price}) * 1.2) + 10000
        require(gas < w3.eth.get_block('latest')['gasLimit'], 'Estimated deployment exceeds block gas limit')
        require(w3.eth.get_balance(signer.address) >= gas * gas_price, 'Node6 has insufficient test ETH')
        tx = constructor.build_transaction({'chainId': w3.eth.chain_id, 'from': signer.address,
                  'nonce': w3.eth.get_transaction_count(signer.address, 'pending'), 'gas': gas, 'gasPrice': gas_price})
        signed = signer.sign_transaction(tx)
        journal = dict(fingerprint, abi=artifact['abi'], raw_transaction=hx(signed.raw_transaction),
                       tx_hash=hx(signed.hash), raw_transaction_bytes=len(signed.raw_transaction),
                       deployment_input_bytes=len(bytes.fromhex(tx['data'].removeprefix('0x'))),
                       nonce=tx['nonce'], gas_limit=gas, gas_price=gas_price,
                       compiler='0.8.24', evm_version='london')
        save_new(pending, journal)  # Persist signed bytes BEFORE the first send.
    timing = pending.with_name(pending.stem + '.first_attempt.json')
    if not timing.exists():
        save_new(timing, {'unix_time': time.time()})
    try:
        chains[0].eth.get_transaction(journal['tx_hash'])
    except TransactionNotFound:
        try:
            chains[0].eth.send_raw_transaction(journal['raw_transaction'])
        except Exception:
            # If the RPC reply was lost after accepting the transaction, query its hash.
            chains[0].eth.get_transaction(journal['tx_hash'])
    print('Transaction:', journal['tx_hash'], flush=True)
    receipt = chains[0].eth.wait_for_transaction_receipt(journal['tx_hash'], timeout=args.timeout, poll_latency=1)
    require(receipt['status'] == 1, 'Deployment reverted; transaction preserved for diagnosis')
    latency = time.time() - read(timing)['unix_time']
    address, codehash, receipt, height = check_deployed(chains, journal, config, args.confirmations, args.timeout)
    final = {k: v for k, v in journal.items() if k != 'raw_transaction'}
    final.update({'address': address, 'runtime_code_hash': codehash, 'block_number': receipt['blockNumber'],
                  'block_hash': hx(receipt['blockHash']), 'gas_used': receipt['gasUsed'],
                  'effective_gas_price': receipt['effectiveGasPrice'],
                  'transaction_fee_wei': receipt['gasUsed'] * receipt['effectiveGasPrice'],
                  'first_attempt_to_receipt_observed_seconds': latency,
                  'latency_note': 'Includes downtime/retries if resumed; not a pure consensus-latency benchmark',
                  'verified_block': height, 'extra_blocks': args.confirmations})
    save_new(state, final)
    print('Registered contract:', address)
    print('gasUsed:', receipt['gasUsed'])
    print('Signed transaction bytes:', journal['raw_transaction_bytes'])
    print('Saved:', state)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['preflight', 'deploy', 'check'])
    parser.add_argument('--app-root', default='/home/Hecate_2/hecate-app')
    parser.add_argument('--solc', default='/home/Hecate_2/hecate-app/tools/solc-0.8.24')
    parser.add_argument('--timeout', type=int, default=240)
    parser.add_argument('--confirmations', type=int, default=2)
    args = parser.parse_args()
    require(args.timeout > 0 and args.confirmations >= 0, 'Invalid wait settings')
    root = Path(args.app_root).resolve()
    config, receiver, setup_dir = local_configuration(root)
    chains = clients()
    verify_receiver(chains, receiver)
    print('Chain/receiver registry checks passed on all three RPC nodes.', flush=True)
    print('Existing setup:', setup_dir)
    state = root / 'deployment/system_registry.json'
    pending = root / 'deployment/system_registry.pending.json'
    if args.command == 'preflight':
        print(json.dumps(config, indent=2))
        print('Read-only preflight passed; no transaction sent.')
    elif args.command == 'check':
        saved = read(state)
        require(saved['config'] == config and saved['genesis_hash'] == receiver['genesis_hash']
                and saved['chain_id'] == receiver['chain_id'], 'Deployment/local state mismatch')
        check_deployed(chains, saved, config, args.confirmations, args.timeout)
        print('Registration verified:', saved['address'])
    else:
        with deployment_lock(root / 'deployment/system_registry.lock'):
            deploy(args, root, config, receiver, chains, state, pending)


if __name__ == '__main__':
    try:
        main()
    except (TimeExhausted, TimeoutError) as exc:
        raise SystemExit(str(exc) + '\nKeep pending files and rerun deploy; do not reset the chain.')
