"""Shared checks/signing helpers from the existing system registration implementation."""

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

def ethereum_account(root, expected):
    node = root.parent / 'blockchain-geth/node6'
    keys = list((node / 'keystore').glob('UTC--*'))
    require(len(keys) == 1, 'Expected exactly one node6 Ethereum keystore; resolve explicitly if multiple')
    account = Account.from_key(Account.decrypt(read(keys[0]), (node / 'password.txt').read_text().strip()))
    require(account.address.lower() == expected.lower(), 'Keystore account does not match alliance owner')
    return account
