"""Hecate research profile v1. Offline Setup/AKeyGen; no Ethereum writes."""
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import secrets
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from py_ecc.bls.hash_to_curve import hash_to_G1
from py_ecc.bls.point_compression import (
    compress_G1, compress_G2, decompress_G1, decompress_G2,
)
from py_ecc.optimized_bls12_381 import (
    G1, G2, Z1, add, multiply, pairing, curve_order, field_modulus,
    is_inf, is_on_curve, b, b2, eq,
)

PROFILE = 'hecate-bls12381-secp256k1-v1'
Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
DST = b'HECATE_V1_BATCH_BLS12381G1_XMD:SHA-256_SSWU_RO_'


def canonical(obj):
    return json.dumps(obj, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def ser(tag, *parts):
    """Typed convention: tag is ASCII; each subsequent part is bytes.

    Integers/points must be converted by their field-specific encoders first.
    Count and lengths make tuples injective; no JSON hex conversion here.
    """
    values = (tag.encode('ascii'),) + parts
    if not all(isinstance(p, bytes) for p in values):
        raise TypeError('Ser accepts bytes fields only')
    return (b'HECATE-SER-v1\x00' + len(values).to_bytes(4, 'big') +
            b''.join(len(p).to_bytes(8, 'big') + p for p in values))


def hash_scalar(tag, *parts, modulus=curve_order):
    # Wide reduction: <= ~2^-256 bias for these 256-bit orders.
    return int.from_bytes(hashlib.shake_256(ser(tag, *parts)).digest(64), 'big') % modulus


def h_id(encoded_context):
    return hash_scalar('H-ID', encoded_context)


def h_batch(batch_identifier):
    return hash_to_G1(ser('BATCH-BASE', batch_identifier), DST, hashlib.sha256)


def h_ctx(encoded_context):
    return hashlib.sha256(ser('H-CTX', encoded_context)).digest()


def h_sig(encoded_context):
    return hash_scalar('H-SIG', encoded_context, modulus=Q)


def kdf(encoded_context):
    return hashlib.shake_256(ser('KDF', encoded_context)).digest(16)


def bkdf(encoded_context):
    counter = 0
    while True:
        value = hash_scalar('BKDF', encoded_context, counter.to_bytes(4, 'big'), modulus=Q)
        if value:
            return value
        counter += 1


def f_p(key, encoded_context):
    if len(key) != 16:
        raise ValueError('Masking seed must be 16 bytes in profile v1')
    return hash_scalar('F-P', key, encoded_context)


def enc_g1(point):
    return int(compress_G1(point)).to_bytes(48, 'big')


def enc_g2(point):
    a, c = compress_G2(point)
    return int(a).to_bytes(48, 'big') + int(c).to_bytes(48, 'big')


def enc_gt(value):
    return b''.join(int(x).to_bytes(48, 'big') for x in value.coeffs)


def dec_g1(raw, allow_identity=False):
    if len(raw) != 48:
        raise ValueError('Invalid G1 length')
    point = decompress_G1(int.from_bytes(raw, 'big'))
    if (not is_on_curve(point, b) or (is_inf(point) and not allow_identity)
            or not is_inf(multiply(point, curve_order)) or enc_g1(point) != raw):
        raise ValueError('Invalid G1 point/subgroup/encoding')
    return point


def dec_g2(raw, allow_identity=False):
    if len(raw) != 96:
        raise ValueError('Invalid G2 length')
    point = decompress_G2((int.from_bytes(raw[:48], 'big'), int.from_bytes(raw[48:], 'big')))
    if (not is_on_curve(point, b2) or (is_inf(point) and not allow_identity)
            or not is_inf(multiply(point, curve_order)) or enc_g2(point) != raw):
        raise ValueError('Invalid G2 point/subgroup/encoding')
    return point


def sig_public(scalar):
    return ec.derive_private_key(scalar, ec.SECP256K1()).public_key().public_bytes(
        Encoding.X962, PublicFormat.CompressedPoint)


def parameters():
    """Concrete fixed profile; changing any interface requires a new version."""
    return {
        'profile': PROFILE, 'security_target_bits': 128,
        'pairing': {'curve': 'BLS12-381', 'order': str(curve_order),
                    'field_modulus': str(field_modulus), 'direction': 'G2 x G1 -> GT',
                    'g1_hex': enc_g1(G1).hex(), 'g2_hex': enc_g2(G2).hex(),
                    'gt': 'pairing(g2,g1), computed during Setup',
                    'gt_encoding': '12 py_ecc FQ12 coefficients, each uint_be48'},
        'schnorr': {'curve': 'secp256k1', 'order': str(Q),
                    'generator_hex': sig_public(1).hex(),
                    'point_encoding': 'SEC1 compressed 33 bytes',
                    'scalar_encoding': 'uint_be32',
                    'signature': 'full-point Schnorr (R,s); not ECDSA or BIP340'},
        'serialization': 'HECATE-SER-v1: magic || uint_be32(count) || (uint_be64(length)||bytes)*; ASCII tag is first field',
        'functions': {
            'H_id': 'SHAKE256(Ser(H-ID,context),64) mod p',
            'H_B': 'py_ecc8 hash_to_G1(Ser(BATCH-BASE,t),DST,SHA256)',
            'H_B_DST': DST.decode(),
            'H_ctx': 'SHA256(Ser(H-CTX,context))',
            'H_sig': 'SHAKE256(Ser(H-SIG,context),64) mod q',
            'KDF': 'SHAKE256(Ser(KDF,context),16)',
            'BKDF': 'SHAKE256(Ser(BKDF,context,uint_be32(counter)),64) mod q; counter starts 0; retry zero',
            'F_p': 'SHAKE256(Ser(F-P,K,context),64) mod p; K is 16 bytes',
            'RD_index': '[H_id(Ser(RD,raw_record_bytes))]_2',
            'overt_encryption': 'AES-128-GCM; fresh random 12-byte nonce; context as AAD; 16-byte tag',
            'capsule': 'fixed em16 || K16 XOR SHAKE256(Ser(CAPS-PAD,dk),32); integer must be 1..q-1; otherwise abort, no retry',
        },
        'capsule_hidden_message_bytes': 16, 'masking_seed_bytes': 16,
        'hidden_r2_zero_policy': 'abort (security proof convention)',
        'scope': 'Setup/AKeyGen implemented; encryption and capsule rules specified for future integration',
    }


def read_receiver_binding(path):
    if path is None:
        return None
    doc = json.loads(Path(path).read_text('utf-8'))
    identifier = doc.get('params_id')
    body = {k: v for k, v in doc.items() if k != 'params_id'}
    expected = '0x' + hashlib.sha256(b'HECATE-RECEIVER-PARAMS-v1\x00' + canonical(body)).hexdigest()
    if identifier != expected:
        raise ValueError('Receiver parameter identifier mismatch; existing file was not modified')
    required = {'curve': 'BLS12-381', 'receiver_public_key_group': 'G2',
                'scalar_order_decimal': str(curve_order),
                'base_field_modulus_decimal': str(field_modulus),
                'g1_generator_hex': enc_g1(G1).hex(), 'g2_generator_hex': enc_g2(G2).hex(),
                'g2_encoding': 'py_ecc.compress_G2:z1_be48||z2_be48'}
    for key, value in required.items():
        actual = doc.get(key)
        if key.endswith('_hex') and isinstance(actual, str):
            actual = actual.removeprefix('0x')
        if actual != value:
            raise ValueError('Receiver parameter incompatibility: ' + key)
    return identifier


def stamp():
    return time.perf_counter_ns(), time.process_time_ns()


def elapsed(t):
    return {'wall_ms': (time.perf_counter_ns() - t[0]) / 1e6,
            'cpu_ms': (time.process_time_ns() - t[1]) / 1e6}


def write_bytes(path, data, private=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if private else 0o644)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def write_json(path, obj, private=False):
    write_bytes(path, canonical(obj) + b'\n', private)


def make_setup(B, receiver_params_id=None):
    if not isinstance(B, int) or B < 1 or B > 1_000_000:
        raise ValueError('B must be in 1..1000000')
    start = stamp()
    pp = parameters()
    pp['pairing']['gt_hex'] = enc_gt(pairing(G2, G1)).hex()
    # Uniform Z_p as in the draft. Reject 0 and 1 degenerate setups (~2/p).
    tau = secrets.randbelow(curve_order - 2) + 2
    power = 1
    points = []
    for _ in range(B):
        power = power * tau % curve_order
        points.append(multiply(G1, power))
    tau2 = multiply(G2, tau)
    # Python deletion is NOT cryptographic memory zeroization.
    del tau, power
    compute = elapsed(start)
    started = stamp()
    raw = b''.join(enc_g1(p) for p in points) + enc_g2(tau2)
    payload = {'format': 'hecate-setup-v1', 'B': B, 'parameters': pp,
               'receiver_params_id': receiver_params_id,
               'srs_encoding': 'P1..PB: compressed G1 48 bytes each; T: compressed G2 96 bytes; P0=G1 implicit',
               'srs_sha256': hashlib.sha256(raw).hexdigest()}
    setup_id = '0x' + hashlib.sha256(ser('SETUP-ID', canonical(payload))).hexdigest()
    manifest = dict(payload, setup_id=setup_id)
    public = canonical(manifest) + b'\n'
    serialize = elapsed(started)
    metrics = {'B': B, 'compute_wall_ms': compute['wall_ms'], 'compute_cpu_ms': compute['cpu_ms'],
               'serialize_wall_ms': serialize['wall_ms'], 'serialize_cpu_ms': serialize['cpu_ms'],
               'srs_bytes': len(raw), 'manifest_bytes': len(public),
               'public_bundle_bytes': len(raw) + len(public)}
    return manifest, raw, metrics


def save_setup(parent, manifest, raw):
    destination = Path(parent) / manifest['setup_id'][2:]
    destination.mkdir(parents=True, exist_ok=False)
    start = stamp()
    write_bytes(destination / 'srs.bin', raw)
    write_json(destination / 'manifest.json', manifest)
    return destination, elapsed(start)


def load_setup(directory):
    directory = Path(directory)
    manifest = json.loads((directory / 'manifest.json').read_text('utf-8'))
    raw = (directory / 'srs.bin').read_bytes()
    payload = {k: v for k, v in manifest.items() if k != 'setup_id'}
    expected = '0x' + hashlib.sha256(ser('SETUP-ID', canonical(payload))).hexdigest()
    if expected != manifest['setup_id'] or hashlib.sha256(raw).hexdigest() != manifest['srs_sha256']:
        raise ValueError('Setup integrity check failed')
    if len(raw) != 48 * manifest['B'] + 96:
        raise ValueError('SRS size mismatch')
    expected_pp = parameters()
    observed_pp = dict(manifest['parameters'])
    observed_pp['pairing'] = dict(observed_pp['pairing'])
    gt = observed_pp['pairing'].pop('gt_hex')
    if observed_pp != expected_pp or gt != enc_gt(pairing(G2, G1)).hex():
        raise ValueError('Unsupported parameter profile')
    return manifest, raw


def verify_setup(directory):
    """All points validated, plus randomized recurrence check after file is fixed.

    A malformed nonzero recurrence escapes with probability <= 1/(p-1).
    Does not certify that the setup creator erased tau.
    """
    manifest, raw = load_setup(directory)
    B = manifest['B']
    points = [G1] + [dec_g1(raw[i*48:(i+1)*48]) for i in range(B)]
    tau2 = dec_g2(raw[-96:])
    left, right = Z1, Z1
    for i in range(1, B + 1):
        coefficient = secrets.randbelow(curve_order - 1) + 1
        left = add(left, multiply(points[i], coefficient))
        right = add(right, multiply(points[i-1], coefficient))
    if pairing(G2, left) != pairing(tau2, right):
        raise ValueError('Invalid SRS powers')
    return manifest


def owner_address(value):
    if not re.fullmatch(r'0x[0-9a-fA-F]{40}', value) or int(value[2:], 16) == 0:
        raise ValueError('Provide a nonzero Ethereum public address for node6')
    return value.lower()


def make_alliance(setup_id, owner):
    start = stamp()
    b_secret = secrets.randbelow(curve_order - 1) + 1
    x_secret = secrets.randbelow(Q - 1) + 1
    public_point = multiply(G2, b_secret)
    signing_bytes = sig_public(x_secret)
    compute = elapsed(start)
    t = stamp()
    payload = {'format': 'hecate-alliance-v1', 'profile': PROFILE, 'setup_id': setup_id,
               'owner_eth_address': owner_address(owner),
               'pairing_public_key_hex': enc_g2(public_point).hex(),
               'schnorr_public_key_hex': signing_bytes.hex()}
    key_id = '0x' + hashlib.sha256(ser('ALLIANCE-ID', canonical(payload))).hexdigest()
    public = dict(payload, key_id=key_id)
    private = {'key_id': key_id, 'setup_id': setup_id,
               'pairing_secret_hex': b_secret.to_bytes(32, 'big').hex(),
               'schnorr_secret_hex': x_secret.to_bytes(32, 'big').hex()}
    public_bytes = len(canonical(public)) + 1
    serialization = elapsed(t)
    metrics = {'keygen_wall_ms': compute['wall_ms'], 'keygen_cpu_ms': compute['cpu_ms'],
               'key_serialize_wall_ms': serialization['wall_ms'],
               'public_keys_raw_bytes': 129, 'public_registration_bytes': public_bytes,
               'private_keys_raw_bytes': 64}
    return public, private, metrics


def validate_alliance(public, private):
    payload = {k: v for k, v in public.items() if k != 'key_id'}
    expected = '0x' + hashlib.sha256(ser('ALLIANCE-ID', canonical(payload))).hexdigest()
    if public['key_id'] != expected or private['key_id'] != expected or private['setup_id'] != public['setup_id']:
        raise ValueError('Alliance identity mismatch')
    b_secret = int(private['pairing_secret_hex'], 16)
    x_secret = int(private['schnorr_secret_hex'], 16)
    if not 0 < b_secret < curve_order or not 0 < x_secret < Q:
        raise ValueError('Alliance secret outside scalar field')
    point = dec_g2(bytes.fromhex(public['pairing_public_key_hex']))
    if not eq(point, multiply(G2, b_secret)) or sig_public(x_secret).hex() != public['schnorr_public_key_hex']:
        raise ValueError('Alliance public/private keys mismatch')


def read_dataset(directory):
    directory = Path(directory)
    doc = json.loads((directory / 'dataset.json').read_text('utf-8'))
    entries = doc['records']
    for entry in entries:
        p = Path(entry['file'])
        resolved = (directory / p).resolve()
        if p.is_absolute() or not resolved.is_relative_to(directory.resolve()):
            raise ValueError('Dataset contains a path outside its directory')
    return doc


def build_repository(dataset, database):
    """Actual Pre[index] = raw record, SQLite BLOBs with binary 96-byte keys.

    Read once, hash once per record; dataset-integrity SHA256 separately timed.
    SQL work includes index lookup and B-tree work, not pure disk latency.
    """
    dataset, database = Path(dataset), Path(database)
    doc = read_dataset(dataset)
    database.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(database, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    wall_start = stamp()
    con = sqlite3.connect(str(database))
    con.execute('PRAGMA journal_mode=DELETE')
    con.execute('PRAGMA synchronous=FULL')
    con.execute('CREATE TABLE records (idx BLOB PRIMARY KEY, content BLOB NOT NULL) WITHOUT ROWID')
    metrics = {name: 0.0 for name in ['read_wall_ms', 'integrity_wall_ms', 'hash_wall_ms',
                                    'g2_wall_ms', 'index_encode_wall_ms', 'sql_wall_ms']}
    total_bytes = unique_bytes = unique_count = duplicates = 0
    try:
        for entry in doc['records']:
            t = time.perf_counter_ns()
            content = (dataset / entry['file']).read_bytes()
            metrics['read_wall_ms'] += (time.perf_counter_ns() - t) / 1e6
            t = time.perf_counter_ns()
            if len(content) != entry['bytes'] or hashlib.sha256(content).hexdigest() != entry['sha256']:
                raise ValueError('Dataset integrity failed: ' + entry['file'])
            metrics['integrity_wall_ms'] += (time.perf_counter_ns() - t) / 1e6
            total_bytes += len(content)
            t = time.perf_counter_ns()
            scalar = h_id(ser('RD', content))
            metrics['hash_wall_ms'] += (time.perf_counter_ns() - t) / 1e6
            t = time.perf_counter_ns()
            index_point = multiply(G2, scalar)
            metrics['g2_wall_ms'] += (time.perf_counter_ns() - t) / 1e6
            t = time.perf_counter_ns()
            index = enc_g2(index_point)
            metrics['index_encode_wall_ms'] += (time.perf_counter_ns() - t) / 1e6
            t = time.perf_counter_ns()
            existing = con.execute('SELECT content FROM records WHERE idx=?', (index,)).fetchone()
            if existing is not None:
                if existing[0] != content:
                    raise ValueError('RD index collision between distinct records')
                duplicates += 1
            else:
                con.execute('INSERT INTO records VALUES (?,?)', (index, content))
                unique_count += 1
                unique_bytes += len(content)
            metrics['sql_wall_ms'] += (time.perf_counter_ns() - t) / 1e6
        t = time.perf_counter_ns()
        con.commit()
        metrics['sql_wall_ms'] += (time.perf_counter_ns() - t) / 1e6
    except BaseException:
        con.rollback()
        raise
    finally:
        con.close()
    duration = elapsed(wall_start)
    metrics.update({'repository_wall_ms': duration['wall_ms'], 'repository_cpu_ms': duration['cpu_ms'],
                    'record_count': len(doc['records']), 'unique_count': unique_count,
                    'duplicate_count': duplicates, 'rd_input_bytes': total_bytes,
                    'rd_unique_bytes': unique_bytes, 'rd_index_bytes': 96 * unique_count,
                    'repository_logical_bytes': unique_bytes + 96 * unique_count,
                    'repository_file_bytes': database.stat().st_size,
                    'rd_ingress_payload_bytes_if_uploaded_once': total_bytes,
                    'dataset_manifest_sha256': hashlib.sha256(canonical(doc)).hexdigest()})
    return metrics


def retrieve(database, index):
    uri = Path(database).resolve().as_uri() + '?mode=ro'
    with closing(sqlite3.connect(uri, uri=True)) as con:
        row = con.execute('SELECT content FROM records WHERE idx=?', (index,)).fetchone()
    if row is None:
        raise KeyError('RD index not present')
    if enc_g2(multiply(G2, h_id(ser('RD', row[0])))) != index:
        raise ValueError('Repository record/index mismatch')
    return row[0]


def environment():
    info = {'python': platform.python_version(), 'platform': platform.platform(),
            'machine': platform.machine(), 'logical_cpus': os.cpu_count(),
            'py_ecc': importlib.metadata.version('py-ecc'),
            'cryptography': importlib.metadata.version('cryptography'),
            'sqlite': sqlite3.sqlite_version, 'timer': 'perf_counter_ns/process_time_ns',
            'timestamp_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    try:
        info['cpuinfo'] = Path('/proc/cpuinfo').read_text().split('\n\n')[0]
        info['meminfo'] = Path('/proc/meminfo').read_text()
    except OSError:
        pass
    return info
