"""Small correctness tests; not benchmark data. Run in a writable directory."""
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from hecate_core import *


class InitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='hecate-tests-', dir=Path.cwd())
        cls.root = Path(cls.temp.name)
        cls.manifest, cls.raw, cls.metrics = make_setup(8)
        cls.location, _ = save_setup(cls.root / 'setups', cls.manifest, cls.raw)

    @classmethod
    def tearDownClass(cls):
        assert Path(cls.temp.name).resolve().is_relative_to(Path.cwd().resolve())
        cls.temp.cleanup()

    def test_srs_and_membership_relation(self):
        verified = verify_setup(self.location)
        self.assertEqual(verified['B'], 8)
        self.assertEqual(len(self.raw), 48*8+96)
        p1, p2 = dec_g1(self.raw[:48]), dec_g1(self.raw[48:96])
        tau2 = dec_g2(self.raw[-96:])
        # S={3,5}; f(X)=X^2-8X+15, witness at id=3 is X-5.
        digest = add(add(p2, multiply(p1, curve_order-8)), multiply(G1, 15))
        witness = add(p1, multiply(G1, curve_order-5))
        tau_minus_id = add(tau2, multiply(G2, curve_order-3))
        self.assertEqual(pairing(G2, digest), pairing(tau_minus_id, witness))

    def test_independent_setups(self):
        second, _, _ = make_setup(1)
        self.assertNotEqual(second['setup_id'], self.manifest['setup_id'])

    def test_tamper_and_no_overwrite(self):
        target = self.root / 'corrupted'
        target.mkdir()
        write_json(target / 'manifest.json', self.manifest)
        altered = bytearray(self.raw)
        altered[10] ^= 1
        write_bytes(target / 'srs.bin', altered)
        with self.assertRaises(ValueError):
            load_setup(target)
        with self.assertRaises(FileExistsError):
            save_setup(self.root / 'setups', self.manifest, self.raw)

    def test_valid_points_with_invalid_power_relation(self):
        # Updating hashes cannot make inconsistent public powers pass pairing validation.
        bad_raw = enc_g1(multiply(G1, 17)) + self.raw[48:]
        payload = {k: v for k, v in self.manifest.items() if k != 'setup_id'}
        payload['srs_sha256'] = hashlib.sha256(bad_raw).hexdigest()
        bad_manifest = dict(payload, setup_id='0x' + hashlib.sha256(ser('SETUP-ID', canonical(payload))).hexdigest())
        location, _ = save_setup(self.root / 'invalid-powers', bad_manifest, bad_raw)
        with self.assertRaises(ValueError):
            verify_setup(location)

    def test_parameters_and_domain_separation(self):
        self.assertNotEqual(ser('RD', b'ab', b'c'), ser('RD', b'a', b'bc'))
        self.assertNotEqual(h_id(ser('RD', b'x')), h_id(ser('SID', b'x')))
        self.assertEqual(h_id(ser('RD', b'x')), h_id(ser('RD', b'x')))
        dec_g1(enc_g1(h_batch(b't001')))
        with self.assertRaises(ValueError):
            dec_g1(enc_g1(Z1))
        with self.assertRaises(ValueError):
            dec_g2(b'\x00' * 95)

    def test_alliance_and_authorization_equation(self):
        public, private, metrics = make_alliance(self.manifest['setup_id'], '0x' + '01'*20)
        validate_alliance(public, private)
        self.assertEqual(metrics['public_keys_raw_bytes'], 129)
        secret = int(private['pairing_secret_hex'], 16)
        xi = 7
        digest = dec_g1(self.raw[:48])
        ht = h_batch(b'unit-test-batch')
        key = add(multiply(add(digest, ht), secret), multiply(digest, xi))
        pk = dec_g2(bytes.fromhex(public['pairing_public_key_hex']))
        # e(G2,sk)=e(pk,dS+h)*e(U,dS) in multiplicative GT representation.
        self.assertEqual(pairing(G2, key), pairing(pk, add(digest, ht))*pairing(multiply(G2, xi), digest))
        modified = dict(private, schnorr_secret_hex=(2).to_bytes(32, 'big').hex())
        with self.assertRaises(ValueError):
            validate_alliance(public, modified)

    def test_repository_duplicates_and_corruption(self):
        dataset = self.root / 'rd'
        dataset.mkdir()
        records = [b'record A\x00\xff', b'record B', b'record A\x00\xff']
        entries = []
        for i, content in enumerate(records):
            name = str(i) + '.bin'
            write_bytes(dataset / name, content)
            entries.append({'file': name, 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()})
        write_json(dataset / 'dataset.json', {'records': entries})
        db = self.root / 'pre.sqlite'
        metrics = build_repository(dataset, db)
        self.assertEqual(metrics['record_count'], 3)
        self.assertEqual(metrics['unique_count'], 2)
        self.assertEqual(metrics['duplicate_count'], 1)
        index = enc_g2(multiply(G2, h_id(ser('RD', records[0]))))
        self.assertEqual(retrieve(db, index), records[0])
        with closing(sqlite3.connect(db)) as con:
            with con:
                con.execute('UPDATE records SET content=? WHERE idx=?', (b'wrong', index))
        with self.assertRaises(ValueError):
            retrieve(db, index)

    def test_receiver_binding(self):
        doc = {'profile': 'hecate-receiver-bls12381-v1', 'scope': 'receiver-key-generation',
               'curve': 'BLS12-381', 'receiver_public_key_group': 'G2',
               'scalar_order_decimal': str(curve_order), 'base_field_modulus_decimal': str(field_modulus),
               'scalar_bytes':32, 'g1_compressed_bytes':48, 'g2_compressed_bytes':96,
               'g1_generator_hex':enc_g1(G1).hex(), 'g2_generator_hex':enc_g2(G2).hex(),
               'g2_encoding':'py_ecc.compress_G2:z1_be48||z2_be48'}
        identifier = '0x' + hashlib.sha256(b'HECATE-RECEIVER-PARAMS-v1\x00' + canonical(doc)).hexdigest()
        doc['params_id'] = identifier
        path = self.root / 'receiver.json'
        write_json(path, doc)
        self.assertEqual(read_receiver_binding(path), identifier)
        doc['curve'] = 'wrong'
        changed = self.root / 'receiver-changed.json'
        write_json(changed, doc)
        with self.assertRaises(ValueError):
            read_receiver_binding(changed)


if __name__ == '__main__':
    unittest.main(verbosity=2)
