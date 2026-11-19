"""Local EVM tests, not the user's Geth network. Requires eth-tester + py-evm.

Usage: python test_registry.py /absolute/path/to/solc-0.8.24
"""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import solcx
from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider

import register_system as mod

SOLC = None


class RegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SOLC.suffix == '.json':
            output = json.loads(SOLC.read_text('utf-8'))
            def artifact(name):
                value = output['contracts'][name+'.sol'][name]
                return {'abi':value['abi'],'bin':value['evm']['bytecode']['object']}
            cls.artifact = artifact('HecateSystemRegistry')
            cls.stub = artifact('ReceiverStub')
            cls.compiler_patch = patch.object(mod,'compile_contract',return_value=cls.artifact)
            cls.compiler_patch.start()
            cls.addClassCleanup(cls.compiler_patch.stop)
            return
        cls.artifact = mod.compile_contract(SOLC)
        source = '''pragma solidity 0.8.24;
        contract ReceiverStub {
            bytes32 public immutable paramsId;
            constructor(bytes32 id) { paramsId = id; }
        }'''
        cls.stub = solcx.compile_source(source, output_values=['abi','bin'], solc_binary=str(SOLC),
                        evm_version='london')['<stdin>:ReceiverStub']

    def setUp(self):
        self.w3 = Web3(EthereumTesterProvider())
        self.owner = self.w3.eth.accounts[0]
        self.w3.eth.default_account = self.owner
        receiver = self.w3.eth.contract(abi=self.stub['abi'], bytecode=self.stub['bin'])
        rec = self.w3.eth.wait_for_transaction_receipt(receiver.constructor(b'\x03'*32).transact())
        self.config = {'setup_id':'0x'+'01'*32,'key_id':'0x'+'02'*32,
                       'receiver_params_id':'0x'+'03'*32,'srs_sha256':'0x'+'04'*32,
                       'B':4096,'owner':self.owner,'receiver_registry':rec['contractAddress'],
                       'pairing_key':'11'*96,'schnorr_key':'02'+'22'*32}
        self.factory = self.w3.eth.contract(abi=self.artifact['abi'], bytecode=self.artifact['bin'])

    def test_deploy_and_readback(self):
        tx = self.factory.constructor(*mod.arguments(self.config)).transact()
        r = self.w3.eth.wait_for_transaction_receipt(tx)
        c = self.w3.eth.contract(address=r['contractAddress'],abi=self.artifact['abi'])
        self.assertTrue(mod.same_config(c.functions.getConfig().call(), self.config))
        names = [x.get('name') for x in self.artifact['abi'] if x['type']=='function']
        self.assertNotIn('setConfig', names)
        self.assertEqual(c.events.SystemRegistered().process_receipt(r)[0]['args']['setupId'], b'\x01'*32)

    def test_reject_wrong_receiver_parameters(self):
        config = dict(self.config, receiver_params_id='0x'+'05'*32)
        with self.assertRaises(Exception):
            self.factory.constructor(*mod.arguments(config)).transact()

    def test_reject_invalid_lengths_and_empty_id(self):
        for updates in [{'pairing_key':'11'*95}, {'schnorr_key':'04'+'22'*32}, {'setup_id':'0x'+'00'*32}, {'B':0}]:
            with self.subTest(updates=updates), self.assertRaises(Exception):
                self.factory.constructor(*mod.arguments(dict(self.config,**updates))).transact()

    def test_reject_noncontract_registry(self):
        with self.assertRaises(Exception):
            self.factory.constructor(*mod.arguments(dict(self.config,receiver_registry=self.w3.eth.accounts[1]))).transact()

    def test_journal_and_retry_do_not_redeploy(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd(),prefix='registry-test-') as folder:
            root=Path(folder)
            state=root/'deployment/system_registry.json'
            pending=root/'deployment/system_registry.pending.json'
            receiver={'chain_id':self.w3.eth.chain_id,'genesis_hash':mod.hx(self.w3.eth.get_block(0)['hash'])}
            secret=self.w3.provider.ethereum_tester.backend.account_keys[0].to_bytes()
            signer=mod.Account.from_key(secret)
            args=SimpleNamespace(solc=str(SOLC),confirmations=0,timeout=5)
            real_save=mod.save_new
            def interrupt_before_final(path, doc):
                if Path(path)==state:
                    raise TimeoutError('simulated interruption after chain inclusion')
                return real_save(path,doc)
            with patch.object(mod,'ethereum_account',return_value=signer), patch.object(mod,'save_new',side_effect=interrupt_before_final):
                with self.assertRaises(TimeoutError):
                    mod.deploy(args,root,self.config,receiver,[self.w3]*3,state,pending)
            nonce=self.w3.eth.get_transaction_count(self.owner)
            journal=mod.read(pending)
            self.assertFalse(state.exists())
            with patch.object(mod,'ethereum_account',side_effect=AssertionError('must not sign again')):
                mod.deploy(args,root,self.config,receiver,[self.w3]*3,state,pending)
                mod.deploy(args,root,self.config,receiver,[self.w3]*3,state,pending)
            self.assertEqual(nonce,self.w3.eth.get_transaction_count(self.owner))
            self.assertEqual(journal['tx_hash'],mod.read(state)['tx_hash'])
            with self.assertRaises(FileExistsError):
                real_save(state,{'bad':'overwrite'})
            self.assertTrue(Path(folder).resolve().is_relative_to(Path.cwd().resolve()))


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('solc')
    args=parser.parse_args()
    SOLC=Path(args.solc).resolve()
    unittest.main(argv=['test_registry.py'],verbosity=2)
