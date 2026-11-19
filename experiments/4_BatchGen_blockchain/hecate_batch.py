"""Version-bound BatchGen, on-chain publication, and authenticated chain fetch."""
import argparse
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import batch_crypto as crypto

HERE=Path(__file__).resolve().parent

def load_modules(root):
    sys.path.insert(0,str(root/'ppk-v1'))
    sys.path.insert(0,str(root/'init-v1'))
    return importlib.import_module('publish_ppk'),importlib.import_module('hecate_core')

def compile_contract(binary):
    import solcx
    version=subprocess.check_output([str(binary),'--version'],text=True)
    crypto.need('0.8.24+commit.e11b9ed9' in version,'Expected existing solc 0.8.24')
    return solcx.compile_source((HERE/'HecateBatchRegistry.sol').read_text('utf-8'),
        output_values=['abi','bin'],solc_binary=str(binary),evm_version='london',optimize=True,optimize_runs=200)['<stdin>:HecateBatchRegistry']

def environment(args,root,pp):
    system=pp.read(root/'deployment/system_registry.json')
    ppk=pp.read(root/'deployment/ppk_registry.json')
    chains=pp.reg.clients()
    height,block_hash=pp.system_check(chains,system,args.confirmations)
    for w in chains:
        c=pp.checked_store(w,ppk,system,height)
        crypto.need(c.functions.finalized().call(block_identifier=height),'Finish PPK publication first')
    return system,ppk,chains,height,block_hash

def deployment_context(pp,system,ppk):
    return {'chain_id':system['chain_id'],'genesis_hash':system['genesis_hash'],
      'system_registry':system['address'],'ppk_store':ppk['address'],
      'setup_id':system['config']['setup_id'],'key_id':system['config']['key_id'],
      'source_sha256':pp.reg.digest(HERE/'HecateBatchRegistry.sol')}

def contract_checked(pp,w,record,system,ppk,height):
    from web3 import Web3
    expected=deployment_context(pp,system,ppk)
    crypto.need(record['context']==expected,'Batch deployment version/source mismatch')
    code=w.eth.get_code(record['address'],height)
    crypto.need(code and pp.hx(Web3.keccak(code))==record['runtime_code_hash'],'Batch contract code mismatch')
    c=w.eth.contract(address=record['address'],abi=record['abi'])
    call=lambda f:f.call(block_identifier=height)
    crypto.need(call(c.functions.systemRegistry()).lower()==system['address'].lower(),'Wrong system registry')
    crypto.need(call(c.functions.ppkStore()).lower()==ppk['address'].lower(),'Wrong PPK contract')
    crypto.need(call(c.functions.owner()).lower()==system['config']['owner'].lower(),'Wrong batch owner')
    crypto.need(pp.hx(call(c.functions.setupId()))==system['config']['setup_id'],'Wrong Setup')
    crypto.need(pp.hx(call(c.functions.keyId()))==system['config']['key_id'],'Wrong alliance key')
    return c

def deploy(args,root,pp,system,ppk,chains):
    from web3 import Web3
    context=deployment_context(pp,system,ppk)
    path=root/'deployment/batch_registry.json'
    journal=root/'deployment/batch_upload'/system['config']['setup_id'][2:]/'deploy'
    with pp.reg.deployment_lock(root/'deployment/batch_upload.lock'):
        if path.exists():
            record=pp.read(path)
        else:
            build_path=journal/'build.json'
            if build_path.exists():
                build=pp.read(build_path)
                crypto.need(build['context']==context,'Saved build mismatch')
            else:
                build={'context':context,'artifact':compile_contract(Path(args.solc))}
                pp.save_new(build_path,build)
            artifact=build['artifact']
            account=pp.reg.ethereum_account(root,system['config']['owner'])
            operation=chains[0].eth.contract(abi=artifact['abi'],bytecode=artifact['bin']).constructor(
                Web3.to_checksum_address(system['address']),Web3.to_checksum_address(ppk['address']))
            receipt=pp.transact(chains,account,operation,journal,'deploy',context,args.timeout,args.confirmations)
            address=receipt['contractAddress']
            crypto.need(address is not None,'Missing batch contract address')
            record={'context':context,'address':address,'abi':artifact['abi'],
              'runtime_code_hash':pp.hx(Web3.keccak(chains[0].eth.get_code(address))),
              'tx_hash':pp.hx(receipt['transactionHash']),'gas_used':receipt['gasUsed'],
              'compiler':'0.8.24','evm_version':'london'}
            pp.save_new(path,record)
        height,_=pp.system_check(chains,system,args.confirmations)
        for w in chains: contract_checked(pp,w,record,system,ppk,height)
    print('Batch registry verified:',record['address'],flush=True)

def bindings(args,root,pp,system,ppk,chains):
    record=pp.read(root/'deployment/batch_registry.json')
    height,block_hash=pp.system_check(chains,system,args.confirmations)
    contracts=[contract_checked(pp,w,record,system,ppk,height) for w in chains]
    context=crypto.scope(system,ppk,record['address'])
    return record,context,contracts,height,block_hash

def paths(root,t):
    return (root/'private/node6/batches'/t[2:]/'state.json',
            root/'public/batches'/t[2:]/'public.json',
            root/'deployment/batch_upload'/t[2:])

def same_or_save(pp,path,doc):
    if path.exists(): crypto.need(pp.read(path)==doc,'Existing file differs: '+str(path))
    else: pp.save_new(path,doc)

def generate(args,root,pp,core,system,ppk,chains):
    record,context,contracts,height,_=bindings(args,root,pp,system,ppk,chains)
    label=args.batch
    t=crypto.batch_id(core,context,label)
    state_path,public_path,journal=paths(root,t)
    info=crypto.metadata(context,label,args.planned_records,args.description)
    with pp.reg.deployment_lock(root/'deployment/batch_upload.lock'):
        if state_path.exists():
            state=pp.read(state_path)
            crypto.validate_private(core,context,system['config'],label,state)
            crypto.need(json.loads(crypto.raw(state['public']['info_hex']))==info,
                        'This label already has different metadata. Use a fresh label for a new batch.')
            print('Existing batch reused; xi and signature were not regenerated.',flush=True)
        else:
            crypto.need(not public_path.exists(),'Public batch exists but private state is missing; restore the original state, do not regenerate')
            crypto.need(not any(c.functions.exists(crypto.raw(t)).call(block_identifier=height) for c in contracts),
                        'Batch already published; restore original private state instead of regenerating')
            local_config,_,_=pp.reg.local_configuration(root)
            crypto.need(local_config==system['config'],'Local alliance does not match chain')
            alliance=root/'private/node6/alliance-v1'
            public=pp.read(alliance/'public.json');private=pp.read(alliance/'secret.json')
            core.validate_alliance(public,private)
            state=crypto.generate(core,context,system['config'],label,info,int(private['schnorr_secret_hex'],16))
            del private
            state_path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            os.chmod(state_path.parent,0o700)
            pp.save_new(state_path,state)
        same_or_save(pp,public_path,state['public'])
        same_or_save(pp,public_path.with_name('metrics.json'),state['metrics'])
    print('BatchGen complete. t:',t,'\nPublic:',public_path,'\nPrivate state saved with restricted permissions; xi not displayed.',flush=True)
    print('No batch transaction sent. Next: publish --batch '+label,flush=True)

def download_one(pp,core,c,height,context,config,label):
    t=crypto.batch_id(core,context,label)
    U,R,s,info,block_number=c.functions.getBatch(crypto.raw(t)).call(block_identifier=height)
    doc=crypto.public_record(core,context,config,label,bytes(U),bytes(R),int.from_bytes(s,'big'),bytes(info))
    crypto.verify(core,context,config,label,doc)
    return doc,block_number

def check(args,root,pp,core,system,ppk,chains):
    record,context,contracts,height,block_hash=bindings(args,root,pp,system,ppk,chains)
    results=[download_one(pp,core,c,height,context,system['config'],args.batch) for c in contracts]
    crypto.need(all(r==results[0] for r in results),'Nodes disagree on batch contents')
    crypto.need(all(pp.hx(w.eth.get_block(height)['hash'])==block_hash for w in chains),'Pinned block changed')
    for port in pp.reg.PORTS: print('RPC %d: batch binding, U subgroup and Schnorr signature verified'%port,flush=True)
    print('Verified batch:',results[0][0]['t'],'at common block',height,flush=True)
    return results[0][0],results[0][1],height,block_hash

def publish(args,root,pp,core,system,ppk,chains):
    record,context,contracts,height,_=bindings(args,root,pp,system,ppk,chains)
    t=crypto.batch_id(core,context,args.batch)
    state_path,public_path,journal=paths(root,t)
    state=pp.read(state_path)
    crypto.validate_private(core,context,system['config'],args.batch,state)
    doc=state['public']
    same_or_save(pp,public_path,doc)
    c=contracts[0]
    with pp.reg.deployment_lock(root/'deployment/batch_upload.lock'):
        if c.functions.exists(crypto.raw(t)).call():
            current,_=download_one(pp,core,c,'latest',context,system['config'],args.batch)
            crypto.need(current==doc,'Published batch conflicts with local state')
            if not (journal/'publish.pending.json').exists():
                print('Batch already on chain; no transaction sent.',flush=True)
                check(args,root,pp,core,system,ppk,chains)
                return
        account=pp.reg.ethereum_account(root,system['config']['owner'])
        operation=c.functions.publishBatch(crypto.raw(t),crypto.raw(doc['U_hex']),crypto.raw(doc['R_hex']),
                    crypto.raw(doc['s_hex']),crypto.raw(doc['info_hex']))
        fingerprint={'deployment':record['context'],'contract':record['address'],'t':t,
                     'public_sha256':pp.sha(core.canonical(doc))}
        receipt=pp.transact(chains,account,operation,journal,'publish',fingerprint,args.timeout,args.confirmations)
        observed,_,_,_=check(args,root,pp,core,system,ppk,chains)
        crypto.need(observed==doc,'Local/chain batch mismatch')
        measured=pp.read(journal/'publish.receipt.json')
        summary={'t':t,'batchgen':state['metrics'],'publication':measured,
                 'note':'Deployment gas is reported separately. Publication latency includes confirmation waits/restarts.'}
        summary_path=journal/'summary.json'
        if not summary_path.exists(): pp.save_new(summary_path,summary)
        print('Batch published. gasUsed:',receipt['gasUsed'],'\nMetrics:',summary_path,flush=True)

def fetch(args,root,pp,core,system,ppk,chains):
    out=Path(args.out).resolve()
    crypto.need(not out.exists(),'Output exists; use the verified cache or choose a new directory')
    record,context,contracts,height,block_hash=bindings(args,root,pp,system,ppk,chains)
    start=time.perf_counter()
    index=pp.reg.PORTS.index(args.rpc_port)
    doc,published_block=download_one(pp,core,contracts[index],height,context,system['config'],args.batch)
    elapsed=time.perf_counter()-start
    crypto.need(pp.hx(chains[index].eth.get_block(height)['hash'])==block_hash,'Pinned block changed')
    out.mkdir(parents=True,exist_ok=False)
    pp.save_new(out/'public.json',doc)
    pp.save_new(out/'CHAIN_VERIFIED.json',{'t':doc['t'],'context':context,'block_number':height,
        'block_hash':block_hash,'published_block':published_block,'rpc_port':args.rpc_port,
        'download_and_verify_wall_s':elapsed,'public_sha256':pp.sha(core.canonical(doc))})
    print('Verified batch chain cache:',out,'\nU_t bytes: 96; signature bytes: 65',flush=True)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=['preflight','deploy','generate','publish','check','fetch'])
    p.add_argument('--root',default='/home/Hecate_2/hecate-app')
    p.add_argument('--solc',default='/home/Hecate_2/hecate-app/tools/solc-0.8.24')
    p.add_argument('--batch')
    p.add_argument('--planned-records',type=int,default=8)
    p.add_argument('--description',default='Hecate integration batch')
    p.add_argument('--rpc-port',type=int,choices=[18545,18546,18547],default=18545)
    p.add_argument('--out')
    p.add_argument('--confirmations',type=int,default=2)
    p.add_argument('--timeout',type=int,default=300)
    args=p.parse_args()
    crypto.need(args.timeout>0 and args.confirmations>=0,'Invalid wait settings')
    crypto.need(args.command in ('preflight','deploy') or args.batch,'This command requires --batch')
    crypto.need(args.command!='fetch' or args.out,'fetch requires --out')
    root=Path(args.root).resolve();pp,core=load_modules(root)
    system,ppk,chains,height,_=environment(args,root,pp)
    if args.command=='preflight':
        local,_,_=pp.reg.local_configuration(root)
        crypto.need(local==system['config'],'Local/chain configuration mismatch')
        private=pp.read(root/'private/node6/alliance-v1/secret.json')
        public=pp.read(root/'private/node6/alliance-v1/public.json')
        core.validate_alliance(public,private);del private
        print('Preflight passed: existing Setup/AKeyGen and finalized PPK agree; no transaction sent.')
    elif args.command=='deploy': deploy(args,root,pp,system,ppk,chains)
    else: globals()[args.command](args,root,pp,core,system,ppk,chains)

if __name__=='__main__': main()
