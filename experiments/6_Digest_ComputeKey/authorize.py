"""Publish Digest; compute private capabilities; deliver only recipient-sealed envelopes."""
import argparse,hashlib,importlib,json,re,subprocess,sys,time
from pathlib import Path
from types import SimpleNamespace
import auth_crypto as ac
HERE=Path(__file__).resolve().parent
def environment(a):
    sys.path.insert(0,str(Path(a.root).resolve()/'aenc-chain-v1'))
    app=importlib.import_module('aenc_chain')
    root=Path(a.root).resolve()
    sys.path[:0]=[str(root/'batch-v1'),str(root/'ppk-v1')]
    pp=importlib.import_module('publish_ppk');hb=importlib.import_module('hecate_batch')
    system,ppk,chains,height,bh=hb.environment(a,root,pp)
    batch_record,context,contracts,height,bh=hb.bindings(a,root,pp,system,ppk,chains)
    docs=[hb.download_one(pp,app.core,c,height,context,system['config'],a.batch)[0] for c in contracts]
    ac.need(all(x==docs[0] for x in docs),'Batch RPC disagreement')
    e=SimpleNamespace(root=root,pp=pp,hb=hb,system=system,ppk=ppk,chains=chains,height=height,bh=bh,
        batch_record=batch_record,context=context,batch=docs[0],rid=bytes(32))
    d,stores=app.store(e)
    return app,e,d,stores
def paths(e):
    return e.root/'private/node6/authorizations'/e.batch['t'][2:]
def deploypath(e):return e.root/'deployment/authorization_registry.json'
def auth_stores(app,e,d):
    saved=app.read(deploypath(e));ac.need(saved['cipher_store']==d['address'],'Wrong cipher store')
    ac.need(saved['source_sha256']==app.digest((HERE/'HecateAuthorization.sol').read_bytes()),'Authorization source mismatch: existing deployment is another version; do not delete metadata or reissue keys')
    contracts=[]
    for w in e.chains:
        code=w.eth.get_code(saved['address'],e.height)
        ac.need(code and e.pp.hx(w.keccak(code))==saved['runtime_code_hash'],'Authorization bytecode mismatch')
        c=w.eth.contract(address=saved['address'],abi=saved['abi'])
        ac.need(c.functions.owner().call(block_identifier=e.height).lower()==e.system['config']['owner'].lower(),'Authorization owner')
        ac.need(c.functions.cipherStore().call(block_identifier=e.height).lower()==d['address'].lower(),'Cipher store binding')
        ac.need(c.functions.capacity().call(block_identifier=e.height)==e.system['config']['B'],'Authorization capacity')
        contracts.append(c)
    return saved,contracts
def deploy(a,app,e,d,stores):
    if deploypath(e).exists():auth_stores(app,e,d);print('Existing authorization contract verified.');return
    import solcx
    ac.need('0.8.24+commit.e11b9ed9' in subprocess.check_output([a.solc,'--version'],text=True),'solc version')
    artifact=solcx.compile_source((HERE/'HecateAuthorization.sol').read_text(),output_values=['abi','bin'],solc_binary=a.solc,evm_version='london',optimize=True)['<stdin>:HecateAuthorization']
    account=e.pp.reg.ethereum_account(e.root,e.system['config']['owner'])
    op=e.chains[0].eth.contract(abi=artifact['abi'],bytecode=artifact['bin']).constructor(d['address'])
    journal=e.root/'deployment/authorization_deploy'
    context={'cipher_store':d['address'],'bytecode_sha256':app.digest(ac.raw(artifact['bin']))}
    receipt=e.pp.transact(e.chains,account,op,journal,'deploy',context,a.timeout,a.confirmations)
    address=receipt['contractAddress']
    app.save(deploypath(e),{'address':address,'abi':artifact['abi'],'cipher_store':d['address'],
        'source_sha256':app.digest((HERE/'HecateAuthorization.sol').read_bytes()),
        'runtime_code_hash':e.pp.hx(e.chains[0].keccak(e.chains[0].eth.get_code(address)))})
    print('Authorization contract:',address)
def selected_records(a,app,e,d,stores):
    selection=app.read(Path(a.selection)) if a.selection else [{'run':a.run,'sender':v} for v in a.senders]
    ac.need(isinstance(selection,list) and 1<=len(selection)<=e.system['config']['B'],'Selection size')
    rows=[]
    for item in selection:
        ac.need(set(item)=={'run','sender'} and all(isinstance(x,str) and re.fullmatch('[A-Za-z0-9_-]{1,64}',x) for x in item.values()),'Invalid selection')
        ready=app.read(e.root/'private/node4/aenc-runs'/item['run']/'READY.json')
        ac.need(ready['suite']==app.SUITE and ready['store'].lower()==d['address'].lower() and ready['batch']==e.batch['t'],'Run binding')
        matches=[r for r in ready['records'] if r['sender']==item['sender']]
        ac.need(len(matches)==1,'Sender missing or ambiguous in run')
        rows.append(dict(matches[0],run=item['run']))
    rows.sort(key=lambda r:int(r['id'],16))
    ac.need(len({int(r['id'],16) for r in rows})==len(rows),'Duplicate IDs')
    for row in rows:
        key=e.chains[0].keccak(ac.raw(row['address'])+ac.raw(e.batch['t'])+ac.raw(row['id']))
        observations=[c.functions.get(key).call(block_identifier=e.height) for c in stores]
        ac.need(all(r==observations[0] for r in observations),'Cipher metadata RPC disagreement')
        r=observations[0]
        ac.need(r[9] and r[0].lower()==row['address'].lower() and bytes(r[1])==ac.raw(e.batch['t']) and bytes(r[2])==ac.raw(row['id']),'Selected record not finalized or record mismatch')
        row['receiver_id']=bytes(r[3]).hex()
        pk=bytes(r[4]);app.core.dec_g2(pk)
        ac.need(pk.hex()==row['pk_ds_hex'] and app.core.h_id(app.core.ser('SID',ac.raw(e.batch['auth_hex']),pk))==int(row['id'],16),'Sender ID/public key mismatch')
        ac.need(r[5]==row['wire_bytes'],'Cipher size mismatch')
        # Chain content is authoritative; verify the ciphertext commitment on all RPCs.
        for c in stores:
            data=b''.join(bytes(c.functions.getChunk(key,i).call(block_identifier=e.height)) for i in range(r[6]))
            ac.need(app.digest(data)==row['sha256'] and app.commitment(data)==bytes(r[7]),'Selected ciphertext mismatch')
            tx=json.loads(data)
            ac.need(tx['format']==app.engine.FORMAT and tx['binding']==dict(app.bindings(e,d,row['address']),receiver_id=row['receiver_id']) and tx['t']==e.batch['t'] and tx['id_hex']==row['id'] and tx['pk_ds_hex']==pk.hex(),'Ciphertext context mismatch')
    return rows
def receiver_info(app,e,rid):
    rid=ac.raw(rid);ac.need(len(rid)==32,'Receiver ID length')
    rr=app.read(e.root/'deployment/receiver_registry.json')
    ac.need(rr['address'].lower()==e.system['config']['receiver_registry'].lower(),'Receiver registry binding')
    observations=[]
    for w in e.chains:
        ac.need(e.pp.hx(w.keccak(w.eth.get_code(rr['address'],e.height)))==rr['runtime_code_hash'],'Receiver code mismatch')
        c=w.eth.contract(address=rr['address'],abi=rr['abi'])
        ac.need(e.pp.hx(c.functions.paramsId().call(block_identifier=e.height))==e.system['config']['receiver_params_id'],'Receiver parameters')
        observations.append(c.functions.getReceiver(rid).call(block_identifier=e.height))
    ac.need(all(x==observations[0] for x in observations),'Receiver RPC disagreement')
    pk=bytes(observations[0][1]);app.core.dec_g2(pk)
    return {'receiver_id':rid.hex(),'receiver_public_key_hex':pk.hex()}

def recipient_binding(app,intent,rid):
    rid=ac.raw(rid).hex()
    candidates=[r for r in intent['recipients'] if r['receiver_id']==rid]
    ac.need(len(candidates)==1,'Recipient is not in finalized authorization')
    return dict(intent['binding'],authorization_sha256=app.digest(app.core.canonical(intent)),**candidates[0])

def base_binding(app,e,d,auth):
    return {'format':'hecate-authorization-v2','chain_id':e.system['chain_id'],'genesis_hash':e.system['genesis_hash'],
        'system_registry':e.system['address'].lower(),'cipher_store':d['address'].lower(),'authorization_registry':auth['address'].lower(),
        'suite':app.SUITE,'setup_id':e.system['config']['setup_id'],'key_id':e.system['config']['key_id'],
        'batch':e.batch['t']}
def load_intent(app,e,d,auth):
    intent=app.read(paths(e)/'intent.json')
    ac.need(intent['binding']==base_binding(app,e,d,auth),'Authorization intent binding')
    ac.need(len(intent['ids'])==len(intent['senders'])==len(intent['receivers']),'Intent record counts')
    expected=[receiver_info(app,e,rid) for rid in sorted(set(intent['receivers']))]
    ac.need(intent['recipients']==expected,'Recipient keys changed or intent corrupted')
    return intent

def preflight(a,app,e,d,stores):
    rows=selected_records(a,app,e,d,stores)
    recipients=[receiver_info(app,e,rid) for rid in sorted({r['receiver_id'] for r in rows})]
    if deploypath(e).exists():auth_stores(app,e,d)
    ac.need(all(e.pp.hx(w.eth.get_block(e.height)['hash'])==e.bh for w in e.chains),'Pinned block changed')
    print(json.dumps({'read_only':True,'batch':e.batch['t'],'set_count':len(rows),
        'recipients':recipients,'records':[{'run':r['run'],'sender':r['sender'],'id':r['id'],'receiver_id':r['receiver_id']} for r in rows]},indent=2))
def digest(a,app,e,d,stores):
    auth,_=auth_stores(app,e,d);rows=selected_records(a,app,e,d,stores)
    print('Selected records verified. Downloading and verifying SRS; B=4096 may take time...',flush=True)
    manifest,srs=app.setup(e,paths(e))
    ds,metrics=ac.digest(app.core,[int(r['id'],16) for r in rows],srs)
    intent={'binding':base_binding(app,e,d,auth),'senders':[r['address'] for r in rows],
        'ids':[r['id'] for r in rows],'digest_hex':ds.hex(),
        'receivers':[r['receiver_id'] for r in rows],
        'recipients':[receiver_info(app,e,rid) for rid in sorted({r['receiver_id'] for r in rows})]}
    # This intent freezes the set locally BEFORE publication. Never silently change it.
    app.same_save(paths(e)/'intent.json',intent)
    public=e.root/'public/authorizations'/e.batch['t'][2:]
    app.same_save(public/'digest.json',intent)
    if not (paths(e)/'digest_metrics.json').exists():app.save(paths(e)/'digest_metrics.json',metrics)
    app.same_save(paths(e)/'selection.json',{'selection':[{'run':r['run'],'sender':r['sender'],'id':r['id']} for r in rows]})
    print('Digest ready:',public/'digest.json','\nSelected:',','.join(r['sender'] for r in rows),'\nNo authorization transaction sent.')
def verify_grant(app,e,d):
    auth,contracts=auth_stores(app,e,d);intent=load_intent(app,e,d,auth)
    observed=[c.functions.get(ac.raw(e.batch['t'])).call(block_identifier=e.height) for c in contracts]
    ac.need(all(x==observed[0] for x in observed),'Digest RPC disagreement')
    g=observed[0];ac.need(g[0],'Publish Digest before ComputeKey')
    ac.need([x.lower() for x in g[1]]==[x.lower() for x in intent['senders']] and [bytes(x).hex() for x in g[2]]==intent['ids'] and bytes(g[3]).hex()==intent['digest_hex'] and [bytes(x).hex() for x in g[4]]==intent['receivers'],'Immutable on-chain authorization differs')
    print('Authorization metadata verified. Verifying SRS and polynomial digest...',flush=True)
    _,srs=app.setup(e,paths(e));ds,_=ac.digest(app.core,[int(i,16) for i in intent['ids']],srs)
    ac.need(ds.hex()==intent['digest_hex'],'Polynomial digest mismatch')
    ac.need(all(e.pp.hx(w.eth.get_block(e.height)['hash'])==e.bh for w in e.chains),'Pinned block changed')
    return intent,auth
def publish(a,app,e,d,stores):
    auth,contracts=auth_stores(app,e,d);intent=load_intent(app,e,d,auth)
    # Check SRS/digest before sending. The contract independently checks finalized record bindings.
    _,srs=app.setup(e,paths(e));ds,_=ac.digest(app.core,[int(i,16) for i in intent['ids']],srs)
    ac.need(ds.hex()==intent['digest_hex'],'Digest integrity')
    journal=paths(e)/'publication';exists=contracts[0].functions.get(ac.raw(e.batch['t'])).call()[0]
    if exists and not (journal/'publish.pending.json').exists():
        verify_grant(app,e,d);print('Same Digest already published; no new transaction.');return
    account=e.pp.reg.ethereum_account(e.root,e.system['config']['owner'])
    op=contracts[0].functions.publish(ac.raw(e.batch['t']),intent['senders'],[ac.raw(i) for i in intent['ids']],ds)
    fingerprint={'contract':auth['address'],'intent_sha256':app.digest(app.core.canonical(intent))}
    receipt=e.pp.transact(e.chains,account,op,journal,'publish',fingerprint,a.timeout,a.confirmations)
    print('Digest published. gas_used:',receipt['gasUsed'],'Run check-digest next.')
def check_digest(a,app,e,d,stores):
    intent,_=verify_grant(app,e,d)
    print('All 3 RPCs: immutable set and recomputed dS agree. Set size:',len(intent['ids']))
def compute_key(a,app,e,d,stores):
    intent,auth=verify_grant(app,e,d);core=app.core;folder=paths(e)
    binding=dict(intent['binding'],authorization_sha256=app.digest(core.canonical(intent)))
    private_path=folder/'capability-private.json'
    alliance=e.root/'private/node6/alliance-v1'
    public=app.read(alliance/'public.json');private=app.read(alliance/'secret.json');core.validate_alliance(public,private)
    ac.need(public['key_id']==e.system['config']['key_id'] and public['setup_id']==e.system['config']['setup_id'] and public['pairing_public_key_hex']==e.system['config']['pairing_key'] and public['schnorr_public_key_hex']==e.system['config']['schnorr_key'],'Alliance does not match chain')
    if private_path.exists():
        capability=app.read(private_path);ac.need(capability['binding']==binding,'Batch already used for another capability')
        print('Existing capability reused; no new set/key issuance.')
    else:
        state_path=e.root/'private/node6/batches'/e.batch['t'][2:]/'state.json'
        state=app.read(state_path);e.hb.crypto.validate_private(core,e.context,e.system['config'],a.batch,state)
        ac.need(state['public']==e.batch,'Private batch differs from chain')
        keys,metrics=ac.compute_keys(core,e.batch['t'],ac.raw(intent['digest_hex']),int(private['pairing_secret_hex'],16),int(state['xi_hex'],16))
        capability={'format':'hecate-private-capability-v1','binding':binding,**keys}
        ac.verify_keys(core,e.batch['t'],ac.raw(intent['digest_hex']),capability,ac.raw(e.system['config']['pairing_key']),ac.raw(e.batch['U_hex']))
        app.save(private_path,capability);app.save(folder/'computekey_metrics.json',metrics)
        del state,keys
    ac.verify_keys(core,e.batch['t'],ac.raw(intent['digest_hex']),capability,ac.raw(e.system['config']['pairing_key']),ac.raw(e.batch['U_hex']))
    for recipient in intent['recipients']:
        rb=recipient_binding(app,intent,recipient['receiver_id'])
        envelope_path=folder/'recipients'/recipient['receiver_id']/'capability-envelope.json'
        if envelope_path.exists():
            envelope=app.read(envelope_path);ac.need(envelope['binding']==rb,'Delivery scope changed')
            ac.verify_signature(core,core.canonical({k:v for k,v in envelope.items() if k!='signature'}),envelope['signature'],ac.raw(e.system['config']['schnorr_key']))
        else:
            envelope=ac.seal(core,rb,capability,ac.raw(recipient['receiver_public_key_hex']),int(private['schnorr_secret_hex'],16))
            app.save(envelope_path,envelope)
        print('Recipient envelope:',envelope_path)
    del private,capability
    print('ComputeKey: one capability pair, 96 raw bytes; envelopes:',len(intent['recipients']))
    print('No capability or envelope submitted to blockchain.')

def deliver(a,app,e,d,stores):
    intent,_=verify_grant(app,e,d);core=app.core
    binding=recipient_binding(app,intent,a.receiver_id)
    folder=paths(e)/'recipients'/binding['receiver_id']
    envelope=app.read(folder/'capability-envelope.json');ac.need(envelope['binding']==binding,'Delivery binding')
    ac.verify_signature(core,core.canonical({k:v for k,v in envelope.items() if k!='signature'}),envelope['signature'],ac.raw(e.system['config']['schnorr_key']))
    # The label is only an inbox path; receiver ID and public key determine the cryptographic recipient.
    dest=e.root/'private/node5'/a.receiver_name/'authorizations'/e.batch['t'][2:]/binding['receiver_id']/'capability-envelope.json'
    app.same_save(dest,envelope)
    app.same_save(folder/'DELIVERY.json',{'receiver_id':binding['receiver_id'],'envelope_sha256':app.digest(core.canonical(envelope)),
        'destination':str(dest),'status':'sealed envelope placed in receiver inbox; receiver acknowledgment pending'})
    print('Private inbox:',dest)
    print('No blockchain transaction. xi is retained until all receiver acknowledgments; no secure-erasure claim.')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=['preflight','deploy','digest','publish','check-digest','compute-key','deliver'])
    p.add_argument('--root',default='/home/Hecate_2/hecate-app');p.add_argument('--batch',default='batch0001')
    p.add_argument('--run',default='eight-ctr-64k-02');p.add_argument('--senders',nargs='+',default=['DS01','DS02','DS03','DS04'])
    p.add_argument('--selection',help='JSON list of {run,sender}; combines records across runs of the SAME batch')
    p.add_argument('--receiver-id',default='0x20860f24446f40135192ff050227e5e287c64d0df7c204d561f6dd7d89f79231')
    p.add_argument('--receiver-name',default='dr01');p.add_argument('--solc',default='/home/Hecate_2/hecate-app/tools/solc-0.8.24')
    p.add_argument('--timeout',type=int,default=300);p.add_argument('--confirmations',type=int,default=2)
    a=p.parse_args();ac.need(a.timeout>0 and a.confirmations>=0,'Wait parameters')
    ac.need(all(re.fullmatch('[A-Za-z0-9_-]{1,64}',x) for x in [a.run,a.receiver_name]),'Invalid path label')
    app,e,d,stores=environment(a)
    lock=e.root/'private/node6/authorization.lock';lock.parent.mkdir(parents=True,exist_ok=True)
    with e.pp.reg.deployment_lock(lock):globals()[a.command.replace('-','_')](a,app,e,d,stores)
if __name__=='__main__':main()
