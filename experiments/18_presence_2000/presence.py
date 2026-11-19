"""100+100 sequential on-chain pilot. Experimental ordinary-format control.
No deployment or replacement of the existing cryptographic modules/contracts.
"""
import argparse,collections,csv,hashlib,inspect,json,math,os,random,re,secrets,sys,time
from pathlib import Path
from types import SimpleNamespace as NS

LABEL='presence-p100-1k-02'
IM_BYTES=1024
RID='0x20860f24446f40135192ff050227e5e287c64d0df7c204d561f6dd7d89f79231'
def need(ok,msg):
    if not ok:raise ValueError(msg)
def read(p):return json.loads(Path(p).read_text('utf-8-sig'))
def sha(b):return hashlib.sha256(b).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def save(p,x):
    data=canonical(x);p=Path(p);p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if p.exists():need(p.read_bytes()==data,'Existing file differs: '+str(p));return
    fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
def ordinary_function(engine,core):
    source=inspect.getsource(engine.aenc);old='kc=capsule_encode(core,em,K,dk,ctx)'
    need(source.count(old)==1,'Unexpected engine source')
    ns=dict(engine.__dict__)
    exec(compile(source.replace(old,'kc=secrets.randbelow(core.Q-1)+1'),'<ordinary-control>','exec'),ns)
    return ns['aenc']
def make_schedule(pairs,seed):
    rng=random.Random(seed);rows=[]
    for block in range((pairs+9)//10):
        group=[]
        for pair in range(block*10,min((block+1)*10,pairs)):
            for label in (0,1):group.append(dict(sample_id=secrets.token_hex(16),pair_id=pair,label=label,generation_block=block))
        rng.shuffle(group);rows+=group
    for i,row in enumerate(rows):row['upload_order']=i
    return rows
def byte_features(data,prefix):
    counts=collections.Counter(data);n=len(data)
    return {prefix+'_bytes':n,prefix+'_zero_bytes':counts.get(0,0),
            prefix+'_entropy':-sum((v/n)*math.log2(v/n) for v in counts.values()) if n else 0}
def feature_row(sample,txrows,payload):
    chunks=[r for r in txrows if r['action'].startswith('chunk-')]
    vals=[r['gas_used'] for r in chunks];avg=sum(vals)/len(vals)
    row={'sample_id':sample,'transaction_count':len(txrows),
         'gas_total':sum(r['gas_used'] for r in txrows),
         'gas_open':next(r['gas_used'] for r in txrows if r['action']=='open'),
         'gas_finalize':next(r['gas_used'] for r in txrows if r['action']=='finalize'),
         'gas_chunk_mean':avg,'gas_chunk_std':math.sqrt(sum((v-avg)**2 for v in vals)/len(vals)),
         'gas_chunk_min':min(vals),'gas_chunk_max':max(vals),
         'calldata_bytes_total':sum(r['calldata_bytes'] for r in txrows),
         'calldata_zero_total':sum(r['calldata_zero_bytes'] for r in txrows),
         'log_count_total':sum(r['log_count'] for r in txrows),
         'log_data_bytes_total':sum(r['log_data_bytes'] for r in txrows)}
    row.update(byte_features(payload,'wire'))
    tx=json.loads(payload)
    for key in ('R_s_hex','s_s_hex','c2_hex'):row.update(byte_features(bytes.fromhex(tx[key]),key))
    return row
def write_csv(p,rows):
    import io
    out=io.StringIO(newline='');w=csv.DictWriter(out,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    data=out.getvalue().encode()
    if p.exists():need(p.read_bytes()==data,'Existing CSV differs: '+str(p));return
    with p.open('xb') as f:f.write(data)

class Pilot:
    def __init__(self,a):
        self.a=a;self.root=Path(a.root).resolve();self.work=self.root/'private/presence'/a.experiment
        need(re.fullmatch(r'[A-Za-z0-9_-]{1,40}',a.experiment),'Bad experiment name')
        self.work.mkdir(parents=True,exist_ok=True,mode=0o700)
        os.environ['HECATE_RPC_HOST']=a.rpc_host
        for name in ('aenc-chain-v1','batch-v1','ppk-v1'):
            sys.path.insert(0,str(self.root/name))
        import aenc_chain as app
        self.app=app;self.pool=self.root/'private/node4/senders-round01'
        self.args=NS(root=str(self.root),batch=a.experiment,receiver_id=a.receiver_id,confirmations=2,timeout=600)
        self.e=app.env(self.args);self.d,self.contracts=app.store(self.e)
        save(self.work/'spec.json',dict(experiment=a.experiment,pairs=a.pairs,seed=a.seed,im_bytes=IM_BYTES,
            receiver_id=a.receiver_id,chain_id=self.e.system['chain_id'],genesis_hash=self.e.system['genesis_hash'],
            batch=self.e.batch['t'],store=self.d['address'],engine_sha256=sha(Path(app.engine.__file__).read_bytes()),
            ordinary_control='independent uniform signature nonce; same outer construction',confirmations=2))
    def check_node(self,role):
        import socket
        expected={'node4':'172.31.1.251','node6':'172.31.3.139'}[role]
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.connect((self.a.rpc_host,18545));actual=s.getsockname()[0]
        need(actual==expected,'Run on '+role+'; detected '+actual)
    def prepare(self):
        self.check_node('node4');app=self.app;e=self.e
        schedule_path=self.work/'labels-private.json'
        if not schedule_path.exists():save(schedule_path,make_schedule(self.a.pairs,self.a.seed))
        schedule=read(schedule_path)
        manifest,srs=app.setup(e,self.work)
        account,_=app.account(self.pool,'DS01')
        ordinary=ordinary_function(app.engine,app.core)
        for row in schedule:
            folder=self.work/'samples'/row['sample_id'];folder.mkdir(parents=True,exist_ok=True,mode=0o700)
            ready=folder/'READY.json'
            if ready.exists():
                saved=read(ready)['records'][0]
                need(sha((folder/'ciphertexts/DS01.json').read_bytes())==saved['sha256'],'Saved ciphertext changed')
                continue
            pairpath=self.work/'inputs'/f"pair-{row['pair_id']:04d}.json"
            if not pairpath.exists():save(pairpath,dict(im=secrets.token_hex(IM_BYTES),rd=sha(secrets.token_bytes(64)),em=secrets.token_hex(16)))
            inp=read(pairpath)
            need(len(bytes.fromhex(inp['im']))==IM_BYTES,'Saved input is not 1024 bytes; use a separate experiment')
            # A crash during generation is explicit; never silently regenerate used alpha.
            marker=folder/'generation-started.json'
            need(not marker.exists(),'Incomplete generation; preserve files and inspect '+str(folder))
            save(marker,dict(started_unix=time.time(),sample_id=row['sample_id']))
            alpha=secrets.randbelow(app.core.curve_order-1)+1
            fn=app.engine.aenc if row['label']==1 else ordinary
            tx,_=fn(app.core,app.bc,manifest,srs,e.context,e.system['config'],e.batch,self.a.experiment,
                e.pkdr,bytes.fromhex(inp['im']),bytes.fromhex(inp['rd']),bytes.fromhex(inp['em']),alpha,
                app.bindings(e,self.d,account.address))
            del alpha
            save(folder/'ciphertexts/DS01.json',tx)
            data=(folder/'ciphertexts/DS01.json').read_bytes()
            summary=dict(sender='DS01',address=account.address,id=tx['id_hex'],pk_ds_hex=tx['pk_ds_hex'],
                sha256=sha(data),wire_bytes=len(data),chunks=(len(data)+4095)//4096)
            save(ready,dict(suite=app.SUITE,store=self.d['address'],batch=e.batch['t'],records=[summary]))
            print('Prepared',row['upload_order']+1,'/',len(schedule),row['sample_id'],len(data),'bytes',flush=True)
        records=[dict(sample_id=r['sample_id'],**read(self.work/'samples'/r['sample_id']/'READY.json')['records'][0]) for r in schedule]
        need(len({r['id'] for r in records})==len(records) and len({r['pk_ds_hex'] for r in records})==len(records),'Repeated Hecate key/id')
        save(self.work/'public-manifest.json',dict(spec=read(self.work/'spec.json'),records=records))
        print('PREPARED: copy public-manifest.json only to node6 for funding. Labels and inputs stay on node4.')
    def fund(self):
        self.check_node('node6');need(self.a.manifest and self.a.amount_eth,'fund requires --manifest and --amount-eth')
        doc=read(self.a.manifest);need(doc['spec']==read(self.work/'spec.json'),'Manifest spec mismatch')
        addresses={r['address'] for r in doc['records']};need(len(addresses)==1 and len(doc['records'])==2*self.a.pairs,'Manifest counts/address')
        address=next(iter(addresses));e=self.e;w=e.chains[0]
        value=w.to_wei(self.a.amount_eth,'ether');need(value>0,'Positive transfer required')
        signer=e.pp.reg.ethereum_account(self.root,e.system['config']['owner'])
        class Transfer:
            def estimate_gas(self,params):return w.eth.estimate_gas(dict(params,to=address,value=value))
            def build_transaction(self,params):return dict(params,to=address,value=value,data='0x')
        e.pp.transact(e.chains,signer,Transfer(),self.work/'funding','fund-DS01',
            {'to':address,'value':str(value),'experiment':self.a.experiment},600,2)
        print('Funding complete; excluded from detection dataset.')
    def upload(self):
        self.check_node('node4');need((self.work/'public-manifest.json').exists(),'Finish prepare first')
        records=read(self.work/'public-manifest.json')['records']
        selected=records if self.a.limit is None else records[:self.a.limit]
        for i,row in enumerate(selected):
            folder=self.work/'samples'/row['sample_id']
            print('UPLOAD',i+1,'/',len(records),row['sample_id'],flush=True)
            fresh=Pilot(self.a)
            self.app.upload(self.args,fresh.e,self.pool,folder)
        if len(selected)<len(records):
            print('Prefix complete; remaining records preserved. Run upload without --limit to finish.');return
        save(self.work/'UPLOAD_COMPLETE.json',dict(records=len(records),batch=self.e.batch['t']))
        print('All uploads finished. Run collect for canonical receipt and byte checks.')
    def collect(self):
        self.check_node('node4');need((self.work/'UPLOAD_COMPLETE.json').exists(),'Finish upload')
        e=self.e;w=e.chains[0];records=read(self.work/'public-manifest.json')['records'];features=[];alltx=[]
        labels=read(self.work/'labels-private.json');need([r['sample_id'] for r in records]==[r['sample_id'] for r in labels],'Order mismatch')
        for row in records:
            fresh=Pilot(self.a);e=fresh.e;w=e.chains[0]
            folder=self.work/'samples'/row['sample_id'];payload=(folder/'ciphertexts/DS01.json').read_bytes()
            need(sha(payload)==row['sha256'],'Local payload changed')
            key=w.keccak(bytes.fromhex(row['address'][2:])+bytes.fromhex(e.batch['t'][2:])+bytes.fromhex(row['id']))
            for contract in fresh.contracts:
                state=contract.functions.get(key).call(block_identifier=e.height)
                need(state[9] and state[5]==len(payload) and state[6]==row['chunks'],'Incomplete chain record')
                actual=b''.join(bytes(contract.functions.getChunk(key,j).call(block_identifier=e.height)) for j in range(row['chunks']))
                need(actual==payload and self.app.commitment(actual)==bytes(state[7]),'Chain bytes differ')
            actions=['open']+[f'chunk-{j:06d}' for j in range(row['chunks'])]+['finalize'];txrows=[]
            for action in actions:
                saved=read(folder/'transactions/DS01'/(action+'.receipt.json'));tx=w.eth.get_transaction(saved['tx_hash'])
                receipts=[node.eth.get_transaction_receipt(saved['tx_hash']) for node in e.chains];rc=receipts[0]
                need(all(int(r['status'])==1 and r['blockHash']==rc['blockHash'] and r['gasUsed']==rc['gasUsed'] for r in receipts),'Receipt mismatch')
                need(rc['blockNumber']<=e.height,'Insufficient confirmations for collection')
                for node in e.chains:need(node.eth.get_block(rc['blockNumber'])['hash']==rc['blockHash'],'Reorg detected')
                need(tx['from'].lower()==row['address'].lower() and tx['to'].lower()==self.d['address'].lower(),'Unexpected transaction endpoint')
                pending=read(folder/'transactions/DS01'/(action+'.pending.json'))
                need(w.keccak(bytes.fromhex(pending['raw_transaction'].removeprefix('0x'))).hex().removeprefix('0x')==saved['tx_hash'].removeprefix('0x'),'Journal hash mismatch')
                data=bytes(tx['input'])
                tr=dict(sample_id=row['sample_id'],action=action,tx_hash=saved['tx_hash'],block_number=int(rc['blockNumber']),
                    gas_used=int(rc['gasUsed']),calldata_bytes=len(data),calldata_zero_bytes=data.count(0),
                    log_count=len(rc['logs']),log_data_bytes=sum(len(bytes(x['data'])) for x in rc['logs']))
                txrows.append(tr);alltx.append(tr)
            need(all(node.eth.get_block(e.height)['hash'].hex().removeprefix('0x')==e.bh.removeprefix('0x') for node in e.chains),'Pinned record block changed')
            features.append(feature_row(row['sample_id'],txrows,payload))
            print('Collected',len(features),'/',len(records),flush=True)
        need(len({r['tx_hash'] for r in alltx})==len(alltx),'Duplicate transaction hashes')
        need(all(node.eth.get_block(e.height)['hash'].hex().removeprefix('0x')==e.bh.removeprefix('0x') for node in e.chains),'Pinned block changed')
        write_csv(self.work/'public_features.csv',features)
        write_csv(self.work/'transactions.csv',alltx)
        write_csv(self.work/'labels_private.csv',labels)
        save(self.work/'COLLECTED.json',dict(records=len(features),per_class=self.a.pairs,
            features_sha256=sha((self.work/'public_features.csv').read_bytes()),labels_sha256=sha((self.work/'labels_private.csv').read_bytes()),
            note='On-chain availability verified; not receiver decryption proof or indistinguishability proof. One batch and one ETH sender.'))
        print('COLLECTED:',self.work)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=['prepare','fund','upload','collect'])
    p.add_argument('--root',default='/home/Hecate_2/hecate-app');p.add_argument('--experiment',required=True)
    p.add_argument('--receiver-id',default=RID);p.add_argument('--rpc-host',default='172.31.27.238')
    p.add_argument('--pairs',type=int,default=100);p.add_argument('--seed',type=int,required=True)
    p.add_argument('--manifest');p.add_argument('--amount-eth')
    p.add_argument('--limit',type=int,help='upload only: finish first K entries of the saved order; default all')
    a=p.parse_args();need(a.pairs==100,'Pilot fixed at 100 pairs; validate another size separately')
    need(a.limit is None or (a.command=='upload' and 1<=a.limit<=200),'--limit requires upload and 1..200')
    obj=Pilot(a)
    # Same global sender-pool lock as the other experiments; prohibits nonce races.
    lock=obj.pool/'.aenc.lock' if a.command in ('prepare','upload') else obj.work/'phase.lock'
    with obj.e.pp.reg.deployment_lock(lock):getattr(obj,a.command)()
if __name__=='__main__':main()
