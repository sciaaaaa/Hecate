"""Read-only chain receiver experiment. Requires receiver secret, never node6 secrets."""
import argparse,csv,hashlib,importlib,json,math,os,re,statistics,sys,time
from pathlib import Path
import adec_crypto as dc

def read(p):return json.loads(Path(p).read_text('utf-8-sig'))
def digest(data):return hashlib.sha256(data).hexdigest()
def write(p,data):
    p=Path(p);p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
def save(p,obj):write(p,(json.dumps(obj,indent=2,ensure_ascii=False)+'\n').encode())

def field_schema(value,prefix=''):
    if isinstance(value,dict):
        for key,v in value.items():
            label=prefix+'.'+key if prefix else key
            if isinstance(v,dict):yield from field_schema(v,label)
            else:yield {'field':label,'type':type(v).__name__}

def load_secret(path,field,encoding,core,expected_pk):
    doc=read(path)
    if field:
        value=doc
        for key in field.split('.'):value=value[key]
        candidates=[(field,value)]
    else:
        accepted={'receiver_secret_hex','receiver_sk_hex','sk_dr_hex','secret_scalar_hex','scalar_hex','sk_hex','beta_hex','secret_key_hex',
            'private_key_hex','hecate_secret_hex','secret_hex','receiver_secret','secret_scalar','beta','sk','sk_dr','scalar','private_key'}
        candidates=[]
        for item in field_schema(doc):
            if item['field'].split('.')[-1] in accepted:
                value=doc
                for key in item['field'].split('.'):value=value[key]
                candidates.append((item['field'],value))
    matches=[]
    for name,value in candidates:
        try:
            if type(value) is int:n=value
            elif isinstance(value,str):
                base=16 if encoding=='hex' or (encoding=='auto' and (name.endswith('_hex') or value.startswith('0x'))) else 10
                n=int(value,base)
            else:continue
            if 0<n<core.curve_order and core.enc_g2(core.multiply(core.G2,n))==expected_pk:matches.append(n)
        except (ValueError,TypeError):continue
    dc.need(len(set(matches))==1,'Cannot identify a matching receiver scalar. Run inspect-key; specify --secret-field and --secret-encoding. Encrypted keystores need their original decryptor; do not regenerate the key.')
    return matches[0]

def modules(root):
    sys.path[:0]=[str(root/'authorization-v2'),str(root/'aenc-chain-v1')]
    return importlib.import_module('authorize'),importlib.import_module('auth_crypto')

def acquire(a,out):
    started=time.perf_counter_ns();az,ac=modules(Path(a.root).resolve())
    print('Reading authenticated system/batch/cipher/authorization contracts...',flush=True)
    app,e,d,stores=az.environment(a);auth,grants=az.auth_stores(app,e,d)
    observed=[c.functions.get(dc.raw(e.batch['t'])).call(block_identifier=e.height) for c in grants]
    dc.need(all(g==observed[0] for g in observed),'Grant RPC disagreement')
    g=observed[0];dc.need(g[0],'Batch has no finalized authorization')
    senders=list(g[1]);ids=[bytes(x).hex() for x in g[2]];receivers=[bytes(x).hex() for x in g[4]]
    dc.need(1<=len(ids)<=e.system['config']['B'] and len(ids)==len(senders)==len(receivers),'Grant array lengths')
    dc.need([int(x,16) for x in ids]==sorted(set(int(x,16) for x in ids)),'Grant IDs not sorted/distinct')
    intent={'binding':az.base_binding(app,e,d,auth),'senders':senders,'ids':ids,'digest_hex':bytes(g[3]).hex(),
        'receivers':receivers,'recipients':[az.receiver_info(app,e,r) for r in sorted(set(receivers))]}
    rid=dc.raw(a.receiver_id).hex();binding=az.recipient_binding(app,intent,rid)
    pkdr=dc.raw(binding['receiver_public_key_hex'])
    print('Fetching public SRS and verifying power relations; this can take time...',flush=True)
    mark=time.perf_counter_ns();manifest,srs=app.setup(e,out)
    srs_wall=dc.elapsed(mark)
    records=[]
    for i,(address,identifier,recipient) in enumerate(zip(senders,ids,receivers)):
        key=e.chains[0].keccak(dc.raw(address)+dc.raw(e.batch['t'])+dc.raw(identifier))
        rs=[c.functions.get(key).call(block_identifier=e.height) for c in stores]
        dc.need(all(r==rs[0] for r in rs),'Cipher metadata RPC disagreement')
        r=rs[0]
        dc.need(r[9] and r[0].lower()==address.lower() and bytes(r[1])==dc.raw(e.batch['t']) and bytes(r[2]).hex()==identifier and bytes(r[3]).hex()==recipient,'Finalized record binding')
        if recipient!=rid:continue
        dc.need(0<r[5]<=64*1024*1024 and r[6]==(r[5]+4095)//4096,'Cipher chunk metadata')
        payload=None
        for c in stores:
            data=b''.join(bytes(c.functions.getChunk(key,j).call(block_identifier=e.height)) for j in range(r[6]))
            dc.need(len(data)==r[5] and app.commitment(data)==bytes(r[7])==bytes(r[8]),'Cipher bytes/commitment mismatch')
            if payload is None:payload=data
            else:dc.need(payload==data,'Cipher byte RPC disagreement')
        tx=json.loads(payload)
        expected=dict(app.bindings(e,d,address),receiver_id=rid)
        dc.need(tx['binding']==expected and tx['id_hex']==identifier and tx['pk_ds_hex']==bytes(r[4]).hex(),'Record payload mismatch')
        records.append({'record':f'record-{i+1:04d}','sender_address':address,'id':identifier,'tx':tx,'binding':expected,'wire_bytes':len(payload)})
        write(out/'chain-ciphertexts'/(identifier+'.json'),payload)
        print('Fetched authorized ciphertext:',identifier[:16],flush=True)
    dc.need(records,'No authorized ciphertext for this receiver')
    dc.need(all(e.pp.hx(w.eth.get_block(e.height)['hash'])==e.bh for w in e.chains),'Pinned chain block changed')
    bootstrap={'chain_load_validate_wall_ms':dc.elapsed(started),'srs_load_validate_wall_ms':srs_wall,
        'verified_block':e.height,'block_hash':e.bh,'set_count':len(ids),'receiver_record_count':len(records),
        'note':'One-time mixed RPC, validation and cache IO. SRS time is a subset, do not add it again.'}
    save(out/'authenticated-authorization.json',intent)
    mark=time.perf_counter_ns();secret=load_secret(a.secret_file,a.secret_field,a.secret_encoding,app.core,pkdr)
    bootstrap['receiver_secret_load_check_ms']=dc.elapsed(mark)
    envelope_path=Path(a.envelope) if a.envelope else e.root/'private/node5'/a.receiver_name/'authorizations'/e.batch['t'][2:]/rid/'capability-envelope.json'
    mark=time.perf_counter_ns();envelope=read(envelope_path);bootstrap['envelope_read_ms']=dc.elapsed(mark)
    mark=time.perf_counter_ns();cap=ac.unseal(app.core,envelope,binding,secret,dc.raw(e.system['config']['schnorr_key']))
    expected_cap_binding=dict(intent['binding'],authorization_sha256=app.digest(app.core.canonical(intent)))
    dc.need(cap['format']=='hecate-private-capability-v1' and cap['binding']==expected_cap_binding,'Private capability scope mismatch')
    bootstrap['delivery_verify_unseal_ms']=dc.elapsed(mark)
    save(out/'bootstrap.json',bootstrap)
    return app,e,ac,intent,cap,srs,records,pkdr,secret,bootstrap

def summarize(rows,fields):
    result={}
    for field in fields:
        values=sorted(float(r[field]) for r in rows);n=len(values)
        result[field]={'n':n,'mean':statistics.mean(values),'median':statistics.median(values),
            'stdev':statistics.stdev(values) if n>1 else 0.0,'p95':values[max(0,math.ceil(.95*n)-1)]}
    return result

def run(a):
    root=Path(a.root).resolve()
    out=Path(a.out).resolve() if a.out else root/'private/node5'/a.receiver_name/'adec-runs'/a.run
    dc.need(not out.exists(),'Output directory already exists; select a new --run or --out, preserving previous results')
    out.mkdir(parents=True,mode=0o700)
    try:
        app,e,ac,intent,cap,srs,records,pkdr,secret,bootstrap=acquire(a,out)
        core=app.core;all_rows=[];shared_rows=[];totals=[];reference={}
        fields=['repeat','record','sender_address','id','im_bytes','verify_ms','overt_decrypt_ms','hidden_incremental_ms','decrypt_total_ms','record_total_ms']
        shared_fields=['repeat','batch_verify_ms','digest_verify_ms','overt_key_verify_ms','hidden_key_verify_ms','shared_verify_ms']
        with (out/'raw.csv').open('x',newline='',encoding='utf-8') as rf,(out/'shared.csv').open('x',newline='',encoding='utf-8') as sf:
            rw=csv.DictWriter(rf,fields);sw=csv.DictWriter(sf,shared_fields);rw.writeheader();sw.writeheader()
            for repeat in range(-a.warmups,a.repeats):
                auth,shared=dc.verify_shared(core,app.bc,ac,e.context,e.system['config'],a.batch,e.batch,intent,cap,srs)
                trial=[]
                for record in records:
                    v,vm=dc.verify_record(core,app.engine,e.batch,record['tx'],record['binding'],pkdr,secret,auth)
                    im,theta,om=dc.open_overt(core,app.engine,ac,v,auth,srs)
                    em,index,hm=dc.open_hidden(core,app.engine,v,auth,theta)
                    stamp=(digest(im),em.hex(),index.hex())
                    if record['id'] in reference:dc.need(reference[record['id']]==stamp,'Repeated opening differs')
                    else:reference[record['id']]=stamp
                    if a.expect_em is not None:dc.need(em==a.expect_em.encode().ljust(16,b'\0'),'Recovered em differs from --expect-em')
                    row=dict(repeat=repeat,record=record['record'],sender_address=record['sender_address'],id=record['id'],im_bytes=len(im),
                        verify_ms=vm,overt_decrypt_ms=om,hidden_incremental_ms=hm,decrypt_total_ms=om+hm,record_total_ms=vm+om+hm)
                    if repeat>=0:rw.writerow(row);rf.flush();all_rows.append(row);trial.append(row)
                    if repeat==0:
                        folder=out/'recovered'/record['id'];write(folder/'im.bin',im)
                        save(folder/'hidden.json',{'em_hex':em.hex(),'em_text_zero_padding_removed':em.rstrip(b'\0').decode('utf-8',errors='replace'),
                            'ind_star_hex':index.hex(),'note':'Recovered index, not proof of node6 repository membership; no rd request performed.'})
                    print(f"repeat={repeat} {record['record']} verify={vm:.3f}ms overt={om:.3f}ms hidden_increment={hm:.3f}ms",flush=True)
                if repeat>=0:
                    sr=dict(repeat=repeat,**shared);sw.writerow(sr);sf.flush();shared_rows.append(sr)
                    totals.append({'repeat':repeat,'verification_total_ms':shared['shared_verify_ms']+sum(r['verify_ms'] for r in trial),
                        'overt_total_ms':sum(r['overt_decrypt_ms'] for r in trial),'hidden_increment_total_ms':sum(r['hidden_incremental_ms'] for r in trial),
                        'algorithm_total_ms':shared['shared_verify_ms']+sum(r['record_total_ms'] for r in trial)})
        measurements=fields[5:]
        with (out/'summary.csv').open('x',newline='',encoding='utf-8') as f:
            writer=csv.DictWriter(f,['record','sender_address','id','im_bytes','n']+[m+'_'+s for m in measurements for s in ('mean','median','stdev','p95')]);writer.writeheader()
            for record in records:
                rr=[r for r in all_rows if r['id']==record['id']];stats=summarize(rr,measurements)
                row={k:rr[0][k] for k in ('record','sender_address','id','im_bytes')};row['n']=len(rr)
                row.update({m+'_'+s:stats[m][s] for m in measurements for s in ('mean','median','stdev','p95')});writer.writerow(row)
        save(out/'totals.json',{'per_repeat':totals,'summary':summarize(totals,list(totals[0])[1:]),
            'shared_summary':summarize(shared_rows,shared_fields[1:]),'timing_scope':'Warmups excluded. Sequential hidden increment reuses overt theta. No RPC/disk IO in algorithm timers. Bootstrap and envelope costs separate.'})
        save(out/'SUCCESS.json',{'batch':e.batch['t'],'receiver_id':dc.raw(a.receiver_id).hex(),'records':len(records),'repeats':a.repeats,
            'outputs_verified_consistent':True,'chain_transactions_sent':0,'rd_retrieved':False})
        print('Completed:',out,flush=True)
    except Exception as exc:
        save(out/'FAILED.json',{'error_type':type(exc).__name__,'note':'No SUCCESS.json; partial measurements must not be reported as a completed experiment.'})
        raise

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['inspect-key','run'])
    p.add_argument('--root',default='/home/Hecate_2/hecate-app');p.add_argument('--batch',default='batch0001')
    p.add_argument('--receiver-name',default='dr01');p.add_argument('--receiver-id',default='0x20860f24446f40135192ff050227e5e287c64d0df7c204d561f6dd7d89f79231')
    p.add_argument('--secret-file',default='/home/Hecate_app/private/node5/dr01/secret.json')
    p.add_argument('--secret-field');p.add_argument('--secret-encoding',choices=['auto','hex','decimal'],default='auto')
    p.add_argument('--envelope');p.add_argument('--out');p.add_argument('--run',default='batch0001-dr01-r10')
    p.add_argument('--repeats',type=int,default=10);p.add_argument('--warmups',type=int,default=1)
    p.add_argument('--confirmations',type=int,default=2);p.add_argument('--expect-em')
    a=p.parse_args()
    dc.need(a.repeats>0 and a.warmups>=0 and a.confirmations>=0,'Invalid repeat/warmup/confirmation count')
    dc.need(all(re.fullmatch('[A-Za-z0-9_-]{1,64}',v) for v in [a.receiver_name,a.run]),'Invalid path label')
    dc.need(a.expect_em is None or len(a.expect_em.encode())<=16,'em exceeds 16 bytes')
    if a.command=='inspect-key':print(json.dumps(list(field_schema(read(a.secret_file))),indent=2));return
    run(a)

if __name__=='__main__':main()
