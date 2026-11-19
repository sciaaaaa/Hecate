"""Hecate aEnc prototype: adjustable em, no RPC or transaction submission.

Uses bundled hecate_bench_core.py and hecate_bench_batch.py. The demo uses fresh
in-memory test inputs; do not publish demo outputs to the operational chain.
The aenc() function accepts public inputs only, including an AUTHENTICATED
receiver public key supplied by its caller. It does not access any Pre database.
"""
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import secrets
import sys
import time

EM_BYTES=16
DEFAULT_EM_TEXT='HECATE-DEMO-0001' # exactly 16 UTF-8/ASCII bytes; change this example
FORMAT='hecate-aenc-aesctr-offline-v2'

def need(condition,message):
    if not condition: raise ValueError(message)

class EncryptionAbort(ValueError):
    """Profile-defined rare abort. Never silently retry or reduce capsule mod q."""

def hx(value): return bytes.fromhex(value.removeprefix('0x'))

def em_bytes(text=None,hex_value=None,integer=None,file=None,pad_zero=False):
    chosen=sum(x is not None for x in (text,hex_value,integer,file))
    need(chosen<=1,'Choose only one em input format')
    if hex_value is not None:
        value=hx(hex_value)
    elif integer is not None:
        number=int(integer,0) if isinstance(integer,str) else integer
        need(0<=number<2**128,'em integer must be in 0..2^128-1')
        value=number.to_bytes(16,'big')
    elif file is not None:
        with Path(file).open('rb') as handle: value=handle.read(17)
    else:
        value=(DEFAULT_EM_TEXT if text is None else text).encode('utf-8')
    original=len(value)
    need(original<=EM_BYTES,'em exceeds 16 bytes (count UTF-8 bytes, not characters)')
    if original<EM_BYTES:
        need(pad_zero,'Profile requires exactly 16 bytes. Use --pad-zero explicitly for shorter data.')
        value=value.ljust(EM_BYTES,b'\x00')
    return value,original

def capsule_encode(core,em,K,dk,ctx):
    need(len(em)==16 and len(K)==16 and len(dk)==16,'Capsule requires em16, K16, dk16')
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    enc=Cipher(algorithms.AES(dk),modes.CTR(caps_iv(core,ctx))).encryptor()
    encoded=enc.update(em+K)+enc.finalize()
    nonce=int.from_bytes(encoded,'big')
    if not 0<nonce<core.Q:
        raise EncryptionAbort('Capsule outside 1..q-1: abort; no modulo reduction or automatic retry')
    return nonce

def capsule_decode(core,nonce,dk,ctx):
    need(0<nonce<core.Q and len(dk)==16,'Invalid capsule input')
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    dec=Cipher(algorithms.AES(dk),modes.CTR(caps_iv(core,ctx))).decryptor()
    data=dec.update(nonce.to_bytes(32,'big'))+dec.finalize()
    return data[:16],data[16:]

def header_bytes(core,parts):
    return core.ser('C1',*parts)

def overt_bytes(core,parts,c2):
    return core.ser('CB',header_bytes(core,parts),c2)

def tx_bytes(core,tx):
    parts=[hx(x) for x in tx['c1_hex']]
    return core.ser('TX-DD',FORMAT.encode('ascii'),overt_bytes(core,parts,hx(tx['c2_hex'])),
                    hx(tx['R_s_hex'])+hx(tx['s_s_hex']),hx(tx['pk_ds_hex']),hx(tx['t']),hx(tx['id_hex']))

def validate_inputs(core,bc,manifest,srs,context,config,batch,label,pk_dr):
    need(manifest['B']==context['B']==config['B'],'B mismatch')
    need(manifest['setup_id']==context['setup_id']==config['setup_id'],'Setup mismatch')
    need(manifest['receiver_params_id']==context['receiver_params_id']==config['receiver_params_id'],'Receiver parameter mismatch')
    body={k:v for k,v in manifest.items() if k!='setup_id'}
    expected='0x'+hashlib.sha256(core.ser('SETUP-ID',core.canonical(body))).hexdigest()
    need(expected==manifest['setup_id'],'Manifest ID mismatch')
    need(len(srs)==48*manifest['B']+96 and hashlib.sha256(srs).hexdigest()==manifest['srs_sha256']==config['srs_sha256'].removeprefix('0x'), 'SRS integrity mismatch')
    observed=dict(manifest['parameters']);observed['pairing']=dict(observed['pairing'])
    gt_hex=observed['pairing'].pop('gt_hex')
    need(observed==core.parameters() and gt_hex==core.enc_gt(core.pairing(core.G2,core.G1)).hex(),'Unsupported Setup profile')
    bc.verify(core,context,config,label,batch)
    # Pairing keys, U and tau are nonidentity points; c1 components may be identity.
    return (core.dec_g2(pk_dr),core.dec_g2(hx(config['pairing_key'])),
            core.dec_g2(hx(batch['U_hex'])),core.dec_g2(srs[-96:]))

def aenc(core,bc,manifest,srs,context,config,batch,label,pk_dr,im,rd,em):
    """Pure sender-side aEnc. Caller authenticates deployment metadata and pk_dr.

    Inputs im/rd/em/pk_dr are bytes. em must be exactly 16 bytes. Full SRS power
    validation belongs to initial trusted Setup acquisition (the existing fetch).
    Return ONLY public ciphertext and metrics; never return alpha,K,r2,dk or em.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from py_ecc.optimized_bls12_381 import neg
    need(all(isinstance(v,bytes) for v in (pk_dr,im,rd,em)),'Byte inputs required')
    need(len(em)==16,'Existing v1 profile requires exactly 16-byte em')
    started=time.perf_counter_ns()
    pkdr,pkal,U,tau2=validate_inputs(core,bc,manifest,srs,context,config,batch,label,pk_dr)
    validation_ms=(time.perf_counter_ns()-started)/1e6
    started=time.perf_counter_ns();cpu=time.process_time_ns()
    t=hx(batch['t']);auth=hx(batch['auth_hex'])
    alpha=secrets.randbelow(core.curve_order-1)+1
    pkds=core.multiply(core.G2,alpha);pkds_raw=core.enc_g2(pkds)
    identifier=core.h_id(core.ser('SID',auth,pkds_raw));idraw=identifier.to_bytes(32,'big')
    ctx=core.h_ctx(core.ser('CTX',auth,pkds_raw,pk_dr))
    ht=core.h_batch(t)
    K=secrets.token_bytes(16)
    mask=core.f_p(K,core.ser('RD-MASK',ctx))
    r2=(core.h_id(core.ser('RD',rd))+mask)%core.curve_order
    if r2==0: raise EncryptionAbort('r2=0: v1 profile aborts, without resampling K')
    rho=secrets.randbelow(core.curve_order)
    c11=core.add(core.multiply(core.G2,rho),core.multiply(core.add(pkal,U),r2))
    c12=core.multiply(core.add(core.multiply(core.G2,identifier),neg(tau2)),rho)
    c13=neg(core.multiply(core.G2,r2))
    parts=[core.enc_g2(c) for c in (c11,c12,c13)]
    theta=core.pairing(pkal,ht)**r2
    theta_raw=core.enc_gt(theta)
    kov=core.kdf(core.ser('OVERT',theta_raw,header_bytes(core,parts),idraw,pkds_raw,pk_dr,ctx))
    nonce=secrets.token_bytes(12)
    c2=nonce+AESGCM(kov).encrypt(nonce,im,ctx) # 12-byte nonce || ciphertext || 16-byte tag
    base=core.enc_g2(core.multiply(pkdr,alpha))
    sst=core.enc_gt(core.pairing(U,core.multiply(ht,alpha)))
    shared=core.bkdf(core.ser('DS-KEY',base,pkds_raw,pk_dr,ctx))
    Pi=core.sig_public(shared)
    dk=core.kdf(core.ser('HIDDEN',sst,base,theta_raw,ctx))
    kc=capsule_encode(core,em,K,dk,ctx)
    Rs=core.sig_public(kc)
    # Follow draft aEnc: Ms=Ser(DS-MSG,CB,ctx). Pi is already in the challenge.
    Ms=core.ser('DS-MSG',overt_bytes(core,parts,c2),ctx)
    es=core.h_sig(core.ser('DS-SCHNORR',Rs,Ms,Pi))
    ss=(kc+es*shared)%core.Q
    compute_ms=(time.perf_counter_ns()-started)/1e6
    cpu_ms=(time.process_time_ns()-cpu)/1e6
    started=time.perf_counter_ns()
    tx={'format':FORMAT,'t':batch['t'],'id_hex':idraw.hex(),'pk_ds_hex':pkds_raw.hex(),
        'c1_hex':[x.hex() for x in parts],'c2_hex':c2.hex(),'R_s_hex':Rs.hex(),
        's_s_hex':ss.to_bytes(32,'big').hex()}
    binary=tx_bytes(core,tx)
    json_data=(json.dumps(tx,sort_keys=True,indent=2)+'\n').encode()
    serialization_ms=(time.perf_counter_ns()-started)/1e6
    metrics={'input_validation_wall_ms':validation_ms,'compute_wall_ms':compute_ms,
        'compute_cpu_ms':cpu_ms,'serialize_wall_ms':serialization_ms,
        'aenc_wall_ms':compute_ms+serialization_ms,'em_fixed_bytes':16,'im_bytes':len(im),'rd_bytes':len(rd),
        'c1_raw_bytes':288,'c2_bytes':len(c2),'signature_bytes':65,'pk_ds_bytes':96,
        'tx_raw_field_bytes':288+len(c2)+65+96+32+32,
        'tx_serialized_bytes':len(binary),'tx_json_bytes':len(json_data),
        'note':'aenc_wall_ms excludes input checks, disk/RPC/chain IO and demo recovery. Includes point/GT encodings used in hashing. Byte counts exclude network/ABI/gas overhead.'}
    return tx,metrics

def _demo_recover(core,manifest,srs,batch,pk_dr,receiver_secret,alliance_secret,xi,tx):
    """Correctness check ONLY: authorized singleton S={id}. Not a deployed aDec service.

    Derives authorized keys using demo authority secrets, never uses sender's
    alpha/rho/r2/K/kc/dk. No database lookup or authorization policy is simulated.
    """
    from py_ecc.optimized_bls12_381 import neg
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    need(tx['format']==FORMAT and tx['t']==batch['t'],'Wrong ciphertext batch')
    pkds_raw=hx(tx['pk_ds_hex']);pkds=core.dec_g2(pkds_raw)
    idraw=hx(tx['id_hex']);identifier=int.from_bytes(idraw,'big')
    need(len(idraw)==32 and identifier<core.curve_order,'Bad id')
    auth=hx(batch['auth_hex'])
    need(identifier==core.h_id(core.ser('SID',auth,pkds_raw)),'Sender ID mismatch')
    ctx=core.h_ctx(core.ser('CTX',auth,pkds_raw,pk_dr))
    ht=core.h_batch(hx(tx['t']))
    ds=core.add(core.dec_g1(srs[:48]),neg(core.multiply(core.G1,identifier)))
    skS=core.add(core.multiply(core.add(ds,ht),alliance_secret),core.multiply(ds,xi))
    dsk=core.multiply(ht,xi)
    parts=[hx(x) for x in tx['c1_hex']]
    need(len(parts)==3,'Wrong c1 arity')
    points=[core.dec_g2(x,allow_identity=True) for x in parts]
    theta=(core.pairing(points[0],ds)*core.pairing(points[1],core.G1)*core.pairing(points[2],skS)).inv()
    theta_raw=core.enc_gt(theta)
    base=core.enc_g2(core.multiply(pkds,receiver_secret))
    shared=core.bkdf(core.ser('DS-KEY',base,pkds_raw,pk_dr,ctx));Pi=core.sig_public(shared)
    Rs=hx(tx['R_s_hex']);sraw=hx(tx['s_s_hex']);ss=int.from_bytes(sraw,'big')
    need(len(sraw)==32 and ss<core.Q,'Bad signature scalar')
    c2=hx(tx['c2_hex']);need(len(c2)>=28,'Truncated AEAD ciphertext')
    Ms=core.ser('DS-MSG',overt_bytes(core,parts,c2),ctx)
    es=core.h_sig(core.ser('DS-SCHNORR',Rs,Ms,Pi))
    kc=(ss-es*shared)%core.Q
    need(kc!=0 and core.sig_public(kc)==Rs,'Sender signature verification failed')
    kov=core.kdf(core.ser('OVERT',theta_raw,header_bytes(core,parts),idraw,pkds_raw,pk_dr,ctx))
    im= AESGCM(kov).decrypt(c2[:12],c2[12:],ctx)
    sst=core.enc_gt(core.pairing(pkds,dsk))
    dk=core.kdf(core.ser('HIDDEN',sst,base,theta_raw,ctx))
    em,K=capsule_decode(core,kc,dk,ctx)
    mask=core.f_p(K,core.ser('RD-MASK',ctx))
    rd_index=core.add(neg(points[2]),neg(core.multiply(core.G2,mask)))
    return im,em,core.enc_g2(rd_index)

def demo_fixture(core,bc,B=4096):
    manifest,srs,_=core.make_setup(B,'0x'+'11'*32)
    # These are ephemeral labels/addresses for offline fixtures, not chain deployments.
    owner='0x'+'22'*20
    pub,secret,_=core.make_alliance(manifest['setup_id'],owner)
    config={'B':B,'setup_id':manifest['setup_id'],'key_id':pub['key_id'],
        'receiver_params_id':manifest['receiver_params_id'],'srs_sha256':'0x'+manifest['srs_sha256'],
        'owner':owner,'pairing_key':pub['pairing_public_key_hex'],'schnorr_key':pub['schnorr_public_key_hex']}
    system={'config':config,'chain_id':1,'genesis_hash':'0x'+'33'*32,'address':'0x'+'44'*20}
    context=bc.scope(system,{'address':'0x'+'55'*20},'0x'+'66'*20)
    label='offline-aenc-aesctr-v2'
    batch_state=bc.generate(core,context,config,label,bc.metadata(context,label,1000000,'OFFLINE TEST ONLY'),int(secret['schnorr_secret_hex'],16))
    receiver=secrets.randbelow(core.curve_order-1)+1
    pkdr=core.enc_g2(core.multiply(core.G2,receiver))
    inputs=(manifest,srs,context,config,batch_state['public'],label,pkdr)
    recovery=(receiver,int(secret['pairing_secret_hex'],16),int(batch_state['xi_hex'],16))
    return inputs,recovery

def caps_iv(core,ctx):
    need(len(ctx)==32,'ctx must be 32 bytes')
    value=bytearray(hashlib.sha256(core.ser('CAPS-AES-CTR-IV-v2',ctx)).digest()[:16])
    value[-1] &= 0xfe
    return bytes(value)

def load_modules(root=None):
    here=str(Path(__file__).resolve().parent)
    sys.path.insert(0,here)
    return importlib.import_module('hecate_bench_core'),importlib.import_module('hecate_bench_batch')

def write_json_new(path,doc):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w',encoding='utf-8',newline='\n') as f:
        json.dump(doc,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())

# Offline experiment driver. No RPC, wallets or chain submissions.
import csv
import random
import statistics
import platform
import zipfile
import urllib.request
import re
import importlib.metadata

def file_hash(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
    return h.hexdigest()

def new_dir(path):
    p=Path(path);p.mkdir(parents=True,exist_ok=False);return p

def prepare(args):
    out=new_dir(args.out)
    core,bc=load_modules()
    print('Preparing independent OFFLINE AES-CTR profile; B=',args.B,flush=True)
    inputs,privates=demo_fixture(core,bc,args.B)
    manifest,srs,context,config,batch,label,pkdr=inputs
    em,_=em_bytes(text='urgent',pad_zero=True)
    rd=b'offline setup self-test RD';im=b'offline setup self-test IM'
    tx,metrics=aenc(core,bc,*inputs,im,rd,em)
    recovered=_demo_recover(core,manifest,srs,batch,pkdr,*privates,tx)
    expected=core.enc_g2(core.multiply(core.G2,core.h_id(core.ser('RD',rd))))
    need(recovered==(im,em,expected),'Preparation round-trip failed')
    # No receiver or alliance secret is persisted. Benchmarks load only this public bundle.
    core.write_bytes(out/'srs.bin',srs)
    write_json_new(out/'public.json',dict(format=FORMAT,test_only=True,manifest=manifest,
        context=context,config=config,batch=batch,label=label,pk_dr_hex=pkdr.hex(),
        recovery_selftest=True,rd_precondition='Caller supplies RD file; membership not checked by sender'))
    print('READY:',out.resolve(),flush=True)

def load_public(path):
    p=Path(path);d=json.loads((p/'public.json').read_text('utf-8'))
    need(d['format']==FORMAT and d['test_only'] is True,'Wrong offline profile')
    return (d['manifest'],(p/'srs.bin').read_bytes(),d['context'],d['config'],
        d['batch'],d['label'],hx(d['pk_dr_hex']))

def dataset(args):
    out=Path(args.out);need(not out.exists(),'Dataset output exists; choose a new version')
    downloads=Path(args.downloads);downloads.mkdir(parents=True,exist_ok=True)
    candidates=[];archives={};source_info=[]
    for name in args.archives:
        need(re.fullmatch(r'\d{3}',name) is not None,'Archive name must be 3 digits')
        archive=downloads/(name+'.zip')
        url='https://downloads.digitalcorpora.org/corpora/files/govdocs1/zipfiles/'+name+'.zip'
        if not archive.exists():
            need(args.download,'Missing '+str(archive)+'; use --download or upload the ZIP')
            partial=downloads/(name+'.zip.part')
            print('Downloading',url,flush=True)
            with urllib.request.urlopen(url,timeout=90) as source,partial.open('wb') as target:
                while True:
                    block=source.read(1024*1024)
                    if not block: break
                    target.write(block)
            with zipfile.ZipFile(partial) as z: need(z.testzip() is None,'ZIP CRC failure')
            partial.replace(archive)
        with zipfile.ZipFile(archive) as z:
            need(z.testzip() is None,'ZIP CRC failure')
            for j,info in enumerate(z.infolist()):
                leaf=info.filename.replace('\\','/').rsplit('/',1)[-1]
                if not info.is_dir() and re.fullmatch(r'\d+(?:\.[^/]+)?',leaf):
                    candidates.append((name,j,info.filename,info.file_size))
        archives[name]=archive
        source_info.append(dict(archive=name+'.zip',url=url,sha256=file_hash(archive)))
    need(len(candidates)>=args.count,f'Only {len(candidates)} eligible files; need {args.count}; add another archive')
    candidates.sort();random.Random(args.seed).shuffle(candidates)
    files=new_dir(out/'files');records=[]
    for i,(name,j,member,size) in enumerate(candidates[:args.count],1):
        dest=files/f'{i:04d}.bin'
        with zipfile.ZipFile(archives[name]) as z,z.open(z.infolist()[j]) as source,dest.open('xb') as target:
            while True:
                b=source.read(1024*1024)
                if not b: break
                target.write(b)
        need(dest.stat().st_size==size,'Extracted size mismatch')
        records.append(dict(position=i,file=dest.relative_to(out).as_posix(),bytes=size,
            sha256=file_hash(dest),source_archive=name+'.zip',source_member=member))
    write_json_new(out/'manifest.json',dict(format='govdocs-im-manifest-v1',seed=args.seed,
        file_count=len(records),unique_content_count=len({r['sha256'] for r in records}),
        total_plaintext_bytes=sum(r['bytes'] for r in records),archives=source_info,records=records))
    print('DATASET READY:',out.resolve(),'files=',len(records),flush=True)

def rows_file(path,fields):
    f=Path(path).open('x',newline='',encoding='utf-8');w=csv.DictWriter(f,fieldnames=fields);w.writeheader();return f,w

def benchmark(args):
    core,bc=load_modules()
    need(args.repeats>0 and args.warmups>=0,'Invalid repeats/warmups')
    out=new_dir(args.out);t=time.perf_counter_ns();inputs=load_public(args.bundle)
    validate_inputs(core,bc,*inputs)
    load_ms=(time.perf_counter_ns()-t)/1e6
    t=time.perf_counter_ns()
    rd=Path(args.rd_file).read_bytes() if args.rd_file else b'R'*65536
    rd_read_ms=(time.perf_counter_ns()-t)/1e6
    em,_=em_bytes(text=args.em,pad_zero=True)
    dataset_root=None;records=[]
    if args.command=='bench-real':
        dataset_root=Path(args.dataset).resolve()
        md=json.loads((dataset_root/'manifest.json').read_text('utf-8'))
        need(len(md['records'])>=args.count,'Dataset contains fewer than requested files')
        records=md['records'][:args.count]
        need(len({r['file'] for r in records})==args.count,'Duplicate manifest paths')
        for r in records:
            p=(dataset_root/r['file']).resolve()
            need(p.is_relative_to(dataset_root) and p.is_file(),'Invalid dataset path')
        write_json_new(out/'input_manifest.json',dict(records=records,source_manifest_sha256=file_hash(dataset_root/'manifest.json')))
    else:
        need(all(n>0 for n in args.sizes),'Sizes must be positive')
        need(len(set(args.sizes))==len(args.sizes),'Duplicate sizes')
    write_json_new(out/'run.json',dict(profile=FORMAT,offline_test_identities=True,
        B=inputs[0]['B'],setup_id=inputs[0]['setup_id'],command=args.command,
        arguments=vars(args),public_load_validate_ms=load_ms,rd_read_ms=rd_read_ms,
        rd_bytes=len(rd),rd_sha256=hashlib.sha256(rd).hexdigest(),
        rd_source=args.rd_file or 'synthetic 65536 bytes of R; NOT claimed to belong to Pre',
        platform=platform.platform(),python=sys.version,
        packages={n:importlib.metadata.version(n) for n in ('py-ecc','cryptography','coincurve')},
        sources={p.name:file_hash(p) for p in Path(__file__).parent.glob('*.py')},
        note='Fresh crypto randomness every encryption. Validation repeated and timed separately. No blockchain, Pre lookup or per-record receiver decryption. Independent recovery self-test was run during prepare.'))
    fields=['repeat','position','source','im_sha256','im_bytes','rd_bytes','input_read_ms',
        'input_validation_wall_ms','compute_wall_ms','compute_cpu_ms','serialize_wall_ms','aenc_wall_ms',
        'tx_raw_field_bytes','tx_serialized_bytes','tx_json_bytes','ciphertext_sha256']
    raw_f,raw=rows_file(out/'raw.csv',fields)
    cumulative_fields=['repeat','file_count','plaintext_bytes_total','compute_ms_total','compute_cpu_ms_total',
        'serialize_ms_total','aenc_ms_total','validation_ms_total','input_read_ms_total',
        'payload_bytes_total','raw_field_bytes_total','elapsed_ms']
    cum_f,cum=rows_file(out/'cumulative.csv',cumulative_fields)
    measured=[]
    if args.save_ciphertexts: (out/'ciphertexts').mkdir()
    def encrypt_one(im,rep,pos,source,read_ms):
        imhash=hashlib.sha256(im).hexdigest() # outside the timed algorithm
        tx,m=aenc(core,bc,*inputs,im,rd,em)
        wire=tx_bytes(core,tx)
        row=dict(repeat=rep,position=pos,source=source,im_sha256=imhash,input_read_ms=read_ms,
            ciphertext_sha256=hashlib.sha256(wire).hexdigest(),**{k:m[k] for k in fields if k in m})
        raw.writerow(row);raw_f.flush();measured.append(row)
        if args.save_ciphertexts:
            (out/'ciphertexts'/f'r{rep:03d}-{pos:06d}.bin').write_bytes(wire)
        return m
    try:
        if args.command=='bench-controlled':
            # Deterministic synthetic bytes are public workload data, never cryptographic keys.
            messages={n:hashlib.shake_256(('IM:'+str(args.seed)+':'+str(n)).encode()).digest(n) for n in args.sizes}
            for n in args.sizes:
                for _ in range(args.warmups): aenc(core,bc,*inputs,messages[n],rd,em)
            jobs=[(rep,n) for rep in range(args.repeats) for n in args.sizes]
            random.Random(args.seed).shuffle(jobs)
            for pos,(rep,n) in enumerate(jobs,1):
                m=encrypt_one(messages[n],rep,pos,f'synthetic:{n}',0.0)
                print(f'[{pos}/{len(jobs)}] im={n} compute_ms={m["compute_wall_ms"]:.3f}',flush=True)
        else:
            warm=(dataset_root/records[0]['file']).read_bytes()
            for _ in range(args.warmups): aenc(core,bc,*inputs,warm,rd,em)
            for rep in range(args.repeats):
                sums={k:0 for k in cumulative_fields if k not in ('repeat','file_count','elapsed_ms')}
                begin=time.perf_counter_ns()
                for pos,r in enumerate(records,1):
                    t=time.perf_counter_ns();im=(dataset_root/r['file']).read_bytes();read_ms=(time.perf_counter_ns()-t)/1e6
                    need(len(im)==r['bytes'] and hashlib.sha256(im).hexdigest()==r['sha256'],'Dataset changed: '+r['file'])
                    m=encrypt_one(im,rep,pos,r['file'],read_ms)
                    for dest,key in [('plaintext_bytes_total','im_bytes'),('compute_ms_total','compute_wall_ms'),
                        ('compute_cpu_ms_total','compute_cpu_ms'),('serialize_ms_total','serialize_wall_ms'),
                        ('aenc_ms_total','aenc_wall_ms'),('validation_ms_total','input_validation_wall_ms'),
                        ('payload_bytes_total','tx_serialized_bytes'),('raw_field_bytes_total','tx_raw_field_bytes')]: sums[dest]+=m[key]
                    sums['input_read_ms_total']+=read_ms
                    if pos%args.step==0 or pos==args.count:
                        row=dict(repeat=rep,file_count=pos,elapsed_ms=(time.perf_counter_ns()-begin)/1e6,**sums)
                        cum.writerow(row);cum_f.flush()
                        print(f'{pos}/{args.count}: compute_s={sums["compute_ms_total"]/1000:.3f}, payload_bytes={sums["payload_bytes_total"]}',flush=True)
    finally:
        raw_f.close();cum_f.close()
    summary=[]
    for size in sorted({r['im_bytes'] for r in measured}):
        group=[r for r in measured if r['im_bytes']==size]
        values=sorted(r['compute_wall_ms'] for r in group)
        summary.append(dict(im_bytes=size,n=len(group),compute_mean_ms=statistics.mean(values),
            compute_stdev_ms=statistics.stdev(values) if len(values)>1 else 0,
            compute_median_ms=statistics.median(values),compute_p95_nearest_rank_ms=values[max(0,__import__('math').ceil(.95*len(values))-1)],
            aenc_mean_ms=statistics.mean(r['aenc_wall_ms'] for r in group),
            payload_mean_bytes=statistics.mean(r['tx_serialized_bytes'] for r in group)))
    f,w=rows_file(out/'summary.csv',list(summary[0]));w.writerows(summary);f.close()
    write_json_new(out/'COMPLETE.json',dict(records=len(measured),profile=FORMAT))
    print('COMPLETE:',out.resolve(),flush=True)

def main():
    p=argparse.ArgumentParser(description='Full Hecate sender computation, AES-CTR capsule, offline experiments only.')
    sub=p.add_subparsers(dest='command',required=True)
    q=sub.add_parser('prepare');q.add_argument('--B',type=int,default=4096);q.add_argument('--out',default='fixtures/aesctr-B4096-v2')
    q=sub.add_parser('dataset');q.add_argument('--download',action='store_true');q.add_argument('--downloads',default='downloads')
    q.add_argument('--archives',nargs='+',default=['010','011']);q.add_argument('--count',type=int,default=1000)
    q.add_argument('--seed',type=int,default=2026);q.add_argument('--out',default='datasets/govdocs-im-1000-v1')
    for name in ('bench-controlled','bench-real'):
        q=sub.add_parser(name);q.add_argument('--bundle',default='fixtures/aesctr-B4096-v2')
        q.add_argument('--rd-file');q.add_argument('--em',default='urgent');q.add_argument('--seed',type=int,default=2026)
        q.add_argument('--repeats',type=int,default=30 if name=='bench-controlled' else 1)
        q.add_argument('--warmups',type=int,default=3);q.add_argument('--out',required=True)
        q.add_argument('--save-ciphertexts',action='store_true')
        if name=='bench-controlled': q.add_argument('--sizes',nargs='+',type=int,default=[128,512,1024,4096,16384,65536,262144,1048576,4194304])
        else:
            q.add_argument('--dataset',default='datasets/govdocs-im-1000-v1');q.add_argument('--count',type=int,default=1000)
            q.add_argument('--step',type=int,default=100)
    args=p.parse_args()
    if args.command=='prepare': prepare(args)
    elif args.command=='dataset':
        need(args.count>0,'Count must be positive');dataset(args)
    else:
        if args.command=='bench-real': need(args.count>0 and args.step>0,'Count/step must be positive')
        benchmark(args)

if __name__=='__main__': main()

