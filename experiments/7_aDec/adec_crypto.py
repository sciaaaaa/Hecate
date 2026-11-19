"""Receiver-only opening of the existing AES-CTR extension; no alliance secrets."""
from time import perf_counter_ns
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from coincurve import PublicKey
from py_ecc.optimized_bls12_381 import neg

def need(ok,message):
    if not ok:raise ValueError(message)

def raw(s):return bytes.fromhex(s.removeprefix('0x'))
def elapsed(start):return (perf_counter_ns()-start)/1e6

def verify_shared(core,bc,ac,context,config,label,batch,intent,cap,srs):
    metrics={};start=perf_counter_ns()
    bc.verify(core,context,config,label,batch)
    metrics['batch_verify_ms']=elapsed(start);start=perf_counter_ns()
    ids=[int(i,16) for i in intent['ids']]
    need(ids==sorted(set(ids)) and 1<=len(ids)<=config['B'],'Invalid finalized set')
    ds,_=ac.digest(core,ids,srs)
    need(ds.hex()==intent['digest_hex'],'Digest polynomial mismatch')
    dp=core.dec_g1(ds,allow_identity=True)
    metrics['digest_verify_ms']=elapsed(start);start=perf_counter_ns()
    h=core.h_batch(raw(batch['t']));pk=core.dec_g2(raw(config['pairing_key']));U=core.dec_g2(raw(batch['U_hex']))
    sk=core.dec_g1(raw(cap['sk_S_t_hex']),allow_identity=True)
    need(core.pairing(core.G2,sk)==core.pairing(core.add(pk,U),dp)*core.pairing(pk,h),'Overt capability invalid')
    metrics['overt_key_verify_ms']=elapsed(start);start=perf_counter_ns()
    dsk=core.dec_g1(raw(cap['dsk_t_hex']),allow_identity=True)
    need(core.pairing(core.G2,dsk)==core.pairing(U,h),'Hidden capability invalid')
    metrics['hidden_key_verify_ms']=elapsed(start)
    metrics['shared_verify_ms']=sum(metrics.values())
    return {'ids':ids,'ds':dp,'sk':sk,'dsk':dsk},metrics

def verify_record(core,engine,batch,tx,binding,pkdr,secret,authorized):
    start=perf_counter_ns()
    need(tx['format']==engine.FORMAT and tx['binding']==binding and tx['t']==batch['t'],'Ciphertext context mismatch')
    pkraw=raw(tx['pk_ds_hex']);pk=core.dec_g2(pkraw)
    idraw=raw(tx['id_hex']);need(len(idraw)==32,'ID length')
    identifier=int.from_bytes(idraw,'big')
    need(identifier==core.h_id(core.ser('SID',raw(batch['auth_hex']),pkraw)),'ID/public key mismatch')
    need(identifier in authorized['ids'],'Not authorized by finalized S')
    ctx=core.h_ctx(core.ser('CTX-AESCTR-EXT-v1',core.canonical(binding),raw(batch['auth_hex']),pkraw,pkdr))
    parts=[raw(x) for x in tx['c1_hex']];need(len(parts)==3,'C1 arity')
    points=[core.dec_g2(x,allow_identity=True) for x in parts]
    c2=raw(tx['c2_hex']);need(len(c2)>=28,'C2 length')
    base=core.enc_g2(core.multiply(pk,secret))
    shared=core.bkdf(core.ser('DS-KEY',base,pkraw,pkdr,ctx));need(0<shared<core.Q,'Shared scalar range')
    Pi=core.sig_public(shared);R=raw(tx['R_s_hex']);sr=raw(tx['s_s_hex']);ss=int.from_bytes(sr,'big')
    need(len(R)==33 and len(sr)==32 and ss<core.Q,'Signature encoding')
    rp=PublicKey(R);need(rp.format()==R,'Noncanonical signature point')
    msg=core.ser('DS-MSG',engine.overt_bytes(core,parts,c2),ctx)
    challenge=core.h_sig(core.ser('DS-SCHNORR',R,msg,Pi))
    if challenge==0:
        need(ss!=0 and core.sig_public(ss)==R,'Sender signature failed')
    else:
        try:right=PublicKey.combine_keys([rp,PublicKey(Pi).multiply(challenge.to_bytes(32,'big'))]).format()
        except ValueError:need(ss==0,'Sender signature failed')
        else:need(ss!=0 and core.sig_public(ss)==right,'Sender signature failed')
    result=dict(identifier=identifier,idraw=idraw,pkraw=pkraw,pk=pk,pkdr=pkdr,ctx=ctx,parts=parts,
        points=points,c2=c2,base=base,shared=shared,R=R,ss=ss,challenge=challenge)
    return result,elapsed(start)

def open_overt(core,engine,ac,checked,authorized,srs):
    start=perf_counter_ns();v=checked
    others=[i for i in authorized['ids'] if i!=v['identifier']]
    # Empty product is 1: the singleton-set witness is G1.
    coeff=ac.polynomial(others,core.curve_order) if others else [1]
    witness=ac.commit(core,coeff,srs)
    theta=(core.pairing(v['points'][0],authorized['ds'])*core.pairing(v['points'][1],witness)*core.pairing(v['points'][2],authorized['sk'])).inv()
    theta_raw=core.enc_gt(theta)
    key=core.kdf(core.ser('OVERT',theta_raw,engine.header_bytes(core,v['parts']),v['idraw'],v['pkraw'],v['pkdr'],v['ctx']))
    im=AESGCM(key).decrypt(v['c2'][:12],v['c2'][12:],v['ctx'])
    return im,theta_raw,elapsed(start)

def open_hidden(core,engine,checked,authorized,theta_raw):
    start=perf_counter_ns();v=checked
    nonce=(v['ss']-v['challenge']*v['shared'])%core.Q
    need(nonce!=0 and core.sig_public(nonce)==v['R'],'Recovered nonce invalid')
    sst=core.enc_gt(core.pairing(v['pk'],authorized['dsk']))
    dk=core.kdf(core.ser('HIDDEN',sst,v['base'],theta_raw,v['ctx']))
    em,K=engine.capsule_decode(core,nonce,dk,v['ctx'])
    mask=core.f_p(K,core.ser('RD-MASK',v['ctx']))
    index=core.enc_g2(core.add(neg(v['points'][2]),neg(core.multiply(core.G2,mask))))
    return em,index,elapsed(start)
