"""Digest/ComputeKey equations; recipient-private authenticated delivery envelope."""
import hashlib,secrets,time,json
def need(ok,msg):
    if not ok:raise ValueError(msg)
def raw(x):return bytes.fromhex(x.removeprefix('0x'))
def polynomial(ids,p):
    need(len(ids)>0 and len(set(ids))==len(ids) and all(0<=i<p for i in ids),'Invalid authorization set')
    coeff=[1]
    for root in ids:
        nxt=[0]*(len(coeff)+1)
        for i,c in enumerate(coeff):
            nxt[i]=(nxt[i]-root*c)%p;nxt[i+1]=(nxt[i+1]+c)%p
        coeff=nxt
    return coeff
def commit(core,coeff,srs):
    need(len(srs)>=96 and (len(srs)-96)%48==0,'SRS encoding')
    B=(len(srs)-96)//48;need(len(coeff)-1<=B,'Set exceeds B')
    point=core.multiply(core.G1,coeff[0])
    for i,c in enumerate(coeff[1:],1):
        point=core.add(point,core.multiply(core.dec_g1(srs[(i-1)*48:i*48]),c))
    return point
def digest(core,ids,srs):
    start=time.perf_counter_ns();coeff=polynomial(ids,core.curve_order);ds=commit(core,coeff,srs)
    compute=(time.perf_counter_ns()-start)/1e6;start=time.perf_counter_ns();encoded=core.enc_g1(ds)
    return encoded,{'digest_compute_wall_ms':compute,'digest_serialize_wall_ms':(time.perf_counter_ns()-start)/1e6,
                    'set_count':len(ids),'digest_bytes':len(encoded),'set_id_bytes':len(ids)*32}
def compute_keys(core,t,ds_raw,b,xi):
    need(0<b<core.curve_order and 0<xi<core.curve_order,'Secret range')
    ds=core.dec_g1(ds_raw,allow_identity=True);h=core.h_batch(raw(t))
    start=time.perf_counter_ns()
    sk=core.add(core.multiply(core.add(ds,h),b),core.multiply(ds,xi));dsk=core.multiply(h,xi)
    elapsed=(time.perf_counter_ns()-start)/1e6;start=time.perf_counter_ns()
    result={'sk_S_t_hex':core.enc_g1(sk).hex(),'dsk_t_hex':core.enc_g1(dsk).hex()}
    return result,{'computekey_compute_wall_ms':elapsed,'computekey_serialize_wall_ms':(time.perf_counter_ns()-start)/1e6,
                    'capability_raw_bytes':96}
def verify_keys(core,t,ds_raw,keys,pkal_raw,U_raw):
    ds=core.dec_g1(ds_raw,allow_identity=True);h=core.h_batch(raw(t))
    sk=core.dec_g1(raw(keys['sk_S_t_hex']),allow_identity=True);dsk=core.dec_g1(raw(keys['dsk_t_hex']),allow_identity=True)
    pk=core.dec_g2(pkal_raw);U=core.dec_g2(U_raw)
    need(core.pairing(core.G2,sk)==core.pairing(core.add(pk,U),ds)*core.pairing(pk,h),'Overt capability equation failed')
    need(core.pairing(core.G2,dsk)==core.pairing(U,h),'Hidden capability equation failed')
def challenge(core,R,pk,message):return core.h_sig(core.ser('AL-CAPABILITY-DELIVERY-v1',R,pk,message))
def sign(core,message,x):
    k=secrets.randbelow(core.Q-1)+1;R=core.sig_public(k);pk=core.sig_public(x)
    return {'R_hex':R.hex(),'s_hex':((k+challenge(core,R,pk,message)*x)%core.Q).to_bytes(32,'big').hex()}
def verify_signature(core,message,signature,pk):
    from coincurve import PublicKey
    R=raw(signature['R_hex']);sraw=raw(signature['s_hex']);s=int.from_bytes(sraw,'big')
    need(len(R)==33 and len(sraw)==32 and 0<=s<core.Q,'Signature encoding')
    rp,public=PublicKey(R),PublicKey(pk)
    need(rp.format()==R and public.format()==pk,'Noncanonical signature key')
    e=challenge(core,R,pk,message)
    if e==0:need(s!=0 and core.sig_public(s)==R,'Signature');return
    try:right=PublicKey.combine_keys([rp,public.multiply(e.to_bytes(32,'big'))]).format()
    except ValueError:need(s==0,'Signature');return
    need(s!=0 and core.sig_public(s)==right,'Signature')
def seal(core,binding,capability,pkdr,signing_secret):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    r=secrets.randbelow(core.curve_order-1)+1;R=core.enc_g2(core.multiply(core.G2,r))
    shared=core.enc_g2(core.multiply(core.dec_g2(pkdr),r))
    header={'format':'hecate-capability-envelope-v1','binding':binding,'ephemeral_g2_hex':R.hex()}
    aad=core.canonical(header)
    key=hashlib.sha256(core.ser('CAPABILITY-TRANSPORT-v1',shared,pkdr,aad)).digest()
    nonce=secrets.token_bytes(12)
    envelope=dict(header,nonce_hex=nonce.hex(),ciphertext_hex=AESGCM(key).encrypt(nonce,core.canonical(capability),aad).hex())
    envelope['signature']=sign(core,core.canonical(envelope),signing_secret)
    return envelope
def unseal(core,envelope,expected_binding,receiver_scalar,pkal_sign):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    need(envelope['format']=='hecate-capability-envelope-v1' and envelope['binding']==expected_binding,'Envelope binding')
    unsigned={k:v for k,v in envelope.items() if k!='signature'}
    verify_signature(core,core.canonical(unsigned),envelope['signature'],pkal_sign)
    need(0<receiver_scalar<core.curve_order,'Receiver secret range')
    pkdr=core.enc_g2(core.multiply(core.G2,receiver_scalar))
    need(pkdr.hex()==expected_binding['receiver_public_key_hex'],'Wrong recipient')
    shared=core.enc_g2(core.multiply(core.dec_g2(raw(envelope['ephemeral_g2_hex'])),receiver_scalar))
    header={k:envelope[k] for k in ['format','binding','ephemeral_g2_hex']};aad=core.canonical(header)
    key=hashlib.sha256(core.ser('CAPABILITY-TRANSPORT-v1',shared,pkdr,aad)).digest()
    return json.loads(AESGCM(key).decrypt(raw(envelope['nonce_hex']),raw(envelope['ciphertext_hex']),aad))
