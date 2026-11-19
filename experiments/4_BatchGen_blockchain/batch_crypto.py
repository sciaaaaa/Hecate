"""Hecate BatchGen wire profile v1. Full-point Schnorr, not BIP340/ECDSA."""
import hashlib
import json
import re
import secrets
import time
from coincurve import PublicKey

FORMAT='hecate-batch-v1'

def need(condition, message):
    if not condition: raise ValueError(message)

def raw(value):
    return bytes.fromhex(value.removeprefix('0x'))

def scope(system, ppk, batch_address):
    c=system['config']
    return {'chain_id':system['chain_id'],'genesis_hash':system['genesis_hash'],
        'system_registry':system['address'].lower(),'ppk_store':ppk['address'].lower(),
        'batch_registry':batch_address.lower(),'setup_id':c['setup_id'],'key_id':c['key_id'],
        'receiver_params_id':c['receiver_params_id'],'B':c['B'],'owner':c['owner'].lower()}

def batch_id(core, context, label):
    need(re.fullmatch(r'[A-Za-z0-9_-]{1,64}',label) is not None,'Batch label must be 1..64 ASCII letters/digits/_/-')
    return '0x'+hashlib.sha256(core.ser('BATCH-ID',core.canonical(context),label.encode('ascii'))).hexdigest()

def metadata(context,label,planned_records,description):
    need(isinstance(planned_records,int) and 1<=planned_records<2**32,'Invalid planned record count')
    # B bounds the authorization set, not the total submitted record count.
    return dict(context,format=FORMAT,label=label,planned_records=planned_records,description=description)

def auth_bytes(core,t,U,info,config):
    return core.ser('BATCH',raw(config['owner']),raw(t),U,raw(config['pairing_key']),info)

def challenge(core,R,public,auth):
    context=core.ser('AL-BATCH',R,public,auth)
    return int.from_bytes(hashlib.shake_256(core.ser('H-SIG',context)).digest(64),'big')%core.Q

def verify_signature(core,R,s,public,auth):
    need(len(R)==33 and len(public)==33 and 0<=s<core.Q,'Invalid signature encoding')
    rp,pk=PublicKey(R),PublicKey(public)
    need(rp.format(compressed=True)==R and pk.format(compressed=True)==public,'Noncanonical secp256k1 point')
    e=challenge(core,R,public,auth)
    if e==0:
        return s!=0 and core.sig_public(s)==R
    try:
        right=PublicKey.combine_keys([rp,pk.multiply(e.to_bytes(32,'big'))]).format(compressed=True)
    except ValueError:
        # Inputs are validated nonidentity points, so a failed sum denotes infinity.
        return s==0
    return s!=0 and core.sig_public(s)==right

def public_record(core,context,config,label,U,R,s,info):
    t=batch_id(core,context,label)
    auth=auth_bytes(core,t,U,info,config)
    return {'format':FORMAT,'t':t,'U_hex':U.hex(),'R_hex':R.hex(),
            's_hex':s.to_bytes(32,'big').hex(),'info_hex':info.hex(),'auth_hex':auth.hex()}

def verify(core,context,config,label,doc):
    need(doc['format']==FORMAT and doc['t']==batch_id(core,context,label),'Batch identity mismatch')
    U,R,sraw,info=map(raw,[doc['U_hex'],doc['R_hex'],doc['s_hex'],doc['info_hex']])
    need(len(U)==96 and len(sraw)==32 and 0<len(info)<=8192,'Invalid batch field length')
    core.dec_g2(U)
    metadata_doc=json.loads(info)
    need(core.canonical(metadata_doc)==info,'Metadata must use canonical encoding')
    need(all(metadata_doc.get(k)==v for k,v in context.items()),'Cross-version/chain/contract metadata mismatch')
    need(metadata_doc.get('format')==FORMAT and metadata_doc.get('label')==label,'Metadata label mismatch')
    need(isinstance(metadata_doc.get('planned_records'),int) and not isinstance(metadata_doc['planned_records'],bool)
         and 1<=metadata_doc['planned_records']<2**32,'Invalid planned record count')
    need(isinstance(metadata_doc.get('description'),str),'Invalid description')
    need(set(metadata_doc)==set(context)|{'format','label','planned_records','description'},'Unexpected metadata fields')
    auth=auth_bytes(core,doc['t'],U,info,config)
    need(raw(doc['auth_hex'])==auth,'Auth reconstruction mismatch')
    need(verify_signature(core,R,int.from_bytes(sraw,'big'),raw(config['schnorr_key']),auth),'Invalid alliance Schnorr signature')
    return metadata_doc

def generate(core,context,config,label,info_obj,signing_secret):
    need(0<signing_secret<core.Q and core.sig_public(signing_secret)==raw(config['schnorr_key']), 'Signing key mismatch')
    info=core.canonical(info_obj)
    need(0<len(info)<=8192,'Metadata exceeds 8192 bytes')
    t=batch_id(core,context,label)
    start=time.perf_counter_ns();cpu=time.process_time_ns()
    xi=secrets.randbelow(core.curve_order-1)+1
    U=core.enc_g2(core.multiply(core.G2,xi))
    auth=auth_bytes(core,t,U,info,config)
    k=secrets.randbelow(core.Q-1)+1
    R=core.sig_public(k)
    e=challenge(core,R,raw(config['schnorr_key']),auth)
    s=(k+e*signing_secret)%core.Q
    del k # Drop reference only; Python cannot guarantee memory zeroization.
    compute_ms=(time.perf_counter_ns()-start)/1e6
    cpu_ms=(time.process_time_ns()-cpu)/1e6
    start=time.perf_counter_ns()
    doc=public_record(core,context,config,label,U,R,s,info)
    # Match registry_support.save_new's on-disk JSON (Linux LF newlines).
    encoded=(json.dumps(doc,sort_keys=True,indent=2)+'\n').encode('utf-8')
    wire=core.ser('TX-BATCH',auth,R+s.to_bytes(32,'big'),U,info,raw(t))
    serialize_ms=(time.perf_counter_ns()-start)/1e6
    start=time.perf_counter_ns();verify(core,context,config,label,doc)
    verify_ms=(time.perf_counter_ns()-start)/1e6
    metrics={'compute_wall_ms':compute_ms,'compute_cpu_ms':cpu_ms,'serialize_wall_ms':serialize_ms,
             'self_verify_wall_ms':verify_ms,'batchgen_wall_ms':compute_ms+serialize_ms,
             'U_bytes':96,'signature_bytes':65,'info_bytes':len(info),'auth_bytes':len(auth),
             'tx_batch_serialized_bytes':len(wire),'public_json_bytes':len(encoded),
             'contract_argument_payload_bytes':32+96+65+len(info),
             'private_xi_bytes':32,
             'note':'BatchGen includes U/auth/signature construction and public serialization; excludes input validation, self verification, disk IO and blockchain. No traffic overhead is included.'}
    return {'public':doc,'xi_hex':xi.to_bytes(32,'big').hex(),'metrics':metrics}

def validate_private(core,context,config,label,state):
    verify(core,context,config,label,state['public'])
    xi=int(state['xi_hex'],16)
    need(len(raw(state['xi_hex']))==32 and 0<xi<core.curve_order,'Invalid batch secret')
    need(core.enc_g2(core.multiply(core.G2,xi)).hex()==state['public']['U_hex'],'Batch secret/public mismatch')
