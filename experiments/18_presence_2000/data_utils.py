import csv,hashlib,json,math,platform
from pathlib import Path
import numpy as np


def need(ok, message):
    if not ok: raise ValueError(message)

def read(p): return json.loads(p.read_text(encoding='utf-8-sig'))

def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def rows(p):
    with p.open(encoding='utf-8-sig', newline='') as f: return list(csv.DictReader(f))

def write(p, obj):
    with p.open('x', encoding='utf-8') as f: json.dump(obj, f, indent=2, ensure_ascii=False)

def versions():
    import sklearn, xgboost
    return dict(python=platform.python_version(), numpy=np.__version__, sklearn=sklearn.__version__, xgboost=xgboost.__version__)

def dataset(d):
    evidence=read(d/'COLLECTED.json')
    for name,key in [('public_features.csv','features_sha256'),('labels_private.csv','labels_sha256')]:
        need(digest(d/name)==evidence[key], 'Data hash mismatch: '+name)
    fs=rows(d/'public_features.csv'); ls=rows(d/'labels_private.csv'); lm={r['sample_id']:r for r in ls}
    ids=[r['sample_id'] for r in fs]
    need(len(fs)==len(ls)==len(lm)==len(set(ids))==200 and set(ids)==set(lm), 'Expected 200 unique matching samples')
    y=np.array([int(lm[s]['label']) for s in ids]); pairs=np.array([int(lm[s]['pair_id']) for s in ids])
    need(len(set(pairs))==100, 'Expected 100 pairs')
    for g in set(pairs): need(sorted(y[pairs==g].tolist())==[0,1], 'Pair must have labels 0 and 1')
    spec=read(d/'spec.json'); manifest=read(d/'public-manifest.json')
    need(manifest['spec']==spec and spec['im_bytes']==1024, 'Experiment spec mismatch or wrong im length')
    recs=manifest['records']
    need(len(recs)==200 and {r['sample_id'] for r in recs}==set(ids), 'Manifest mismatch')
    need(len({r['pk_ds_hex'] for r in recs})==200 and len({r['id'] for r in recs})==200, 'Duplicate Hecate keys/ids')
    return fs,y,pairs,spec,recs

def matrix(fs, cols):
    x=np.array([[float(r[c]) for c in cols] for r in fs],dtype=float)
    need(np.isfinite(x).all(), 'Nonfinite feature')
    return x

def auc(y,p):
    a=p[y==1]; b=p[y==0]; delta=a[:,None]-b[None,:]
    return float(np.mean((delta>0)+0.5*(delta==0)))

def metrics(y,p):
    h=p>=0.5
    tp=int(sum((y==1)&h));tn=int(sum((y==0)&~h));fp=int(sum((y==0)&h));fn=int(sum((y==1)&~h))
    precision=tp/(tp+fp) if tp+fp else None
    den=(tp+fp)*(tp+fn)*(tn+fp)*(tn+fn)
    return dict(auc=auc(y,p),accuracy=(tp+tn)/len(y),precision=precision,recall=tp/(tp+fn),
                f1=2*tp/(2*tp+fp+fn),fpr=fp/(fp+tn),specificity=tn/(tn+fp),
                balanced_accuracy=(tp/(tp+fn)+tn/(tn+fp))/2,
                mcc=(tp*tn-fp*fn)/math.sqrt(den) if den else 0.0,
                confusion_matrix=[[tn,fp],[fn,tp]],threshold=0.5)

def bootstrap(y,p,pairs,seed=20261021,repeats=2000):
    rng=np.random.default_rng(seed); groups=sorted(set(pairs)); indices={g:np.flatnonzero(pairs==g) for g in groups}; vals=[]
    for _ in range(repeats):
        idx=np.concatenate([indices[g] for g in rng.choice(groups,len(groups),replace=True)])
        vals.append(auc(y[idx],p[idx]))
    return [float(v) for v in np.quantile(vals,[.025,.975])]
