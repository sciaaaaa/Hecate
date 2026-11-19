"""Fixed 10-batch protocol: B01-05 train, B06-07 validation, B08-10 final test."""
import argparse, csv, datetime, json
from pathlib import Path
import numpy as np
from data_utils import need,read,write,digest,dataset,matrix,metrics,versions

HERE=Path(__file__).resolve().parent
GAS=['gas_total','gas_open','gas_finalize','gas_chunk_mean','gas_chunk_std','gas_chunk_min','gas_chunk_max']
STRUCT=['transaction_count','calldata_bytes_total','calldata_zero_total','log_count_total','log_data_bytes_total','wire_bytes']
CONTENT=['wire_zero_bytes','wire_entropy']+[k+s for k in ('R_s_hex','s_s_hex','c2_hex') for s in ('_bytes','_zero_bytes','_entropy')]
SETS={'F1_gas':GAS,'F2_gas_structure':GAS+STRUCT,'F3_public_statistics':GAS+STRUCT+CONTENT}
FILES=['COLLECTED.json','public_features.csv','labels_private.csv','spec.json','public-manifest.json']

def fast_auc(y,p):
    # Average ranks handle tied scores; algebraically identical to pair counting.
    _,inv,counts=np.unique(p,return_inverse=True,return_counts=True)
    rank=np.cumsum(counts)-(counts-1)/2
    n1=int(sum(y==1));n0=len(y)-n1
    need(n1>0 and n0>0,'AUC requires both classes')
    return float((sum(rank[inv][y==1])-n1*(n1+1)/2)/(n1*n0))

def plan_at(): return read(HERE/'plan.json')
def code_hashes(): return {n:digest(HERE/n) for n in ['study.py','data_utils.py','plan.json']}
def write_same(p,obj):
    if p.exists():need(read(p)==obj,'Existing evidence differs: '+str(p))
    else:write(p,obj)
def load_batches(base,numbers,plan):
    result=[];seen={k:set() for k in ('sample_id','pk_ds_hex','id','sha256')};batches=set();ref=None;address=None
    for number in numbers:
        entry=plan['batches'][number-1];d=base/entry['experiment']
        fs,y,pairs,spec,recs=dataset(d)
        need(spec['experiment']==entry['experiment'] and spec['seed']==entry['seed'],'Wrong experiment/seed: '+str(number))
        need(spec.get('pairs')==100 and spec['im_bytes']==1024,'Wrong input size/count')
        if ref is None:ref=spec;address={r['address'] for r in recs}
        for key in ref:
            if key not in ('experiment','seed','batch'):need(spec.get(key)==ref[key],'Protocol/config differs: '+str(number)+' '+key)
        need(spec['batch'] not in batches,'Reused batch t');batches.add(spec['batch'])
        need({r['address'] for r in recs}==address and len(address)==1,'Sender account changed')
        for key in seen:
            values={r[key] for r in recs}
            need(len(values)==200 and not values&seen[key],'Duplicate/cross-batch reuse: '+key)
            seen[key]|=values
        result.append(dict(number=number,experiment=entry['experiment'],role=entry['role'],features=fs,y=y,pairs=pairs,
                           spec=spec,records=recs,hashes={n:digest(d/n) for n in FILES}))
        print('CHECKED',entry['experiment'],entry['role'],200,flush=True)
    return result
def evidence(data):return {str(b['number']):dict(experiment=b['experiment'],hashes=b['hashes']) for b in data}
def require_plan(study,plan):
    need((study/'plan.json').exists(),'Run init first')
    need(read(study/'plan.json')==plan,'Saved plan differs; do not silently change protocol')
def check_versions(expected):
    v=versions();need(all(v[k]==expected[k] for k in ('numpy','sklearn','xgboost')),'Use original ML versions: '+str(expected));return v
def init(a,plan):
    # This reads only the already completed two batches, never final test data.
    data=load_batches(a.base,[1,2],plan)
    expected=read(a.base/plan['batches'][0]['experiment']/'ml-first/results.json')['versions']
    check_versions(expected)
    a.study.mkdir(parents=True,exist_ok=True)
    write_same(a.study/'plan.json',plan)
    write_same(a.study/'reuse.json',dict(batches=evidence(data),expected_versions=expected))
    print('READY: reused 400 records. Collect B03-B07 next.',flush=True)
def check(a,plan):
    require_plan(a.study,plan)
    data=load_batches(a.base,range(1,8),plan)
    reuse=read(a.study/'reuse.json')
    need(all(evidence(data)[n]==v for n,v in reuse['batches'].items()),'Old batches changed after init')
    print('DEVELOPMENT READY: train 1000; validation 400. No test batches read.',flush=True)
def candidates(seed):
    from sklearn.dummy import DummyClassifier
    from sklearn.pipeline import make_pipeline
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import StandardScaler
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier
    from xgboost import XGBClassifier
    return {
      'dummy':[('prior',DummyClassifier(strategy='prior'))],
      'logistic':[(f'C={c}',make_pipeline(SimpleImputer(strategy='median'),StandardScaler(),LogisticRegression(C=c,max_iter=2000,random_state=seed))) for c in (.1,1,10)],
      'random_forest':[(f'depth={d}',RandomForestClassifier(n_estimators=200,max_depth=d,min_samples_leaf=3,random_state=seed,n_jobs=1)) for d in (3,None)],
      'xgboost':[(f'depth={d}',XGBClassifier(n_estimators=100,max_depth=d,learning_rate=.05,subsample=.8,colsample_bytree=.8,reg_lambda=1,objective='binary:logistic',eval_metric='logloss',random_state=seed,n_jobs=1,tree_method='hist')) for d in (2,3)]}
def concat(data,role):
    chosen=[b for b in data if b['role']==role]
    fs=[r for b in chosen for r in b['features']]
    y=np.concatenate([b['y'] for b in chosen])
    return fs,y
def freeze(a,plan):
    import joblib
    require_plan(a.study,plan);out=a.study/'frozen'
    need(not out.exists(),'Frozen directory already exists; do not overwrite. Inspect partial run if no freeze.json.')
    # No new test collection should occur before choosing and freezing models.
    for entry in plan['batches'][7:]:need(not (a.base/entry['experiment']/'spec.json').exists(),'Test batch already started before freeze: '+entry['experiment'])
    data=load_batches(a.base,range(1,8),plan);reuse=read(a.study/'reuse.json')
    need(all(evidence(data)[n]==v for n,v in reuse['batches'].items()),'Reused data changed')
    v=check_versions(reuse['expected_versions']);train_rows,ty=concat(data,'train');val_rows,vy=concat(data,'validation')
    need(len(ty)==1000 and len(vy)==400,'Wrong split sizes')
    out.mkdir();models=[];trials=[]
    for setname,cols in SETS.items():
        x=matrix(train_rows,cols);vx=matrix(val_rows,cols)
        for name,options in candidates(plan['model_seed']).items():
            best=None
            for params,model in options:
                model.fit(x,ty);p=model.predict_proba(vx)[:,1];score=fast_auc(vy,p)
                trials.append(dict(feature_set=setname,model=name,params=params,validation_auc=score))
                if best is None or score>best[0]:best=(score,params,model,p)
            score,params,model,p=best
            filename=setname+'__'+name+('.json' if name=='xgboost' else '.joblib')
            if name=='xgboost':model.save_model(out/filename)
            else:joblib.dump(model,out/filename)
            models.append(dict(feature_set=setname,model=name,params=params,features=cols,file=filename,sha256=digest(out/filename),validation_metrics=metrics(vy,p)))
            print('FROZEN',setname,name,'validation AUC',score,flush=True)
    manifest=dict(format='HECATE-FREEZE-2000-v1',created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  plan=plan,code_hashes=code_hashes(),versions=v,development=evidence(data),models=models,candidates=trials,
                  train_count=len(ty),validation_count=len(vy),threshold=0.5,
                  note='No final test data used. No refit on validation. All feature/model combinations retained.')
    write(out/'freeze.json',manifest)
    write(a.study/'test-release.json',dict(format='HECATE-TEST-RELEASE-v1',plan_sha256=digest(HERE/'plan.json'),freeze_sha256=digest(out/'freeze.json'),allowed_batches=[8,9,10]))
    print('FREEZE COMPLETE:',out,'\nTest collection B08-B10 may now begin.',flush=True)
def validate_freeze(a,plan):
    require_plan(a.study,plan);f=read(a.study/'frozen/freeze.json')
    need(f['format']=='HECATE-FREEZE-2000-v1' and f['plan']==plan and f['threshold']==.5,'Invalid freeze')
    need(f['code_hashes']==code_hashes(),'Analysis code/plan changed after freeze')
    check_versions(f['versions'])
    need(len(f['models'])==12,'Incomplete model set')
    for row in f['models']:
        need(Path(row['file']).name==row['file'],'Invalid model filename')
        need(digest(a.study/'frozen'/row['file'])==row['sha256'],'Model changed: '+row['file'])
    return f
def gate(a,plan):
    validate_freeze(a,plan)
    print('FREEZE VALID: model and plan hashes match.',flush=True)
def stratified_ci(y,p,batch,pairs,plan):
    rng=np.random.default_rng(plan['bootstrap_seed']);indices=[]
    for b in sorted(set(batch)):
        indices.append([np.flatnonzero((batch==b)&(pairs==g)) for g in sorted(set(pairs[batch==b]))])
    values=[]
    for _ in range(plan['bootstrap_repeats']):
        idx=np.concatenate([group[j] for group in indices for j in rng.integers(0,len(group),len(group))])
        values.append(fast_auc(y[idx],p[idx]))
    return [float(z) for z in np.quantile(values,[.025,.975])]
def evaluate(a,plan):
    import joblib
    from xgboost import XGBClassifier
    f=validate_freeze(a,plan);out=a.study/'final-evaluation'
    need(not out.exists(),'Final evaluation exists; preserve original results')
    data=load_batches(a.base,range(1,11),plan)
    need(evidence(data[:7])==f['development'],'Development data changed since freeze')
    tests=data[7:];fs,y=concat(tests,'test');need(len(y)==600,'Expected 600 final test records')
    batch=np.concatenate([np.repeat(b['number'],len(b['y'])) for b in tests]);pairs=np.concatenate([b['pairs'] for b in tests])
    results=[];predictions=[]
    for entry in f['models']:
        path=a.study/'frozen'/entry['file']
        if entry['model']=='xgboost':model=XGBClassifier();model.load_model(path)
        else:model=joblib.load(path)
        p=model.predict_proba(matrix(fs,entry['features']))[:,1]
        need(np.isfinite(p).all() and ((p>=0)&(p<=1)).all(),'Invalid model probabilities')
        per={str(b):metrics(y[batch==b],p[batch==b]) for b in (8,9,10)}
        pooled=metrics(y,p);ci=stratified_ci(y,p,batch,pairs,plan)
        results.append(dict(feature_set=entry['feature_set'],model=entry['model'],params=entry['params'],pooled=pooled,auc_ci95=ci,per_batch=per))
        for row,g,b,label,prob in zip(fs,pairs,batch,y,p):predictions.append(dict(feature_set=entry['feature_set'],model=entry['model'],batch=int(b),sample_id=row['sample_id'],pair_id=int(g),label=int(label),probability=float(prob),predicted_label=int(prob>=.5)))
        print('TEST',entry['feature_set'],entry['model'],'AUC',pooled['auc'],'CI',ci,flush=True)
    out.mkdir()
    for filename,rs in [('predictions.csv',predictions),('metrics.csv',[dict(feature_set=r['feature_set'],model=r['model'],scope=scope,**{k:v for k,v in vals.items() if k!='confusion_matrix'}) for r in results for scope,vals in [('pooled',r['pooled'])]+list(r['per_batch'].items())])]:
        with (out/filename).open('x',encoding='utf-8',newline='') as file:
            writer=csv.DictWriter(file,fieldnames=list(rs[0]));writer.writeheader();writer.writerows(rs)
    write(out/'evaluation.json',dict(results=results,freeze_sha256=digest(a.study/'frozen/freeze.json'),test_data=evidence(tests),versions=versions(),sample_count=600,normal_count=300,hidden_count=300,
        note='Pooled AUC includes cross-batch comparisons; inspect per-batch results. CI resamples pairs within each of the three fixed batches, not uncertainty over unseen batches or retraining. No threshold tuning or model selection on final test; report all results. No indistinguishability proof.'))
    print('FINAL EVALUATION COMPLETE:',out,flush=True)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['init','check','freeze','gate','evaluate'])
    p.add_argument('--base',type=Path,default=Path('/home/Hecate_2/hecate-app/private/presence'))
    p.add_argument('--study',type=Path);a=p.parse_args();a.study=a.study or a.base/'study-2000-v1'
    globals()[a.command](a,plan_at())
if __name__=='__main__':main()
