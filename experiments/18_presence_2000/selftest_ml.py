"""Synthetic learn/save/load check in the user's original ML environment. Not Hecate evidence."""
import tempfile
from pathlib import Path
import numpy as np
import joblib
from xgboost import XGBClassifier
from study import SETS,candidates,fast_auc
from data_utils import versions

def main():
    rng=np.random.default_rng(20261017)
    y=np.tile([0,1],1000)
    x=rng.normal(0,.1,(2000,len(SETS['F3_public_statistics'])))+y[:,None]*10
    with tempfile.TemporaryDirectory(prefix='hecate-study-selftest-') as tmp:
        for setname,cols in SETS.items():
            xx=x[:,:len(cols)]
            for name,options in candidates(20261017).items():
                best=None
                for params,m in options:
                    m.fit(xx[:1000],y[:1000])
                    v=fast_auc(y[1000:1400],m.predict_proba(xx[1000:1400])[:,1])
                    if best is None or v>best[0]:best=(v,m)
                m=best[1];before=m.predict_proba(xx[1400:])[:,1]
                path=Path(tmp)/(setname+'-'+name+('.json' if name=='xgboost' else '.joblib'))
                if name=='xgboost':
                    m.save_model(path);loaded=XGBClassifier();loaded.load_model(path)
                else:
                    joblib.dump(m,path);loaded=joblib.load(path)
                after=loaded.predict_proba(xx[1400:])[:,1]
                assert np.max(np.abs(before-after))<=1e-7
                auc=fast_auc(y[1400:],after)
                assert auc==.5 if name=='dummy' else auc>.95
                print('PASS synthetic',setname,name,'AUC',auc,flush=True)
    print('PASS native ML fit/save/load. Synthetic signal only, not Hecate security results.',versions(),flush=True)
if __name__=='__main__':main()
