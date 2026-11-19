"""Public collection gate; no model or private keys are transferred to node6."""
import hashlib,json,sys
from pathlib import Path
here=Path(__file__).resolve().parent
release=json.loads(Path(sys.argv[1]).read_text())
assert release['format']=='HECATE-TEST-RELEASE-v1'
assert release['plan_sha256']==hashlib.sha256((here/'plan.json').read_bytes()).hexdigest()
assert release['allowed_batches']==[8,9,10]
assert len(release['freeze_sha256'])==64 and all(c in '0123456789abcdef' for c in release['freeze_sha256'])
print('Public test-collection release checked. This is an accidental-use guard, not a digital signature.')
