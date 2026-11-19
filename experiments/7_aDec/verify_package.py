"""Check package files against the accompanying SHA256 manifest."""
import hashlib,json
from pathlib import Path
p=Path(__file__).resolve().parent
manifest=json.loads((p/'SHA256SUMS.json').read_text('utf-8'))
for name,expected in manifest.items():
    if Path(name).name!=name:raise ValueError('Invalid manifest path')
    actual=hashlib.sha256((p/name).read_bytes()).hexdigest()
    if actual!=expected:raise ValueError('Package checksum mismatch: '+name)
print('Package verified:',len(manifest),'files')
