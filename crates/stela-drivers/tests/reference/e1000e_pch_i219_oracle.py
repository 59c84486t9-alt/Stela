#!/usr/bin/env python3
"""Run the unchanged-helper oracle for each actual SPT/CNP/TGP/ADP MAC family.

The shared runner verifies and joins the pinned PCI table, board-info table and
MAC-info definitions. Fresh child folders retain each compiler command, exact
source bodies, binary, trace and family inventory. No physical proof is implied.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

source,out=map(Path,sys.argv[1:])
out.mkdir(parents=True,exist_ok=False)
runner=Path(__file__).with_name('e1000e_pch_spt_oracle.py')
families={}
for family in ('spt','cnp','tgp','adp'):
    child=out/family
    command=[sys.executable,str(runner),str(source),str(child),family]
    subprocess.run(command,check=True)
    families[family]=json.loads((child/'manifest.json').read_text())
inventory=families['spt']['pci_inventory']
assert all(m['pci_inventory']==inventory for m in families.values())
selected=[row for m in families.values() for row in m['selected_inventory']]
assert len(selected)==39 and {r['device'] for r in selected}=={r['device'] for r in inventory}
def binding(path):
    raw=path.read_bytes()
    return dict(path=str(path),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
manifest=dict(linux_commit=families['spt']['linux_commit'],pci_inventory=inventory,
              family_cases={f:m['cases'] for f,m in families.items()},
              total_cases=sum(sum(m['cases'].values()) for m in families.values()),
              unchanged_helper_count=len(families['spt']['unchanged_functions']),
              artifacts=[binding(out/f/name) for f in families for name in ('manifest.json','trace.bin','pch_spt.c','pch_spt','inventory.json')])
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(binding(out/'manifest.json')))
