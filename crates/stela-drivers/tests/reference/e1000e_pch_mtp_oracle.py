#!/usr/bin/env python3
"""Fresh unchanged e1000e MTP/PTP lifecycle and actual DMI-quirk reference.

Usage: E1000E_DIRECTORY DMI_DIRECTORY FRESH_OUTPUT_DIRECTORY
The DMI directory holds pinned drivers/firmware/dmi_scan.c and
include/linux/device-id/dmi.h as dmi_scan.c and device-id-dmi.h.
No native firmware provider or physical hardware proof is implied.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,dmi,out=map(Path,sys.argv[1:]);out.mkdir(parents=True,exist_ok=False)
runner=Path(__file__).with_name('e1000e_pch_spt_oracle.py')
for family in ('mtp','ptp'):
 subprocess.run([sys.executable,str(runner),str(source),str(out/family),family],check=True)
def binding(p):
 raw=p.read_bytes();return dict(path=str(p),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
expected={'dmi_scan.c':'f34399c19dce69a88d80c8894426b84e27bd945d19600fa057a7219c0e1bb900','device-id-dmi.h':'9b3a391fbdb28aec02fa0a7644372e2b9ba443cf98fede68c6ed4f3d86f01405'}
for name,digest in expected.items():assert binding(dmi/name)['sha256']==digest
text=(dmi/'dmi_scan.c').read_text();start=text.index('static bool dmi_matches(');end=text.index('\n}\n',start)+2;helper=text[start:end]
text=(source/'netdev.c').read_text();assert hashlib.sha256(text.encode()).hexdigest()=='771cc6e1d44d40d3cd6204ba4800c3289e145ea4ca97455f341007c3aaf76827'
start=text.index('static const struct dmi_system_id disable_k1_list[]');end=text.index('\n};',start)+3;table=text[start:end]
vendors=[None,b'',b'Dell Inc.',b'LENOVO',b'prefixDell Inc.suffix',b'lenovo',b'Dell\0 Inc.',b'\xffLENOVO']
names=[None,b'',b'Dell Pro 16 Plus PB16250',b'prefix Dell Pro 16 Plus PB16250 suffix',b'dell Pro 16 Plus PB16250',b'Dell Pro 16 Plus\0 PB16250',b'\xffDell Pro 16 Plus PB16250',b'ThinkPad P14s Gen 5']
versions=[None,b'',b'ThinkPad P14s Gen 5',b'prefixThinkPad P14s Gen 5suffix',b'thinkPad P14s Gen 5',b'ThinkPad\0 P14s Gen 5',b'\xfeThinkPad P14s Gen 5',b'Dell Pro 16 Plus PB16250']
prelude='''// SPDX-License-Identifier: GPL-2.0-only
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(*(a)))
'''+(dmi/'device-id-dmi.h').read_text()+'''
struct dmi_device { int unused; };
#define DMI_DEV_TYPE_OEM_STRING -2
static const char *dmi_ident[DMI_STRING_MAX];
static const struct dmi_device *dmi_find_device(int type,const char *name,const void *from){(void)type;(void)name;(void)from;abort();}
'''
rows=[]
for group,values in [('vendors',vendors),('names',names),('versions',versions)]:
 vals=[]
 for n,v in enumerate(values):
  if v is None:vals.append('NULL');continue
  label=group+str(n);rows.append('static const char '+label+'[]={'+','.join(str(x) for x in v+b'\0')+'};');vals.append(label)
 rows.append('static const char *'+group+'[]={'+','.join(vals)+'};')
main='''
int main(void){for(uint32_t v=0;v<8;v++)for(uint32_t n=0;n<8;n++)for(uint32_t p=0;p<8;p++){
 dmi_ident[DMI_SYS_VENDOR]=vendors[v];dmi_ident[DMI_PRODUCT_NAME]=names[n];dmi_ident[DMI_PRODUCT_VERSION]=versions[p];
 uint32_t result=0;for(unsigned i=0;i<2;i++)if(dmi_matches(&disable_k1_list[i]))result=1;
 uint32_t row[]={14,v,n,p,result,0};if(fwrite(row,sizeof(row),1,stdout)!=1)abort();
}
 return 0;
}
'''
cpath=out/'dmi_quirk.c';cpath.write_text(prelude+helper+'\n'+table+'\n'+'\n'.join(rows)+main)
binary=out/'dmi_quirk';command=['clang','-std=c11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-Wall','-Wextra','-Werror','-Wno-sign-compare',str(cpath),'-o',str(binary)]
subprocess.run(command,check=True)
with (out/'dmi_trace.bin').open('wb') as f:subprocess.run([str(binary.resolve())],stdout=f,check=True)
families={f:json.loads((out/f/'manifest.json').read_text()) for f in ('mtp','ptp')}
manifest=dict(linux_commit=families['mtp']['linux_commit'],source_inventory=families['mtp']['pci_inventory'],family_cases={f:m['cases'] for f,m in families.items()},dmi_cases=512,donor_helper_count=len(families['mtp']['unchanged_functions'])+1,dmi_source=expected,dmi_matches_sha256=hashlib.sha256(helper.encode()).hexdigest(),unchanged_quirk_table_sha256=hashlib.sha256(table.encode()).hexdigest(),command=command,limits=['DMI input is actual decoded bounded field observation; parser/discovery/native firmware ownership is outside this helper.','Observed absence is source NULL, byte strings preserve first-NUL and case-sensitive substring semantics. Native NotObserved is a separate pre-I/O refusal, never source non-match.','DMI no-OEM branch stub aborts if the exact unchanged two-entry table unexpectedly requires it.'],artifacts=[binding(out/f/name) for f in ('mtp','ptp') for name in ('manifest.json','pch_spt.c','pch_spt','trace.bin','inventory.json')]+[binding(out/name) for name in ('dmi_quirk.c','dmi_quirk','dmi_trace.bin')])
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(binding(out/'manifest.json')))
