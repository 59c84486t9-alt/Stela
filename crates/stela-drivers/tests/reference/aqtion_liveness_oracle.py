#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Two exact original live-read/flag helpers; native comparison is separate."""
import hashlib,json,pathlib,re,shutil,subprocess,sys,os
from datetime import datetime,timezone
source,out=map(pathlib.Path,sys.argv[1:]);H={'aq_hw_utils.c': 'd28153e839b7a7945956ec30adbe8eb5136328fb1f822a33f4ef3324510cae8f', 'aq_utils.h': '3bf6f61fccb49e54717d222f9c6d4971a9c0a95905b4566c644035d690441252', 'aq_hw.h': '73b67833f0cb4fbeb234d10a4fd929dfbca421825a58d01d568d9727100f1e9d', 'hw_atl/hw_atl_b0.c': 'a835c3d29a507bfc761b773b9759847e9006ee457ddbd64339e7b4f01b3c2020', 'hw_atl2/hw_atl2.c': '5cdd3f83eb01208a9bfd2e88e285531148f05d03100255e74b8d6d0ebd78df5c'}
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
t={f:(source/f).read_text() for f in H}
assert all(sha(source/f)==h for f,h in H.items())
for f in ['hw_atl/hw_atl_b0.c','hw_atl2/hw_atl2.c']:assert '.hw_alive_check_addr = 0x10U' in t[f]
def function(f,n):
 m=re.search(r'^(?:static inline )?(?:void|u32)\s+'+n+r'\([^;{}]*?\)\n\{',t[f],re.M);assert m,n
 i=m.end();d=1
 while d:d+=(t[f][i]=='{')-(t[f][i]=='}');i+=1
 return t[f][m.start():i]
bodies=[function('aq_utils.h','aq_utils_obj_set'),function('aq_hw_utils.c','aq_hw_read_reg')]
flag=next(l for l in t['aq_hw.h'].splitlines() if l.startswith('#define AQ_HW_FLAG_ERR_UNPLUG '))
pre=r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2014-2019 aQuantia Corporation
// Copyright (C) 2019-2020 Marvell International Ltd.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint32_t u32;typedef uint32_t atomic_t;
#define U32_MAX UINT32_MAX
static u32 atomic_read(atomic_t*f){return *f;}
static u32 atomic_cmpxchg(atomic_t*f,u32 old,u32 next){u32 prev=*f;if(prev==old)*f=next;return prev;}
struct caps{u32 hw_alive_check_addr;};struct cfg{struct caps*aq_hw_caps;};
struct aq_hw_s{unsigned char*mmio;struct cfg*aq_nic_cfg;atomic_t flags;};
static unsigned char*base;static unsigned reads[4],nr;
static u32 readl(void*p){unsigned at=(unsigned char*)p-base;if((at!=16&&at!=32)||nr>=4)abort();reads[nr++]=at;return *(u32*)p;}
'''
main=r'''
int main(void){const u32 values[]={0,0x12345678,0x80000000,UINT32_MAX};
 for(unsigned profile=0;profile<2;profile++)for(unsigned vi=0;vi<4;vi++)for(unsigned live=0;live<2;live++)for(unsigned fi=0;fi<2;fi++){
  u32 memory[16]={0};memory[4]=live?UINT32_MAX:0;memory[8]=values[vi];base=(unsigned char*)memory;nr=0;
  struct caps caps={16};struct cfg cfg={&caps};struct aq_hw_s hw={base,&cfg,fi?0x100:0};
  u32 value=aq_hw_read_reg(&hw,32);
  printf("L %u %u %u %u %u %u %u",profile,values[vi],memory[4],fi?0x100:0,value,hw.flags,nr);
  for(unsigned i=0;i<nr;i++)printf(" %u",reads[i]);puts("");
 }
}
'''
assert not out.exists();out.mkdir(parents=True);unit=out/'linux-live-read.c';unit.write_text('\n'.join([pre,flag,*bodies,main]))
compiler=pathlib.Path(shutil.which('clang') or sys.exit('clang unavailable')).resolve();version=subprocess.run([str(compiler),'--version'],capture_output=True,text=True,check=True,timeout=10)
exe=out/'linux-live-read';cmd=[str(compiler),'-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(unit.resolve()),'-o',str(exe.resolve())]
a={'pin':'cc9de5d4b5ab6459f5774946aa3195ad51236fa8','sources':H,'bodies_sha256':[hashlib.sha256(b.encode()).hexdigest() for b in bodies],'script_sha256':sha(__file__),'unit_sha256':sha(unit),'compiler':str(compiler),'compiler_sha256':sha(compiler),'version':version.stdout,'command':cmd,'scope':'Source prep only;32 scalar calls, actual read offset sequence/returned data/flags. Native comparison absent; CAS/readl are explicit callback boundaries.'};(out/'admission.json').write_text(json.dumps(a,indent=2)+'\n')
status={'compile':'not started','execution':'not started'}
try:
 with (out/'compile.stdout').open('xb') as so,(out/'compile.stderr').open('xb') as se:
  p=subprocess.run(cmd,stdout=so,stderr=se,timeout=60);status['compile']=p.returncode;p.check_returncode()
 status['binary_sha256_before_execution']=sha(exe);(out/'execution-admission.json').write_text(json.dumps(status,indent=2)+'\n')
 env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
 with (out/'records.txt').open('xb') as so,(out/'execute.stderr').open('xb') as se:
  p=subprocess.run([str(exe.resolve())],stdout=so,stderr=se,env=env,timeout=15);status['execution']=p.returncode;p.check_returncode()
 assert len((out/'records.txt').read_text().splitlines())==32
 assert sha(exe)==status['binary_sha256_before_execution'] and sha(unit)==a['unit_sha256'] and sha(__file__)==a['script_sha256'] and sha(compiler)==a['compiler_sha256'] and all(sha(source/f)==h for f,h in H.items())
 status['records_sha256']=sha(out/'records.txt');status['result']='PASS_SOURCE_ONLY'
except BaseException as e:status['result']='FAIL';status['error']=repr(e);raise
finally:
 status['finished']=datetime.now(timezone.utc).isoformat();status['artifacts']={p.name:sha(p) for p in out.iterdir() if p.is_file()};(out/'report.json').write_text(json.dumps(status,indent=2)+'\n')
print(out/'report.json')
