#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Five unchanged Linux Atlantic FLB/RBL reset helpers; actual effects/waits.
Usage: aqtion_reset_oracle.py VERIFIED_ATLANTIC_DIRECTORY FRESH_OUTPUT
Read/write/time boundaries are independently modeled; no physical reset claim.
"""
import hashlib,json,os,pathlib,re,shutil,subprocess,sys
from datetime import datetime,timezone
source,out=map(pathlib.Path,sys.argv[1:])
HASHES={'hw_atl/hw_atl_utils.c': 'ec71b0f209b263926dca1adc36e304e827d905e848c5b2a2eb3722f8a7ddb981', 'hw_atl/hw_atl_llh.c': '26921d261d50b1b66911671d398cb257c00ef099461398697d76f9935633358d', 'hw_atl/hw_atl_llh_internal.h': '81f10e0620c9b7114892bf06e115d2c9e18b6988c6078c592a68cfb3c44d74d6', 'aq_hw_utils.c': 'd28153e839b7a7945956ec30adbe8eb5136328fb1f822a33f4ef3324510cae8f', 'aq_hw_utils.h': 'd9f050b56ae5b7e2612c473a77aada56cfbc7e92670ab1fa14804eb870881c65'}
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
texts={}
for p,h in HASHES.items():
 assert sha(source/p)==h,p
 texts[p]=(source/p).read_text()
assert not out.exists(),"preserve historical outputs"
out.mkdir(parents=True)
def function(file,name):
 t=texts[file];m=re.search(r"^(?:static )?(?:int|void|u32)\s+"+name+r"\([^;{}]*?\)\n\{",t,re.M);assert m,name
 i=m.end();depth=1
 while depth:depth+=(t[i]=='{')-(t[i]=='}');i+=1
 return t[m.start():i]
helpers=[('aq_hw_utils.c','aq_hw_write_reg_bit'),('hw_atl/hw_atl_llh.c','hw_atl_rx_rx_reg_res_dis_set'),('hw_atl/hw_atl_llh.c','hw_atl_tx_tx_reg_res_dis_set'),('hw_atl/hw_atl_utils.c','hw_atl_utils_soft_reset_flb'),('hw_atl/hw_atl_utils.c','hw_atl_utils_soft_reset_rbl')]
bodies=[function(f,n) for f,n in helpers]
prelude=r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2014-2019 aQuantia Corporation
// Copyright (C) 2019-2020 Marvell International Ltd.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define aq_pr_err(...) ((void)0)
struct aq_hw_s{u32 regs[0x8000/4],gsr;};
struct effect{u32 kind,address,value;};
static struct effect effects[64];static unsigned ne;
static void record(u32 kind,u32 at,u32 val){if(ne>=64)abort();effects[ne++]=(struct effect){kind,at,val};}
static u32 aq_hw_read_reg(struct aq_hw_s*h,u32 a){if(a%4||a>=0x8000)abort();return a==0?h->gsr:h->regs[a/4];}
static void aq_hw_write_reg(struct aq_hw_s*h,u32 a,u32 v){
 if(a%4||a>=0x8000)abort();record(0,a,v);h->regs[a/4]=v;
 if(a==0x404&&v==0x40e0)h->regs[0x388/4]=1;
 if(a==0x404&&v==0x180e0)h->regs[0x704/4]=0x10;
}
static void mdelay(unsigned ms){record(1,0,ms*1000);}
'''
macros=texts['hw_atl/hw_atl_llh_internal.h']+'\n'
macros+='\n'.join(line for line in texts['hw_atl/hw_atl_utils.c'].splitlines() if line.startswith('#define HW_ATL_') or line.startswith('#define FORCE_FLASHLESS'))
macros+='\n'+next(line for line in texts['aq_hw_utils.h'].splitlines() if line.startswith('#define AQ_HW_SLEEP'))
main=r'''
int main(void){const u32 g[]={0,0x55aa1234,0x00ff4444,0xdeadbeef};
 for(unsigned flb=0;flb<2;flb++)for(unsigned gi=0;gi<4;gi++)for(unsigned spi=0;spi<2;spi++)for(unsigned seed=0;seed<2;seed++){
  struct aq_hw_s h={0};h.gsr=g[gi];h.regs[0x53c/4]=spi?0x13579bcd:0;
  h.regs[0x5000/4]=h.regs[0x7000/4]=h.regs[0x4000/4]=0x20000000U|(seed?0x05030201U:0);
  h.regs[0x18/4]=0x0301005a;ne=0;
  int ret=flb?hw_atl_utils_soft_reset_flb(&h):hw_atl_utils_soft_reset_rbl(&h);
  printf("R %u %u %u %u %d %u",flb,h.gsr,spi,seed,ret,ne);
  for(unsigned i=0;i<ne;i++)printf(" %u %u %u",effects[i].kind,effects[i].address,effects[i].value);
  puts("");
 }
}
'''
unit=out/'linux-reset.c';unit.write_text('\n'.join([prelude,macros,*bodies,main]))
compiler=pathlib.Path(shutil.which('clang') or sys.exit('clang unavailable')).resolve()
version=subprocess.run([str(compiler),'--version'],capture_output=True,text=True,check=True,timeout=10)
exe=out/'linux-reset';command=[str(compiler),'-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(unit.resolve()),'-o',str(exe.resolve())]
env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
admission={'pin':'cc9de5d4b5ab6459f5774946aa3195ad51236fa8','sources':HASHES,'helpers':{n:sha256 for (_,n),sha256 in zip(helpers,[hashlib.sha256(b.encode()).hexdigest() for b in bodies])},'script_sha256':sha(__file__),'unit_sha256':sha(unit),'compiler':str(compiler),'compiler_sha256':sha(compiler),'compiler_version':version.stdout,'command':command,'started':datetime.now(timezone.utc).isoformat(),'scope':'Complete5helpers,32ready-bootcases,orderedwrites/requestedwaits; read0 exposes independently retained control/status highbits across reset; no physical claim'}
(out/'admission.json').write_text(json.dumps(admission,indent=2)+'\n')
status={'compile':'not started','execute':'not started'}
try:
 with (out/'compile.stdout').open('xb') as so,(out/'compile.stderr').open('xb') as se:
  p=subprocess.run(command,stdout=so,stderr=se,timeout=60);status['compile']=p.returncode;p.check_returncode()
 status['binary_before_execution_sha256']=sha(exe)
 (out/'execution-admission.json').write_text(json.dumps(status,indent=2)+'\n')
 with (out/'records.txt').open('xb') as so,(out/'execute.stderr').open('xb') as se:
  p=subprocess.run([str(exe.resolve())],stdout=so,stderr=se,env=env,timeout=15);status['execute']=p.returncode;p.check_returncode()
 assert len((out/'records.txt').read_text().splitlines())==32
 assert all(sha(source/p)==h for p,h in HASHES.items())
 assert sha(unit)==admission['unit_sha256'] and sha(__file__)==admission['script_sha256']
 assert sha(exe)==status['binary_before_execution_sha256'] and sha(compiler)==admission['compiler_sha256']
 status['records_sha256']=sha(out/'records.txt');status['result']='PASS'
except BaseException as e:status['result']='FAIL';status['error']=repr(e);raise
finally:
 status['finished']=datetime.now(timezone.utc).isoformat();status['artifacts']={p.name:sha(p) for p in out.iterdir() if p.is_file()}
 (out/'report.json').write_text(json.dumps(status,indent=2)+'\n')
print(out/'report.json')
