#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Realtek PCI-Express SD/MMC Card Interface driver
# Copyright(c) 2009-2013 Realtek Semiconductor Corp. All rights reserved.
# Author: Wei WANG <wei_wang@realsil.com.cn>
# include/linux/mmc/host.h: GPL-2.0-only; Host driver specific definitions.
# Its complete original notice is retained in the generated fixture.
"""Source-only RTSX phase/timing baseline; native behavior is verified separately."""
import hashlib,json,re,shutil,subprocess,sys
from pathlib import Path
source,out=map(Path,sys.argv[1:]);pin='cc9de5d4b5ab6459f5774946aa3195ad51236fa8'
hashes={'drivers/mmc/host/rtsx_pci_sdmmc.c':'38d7eea80901e32d77fce1029fc6bbf5aaaf2ad2fc56a8f962002907ac062204','include/linux/rtsx_pci.h':'b2be76fcbfbcd5337253c59c42d4362d20a6df726b8009f206201854df4967cb','include/linux/mmc/host.h':'48ddebc041d079a90ba43628d106acbd2b0a09bbe459deca9d7a73ae561945cc','Makefile':'77d977b5a40efd0338d6aca5d4fa932db44c76635b96b103b3b338e829484a22'}
texts={}
for p,h in hashes.items():
 raw=(source/p).read_bytes();assert hashlib.sha256(raw).hexdigest()==h,p;texts[p]=raw.decode()
assert 'KBUILD_CFLAGS\t+= -fno-strict-overflow' in texts['Makefile'];out.mkdir(exist_ok=False,parents=True);fragments=[]
text=texts['drivers/mmc/host/rtsx_pci_sdmmc.c']
def function(name):
 m=re.search(r'^(?:(?:static|inline) )*(?:u8|u32|int) '+name+r'\([^;{}]*\)\n\{',text,re.M);assert m,name
 end=m.end();depth=1
 while depth:depth+=(text[end]=='{')-(text[end]=='}');end+=1
 body=text[m.start():end];fragments.append(dict(name=name,sha256=hashlib.sha256(body.encode()).hexdigest()));return body
bodies=[function(n) for n in ['sd_change_phase','test_phase_bit','sd_get_phase_len','sd_search_final_phase','sd_set_timing']]
defs={}
for t in texts.values():
 for name,params,value in re.findall(r'^#define\s+([A-Za-z][A-Za-z0-9_]*)(\([^\n]*?\))?\s+(.+)$',t.replace('\\\n',''),re.M):defs[name]=(params,value)
clean=lambda s:re.sub(r'/\*.*?\*/|//[^\n]*','',s,flags=re.S)
names=set(re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\b',clean('\n'.join(bodies)))) & defs.keys()
while True:
 old=set(names)
 for n in old:names.update(set(re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\b',clean(defs[n][1]))) & defs.keys())
 if names==old:break
c=text.split('#include')[0]+texts['include/linux/mmc/host.h'].split('#ifndef')[0]+r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define dev_dbg(...) ((void)0)
#define dev_err(...) ((void)0)
struct rtsx_pcr {u8 regs[65536];unsigned ci;};
struct realtek_pci_sdmmc {struct rtsx_pcr *pcr;};
static int rtsx_pci_write_register(struct rtsx_pcr *p,u16 at,u8 m,u8 v) {p->regs[at]=(p->regs[at]&~m)|(v&m);return 0;}
static void rtsx_pci_add_cmd(struct rtsx_pcr *p,unsigned kind,u16 at,u8 m,u8 v) {(void)kind;rtsx_pci_write_register(p,at,m,v);}
static int rtsx_pci_send_cmd(struct rtsx_pcr *p,unsigned time) {(void)p;(void)time;return 0;}
'''
c+='\n'.join('#define '+n+defs[n][0]+' '+defs[n][1] for n in sorted(names))+'\n'+'\n'.join(bodies)
c+=r'''
static u32 rotate(u32 v,unsigned bits) {return bits?(v<<bits)|(v>>(32-bits)):v;}
static void emit_map(struct realtek_pci_sdmmc *h,u32 map) {printf("F %u %u\n",map,sd_search_final_phase(h,map));}
int main(void) {
 struct rtsx_pcr p={0};struct realtek_pci_sdmmc h={&p};const u8 seeds[3]={0,0x5a,0xff};
 for(unsigned timing=0;timing<7;++timing)for(unsigned seed=0;seed<3;++seed) {
  p.regs[SD_CFG1]=p.regs[CLK_CTL]=p.regs[CARD_CLK_SOURCE]=p.regs[SD_PUSH_POINT_CTL]=p.regs[SD_SAMPLE_POINT_CTL]=seeds[seed];
  if(sd_set_timing(&h,timing))abort();
  printf("T %u %u %u %u %u %u %u\n",timing,seeds[seed],p.regs[SD_CFG1],p.regs[CLK_CTL],p.regs[CARD_CLK_SOURCE],p.regs[SD_PUSH_POINT_CTL],p.regs[SD_SAMPLE_POINT_CTL]);
 }
 for(unsigned rx=0;rx<2;++rx)for(unsigned phase=0;phase<32;++phase)for(unsigned seed=0;seed<3;++seed) {
  p.regs[SD_CFG1]=p.regs[CLK_CTL]=p.regs[SD_VPTX_CTL]=p.regs[SD_VPRX_CTL]=seeds[seed];
  if(sd_change_phase(&h,phase,rx))abort();
  printf("P %u %u %u %u %u %u %u\n",rx,phase,seeds[seed],p.regs[SD_CFG1],p.regs[CLK_CTL],p.regs[SD_VPTX_CTL],p.regs[SD_VPRX_CTL]);
 }
 emit_map(&h,0);emit_map(&h,UINT32_MAX);
 for(unsigned len=1;len<32;++len)for(unsigned start=0;start<32;++start)emit_map(&h,rotate((1U<<len)-1,start));
 const u32 patterns[5]={0xaaaaaaaa,0x55555555,0xc0000003,0xf00f,0x80000001};for(unsigned i=0;i<5;++i)emit_map(&h,patterns[i]);
 u32 random=0xa5a55a5a;for(unsigned i=0;i<2048;++i) {random^=random<<13;random^=random>>17;random^=random<<5;emit_map(&h,random);}
 return 0;
}
'''
(out/'oracle.c').write_text(c);cc=shutil.which('clang') or shutil.which('gcc');assert cc
command=[cc,'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-fno-strict-overflow','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(out/'oracle.c'),'-o',str(out/'oracle')]
r=subprocess.run(command,capture_output=True,text=True,timeout=60);(out/'compile.log').write_text(r.stdout+r.stderr);r.check_returncode();r=subprocess.run([str(out/'oracle')],capture_output=True,text=True,timeout=60);(out/'stderr.log').write_text(r.stderr);r.check_returncode();assert len(r.stdout.splitlines())==3260
(out/'records.txt').write_text(r.stdout);(out/'report.json').write_text(json.dumps(dict(pin=pin,sources=hashes,functions=fragments,records=3260,command=command,output_sha256=hashlib.sha256(r.stdout.encode()).hexdigest(),limits=['Five complete unchanged phase/circularsearch/timing helpers, 21timing/192phase/3047map records','Native admission/tuning/PIO/error qualification separate; queued writes linearized underexclusiveaccess, no physical completion/IRQ/DMA','Pinned Makefile1166 -fno-strict-overflow preserves actualkernel compiler signedshift policy; original1<<31 body remains unchanged and all UBSan checks enabled','Source-only baseline, not paired3260native comparison or full CMD11/tuning trace equivalence']),indent=2)+'\n');print(out/'report.json')
