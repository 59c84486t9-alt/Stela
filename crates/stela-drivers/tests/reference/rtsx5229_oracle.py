#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright(c) 2009-2013 Realtek Semiconductor Corp. All rights reserved.
# Original authors: Wei WANG, Roger Tseng.
"""Execute nine unchanged RTS5229 setup/voltage/power functions.

Usage: rtsx5229_oracle.py VERIFIED_REFERENCE_ROOT FRESH_OUTPUT_DIRECTORY
Register/PCI/PHY and command-queue boundaries are modeled; no physical device.
"""
import hashlib,json,re,shutil,subprocess,sys
from pathlib import Path
PIN='cc9de5d4b5ab6459f5774946aa3195ad51236fa8'
HASHES={'drivers/misc/cardreader/rts5229.c':'fd352fcd7ff00a8557ae8eafc57ceaa71ad5a2053aa597059db92edced7fb591','drivers/misc/cardreader/rtsx_pcr.h':'59c6edae2aeed0773e6053d74c0a3e03e52c3d7d32c5e69400cd13f4cf966efb','include/linux/rtsx_pci.h':'b2be76fcbfbcd5337253c59c42d4362d20a6df726b8009f206201854df4967cb'}
HASHES['include/linux/rtsx_common.h']='9fa9f06ccc72dd843ec99b0a237100720aa8ef9276bbb91832512fd31cdb30a4'
source,out=map(Path,sys.argv[1:]);texts={}
for path,digest in HASHES.items():
 raw=(source/path).read_bytes();assert hashlib.sha256(raw).hexdigest()==digest,path;texts[path]=raw.decode()
out.mkdir(exist_ok=False,parents=True);fragments=[]
def function(path,name):
 text=texts[path];m=re.search(r'^(?:(?:static|inline) )*(?:u8|int|void) '+name+r'\([^;{}]*\)\n\{',text,re.M);assert m,name
 end=m.end();depth=1
 while depth:depth+=(text[end]=='{')-(text[end]=='}');end+=1
 body=text[m.start():end];fragments.append(dict(path=path,name=name,sha256=hashlib.sha256(body.encode()).hexdigest()));return body
bodies=[function('drivers/misc/cardreader/rtsx_pcr.h','map_sd_drive')]
bodies += [function('drivers/misc/cardreader/rts5229.c',name) for name in ['rts5229_get_ic_version','rts5229_fetch_vendor_settings','rts5229_extra_init_hw','rts5229_optimize_phy','rts5229_card_power_on','rts5229_card_power_off','rts5229_switch_output_voltage','rts5229_init_params']]
tables=re.findall(r'static const u32 rts5229_[^;]+?\n\};',texts['drivers/misc/cardreader/rts5229.c'],re.S);assert len(tables)==6
all_text='\n'.join(bodies+tables)
definitions={}
for text in texts.values():
 for name,params,value in re.findall(r'^#define\s+([A-Za-z][A-Za-z0-9_]*)(\([^\n]*?\))?\s+(.+)$',text.replace('\\\n',''),re.M):definitions[name]=(params,value)
clean=lambda s:re.sub(r'/\*.*?\*/|//[^\n]*','',s,flags=re.S)
names=set(re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\b',clean(all_text))) & definitions.keys()
names.update(['PCR_SETTING_REG1','PCR_SETTING_REG2','SD30_DRIVE_SEL','SD_POWER_MASK','LDO3318_PWR_MASK'])
names.discard('pcr_dbg')
while True:
 old=set(names)
 for name in old:names.update(set(re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\b',clean(definitions[name][1]))) & definitions.keys())
 if names==old:break
c=texts['drivers/misc/cardreader/rts5229.c'].split('#include')[0]+r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define pcr_dbg(...) ((void)0)
struct pci_dev {u32 setting1,setting2;};
struct pcr_ops {int unused;};
static const struct pcr_ops rts5229_pcr_ops={0};
struct rtsx_pcr {struct pci_dev *pci;unsigned extra_caps,num_slots,flags,aspm_en,aspm_mode,tx_initial_phase,rx_initial_phase,ic_version,ci;const struct pcr_ops *ops;u8 card_drive_sel,sd30_drive_sel_1v8,sd30_drive_sel_3v3;const u32 *sd_pull_ctl_enable_tbl,*sd_pull_ctl_disable_tbl,*ms_pull_ctl_enable_tbl,*ms_pull_ctl_disable_tbl;u8 regs[65536];u16 phy[256];};
static unsigned delay_us;
static int pci_read_config_dword(struct pci_dev *,unsigned,u32 *);
static int rtsx_pci_read_register(struct rtsx_pcr *p,u16 at,u8 *v) {*v=p->regs[at];return 0;}
static int rtsx_pci_write_register(struct rtsx_pcr *p,u16 at,u8 mask,u8 value) {p->regs[at]=(p->regs[at]&~mask)|(value&mask);return 0;}
static int rtsx_pci_write_phy_register(struct rtsx_pcr *p,u8 at,u16 v) {p->phy[at]=v;return 0;}
/* No independent user observes these serialized modeled queued stores. */
static void rtsx_pci_add_cmd(struct rtsx_pcr *p,unsigned kind,u16 at,u8 mask,u8 v) {(void)kind;rtsx_pci_write_register(p,at,mask,v);}
static int rtsx_pci_send_cmd(struct rtsx_pcr *p,unsigned timeout) {(void)p;(void)timeout;return 0;}
static void udelay(unsigned us) {delay_us+=us;}
'''
c+='\n'.join('#define '+name+definitions[name][0]+' '+definitions[name][1] for name in sorted(names))+'\n'
c+=re.search(r'^enum ASPM_MODE[^\n]+;',texts['include/linux/rtsx_pci.h'],re.M)[0]+'\n'
c+='''static int pci_read_config_dword(struct pci_dev *p,unsigned at,u32 *v) {if(at==PCR_SETTING_REG1)*v=p->setting1;else if(at==PCR_SETTING_REG2)*v=p->setting2;else abort();return 0;}\n'''
c+='\n'.join(tables+bodies)
c+=r'''
int main(void) {
 const unsigned revisions[3]={0,2,15};
 for(unsigned rev=0;rev<3;++rev)for(unsigned valid=0;valid<2;++valid)
 for(unsigned drive18=0;drive18<4;++drive18)for(unsigned drive33=0;drive33<4;++drive33)
 for(unsigned carddrive=0;carddrive<2;++carddrive)for(unsigned aspm=0;aspm<2;++aspm) {
  struct pci_dev pci={.setting1=(valid?0:1U<<24)|(drive18<<26)|(carddrive<<25)|((aspm?3:0)<<28),.setting2=drive33<<5|0x00c04010};
  struct rtsx_pcr p={.pci=&pci};p.regs[DUMMY_REG_RESET_0]=0xa0|revisions[rev];
  rts5229_init_params(&p);rts5229_fetch_vendor_settings(&p);
  if(rts5229_extra_init_hw(&p)||rts5229_optimize_phy(&p))abort();
  p.regs[SD30_DRIVE_SEL]=0xb8;
  if(rts5229_switch_output_voltage(&p,OUTPUT_1V8))abort();unsigned v18=p.regs[SD30_DRIVE_SEL],phy18=p.phy[8];
  if(rts5229_switch_output_voltage(&p,OUTPUT_3V3))abort();unsigned v33=p.regs[SD30_DRIVE_SEL],phy33=p.phy[8];
  delay_us=0;if(rts5229_card_power_on(&p,0))abort();unsigned on=p.regs[CARD_PWR_CTL]&SD_POWER_MASK,gate=p.regs[PWR_GATE_CTRL]&LDO3318_PWR_MASK;
  if(rts5229_card_power_off(&p,0))abort();
  printf("R %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u\n",revisions[rev],valid,drive18,drive33,carddrive,aspm,p.ic_version,p.card_drive_sel,p.sd30_drive_sel_1v8,p.sd30_drive_sel_3v3,p.sd_pull_ctl_enable_tbl[0]&255,p.sd_pull_ctl_enable_tbl[1]&255,p.sd_pull_ctl_disable_tbl[0]&255,p.sd_pull_ctl_disable_tbl[1]&255,p.phy[0],v18,phy18,v33,phy33,on,gate,delay_us,p.regs[CARD_PWR_CTL]&SD_POWER_MASK,p.regs[PWR_GATE_CTRL]&LDO3318_PWR_MASK);
 }
 return 0;
}
'''
(out/'oracle.c').write_text(c);compiler=shutil.which('clang') or shutil.which('gcc');assert compiler
command=[compiler,'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(out/'oracle.c'),'-o',str(out/'oracle')]
r=subprocess.run(command,capture_output=True,text=True,timeout=60);(out/'compile.log').write_text(r.stdout+r.stderr);r.check_returncode()
r=subprocess.run([str(out/'oracle')],capture_output=True,text=True,timeout=60);(out/'stderr.log').write_text(r.stderr);r.check_returncode();assert len(r.stdout.splitlines())==384
(out/'records.txt').write_text(r.stdout);(out/'report.json').write_text(json.dumps(dict(pin=PIN,sources=HASHES,fragments=fragments,records=384,command=command,output_sha256=hashlib.sha256(r.stdout.encode()).hexdigest(),limitations=['Nine complete unchanged setup/vendor/drive/voltage/power functions and six original pull tables execute; recorded comparison fields are register/PHY/board/power effects, not full eventtrace equivalence','PCI/register/PHY/queued-command boundaries modeled; queued writes linearized under exclusive access, no error/IRQ/DMA/busy/physical execution','Native actual-controller/card peers separately execute cold initialization, real PIO payloads, deadlines, pull/power sequencing and failed acknowledgments','RTS5229 native public path currently ordinary SD/MMC; source1.8V helper comparison does not grant SD UHS or CMD11/tuning; MS/PM/DMA remain unsupported']),indent=2)+'\n');print(out/'report.json')
