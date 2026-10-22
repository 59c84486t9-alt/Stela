#!/usr/bin/env python3
"""Compile unchanged actual PCI send callbacks after full MCU fill helpers.

Usage: mt792x_pci_mcu_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY
Models queue handoff, captures effective post-fill timeout/queue/wire bytes.
The pinned common send path's expiry-after-callback order is source-checked.
No wall-clock timeout or hardware DMA proof is claimed by this codec oracle.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
source,out=map(Path,sys.argv[1:]);out.mkdir(parents=True,exist_ok=False)
hashes={
 'mt7921/pci_mcu.c':'3245b5e72efb6913a99a20dcaae14c5f5748fc0b2ac8f47c4b43fb17e4c0057b',
 'mt7925/pci_mcu.c':'9569a85ab5888050b4afef34a061d555c41b89835f6ed38c8f1d5ceff3b7d290',
 'mcu.c':'e0c3fc3323c0482afbd3a943676e5091e5832da4a1e2f711303183f886f4c79a',
}
texts={}
for name,digest in hashes.items():
 raw=(source/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==digest,name;texts[name]=raw.decode()
def function(file,name):
 text=texts[file];m=re.search(r'\b'+name+r'\([^;{}]*?\)\n\{',text);assert m,name
 start=text.rfind('\n\n',0,m.start())+2;at,depth=m.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[start:at]+'\n'
common=function('mcu.c','mt76_mcu_skb_send_and_get_msg')
assert common.index('dev->mcu_ops->mcu_skb_send_msg(dev, skb, cmd, wait_resp ? &seq : NULL)') < common.index('expires = jiffies + dev->mcu.timeout;')
# Reuse the exact complete fill unit and independently preserve all existing
# immutable boot/UNI/capability outputs in its own fresh child directory.
generator=Path(__file__).with_name('mt792x_mcu_oracle.py')
subprocess.run([sys.executable,str(generator),str(source),str(out/'fill')],stdout=subprocess.PIPE,check=True)
manifest=json.loads((out/'fill/manifest.json').read_text());hashes.update(manifest['sources'])
unit=(out/'fill/linux-mt792x-mcu.c').read_text().split('int main(',1)[0]
old='struct mt76_dev { struct { int timeout; u8 msg_seq; } mcu; };'
new='struct mt76_dev { struct { int timeout; u8 msg_seq; } mcu; void *q_mcu[2]; };'
assert old in unit;unit=unit.replace(old,new)
scaffold=r'''
#include <stddef.h>
struct mt792x_dev { struct mt76_dev mt76; };
enum mt76_mcuq_id { MT_MCUQ_WM, MT_MCUQ_FWDL };
#define container_of(ptr,type,member) ((type *)((u8 *)(ptr)-offsetof(type,member)))
static enum mt76_mcuq_id actual_queue;
static int mt76_tx_queue_skb_raw(struct mt792x_dev *d,void *q,struct sk_buff *s,int flags) {
 (void)s;if(flags)abort();
 if(q==d->mt76.q_mcu[MT_MCUQ_WM])actual_queue=MT_MCUQ_WM;
 else if(q==d->mt76.q_mcu[MT_MCUQ_FWDL])actual_queue=MT_MCUQ_FWDL;
 else abort();return 0;
}
'''
main=r'''
int main(int argc,char **argv) {
 if(argc!=2)return 1;int chip=atoi(argv[1]);struct mt792x_dev owner={0};struct mt76_dev *d=&owner.mt76;
 u8 queues[2];d->q_mcu[0]=&queues[0];d->q_mcu[1]=&queues[1];
 u8 commands[]={1,2,5,7,0x10,0xee};
 for(int i=0;i<90;i++) {
  u8 profile=(i/6)%3,cmd=commands[i%6];int n=cmd==0xee?4096:cmd==2?8:(cmd==1||cmd==5)?12:4;
  if(profile==1){cmd=1+i%3;n=8+(i*37)%1000;}
  if(profile==2){cmd=chip==7925?14:0x8a;n=chip==7925?8:0;}
  u8 *allocation=calloc(1,n+128);if(!allocation)abort();struct sk_buff s={.data=allocation+128,.len=n};
  for(int j=0;j<n;j++)s.data[j]=(u8)(i*17+j);
  if(profile==2&&chip==7925){memset(s.data,0,n);s.data[4]=3;s.data[6]=4;}
  int wire_cmd=cmd|(profile==1?__MCU_CMD_FIELD_UNI:profile==2?(chip==7925?__MCU_CMD_FIELD_UNI:__MCU_CMD_FIELD_CE):0);
  int seq=0;int rc=chip==7925?mt7925_mcu_send_message(d,&s,wire_cmd,&seq):mt7921_mcu_send_message(d,&s,wire_cmd,&seq);
  if(rc)abort();u8 hdr[4]={profile,cmd,seq,actual_queue};u32 details[]={d->mcu.timeout,s.len};
  if(fwrite(hdr,1,4,stdout)!=4||fwrite(details,1,8,stdout)!=8||fwrite(s.data,1,s.len,stdout)!=(size_t)s.len)abort();free(allocation);
 }
 return 0;
}
'''
unit_path=out/'linux-mt792x-pci-mcu.c';unit_path.write_text(unit+scaffold+function('mt7921/pci_mcu.c','mt7921_mcu_send_message')+function('mt7925/pci_mcu.c','mt7925_mcu_send_message')+main)
exe=out/'linux-mt792x-pci-mcu';subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(unit_path),'-o',str(exe)],check=True)
cases=[]
for chip in [7921,7922,7925]:
 trace=subprocess.run([str(exe.resolve()),str(chip)],stdout=subprocess.PIPE,check=True).stdout
 (out/f'{chip}.trace').write_bytes(trace);cases.append({'chip':chip,'messages':90,'bytes':len(trace),'sha256':hashlib.sha256(trace).hexdigest()})
(out/'manifest.json').write_text(json.dumps({'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':hashes,'hz':1000,'expiry_after_actual_send_callback':True,'cases':cases,'unchanged_fill_cases':manifest['cases']},indent=2)+'\n')
print(json.dumps(cases,indent=2))
