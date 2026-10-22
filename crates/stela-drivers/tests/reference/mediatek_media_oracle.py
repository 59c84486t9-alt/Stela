#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
# Linux extracted function terms: GPL-2.0-or-later (btusb), ISC (btmtk).
# Copyright (C) 2005-2008 Marcel Holtmann; Copyright (C) 2021 MediaTek Inc.
"""Compare pinned unchanged MT7925 media helpers with native source.
Usage: mediatek_media_oracle.py PINNED_LINUX_DIRECTORY NEW_OUTPUT_DIRECTORY
No hardware access. Logical skb capacity264 is an explicit fixture boundary.
CARGO_TARGET_DIR may name a private existing cache; CARGO_BUILD_JOBS is one.
"""
from pathlib import Path
import hashlib,json,subprocess,sys,os,shutil
base,out=map(Path,sys.argv[1:])
out.mkdir(parents=True,exist_ok=False)
root=Path(__file__).resolve().parents[4]
expected={
 'btusb.c':'6d3d641ea15cc84834ec1becd3cd1860ec578be6b12ec92c5a06706f2e4678b6',
 'btmtk.c':'a8c5f0b8d655bc353a12059db49a8ee2a6f15ff8d95192d3cb6b9acec1d3a5c1',
 'btmtk.h':'bb6c73f2d57658bd20a6bfbb6e2ce1ab1edc650e36045be3399be567b665809b',
}
for name,digest in expected.items():
 assert hashlib.sha256((base/name).read_bytes()).hexdigest()==digest,name
def function(path,signature):
 s=path.read_text(); start=s.index(signature); opening=s.index('{',start); depth=0
 for i in range(opening,len(s)):
  if s[i]=='{':depth+=1
  elif s[i]=='}':
   depth-=1
   if depth==0:return s[start:i+1]
parts=[function(base/'btusb.c','static void btusb_work('),function(base/'btmtk.c','static int btmtk_isopkt_pad('),function(base/'btmtk.c','static int btmtk_recv_isopkt(')]
pre=r'''// Unmodified pinned Linux functions; synthetic boundary stubs only.
// btusb: GPL-2.0-or-later, Copyright 2005-2008 Marcel Holtmann.
// btmtk: ISC, Copyright 2021 MediaTek Inc.
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
#define MTK_ISO_THRESHOLD 264
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
typedef unsigned uint;
#define HCI_MAX_ISO_SIZE 251
#define HCI_ISO_HDR_SIZE 4
#define HCI_ISODATA_PKT 5
#define GFP_ATOMIC 0
#define BTUSB_DID_ISO_RESUME 0
#define BTUSB_ISOC_RUNNING 1
#define BTUSB_USE_ALT3_FOR_WBS 2
#define HCI_NOTIFY_ENABLE_SCO_CVSD 1
#define HCI_NOTIFY_ENABLE_SCO_TRANSP 2
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define container_of(ptr,t,m) ((t*)((char*)(ptr)-offsetof(t,m)))
#define bt_dev_err(...) ((void)0)
#define bt_dev_info(...) ((void)0)
#define spin_lock_irqsave(a,b) ((void)0)
#define spin_unlock_irqrestore(a,b) ((void)0)
#define __le16_to_cpu(a) (a)
typedef uint16_t __le16;
struct hci_iso_hdr { uint16_t handle,dlen; } __attribute__((packed));
struct sk_buff { unsigned len,expect,type; unsigned char data[264]; };
struct btmtk_data { struct sk_buff *isopkt_skb; int isorxlock; };
struct hci_dev { unsigned voice_setting,sco_mtu; struct btmtk_data *data; };
struct work_struct { int unused; };
struct btusb_data { struct work_struct work; struct hci_dev *hdev; unsigned sco_num,air_mode,mask; unsigned long flags; void *isoc,*intf; int isoc_anchor,selected; };
static int usb_autopm_get_interface(void*p){return 0;}
static void usb_autopm_put_interface(void*p){}
static void usb_kill_anchored_urbs(void*p){}
static int test_bit(int bit,unsigned long*p){return (*p>>bit)&1;}
static int test_and_clear_bit(int bit,unsigned long*p){int v=test_bit(bit,p);*p&=~(1ul<<bit);return v;}
static void clear_bit(int bit,unsigned long*p){*p&=~(1ul<<bit);}
static void set_bit(int bit,unsigned long*p){*p|=1ul<<bit;}
static void *btusb_find_altsetting(struct btusb_data*d,int alt){return d->mask&(1u<<alt)?d:NULL;}
static int btusb_switch_alt_setting(struct hci_dev*h,int alt){struct btusb_data*d=(void*)(h+1); if(!(d->mask&(1u<<alt)))return -1;d->selected=alt;return 0;}
static int __set_isoc_interface(struct hci_dev*h,int alt){struct btusb_data*d=(void*)(h+1);d->selected=alt;return 0;}
static struct btmtk_data *hci_get_priv(struct hci_dev*h){return h->data;}
static struct sk_buff *bt_skb_alloc(int n,int flags){return calloc(1,sizeof(struct sk_buff));}
static int skb_pad(struct sk_buff*s,unsigned n){if(n>264-s->len)return -1;memset(s->data+s->len,0,n);return 0;}
static void __skb_put(struct sk_buff*s,unsigned n){s->len+=n;}
static void skb_put_data(struct sk_buff*s,const void*p,unsigned n){if(n>264-s->len)abort();memcpy(s->data+s->len,p,n);s->len+=n;}
static unsigned skb_tailroom(struct sk_buff*s){return 264-s->len;}
static void kfree_skb(struct sk_buff*s){free(s);}
#define hci_skb_pkt_type(s) ((s)->type)
#define hci_skb_expect(s) ((s)->expect)
static void print_hex(const unsigned char*p,unsigned n){for(unsigned i=0;i<n;i++)printf("%02x",p[i]);}
static void hci_recv_frame(struct hci_dev*h,struct sk_buff*s){print_hex(s->data,s->len);printf(";");free(s);}
'''
main=r'''
int main(void){
 struct {struct hci_dev h;struct btusb_data d;} s={0};s.d.hdev=&s.h;s.d.flags=3;s.h.sco_mtu=72;
 for(unsigned mask=0;mask<3;mask++)for(unsigned mode=1;mode<=2;mode++)for(unsigned bits=0;bits<2;bits++)for(unsigned links=0;links<=3;links++){
 s.d.mask=mask==0?127:mask==1?63:61;s.d.air_mode=mode;s.d.sco_num=links;s.h.voice_setting=bits?32:0;s.d.selected=-1;s.d.flags=3;btusb_work(&s.d.work);
 printf("A %u %u %u %u %d\n",mask,mode,bits,links,s.d.selected);
 }
 for(unsigned len=4;len<=265;len++){
 struct sk_buff skb={.len=len};for(unsigned i=0;i<len&&i<264;i++)skb.data[i]=(unsigned char)i;
 skb.data[2]=(len-4)&255;skb.data[3]=(len-4)>>8;int r=btmtk_isopkt_pad(&s.h,&skb);printf("P %u %d ",len,r);if(!r)print_hex(skb.data,skb.len);printf("\n");
 }
 unsigned char raw[]={1,0,3,0,9,8,7,2,0,2,0,6,5};
 for(unsigned split=0;split<=sizeof(raw);split++){
 struct btmtk_data data={0};s.h.data=&data;printf("F %u ",split);
 int a=btmtk_recv_isopkt(&s.h,raw,split);int b=btmtk_recv_isopkt(&s.h,raw+split,sizeof(raw)-split);
 printf(" %d %d %d\n",a,b,data.isopkt_skb!=NULL);if(data.isopkt_skb)free(data.isopkt_skb);
 }
 return 0;
}
'''
src=pre+'\n\n'.join(parts)+main
(out/'linux_media.c').write_text(src)
subprocess.run(['clang','-std=gnu11','-O2','-fsanitize=address,undefined','-fno-omit-frame-pointer','-Wno-unused-value',str(out/'linux_media.c'),'-o',str(out/'linux_media')],check=True)
with (out/'linux-output.txt').open('wb') as f:subprocess.run([str(out/'linux_media')],stdout=f,check=True)
(out/'extraction.json').write_text(json.dumps({'linux_revision':'a804c5742bff224d4cb4d25dd383554d598be32b','functions':[{'signature':p[:p.index('{')].strip(),'bytes':len(p.encode()),'sha256':hashlib.sha256(p.encode()).hexdigest()} for p in parts],'stubs':'synthetic only; skb capacity264 is an explicit model budget, not Linux allocator prediction; no USB/HCI hardware calls'},indent=2)+'\n')

out_saved=out
out=out/'rust'
(out/'src').mkdir(parents=True,exist_ok=True)
(out/'Cargo.toml').write_text('[package]\nname="mt7925-media-oracle"\nversion="0.1.0"\nedition="2024"\n[workspace]\n[dependencies]\nstela-drivers={path='+repr(str(root/'crates/stela-drivers')).replace("'",'"')+'}\n')
source=(root/'crates/stela-drivers/src/usb/bluetooth/mediatek/media/framing.rs').read_text()
# Compile the actual production framer verbatim except inner documentation,
# which Rust cannot include after an include! expansion. The receipt binds both.
(out/'src/framing.rs').write_text(source.replace('//!','//'))
s=(root/'crates/stela-drivers/src/usb/bluetooth/mediatek/media.rs').read_text()
a=s.index('    pub(in crate::usb::bluetooth) fn binding()'); b=s.index('    struct NoDma;',a)
fixture=s[a:b].replace('pub(in crate::usb::bluetooth) fn binding()', 'fn binding()')
main=r'''
extern crate alloc;
use stela_drivers::usb::{bluetooth::{Binding,mediatek::media::{AirMode,Bindings,Voice,Error,Result}},xhci::{self,Device,HIGH_SPEED}};
mod framing;
fn hex(b:&[u8]){ for x in b {print!("{x:02x}");} }
'''+fixture+r'''
fn masked(mask:u32)->Binding{
 let b=binding();let mut d=b.device().clone();let mut c=Vec::new();let mut at=0;let mut keep=true;
 while at<d.configuration.len(){let n=d.configuration[at]as usize;let v=&d.configuration[at..at+n];if v[1]==4{keep=v[2]!=1 || v[3]==0 || mask&(1<<v[3])!=0;}if keep{c.extend_from_slice(v);}at+=n;}
 let n=c.len()as u16;c[2..4].copy_from_slice(&n.to_le_bytes());d.configuration=c;
 Binding::new(&d,&xhci::interfaces(&d.configuration)[0]).unwrap()
}
fn main(){
 for mask in 0..3 {let b=Bindings::new(&masked([127,63,61][mask])).unwrap();for mode in 1..=2 {for bits in 0..2 {for links in 0..=3 {
 let result=b.sco(Voice{connections:links,air_mode:if mode==1{AirMode::Cvsd}else{AirMode::Transparent},voice_setting:if bits==1{32}else{0}});
 let alt=match result{Ok(None)=>0,Ok(Some(p))=>i32::from(p.alternate),Err(_)=>-1};println!("A {mask} {mode} {bits} {links} {alt}");
 }}}}
 for len in 4..=265{let mut packet:Vec<_>=(0..len).map(|i|i as u8).collect();packet[2..4].copy_from_slice(&((len-4)as u16).to_le_bytes());
 match framing::iso_output(&packet){Ok(bytes)=>{print!("P {len} 0 ");hex(&bytes);println!();},Err(_)=>println!("P {len} -22 ")};}
 let raw=[1,0,3,0,9,8,7,2,0,2,0,6,5];
 for split in 0..=raw.len(){let mut f=framing::Framer::new(framing::Kind::Iso);print!("F {split} ");for b in f.feed(&raw[..split],0).unwrap(){hex(&b);print!(";");}for b in f.feed(&raw[split..],1).unwrap(){hex(&b);print!(";");}println!(" 0 0 {}",u8::from(f.partial()));}
}
'''
(out/'src/main.rs').write_text(main)

env=dict(os.environ,CARGO_BUILD_JOBS='1',CARGO_INCREMENTAL='0')
env.setdefault('CARGO_TARGET_DIR',str(out.resolve()/'target'))
with (out_saved/'rust-output.txt').open('wb') as output, (out_saved/'rust-build.txt').open('wb') as diagnostic:
 subprocess.run(['cargo','run','--manifest-path',str(out/'Cargo.toml'),'--quiet'],stdout=output,stderr=diagnostic,check=True,env=env)
shutil.copy2(Path(env['CARGO_TARGET_DIR'])/'debug/mt7925-media-oracle',out_saved/'native-probe')
c=(out_saved/'linux-output.txt').read_bytes(); r=(out_saved/'rust-output.txt').read_bytes()
assert c==r,'native output differs from unchanged pinned helpers'
report={'passed':True,'records':len(c.splitlines()),'alternate_cases':48,'padded_transfers':262,'split_coalesced_cases':14,'linux_output_sha256':hashlib.sha256(c).hexdigest(),'rust_output_sha256':hashlib.sha256(r).hexdigest(),'scope':'unchanged Linux functions; synthetic logical objects/264B skb capacity; no hardware, no allocator prediction/radio/stack qualification','native_framer_sha256':hashlib.sha256(source.encode()).hexdigest(),'native_binding_sha256':hashlib.sha256((root/'crates/stela-drivers/src/usb/bluetooth/mediatek/media/binding.rs').read_bytes()).hexdigest()}
(out_saved/'comparison.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
