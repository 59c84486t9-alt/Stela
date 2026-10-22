#!/usr/bin/env python3
"""Run unchanged ASIX RX/TX fixups on real SKB-shaped byte buffers.

The harness supplies contiguous uncloned no-offload buffers, actual allocation,
SKB bounds/ownership and returned packet storage. Generated artifacts are ignored.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys
source,out=map(Path,sys.argv[1:])
assert hashlib.sha256(source.read_bytes()).hexdigest()=="fa49b818e1051cf13e765792a8a386aa828e4ac9bd516f16c2b134c6edf6a6c8"
text=source.read_text();out.mkdir(parents=True,exist_ok=True)
def function(name):
 m=re.search(r"^static[^;{}]*?\b"+name+r"\([^;{}]*?\)\n\{",text,re.M);assert m,name
 at,depth=m.end(),1
 while depth:
  depth+=(text[at]=="{")-(text[at]=="}");at+=1
 return text[m.start():at]
names=["ax88179_rx_checksum","ax88179_rx_fixup","ax88179_tx_fixup"]
defines="\n".join(re.findall(r"^#define AX_RXHDR_[^\n]*",text,re.M))
prelude=r'''// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2011-2013 ASIX
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "oracle requires a little-endian host"
#endif
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef int gfp_t;
#define BIT(n) (1U<<(n))
#define ETH_HLEN 14
#define GFP_ATOMIC 0
#define NETIF_F_SG 1
#define CHECKSUM_NONE 0
#define CHECKSUM_UNNECESSARY 1
#define le32_to_cpus(p) ((void)0)
struct info{unsigned gso_size,gso_segs;};
struct sk_buff{u8*head,*data;unsigned len,capacity;int ip_summed;struct info info;};
struct net_device{unsigned features;struct{unsigned rx_errors;}stats;};
struct usbnet{struct net_device*net;unsigned maxpacket;};
static u32 get_unaligned_le32(const void*p){u32 v;memcpy(&v,p,4);return v;}
static void put_unaligned_le32(u32 v,void*p){memcpy(p,&v,4);}
static struct sk_buff*alloc_skb(unsigned n){struct sk_buff*s=calloc(1,sizeof*s);assert(s);s->capacity=n+64;s->head=calloc(1,s->capacity);assert(s->head);s->data=s->head+32;return s;}
static void dev_kfree_skb_any(struct sk_buff*s){free(s->head);free(s);}
static void skb_trim(struct sk_buff*s,unsigned n){assert(n<=s->len);s->len=n;}
static void*skb_tail_pointer(struct sk_buff*s){return s->data+s->len;}
static void*skb_pull(struct sk_buff*s,unsigned n){assert(n<=s->len);s->data+=n;s->len-=n;return s->data;}
static void*skb_put(struct sk_buff*s,unsigned n){assert(s->data-s->head+s->len+n<=s->capacity);void*p=s->data+s->len;s->len+=n;return p;}
static void*skb_push(struct sk_buff*s,unsigned n){assert(s->data-s->head>=n);s->data-=n;s->len+=n;return s->data;}
static unsigned skb_headroom(struct sk_buff*s){return s->data-s->head;}
static unsigned skb_header_cloned(struct sk_buff*s){(void)s;return 0;}
static int skb_linearize(struct sk_buff*s){(void)s;abort();}
static int pskb_expand_head(struct sk_buff*s,unsigned a,unsigned b,int f){(void)s;(void)a;(void)b;(void)f;abort();}
#define skb_shinfo(s) (&(s)->info)
static struct sk_buff*netdev_alloc_skb_ip_align(struct net_device*n,unsigned size){(void)n;return alloc_skb(size);}
static u8 returned[4][2048];static unsigned lengths[4],count;
static void usbnet_skb_return(struct usbnet*d,struct sk_buff*s){(void)d;assert(count<4&&s->len<=2048);lengths[count]=s->len;memcpy(returned[count++],s->data,s->len);dev_kfree_skb_any(s);}
static void usbnet_set_skb_tx_stats(struct sk_buff*s,unsigned a,unsigned b){(void)s;(void)a;(void)b;}
'''
main=r'''
static void hex(const u8*p,unsigned n){for(unsigned i=0;i<n;i++)printf("%02x",p[i]);}
static unsigned aggregate(u8*raw,unsigned a,unsigned b,unsigned dummy,unsigned error){
 unsigned sizes[]={a,b},at=0;u32 metadata[4];unsigned n=0;
 for(unsigned i=0;i<2;i++){
  unsigned size=sizes[i]+2;raw[at]=raw[at+1]=0;memset(raw+at+2,i?0xa6:0x59,sizes[i]);
  at+=(size+7)&~7;metadata[n++]=(size<<16)|(i?0:error);
  if(dummy)metadata[n++]=0x80000000;
 }
 unsigned offset=at;memcpy(raw+at,metadata,n*4);at+=n*4;if(dummy)at+=4;
 u32 trailer=(offset<<16)|n;memcpy(raw+at,&trailer,4);return at+4;
}
static void rx(struct usbnet*d,u8*raw,unsigned n,unsigned bad){
 count=0;struct sk_buff*s=alloc_skb(n);memcpy(skb_put(s,n),raw,n);
 if(ax88179_rx_fixup(d,s))usbnet_skb_return(d,s);else dev_kfree_skb_any(s);
 printf("%c ",bad?'B':'R');if(n)hex(raw,n);else printf("-");printf(" %u ",count);
 if(!count)printf("-");for(unsigned i=0;i<count;i++){if(i)printf(",");hex(returned[i],lengths[i]);}puts("");
}
int main(void){
 struct net_device net={0};struct usbnet d={.net=&net};
 const unsigned tx[]={14,60,61,120,504,1016,1514,1518},packets[]={8,16,32,64,512,1024};
 for(unsigned p=0;p<6;p++)for(unsigned j=0;j<8;j++){
  unsigned original=tx[j],n=original<60?60:original;d.maxpacket=packets[p];struct sk_buff*s=alloc_skb(n);memset(skb_put(s,n),0,n);memset(s->data,0x53,original);
  s=ax88179_tx_fixup(&d,s,0);assert(s);printf("T %u %u ",packets[p],original);hex(s->data,s->len);puts("");dev_kfree_skb_any(s);
 }
 const unsigned a[]={14,60,61,1514,1518},b[]={14,60,1514,1518};const u32 errors[]={0,1U<<29,1U<<31,3};
 for(unsigned i=0;i<5;i++)for(unsigned j=0;j<4;j++)for(unsigned dummy=0;dummy<2;dummy++)for(unsigned e=0;e<4;e++){
  u8 raw[4096]={0};unsigned n=aggregate(raw,a[i],b[j],dummy,errors[e]);rx(&d,raw,n,0);
 }
 u8 raw[4096]={0};rx(&d,raw,0,1);rx(&d,raw,4,1);
 u32 v=0xffffffff;memcpy(raw+4,&v,4);rx(&d,raw,8,1);
 memset(raw,0,sizeof raw);unsigned n=aggregate(raw,60,60,0,0);u32 trailer;memcpy(&trailer,raw+n-4,4);v=0x1fff0000;memcpy(raw+(trailer>>16),&v,4);rx(&d,raw,n,1);
 return 0;
}
'''
unit=out/"linux-asix-framing.c";unit.write_text(prelude+"\n"+defines+"\n"+"\n".join(function(n)for n in names)+main)
exe=out/"linux-asix-framing"
subprocess.run(["cc","-std=gnu11","-O1","-g","-fsanitize=address,undefined",str(unit),"-o",str(exe)],check=True)
with(out/"frames.txt").open("wb")as f:subprocess.run([str(exe.resolve())],stdout=f,check=True)
print(out/"frames.txt")
