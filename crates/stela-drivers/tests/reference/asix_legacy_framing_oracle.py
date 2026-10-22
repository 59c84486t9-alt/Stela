#!/usr/bin/env python3
"""Execute unchanged AX88772 RX state machine and TX fixup on real byte buffers.

The pinned kernel Makefile supplies -fno-strict-overflow, required for the
original split-header integer promotion/shift. Function bodies remain unchanged.
Contiguous uncloned SKBs and successful allocations are modeled. Split headers,
continuations, lost-buffer resynchronization and invalid framing are exercised;
no hardware timing, allocation-failure or Linux OS qualification is implied.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys
source,header,kbuild,out=map(Path,sys.argv[1:])
assert hashlib.sha256(kbuild.read_bytes()).hexdigest()=="d9cd934cdb950f6248123045263a0f9e6be271c84bb1f185aab2319796533bd1"
assert "KBUILD_CFLAGS\t+= -fno-strict-overflow" in kbuild.read_text()
assert hashlib.sha256(source.read_bytes()).hexdigest()=="2174300347b7ee862d3ed24fe5ba7423a45111377d6232acbc812ea1cc3706f8"
assert hashlib.sha256(header.read_bytes()).hexdigest()=="4d04e4b63d0884bce00d5d8a8bf01504e4114b844d875d2bc79dc24f6d29b278"
text=source.read_text();out.mkdir(parents=True,exist_ok=True)
def function(name):
 m=re.search(r"^[a-zA-Z_][^;{}]*?\b"+name+r"\([^;{}]*?\)\n\{",text,re.M);assert m,name
 at,depth=m.end(),1
 while depth:
  depth+=(text[at]=="{")-(text[at]=="}");at+=1
 return text[m.start():at]
prelude=r'''// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2003-2006 David Hollis; 2005 Phil Chang;
// 2006 James Painter; 2002-2003 TiVo Inc.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef int gfp_t;
#define ETH_HLEN 14
#define VLAN_HLEN 4
#define netdev_err(...) ((void)0)
#define netdev_dbg(...) ((void)0)
struct sk_buff{u8*head,*data;unsigned len,capacity;};
struct net_device{unsigned mtu;};
struct usbnet{struct net_device*net;unsigned maxpacket;};
static u16 get_unaligned_le16(const void*p){u16 v;memcpy(&v,p,2);return v;}
static u32 get_unaligned_le32(const void*p){u32 v;memcpy(&v,p,4);return v;}
static void put_unaligned_le32(u32 v,void*p){memcpy(p,&v,4);}
static struct sk_buff*alloc_skb(unsigned n){struct sk_buff*s=calloc(1,sizeof*s);assert(s);s->capacity=n+64;s->head=calloc(1,s->capacity);assert(s->head);s->data=s->head+32;return s;}
static void dev_kfree_skb_any(struct sk_buff*s){if(s){free(s->head);free(s);}}
#define kfree_skb dev_kfree_skb_any
static void*skb_tail_pointer(struct sk_buff*s){return s->data+s->len;}
static void*skb_put(struct sk_buff*s,unsigned n){assert(s->data-s->head+s->len+n<=s->capacity);void*p=s->data+s->len;s->len+=n;return p;}
static void skb_put_data(struct sk_buff*s,const void*p,unsigned n){memcpy(skb_put(s,n),p,n);}
static void*skb_push(struct sk_buff*s,unsigned n){assert(s->data-s->head>=n);s->data-=n;s->len+=n;return s->data;}
static unsigned skb_headroom(struct sk_buff*s){return s->data-s->head;}
static unsigned skb_tailroom(struct sk_buff*s){return s->capacity-(s->data-s->head)-s->len;}
static unsigned skb_header_cloned(struct sk_buff*s){(void)s;return 0;}
static unsigned skb_cloned(struct sk_buff*s){(void)s;return 0;}
static void skb_set_tail_pointer(struct sk_buff*s,unsigned n){assert(n==s->len);}
static struct sk_buff*skb_copy_expand(struct sk_buff*s,unsigned a,unsigned b,gfp_t f){(void)s;(void)a;(void)b;(void)f;abort();}
static struct sk_buff*netdev_alloc_skb_ip_align(struct net_device*n,unsigned size){(void)n;return alloc_skb(size);}
static u8 returned[8][2048];static unsigned lengths[8],count;
static void usbnet_skb_return(struct usbnet*d,struct sk_buff*s){(void)d;assert(count<8&&s->len<=2048);lengths[count]=s->len;memcpy(returned[count++],s->data,s->len);dev_kfree_skb_any(s);}
static void usbnet_set_skb_tx_stats(struct sk_buff*s,unsigned a,unsigned b){(void)s;(void)a;(void)b;}
'''
structure=re.search(r"struct asix_rx_fixup_info \{.*?\n\};",header.read_text(),re.S).group()
main=r'''
static void hex(const u8*p,unsigned n){if(!n){printf("-");return;}for(unsigned i=0;i<n;i++)printf("%02x",p[i]);}
static unsigned frame(u8*raw,unsigned n,u8 fill){put_unaligned_le32(n|((~n&0xffff)<<16),raw);memset(raw+4,fill,n);if(n&1)raw[n+4]=0;return 4+((n+1)&~1);}
static int rx(struct usbnet*d,struct asix_rx_fixup_info*r,const u8*raw,unsigned n){struct sk_buff*s=alloc_skb(n);skb_put_data(s,raw,n);int ret=asix_rx_fixup_internal(d,s,r);dev_kfree_skb_any(s);return ret;}
static void result(void){printf(" %u ",count);if(!count)printf("-");for(unsigned j=0;j<count;j++){if(j)printf(",");hex(returned[j],lengths[j]);}puts("");}
int main(void){
 struct net_device net={.mtu=1500};struct usbnet d={.net=&net};
 const unsigned packets[]={8,16,32,64,512},sizes[]={14,60,61,508,509,1514,1518};
 for(unsigned p=0;p<5;p++)for(unsigned j=0;j<7;j++){
  unsigned original=sizes[j],n=original<60?60:original;d.maxpacket=packets[p];struct sk_buff*s=alloc_skb(n);memset(skb_put(s,n),0,n);memset(s->data,0x53,original);
  s=asix_tx_fixup(&d,s,0);assert(s);printf("T %u %u ",packets[p],original);hex(s->data,s->len);puts("");dev_kfree_skb_any(s);
 }
 const unsigned lengths[]={14,60,61,1514,1518};
 for(unsigned j=0;j<5;j++){
  u8 raw[2048]={0};unsigned n=frame(raw,lengths[j],0x93);n+=frame(raw+n,60,0x4d);
  for(unsigned split=0;split<=n;split+=2){
   struct asix_rx_fixup_info r={0};count=0;assert(rx(&d,&r,raw,split));assert(rx(&d,&r,raw+split,n-split));
   printf("S %u ",split);hex(raw,n);result();reset_asix_rx_fixup_info(&r);
  }
 }
 // First URB is truncated, then a complete new frame must resynchronize.
 struct asix_rx_fixup_info r={0};u8 first[128]={0},second[128]={0};unsigned n=frame(first,60,0x72);unsigned m=frame(second,61,0x37);
 count=0;assert(rx(&d,&r,first,24));assert(rx(&d,&r,second,m));printf("L ");hex(first,24);printf(" ");hex(second,m);result();reset_asix_rx_fixup_info(&r);
 // Bad complement and odd tail are source-defined rejected inputs.
 const unsigned invalid[]={1,4,5,9};
 for(unsigned j=0;j<4;j++){u8 raw[16]={0};count=0;assert(!rx(&d,&r,raw,invalid[j]));printf("B ");hex(raw,invalid[j]);puts("");reset_asix_rx_fixup_info(&r);}
 (void)n;
}
'''
unit=out/"linux-asix-legacy-framing.c"
unit.write_text(prelude+structure+"\n"+"\n".join(function(n)for n in ["reset_asix_rx_fixup_info","asix_rx_fixup_internal","asix_tx_fixup"])+main)
exe=out/"linux-asix-legacy-framing"
subprocess.run(["cc","-std=gnu11","-O1","-g","-fno-strict-overflow","-fsanitize=address,undefined",str(unit),"-o",str(exe)],check=True)
with(out/"frames.txt").open("wb")as f:subprocess.run([str(exe.resolve())],stdout=f,check=True)
print(out/"frames.txt")
