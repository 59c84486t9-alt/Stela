#!/usr/bin/env python3
"""Full unchanged pinned Linux station A-MSDU conversion, checked linear skbs.

Usage: wifi_amsdu_oracle.py FRESH_OUTPUT_DIR VERIFIED_LINUX_CACHE
Only source helpers and bounded storage/queue shims execute. No radio, DMA,
key, replay, grouping, mesh or physical platform qualification is inferred.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from wifi_data_oracle import complete_function, SOURCES
from wifi_mac_oracle import PIN

out, cache = map(Path, sys.argv[1:])
out.mkdir(parents=True, exist_ok=False)
path = cache / "net/wireless/util.c"
raw = path.read_bytes()
assert hashlib.sha256(raw).hexdigest() == SOURCES["net/wireless/util.c"]
source = raw.decode()
helpers = [complete_function(source, name) for name in (
    "bool ieee80211_get_8023_tunnel_proto(",
    "static u16\nieee80211_amsdu_subframe_length(",
    "static bool\nis_amsdu_aggregation_attack(",
    "void ieee80211_amsdu_to_8023s(",
)]
scaffold = r'''
// SPDX-License-Identifier: GPL-2.0-only
// Full source notices retained in the source ledger and src/net/wifi/THIRD_PARTY.md.
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint16_t __le16;typedef uint16_t __be16;
#define ETH_ALEN 6
#define ETH_P_AARP 0x80f3
#define ETH_P_IPX 0x8137
#define likely(x) (x)
#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))
#define le16_to_cpu(x) (x)
#define be16_to_cpu(x) ntohs(x)
enum nl80211_iftype {NL80211_IFTYPE_STATION,NL80211_IFTYPE_MESH_POINT};
struct ethhdr {u8 h_dest[6],h_source[6];__be16 h_proto;} __attribute__((packed));
struct sk_buff {u8 *data;int len;u8 storage[2048];bool head_frag;void *dev;unsigned priority;struct sk_buff *next;};
struct sk_buff_head {struct sk_buff *head,**tail;unsigned count;};
static const u8 rfc1042_header[6]={0xaa,0xaa,3,0,0,0},bridge_tunnel_header[6]={0xaa,0xaa,3,0,0,0xf8};
static bool ether_addr_equal(const void *a,const void *b) {return !memcmp(a,b,6);}
static bool is_multicast_ether_addr(const u8 *a) {return a[0]&1;}
static int __ieee80211_get_mesh_hdrlen(u8 f) {(void)f;abort();}
static bool skb_has_frag_list(struct sk_buff *s) {(void)s;return false;}
static bool skb_is_nonlinear(struct sk_buff *s) {(void)s;return false;}
static void skb_copy_bits(struct sk_buff *s,int offset,void *to,int length) {
 if(offset<0||length<0||offset>s->len||length>s->len-offset)abort();memcpy(to,s->data+offset,(size_t)length);
}
static u8 *skb_pull(struct sk_buff *s,int n) {if(n<0||n>s->len)abort();s->data+=n;s->len-=n;return s->data;}
static u8 *skb_push(struct sk_buff *s,int n) {if(n<0||n>s->data-s->storage)abort();s->data-=n;s->len+=n;return s->data;}
static void skb_reset_network_header(struct sk_buff *s) {(void)s;}
static void dev_kfree_skb(struct sk_buff *s) {free(s);}
static struct sk_buff *__ieee80211_amsdu_copy(struct sk_buff *s,unsigned hlen,int offset,int n,bool reuse,int linear) {
 (void)hlen;(void)reuse;(void)linear;if(n<0||n>1900)abort();
 struct sk_buff *t=calloc(1,sizeof(*t));if(!t)abort();t->data=t->storage+64;t->len=n;
 skb_copy_bits(s,offset,t->data,n);return t;
}
static void __skb_queue_tail(struct sk_buff_head *q,struct sk_buff *s) {*q->tail=s;q->tail=&s->next;q->count++;}
static void __skb_queue_purge(struct sk_buff_head *q) {while(q->head){struct sk_buff *s=q->head;q->head=s->next;free(s);}q->tail=&q->head;q->count=0;}
'''
main = r'''
static void emit32(uint32_t n) {if(fwrite(&n,4,1,stdout)!=1)abort();}
int main(void) {
 const u8 local[6]={2,1,2,3,4,5};
 for(unsigned c=0;c<512;c++) {
  struct sk_buff *s=calloc(1,sizeof(*s));if(!s)abort();s->data=s->storage+64;
  unsigned count=1+c%4;
  for(unsigned i=0;i<count;i++) {
   u8 *h=s->data+s->len;memcpy(h,local,6);memcpy(h+6,(u8[]){4,(u8)i,2,3,4,5},6);
   if((c+i)%13==0)h[0]=4; // source skips a foreign unicast DA
   if(i==0&&c%19==0)memcpy(h,rfc1042_header,6);
   unsigned n=8+(c+i)%25;h[12]=0;h[13]=(u8)n;
   const u8 *prefix=c%3==0?rfc1042_header:c%3==1?bridge_tunnel_header:(u8[]){0xab,0xaa,3,0,0,0};
   memcpy(h+14,prefix,6);
   uint16_t proto=c%5==0?0x80f3:c%7==0?0x8137:0x0800;
   h[20]=proto>>8;h[21]=(u8)proto;
   for(unsigned j=8;j<n;j++)h[14+j]=(u8)(c+i+j);
   unsigned size=14+n,padding=(4-size)&3;
   s->len+=size;
   if(i+1<count){memset(s->data+s->len,0x9e,padding);s->len+=padding;}
   else {unsigned trailing=c%(padding+1);memset(s->data+s->len,0x7d,trailing);s->len+=trailing;}
   if(i+1==count&&c%17==0)h[12]=4; // malformed later length purges all
  }
  emit32((uint32_t)s->len);if(fwrite(s->data,1,s->len,stdout)!=(size_t)s->len)abort();
  struct sk_buff_head q={0};q.tail=&q.head;
  ieee80211_amsdu_to_8023s(s,&q,local,NL80211_IFTYPE_STATION,0,local,NULL,0);
  emit32(q.count);
  for(struct sk_buff *f=q.head;f;f=f->next){emit32((uint32_t)f->len);if(fwrite(f->data,1,f->len,stdout)!=(size_t)f->len)abort();}
  __skb_queue_purge(&q);
 }
 return fflush(stdout)!=0;
}
'''
code = scaffold + "\n".join(helpers) + main
cpath, executable = out / "amsdu.c", out / "amsdu"
cpath.write_text(code)
command = ["clang", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined",
           "-fno-omit-frame-pointer", str(cpath), "-o", str(executable)]
subprocess.run(command, check=True)
trace = subprocess.run([str(executable)], check=True, capture_output=True).stdout
(out / "amsdu.bin").write_bytes(trace)
receipt = {"pin": PIN, "source": "net/wireless/util.c", "source_sha256": hashlib.sha256(raw).hexdigest(),
           "source_git_blob_sha1": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
           "helpers_sha256": [hashlib.sha256(h.encode()).hexdigest() for h in helpers],
           "cases": 512, "harness_sha256": hashlib.sha256(code.encode()).hexdigest(),
           "trace_sha256": hashlib.sha256(trace).hexdigest(), "command": command,
           "limits": "checked linear station buffers; no mesh/fragment/DMA/radio/key or replay qualification"}
(out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
print(json.dumps(receipt, indent=2))
