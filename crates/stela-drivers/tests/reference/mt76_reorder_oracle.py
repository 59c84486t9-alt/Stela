#!/usr/bin/env python3
"""Run full unchanged mt76 receive reorder/start/stop/timer code under ASan/UBSan.

Usage: mt76_reorder_oracle.py FRESH_OUTPUT_DIR VERIFIED_LINUX_SOURCE_ROOT
The scaffold provides serialized locks, owned skb queues and an explicit timer;
it does not replace sequence, reorder, BAR, expiry or teardown decisions.
No radio, firmware ACK, security/replay, concurrency or DMA proof is inferred.
"""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from wifi_data_oracle import complete_function
from wifi_mac_oracle import PIN, function

SOURCES = {
    "drivers/net/wireless/mediatek/mt76/agg-rx.c": "8b33411be7ebdcff693358b506c2cc63607722af1e3b373248d48ee4d975ba5d",
    "drivers/net/wireless/mediatek/mt76/mt76.h": "b7e52e9559ff1bd5d256ccdbaa2b4c277d418955acd141708059af3161470bea",
    "include/linux/ieee80211.h": "a65c9f90c87f66509a8fb31c0a77bdbbfae019cd0199edf131cbd798f140bdaa",
    "include/linux/ieee80211-ht.h": "0e25fe12bd20064f3eafc2aaadf9b7df4f0d577bc887762169ac042985b9d09b",
}

PRELUDE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
typedef uint16_t __le16;
#define IEEE80211_SN_MASK 4095
#define IEEE80211_SN_MODULO 4096
#define IEEE80211_SEQ_TO_SN(s) (((s)&0xfff0)>>4)
#define IEEE80211_FCTL_FTYPE 0x000c
#define IEEE80211_FCTL_STYPE 0x00f0
#define IEEE80211_FTYPE_CTL 0x0004
#define IEEE80211_STYPE_BACK_REQ 0x0080
#define IEEE80211_QOS_CTL_TID_MASK 15
#define IEEE80211_QOS_CTL_ACK_POLICY_MASK 0x60
#define IEEE80211_QOS_CTL_ACK_POLICY_NOACK 0x20
#define RX_FLAG_8023 1
#define RX_FLAG_DUP_VALIDATED 2
#define ENOMEM 12
#define cpu_to_le16(x) (x)
#define le16_to_cpu(x) (x)
#define time_after32(a,b) ((int32_t)((u32)(b)-(u32)(a))<0)
static u32 jiffies,HZ;
struct work_struct {unsigned unused;};
struct delayed_work {struct work_struct work;};
struct rcu_head {unsigned unused;};typedef unsigned spinlock_t;
struct ieee80211_sta {unsigned unused;};
struct ieee80211_bar {u16 frame_control,control,start_seq_num;};
struct mt76_wcid {struct mt76_rx_tid *aggr[16];struct mt76_wcid *def_wcid;bool sta;};
struct mt76_rx_status {struct mt76_wcid *wcid;u32 flag,reorder_time;u16 seqno;u8 qos_ctl;bool aggr;};
struct sk_buff {struct sk_buff *next,*prev;u32 id;struct ieee80211_bar bar;
 _Alignas(max_align_t) unsigned char cb[64];};
struct sk_buff_head {struct sk_buff *first,*last;};
struct mt76_dev {void *hw;unsigned mutex;};
#ifndef __counted_by
#define __counted_by(x)
#endif
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define spin_lock(p) ((void)(p))
#define spin_unlock(p) ((void)(p))
#define spin_lock_bh(p) ((void)(p))
#define spin_unlock_bh(p) ((void)(p))
#define spin_lock_init(p) (*(p)=0)
#define local_bh_disable() ((void)0)
#define local_bh_enable() ((void)0)
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define rcu_dereference(p) (p)
#define rcu_assign_pointer(p,v) ((p)=(v))
#define rcu_replace_pointer(p,v,c) ({(void)(c);__typeof__(p) old=(p);(p)=(v);old;})
#define lockdep_is_held(p) ((void)(p),true)
#define INIT_DELAYED_WORK(p,f) ((void)(p))
#define kzalloc_flex(t,m,n) calloc(1,sizeof(t)+sizeof((t).m[0])*(n))
#define kfree_rcu(p,m) free(p)
#define EXPORT_SYMBOL_GPL(x)
static void cancel_delayed_work_sync(void *p) {(void)p;}
static void ieee80211_queue_delayed_work(void *hw,void *work,unsigned long delay) {
 (void)hw;(void)work;assert(delay>0);
}
static void __skb_queue_head_init(struct sk_buff_head *q) {q->first=q->last=NULL;}
static void __skb_queue_tail(struct sk_buff_head *q,struct sk_buff *s) {
 s->next=NULL;s->prev=q->last;
 if(q->last)q->last->next=s;else q->first=s;q->last=s;
}
static void __skb_unlink(struct sk_buff *s,struct sk_buff_head *q) {
 if(s->prev)s->prev->next=s->next;else q->first=s->next;
 if(s->next)s->next->prev=s->prev;else q->last=s->prev;
 s->next=s->prev=NULL;
}
static void dev_kfree_skb(struct sk_buff *s) {free(s);}
static struct ieee80211_sta *wcid_to_sta(struct mt76_wcid *w) {
 static struct ieee80211_sta sta;return w->sta?&sta:NULL;
}
static struct ieee80211_bar *mt76_skb_get_hdr(struct sk_buff *s) {return &s->bar;}
static struct sk_buff_head released;
static void mt76_rx_complete(struct mt76_dev *d,struct sk_buff_head *q,void *arg) {
 (void)d;(void)arg;while(q->first) {struct sk_buff *s=q->first;
 __skb_unlink(s,q);__skb_queue_tail(&released,s);}
}
void mt76_rx_aggr_stop(struct mt76_dev *,struct mt76_wcid *,u8);
'''

MAIN = r'''
static void byte(u8 v) {assert(putchar(v)!=EOF);}
static void word(u16 v) {byte(v);byte(v>>8);}
static void dword(u32 v) {word(v);word(v>>16);}
static u32 random32(u32 *x) {*x^=*x<<13;*x^=*x>>17;*x^=*x<<5;return *x;}
static void snapshot(struct mt76_rx_tid *t) {
 word(t->head);word(t->nframes);byte(t->started);byte(t->stopped);
 u16 n=0;for(struct sk_buff *s=released.first;s;s=s->next)if(s->id)n++;
 word(n);while(released.first) {struct sk_buff *s=released.first;
 __skb_unlink(s,&released);if(s->id)dword(s->id);free(s);}
 for(unsigned i=0;i<t->size;i++)if(t->reorder_buf[i]) {
  struct sk_buff *s=t->reorder_buf[i];struct mt76_rx_status *r=(void *)s->cb;
  word(i);dword(s->id);word(r->seqno);dword(r->reorder_time);
 }
}
int main(void) {
 const u16 sizes[]={1,2,3,7,16,17,64,256,1023,1024};
 const u16 starts[]={0,1,2000,2047,2048,4090,4094,4095};
 const u32 clocks[]={100,250,1000};
 u32 case_id=0;dword(8*10*8*3);
 for(u8 tidno=0;tidno<8;tidno++)for(unsigned sz=0;sz<10;sz++)
 for(unsigned st=0;st<8;st++)for(unsigned hz=0;hz<3;hz++) {
  struct mt76_dev dev={0};struct mt76_wcid wcid={.sta=true};
  u32 rng=++case_id*0x9e3779b9U;HZ=clocks[hz];jiffies=case_id&1?UINT32_MAX-80:0;
  assert(!mt76_rx_aggr_start(&dev,&wcid,tidno,starts[st],sizes[sz]));
  struct mt76_rx_tid *t=wcid.aggr[tidno];
  byte(tidno);word(starts[st]);word(sizes[sz]);dword(HZ);word(65);
  for(unsigned op=0;op<65;op++) {
   u32 r=random32(&rng);jiffies+=(r>>16)%25;
   u8 kind=op==64?3:op%11==9?2:op%4==3?1:0;
   u16 offsets[]={4095,0,1,2,(u16)(t->size-1),t->size,(u16)(t->size*2),2048};
   u16 seq=(t->head+offsets[(r>>8)%8])&4095;
   byte(kind);word(seq);dword(jiffies);dword(op+1);
   if(kind==0) {
    struct sk_buff *s=calloc(1,sizeof(*s));assert(s);s->id=op+1;
    struct mt76_rx_status *status=(void *)s->cb;
    status->wcid=&wcid;status->aggr=true;status->qos_ctl=tidno;status->seqno=seq;
    mt76_rx_aggr_reorder(s,&released);
   } else if(kind==1) {
    mt76_rx_aggr_reorder_work(&t->reorder_work.work);
   } else if(kind==2) {
    struct sk_buff *s=calloc(1,sizeof(*s));assert(s);
    s->bar=(struct ieee80211_bar){.frame_control=0x0084,.control=tidno<<12,.start_seq_num=seq<<4};
    struct mt76_rx_status *status=(void *)s->cb;status->wcid=&wcid;
    mt76_rx_aggr_reorder(s,&released);
   } else {
    mt76_rx_aggr_shutdown(&dev,t);
   }
   snapshot(t);
  }
  mt76_rx_aggr_stop(&dev,&wcid,tidno);assert(!wcid.aggr[tidno]);
 }
 return fflush(stdout)!=0;
}
'''


def main():
    out, cache = (Path(x).resolve() for x in sys.argv[1:])
    out.mkdir(parents=True, exist_ok=False)
    source, receipt = {}, {"pin": PIN, "sources": []}
    for name, expected in SOURCES.items():
        data = (cache / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError(f"donor mismatch: {name}")
        source[name] = data.decode()
        receipt["sources"].append({"path": name, "sha256": expected,
            "git_blob_sha1": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()})
    header = source["include/linux/ieee80211.h"]
    helpers = [function(header, name) for name in (
        "ieee80211_sn_less", "ieee80211_sn_add", "ieee80211_sn_inc", "ieee80211_sn_sub",
        "ieee80211_is_ctl", "ieee80211_is_back_req")]
    layout = complete_function(source["drivers/net/wireless/mediatek/mt76/mt76.h"],
        "struct mt76_rx_tid {") + ";"
    # Preserve every complete implementation function, including timer/RCU wrappers.
    donor = source["drivers/net/wireless/mediatek/mt76/agg-rx.c"].replace('#include "mt76.h"', '')
    harness = PRELUDE + layout + "\n" + "\n".join(helpers) + "\n" + donor + MAIN
    c, exe = out / "reorder.c", out / "reorder"
    c.write_text(harness)
    command = ["clang", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", "-O1", "-g",
        "-fsanitize=address,undefined", str(c), "-o", str(exe)]
    subprocess.run(command, check=True)
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
    result = subprocess.run([str(exe)], check=True, capture_output=True, env=env)
    (out / "reorder.bin").write_bytes(result.stdout)
    receipt.update({"cases": 1920, "operations": 124800, "command": command,
        "harness_sha256": hashlib.sha256(harness.encode()).hexdigest(),
        "unchanged_translation_unit_sha256": hashlib.sha256(donor.encode()).hexdigest(),
        "helper_sha256": [hashlib.sha256(x.encode()).hexdigest() for x in helpers],
        "layout_sha256": hashlib.sha256(layout.encode()).hexdigest(),
        "output_bytes": len(result.stdout), "output_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "scope": "Complete unchanged mt76 eligible RX reorder plus start, BAR, timer work, shutdown and stop; exact full queue snapshots.8TIDs,10windows including nonpowers and1024,8SSNs crossing wrap/halfspace,3HZ,tickrollover. Locks/RCU serialized; scheduler callbacks manually driven. No hardware, firmware, replay or concurrency qualification."})
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({key: receipt[key] for key in ("cases", "operations", "output_bytes", "output_sha256")}))


if __name__ == "__main__":
    main()
