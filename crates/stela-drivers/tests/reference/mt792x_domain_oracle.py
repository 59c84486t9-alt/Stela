#!/usr/bin/env python3
"""Execute complete unchanged channel-domain helpers and MCU writers.

Usage: mt792x_domain_oracle.py MT76_DIRECTORY FRESH_OUTPUT_DIRECTORY
Allocation, skb and wiphy channel arrays are bounded host models. Source
requests/completion mode and every actual full writer byte are captured;
this does not qualify native regulatory authority or firmware application.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
out.mkdir(parents=True, exist_ok=False)
hashes = {
    'mt76_connac_mcu.c': '52472fd20bc0a1d744f3eee7a28b7205609e160c479a9da1ec5afa4528e389ec',
    'mt76_connac_mcu.h': '2448b6c145f17397a717965eadf50c591934902f0b09684d37a8b0ae290b31ed',
    'mt7925/mcu.c': 'cca76caa6429584b0b37f2772f5132e754a9e26b71660fb0e362ead4ee01dde6',
    'kernel-cfg80211.h': '972ae23f32259859b54c4b93fa46fb60cba8c879da888b2751014a6cd27bfcf3',
}
texts = {}
for name, digest in hashes.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()

def function(file, name):
    text = texts[file]
    m = re.search(r'\b' + name + r'\([^;{}]*?\)\n\{', text)
    assert m, name
    start = text.rfind('\n\n', 0, m.start()) + 2
    at, depth = m.end(), 1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
    return text[start:at] + '\n'

subprocess.run([sys.executable, str(Path(__file__).with_name('mt792x_mcu_oracle.py')),
                str(source), str(out / 'fill')], stdout=subprocess.PIPE, check=True)
fill = json.loads((out / 'fill/manifest.json').read_text())
hashes.update(fill['sources'])
unit = (out / 'fill/linux-mt792x-mcu.c').read_text().split('int main(', 1)[0]
assert unit.count('struct mt76_dev { struct { int timeout; u8 msg_seq; } mcu; };') == 1
unit = unit.replace('struct mt76_dev { struct { int timeout; u8 msg_seq; } mcu; };',
                    'struct mt76_dev { struct { int timeout; u8 msg_seq; } mcu; u8 alpha2[2]; };')
assert unit.count('struct sk_buff { unsigned char *data; int len; };') == 1
unit = unit.replace('struct sk_buff { unsigned char *data; int len; };',
                    'struct sk_buff { unsigned char *data; int len; u8 *allocation; int capacity; };')
h = texts['mt76_connac_mcu.h']
start = h.rfind('enum {', 0, h.index('MCU_CE_CMD_SET_CHAN_DOMAIN'))
ce = h[start:h.index('};', start) + 2]
cfg = texts['kernel-cfg80211.h']
start = cfg.index('enum ieee80211_channel_flags {')
flags = cfg[start:cfg.index('};', start) + 2]
model = r'''
#include <errno.h>
// Channel flag ABI: GPL-2.0-only; include/net/cfg80211.h
// Copyright 2006-2010 Johannes Berg <johannes@sipsolutions.net>
// Copyright 2013-2014 Intel Mobile Communications GmbH
// Copyright 2015-2017 Intel Deutschland GmbH
// Copyright (C) 2018-2026 Intel Corporation
#define MCU_CE_CMD(x) (__MCU_CMD_FIELD_CE|MCU_CE_CMD_##x)
#define BUILD_BUG_ON(x) _Static_assert(!(x), "source layout")
struct ieee80211_channel {u16 hw_value;u32 flags;};
struct band {int n_channels;struct ieee80211_channel *channels;};
struct mt76_phy {struct mt76_dev *dev;struct {struct band sband;} sband_2g,sband_5g,sband_6g;};
static int chip;
static struct sk_buff *mt76_mcu_msg_alloc(struct mt76_dev *dev,void *data,int length){
 (void)dev;if(data||length<0||length>8192)abort();struct sk_buff *s=calloc(1,sizeof(*s));if(!s)abort();
 s->allocation=calloc(1,length+128);if(!s->allocation)abort();s->capacity=length+128;s->data=s->allocation+128;return s;
}
static void skb_reserve(struct sk_buff *s,int n){if(s->len||n<0||s->data+n>s->allocation+s->capacity)abort();s->data+=n;}
static void skb_put_data(struct sk_buff *s,void *p,int n){if(n<0||s->data+s->len+n>s->allocation+s->capacity)abort();memcpy(s->data+s->len,p,n);s->len+=n;}
static void *__skb_push(struct sk_buff *s,int n){if(n<0||s->data-n<s->allocation)abort();return skb_push(s,n);}
static void output(void *p,size_t n){if(fwrite(p,1,n,stdout)!=n)abort();}
static int mt76_mcu_skb_send_msg(struct mt76_dev *dev,struct sk_buff *s,int cmd,bool wait){
 u32 c=cmd;u8 w=wait;u16 n=s->len;if(n!=s->len)abort();output(&c,4);output(&w,1);output(&n,2);output(s->data,n);
 int seq;int result=chip==7925?mt7925_mcu_fill_message(dev,s,cmd,&seq):mt76_connac2_mcu_fill_message(dev,s,cmd,&seq);if(result)abort();
 n=s->len;if(n!=s->len)abort();output(&n,2);output(s->data,n);free(s->allocation);free(s);return 0;
}
'''
main = r'''
int main(int argc,char **argv){
 if(argc!=2)return 1;chip=atoi(argv[1]);struct mt76_dev dev={0};struct ieee80211_channel channels[3][255];
 for(unsigned i=0;i<192;i++){
  u16 counts[3]={i%17,(i*3)%65,(i*7)%80};if(i==0)memset(counts,0,sizeof(counts));
  if(i>=190){memset(counts,0,sizeof(counts));counts[i-190]=255;}
  dev.alpha2[0]=(i%3)?'U':'0';dev.alpha2[1]=(i%3)?'S':'0';output(counts,6);output(dev.alpha2,2);
  for(int b=0;b<3;b++)for(int j=0;j<counts[b];j++){
   channels[b][j].hw_value=(u16)(i*19+j*3+b*64);
   channels[b][j].flags=(i*0x1020304u+j*0x1041u)^(0xa5000000u+b*0x20000u);
   if(i>=190)channels[b][j].flags&=~IEEE80211_CHAN_DISABLED;
   output(&channels[b][j].hw_value,2);output(&channels[b][j].flags,4);
  }
  struct mt76_phy phy={.dev=&dev,.sband_2g.sband={counts[0],channels[0]},.sband_5g.sband={counts[1],channels[1]},.sband_6g.sband={counts[2],channels[2]}};
  int result=chip==7925?mt7925_mcu_set_channel_domain(&phy):mt76_connac_mcu_set_channel_domain(&phy);if(result)abort();
 }
 return 0;
}
'''
path = out / 'linux-mt792x-domain.c'
path.write_text(unit + ce + '\n' + flags + '\n' + model
                + function('mt76_connac_mcu.c', 'mt76_connac_mcu_set_channel_domain')
                + function('mt7925/mcu.c', 'mt7925_mcu_set_channel_domain') + main)
exe = out / 'linux-mt792x-domain'
subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                '-fno-sanitize-recover=all', str(path), '-o', str(exe)], check=True)
cases = []
for chip in [7921, 7922, 7925]:
    trace = subprocess.run([str(exe.resolve()), str(chip)], stdout=subprocess.PIPE, check=True).stdout
    (out / f'{chip}.trace').write_bytes(trace)
    cases.append({'chip': chip, 'requests': 192, 'bytes': len(trace), 'sha256': hashlib.sha256(trace).hexdigest()})
(out / 'manifest.json').write_text(json.dumps({'linux_commit': fill['linux_commit'], 'sources': hashes,
                                              'cases': cases, 'unchanged_fill_cases': fill['cases']}, indent=2) + '\n')
print(json.dumps(cases, indent=2))
