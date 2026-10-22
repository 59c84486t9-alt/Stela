#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2005-2014, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2016-2017 Intel Deutschland GmbH
"""Unchanged channel table and full source restriction helper.
Usage: iwlwifi_channel_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
Harness NL80211_RRF values are unique semantic witness bits, not the Linux ABI.
No regulatory database, firmware, power programming or authorization executes.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,out=map(Path,sys.argv[1:])
expected={
 'iwl-nvm-parse.c':'74c228762c2e74d85a1731314d5fd867584b9eab0008bede2afc8a1166055d7d',
 'iwl-nvm-parse.h':'f65b8bef3df63ceffd5c6a995c4af3e00d5082d817c73ed89ae2a2eb856fef36',
}
texts={}
for name,digest in expected.items():
 data=(source/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name;texts[name]=data.decode()
def extract(text,pattern):
 match=re.search(pattern,text,re.M);assert match,pattern
 at,depth=match.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[match.start():at]
prelude=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
typedef uint16_t u16;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define NUM_2GHZ_CHANNELS 14
#define NUM_5GHZ_CHANNELS 37
#define LAST_2GHZ_HT_PLUS 9
#define FIRST_2GHZ_HT_MINUS 5
'''
names=['NO_HT40PLUS','NO_HT40MINUS','NO_80MHZ','NO_160MHZ','NO_320MHZ','NO_IR','DFS','NO_OUTDOOR','ALLOW_20MHZ_ACTIVITY','GO_CONCURRENT','DFS_CONCURRENT','ALLOW_6GHZ_VLP_AP','NO_6GHZ_VLP_CLIENT','NO_6GHZ_AFC_CLIENT','NO_HE','NO_EHT','NO_UHR']
for i,name in enumerate(names):prelude+=f'#define NL80211_RRF_{name} BIT({i})\n'
prelude+='#define NL80211_RRF_NO_HT40 (NL80211_RRF_NO_HT40PLUS | NL80211_RRF_NO_HT40MINUS)\n'
prelude+=extract(texts['iwl-nvm-parse.h'],r'^enum iwl_nvm_channel_flags\s*\{')+';\n'
prelude+=extract(texts['iwl-nvm-parse.h'],r'^enum iwl_puncturing_status\s*\{')+';\n'
prelude+=extract(texts['iwl-nvm-parse.h'],r'^struct iwl_reg_capa\s*\{')+';\n'
prelude+=extract(texts['iwl-nvm-parse.c'],r'^static const u16 iwl_unii9_nvm_channels\[\] = \{')+';\n'
prelude+=extract(texts['iwl-nvm-parse.c'],r'^u32 iwl_nvm_get_regdom_bw_flags\([^;{}]*?\)\n\{')+'\n'
main=r'''
static void run(unsigned i,u32 raw,unsigned caps){
 struct iwl_reg_capa c={.allow_40mhz=caps&1,.allow_80mhz=caps&2,.allow_160mhz=caps&4,.allow_320mhz=caps&8,.disable_11ax=caps&16,.disable_11be=caps&32,.disable_11bn=caps&64};
 printf("rule %u %u %u %u\n",i,raw,caps,iwl_nvm_get_regdom_bw_flags(iwl_unii9_nvm_channels,i,(u16)raw,c));
}
int main(void){
 for(unsigned i=0;i<115;i++)printf("channel %u %u\n",i,iwl_unii9_nvm_channels[i]);
 u32 random=0;
 for(unsigned flags=0;flags<65536;flags++){
  random=random*1664525+1013904223;
  run(flags%115,flags|(random&0xffff0000),random>>25);
 }
 for(unsigned i=0;i<115;i++)for(unsigned bit=0;bit<16;bit++){
  run(i,1U<<bit,15);run(i,0xffffU^(1U<<bit),0);
 }
 return 0;
}
'''
out.mkdir(parents=True,exist_ok=True);unit=out/'linux-iwlwifi-channel.c';unit.write_text(prelude+main);exe=out/'linux-iwlwifi-channel'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
