#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2012-2014, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2015-2017 Intel Deutschland GmbH
"""Run unchanged pinned PHY/RLC encoders for a cold, unbound interface.

Usage: iwlwifi_phy_context_oracle.py IWLWIFI_SOURCE OUTPUT_DIRECTORY
The harness has no active bound interfaces or debug overrides. Its send callback
captures bytes; it does not execute device firmware or provide DMA/RF evidence.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

source, out = map(Path, sys.argv[1:])
expected = {
    'mvm/phy-ctxt.c': '5b5bc999db3b4a6089b6261b5890b45b4d9c8682363f4947f701f4442d91f4ec',
    'mvm/mvm.h': '2fdeb7f77b7127a48a27ec864ec5d04e474dc15d8d9d473379f59a0a11bfe8c8',
    'mvm/utils.c': 'bf94624889244fa7f87a9295ea15b771235efbd7fb66e692305421270c1f57bc',
    'mvm/binding.c': '21de8ea8731113bd433d16c8f9c1ecce673c5e651173d78d2ea082fb2f937fad',
    'fw/api/phy-ctxt.h': '5f40dde9483551f27859e0a9bf8d782220d4d51ec03673b4118a416198e32b92',
    'fw/api/datapath.h': '746573de706f6fbc936183670792d4a50ee72c7ceebd72140d7e91b15bbb1a54',
    'fw/api/commands.h': '4121211c514ab459439cf97480a3925fe2b8353780cdc2dd852451137f150a45',
    'fw/api/context.h': '0c9bf2fc06eeed23871269cf06cb05440e06fde1ad0d2f69dfa8391af1b31f6b',
    'fw/file.h': '148a5f3b2ac6afd9e6b0c2bbc255773482dd7fd6890e70ccd65bca17f3ea9a6c',
}
texts = {}
for name, digest in expected.items():
    data = (source / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest, name
    texts[name] = data.decode()


def extract(file, pattern):
    text = texts[file]
    match = re.search(pattern, text, re.M)
    assert match, pattern
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
    return text[match.start():at]


def function(file, name):
    return extract(file, r'^(?:static )?(?:inline\s+)?(?:int|void|u8|u32|bool)\s+'
                   + name + r'\([^{};]*?\)\n\{') + '\n'


prelude = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
typedef uint16_t __le16; typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define cpu_to_le32(x) ((u32)(x))
#define WARN(x,...) (!!(x))
#define WARN_ON(x) (!!(x))
#define WARN_ONCE(x,...) (!!(x))
#define IWL_ERR(...)
#define IWL_DEBUG_FW(...)
#define lockdep_assert_held(...)
#define BUILD_BUG_ON(x) _Static_assert(!(x),"source assertion")
#define WIDE_ID(g,o) (((g)<<8)|(o))
#define iwl_cmd_id(o,g,v) (((v)<<16)|((g)<<8)|(o))
#define num_of_ant(m) __builtin_popcount(m)
#define IEEE80211_IFACE_ITER_NORMAL 0
enum nl80211_band {NL80211_BAND_2GHZ,NL80211_BAND_5GHZ,NL80211_BAND_6GHZ};
enum {NL80211_CHAN_WIDTH_20_NOHT,NL80211_CHAN_WIDTH_20,NL80211_CHAN_WIDTH_40,
      NL80211_CHAN_WIDTH_80,NL80211_CHAN_WIDTH_160,NL80211_CHAN_WIDTH_320};
struct ieee80211_channel {enum nl80211_band band; int center_freq; unsigned hw_value;};
struct cfg80211_chan_def {struct ieee80211_channel *chan; unsigned width; int center_freq1;};
struct fw {u8 valid_rx_ant,valid_tx_ant; uint64_t ucode_capa; unsigned phy_ver,rlc_ver;};
struct nvm {u8 valid_rx_ant,valid_tx_ant;};
struct cfg {bool rx_with_siso_diversity;};
struct iwl_mvm_phy_ctxt {u32 id,color; bool rlc_disabled;};
struct iwl_mvm {struct fw *fw; struct nvm *nvm_data; struct cfg *cfg; u8 set_rx_ant,set_tx_ant; void *hw;};
struct {unsigned power_scheme;} iwlmvm_mod_params;
struct iwl_mvm_diversity_iter_data {struct iwl_mvm_phy_ctxt *ctxt; bool result;};
struct ieee80211_vif;
static void iwl_mvm_diversity_iter(void *p,u8 *m,struct ieee80211_vif *v){(void)p;(void)m;(void)v;abort();}
static void ieee80211_iterate_active_interfaces_atomic(void *h,unsigned f,
    void (*cb)(void*,u8*,struct ieee80211_vif*),void *d){(void)h;(void)f;(void)cb;(void)d;}
static bool fw_has_capa(uint64_t *c,unsigned b){return (*c>>b)&1;}
static unsigned iwl_fw_lookup_cmd_ver(struct fw *f,unsigned id,unsigned fallback){
    if(id==8)return f->phy_ver;if(id==0x508)return f->rlc_ver;return fallback;}
static u8 wire[2][64]; static unsigned ids[2],lens[2],count;
static int iwl_mvm_send_cmd_pdu(struct iwl_mvm *m,u32 id,u32 flags,unsigned len,const void *p){
    (void)m;(void)flags;if(count==2||len>64)abort();ids[count]=id;lens[count]=len;
    memcpy(wire[count++],p,len);return 0;}
'''
# All numeric protocol selectors below are checked against pinned declarations.
for name, value in [('PHY_CONTEXT_CMD', 8), ('DATA_PATH_GROUP', 5), ('RLC_CONFIG_CMD', 8)]:
    text = texts['fw/api/datapath.h' if name == 'RLC_CONFIG_CMD' else 'fw/api/commands.h']
    match = re.search(r'\b' + name + r'\s*=\s*(0x[0-9a-fA-F]+|\d+)', text)
    assert match and int(match[1], 0) == value, name
    prelude += f'#define {name} {value}\n'
for name, value in [('ULTRA_HB_CHANNELS', 48), ('CDB_SUPPORT', 40)]:
    match = re.search(r'IWL_UCODE_TLV_CAPA_' + name + r'\s*=\s*\(__force iwl_ucode_tlv_capa_t\)(\d+)', texts['fw/file.h'])
    assert match and int(match[1]) == value, name
    prelude += f'#define IWL_UCODE_TLV_CAPA_{name} {value}\n'
prelude += texts['fw/api/context.h'] + '\n'
prelude += extract('mvm/mvm.h', r'^enum iwl_power_scheme\s*\{') + ';\n'
prelude += texts['fw/api/phy-ctxt.h'] + '\n'
prelude += extract('fw/api/datapath.h', r'^enum iwl_rlc_chain_info\s*\{') + ';\n'
for name in ['iwl_rlc_properties', 'iwl_sad_properties', 'iwl_rlc_config_cmd']:
    prelude += extract('fw/api/datapath.h', r'^struct ' + name + r'\s*\{') + ' __packed;\n'
for name in ['iwl_mvm_get_valid_rx_ant', 'iwl_mvm_get_valid_tx_ant', 'iwl_mvm_has_rlc_offload',
             'iwl_mvm_has_ultra_hb_channel', 'iwl_mvm_phy_band_from_nl80211', 'iwl_mvm_set_chan_info']:
    prelude += function('mvm/mvm.h', name)
prelude += extract('mvm/mvm.h', r'^static inline void \*iwl_mvm_chan_info_cmd_tail\([^{};]*?\)\n\{') + '\n'
prelude += extract('mvm/mvm.h', r'^static inline size_t iwl_mvm_chan_info_padding\([^{};]*?\)\n\{') + '\n'
prelude += function('mvm/phy-ctxt.c', 'iwl_mvm_get_channel_width')
prelude += function('mvm/phy-ctxt.c', 'iwl_mvm_get_ctrl_pos')
prelude += function('mvm/mvm.h', 'iwl_mvm_set_chan_info_chandef')
prelude += function('mvm/utils.c', 'iwl_mvm_rx_diversity_allowed')
prelude += function('mvm/binding.c', 'iwl_mvm_get_lmac_id')
for name in ['iwl_mvm_phy_ctxt_cmd_hdr', 'iwl_mvm_phy_ctxt_set_rxchain',
             'iwl_mvm_phy_ctxt_cmd_data_v1', 'iwl_mvm_phy_ctxt_cmd_data',
             'iwl_mvm_phy_send_rlc', 'iwl_mvm_phy_ctxt_apply']:
    prelude += function('mvm/phy-ctxt.c', name)
main = r'''
static void hex(const void *p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",((const u8*)p)[i]);}
int main(void){
 struct fw fw={.valid_tx_ant=3};struct nvm nvm={.valid_tx_ant=3};struct cfg cfg={0};
 struct iwl_mvm m={.fw=&fw,.nvm_data=&nvm,.cfg=&cfg};struct iwl_mvm_phy_ctxt ctxt={0};
 struct ieee80211_channel ch={0};struct cfg80211_chan_def chandef={.chan=&ch,.width=NL80211_CHAN_WIDTH_20_NOHT};
 for(unsigned ver=3;ver<=4;ver++)for(unsigned rlc=0;rlc<=3;rlc++)
 for(unsigned uhb=0;uhb<2;uhb++)for(unsigned cdb=0;cdb<2;cdb++)
 for(unsigned ant=1;ant<=3;ant++)for(unsigned n=0;n<=3;n++)
 for(unsigned cam=0;cam<2;cam++)for(unsigned band=0;band<2;band++){
  fw.phy_ver=ver;fw.rlc_ver=rlc;fw.valid_rx_ant=ant;nvm.valid_rx_ant=n;
  unsigned rx=ant;if(n)rx&=n;if(!rx)continue;
  fw.ucode_capa=((uint64_t)uhb<<48)|((uint64_t)cdb<<40);iwlmvm_mod_params.power_scheme=cam?1:2;
  ch.band=band;ch.hw_value=band?36:1;ch.center_freq=band?5180:2412;chandef.center_freq1=ch.center_freq;
  for(unsigned remove=0;remove<2;remove++){
   count=0;if(iwl_mvm_phy_ctxt_apply(&m,&ctxt,&chandef,1,1,remove?3:1))abort();
   printf("%u %u %u %u %u %u %u %u %u %u",ver,rlc,uhb,cdb,ant,n,cam,band,remove,count);
   for(unsigned i=0;i<count;i++){printf(" %u ",ids[i]);hex(wire[i],lens[i]);}puts("");
  }
 }
 return 0;
}
'''
out.mkdir(parents=True, exist_ok=True)
unit = out / 'linux-iwlwifi-phy-context.c'
unit.write_text(prelude + main)
exe = out / 'linux-iwlwifi-phy-context'
subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                str(unit), '-o', str(exe)], check=True, timeout=60)
with (out / 'trace.txt').open('wb') as trace:
    subprocess.run([str(exe.resolve())], stdout=trace, check=True, timeout=60)
trace = (out / 'trace.txt').read_bytes()
manifest = {'linux_commit': 'cc9de5d4b5ab6459f5774946aa3195ad51236fa8', 'sources': expected,
            'records': len(trace.splitlines()), 'trace_sha256': hashlib.sha256(trace).hexdigest()}
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest, indent=2))
