#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2012-2014, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2015-2017 Intel Deutschland GmbH
"""Unchanged cold binding/SF and MAC-power functions, no firmware/DMA/RF.

Usage: iwlwifi_binding_oracle.py IWLWIFI_SOURCE OUTPUT_DIRECTORY
The original exclusive cold state is SF_INIT_OFF, one unassociated BSS and
no other bound interfaces. Unsupported SF transitions abort in the harness.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

source, out = map(Path, sys.argv[1:])
expected = {
    'mvm/binding.c': '21de8ea8731113bd433d16c8f9c1ecce673c5e651173d78d2ea082fb2f937fad',
    'mvm/sf.c': '3736e9aa37cab6a468557ab5dfe81575c7dd8abc99a72910bf1e9db2042081b1',
    'mvm/power.c': '1897b18f1b2da963504206c3a8c2a021e990a6a918708fa8b25ab4963087ffed',
    'mvm/constants.h': 'a4a1b1d917f3b5655e8057c298abca7cd2682eaaa28b77c23c320e68bbb3185f',
    'fw/api/binding.h': '210eb352450fac99319cd8504cbc4e1d14dfc26c6da6a04f2d2a1c57b2a1f56e',
    'fw/api/sf.h': 'bc3293c5a69513664e09406d361e6c32343942c1b384cb0bc8d180b093eec06e',
    'fw/api/power.h': '8182c5583306e9c35628991815d63233c70c333a58f14eac42069af75b1fe7f4',
    'fw/api/context.h': '0c9bf2fc06eeed23871269cf06cb05440e06fde1ad0d2f69dfa8391af1b31f6b',
    'fw/api/commands.h': '4121211c514ab459439cf97480a3925fe2b8353780cdc2dd852451137f150a45',
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
    return extract(file, r'^(?:static )?(?:inline\s+)?(?:int|void|u32)\s+' + name
                   + r'\([^{};]*?\)\n\{') + '\n'


prelude = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
typedef uint16_t __le16;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define __maybe_unused
#define BIT(n) (1U<<(n))
#define cpu_to_le16(x) ((u16)(x))
#define cpu_to_le32(x) ((u32)(x))
#define WARN_ON(x) (!!(x))
#define WARN_ON_ONCE(x) (!!(x))
#define WARN_ONCE(x,...) (!!(x))
#define IWL_ERR(...)
#define lockdep_assert_held(...)
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define max(a,b) ((a)>(b)?(a):(b))
#define USEC_PER_SEC 1000000
#define USEC_PER_MSEC 1000
#define ieee80211_tu_to_usec(n) ((n)*1024)
#define IEEE80211_IFACE_ITER_NORMAL 0
#define IWL_MVM_STATUS_IN_HW_RESTART 0
#define IWL_MVM_STATUS_IN_D3 1
#define CMD_ASYNC 1
enum nl80211_band{NL80211_BAND_2GHZ,NL80211_BAND_5GHZ,NL80211_BAND_6GHZ};
enum{NL80211_IFTYPE_STATION,NL80211_IFTYPE_P2P_DEVICE};
'''
prelude += texts['fw/api/context.h'] + '\n' + texts['fw/api/sf.h'] + '\n'
prelude += extract('fw/api/power.h', r'^enum iwl_power_flags\s*\{') + ';\n'
prelude += re.search(r'^#define MAX_MACS_IN_BINDING[^\n]+', texts['fw/api/binding.h'], re.M)[0] + '\n'
for name in ['iwl_binding_cmd_v1', 'iwl_binding_cmd']:
    prelude += extract('fw/api/binding.h', r'^struct ' + name + r'\s*\{') + ' __packed;\n'
prelude += extract('fw/api/power.h', r'^struct iwl_mac_power_cmd_v2\s*\{') + ' __packed;\n'
# Protocol selectors are bound to pinned enum/define declarations.
for name, value, file in [('BINDING_CONTEXT_CMD', 0x2b, 'fw/api/commands.h'),
                          ('REPLY_SF_CFG_CMD', 0xd1, 'fw/api/commands.h'),
                          ('MAC_PM_POWER_TABLE', 0xa9, 'fw/api/commands.h')]:
    match = re.search(name + r'\s*=\s*(0x[0-9a-fA-F]+|\d+)', texts[file])
    assert match and int(match[1], 0) == value, name
    prelude += f'#define {name} {value}\n'
prelude += '#define IWL_BINDING_CMD_SIZE_V1 sizeof(struct iwl_binding_cmd_v1)\n'
for name in ['BINDING_CDB_SUPPORT', 'CDB_SUPPORT', 'SHORT_PM_TIMEOUTS']:
    match = re.search(r'IWL_UCODE_TLV_CAPA_' + name + r'\s*=\s*\(__force iwl_ucode_tlv_capa_t\)(\d+)', texts['fw/file.h'])
    assert match, name
    prelude += f'#define IWL_UCODE_TLV_CAPA_{name} {match[1]}\n'
assert re.search(r'IWL_UCODE_TLV_API_SMART_FIFO_OFFLOAD\s*=\s*\(__force iwl_ucode_tlv_api_t\)68', texts['fw/file.h'])
prelude += '#define IWL_UCODE_TLV_API_SMART_FIFO_OFFLOAD 68\n'
for file in ['mvm/constants.h', 'mvm/power.c', 'fw/api/power.h']:
    for line in texts[file].splitlines():
        if re.match(r'^#define (?:IWL_MVM_(?:DEFAULT_PS|SHORT_PS|WOWLAN_PS|P2P_LOWLATENCY)|POWER_KEEP_ALIVE_PERIOD_SEC|POWER_LPRX_RSSI_THRESHOLD\s)', line):
            prelude += line + '\n'
prelude += r'''
struct caps{uint64_t bits;bool offload;};struct fw{struct caps ucode_capa;};
struct ieee80211_channel{enum nl80211_band band;};
struct iwl_mvm_phy_ctxt{u32 id,color;struct ieee80211_channel *channel;};
struct ieee80211_sta;
struct iwl_mvm_vif{u32 id,color;bool pm_enabled,p2p_in_binding;
 struct{struct iwl_mvm_phy_ctxt *phy_ctxt;}deflink;struct ieee80211_sta *ap_sta;};
struct ieee80211_vif{unsigned type;bool p2p;struct{bool assoc,ps;}cfg;
 struct{unsigned dtim_period,beacon_int;struct{unsigned bitrate;}*beacon_rate;}bss_conf;struct iwl_mvm_vif *priv;};
struct iwl_mvm{struct fw *fw;enum iwl_sf_state sf_state;unsigned long status;void *hw;bool ps_disabled;};
static struct iwl_mvm_vif *iwl_mvm_vif_from_mac80211(struct ieee80211_vif *v){return v->priv;}
static bool fw_has_capa(struct caps *c,unsigned bit){if(bit>=64)abort();return(c->bits>>bit)&1;}
static bool fw_has_api(struct caps *c,unsigned bit){if(bit!=68)abort();return c->offload;}
static bool test_bit(unsigned bit,unsigned long *status){return(*status>>bit)&1;}
static void ieee80211_iterate_active_interfaces_atomic(void *h,unsigned f,
 void(*cb)(void*,u8*,struct ieee80211_vif*),void *d){(void)h;(void)f;(void)cb;(void)d;}
static void iwl_mvm_iface_iterator(void *p,u8 *m,struct ieee80211_vif *v){(void)p;(void)m;(void)v;abort();}
static void iwl_mvm_bound_iface_iterator(void *p,u8 *m,struct ieee80211_vif *v){(void)p;(void)m;(void)v;abort();}
static void iwl_mvm_fill_sf_command(struct iwl_mvm *m,struct iwl_sf_cfg_cmd *c,struct ieee80211_sta *s){(void)m;(void)c;(void)s;abort();}
static unsigned sf_commands,next_status,length;static u8 wire[64];
static int iwl_mvm_send_cmd_pdu(struct iwl_mvm *m,u32 id,u32 flags,unsigned n,void *p){
 (void)m;(void)id;(void)flags;(void)n;(void)p;sf_commands++;abort();}
static int iwl_mvm_send_cmd_pdu_status(struct iwl_mvm *m,u32 id,unsigned n,void *p,u32 *status){
 (void)m;if(id!=BINDING_CONTEXT_CMD||n>64)abort();memcpy(wire,p,n);length=n;*status=next_status;return 0;}
static bool iwl_mvm_vif_low_latency(struct iwl_mvm_vif *v){(void)v;abort();}
static unsigned iwl_fw_lookup_cmd_ver(struct fw *f,u32 id,unsigned fallback){(void)f;(void)id;return fallback;}
static void iwl_mvm_power_config_skip_dtim(struct iwl_mvm *m,struct ieee80211_vif *v,struct iwl_mac_power_cmd_v2 *c){(void)m;(void)v;(void)c;abort();}
static bool iwl_mvm_power_allow_uapsd(struct iwl_mvm *m,struct ieee80211_vif *v){(void)m;(void)v;abort();}
static void iwl_mvm_power_configure_uapsd(struct iwl_mvm *m,struct ieee80211_vif *v,struct iwl_mac_power_cmd_v2 *c){(void)m;(void)v;(void)c;abort();}
'''
prelude += extract('mvm/binding.c', r'^struct iwl_mvm_iface_iterator_data\s*\{') + ';\n'
prelude += extract('mvm/sf.c', r'^struct iwl_mvm_active_iface_iterator_data\s*\{') + ';\n'
prelude += function('mvm/binding.c', 'iwl_mvm_get_lmac_id')
prelude += function('mvm/binding.c', 'iwl_mvm_binding_cmd')
prelude += function('mvm/binding.c', 'iwl_mvm_binding_update')
prelude += function('mvm/sf.c', 'iwl_mvm_sf_config')
prelude += function('mvm/sf.c', 'iwl_mvm_sf_update')
prelude += function('mvm/binding.c', 'iwl_mvm_binding_add_vif')
prelude += function('mvm/binding.c', 'iwl_mvm_binding_remove_vif')
prelude += function('mvm/power.c', 'iwl_mvm_power_build_cmd')
main = r'''
static void hex(const void *p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",((const u8*)p)[i]);}
int main(void){
 struct fw fw={0};struct iwl_mvm m={.fw=&fw};struct ieee80211_channel channel={0};
 struct iwl_mvm_phy_ctxt phy={.channel=&channel};struct iwl_mvm_vif mvif={.deflink={.phy_ctxt=&phy}};
 struct ieee80211_vif vif={.type=NL80211_IFTYPE_STATION,.priv=&mvif};
 for(unsigned layout=0;layout<2;layout++)for(unsigned cdb=0;cdb<2;cdb++)for(unsigned band=0;band<2;band++)
 for(unsigned offload=0;offload<2;offload++)for(unsigned cam=0;cam<2;cam++)
 for(unsigned remove=0;remove<2;remove++)for(unsigned status=0;status<2;status++){
  fw.ucode_capa.bits=((uint64_t)layout<<39)|((uint64_t)cdb<<40);fw.ucode_capa.offload=offload;
  m.sf_state=SF_INIT_OFF;m.ps_disabled=cam;channel.band=band;sf_commands=0;next_status=status;
  int result=remove?iwl_mvm_binding_remove_vif(&m,&vif):iwl_mvm_binding_add_vif(&m,&vif);
  if(sf_commands)abort();struct iwl_mac_power_cmd_v2 power={0};iwl_mvm_power_build_cmd(&m,&vif,&power);
  printf("%u %u %u %u %u %u %u %d %u %u ",layout,cdb,band,offload,cam,remove,status,result,sf_commands,length);
  hex(wire,length);printf(" ");hex(&power,sizeof(power));puts("");
 }
 return 0;
}
'''
out.mkdir(parents=True, exist_ok=True)
unit = out / 'linux-iwlwifi-binding.c'
unit.write_text(prelude + main)
exe = out / 'linux-iwlwifi-binding'
subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                str(unit), '-o', str(exe)], check=True, timeout=60)
with (out / 'trace.txt').open('wb') as trace:
    subprocess.run([str(exe.resolve())], stdout=trace, check=True, timeout=60)
data = (out / 'trace.txt').read_bytes()
manifest = {'linux_commit': 'cc9de5d4b5ab6459f5774946aa3195ad51236fa8', 'sources': expected,
            'records': len(data.splitlines()), 'trace_sha256': hashlib.sha256(data).hexdigest(),
            'scope': 'one original cold unassociated BSS; SF_INIT_OFF or offload; no other bound interfaces; no live firmware/DMA/RF'}
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest, indent=2))
