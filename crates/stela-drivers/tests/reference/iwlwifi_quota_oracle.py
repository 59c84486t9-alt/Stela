#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2012-2014, 2018, 2021-2022, 2025-2026 Intel Corporation
# Copyright (C) 2013-2014 Intel Mobile Communications GmbH
# Copyright (C) 2016-2017 Intel Deutschland GmbH
"""Original quota update/iterator/helpers for one cold unassociated BSS.

Usage: iwlwifi_quota_oracle.py IWLWIFI_SOURCE OUTPUT_DIRECTORY
No firmware, DMA or RF executes. The actual single-vif iterator is called.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

source, out = map(Path, sys.argv[1:])
expected = {
    'mvm/quota.c': 'b2179cddf72cd7e9aee528adb1a7c04a6bced0bbf2ed3faeb2da80a993e31912',
    'mvm/mvm.h': '2fdeb7f77b7127a48a27ec864ec5d04e474dc15d8d9d473379f59a0a11bfe8c8',
    'mvm/fw.c': '0b81a7a3febe192b14525ada360149cbf1dadc6aeecb5535db2badb7b7e8417f',
    'mvm/constants.h': 'a4a1b1d917f3b5655e8057c298abca7cd2682eaaa28b77c23c320e68bbb3185f',
    'fw/api/binding.h': '210eb352450fac99319cd8504cbc4e1d14dfc26c6da6a04f2d2a1c57b2a1f56e',
    'fw/api/context.h': '0c9bf2fc06eeed23871269cf06cb05440e06fde1ad0d2f69dfa8391af1b31f6b',
    'fw/file.h': '148a5f3b2ac6afd9e6b0c2bbc255773482dd7fd6890e70ccd65bca17f3ea9a6c',
    'fw/api/commands.h': '4121211c514ab459439cf97480a3925fe2b8353780cdc2dd852451137f150a45',
    'fw/api/phy-ctxt.h': '5f40dde9483551f27859e0a9bf8d782220d4d51ec03673b4118a416198e32b92',
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


prelude = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define cpu_to_le32(x) ((u32)(x))
#define le32_to_cpu(x) ((u32)(x))
#define le32_add_cpu(p,x) (*(p)+=(x))
#define WARN_ON_ONCE(x) (!!(x))
#define WARN_ONCE(x,...) (!!(x))
#define BUILD_BUG_ON(x) _Static_assert(!(x),#x)
#define lockdep_assert_held(...)
#define IWL_DEBUG_QUOTA(...)
#define IWL_ERR(...)
#define IEEE80211_IFACE_ITER_NORMAL 0
#define IWL_MVM_STATUS_IN_HW_RESTART 0
enum{NL80211_IFTYPE_STATION,NL80211_IFTYPE_AP,NL80211_IFTYPE_ADHOC,
 NL80211_IFTYPE_MONITOR,NL80211_IFTYPE_P2P_DEVICE};
'''
prelude += texts['fw/api/context.h'] + '\n'
prelude += re.search(r'^#define NUM_PHY_CTX[^\n]+', texts['fw/api/phy-ctxt.h'], re.M)[0] + '\n'
for name in ['MAX_BINDINGS', 'IWL_MVM_MAX_QUOTA']:
    prelude += re.search(r'^#define ' + name + r'[^\n]+', texts['fw/api/binding.h'], re.M)[0] + '\n'
for name in ['IWL_MVM_QUOTA_THRESHOLD', 'IWL_MVM_LOWLAT_QUOTA_MIN_PERCENT']:
    prelude += re.search(r'^#define ' + name + r'[^\n]+', texts['mvm/constants.h'], re.M)[0] + '\n'
for name in ['iwl_time_quota_data_v1', 'iwl_time_quota_cmd_v1', 'iwl_time_quota_data', 'iwl_time_quota_cmd']:
    prelude += extract('fw/api/binding.h', r'^struct ' + name + r'\s*\{') + ' __packed;\n'
for name, value in [('CAPA_DYNAMIC_QUOTA', 44), ('API_QUOTA_LOW_LATENCY', 38)]:
    match = re.search(r'IWL_UCODE_TLV_' + name + r'\s*=\s*\(__force iwl_ucode_tlv_\w+_t\)(\d+)', texts['fw/file.h'])
    assert match and int(match[1]) == value
    prelude += f'#define IWL_UCODE_TLV_{name} {value}\n'
assert re.search(r'TIME_QUOTA_CMD\s*=\s*0x2c', texts['fw/api/commands.h'])
assert 'memset(&mvm->last_quota_cmd, 0xff, sizeof(mvm->last_quota_cmd));' in texts['mvm/fw.c']
prelude += r'''
#define TIME_QUOTA_CMD 0x2c
struct caps{bool dynamic,low;};struct fw{struct caps ucode_capa;};
struct iwl_mvm_phy_ctxt{u16 id,color;};
struct iwl_mvm_vif{struct{struct iwl_mvm_phy_ctxt *phy_ctxt;}deflink;bool ap_ibss_active,monitor_active;};
struct ieee80211_vif{unsigned type;struct{bool assoc;}cfg;struct iwl_mvm_vif *priv;};
struct iwl_mvm{struct fw *fw;unsigned long status;void *hw;struct iwl_time_quota_cmd last_quota_cmd;};
static bool fw_has_capa(struct caps *c,unsigned bit){if(bit!=44)abort();return c->dynamic;}
static bool fw_has_api(struct caps *c,unsigned bit){if(bit!=38)abort();return c->low;}
static bool test_bit(unsigned bit,unsigned long *status){return(*status>>bit)&1;}
static struct iwl_mvm_vif *iwl_mvm_vif_from_mac80211(struct ieee80211_vif *v){return v->priv;}
static bool iwl_mvm_vif_low_latency(struct iwl_mvm_vif *v){(void)v;abort();}
static void ieee80211_iterate_active_interfaces_atomic(void *hw,unsigned flags,
 void(*cb)(void*,u8*,struct ieee80211_vif*),void *data){(void)flags;cb(data,NULL,hw);}
static unsigned sends,length;static int failure;static u8 wire[64];
static int iwl_mvm_send_cmd_pdu(struct iwl_mvm *m,u32 id,u32 flags,unsigned n,void *p){
 (void)m;if(id!=TIME_QUOTA_CMD||flags||n>64)abort();sends++;length=n;memcpy(wire,p,n);return failure;}
'''
prelude += extract('mvm/mvm.h', r'^static inline bool iwl_mvm_has_quota_low_latency\([^{};]*?\)\n\{') + '\n'
prelude += extract('mvm/mvm.h', r'^static inline size_t iwl_mvm_quota_cmd_size\([^{};]*?\)\n\{') + '\n'
prelude += extract('mvm/mvm.h', r'^static inline struct iwl_time_quota_data\n\*iwl_mvm_quota_cmd_get_quota\([^{};]*?\)\n\{') + '\n'
prelude += extract('mvm/quota.c', r'^#define QUOTA_100[^\n]*\n#define QUOTA_LOWLAT_MIN[^\n]*\n\nstruct iwl_mvm_quota_iterator_data\s*\{') + ';\n'
prelude += extract('mvm/quota.c', r'^static void iwl_mvm_quota_iterator\([^{};]*?\)\n\{') + '\n'
prelude += extract('mvm/quota.c', r'^int iwl_mvm_update_quotas\([^{};]*?\)\n\{') + '\n'
main = r'''
static void hex(const void *p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",((const u8*)p)[i]);}
int main(void){
 struct fw fw={0};struct iwl_mvm_phy_ctxt phy={0};struct iwl_mvm_vif mvif={.deflink={.phy_ctxt=&phy}};
 struct ieee80211_vif vif={.type=NL80211_IFTYPE_STATION,.priv=&mvif};
 struct iwl_mvm m={.fw=&fw,.hw=&vif};
 for(unsigned low=0;low<2;low++)for(unsigned offload=0;offload<2;offload++)
 for(unsigned cached=0;cached<2;cached++)for(unsigned failed=0;failed<2;failed++){
  fw.ucode_capa.low=low;fw.ucode_capa.dynamic=offload;
  memset(&m.last_quota_cmd,0xff,sizeof(m.last_quota_cmd));
  if(cached){memset(&m.last_quota_cmd,0,sizeof(m.last_quota_cmd));
   for(unsigned i=0;i<4;i++)iwl_mvm_quota_cmd_get_quota(&m,&m.last_quota_cmd,i)->id_and_color=FW_CTXT_INVALID;}
  struct iwl_time_quota_cmd before=m.last_quota_cmd;sends=length=0;failure=failed?-5:0;
  int result=iwl_mvm_update_quotas(&m,false,NULL);
  printf("%u %u %u %u %d %u %u %u ",low,offload,cached,failed,result,sends,length,
   memcmp(&before,&m.last_quota_cmd,sizeof(before))!=0);
  if(length)hex(wire,length);else printf("-");puts("");
 }
 return 0;
}
'''
out.mkdir(parents=True, exist_ok=True)
unit = out / 'linux-iwlwifi-quota.c'
unit.write_text(prelude + main)
exe = out / 'linux-iwlwifi-quota'
subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                str(unit), '-o', str(exe)], check=True, timeout=60)
with (out / 'trace.txt').open('wb') as trace:
    subprocess.run([str(exe.resolve())], stdout=trace, check=True, timeout=60)
data = (out / 'trace.txt').read_bytes()
manifest = {'linux_commit': 'cc9de5d4b5ab6459f5774946aa3195ad51236fa8', 'sources': expected,
            'records': len(data.splitlines()), 'trace_sha256': hashlib.sha256(data).hexdigest(),
            'scope': 'actual single cold unassociated station iterator; FF or genuinely ACKed empty cache; no RF, DMA or firmware'}
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest, indent=2))
