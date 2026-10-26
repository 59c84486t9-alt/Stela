#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2012-2014, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2015-2017 Intel Deutschland GmbH
"""Unchanged Linux SET_LINK encoder; no firmware or radio execution.

Usage: iwlwifi_transmit_power_oracle.py IWLWIFI_SOURCE OUTPUT_DIRECTORY
Linux's default22dBm maps to its automatic0x7fff sentinel. Stela's explicit
bounded22dBm request intentionally retains176; the Rust comparison records
that semantic difference separately rather than claiming byte equivalence.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

source, out = map(Path, sys.argv[1:])
expected = {
    'mvm/mac80211.c': 'd79214d17083e0757dde6f5e810b6528ae57f345a5a80c2d7eb3391a9544fb8a',
    'fw/api/power.h': '8182c5583306e9c35628991815d63233c70c333a58f14eac42069af75b1fe7f4',
    'iwl-config.h': 'b37b175d2b80eb7a9309792d22f41e8cc94a60246420948e1e7a5b5aff65c4c9',
    'fw/file.h': '148a5f3b2ac6afd9e6b0c2bbc255773482dd7fd6890e70ccd65bca17f3ea9a6c',
    'fw/api/commands.h': '4121211c514ab459439cf97480a3925fe2b8353780cdc2dd852451137f150a45',
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
#include <string.h>
#include <errno.h>
#include <stdlib.h>
typedef uint8_t u8;typedef uint16_t u16;typedef int16_t s16;typedef uint32_t u32;
typedef uint16_t __le16;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define cpu_to_le16(x) ((u16)(x))
#define cpu_to_le32(x) ((u32)(x))
#define WARN_ON(x) (!!(x))
struct caps{bool reduce,ack;};
struct fw{unsigned version;struct caps ucode_capa;};
struct iwl_mvm{struct fw *fw;};
struct iwl_mvm_vif_link_info{u32 fw_link_id;};
struct iwl_mvm_vif{u32 id;struct iwl_mvm_vif_link_info *link[1];};
struct ieee80211_vif{struct iwl_mvm_vif *priv;};
struct ieee80211_bss_conf{struct ieee80211_vif *vif;u8 link_id;};
static struct iwl_mvm_vif *iwl_mvm_vif_from_mac80211(struct ieee80211_vif *v){return v->priv;}
static unsigned iwl_fw_lookup_cmd_ver(struct fw *fw,u32 id,unsigned fallback){(void)id;(void)fallback;return fw->version;}
static bool fw_has_api(struct caps *c,unsigned bit){if(bit!=45)abort();return c->reduce;}
static bool fw_has_capa(struct caps *c,unsigned bit){if(bit!=84)abort();return c->ack;}
static u8 wire[256];static unsigned length;
static int iwl_mvm_send_cmd_pdu(struct iwl_mvm *m,u32 id,u32 flags,unsigned n,const void *p){
 (void)m;(void)flags;if(id!=0x9f||n>sizeof(wire))abort();length=n;memcpy(wire,p,n);return 0;}
'''
for name in ['IWL_NUM_CHAIN_TABLES', 'IWL_NUM_CHAIN_TABLES_V2', 'IWL_NUM_CHAIN_LIMITS',
             'IWL_NUM_SUB_BANDS_V1', 'IWL_NUM_SUB_BANDS_V2', 'IWL_NUM_SUB_BANDS_V3', 'IWL_DEV_MAX_TX_POWER']:
    match = re.search(r'^#define ' + name + r'\s+[^\n]+', texts['fw/api/power.h'], re.M)
    assert match, name
    prelude += match[0] + '\n'
match = re.search(r'^#define IWL_DEFAULT_MAX_TX_POWER\s+22\b[^\n]*', texts['iwl-config.h'], re.M)
assert match
prelude += match[0] + '\n'
for name, value in [('IWL_UCODE_TLV_API_REDUCE_TX_POWER', 45), ('IWL_UCODE_TLV_CAPA_TX_POWER_ACK', 84)]:
    match = re.search(name + r'\s*=\s*\(__force iwl_ucode_tlv_(?:api|capa)_t\)(\d+)', texts['fw/file.h'])
    assert match and int(match[1]) == value, name
    prelude += f'#define {name} {value}\n'
assert re.search(r'REDUCE_TX_POWER_CMD\s*=\s*0x9[fF]', texts['fw/api/commands.h'])
prelude += '#define REDUCE_TX_POWER_CMD 0x9f\n'
prelude += extract('fw/api/power.h', r'^enum iwl_dev_tx_power_cmd_mode\s*\{') + ';\n'
for name in ['iwl_dev_tx_power_common', 'iwl_dev_tx_power_cmd_per_band',
             'iwl_dev_tx_power_cmd_v3', 'iwl_dev_tx_power_cmd_v4', 'iwl_dev_tx_power_cmd_v5',
             'iwl_dev_tx_power_cmd_v8', 'iwl_dev_tx_power_cmd_v3_v8', 'iwl_dev_tx_power_cmd_v9',
             'iwl_dev_tx_power_cmd_v10', 'iwl_dev_tx_power_cmd_v11', 'iwl_dev_tx_power_cmd']:
    prelude += extract('fw/api/power.h', r'^struct ' + name + r'\s*\{')
    # Preserve the declaration's exact packed expression or ordinary semicolon.
    text = texts['fw/api/power.h']
    start = text.index('struct ' + name + ' {')
    body = extract('fw/api/power.h', r'^struct ' + name + r'\s*\{')
    end = start + len(body)
    prelude += text[end:text.index(';', end) + 1] + '\n'
prelude += extract('mvm/mac80211.c', r'^int iwl_mvm_set_tx_power\([^{};]*?\)\n\{') + '\n'
main = r'''
int main(void){
 struct fw fw={0};struct iwl_mvm m={.fw=&fw};struct iwl_mvm_vif_link_info link={0};
 struct iwl_mvm_vif vif={.link={&link}};struct ieee80211_vif v={.priv=&vif};
 struct ieee80211_bss_conf bss={.vif=&v};
 for(unsigned ver=3;ver<=5;ver++)for(unsigned reduce=0;reduce<2;reduce++)
 for(unsigned ack=0;ack<2;ack++)for(unsigned power=0;power<=40;power++){
  fw.version=ver;fw.ucode_capa.reduce=reduce;fw.ucode_capa.ack=ack;
  if(iwl_mvm_set_tx_power(&m,&bss,power))abort();
  printf("%u %u %u %u %u ",ver,reduce,ack,power,length);
  for(unsigned i=0;i<length;i++)printf("%02x",wire[i]);puts("");
 }
 return 0;
}
'''
out.mkdir(parents=True, exist_ok=True)
unit = out / 'linux-iwlwifi-transmit-power.c'
unit.write_text(prelude + main)
exe = out / 'linux-iwlwifi-transmit-power'
subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                str(unit), '-o', str(exe)], check=True, timeout=60)
with (out / 'trace.txt').open('wb') as trace:
    subprocess.run([str(exe.resolve())], stdout=trace, check=True, timeout=60)
data = (out / 'trace.txt').read_bytes()
manifest = {'linux_commit': 'cc9de5d4b5ab6459f5774946aa3195ad51236fa8', 'sources': expected,
            'records': len(data.splitlines()), 'trace_sha256': hashlib.sha256(data).hexdigest(),
            'intentional_native_difference': 'explicit bounded22dBm encodes176; Linux default22 sentinel encodes32767'}
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest, indent=2))
