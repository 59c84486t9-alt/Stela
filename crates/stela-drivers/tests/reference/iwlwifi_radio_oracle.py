#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2012-2014, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2016-2017 Intel Deutschland GmbH
"""Unchanged source cold radio-prefix helpers, no actual firmware/radio.
Usage: iwlwifi_radio_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
The SF associated-station branch is compiled but not executed or qualified.
"""
import hashlib,json,re,subprocess,sys
from pathlib import Path
source,out=map(Path,sys.argv[1:])
expected={
'mvm/sf.c':'3736e9aa37cab6a468557ab5dfe81575c7dd8abc99a72910bf1e9db2042081b1',
'mvm/fw.c':'b08bbfe33ba78e332c1084917ab320b2a7efb54aa8c491602ff087554b77467c',
'mvm/coex.c':'447f9e0de8fb3f1b62a168ae271866c8eb6762d8681c8d90b702fcab7f038fd0',
'mvm/mvm.h':'613e549d15c1c3d79f661621f058f94efe9312642a6af9605a351152742cf751',
'mvm/constants.h':'a4a1b1d917f3b5655e8057c298abca7cd2682eaaa28b77c23c320e68bbb3185f',
'fw/init.c':'64f980ff5ec120fe9b6ff51e1639e74552fd7890c6d6608eba6d520b144fb2c5',
'fw/api/config.h':'e3b2c4c651e9959ef32d1bf98c88d04591b9895ce2f526344989d6789b5f4a99',
'fw/api/coex.h':'63178c0d776ea57b517f7b13796ebf0775d44e3fae3ecbcf4d20184423ee36a6',
'fw/api/system.h':'22f3fe7a815ca2e694350748390dfd48019a5955b5519ee78fb49bf56e37175e',
'fw/api/sf.h':'bc3293c5a69513664e09406d361e6c32343942c1b384cb0bc8d180b093eec06e',
}
texts={}
for name,digest in expected.items():
 data=(source/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest,name;texts[name]=data.decode()
def extract(text,pattern):
 m=re.search(pattern,text,re.M);assert m,pattern
 at,depth=m.end(),1
 while depth:depth+=(text[at]=='{')-(text[at]=='}');at+=1
 return text[m.start():at]
def function(file,name):return extract(texts[file],r'^(?:static )?(?:inline )?(?:int|void|u8|bool) '+name+r'\([^{};]*?\)\n\{')+'\n'
def struct(file,name):return extract(texts[file],r'^struct '+name+r'\s*\{')+' __packed;\n'
prelude=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef uint8_t u8;typedef uint32_t u32;typedef uint16_t __le16;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define cpu_to_le32(x) (x)
#define le32_encode_bits(value,mask) (((value)<<__builtin_ctz(mask))&(mask))
#define IWL_DEBUG_FW(...)
#define IWL_ERR(...)
#define lockdep_assert_held(...)
#define unlikely(x) (x)
#define WARN_ON(x) oracle_warn_on(x)
static bool oracle_warn_on(bool value){return value;}
#define BUILD_BUG_ON(x) _Static_assert(!(x),"source assertion")
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define max(a,b) ((a)>(b)?(a):(b))
#define rcu_read_lock()
#define rcu_read_unlock()
#define rcu_dereference(x) (x)
#define TX_ANT_CONFIGURATION_CMD 0x98
#define BT_CONFIG 0x9b
#define SYSTEM_GROUP 2
#define SOC_CONFIGURATION_CMD 1
#define WIDE_ID(g,o) (((g)<<8)|(o))
#define IWL_CFG_TRANS_LTR_DELAY_NONE 0
#define IWL_CFG_TRANS_LTR_DELAY_200US 1
#define IWL_CFG_TRANS_LTR_DELAY_2500US 2
#define IWL_CFG_TRANS_LTR_DELAY_1820US 3
#define SCAN_REQ_UMAC 0x10d
#define IWL_FW_CMD_VER_UNKNOWN 255
#define IWL_UCODE_TLV_CAPA_BT_MPLUT_SUPPORT 67
struct fw {unsigned valid_tx_ant;unsigned ucode_capa;};
struct nvm {unsigned valid_tx_ant;};
struct cfg {bool integrated,low_latency_xtal;unsigned ltr_delay,xtal_latency;};
struct trans {struct cfg *mac_cfg;};
struct iwl_mvm {struct fw *fw;struct nvm *nvm_data;struct trans *trans;unsigned set_tx_ant,bt_force_ant_mode;u32 last_bt_notif,last_bt_ci_cmd;};
struct iwl_fw_runtime {struct trans *trans;struct fw *fw;};
struct iwl_host_cmd {u32 id;void *data[1];unsigned len[1];};
struct ieee80211_link_sta {struct {bool ht_supported;} ht_cap;struct {bool vht_supported;} vht_cap;struct {bool has_eht;} eht_cap;struct {bool has_he;} he_cap;unsigned rx_nss;};
struct ieee80211_sta {struct ieee80211_link_sta *link[16];};
static u8 wire[1024];static unsigned length;
static int fw_has_capa(unsigned *c,unsigned bit){return *c && bit==67;}
static unsigned iwl_fw_lookup_cmd_ver(struct fw *fw,unsigned id,unsigned fallback){(void)fw;(void)id;return fallback;}
static int iwl_mvm_send_cmd_pdu(struct iwl_mvm *m,u32 id,u32 flags,unsigned len,void *p){(void)m;(void)id;(void)flags;memcpy(wire,p,len);length=len;return 0;}
static int iwl_trans_send_cmd(struct trans *t,struct iwl_host_cmd *h){(void)t;memcpy(wire,h->data[0],h->len[0]);length=h->len[0];return 0;}
'''
for f,prefix in [('fw/api/sf.h','SF_'),('fw/api/system.h','SOC_'),('mvm/constants.h','IWL_MVM_BT_COEX_')]:
 for line in texts[f].splitlines():
  if re.match(r'^#define '+prefix,line):prelude+=line+'\n'
prelude+=extract(texts['mvm/mvm.h'],r'^enum iwl_bt_force_ant_mode\s*\{')+';\n'
for name in ['iwl_sf_state','iwl_sf_scenario']:
 prelude+=extract(texts['fw/api/sf.h'],r'^enum '+name+r'\s*\{')+';\n'
for name in ['iwl_bt_coex_mode','iwl_bt_coex_enabled_modules']:
 prelude+=extract(texts['fw/api/coex.h'],r'^enum '+name+r'\s*\{')+';\n'
for f,n in [('fw/api/config.h','iwl_tx_ant_cfg_cmd'),('fw/api/coex.h','iwl_bt_coex_cmd'),('fw/api/system.h','iwl_soc_configuration_cmd'),('fw/api/sf.h','iwl_sf_cfg_cmd')]:prelude+=struct(f,n)
for name in ['sf_full_timeout_def','sf_full_timeout']:
 prelude+=extract(texts['mvm/sf.c'],r'^static (?:const\n|const )__le32 '+name+r'\[[^{};]*?= \{')+';\n'
prelude+=function('mvm/mvm.h','iwl_mvm_is_mplut_supported')
prelude+=function('mvm/mvm.h','iwl_mvm_get_valid_tx_ant')
prelude+=function('mvm/fw.c','iwl_send_tx_ant_cfg')
prelude+=function('mvm/coex.c','iwl_mvm_send_bt_init_conf')
prelude+=function('fw/init.c','iwl_set_soc_latency')
prelude+=function('mvm/sf.c','iwl_mvm_fill_sf_command')
main=r'''
static void hex(const void *p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",((const u8*)p)[i]);puts("");}
int main(void){
 struct fw fw={0};struct nvm nvm={0};struct cfg cfg={0};struct trans t={.mac_cfg=&cfg};struct iwl_mvm m={.fw=&fw,.nvm_data=&nvm,.trans=&t};
 for(unsigned f=0;f<16;f++)for(unsigned n=0;n<256;n++){
  fw.valid_tx_ant=f;nvm.valid_tx_ant=n;unsigned ant=iwl_mvm_get_valid_tx_ant(&m);
  iwl_send_tx_ant_cfg(&m,ant);printf("tx %u %u %u ",f,n,ant);hex(wire,length);
 }
 for(unsigned c=0;c<2;c++){fw.ucode_capa=c;iwl_mvm_send_bt_init_conf(&m);printf("bt %u ",c);hex(wire,length);}
 struct iwl_fw_runtime rt={.fw=&fw,.trans=&t};
 for(unsigned f=0;f<2;f++){cfg.xtal_latency=f?500:0;iwl_set_soc_latency(&rt);printf("soc %u ",f);hex(wire,length);}
 struct iwl_sf_cfg_cmd sf={.state=SF_INIT_OFF};iwl_mvm_fill_sf_command(&m,&sf,NULL);printf("sf ");hex(&sf,sizeof(sf));
 return 0;
}
'''
out.mkdir(parents=True,exist_ok=True);unit=out/'linux-iwlwifi-radio.c';unit.write_text(prelude+main);exe=out/'linux-iwlwifi-radio'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True)
manifest={'linux_commit':'a804c5742bff224d4cb4d25dd383554d598be32b','sources':expected,'trace_sha256':hashlib.sha256((out/'trace.txt').read_bytes()).hexdigest()};(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
