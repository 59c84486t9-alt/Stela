#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2012-2014, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2016-2017 Intel Deutschland GmbH
"""Original cold MLD MAC and inactive link functions, without firmware/DMA/RF.
Usage: SCRIPT IWLWIFI_SOURCE OUTPUT_DIRECTORY
Cold station, original NVM address, no association/HE/EHT/other vif/PHY/peer.
HE ACK capability is bound to the original native NVM table and HE constants.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
source, out = map(Path, sys.argv[1:])
expected = {
    'mvm/mld-mac.c':'a7995e335253ec61d90292a766a3338ca0318d951b5fcf365754c092df2b107c',
    'mvm/link.c':'d1a57405b016a6ec8374397c69df93611b2e9ec90c50cd5015e66b05b63c1686',
    'mvm/mld-mac80211.c':'8deacc0c8985757f549cc11041c03479412e610a9684ba469c34ba0e44e43afc',
    'mvm/mac80211.c':'d79214d17083e0757dde6f5e810b6528ae57f345a5a80c2d7eb3391a9544fb8a',
    'mvm/mac-ctxt.c':'08286167771893332856ff9b30ee7cb840a94db8982c23a67b6b7fdd387d89b7',
    'mvm/sf.c':'3736e9aa37cab6a468557ab5dfe81575c7dd8abc99a72910bf1e9db2042081b1',
    'mvm/mvm.h':'2fdeb7f77b7127a48a27ec864ec5d04e474dc15d8d9d473379f59a0a11bfe8c8',
    'iwl-nvm-parse.c':'da78b5997dfcc34974f382f575331d71a8dd92eb0774b7a012dfc87d5fa6459a',
    'fw/api/mac-cfg.h':'3e4aa8bb08a992255e92b5136409b287cab5bfe0e693d7a2df57c87e68c3b0ae',
    'fw/api/mac.h':'6076083cec1720a0c5d94eebe9e156a8e866c24afad12ca7fd2efc54404f9bc0',
    'fw/api/context.h':'0c9bf2fc06eeed23871269cf06cb05440e06fde1ad0d2f69dfa8391af1b31f6b',
    'fw/api/sf.h':'bc3293c5a69513664e09406d361e6c32343942c1b384cb0bc8d180b093eec06e',
    'fw/api/commands.h':'4121211c514ab459439cf97480a3925fe2b8353780cdc2dd852451137f150a45',
    'fw/file.h':'148a5f3b2ac6afd9e6b0c2bbc255773482dd7fd6890e70ccd65bca17f3ea9a6c',
}
texts={}
for name,digest in expected.items():
    data=(source/name).read_bytes()
    assert hashlib.sha256(data).hexdigest()==digest,name
    texts[name]=data.decode()
he=source.parents[4]/'include/linux/ieee80211-he.h'
data=he.read_bytes()
assert hashlib.sha256(data).hexdigest()=='f8e110ec4c212914f45c36db1599be55da17823a1148d38241e227602390728e'
he=data.decode()
assert 'IEEE80211_HE_MAC_CAP2_ACK_EN' not in texts['iwl-nvm-parse.c']
assert re.search(r'\.mac_cap_info\[2\]\s*=\s*IEEE80211_HE_MAC_CAP2_32BIT_BA_BITMAP,',texts['iwl-nvm-parse.c'])


def extract(file,pattern):
    text=texts[file];match=re.search(pattern,text,re.M);assert match,pattern
    at,depth=match.end(),1
    while depth:
        depth+=(text[at]=='{')-(text[at]=='}');at+=1
    return text[match.start():at]


def function(file,name):
    return extract(file,r'^(?:static )?(?:void|bool|int)\s+'+name+r'\([^{};]*?\)\n\{')+'\n'


prelude=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
typedef uint16_t __le16;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define BIT(n) (1U<<(n))
#define cpu_to_le16(x) ((u16)(x))
#define cpu_to_le32(x) ((u32)(x))
#define le32_to_cpu(x) ((u32)(x))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define WARN_ON(x) (!!(x))
#define WARN_ON_ONCE(x) (!!(x))
#define WARN_ONCE(x,...) (!!(x))
#define IWL_ERR(...)
#define rcu_read_lock()
#define rcu_read_unlock()
#define rcu_dereference(x) (x)
#define ETH_ALEN 6
#define WIDE_ID(g,o) (((g)<<8)|(o))
#define IEEE80211_IFACE_ITER_NORMAL 0
#define IWL_UCODE_TLV_API_SMART_FIFO_OFFLOAD 68
#define CMD_ASYNC 1
#define NL80211_BAND_2GHZ 0
enum{NL80211_IFTYPE_STATION,NL80211_IFTYPE_AP,NL80211_IFTYPE_MONITOR,NL80211_IFTYPE_P2P_DEVICE,NL80211_IFTYPE_ADHOC};
'''
for name in ['IEEE80211_HE_MAC_CAP2_ACK_EN','IEEE80211_HE_MAC_CAP2_32BIT_BA_BITMAP']:
    prelude+=re.search(r'^#define '+name+r'[^\n]+',he,re.M)[0]+'\n'
prelude+=texts['fw/api/context.h']+'\n'+texts['fw/api/sf.h']+'\n'
prelude+=extract('fw/api/commands.h',r'^enum iwl_mvm_command_groups\s*\{')+';\n'
prelude+=extract('mvm/mvm.h',r'^enum iwl_mvm_status\s*\{')+';\n'
match=re.search(r'IWL_UCODE_TLV_CAPA_COEX_HIGH_PRIO\s*=\s*\(__force iwl_ucode_tlv_capa_t\)(\d+)',texts['fw/file.h']);assert match
prelude+=f'#define IWL_UCODE_TLV_CAPA_COEX_HIGH_PRIO {match[1]}\n'
match=re.search(r'COEX_HIGH_PRIORITY_ENABLE\s*=\s*BIT\((\d+)\)',texts['fw/api/mac.h']);assert match
prelude+=f'#define COEX_HIGH_PRIORITY_ENABLE BIT({match[1]})\n'
match=re.search(r'REPLY_SF_CFG_CMD\s*=\s*(0x\w+)',texts['fw/api/commands.h']);assert match
prelude+=f'#define REPLY_SF_CFG_CMD {match[1]}\n'
for name in ['iwl_ac','iwl_mac_types']:
    prelude+=extract('fw/api/mac.h',r'^enum '+name+r'\s*\{')+';\n'
for name in ['iwl_mac_conf_subcmd_ids','iwl_mac_config_filter_flags']:
    prelude+=extract('fw/api/mac-cfg.h',r'^enum '+name+r'\s*\{')+';\n'
for name in ['iwl_ac_qos','iwl_he_backoff_conf']:
    prelude+=extract('fw/api/mac.h',r'^struct '+name+r'\s*\{')+' __packed;\n'
for name in ['iwl_mac_client_data','iwl_mac_p2p_dev_data','iwl_mac_wifi_gen_support_v2',
             'iwl_mac_wifi_gen_support','iwl_mac_config_cmd_v3','iwl_npca_params','iwl_link_config_cmd']:
    prelude+=extract('fw/api/mac-cfg.h',r'^struct '+name+r'\s*\{')+' __packed;\n'
prelude+=re.search(r'^#define IWL_MVM_FW_LINK_ID_INVALID[^\n]+',texts['mvm/mvm.h'],re.M)[0]+'\n'
prelude+=r'''
struct ieee80211_sta;
struct ieee80211_sta_he_cap{struct{u8 mac_cap_info[6];}he_cap_elem;};
struct ieee80211_supported_band{struct ieee80211_sta_he_cap *he;};
struct wiphy{struct ieee80211_supported_band *bands[1];};struct ieee80211_hw{struct wiphy *wiphy;};
struct ieee80211_bss_conf{unsigned link_id;bool he_support,eht_support;u8 addr[6];const u8 *bssid;unsigned dtim_period;};
struct iwl_mvm_vif_link_info{u32 fw_link_id,listen_lmac;void *phy_ctxt;};
struct iwl_mvm_vif{u32 id;bool uploaded,authorized;struct iwl_mvm_vif_link_info *link[1];struct ieee80211_sta *ap_sta;};
struct ieee80211_vif{unsigned type;bool p2p,probe_req_reg;struct{bool assoc;u16 aid;}cfg;
 u8 addr[6];struct ieee80211_bss_conf bss_conf;struct ieee80211_bss_conf *link_conf[1];struct iwl_mvm_vif *priv;};
struct caps{bool offload;};struct fw{struct caps ucode_capa;};
struct iwl_mvm{struct fw *fw;struct ieee80211_hw *hw;unsigned long status;enum iwl_sf_state sf_state;};
static struct{bool disable_11ax;}iwlwifi_mod_params;
static struct iwl_mvm_vif *iwl_mvm_vif_from_mac80211(struct ieee80211_vif *v){return v->priv;}
static const struct ieee80211_sta_he_cap *ieee80211_get_he_iftype_cap_vif(const struct ieee80211_supported_band *s,struct ieee80211_vif *v){(void)v;return s->he;}
static unsigned mac_version,link_version,length,sf_commands;static u8 wire[256];
static unsigned iwl_fw_lookup_cmd_ver(struct fw *f,u32 id,unsigned fallback){(void)f;(void)fallback;if(id==WIDE_ID(MAC_CONF_GROUP,8))return mac_version;if(id==WIDE_ID(MAC_CONF_GROUP,9))return link_version;abort();}
static bool fw_has_api(struct caps *c,unsigned bit){if(bit!=68)abort();return c->offload;}
static bool fw_has_capa(struct caps *c,unsigned bit){(void)c;(void)bit;abort();}
static bool test_bit(unsigned bit,unsigned long *s){return(*s>>bit)&1;}
static int iwl_mvm_send_cmd_pdu(struct iwl_mvm *m,u32 id,u32 flags,unsigned n,const void *p){(void)m;if(id==WIDE_ID(1,0xd1)||id==0xd1){sf_commands++;abort();}if(flags||n>sizeof(wire)||(id!=WIDE_ID(MAC_CONF_GROUP,8)&&id!=WIDE_ID(MAC_CONF_GROUP,9)))abort();length=n;memcpy(wire,p,n);return 0;}
static void ieee80211_iterate_active_interfaces_atomic(void *h,unsigned f,void(*cb)(void*,u8*,struct ieee80211_vif*),void *p){(void)h;(void)f;(void)cb;(void)p;}
static void iwl_mvm_bound_iface_iterator(void *p,u8 *a,struct ieee80211_vif *v){(void)p;(void)a;(void)v;abort();}
static void iwl_mvm_fill_sf_command(struct iwl_mvm *m,struct iwl_sf_cfg_cmd *c,struct ieee80211_sta *s){(void)m;(void)c;(void)s;abort();}
static u32 iwl_mvm_mac_ctxt_cmd_p2p_sta_get_oppps_ctwin(struct iwl_mvm *m,struct ieee80211_vif *v){(void)m;(void)v;abort();}
static u16 iwl_mvm_mac_ctxt_cmd_sta_get_twt_policy(struct iwl_mvm *m,struct ieee80211_vif *v){(void)m;(void)v;abort();}
static void iwl_mvm_set_last_nonqos_seq(struct iwl_mvm *m,struct ieee80211_vif *v){(void)m;(void)v;}
static int iwl_mvm_mld_mac_ctxt_cmd_ap_go(struct iwl_mvm *m,struct ieee80211_vif *v,u32 a){(void)m;(void)v;(void)a;abort();}
static int iwl_mvm_mld_mac_ctxt_cmd_listener(struct iwl_mvm *m,struct ieee80211_vif *v,u32 a){(void)m;(void)v;(void)a;abort();}
static int iwl_mvm_mld_mac_ctxt_cmd_p2p_device(struct iwl_mvm *m,struct ieee80211_vif *v,u32 a){(void)m;(void)v;(void)a;abort();}
static int iwl_mvm_mld_mac_ctxt_cmd_ibss(struct iwl_mvm *m,struct ieee80211_vif *v,u32 a){(void)m;(void)v;(void)a;abort();}
'''
prelude+=extract('mvm/sf.c',r'^struct iwl_mvm_active_iface_iterator_data\s*\{')+';\n'
for file,name in [('mvm/mac-ctxt.c','iwl_mvm_get_mac_type'),('mvm/mac80211.c','iwl_mvm_is_nic_ack_enabled'),
 ('mvm/sf.c','iwl_mvm_sf_config'),('mvm/sf.c','iwl_mvm_sf_update'),
 ('mvm/mld-mac.c','iwl_mvm_mld_set_he_support'),('mvm/mld-mac.c','iwl_mvm_mld_mac_ctxt_cmd_common'),
 ('mvm/mld-mac.c','iwl_mvm_mld_mac_ctxt_send_cmd'),('mvm/mld-mac.c','iwl_mvm_mld_mac_ctxt_cmd_sta'),
 ('mvm/mld-mac.c','iwl_mvm_mld_mac_ctx_send'),('mvm/mld-mac.c','iwl_mvm_mld_mac_ctxt_add'),
 ('mvm/mld-mac.c','iwl_mvm_mld_mac_ctxt_remove'),('mvm/link.c','iwl_mvm_link_cmd_send'),
 ('mvm/link.c','iwl_mvm_set_link_fw_id'),('mvm/link.c','iwl_mvm_add_link'),('mvm/link.c','iwl_mvm_remove_link')]:
    prelude+=function(file,name)
main=r'''
static void record(char kind,unsigned mv,unsigned lv,unsigned own,unsigned serial,unsigned remove){
 printf("%c %u %u %u %u %u %u %u ",kind,mv,lv,own,serial,remove,sf_commands,length);
 for(unsigned i=0;i<length;i++)printf("%02x",wire[i]);puts("");
}
int main(void){struct fw fw={0};struct iwl_mvm_vif_link_info link={0};
 struct iwl_mvm_vif mvif={.link={&link}};struct ieee80211_vif vif={.type=NL80211_IFTYPE_STATION,.priv=&mvif};
 vif.link_conf[0]=&vif.bss_conf;struct ieee80211_sta_he_cap he={.he_cap_elem={.mac_cap_info={[2]=IEEE80211_HE_MAC_CAP2_32BIT_BA_BITMAP}}};
 struct ieee80211_supported_band band={0};struct wiphy wiphy={.bands={&band}};struct ieee80211_hw hw={.wiphy=&wiphy};
 struct iwl_mvm m={.fw=&fw,.hw=&hw,.sf_state=SF_INIT_OFF};
 for(mac_version=1;mac_version<=3;mac_version++)for(link_version=1;link_version<=8;link_version+=7)
 for(unsigned own=0;own<2;own++)for(unsigned serial=0;serial<3;serial++){
  band.he=own?&he:NULL;for(unsigned i=0;i<5;i++)vif.addr[i]=vif.bss_conf.addr[i]=i?i+2:2;vif.addr[5]=vif.bss_conf.addr[5]=serial;
  mvif.uploaded=false;link.fw_link_id=IWL_MVM_FW_LINK_ID_INVALID;sf_commands=0;
  if(iwl_mvm_mld_mac_ctxt_add(&m,&vif))abort();record('M',mac_version,link_version,own,serial,0);
  if(iwl_mvm_add_link(&m,&vif,&vif.bss_conf))abort();record('L',mac_version,link_version,own,serial,0);
  if(iwl_mvm_remove_link(&m,&vif,&vif.bss_conf))abort();record('L',mac_version,link_version,own,serial,1);
  if(iwl_mvm_mld_mac_ctxt_remove(&m,&vif))abort();record('M',mac_version,link_version,own,serial,1);
 }
 return 0;
}
'''
out.mkdir(parents=True,exist_ok=True)
unit=out/'linux-iwlwifi-mld-mac.c';unit.write_text(prelude+main)
exe=out/'linux-iwlwifi-mld-mac'
subprocess.run(['cc','-std=gnu11','-O1','-g','-fsanitize=address,undefined',str(unit),'-o',str(exe)],check=True,timeout=60)
with (out/'trace.txt').open('wb') as trace:subprocess.run([str(exe.resolve())],stdout=trace,check=True,timeout=60)
data=(out/'trace.txt').read_bytes()
manifest={'linux_commit':'cc9de5d4b5ab6459f5774946aa3195ad51236fa8','sources':expected,
 'he_header_sha256':'f8e110ec4c212914f45c36db1599be55da17823a1148d38241e227602390728e',
 'records':len(data.splitlines()),'trace_sha256':hashlib.sha256(data).hexdigest(),'scope':__doc__}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
