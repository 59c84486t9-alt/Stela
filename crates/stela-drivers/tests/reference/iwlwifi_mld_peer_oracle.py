#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Copyright (C) 2012-2015, 2018-2026 Intel Corporation
# Copyright (C) 2013-2015 Intel Mobile Communications GmbH
# Copyright (C) 2016-2017 Intel Deutschland GmbH
"""Original MLD station config/size/remove and legacy TLC/flush wire seam.

Usage: SCRIPT IWLWIFI_SOURCE QUALIFIED_LEGACY_PEER_ORACLE OUTPUT_DIRECTORY
The original full MLD add callback calls cfg twice (update then active links);
common NOTEXIST->NONE then initializes TLC. Callback ordering is separately
source reviewed: this oracle compares the actual original command operations.
No station queue, key, normalized RX, association, frame or RF is executed.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

source, legacy, out = map(Path, sys.argv[1:])
base = (legacy / 'linux-iwlwifi-peer.c').read_bytes()
assert hashlib.sha256(base).hexdigest() == '692264e3b7a02f6a19ce7d2b0d9125ff6063bf1c2144d1a9a9851c19b84a89b9'
expected = json.loads((legacy / 'manifest.json').read_text())['sources']
expected.update({
    'mvm/mld-sta.c': 'f73b9d22de00ca5a16717628af967fd7f7b710f9b3336cd96d73ba8cdcb60e7e',
    'fw/api/mac-cfg.h': '3e4aa8bb08a992255e92b5136409b287cab5bfe0e693d7a2df57c87e68c3b0ae',
    'fw/api/mac.h': '6076083cec1720a0c5d94eebe9e156a8e866c24afad12ca7fd2efc54404f9bc0',
    'mvm/mac80211.c': 'd79214d17083e0757dde6f5e810b6528ae57f345a5a80c2d7eb3391a9544fb8a',
    'mvm/mld-mac80211.c': '8deacc0c8985757f549cc11041c03479412e610a9684ba469c34ba0e44e43afc',
    'mvm/mvm.h': '2fdeb7f77b7127a48a27ec864ec5d04e474dc15d8d9d473379f59a0a11bfe8c8',
    'mvm/mld-key.c': 'b5edda87a55d377e4164182b9fed663f0623b7eddd966a59400f92d6ae2b3c6d',
    'mvm/rs.c': '9ce334a3602c416906b2e52c2cc95b1e771c290d1a1e96dd4dd3bfa87131d295',
})
texts = {}
for name, digest in expected.items():
    data = (source / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest, name
    texts[name] = data.decode()
root = source.parents[4]
headers = {
    'include/net/mac80211.h': 'aa6fab3b830cb56fcfa20b1090a6f947aeef19ad0f81ed9153b517944bd4a740',
    'include/linux/ieee80211-he.h': 'f8e110ec4c212914f45c36db1599be55da17823a1148d38241e227602390728e',
    'include/linux/ieee80211-vht.h': 'eaae1e52bcaed0ecb9bbcf1c87a65e03a7ac5ea29733111a90e92bb993741775',
    'include/linux/ieee80211-eht.h': '1d947e2d744d9296a45d2481ecaca957d47aca4980ace0230c9b45f056e9526a',
}
for name, digest in headers.items():
    data = (root / name).read_bytes()
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
    return extract(file, r'^(?:static )?(?:inline )?(?:void|bool|int|u8|u32)\s+' + name + r'\([^{};]*?\)\s*\n\{') + '\n'


prefix = base.decode().split('static inline int iwl_mvm_add_sta_cmd_size')[0]


def replace(old, new):
    global prefix
    assert prefix.count(old) == 1, old
    prefix = prefix.replace(old, new)


# Only authored fixture declarations change. Every appended command function
# is copied byte-exact from its verified original source.
decl = ''
for name in ['MAX_HE_SUPP_NSS', 'MAX_CHANNEL_BW_INDX_API_D_VER_2']:
    decl += re.search(r'^#define ' + name + r'[^\n]+', texts['fw/api/mac.h'], re.M)[0] + '\n'
decl += extract('fw/api/mac.h', r'^struct iwl_he_pkt_ext_v2\s*\{') + ' __packed;\n'
for name in ['iwl_sta_cfg_cmd_v1', 'iwl_sta_cfg_cmd_v2', 'iwl_remove_sta_cmd']:
    decl += extract('fw/api/mac-cfg.h', r'^struct ' + name + r'\s*\{') + ' __packed;\n'
decl += extract('fw/api/mac-cfg.h', r'^enum iwl_fw_sta_type\s*\{') + ';\n'
decl += extract('include/net/mac80211.h', r'^enum ieee80211_sta_state\s*\{') + ';\n'
for file, name in [('include/linux/ieee80211-he.h', 'IEEE80211_HE_6GHZ_CAP_MIN_MPDU_START'),
                   ('include/linux/ieee80211-he.h', 'IEEE80211_HE_6GHZ_CAP_MAX_AMPDU_LEN_EXP'),
                   ('include/linux/ieee80211-he.h', 'IEEE80211_HE_MAC_CAP3_MAX_AMPDU_LEN_EXP_MASK'),
                   ('include/linux/ieee80211-he.h', 'IEEE80211_HE_MAC_CAP2_ACK_EN'),
                   ('include/linux/ieee80211-vht.h', 'IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT'),
                   ('include/linux/ieee80211-vht.h', 'IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK'),
                   ('include/linux/ieee80211-eht.h', 'IEEE80211_EHT_MAC_CAP1_MAX_AMPDU_LEN_MASK')]:
    lines = texts[file].splitlines()
    at = next(i for i, line in enumerate(lines) if re.match(r'^#define ' + name + r'\s', line))
    while True:
        decl += lines[at] + '\n'
        if not lines[at].endswith('\\'):
            break
        at += 1
match = re.search(r'IWL_UCODE_TLV_CAPA_STA_EXP_MFP_SUPPORT\s*=\s*\(__force iwl_ucode_tlv_capa_t\)(\d+)', texts['fw/file.h'])
assert match
decl += '#define IWL_UCODE_TLV_CAPA_STA_EXP_MFP_SUPPORT ' + match[1] + '\n'
for name in ['STA_CONFIG_CMD', 'STA_REMOVE_CMD']:
    value = re.search(name + r'\s*=\s*(0x[0-9a-fA-F]+)', texts['fw/api/mac-cfg.h'])
    assert value
    decl += '#define ' + name + ' ' + value[1] + '\n'
assert re.search(r'MAC_CONF_GROUP\s*=\s*0x3', texts['fw/api/commands.h'])
decl += '#define MAC_CONF_GROUP 3\n#define IWL_MVM_FW_LINK_ID_INVALID 255\n'
decl += '#define rcu_access_pointer(x) (x)\n'
decl += '#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))\n'
decl += '#define u32_get_bits(x,m) (((x)&(m))/((m)&-(m)))\n#define u8_get_bits u32_get_bits\n#define le16_get_bits u32_get_bits\n'
replace('#define IEEE80211_STA_ASSOC 2\n', decl)
replace('struct ieee80211_sta_ht_cap{bool ht_supported;struct{u8 rx_mask[2];}mcs;};',
        'struct ieee80211_sta_ht_cap{bool ht_supported;u8 ampdu_factor,ampdu_density;struct{u8 rx_mask[2];}mcs;};')
replace('struct ieee80211_sta_vht_cap{bool vht_supported;};', 'struct ieee80211_sta_vht_cap{bool vht_supported;u32 cap;};')
replace('struct ieee80211_sta_he_cap{bool has_he;};', 'struct ieee80211_sta_he_cap{bool has_he;struct{u8 mac_cap_info[6];}he_cap_elem;};')
replace('struct ieee80211_sta_eht_cap{bool has_eht;struct{u8 phy_cap_info[6];}eht_cap_elem;};',
        'struct ieee80211_sta_eht_cap{bool has_eht;struct{u8 phy_cap_info[6],mac_cap_info[2];}eht_cap_elem;};')
replace('struct ieee80211_link_sta{unsigned bandwidth,rx_nss,smps_mode,link_id;unsigned long supp_rates[3];',
        'struct ieee80211_link_sta{u8 addr[6];struct{u16 capa;}he_6ghz_capa;unsigned bandwidth,rx_nss,smps_mode,link_id;unsigned long supp_rates[3];')
replace('struct ieee80211_bss_conf{struct{struct{struct ieee80211_channel *chan;}oper;}chanreq;unsigned link_id;};',
        'struct ieee80211_bss_conf{struct{struct{struct ieee80211_channel *chan;}oper;}chanreq;unsigned link_id;bool uora_exists;};')
replace('struct ieee80211_sta{u8 addr[6];u16 aid;bool wme;', 'struct ieee80211_sta{u8 addr[6];u16 aid;bool mfp,wme;')
replace('struct iwl_mvm_vif{u16 max_tx_op;};', 'struct iwl_mvm_vif_link_info{u8 fw_link_id;};struct iwl_mvm_vif{u16 max_tx_op;struct iwl_mvm_vif_link_info *link[1];};')
replace('struct caps{bool sta_type;};', 'struct caps{bool sta_type,mfp;};')
old = re.search(r'static u32 iwl_mvm_get_sta_ampdu_dens[^}]+\}', prefix)[0]
replace(old, '')
replace('static bool fw_has_api', 'static bool fw_has_capa(struct caps *c,unsigned bit){if(bit!=IWL_UCODE_TLV_CAPA_STA_EXP_MFP_SUPPORT)abort();return c->mfp;}\nstatic bool fw_has_api')
replace('id!=WIDE_ID(5,15))', 'id!=WIDE_ID(5,15)&&id!=WIDE_ID(3,STA_CONFIG_CMD)&&id!=WIDE_ID(3,STA_REMOVE_CMD))')
prefix += r'''
static void iwl_mvm_set_sta_pkt_ext(struct iwl_mvm *m,struct ieee80211_link_sta *l,struct iwl_he_pkt_ext_v2 *p){(void)m;(void)l;(void)p;abort();}
static u32 iwl_mvm_get_sta_htc_flags(struct ieee80211_sta *s,struct ieee80211_link_sta *l){(void)s;(void)l;abort();}
'''
functions = [('mvm/sta.c', 'iwl_mvm_get_sta_ampdu_dens'),
             ('mvm/mld-sta.c', 'iwl_mvm_mld_send_sta_cmd'),
             ('mvm/mld-sta.c', 'iwl_mvm_mld_cfg_sta'),
             ('mvm/mld-sta.c', 'iwl_mvm_mld_rm_sta_from_fw'),
             ('mvm/tx.c', 'iwl_mvm_flush_sta_tids'),
             ('mvm/rs-fw.c', 'rs_fw_bw_from_sta_bw'),
             ('mvm/rs-fw.c', 'rs_fw_set_active_chains'),
             ('mvm/rs-fw.c', 'rs_fw_set_supp_rates'),
             ('mvm/rs-fw.c', 'iwl_mvm_rs_fw_rate_init')]
for file, name in functions:
    prefix += function(file, name)
main = r'''
static void hex(void){if(!length){printf("-");return;}for(unsigned i=0;i<length;i++)printf("%02x",wire[i]);}
int main(void){
 struct fw fw={0};struct ieee80211_channel channel={0};struct iwl_mvm_vif_link_info vi={0};
 struct iwl_mvm_vif mvif={.link={&vi}};struct ieee80211_vif vif={.priv=&mvif,.bss_conf={.chanreq={.oper={.chan=&channel}}}};
 struct iwl_mvm_link_sta link={0};struct iwl_mvm_sta ms={.vif=&vif,.sta_state=IEEE80211_STA_NONE,.sta_type=STATION_TYPE_PEER,.link={&link}};
 struct ieee80211_sta sta={.priv=&ms,.addr={2,3,4,5,6,7},.deflink={.addr={2,3,4,5,6,7},.rx_nss=1,.smps_mode=IEEE80211_SMPS_OFF}};
 struct ieee80211_rate bitrates[12];for(unsigned i=0;i<12;i++)bitrates[i].hw_value=i;
 struct ieee80211_supported_band bands[2]={{.band=0,.bitrates=bitrates},{.band=1,.bitrates=bitrates+4}};
 struct wiphy wiphy={.bands={&bands[0],&bands[1]}};struct ieee80211_hw hw={.wiphy=&wiphy};
 struct iwl_mvm m={.fw=&fw,.hw=&hw,.fw_id_to_mac_id={&sta}};
 for(unsigned version=0;version<=2;version++)for(unsigned mfp=0;mfp<2;mfp++)for(unsigned failed=0;failed<2;failed++){
  next_cmd_ver=version;fw.ucode_capa.mfp=mfp;failure=failed?-5:0;length=sends=0;
  int result=iwl_mvm_mld_cfg_sta(&m,&sta,&vif,&sta.deflink,&vif.bss_conf,&link);
  if(sends!=1)abort();printf("S %u %u %u %d %u ",version,mfp,failed,result,length);hex();puts("");
 }
 failure=0;
 for(unsigned version=1;version<=4;version++)for(unsigned ant=1;ant<=3;ant++)
 for(unsigned band=0;band<2;band++)for(unsigned mask=0;mask<3;mask++){
  static unsigned masks[2][3]={{1,0x15f,0xfff},{0x10,0x150,0xff0}};
  unsigned rates=masks[band][mask];next_cmd_ver=version;antennas=ant;channel.band=band;
  sta.deflink.supp_rates[band]=band?rates>>4:rates;length=sends=0;
  iwl_mvm_rs_fw_rate_init(&m,&vif,&sta,&vif.bss_conf,&sta.deflink,band);
  printf("T %u %u %u %u %u ",version,ant,band,rates,length);hex();puts("");
 }
 for(unsigned notification=0;notification<2;notification++){
  next_notif_ver=notification;memset(&response,0,sizeof(response));length=sends=0;
  int result=iwl_mvm_flush_sta_tids(&m,0,0xffff);printf("F %u %d %u ",notification,result,length);hex();puts("");
 }
 for(unsigned failed=0;failed<2;failed++){
  failure=failed?-5:0;length=sends=0;int result=iwl_mvm_mld_rm_sta_from_fw(&m,0);
  printf("R %u %d %u ",failed,result,length);hex();puts("");
 }
 return 0;
}
'''
out.mkdir(parents=True, exist_ok=False)
# Retain additional full original callback/host-only branches for independent
# source review. They are deliberately separate from the compiled wire unit:
# their preservation is integrity evidence, not an execution claim.
callbacks = [('mvm/mld-mac80211.c', 'iwl_mvm_mld_mac_sta_state'),
             ('mvm/mac80211.c', 'iwl_mvm_vif_conf_from_sta'),
             ('mvm/mac80211.c', 'iwl_mvm_rs_rate_init_all_links'),
             ('mvm/mac80211.c', 'iwl_mvm_sta_state_notexist_to_none'),
             ('mvm/mac80211.c', 'iwl_mvm_mac_sta_state_common'),
             ('mvm/mld-sta.c', 'iwl_mvm_mld_alloc_sta_link'),
             ('mvm/mld-sta.c', 'iwl_mvm_mld_alloc_sta_links'),
             ('mvm/mld-sta.c', 'iwl_mvm_mld_set_ap_sta_id'),
             ('mvm/mld-sta.c', 'iwl_mvm_mld_update_sta'),
             ('mvm/mld-sta.c', 'iwl_mvm_mld_add_sta'),
             ('mvm/mld-sta.c', 'iwl_mvm_mld_disable_sta_queues'),
             ('mvm/mld-sta.c', 'iwl_mvm_mld_rm_sta'),
             ('mvm/sta.c', 'iwl_mvm_find_free_sta_id'),
             ('mvm/sta.c', 'iwl_mvm_sta_init'),
             ('mvm/sta.c', 'iwl_mvm_wait_sta_queues_empty'),
             ('mvm/sta.c', 'iwl_mvm_sta_del'),
             ('mvm/mld-key.c', 'iwl_mvm_sec_key_remove_ap'),
             ('mvm/rs.c', 'iwl_mvm_rs_rate_init'),
             ('mvm/mvm.h', 'iwl_mvm_has_new_station_api')]
spans = ''.join('/* Original ' + file + ':' + name + ' */\n' + function(file, name) for file, name in callbacks)
(out / 'original-callbacks-source-review.c').write_text(spans)
unit = out / 'linux-iwlwifi-mld-peer.c'
unit.write_text(prefix + main)
exe = out / 'linux-iwlwifi-mld-peer'
subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', str(unit), '-o', str(exe)], check=True, timeout=60)
with (out / 'trace.txt').open('wb') as trace:
    subprocess.run([str(exe.resolve())], stdout=trace, check=True, timeout=60)
data = (out / 'trace.txt').read_bytes()
manifest = {'linux_commit': 'cc9de5d4b5ab6459f5774946aa3195ad51236fa8', 'sources': expected,
            'headers': headers, 'whole_functions': functions, 'records': len(data.splitlines()),
            'source_review_only_callbacks': callbacks,
            'source_review_only_sha256': hashlib.sha256(spans.encode()).hexdigest(),
            'trace_sha256': hashlib.sha256(data).hexdigest(), 'scope': __doc__}
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest, indent=2))
