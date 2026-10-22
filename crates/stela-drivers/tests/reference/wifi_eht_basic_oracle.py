#!/usr/bin/env python3
"""Execute unchanged pinned EHT local basic-MCS getter+verification helpers.

Usage: wifi_eht_basic_oracle.py OUTPUT_DIR VERIFIED_MODERN_SOURCE_CACHE
Full source/declarations are hash-bound. Donors and native output stay ignored.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from wifi_mac_oracle import PIN
from wifi_data_oracle import complete_function

SOURCES={
 'net/mac80211/mlme.c':'c21da8dfbe059571692bdc75e75f5aa57e0133587afbf2c915ad73f055495011',
 'include/net/cfg80211.h':'972ae23f32259859b54c4b93fa46fb60cba8c879da888b2751014a6cd27bfcf3',
 'include/linux/ieee80211-eht.h':'3301a09629b7efafe791abcbc9346c7b20a515dc1e254826f03e71c602052f5e',
 'include/linux/ieee80211-he.h':'f8e110ec4c212914f45c36db1599be55da17823a1148d38241e227602390728e',
}
def main():
 root,cache=Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve()
 root.mkdir(parents=True,exist_ok=True);source={};receipt={'pin':PIN,'sources':[]}
 for name,expected in SOURCES.items():
  data=(cache/name).read_bytes()
  if hashlib.sha256(data).hexdigest()!=expected: raise RuntimeError(f'donor mismatch:{name}')
  source[name]=data.decode();receipt['sources'].append({'path':name,'sha256':expected,
   'git_blob_sha1':hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()})
 helpers=[complete_function(source['net/mac80211/mlme.c'],signature) for signature in [
  'static u8\nieee80211_get_eht_cap_mcs_nss(',
  'static bool\nieee80211_verify_sta_eht_mcs_support(']]
 declarations=[complete_function(source['include/linux/ieee80211-eht.h'],'struct '+name+' {')+';' for name in [
  'ieee80211_eht_mcs_nss_supp_20mhz_only','ieee80211_eht_mcs_nss_supp_bw']]
 declarations+=[complete_function(source['include/net/cfg80211.h'],'struct ieee80211_eht_mcs_nss_supp {')+' __packed;']
 harness=r'''
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint8_t u8;typedef uint16_t u16;
#define __packed __attribute__((packed))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define WARN_ON(x) ((void)(x))
#define u8_get_bits(v,m) (((v)&(m)) >> __builtin_ctz((unsigned)(m)))
#define IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_MASK_ALL 0x1e
#define IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G 8
#define IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G 16
#define IEEE80211_EHT_PHY_CAP0_320MHZ_IN_6GHZ 2
#define IEEE80211_EHT_MCS_NSS_RX 15
#define IEEE80211_EHT_MCS_NSS_TX 0xf0
'''+ '\n'.join(declarations)+r'''
_Static_assert(sizeof(struct ieee80211_eht_mcs_nss_supp)==9,"actual source union");
struct ieee80211_sta_he_cap {struct {u8 mac_cap_info[6],phy_cap_info[11];}he_cap_elem;};
struct ieee80211_sta_eht_cap {struct {u8 mac_cap_info[2],phy_cap_info[9];}eht_cap_elem;
 struct ieee80211_eht_mcs_nss_supp eht_mcs_nss_supp;};
struct ieee80211_eht_operation {u8 params;struct ieee80211_eht_mcs_nss_supp_20mhz_only basic_mcs_nss;};
struct ieee80211_sub_if_data {unsigned vif;};struct ieee80211_supported_band {unsigned band;};
static struct ieee80211_sta_he_cap he;
static struct ieee80211_sta_eht_cap eht;
static const struct ieee80211_sta_he_cap *ieee80211_get_he_iftype_cap_vif(const void *s,const void *v) {
 (void)s;(void)v;return &he;
}
static const struct ieee80211_sta_eht_cap *ieee80211_get_eht_iftype_cap_vif(const void *s,const void *v) {
 (void)s;(void)v;return &eht;
}
'''+ '\n\n'.join(helpers)+r'''
int main(void) {
 for(unsigned flags=0;flags<32;flags+=2) for(unsigned wide=0;wide<2;++wide)
 for(unsigned group=0;group<4;++group) for(unsigned bw=0;bw<3;++bw)
 for(unsigned have=0;have<9;++have) for(unsigned required=0;required<9;++required)
 for(unsigned direction=0;direction<2;++direction) {
  he.he_cap_elem.phy_cap_info[0]=flags;eht.eht_cap_elem.phy_cap_info[0]=wide ? 2 : 0;
  u8 *raw=(void *)&eht.eht_mcs_nss_supp;memset(raw,0x88,9);
  unsigned idx=flags&0x1e ? bw*3+(group ? group-1 : 0) : group;
  raw[idx]=direction ? 8|(have<<4) : have|0x80;
  struct ieee80211_eht_operation operation={0};
  operation.basic_mcs_nss.rx_tx_max_nss[group]=direction ? required<<4 : required;
  struct ieee80211_sub_if_data s={0};struct ieee80211_supported_band b={0};
  if(putchar(ieee80211_verify_sta_eht_mcs_support(&s,&b,&operation))==EOF) abort();
 }
 return fflush(stdout)!=0;
}
'''
 c,exe=root/'basic.c',root/'basic';c.write_text(harness)
 cmd=['clang','-std=c11','-Wall','-Wextra','-Werror','-O1','-g',
  '-fsanitize=address,undefined',str(c),'-o',str(exe)]
 subprocess.run(cmd,check=True);output=subprocess.run([str(exe)],check=True,capture_output=True).stdout
 if len(output)!=62208: raise RuntimeError('incomplete EHT basic output')
 (root/'basic.bin').write_bytes(output)
 receipt.update({'cases':len(output),'output_sha256':hashlib.sha256(output).hexdigest(),
  'harness_sha256':hashlib.sha256(harness.encode()).hexdigest(),
  'helpers_sha256':[hashlib.sha256(x.encode()).hexdigest() for x in helpers],
  'declarations_sha256':[hashlib.sha256(x.encode()).hexdigest() for x in declarations],
  'command':cmd,'scope':'Full unchanged all-local-width EHT basic-MCS getter+verification;20-only, all HE width flags, EHT320, every four MCS group, each weak width and independent RX/TX NSS0..8 versus requirement0..8. Scaffold supplies actual source union layout and both local capability pointers; no cryptography/radio/association authority.'})
 (root/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(receipt['output_sha256'])
if __name__=='__main__':main()
