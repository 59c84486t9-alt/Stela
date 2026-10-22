#!/usr/bin/env python3
"""Run full unchanged pinned EHT-to-station helper with ASan/UBSan.

Usage: wifi_eht_union_oracle.py OUTPUT_DIR PINNED_SOURCE_CACHE
Only the reproducer is committed; donors/binaries/output remain ignored.
The scaffold supplies layout/availability only, not replacement map-copy logic.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from wifi_mac_oracle import PIN
from wifi_data_oracle import complete_function

SOURCES = {
    'net/mac80211/eht.c': '3ddef246e9893d5f62e26c4d258a80db47c3600ae2fe787b6f44a0b37142c607',
    'include/net/cfg80211.h': '972ae23f32259859b54c4b93fa46fb60cba8c879da888b2751014a6cd27bfcf3',
    'include/linux/ieee80211-eht.h': '3301a09629b7efafe791abcbc9346c7b20a515dc1e254826f03e71c602052f5e',
}

def main():
    root, cache = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    sources, manifest = {}, {'pin': PIN, 'sources': []}
    for name, expected in SOURCES.items():
        data = (cache / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError(f'donor mismatch: {name}')
        sources[name] = data.decode()
        manifest['sources'].append({'path': name, 'sha256': expected,
            'git_blob_sha1': hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()})
    eht = sources['include/linux/ieee80211-eht.h']
    helpers = [complete_function(eht, name) for name in [
        'static inline u8\nieee80211_eht_mcs_nss_size(',
        'static inline u8\nieee80211_eht_ppe_size(']]
    helpers.append(complete_function(sources['net/mac80211/eht.c'],
        'void\nieee80211_eht_cap_ie_to_sta_eht_cap('))
    # Preserve exact packed source MCS layouts, including anonymous overlays.
    declarations = [complete_function(eht, 'struct '+name+' {')+';' for name in [
        'ieee80211_eht_mcs_nss_supp_20mhz_only', 'ieee80211_eht_mcs_nss_supp_bw']]
    declarations += [complete_function(sources['include/net/cfg80211.h'],
        'struct ieee80211_eht_mcs_nss_supp {')+' __packed;']
    harness = r'''
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
#define __packed __attribute__((packed))
#define hweight16(x) __builtin_popcount((unsigned)(x))
#define u16_get_bits(v,m) (((v)&(m)) >> __builtin_ctz((unsigned)(m)))
#define u8_get_bits(v,m) u16_get_bits(v,m)
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_IN_2G 2
#define IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G 4
#define IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G 8
#define IEEE80211_EHT_PHY_CAP0_320MHZ_IN_6GHZ 2
#define IEEE80211_EHT_PHY_CAP5_PPE_THRESHOLD_PRESENT 8
#define IEEE80211_EHT_PPE_THRES_RU_INDEX_BITMASK_MASK 0x1f0
#define IEEE80211_EHT_PPE_THRES_NSS_MASK 15
#define IEEE80211_EHT_PPE_THRES_INFO_PPET_SIZE 3
#define IEEE80211_EHT_PPE_THRES_INFO_HEADER_SIZE 9
#define IEEE80211_EHT_MAC_CAP0_MAX_MPDU_LEN_MASK 0xc0
#define IEEE80211_EHT_MAC_CAP0_MAX_MPDU_LEN_3895 0
#define IEEE80211_EHT_MAC_CAP0_MAX_MPDU_LEN_11454 2
#define IEEE80211_EHT_MAC_CAP0_MAX_MPDU_LEN_7991 1
#define IEEE80211_MAX_MPDU_LEN_VHT_11454 11454
#define IEEE80211_MAX_MPDU_LEN_VHT_7991 7991
#define IEEE80211_MAX_MPDU_LEN_VHT_3895 3895
#define NL80211_IFTYPE_STATION 1
#define NL80211_BAND_2GHZ 0
struct ieee80211_he_cap_elem { u8 mac_cap_info[6],phy_cap_info[11]; } __packed;
struct ieee80211_eht_cap_elem_fixed { u8 mac_cap_info[2],phy_cap_info[9]; } __packed;
struct ieee80211_eht_cap_elem { struct ieee80211_eht_cap_elem_fixed fixed; u8 optional[]; } __packed;
''' + '\n'.join(declarations) + r'''
_Static_assert(sizeof(struct ieee80211_eht_mcs_nss_supp)==9,"source union size");
struct ieee80211_sta_eht_cap { bool has_eht; struct ieee80211_eht_cap_elem_fixed eht_cap_elem;
 struct ieee80211_eht_mcs_nss_supp eht_mcs_nss_supp; u8 eht_ppe_thres[32]; };
struct pub_sta { struct ieee80211_sta_eht_cap eht_cap; struct { unsigned max_amsdu_len; } agg; };
struct sta_info { unsigned sta; };
struct link_sta_info { struct pub_sta *pub; struct sta_info *sta; };
struct ieee80211_sub_if_data { struct { unsigned type; } vif; };
struct ieee80211_supported_band { unsigned band; };
static bool available;
static const void *ieee80211_get_eht_iftype_cap_vif(const void *a,const void *b) {
 (void)a;(void)b;return available ? &available : NULL;
}
static u16 get_unaligned_le16(const void *p) { const u8 *b=p;return b[0]|b[1]<<8; }
static void ieee80211_sta_recalc_aggregates(void *p) { (void)p; }
''' + '\n\n'.join(helpers) + r'''
int main(void) {
 for(unsigned phy0=0;phy0<256;++phy0) for(unsigned width320=0;width320<2;++width320)
 for(unsigned ap=0;ap<2;++ap) for(unsigned local=0;local<2;++local)
 for(int extra=-1;extra<=1;++extra) {
  struct ieee80211_he_cap_elem he={0};he.phy_cap_info[0]=phy0;
  u8 buffer[32]={0};struct ieee80211_eht_cap_elem *e=(void *)buffer;
  e->fixed.phy_cap_info[0]=width320 ? 2 : 0;
  unsigned size=ieee80211_eht_mcs_nss_size(&he,&e->fixed,ap);
  for(unsigned i=0;i<size;++i) e->optional[i]=(u8)(0x11*(1+i%8));
  struct pub_sta pub;memset(&pub,0xa5,sizeof(pub));struct sta_info sta={0};
  struct link_sta_info link={&pub,&sta};struct ieee80211_supported_band band={1};
  struct ieee80211_sub_if_data sdata={.vif={ap ? NL80211_IFTYPE_STATION : 2}};
  available=local;
  ieee80211_eht_cap_ie_to_sta_eht_cap(&sdata,&band,(u8 *)&he,sizeof(he),e,
      (u8)(11+size+extra),&link);
  if(putchar(pub.eht_cap.has_eht)==EOF ||
     fwrite(&pub.eht_cap.eht_mcs_nss_supp,1,9,stdout)!=9) abort();
 }
 return fflush(stdout)!=0;
}
'''
    path, executable = root/'eht.c', root/'eht'
    path.write_text(harness)
    command = ['clang','-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-O1','-g',
        '-fsanitize=address,undefined',str(path),'-o',str(executable)]
    subprocess.run(command,check=True)
    output = subprocess.run([str(executable)],check=True,capture_output=True).stdout
    if len(output)!=61440:
        raise RuntimeError('incomplete EHT union output')
    (root/'eht.bin').write_bytes(output)
    manifest.update({'cases':6144,'output_sha256':hashlib.sha256(output).hexdigest(),
        'harness_sha256':hashlib.sha256(harness.encode()).hexdigest(),
        'helpers_sha256':[hashlib.sha256(x.encode()).hexdigest() for x in helpers],
        'declarations_sha256':[hashlib.sha256(x.encode()).hexdigest() for x in declarations],
        'command':command,'scope':'Full unchanged EHT station helper, source union overlays, all width bytes/roles, missing local support and short/exact/extra input. No TX authority or cryptography.'})
    (root/'receipt.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(manifest['output_sha256'])

if __name__=='__main__':
    main()
