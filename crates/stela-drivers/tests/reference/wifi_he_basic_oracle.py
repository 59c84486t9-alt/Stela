#!/usr/bin/env python3
"""Full unchanged Linux default-profile peer/local HE Basic verifiers.

Usage: wifi_he_basic_oracle.py OUTPUT_DIR VERIFIED_MODERN_SOURCE_CACHE
Source, native binaries and receipts stay ignored. No AP/application exceptions.
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
 'include/linux/ieee80211-he.h':'f8e110ec4c212914f45c36db1599be55da17823a1148d38241e227602390728e',
}
def main():
 root,cache=Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve();root.mkdir(parents=True,exist_ok=True)
 source={};receipt={'pin':PIN,'sources':[]}
 for name,sha in SOURCES.items():
  data=(cache/name).read_bytes()
  if hashlib.sha256(data).hexdigest()!=sha:raise RuntimeError(f'donor mismatch:{name}')
  source[name]=data.decode();receipt['sources'].append({'path':name,'sha256':sha,
   'git_blob_sha1':hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()})
 helpers=[complete_function(source['net/mac80211/mlme.c'],s) for s in [
  'static bool\nieee80211_verify_peer_he_mcs_support(',
  'static bool\nieee80211_verify_sta_he_mcs_support(']]
 declarations=[complete_function(source['include/linux/ieee80211-he.h'],'struct '+name+' {')+' __packed;' for name in [
  'ieee80211_he_cap_elem','ieee80211_he_mcs_nss_supp','ieee80211_he_operation']]
 harness=r'''
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint16_t __le16;typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define le16_to_cpu(x) (x)
#define IEEE80211_HE_MCS_NOT_SUPPORTED 3
#define ieee80211_hw_check(hw,flag) false
#define link_id_info(s,id,fmt,...) ((void)0)
'''+ '\n'.join(declarations)+r'''
struct ieee80211_sta_he_cap {bool has_he;struct ieee80211_he_cap_elem he_cap_elem;struct ieee80211_he_mcs_nss_supp he_mcs_nss_supp;};
struct ieee80211_sub_if_data {unsigned vif;};struct ieee80211_supported_band {unsigned band;};
static struct ieee80211_sta_he_cap local __attribute__((aligned(8)));
static const struct ieee80211_sta_he_cap *ieee80211_get_he_iftype_cap_vif(const void *b,const void *v) {
 (void)b;(void)v;return &local;
}
'''+ '\n\n'.join(helpers)+r'''
static void run(u16 basic,u16 peer_rx,u16 peer_tx,const u16 maps[6]) {
 struct {struct ieee80211_he_cap_elem fixed;struct ieee80211_he_mcs_nss_supp maps;} __packed peer={0};
 peer.maps.rx_mcs_80=peer_rx;peer.maps.tx_mcs_80=peer_tx;
 memcpy(&local.he_mcs_nss_supp,maps,12);
 struct ieee80211_he_operation op={.he_mcs_nss_set=basic};
 struct ieee80211_sub_if_data s={0};struct ieee80211_supported_band band={0};
 if(putchar(ieee80211_verify_peer_he_mcs_support(&s,0,&peer.fixed,&op))==EOF ||
    putchar(ieee80211_verify_sta_he_mcs_support(&s,&band,&op))==EOF)abort();
}
int main(void) {
 local.has_he=true;
 for(unsigned nss=0;nss<8;++nss) for(unsigned req=0;req<4;++req)
 for(unsigned rx=0;rx<4;++rx) for(unsigned tx=0;tx<4;++tx)
 for(unsigned peer_rx=0;peer_rx<4;++peer_rx) for(unsigned peer_tx=0;peer_tx<4;++peer_tx)
 for(unsigned width=0;width<3;++width) for(unsigned zero=0;zero<2;++zero) {
  unsigned shift=nss*2;u16 mask=(u16)~(3u<<shift);
  u16 maps[6];for(unsigned i=0;i<6;++i)maps[i]=zero ? 0 : 0xffff;
  maps[2*width]=mask|(rx<<shift);maps[2*width+1]=mask|(tx<<shift);
  u16 base=0xfffc;
  run(mask|(req<<shift),(base&mask)|(peer_rx<<shift),(base&mask)|(peer_tx<<shift),maps);
 }
 for(unsigned rx=0;rx<4;++rx)for(unsigned tx=0;tx<4;++tx) {
  const u16 absent[6]={0xffff,0xffff,0xffff,0xffff,0xffff,0xffff};run(0,0xfffc|rx,0xfffc|tx,absent);
 }
 return fflush(stdout)!=0;
}
'''
 c,exe=root/'he-basic.c',root/'he-basic';c.write_text(harness)
 cmd=['clang','-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-O1','-g',
  '-fsanitize=address,undefined',str(c),'-o',str(exe)]
 subprocess.run(cmd,check=True);out=subprocess.run([str(exe)],check=True,capture_output=True).stdout
 if len(out)!=98336:raise RuntimeError('incomplete HE basic output')
 (root/'he-basic.bin').write_bytes(out)
 receipt.update({'cases':49168,'output_sha256':hashlib.sha256(out).hexdigest(),
  'harness_sha256':hashlib.sha256(harness.encode()).hexdigest(),'helpers_sha256':[hashlib.sha256(x.encode()).hexdigest() for x in helpers],
  'declarations_sha256':[hashlib.sha256(x.encode()).hexdigest() for x in declarations],
  'command':cmd,'scope':'Unchanged peer/local HE verifiers with actual selected non-STRICT flag. Each NSS/basic encoding/independent local+peer RX/TX map encoding, every full local source width slot and actual zeroed/unsupported other slots; literal Basic0 retains mandatory peer1SS. Local source6words supplied explicitly, never inferred from wire absence. No physical/policy/auth authority.'})
 (root/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(receipt['output_sha256'])
if __name__=='__main__':main()
