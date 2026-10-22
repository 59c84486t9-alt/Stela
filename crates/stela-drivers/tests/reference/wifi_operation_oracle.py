#!/usr/bin/env python3
"""Full unchanged Linux channel geometry/puncturing oracle, ASan/UBSan.

Usage: wifi_operation_oracle.py OUTPUT_DIR PINNED_ASSOCIATION_SOURCE_CACHE
Only this reproducer is committed. Source/binary/results remain ignored.
Non-Wi-Fi/S1G/NPCA/EDMG branches are unavailable in the explicit test profile.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from wifi_mac_oracle import PIN
from wifi_data_oracle import complete_function

SHA='a58880f0b3225a5790e1874e6a88675e4ac0eb8098df432d597ca1549d79ded0'
def main():
    root, cache=Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve()
    root.mkdir(parents=True,exist_ok=True)
    data=(cache/'net/wireless/chan.c').read_bytes()
    if hashlib.sha256(data).hexdigest()!=SHA: raise RuntimeError('donor mismatch')
    source=data.decode()
    util_data=(cache/'net/mac80211/util.c').read_bytes()
    util_sha='40be00a3ec50e372842238c4fbd6c1f61e5f6554ac205a2d55c905dd0d848bed'
    if hashlib.sha256(util_data).hexdigest()!=util_sha: raise RuntimeError('util donor mismatch')
    begin=source.index('struct cfg80211_per_bw_puncturing_values {')
    end=source.index('static bool cfg80211_edmg_chandef_valid(',begin)
    helpers=[source[begin:end]]+[complete_function(source,s) for s in [
        'int nl80211_chan_width_to_mhz(', 'static bool cfg80211_valid_center_freq(',
        'static bool\ncfg80211_chandef_valid_control_freq(', 'bool cfg80211_chandef_valid(']]
    vht_helper=complete_function(util_data.decode(),'bool ieee80211_chandef_vht_oper(')
    harness=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define BIT(n) (1u<<(n))
#define WARN_ON_ONCE(x) (x)
#define fallthrough __attribute__((fallthrough))
enum nl80211_chan_width {NL80211_CHAN_WIDTH_20,NL80211_CHAN_WIDTH_40,
 NL80211_CHAN_WIDTH_80,NL80211_CHAN_WIDTH_160,NL80211_CHAN_WIDTH_80P80,
 NL80211_CHAN_WIDTH_320,NL80211_CHAN_WIDTH_20_NOHT,NL80211_CHAN_WIDTH_1,
 NL80211_CHAN_WIDTH_2,NL80211_CHAN_WIDTH_4,NL80211_CHAN_WIDTH_8,NL80211_CHAN_WIDTH_16};
struct ieee80211_channel {u32 center_freq;unsigned band;};
struct cfg80211_chan_def {struct ieee80211_channel *chan;enum nl80211_chan_width width;
 u32 center_freq1,center_freq2,freq1_offset,npca_chan,npca_punctured,punctured;
 bool s1g_primary_2mhz;};
static bool cfg80211_chandef_is_s1g(const void *p) {(void)p;return false;}
static bool cfg80211_chandef_is_edmg(const void *p) {(void)p;return false;}
static bool cfg80211_edmg_chandef_valid(const void *p) {(void)p;abort();}
static u32 cfg80211_s1g_get_start_freq_khz(const void *p) {(void)p;abort();}
static u32 cfg80211_s1g_get_end_freq_khz(const void *p) {(void)p;abort();}
static u32 ieee80211_chandef_to_khz(const struct cfg80211_chan_def *p) {return p->center_freq1*1000;}
static u32 ieee80211_channel_to_khz(const struct ieee80211_channel *p) {return p->center_freq*1000;}
'''+ '\n\n'.join(helpers)+r'''
#define IEEE80211_VHT_CAP_EXT_NSS_BW_MASK 0xc0000000u
#define IEEE80211_VHT_CAP_EXT_NSS_BW_SHIFT 30
#define IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_MASK 0xc
#define IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ 4
#define IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ 8
#define IEEE80211_HT_OP_MODE_CCFS2_MASK 0x1fe0
#define IEEE80211_HT_OP_MODE_CCFS2_SHIFT 5
#define IEEE80211_VHT_CHANWIDTH_USE_HT 0
#define IEEE80211_VHT_CHANWIDTH_80MHZ 1
#define IEEE80211_VHT_CHANWIDTH_160MHZ 2
#define IEEE80211_VHT_CHANWIDTH_80P80MHZ 3
#define u32_get_bits(v,m) (((v)&(m)) >> __builtin_ctz((unsigned)(m)))
#define le16_to_cpu(v) (v)
#define ieee80211_hw_check(hw,flag) true
struct ieee80211_vht_operation {u8 chan_width,center_freq_seg0_idx,center_freq_seg1_idx;u16 basic_mcs_set;};
struct ieee80211_ht_operation {u8 primary_chan,ht_param;u16 operation_mode,stbc_param;u8 basic_set[16];};
struct band {struct {u32 cap;}vht_cap;};
struct wiphy {struct band *bands[3];};struct ieee80211_hw {struct wiphy *wiphy;};
/* Exact source conversion for this bounded 5GHz1..177 test range, zero absent. */
static int ieee80211_channel_to_frequency(int channel,unsigned band) {
 (void)band;return channel>0 ? 5000+5*channel : 0;
}
'''+vht_helper+r'''
int main(void) {
 const enum nl80211_chan_width widths[]={NL80211_CHAN_WIDTH_20,NL80211_CHAN_WIDTH_40,
  NL80211_CHAN_WIDTH_80,NL80211_CHAN_WIDTH_160,NL80211_CHAN_WIDTH_80P80,NL80211_CHAN_WIDTH_320};
 for(unsigned w=0;w<6;++w) for(unsigned n=1;n<=233;++n) for(unsigned c=1;c<=233;++c) {
  struct ieee80211_channel chan={.center_freq=n==2 ? 5935 : 5950+n*5};
  struct cfg80211_chan_def def={.chan=&chan,.width=widths[w],.center_freq1=5950+c*5,
    .center_freq2=w==4 ? 6755 : 0};
  if(putchar(cfg80211_chandef_valid(&def))==EOF) abort();
 }
 for(unsigned w=2;w<=5;++w) {
  if(w==4) continue;
  unsigned bw=w==2 ? 80 : w==3 ? 160 : 320;
  unsigned center=5945+bw/2;
  for(unsigned n=0;n<bw/20;++n) for(unsigned mask=0;mask<65536;++mask) {
   struct ieee80211_channel chan={.center_freq=center-bw/2+10+n*20};
   struct cfg80211_chan_def def={.chan=&chan,.width=widths[w],.center_freq1=center,.punctured=mask};
   if(putchar(cfg80211_chandef_valid(&def))==EOF) abort();
  }
 }
 const u32 caps[]={0,4,8};
 for(unsigned own=0;own<3;++own) for(unsigned peer=0;peer<3;++peer)
 for(unsigned width=0;width<4;++width) for(unsigned c0=0;c0<178;++c0) for(unsigned c1=0;c1<178;++c1) {
  struct band band={.vht_cap={caps[own]}};struct wiphy wiphy={.bands={&band}};
  struct ieee80211_hw hw={&wiphy};struct ieee80211_channel chan={.center_freq=5180,.band=0};
  struct cfg80211_chan_def def={.chan=&chan,.width=NL80211_CHAN_WIDTH_40,.center_freq1=5190};
  struct ieee80211_ht_operation ht={.primary_chan=36,.ht_param=5};
  struct ieee80211_vht_operation vht={width,c0,c1,0xffff};
  bool ok=ieee80211_chandef_vht_oper(&hw,caps[peer],&vht,&ht,&def);
  u8 bytes[6]={0};if(ok) {bytes[0]=1;bytes[1]=def.width;
    bytes[2]=def.center_freq1&255;bytes[3]=def.center_freq1>>8;
    bytes[4]=def.center_freq2&255;bytes[5]=def.center_freq2>>8;}
  if(fwrite(bytes,1,6,stdout)!=6) abort();
 }
 return fflush(stdout)!=0;
}
'''
    c, exe=root/'operations.c',root/'operations'
    c.write_text(harness)
    cmd=['clang','-std=c11','-Wall','-Wextra','-Werror','-O1','-g',
      '-fsanitize=address,undefined',str(c),'-o',str(exe)]
    subprocess.run(cmd,check=True)
    output=subprocess.run([str(exe)],check=True,capture_output=True).stdout
    if len(output)!=9004486: raise RuntimeError('incomplete operation output')
    (root/'operations.bin').write_bytes(output)
    # Preserve raw donor output unchanged. The native single-link profile also
    # refuses overlapping80+80 segments, which the donor's non6GHz center-grid
    # validation does not fully reject. Record this explicit stricter boundary.
    native=bytearray(output)
    overlap_refusals=0
    for offset in range(2160742,len(native),6):
        if native[offset] and native[offset+1]==4:
            first=int.from_bytes(native[offset+2:offset+4],'little')
            second=int.from_bytes(native[offset+4:offset+6],'little')
            if abs(first-second)<=80:
                native[offset:offset+6]=bytes(6)
                overlap_refusals+=1
    (root/'native-profile.bin').write_bytes(native)
    receipt={'pin':PIN,'source':{'path':'net/wireless/chan.c','sha256':SHA,
      'git_blob_sha1':hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()},
      'cases':3301366,'output_sha256':hashlib.sha256(output).hexdigest(),
      'native_profile_sha256':hashlib.sha256(native).hexdigest(),'additional_overlap_refusals':overlap_refusals,
      'harness_sha256':hashlib.sha256(harness.encode()).hexdigest(),
      'helpers_sha256':[hashlib.sha256(x.encode()).hexdigest() for x in helpers+[vht_helper]],
      'vht_source':{'path':'net/mac80211/util.c','sha256':util_sha,'git_blob_sha1':hashlib.sha1(b'blob '+str(len(util_data)).encode()+b'\0'+util_data).hexdigest()},
      'command':cmd,'scope':'6GHz integral MHz geometry20/40/80/160/80+80/320 and every16bit puncture pattern/primary position; complete unchanged VHT operation helper extNSS0 across9local/peer width pairs x4encodings x178x178segment indices, 5GHz control36. Other bands/profiles,S1G/EDMG/NPCA unavailable; no regulatory permission.'}
    (root/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(receipt['output_sha256'])
if __name__=='__main__': main()
