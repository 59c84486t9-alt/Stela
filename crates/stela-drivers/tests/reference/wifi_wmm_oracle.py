#!/usr/bin/env python3
"""Run unchanged pinned station regulatory WMM clamp with ASan/UBSan.

Usage: wifi_wmm_oracle.py FRESH_OUTPUT VERIFIED_LINUX_CACHE
Only the reproducer is committed. Native OS/wiphy/RCU acquisition is scaffolded;
queue/regulatory target structures and the complete clamp body are unchanged.
The profile is station-only; AP/mesh operation is not claimed.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from wifi_data_oracle import complete_function
from wifi_mac_oracle import PIN

SOURCES = {
    "net/mac80211/util.c":"40be00a3ec50e372842238c4fbd6c1f61e5f6554ac205a2d55c905dd0d848bed",
    "include/net/regulatory.h":"f79e798657c7c688d851fa96d1fb65d8970ee6f866692f411c317f1d6b2ec179",
    "include/net/mac80211.h":"3d1dd58c0b2ae0ea144f978b1141348274bcf3976e348847b298f2b5827038f9",
    "include/linux/ieee80211-he.h":"f8e110ec4c212914f45c36db1599be55da17823a1148d38241e227602390728e",
}

def main():
    root=Path(sys.argv[1]).resolve();root.mkdir(parents=True,exist_ok=False)
    cache=Path(sys.argv[2]);sources={}
    for path,pin in SOURCES.items():
        data=(cache/path).read_bytes()
        if hashlib.sha256(data).hexdigest()!=pin:raise RuntimeError("source mismatch:"+path)
        sources[path]=data.decode()
    def layout(path,name,packed=False):
        text=sources[path];start=text.index("struct "+name+" {")
        ending="} __packed;" if packed else "};"
        return text[start:text.index(ending,start)+len(ending)]
    layouts=[layout("include/linux/ieee80211-he.h","ieee80211_he_mu_edca_param_ac_rec",True),
        layout("include/net/mac80211.h","ieee80211_tx_queue_params")]
    layouts += [layout("include/net/regulatory.h",name) for name in ["ieee80211_freq_range","ieee80211_power_rule","ieee80211_wmm_ac","ieee80211_wmm_rule","ieee80211_reg_rule"]]
    body=complete_function(sources["net/mac80211/util.c"],"void ieee80211_regulatory_limit_wmm_params(")
    harness=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint8_t u8;typedef int8_t s8;typedef uint16_t u16;typedef uint32_t u32;
#define __packed __attribute__((packed))
#define IEEE80211_NUM_ACS 4
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define MHZ_TO_KHZ(x) ((x)*1000)
#define NL80211_IFTYPE_STATION 2
#define NL80211_IFTYPE_AP 3
#define IS_ERR_OR_NULL(x) (!(x))
#define rcu_read_lock() do{}while(0)
#define rcu_read_unlock() do{}while(0)
#define rcu_dereference(x) (x)
''' + "\n".join(layouts) + r'''
struct channel {int center_freq;};
struct ieee80211_chanctx_conf {struct {struct channel *chan;} def;};
struct ieee80211_sub_if_data {struct {int type;struct {struct ieee80211_chanctx_conf *chanctx_conf;} bss_conf;} vif;struct {void*wiphy;} wdev;};
static struct ieee80211_reg_rule rule;
static bool present;
static const struct ieee80211_reg_rule *freq_reg_info(void*wiphy,u32 freq){(void)wiphy;if(freq!=5180000)abort();return present?&rule:NULL;}
''' + body + r'''
static void byte(u8 x){if(fputc(x,stdout)==EOF)abort();}
static void word(u16 x){byte(x);byte(x>>8);}
int main(void){
 for(unsigned i=0;i<4096;++i){unsigned mode=i%5;struct channel ch={.center_freq=mode==1?0:5180};
  struct ieee80211_chanctx_conf ctx={.def.chan=&ch};
  struct ieee80211_sub_if_data s={.vif.type=NL80211_IFTYPE_STATION,.vif.bss_conf.chanctx_conf=mode?&ctx:NULL};
  present=mode>=3;rule.has_wmm=mode==4;
  for(unsigned j=0;j<4;++j){unsigned lo=(i+5*j)%15;
   rule.wmm_rule.client[j]=(struct ieee80211_wmm_ac){.cw_min=(1U<<lo)-1,.cw_max=(1U<<(lo+1))-1,.aifsn=1+(i+31*j)%255,.cot=(i*997+j*1237)%65536};}
  for(unsigned aci=0;aci<4;++aci){unsigned lo=(i+aci)%16,hi=lo+(i/16)%(16-lo);
   struct ieee80211_tx_queue_params q={.cw_min=(1U<<lo)-1,.cw_max=(1U<<hi)-1,.aifs=2+(i+aci)%14,.txop=(i*37+aci*101)%65536,.acm=(i+aci)%2};
   static const unsigned queue[]={2,3,1,0};
   ieee80211_regulatory_limit_wmm_params(&s,&q,queue[aci]);
   byte(aci);byte(q.acm);word(q.cw_min);word(q.cw_max);byte(q.aifs);word(q.txop);
  }
 }
 return 0;
}
'''
    (root/"oracle.c").write_text(harness)
    subprocess.run(["clang","-std=gnu11","-O1","-g","-fsanitize=address,undefined","-fno-sanitize-recover=all",str(root/"oracle.c"),"-o",str(root/"oracle")],check=True)
    with (root/"trace.bin").open("wb") as out:subprocess.run([str(root/"oracle")],stdout=out,check=True)
    manifest={"pin":PIN,"sources":SOURCES,"helper_sha256":hashlib.sha256(body.encode()).hexdigest(),
        "target_layouts":[{"body":v,"sha256":hashlib.sha256(v.encode()).hexdigest()}for v in layouts],
        "cases":4096,"queue_results":16384,"trace_sha256":hashlib.sha256((root/"trace.bin").read_bytes()).hexdigest(),
        "oracle_limit":["RCU/OS current-channel and rule lookup are controlled scaffolds; no OS/hardware permission", "station profile; other interface roles outside declared driver", "native command effect covered separately by actual model ACK/rejection tests"]}
    (root/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(json.dumps({k:v for k,v in manifest.items()if k!="target_layouts"},indent=2))
if __name__=="__main__":main()
