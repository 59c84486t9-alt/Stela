#!/usr/bin/env python3
"""Run unchanged pinned reg.c database/query/WMM/AUTO_BW helpers with sanitizers.

Usage: regulatory_database_oracle.py OUTPUT_DIR VERIFIED_LINUX_CACHE
The scaffold replaces allocation, endian helpers, signature-policy input and
reg_schedule_apply's OS publication. No radio is programmed by this oracle.
Mandatory-read truncations/unknown flags are Rust-only conservative refusals;
the source validator does not bound all mandatory rule reads. Donor/trace stay
ignored and are never overwritten by this reproducer.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from wifi_mac_oracle import PIN
from wifi_data_oracle import complete_function

SOURCE_SHA = "807927d3c1bc2619314691e0814d7b52fb2ba5d89006a1b22c5e12653b94a6ea"

def fixture(flags, length, region):
    b = bytearray(128)
    b[:8] = b"RGDB" + struct.pack(">I", 20)
    b[8:12] = b"US" + struct.pack(">H", 4)
    b[16:19] = bytes([3, 2, region])
    b[20:24] = struct.pack(">HH", 6, 12)
    for at, start, end, mask in [(24, 5150000, 5250000, flags), (48, 5250000, 5350000, flags ^ 3)]:
        b[at:at+16] = bytes([length, mask]) + struct.pack(">HIII", 1700+flags, start, end, 80000)
        if length >= 18:
            b[at+16:at+18] = struct.pack(">H", 60+region)
        if length >= 20:
            b[at+18:at+20] = struct.pack(">H", 20)
    for ac in range(8):
        b[80+ac*4:84+ac*4] = bytes([0x35+(ac % 2), 1+ac, 0, 3+ac])
    return b

def main():
    root = Path(sys.argv[1]).resolve()
    root.mkdir(parents=True, exist_ok=False)
    source = (Path(sys.argv[2]) / "net/wireless/reg.c").read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA:
        raise RuntimeError("pinned reg.c hash mismatch")
    header = (Path(sys.argv[2]) / "include/net/regulatory.h").read_bytes()
    header_sha = "f79e798657c7c688d851fa96d1fb65d8970ee6f866692f411c317f1d6b2ec179"
    if hashlib.sha256(header).hexdigest() != header_sha:
        raise RuntimeError("pinned regulatory.h hash mismatch")
    def layout(name):
        text = header.decode()
        start = text.index("struct " + name + " {")
        return text[start:text.index("};", start) + 2]
    target_layouts = [layout(name) for name in ["ieee80211_freq_range", "ieee80211_power_rule",
        "ieee80211_wmm_ac", "ieee80211_wmm_rule", "ieee80211_reg_rule", "ieee80211_regdomain"]]
    text = source.decode()
    layouts = text[text.index("struct fwdb_country {"):text.index("static int ecw2cw(")]
    signatures = ["static int ecw2cw(", "static bool valid_wmm(", "static bool valid_rule(",
        "static bool valid_country(", "static bool valid_regdb(", "static void set_wmm_rule(",
        "static unsigned int\nreg_get_max_bandwidth_from_range(", "unsigned int reg_get_max_bandwidth(",
        "static int regdb_query_country("]
    helpers = [complete_function(text, sig) for sig in signatures]
    harness = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
typedef uint8_t u8; typedef int8_t s8; typedef uint16_t u16; typedef uint32_t u32;
typedef uint16_t __be16; typedef uint32_t __be32;
#define __packed __attribute__((packed))
#define __aligned(n) __attribute__((aligned(n)))
#define BIT(n) (1U<<(n))
#define IEEE80211_NUM_ACS 4
#define be16_to_cpu(x) ntohs(x)
#define be32_to_cpu(x) ntohl(x)
#define cpu_to_be32(x) htonl(x)
#define offsetofend(t,m) (offsetof(t,m)+sizeof(((t*)0)->m))
#define ALIGN(n,a) (((n)+(a)-1)&~((a)-1))
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define MHZ_TO_KHZ(x) ((x)*1000)
#define ENOMEM 12
#define NL80211_RRF_NO_OFDM BIT(0)
#define NL80211_RRF_NO_OUTDOOR BIT(3)
#define NL80211_RRF_DFS BIT(4)
#define NL80211_RRF_NO_IR BIT(7)
#define NL80211_RRF_AUTO_BW BIT(11)
#define NL80211_RRF_NO_HT40MINUS BIT(13)
#define NL80211_RRF_NO_HT40PLUS BIT(14)
#define NL80211_RRF_NO_80MHZ BIT(15)
#define NL80211_RRF_NO_160MHZ BIT(16)
#define NL80211_RRF_NO_320MHZ BIT(18)
#define pr_err(...) fprintf(stderr,__VA_ARGS__)
#define kzalloc_flex(t,m,n) calloc(1,sizeof(t)+sizeof((t).m[0])*(n))
struct rcu_head {void *next;void *func;};
enum nl80211_dfs_regions {NL80211_DFS_UNSET,NL80211_DFS_FCC,NL80211_DFS_ETSI,NL80211_DFS_JP};
''' + "\n".join(target_layouts) + r'''
static bool regdb_has_valid_signature(const u8 *data,unsigned size){(void)data;(void)size;return true;}
static int reg_schedule_apply(struct ieee80211_regdomain *rd);
static void out(u32 v){u8 b[]={v,v>>8,v>>16,v>>24};if(fwrite(b,1,4,stdout)!=4)abort();}
''' + layouts + "\n\n".join(helpers) + r'''
static int reg_schedule_apply(struct ieee80211_regdomain *rd){
 out(rd->alpha2[0]);out(rd->alpha2[1]);out(rd->dfs_region);out(rd->n_reg_rules);
 for(unsigned i=0;i<rd->n_reg_rules;++i){struct ieee80211_reg_rule *r=&rd->reg_rules[i];
  out(r->freq_range.start_freq_khz);out(r->freq_range.end_freq_khz);out(r->freq_range.max_bandwidth_khz);
  out(r->power_rule.max_eirp);out(!!(r->flags&NL80211_RRF_NO_OFDM));out(!!(r->flags&NL80211_RRF_NO_OUTDOOR));
  out(!!(r->flags&NL80211_RRF_DFS));out(!!(r->flags&NL80211_RRF_NO_IR));out(!!(r->flags&NL80211_RRF_AUTO_BW));
  out(r->dfs_cac_ms);out(r->has_wmm);out((r->flags&NL80211_RRF_AUTO_BW)?reg_get_max_bandwidth(rd,r):r->freq_range.max_bandwidth_khz);
  if(r->has_wmm){for(unsigned j=0;j<8;++j){struct ieee80211_wmm_ac *a=j<4?&r->wmm_rule.client[j]:&r->wmm_rule.ap[j-4];
   out(a->cw_min);out(a->cw_max);out(a->aifsn);out(a->cot);}}
 }
 free(rd);return 0;
}
int main(int argc,char**argv){if(argc!=2)return 2;FILE*f=fopen(argv[1],"rb");if(!f)return 3;
 _Alignas(4) u8 b[128];while(fread(b,1,sizeof(b),f)==sizeof(b)){
  bool valid=valid_regdb(b,sizeof(b));out(valid);if(valid)regdb_query_country((void*)b,(void*)(b+8));
 }fclose(f);return 0;}
'''
    (root / "oracle.c").write_text(harness)
    cases = b"".join(fixture(flags, length, region) for flags in range(32) for length in [16,18,20] for region in range(4))
    invalid = []
    for mode in range(5):
        b = fixture(0,20,1)
        if mode == 0: b[0] = 0
        if mode == 1: b[7] = 21
        if mode == 2: b[24] = 15
        if mode == 3: b[80] = 0x55
        if mode == 4: b[81] = 0
        invalid.append(b)
    cases += b"".join(invalid)
    for cot in [0,1,65,66,255,1024,65535]:
        b = fixture(0,20,1)
        for ac in range(8):
            b[82+ac*4:84+ac*4] = struct.pack(">H",cot)
        cases += b
    (root / "cases.bin").write_bytes(cases)
    subprocess.run(["clang","-std=gnu11","-O1","-g","-fsanitize=address,undefined","-fno-sanitize-recover=all",str(root / "oracle.c"),"-o",str(root / "oracle")],check=True)
    with (root / "trace.bin").open("wb") as out_file:
        subprocess.run([str(root / "oracle"),str(root / "cases.bin")],stdout=out_file,check=True)
    manifest = {"pin":PIN,"source_sha256":SOURCE_SHA,"source_blob":"11665e0a7efc8a7b81d82834a0fcc79dffb396bb",
        "helpers":[{"signature":sig,"sha256":hashlib.sha256(body.encode()).hexdigest()} for sig,body in zip(signatures,helpers)],
        "header_sha256":header_sha,"target_layouts":[{"body":body,"sha256":hashlib.sha256(body.encode()).hexdigest()} for body in target_layouts],
        "cases":396,"valid_cases":391,"invalid_cases":5,"cases_sha256":hashlib.sha256(cases).hexdigest(),
        "trace_sha256":hashlib.sha256((root / "trace.bin").read_bytes()).hexdigest(),
        "oracle_limit":["signature trust is an explicit setup manifest input, not crypto execution", "OS apply is replaced only after complete unchanged source query decoding", "mandatory rule truncations and unknown future flags are checked independently in Rust, not source-equivalence cases"]}
    (root / "manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(json.dumps(manifest,indent=2))
if __name__ == "__main__": main()
