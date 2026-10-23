#!/usr/bin/env python3
"""Run unchanged pinned cfg80211 channel-IE precedence under ASan/UBSan.

Usage: wifi_scan_channel_oracle.py OUTPUT_DIR [DONOR_CACHE]
Cache may contain linux/ and scan-sources/ subdirectories from earlier leaves.
Only this reproducer is committed. The donor selector, HE size/offset helpers
and element iteration remain unchanged. S1G is outside the exercised profile.
"""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from urllib.request import urlopen

from wifi_mac_oracle import PIN
from wifi_data_oracle import complete_function

SOURCES = {
    "include/linux/ieee80211.h": "a65c9f90c87f66509a8fb31c0a77bdbbfae019cd0199edf131cbd798f140bdaa",
    "include/net/cfg80211.h": "972ae23f32259859b54c4b93fa46fb60cba8c879da888b2751014a6cd27bfcf3",
    "net/wireless/scan.c": "873356e3432355feddaeaf3d725548d10c79bc6cfd218282b863c87395b6027c",
    "include/linux/ieee80211-he.h": "f8e110ec4c212914f45c36db1599be55da17823a1148d38241e227602390728e",
    "include/linux/ieee80211-ht.h": "0e25fe12bd20064f3eafc2aaadf9b7df4f0d577bc887762169ac042985b9d09b",
}


def main():
    root = Path(sys.argv[1]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    cache = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else root / "linux"
    source, manifest = {}, {"pin": PIN, "sources": []}
    for name, expected in SOURCES.items():
        path = next((candidate for candidate in [cache / name, cache / "linux" / name,
            cache / "scan-sources" / name] if candidate.exists()), cache / name)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(urlopen(f"https://raw.githubusercontent.com/torvalds/linux/{PIN}/{name}").read())
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError(f"donor hash mismatch: {name}")
        source[name] = data.decode()
        manifest["sources"].append({"path": name, "sha256": expected,
            "git_blob_sha1": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()})
    header = source["include/linux/ieee80211.h"]
    macros = header[header.index("#define for_each_element("):header.index("#define for_each_element_extid(")]
    ht = source["include/linux/ieee80211-ht.h"]
    ht_start = ht.index("struct ieee80211_ht_operation {")
    ht_struct = ht[ht_start:ht.index("} __packed;", ht_start) + len("} __packed;")]
    he = source["include/linux/ieee80211-he.h"]
    import re
    def layout(name):
        at = he.index("struct " + name + " {")
        return he[at:he.index("} __packed;", at) + len("} __packed;")]
    he_layouts = layout("ieee80211_he_operation") + "\n" + layout("ieee80211_he_6ghz_oper")
    he_flags = "\n".join(re.search(r"^#define " + name + r"\s+[^\n]+", he, re.M).group() for name in [
        "IEEE80211_HE_OPERATION_VHT_OPER_INFO", "IEEE80211_HE_OPERATION_CO_HOSTED_BSS", "IEEE80211_HE_OPERATION_6GHZ_OP_INFO"])
    helpers = [complete_function(source["net/wireless/scan.c"], "const struct element *\ncfg80211_find_elem_match("),
        complete_function(source["include/net/cfg80211.h"], "static inline const struct element *\ncfg80211_find_elem("),
        complete_function(source["include/net/cfg80211.h"], "static inline const struct element *\ncfg80211_find_ext_elem("),
        complete_function(he, "static inline u8\nieee80211_he_oper_size("),
        complete_function(he, "static inline const struct ieee80211_he_6ghz_oper *\nieee80211_he_6ghz_oper("),
        complete_function(source["net/wireless/scan.c"], "int cfg80211_get_ies_channel_number(")]
    harness = r"""
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t __le16;
typedef uint32_t u32;
typedef uint32_t __le32;
#define le32_to_cpu(x) (x)
#define WLAN_EID_EXTENSION 255
#define __packed __attribute__((packed))
#define WLAN_EID_DS_PARAMS 3
#define WLAN_EID_HT_OPERATION 61
#define WLAN_EID_EXT_HE_OPERATION 36
#define WLAN_EID_S1G_OPERATION 232
enum nl80211_band { NL80211_BAND_2GHZ,NL80211_BAND_5GHZ,NL80211_BAND_6GHZ,NL80211_BAND_S1GHZ };
struct element { u8 id,datalen;u8 data[]; } __packed;
struct ieee80211_s1g_oper_ie { u8 oper_ch; };
/* Kernel memcmp permits a zero-length match with NULL, unlike the hosted
 * libc declaration's nonnull annotation. Preserve those kernel semantics. */
static int kernel_memcmp(const void *a,const void *b,size_t n) { return n ? memcmp(a,b,n) : 0; }
#define memcmp kernel_memcmp
""" + he_flags + "\n" + he_layouts + "\n" + ht_struct + "\n" + macros + "\n\n".join(helpers) + r"""
static void add(u8 *data,size_t *length,u8 id,unsigned count,u8 first) {
    if(*length+2+count>80) abort();data[(*length)++]=id;data[(*length)++]=count;
    for(unsigned i=0;i<count;++i) data[(*length)++]=i ? 0 : first;
}
static void he_case(u8 *ies,size_t *length,unsigned flags,unsigned variant,u8 primary) {
    u32 params=(flags&1 ? IEEE80211_HE_OPERATION_VHT_OPER_INFO:0) |
        (flags&2 ? IEEE80211_HE_OPERATION_CO_HOSTED_BSS:0) |
        (flags&4 ? IEEE80211_HE_OPERATION_6GHZ_OP_INFO:0);
    u8 data[20]={36};size_t n=7;memcpy(data+1,&params,4);
    if(flags&1)n+=3;if(flags&2)n++;
    if(flags&4){data[n]=primary;n+=5;}
    if(variant==1)n--;
    if(variant==2)data[n++]=0xa5;
    if(variant==3 || variant==5){size_t first=variant==3?5:6;ies[(*length)++]=255;ies[(*length)++]=first;memcpy(ies+*length,data,first);*length+=first;}
    if(variant==4){add(ies,length,3,1,primary^0x5a);add(ies,length,61,22,primary^0x33);}
    if(variant==6){params &= ~IEEE80211_HE_OPERATION_6GHZ_OP_INFO;memcpy(data+1,&params,4);}
    if(variant==7)add(ies,length,255,1,35);
    ies[(*length)++]=255;ies[(*length)++]=n;memcpy(ies+*length,data,n);*length+=n;
}
int main(void) {
    _Static_assert(sizeof(struct ieee80211_ht_operation)==22,"HT operation size");
    for(unsigned band=0;band<2;++band) for(unsigned variant=0;variant<8;++variant) for(unsigned value=0;value<256;++value) {
        u8 ies[80]={0};size_t length=0;
        if(variant==0 || variant==6) add(ies,&length,3,1,value);
        if(variant==1) add(ies,&length,3,0,0);
        if(variant==2 || variant==3) add(ies,&length,3,2,value);
        if(variant==3) add(ies,&length,3,1,value);
        if(variant<6) add(ies,&length,61,variant==2 ? 21 : variant==5 ? 23 : 22,
                         variant==0 || variant==3 ? value^0x5a : value);
        int result=cfg80211_get_ies_channel_number(ies,length,(enum nl80211_band)band);
        uint16_t encoded=(uint16_t)(int16_t)result;
        if(putchar(encoded&255)==EOF || putchar(encoded>>8)==EOF) abort();
    }
    for(unsigned flags=0;flags<8;flags++)for(unsigned variant=0;variant<8;variant++)for(unsigned primary=0;primary<256;primary++){
        u8 ies[80]={0};size_t length=0;he_case(ies,&length,flags,variant,primary);
        int result=cfg80211_get_ies_channel_number(ies,length,NL80211_BAND_6GHZ);
        uint16_t encoded=(uint16_t)(int16_t)result;
        if(putchar(encoded&255)==EOF || putchar(encoded>>8)==EOF)abort();
    }
    return fflush(stdout)!=0;
}
"""
    c_file, executable = root / "channel.c", root / "channel"
    c_file.write_text(harness)
    command = ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-g",
        "-fsanitize=address,undefined", str(c_file), "-o", str(executable)]
    subprocess.run(command, check=True)
    output = subprocess.run([str(executable)], check=True, capture_output=True).stdout
    if len(output) != (4096 + 16384) * 2:
        raise RuntimeError("incomplete channel output")
    legacy, six = output[:4096 * 2], output[4096 * 2:]
    (root / "channel.bin").write_bytes(legacy)
    (root / "channel6.bin").write_bytes(six)
    manifest.update({"cases": 4096, "output_sha256": hashlib.sha256(legacy).hexdigest(),
        "six_ghz_cases": 16384, "six_ghz_output_sha256": hashlib.sha256(six).hexdigest(),
        "harness_sha256": hashlib.sha256(harness.encode()).hexdigest(), "command": command,
        "helpers_sha256": [hashlib.sha256(helper.encode()).hexdigest() for helper in helpers],
        "macros_sha256": hashlib.sha256(macros.encode()).hexdigest(),
        "ht_struct_sha256": hashlib.sha256(ht_struct.encode()).hexdigest(),
        "limits": "2.4/5GHz DS/HT and 6GHz HE channel selection; S1G and scan radio lifecycle outside this oracle"})
    (root / "receipt.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(manifest["output_sha256"])


if __name__ == "__main__":
    main()
