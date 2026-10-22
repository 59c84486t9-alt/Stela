#!/usr/bin/env python3
"""Run unchanged pinned cfg80211 channel-IE precedence under ASan/UBSan.

Usage: wifi_scan_channel_oracle.py OUTPUT_DIR [DONOR_CACHE]
Cache may contain linux/ and scan-sources/ subdirectories from earlier leaves.
Only this reproducer is committed. HE/6GHz/S1G scaffolding aborts if entered;
the donor function and element iteration remain unchanged for 2.4/5GHz.
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
    helpers = [complete_function(source["net/wireless/scan.c"], "const struct element *\ncfg80211_find_elem_match("),
        complete_function(source["include/net/cfg80211.h"], "static inline const struct element *\ncfg80211_find_elem("),
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
#define __packed __attribute__((packed))
#define WLAN_EID_DS_PARAMS 3
#define WLAN_EID_HT_OPERATION 61
#define WLAN_EID_EXT_HE_OPERATION 36
#define WLAN_EID_S1G_OPERATION 232
enum nl80211_band { NL80211_BAND_2GHZ,NL80211_BAND_5GHZ,NL80211_BAND_6GHZ,NL80211_BAND_S1GHZ };
struct element { u8 id,datalen;u8 data[]; } __packed;
struct ieee80211_he_operation { u8 unused; };
struct ieee80211_he_6ghz_oper { u8 primary; };
struct ieee80211_s1g_oper_ie { u8 oper_ch; };
/* Kernel memcmp permits a zero-length match with NULL, unlike the hosted
 * libc declaration's nonnull annotation. Preserve those kernel semantics. */
static int kernel_memcmp(const void *a,const void *b,size_t n) { return n ? memcmp(a,b,n) : 0; }
#define memcmp kernel_memcmp
static const struct element *cfg80211_find_ext_elem(u8 id,const u8 *ie,size_t len) { (void)id;(void)ie;(void)len;abort(); }
static size_t ieee80211_he_oper_size(const u8 *data) { (void)data;abort(); }
static const struct ieee80211_he_6ghz_oper *ieee80211_he_6ghz_oper(const struct ieee80211_he_operation *op) { (void)op;abort(); }
""" + ht_struct + "\n" + macros + "\n\n".join(helpers) + r"""
static void add(u8 *data,size_t *length,u8 id,unsigned count,u8 first) {
    if(*length+2+count>80) abort();data[(*length)++]=id;data[(*length)++]=count;
    for(unsigned i=0;i<count;++i) data[(*length)++]=i ? 0 : first;
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
    return fflush(stdout)!=0;
}
"""
    c_file, executable = root / "channel.c", root / "channel"
    c_file.write_text(harness)
    command = ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-g",
        "-fsanitize=address,undefined", str(c_file), "-o", str(executable)]
    subprocess.run(command, check=True)
    output = subprocess.run([str(executable)], check=True, capture_output=True).stdout
    if len(output) != 4096 * 2:
        raise RuntimeError("incomplete channel output")
    (root / "channel.bin").write_bytes(output)
    manifest.update({"cases": 4096, "output_sha256": hashlib.sha256(output).hexdigest(),
        "harness_sha256": hashlib.sha256(harness.encode()).hexdigest(), "command": command,
        "helpers_sha256": [hashlib.sha256(helper.encode()).hexdigest() for helper in helpers],
        "macros_sha256": hashlib.sha256(macros.encode()).hexdigest(),
        "ht_struct_sha256": hashlib.sha256(ht_struct.encode()).hexdigest(),
        "limits": "2.4/5GHz first DS/HT element precedence only; HE/6GHz/S1G abort if entered; no scan radio lifecycle executed"})
    (root / "receipt.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(manifest["output_sha256"])


if __name__ == "__main__":
    main()
