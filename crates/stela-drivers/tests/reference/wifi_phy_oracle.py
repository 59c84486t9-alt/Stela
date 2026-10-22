#!/usr/bin/env python3
"""Run complete unchanged pinned HE intersection/HE+EHT sizing under sanitizers.

Usage: wifi_phy_oracle.py OUTPUT_DIR [PINNED_SOURCE_CACHE]
Only the reproducer is committed; donors, native binaries and receipts stay local.
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
    "net/mac80211/he.c": "08f12eb8965ff285663d9de13493c472a85821417395833eb778b0ab5240eb45",
    "include/linux/ieee80211-he.h": "f8e110ec4c212914f45c36db1599be55da17823a1148d38241e227602390728e",
    "include/linux/ieee80211-eht.h": "3301a09629b7efafe791abcbc9346c7b20a515dc1e254826f03e71c602052f5e",
}


def main():
    root = Path(sys.argv[1]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    cache = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else root / "linux"
    source, manifest = {}, {"pin": PIN, "sources": []}
    for name, expected in SOURCES.items():
        path = cache / name
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(urlopen(f"https://raw.githubusercontent.com/torvalds/linux/{PIN}/{name}").read())
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError(f"donor mismatch: {name}")
        source[name] = data.decode()
        manifest["sources"].append({"path": name, "sha256": expected,
            "git_blob_sha1": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()})
    he = source["include/linux/ieee80211-he.h"]
    eht = source["include/linux/ieee80211-eht.h"]
    helpers = [
        complete_function(source["net/mac80211/he.c"], "static void ieee80211_he_mcs_intersection("),
        complete_function(he, "static inline u8\nieee80211_he_ppe_size("),
        complete_function(eht, "static inline u8\nieee80211_eht_ppe_size("),
        complete_function(eht, "static inline u8\nieee80211_eht_mcs_nss_size("),
    ]
    harness = r"""
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint16_t __le16;
#define cpu_to_le16(x) ((uint16_t)(x))
#define le16_to_cpu(x) ((uint16_t)(x))
#define hweight8(x) __builtin_popcount((unsigned)(x))
#define hweight16(x) __builtin_popcount((unsigned)(x))
#define u16_get_bits(v,m) (((v)&(m)) >> __builtin_ctz((unsigned)(m)))
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define IEEE80211_HE_MCS_NOT_SUPPORTED 3
#define IEEE80211_HE_PHY_CAP6_PPE_THRESHOLD_PRESENT 0x80
#define IEEE80211_PPE_THRES_RU_INDEX_BITMASK_MASK 0x78
#define IEEE80211_PPE_THRES_NSS_MASK 7
#define IEEE80211_PPE_THRES_NSS_POS 0
#define IEEE80211_PPE_THRES_INFO_PPET_SIZE 3
#define IEEE80211_EHT_PHY_CAP5_PPE_THRESHOLD_PRESENT 8
#define IEEE80211_EHT_PPE_THRES_RU_INDEX_BITMASK_MASK 0x1f0
#define IEEE80211_EHT_PPE_THRES_NSS_MASK 15
#define IEEE80211_EHT_PPE_THRES_INFO_PPET_SIZE 3
#define IEEE80211_EHT_PPE_THRES_INFO_HEADER_SIZE 9
#define IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_IN_2G 2
#define IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G 4
#define IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G 8
#define IEEE80211_EHT_PHY_CAP0_320MHZ_IN_6GHZ 2
struct ieee80211_he_cap_elem { u8 mac_cap_info[6],phy_cap_info[11]; };
struct ieee80211_eht_cap_elem_fixed { u8 mac_cap_info[2],phy_cap_info[9]; };
""" + "\n\n".join(helpers) + r"""
static void output16(u16 value) { if(putchar(value&255)==EOF || putchar(value>>8)==EOF) abort(); }
int main(void) {
    for(unsigned nss=0;nss<8;++nss) for(unsigned ownrx=0;ownrx<4;++ownrx)
    for(unsigned owntx=0;owntx<4;++owntx) for(unsigned peerrx=0;peerrx<4;++peerrx)
    for(unsigned peertx=0;peertx<4;++peertx) {
        unsigned shift=nss*2;u16 mask=(u16)~(3u<<shift);
        __le16 a=mask|(ownrx<<shift),b=mask|(peerrx<<shift);
        __le16 c=mask|(owntx<<shift),d=mask|(peertx<<shift);
        ieee80211_he_mcs_intersection(&a,&b,&c,&d);
        output16(b);output16(d);
    }
    for(unsigned enabled=0;enabled<2;++enabled) for(unsigned header=0;header<256;++header) {
        u8 phy[11]={0};phy[6]=enabled ? 0x80 : 0;
        if(putchar(ieee80211_he_ppe_size(header,phy))==EOF) abort();
    }
    for(unsigned enabled=0;enabled<2;++enabled) for(unsigned header=0;header<512;++header) {
        u8 phy[9]={0};phy[5]=enabled ? 8 : 0;
        if(putchar(ieee80211_eht_ppe_size(header,phy))==EOF) abort();
    }
    for(unsigned phy0=0;phy0<256;++phy0) for(unsigned width320=0;width320<2;++width320)
    for(unsigned ap=0;ap<2;++ap) {
        struct ieee80211_he_cap_elem h={0};struct ieee80211_eht_cap_elem_fixed e={0};
        h.phy_cap_info[0]=phy0;e.phy_cap_info[0]=width320 ? 2 : 0;
        if(putchar(ieee80211_eht_mcs_nss_size(&h,&e,ap))==EOF) abort();
    }
    return fflush(stdout)!=0;
}
"""
    path, executable = root / "phy.c", root / "phy"
    path.write_text(harness)
    command = ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-g",
        "-fsanitize=address,undefined", str(path), "-o", str(executable)]
    subprocess.run(command, check=True)
    output = subprocess.run([str(executable)], check=True, capture_output=True).stdout
    if len(output) != 10752:
        raise RuntimeError("incomplete PHY output")
    (root / "phy.bin").write_bytes(output)
    manifest.update({"cases": 4608, "output_sha256": hashlib.sha256(output).hexdigest(),
        "harness_sha256": hashlib.sha256(harness.encode()).hexdigest(), "command": command,
        "helpers_sha256": [hashlib.sha256(x.encode()).hexdigest() for x in helpers],
        "limits": "Exact HE directional MCS intersection and HE/EHT PPE + role/width MCS sizing only; no radio or protocol-success claim"})
    (root / "receipt.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(manifest["output_sha256"])


if __name__ == "__main__":
    main()
