#!/usr/bin/env python3
"""Extract unchanged pinned Linux header/CCMP helpers; emit an exhaustive oracle.

Only source files and harnesses are saved under the supplied ignored directory.
Run: python3 crates/stela-drivers/tests/reference/wifi_mac_oracle.py .stela/wifi-mac
Requires clang with AddressSanitizer and UndefinedBehaviorSanitizer.
Linux-derived helpers retain GPL-2.0-only and their original notices in source.
"""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.request import urlopen

PIN = "a804c5742bff224d4cb4d25dd383554d598be32b"
SOURCES = {
    "include/linux/ieee80211.h": "a65c9f90c87f66509a8fb31c0a77bdbbfae019cd0199edf131cbd798f140bdaa",
    "net/wireless/util.c": "634e0be5dc138ee467b2b08a287480cd7b639cd0c498ba742b0c7a703621ae22",
    "net/mac80211/wpa.c": "07087347278d9f01307c98bad12554a611a8b70f703af4e7ca31747713d365b5",
}


def function(source, name):
    match = re.search(r"^(?:static inline |unsigned int __attribute_const__ )[^\n]*\b" + name + r"\([^;]*?\)\n\{", source, re.M)
    if not match:
        raise RuntimeError(f"missing donor function {name}")
    start = source.index("{", match.start())
    depth = 1
    end = start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end]


def main():
    root = Path(sys.argv[1]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    source = {}
    manifest = {"pin": PIN, "sources": [], "helpers": []}
    for name, expected in SOURCES.items():
        target = root / "linux" / name
        if target.exists():
            data = target.read_bytes()
        else:
            data = urlopen(f"https://raw.githubusercontent.com/torvalds/linux/{PIN}/{name}").read()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected:
            raise RuntimeError(f"donor hash mismatch: {name}")
        source[name] = data.decode()
        manifest["sources"].append({"path": name, "sha256": digest,
            "git_blob_sha1": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()})
    header = source["include/linux/ieee80211.h"]
    names = ["ieee80211_has_a4", "ieee80211_has_order", "ieee80211_is_mgmt",
             "ieee80211_is_ctl", "ieee80211_is_data", "ieee80211_is_ext", "ieee80211_is_data_qos"]
    helpers = [function(header, name) for name in names]
    helpers += [function(source["net/wireless/util.c"], "ieee80211_hdrlen"),
                function(source["net/mac80211/wpa.c"], "ccmp_hdr2pn")]
    for helper in helpers:
        manifest["helpers"].append({"sha256": hashlib.sha256(helper.encode()).hexdigest(), "source": helper})
    harness = """
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
typedef uint16_t __le16;
typedef uint8_t u8;
#define __attribute_const__
#define cpu_to_le16(x) (x)
#define IEEE80211_FCTL_FTYPE 0x000c
#define IEEE80211_FCTL_STYPE 0x00f0
#define IEEE80211_FCTL_TODS 0x0100
#define IEEE80211_FCTL_FROMDS 0x0200
#define IEEE80211_FCTL_ORDER 0x8000
#define IEEE80211_FTYPE_MGMT 0x0000
#define IEEE80211_FTYPE_CTL 0x0004
#define IEEE80211_FTYPE_DATA 0x0008
#define IEEE80211_FTYPE_EXT 0x000c
#define IEEE80211_STYPE_QOS_DATA 0x0080
#define IEEE80211_QOS_CTL_LEN 2
#define IEEE80211_HT_CTL_LEN 4
""" + "\n\n".join(helpers) + """
int main(void) {
    for (unsigned int i = 0; i <= 65535; ++i) {
        unsigned int len = ieee80211_hdrlen((uint16_t)i);
        u8 h[8] = {(u8)i, (u8)(i >> 8), 0, (u8)(0x20 | ((i >> 14) << 6)),
                   (u8)(i * 3), (u8)(i >> 3), (u8)(i * 7), (u8)(i >> 5)};
        u8 pn[6];
        ccmp_hdr2pn(pn, h);
        if (putchar((u8)len) == EOF || putchar((u8)(len >> 8)) == EOF ||
            fwrite(pn, 1, 6, stdout) != 6) return 1;
    }
    return fflush(stdout) != 0;
}
"""
    c_file = root / "oracle.c"
    c_file.write_text(harness)
    executable = root / "oracle"
    command = ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-g",
               "-fsanitize=address,undefined", str(c_file), "-o", str(executable)]
    subprocess.run(command, check=True)
    output = subprocess.run([str(executable)], check=True, capture_output=True).stdout
    if len(output) != 65536 * 8:
        raise RuntimeError("truncated oracle")
    (root / "oracle.bin").write_bytes(output)
    manifest.update({"cases": 65536, "output_sha256": hashlib.sha256(output).hexdigest(),
                     "harness_sha256": hashlib.sha256(harness.encode()).hexdigest(), "command": command})
    (root / "oracle.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(manifest["output_sha256"])


if __name__ == "__main__":
    main()
