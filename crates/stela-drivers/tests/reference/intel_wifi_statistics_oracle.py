#!/usr/bin/env python3
"""Serialize complete packets using pinned Linux Intel statistics declarations.

Usage: script PINNED_IWLWIFI_FW_API_DIRECTORY OUTPUT_DIRECTORY
Only declaration layout and C field conversion are measured; no firmware is read.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

PIN = "cc9de5d4b5ab6459f5774946aa3195ad51236fa8"
HASHES = {
    "stats.h": "23563771253355aedad33a1de51655a2ef7499e3aff4b71fd00db4ae44527e2a",
    "mac.h": "6076083cec1720a0c5d94eebe9e156a8e866c24afad12ca7fd2efc54404f9bc0",
    "mac-cfg.h": "3e4aa8bb08a992255e92b5136409b287cab5bfe0e693d7a2df57c87e68c3b0ae",
}
MACROS = {
    "mac.h": ["MAC_INDEX_AUX", "NUM_MAC_INDEX_DRIVER", "NUM_MAC_INDEX", "NUM_MAC_INDEX_CDB", "IWL_STATION_COUNT_MAX"],
    "mac-cfg.h": ["IWL_FW_MAX_LINK_ID", "IWL_FW_MAX_LINKS"],
}
reference, output = map(Path, sys.argv[1:])
if sys.byteorder != "little":
    raise ValueError("this C declaration fixture requires a little-endian host")
sources = {}
for name, expected in HASHES.items():
    data = (reference / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("changed pinned donor: " + name)
    sources[name] = data
output.mkdir(parents=True, exist_ok=True)
(output / "stats.h").write_bytes(sources["stats.h"])
for name, macros in MACROS.items():
    definitions = []
    for macro in macros:
        hits = [line for line in sources[name].decode().splitlines()
                if line.startswith("#define " + macro + " ") or line.startswith("#define " + macro + "\t")]
        if len(hits) != 1:
            raise ValueError("expected one pinned definition: " + macro)
        definitions.extend(hits)
    (output / name).write_text("\n".join(definitions) + "\n")

PREAMBLE = r"""#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t __s8;
typedef uint8_t __u8;
typedef uint16_t __le16;
typedef uint32_t __le32;
typedef uint64_t __le64;
#define __packed __attribute__((__packed__))
#define BIT(x) (1U << (x))
#define BIT_ULL(x) (1ULL << (x))
#include "stats.h"
#include <string.h>
"""
WRAPPER = r"""static void dump(const char *name,int mac,int32_t sig,size_t len,const void *raw) {
 printf("%s %d %d ",name,mac,sig);
 const uint8_t *bytes=raw;
 for(size_t i=0;i<len;i++) printf("%02x",bytes[i]);
 printf("\n");
}
int main(void) {
 uint32_t energies[]={0,1,50,62,65,70,127,255,256,0x80000000,0xffffffff};
 for(unsigned int mac=0;mac<MAC_INDEX_AUX;mac++) {
  for(unsigned int i=0;i<sizeof(energies)/sizeof(energies[0]);i++) {
   uint32_t e=energies[i];
   struct iwl_notif_statistics_v11 a;memset(&a,0x5a,sizeof(a));
   a.rx.general.mac_id=mac;a.general.common.beacon_filter_average_energy=e;
   dump("legacy11",mac,-(int)a.general.common.beacon_filter_average_energy,sizeof(a),&a);
   struct iwl_notif_statistics b;memset(&b,0x5a,sizeof(b));
   b.rx.general.mac_id=mac;b.general.common.beacon_filter_average_energy=e;
   dump("legacy13",mac,-(int)b.general.common.beacon_filter_average_energy,sizeof(b),&b);
   struct iwl_statistics_operational_ntfy_ver_14 c;memset(&c,0x5a,sizeof(c));
   c.hdr.type=FW_STATISTICS_OPERATIONAL;c.hdr.version=14;c.hdr.size=sizeof(c);
   c.mac_id=mac;c.beacon_filter_average_energy=e;
   dump("tlv14",mac,-(int)(uint8_t)c.beacon_filter_average_energy,sizeof(c),&c);
   struct iwl_statistics_operational_ntfy d;memset(&d,0x5a,sizeof(d));
   d.hdr.type=FW_STATISTICS_OPERATIONAL;d.hdr.version=15;d.hdr.size=sizeof(d);
   d.per_mac[mac].beacon_filter_average_energy=e;
   dump("tlv15",mac,(int32_t)(0-d.per_mac[mac].beacon_filter_average_energy),sizeof(d),&d);
   struct iwl_system_statistics_notif_oper f;memset(&f,0x5a,sizeof(f));
   f.per_link[mac].beacon_filter_average_energy=e;
   dump("system3",mac,(int32_t)(0-f.per_link[mac].beacon_filter_average_energy),sizeof(f),&f);
  }
 }
 return 0;
}
"""

c_source = PREAMBLE + WRAPPER
(output / "packets.c").write_text(c_source)
subprocess.run([
    "clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
    "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
    str(output / "packets.c"), "-o", str(output / "packets"),
], check=True)
packets = subprocess.check_output([str(output / "packets")])
if len(packets.splitlines()) != 220:
    raise ValueError("expected 220 complete C packets")
header = "linux=" + PIN + " " + " ".join(name + "=" + digest for name, digest in HASHES.items())
trace = header.encode() + b"\n" + packets
(output / "packets.trace").write_bytes(trace)
manifest = {
    "linux_revision": PIN,
    "sources": HASHES,
    "cases": 220,
    "wrapper_sha256": hashlib.sha256(c_source.encode()).hexdigest(),
    "trace_sha256": hashlib.sha256(trace).hexdigest(),
    "scope": "declaration layout and field conversion only; no firmware or hardware acceptance",
}
(output / "source.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps(manifest))
