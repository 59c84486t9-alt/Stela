#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Original tg3 AUX decode plus exact copper MAC speed/duplex source blocks.

Arguments: original broadcom directory, original uapi/linux/ethtool.h, fresh
ignored output directory. Scalar register encodings only, no physical wire proof.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from tg3_transport_oracle import DONORS, body

ETHTOOL_SHA256 = "4c79ad8d7c4c06aa85cc9f13fc88a165711b5986ca779ca8b9ee284717faa998"
PIN = "cc9de5d4b5ab6459f5774946aa3195ad51236fa8"


def main():
    source, ethtool, output = map(Path, sys.argv[1:])
    root = Path(__file__).resolve().parents[4]
    if not output.resolve().is_relative_to(root / ".stela"):
        raise ValueError("output must remain in ignored .stela")
    texts = {}
    for name, digest in DONORS.items():
        raw = (source / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("changed original " + name)
        texts[name] = raw.decode()
    eth_raw = ethtool.read_bytes()
    if hashlib.sha256(eth_raw).hexdigest() != ETHTOOL_SHA256:
        raise ValueError("changed original ethtool.h")
    names = {"SPEED_10", "SPEED_100", "SPEED_1000", "SPEED_UNKNOWN", "DUPLEX_HALF", "DUPLEX_FULL", "DUPLEX_UNKNOWN"}
    macros = [line for line in eth_raw.decode().splitlines()
              if re.match(r"#define\s+(\w+)", line)
              and re.match(r"#define\s+(\w+)", line).group(1) in names]
    if len(macros) != len(names):
        raise ValueError("missing original speed/duplex macros")
    macros.extend(line for line in texts["tg3.h"].splitlines()
                  if line.startswith("#define TG3_PHYFLG_IS_FET"))
    decode = body(texts["tg3.c"], "tg3_aux_stat_to_speed_duplex")
    copper = body(texts["tg3.c"], "tg3_setup_copper_phy")
    start = copper.index("\ttp->mac_mode &= ~MAC_MODE_PORT_MODE_MASK;")
    port = copper[start:copper.index("\n\t/* In order for", start)]
    start = copper.index("\ttp->mac_mode &= ~MAC_MODE_HALF_DUPLEX;")
    duplex = copper[start:copper.index("\n\tif (tg3_asic_rev(tp) == ASIC_REV_5700)", start)]
    header = texts["tg3.h"].split("struct tg3_tx_buffer_desc {", 1)[0] + "\n#endif\n"
    wrapper = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
typedef uint32_t u32;typedef uint8_t u8;
#include "donor_constants.h"
struct tg3 {u32 phy_flags,mac_mode;struct {u32 active_speed;u8 active_duplex;}link_config;};
'''
    wrapper += "\n".join(macros) + "\n" + decode
    wrapper += "\nstatic u32 original_mac(struct tg3 *tp) {bool current_link_up=true;\n" + port + "\n" + duplex + "\nreturn tp->mac_mode;}\n"
    wrapper += r'''
int main(void) {
 const u32 initial[]={0,0xa5f12345,0x5a0abcde,0x3c};
 puts("TG3_PHY_LINK_V1 32");
 for(unsigned sample=0;sample<4;sample++) for(unsigned aux=0;aux<8;aux++) {
  u32 speed;u8 duplex;u32 status=(aux<<8)|(sample<<12)|0x55;
  struct tg3 tp={.phy_flags=0,.mac_mode=initial[sample]};
  tg3_aux_stat_to_speed_duplex(&tp,status,&speed,&duplex);
  tp.link_config.active_speed=speed;tp.link_config.active_duplex=duplex;
  u32 after=(speed==(u32)SPEED_UNKNOWN)?tp.mac_mode:original_mac(&tp);
  printf("%u %u %u %u %u\n",status,initial[sample],speed,duplex,after);
 }
 puts("END 32");
}
'''
    output.mkdir(parents=True, exist_ok=False)
    (output / "donor_constants.h").write_text(header)
    (output / "ethtool.h").write_bytes(eth_raw)
    (output / "oracle.c").write_text(wrapper)
    exe = output / "oracle"
    command = ["clang", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
               "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
               str(output / "oracle.c"), "-o", str(exe)]
    subprocess.run(command, check=True, timeout=60)
    result = subprocess.run([str(exe)], check=True, capture_output=True, timeout=15)
    (output / "trace.txt").write_bytes(result.stdout)
    (output / "stderr.txt").write_bytes(result.stderr)
    (output / "manifest.json").write_text(json.dumps({
        "linux_pin": PIN, "donors": DONORS, "ethtool_sha256": ETHTOOL_SHA256,
        "helper_sha256": hashlib.sha256(decode.encode()).hexdigest(),
        "port_block_sha256": hashlib.sha256(port.encode()).hexdigest(),
        "duplex_block_sha256": hashlib.sha256(duplex.encode()).hexdigest(),
        "wrapper_sha256": hashlib.sha256(wrapper.encode()).hexdigest(),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "executable_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
        "trace_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "command": command, "cases": 32,
        "scope": "unchanged AUX decoder and complete selected MAC speed/duplex blocks; 1000half intentionally refused by Rust advertisement policy; no PHY/MDIO/packet or physical proof",
        "rust_comparison": "UNRUN until coordinated Rust gate",
    }, indent=2) + "\n")
    print("32 original AUX/MAC cases passed ASan/UBSan")


if __name__ == "__main__":
    main()
