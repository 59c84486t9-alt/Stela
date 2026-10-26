#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run unchanged Linux tg3_power_down_phy for admitted unmanaged copper ASICs.

Arguments: original broadcom directory, original uapi/linux/mii.h, fresh ignored
output directory, optional literal bcm5761 for its three PLL-selection cases.
No rail/power ownership, DMA, physical PHY or PCI PM proof.
"""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

from tg3_transport_oracle import DONORS, body

PIN = "cc9de5d4b5ab6459f5774946aa3195ad51236fa8"
MII_SHA256 = "b0260b7f7d093788954660a8cdc3eda738673690604e7528db121c860c3905ae"


def bool_body(source, name):
    match = re.search(r"^static bool " + name + r"\([^;]+?\n\{", source, re.M)
    if not match:
        raise ValueError(name)
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end]


def main():
    if len(sys.argv) not in (4, 5) or len(sys.argv) == 5 and sys.argv[4] != "bcm5761":
        raise ValueError("broadcom-directory mii.h fresh-output [bcm5761]")
    bcm5761 = len(sys.argv) == 5
    source, mii, output = map(Path, sys.argv[1:4])
    root = Path(__file__).resolve().parents[4]
    if not output.resolve().is_relative_to(root / ".stela"):
        raise ValueError("output must remain in repository ignored .stela")
    texts = {}
    for name, digest in DONORS.items():
        raw = (source / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("changed original " + name)
        texts[name] = raw.decode()
    # The parent's Git-blob receipt supplies original mii.h provenance. Keep its
    # complete bytes and digest in this new immutable invocation's manifest.
    mii_raw = mii.read_bytes()
    if hashlib.sha256(mii_raw).hexdigest() != MII_SHA256:
        raise ValueError("changed original include/uapi/linux/mii.h")
    mii_names = {"MII_BMCR", "MII_ADVERTISE", "BMCR_PDOWN", "BMCR_ANENABLE", "BMCR_ANRESTART"}
    mii_macros = [line for line in mii_raw.decode().splitlines()
                  if re.match(r"#define\s+(\w+)", line)
                  and re.match(r"#define\s+(\w+)", line).group(1) in mii_names]
    if len(mii_macros) != len(mii_names):
        raise ValueError("missing original MII macros")
    phy_names = {"TG3_PHYFLG_KEEP_LINK_ON_PWRDN", "TG3_PHYFLG_PHY_SERDES", "TG3_PHYFLG_MII_SERDES", "TG3_PHYFLG_IS_FET"}
    phy_macros = [line for line in texts["tg3.h"].splitlines()
                  if re.match(r"#define\s+(\w+)", line)
                  and re.match(r"#define\s+(\w+)", line).group(1) in phy_names]
    if len(phy_macros) != len(phy_names):
        raise ValueError("missing original PHY flags")
    bodies = {
        "tg3_phy_auxctl_write": body(texts["tg3.c"], "tg3_phy_auxctl_write"),
        "tg3_phy_power_bug": bool_body(texts["tg3.c"], "tg3_phy_power_bug"),
        "tg3_phy_led_bug": bool_body(texts["tg3.c"], "tg3_phy_led_bug"),
        "tg3_power_down_phy": body(texts["tg3.c"], "tg3_power_down_phy"),
    }
    header = texts["tg3.h"].split("struct tg3_tx_buffer_desc {", 1)[0] + "\n#endif\n"
    wrapper = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint32_t u32;
#include "donor_constants.h"
#define tg3_asic_rev(tp) ((tp)->chip >> 12)
#define tg3_chip_rev(tp) ((tp)->chip >> 8)
struct tg3 {u32 chip, phy_flags, pci_fn;};
static int tg3_readphy(struct tg3 *tp,u32 at,u32 *v) {(void)tp;(void)at;(void)v;abort();}
static int tg3_writephy(struct tg3 *tp,u32 at,u32 value) {
 (void)tp;printf("W %u %u\n",at,value);return 0;
}
static void tg3_bmcr_reset(struct tg3 *tp) {(void)tp;abort();}
static u32 power_clock;
static u32 unexpected_read(u32 at) {
 if(at!=TG3_CPMU_LSPD_1000MB_CLK) abort(); return power_clock;
}
static void unexpected_write(u32 at,u32 v) {
 if(at!=TG3_CPMU_LSPD_1000MB_CLK) abort(); power_clock=v;
 printf("M %u %u\n",at,v);
}
#define tr32(at) unexpected_read(at)
#define tw32(at,v) unexpected_write(at,v)
#define tw32_f(at,v) unexpected_write(at,v)
#define udelay(us) ((void)(us))
'''
    wrapper += "\n" + "\n".join(mii_macros + phy_macros) + "\n"
    wrapper += "\n".join(bodies.values())
    if bcm5761:
        wrapper += r'''
int main(void) {
 const u32 clocks[]={0xa0000000,0x5a11000b,0x00110000};
 puts("TG3_PHY_POWER_5761_V1 3");
 for(unsigned c=0;c<3;c++) {
  struct tg3 tp={.chip=CHIPREV_5761_AX<<8,.phy_flags=0,.pci_fn=0};
  power_clock=clocks[c]; printf("CASE %u\n",power_clock);
  tg3_power_down_phy(&tp,true); puts("END");
 }
}
'''
    else:
        wrapper += r'''
int main(void) {
 const u32 chips[]={CHIPREV_ID_5720_A0,CHIPREV_ID_5762_A0};
 puts("TG3_PHY_POWER_V1 2");
 for(unsigned c=0;c<2;c++) {
  struct tg3 tp={.chip=chips[c],.phy_flags=0,.pci_fn=0};
  printf("CASE %u\n",tp.chip);
  tg3_power_down_phy(&tp,true); puts("END");
 }
}
'''
    output.mkdir(parents=True, exist_ok=False)
    (output / "donor_constants.h").write_text(header)
    (output / "mii.h").write_bytes(mii_raw)
    (output / "oracle.c").write_text(wrapper)
    exe = output / "oracle"
    compiler = Path(shutil.which("clang") or "clang").resolve(strict=True)
    command = [str(compiler), "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
               "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
               str(output / "oracle.c"), "-o", str(exe)]
    manifest = {
        "linux_pin": PIN, "donors": DONORS,
        "mii_sha256": hashlib.sha256(mii_raw).hexdigest(),
        "helper_sha256": {name: hashlib.sha256(raw.encode()).hexdigest() for name, raw in bodies.items()},
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "wrapper_sha256": hashlib.sha256(wrapper.encode()).hexdigest(),
        "compiler": str(compiler),
        "compiler_sha256": hashlib.sha256(compiler.read_bytes()).hexdigest(),
        "compiler_version": subprocess.run([str(compiler), "--version"], check=True,
                                            capture_output=True, timeout=15).stdout.decode(),
        "python": sys.executable, "cwd": str(Path.cwd()),
        "command": command, "cases": 3 if bcm5761 else 2,
        "profile": "BCM5761 A0 PLL-selection cases" if bcm5761 else "BCM5720/5762 A0 original mode",
        "scope": "unchanged PHY lowpower write selection only; no PCI power/ownership, real MDIO, DMA or physical proof",
        "rust_comparison": "UNRUN until coordinated Rust gate",
        "c_status": "admitted original inputs; compile pending",
    }
    def save():
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    save()
    try:
        compiled = subprocess.run(command, check=True, capture_output=True, timeout=60)
        (output / "compile-stdout.txt").write_bytes(compiled.stdout)
        (output / "compile-stderr.txt").write_bytes(compiled.stderr)
        manifest["executable_sha256"] = hashlib.sha256(exe.read_bytes()).hexdigest()
        manifest["c_status"] = "compiled; source execution pending"
        save()
        result = subprocess.run([str(exe)], check=True, capture_output=True, timeout=15)
        (output / "trace.txt").write_bytes(result.stdout)
        (output / "stderr.txt").write_bytes(result.stderr)
        manifest["trace_sha256"] = hashlib.sha256(result.stdout).hexdigest()
        manifest["c_status"] = "PASS original source cases under ASan/UBSan"
        save()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        (output / "failure-stdout.txt").write_bytes(error.stdout or b"")
        (output / "failure-stderr.txt").write_bytes(error.stderr or b"")
        manifest["c_status"] = "FAILED: " + str(error)
        save()
        raise
    print(result.stdout.decode(), end="")


if __name__ == "__main__":
    main()
