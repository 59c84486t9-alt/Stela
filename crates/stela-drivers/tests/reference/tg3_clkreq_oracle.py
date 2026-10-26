#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Original tg3 CLKREQ flag derivation and complete negotiated-speed policy.

Arguments: verified bounded original Linux root, fresh ignored output directory.
Source callbacks model exact endpoint WORD RMW; no platform/ASPM authority follows.
"""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

from tg3_transport_oracle import DONORS, body
from tg3_bcm5762_packet_oracle import block

PIN = "cc9de5d4b5ab6459f5774946aa3195ad51236fa8"
HEADERS = {
    "include/uapi/linux/pci_regs.h": "51d2a1344da2a56e913e9d69b3b5d90eaaf4fb0bf96e672a5674ea819182c69b",
    "include/uapi/linux/ethtool.h": "4c79ad8d7c4c06aa85cc9f13fc88a165711b5986ca779ca8b9ee284717faa998",
}


def main():
    original, output = map(Path, sys.argv[1:])
    root = Path(__file__).resolve().parents[4]
    if not output.resolve().is_relative_to(root / ".stela"):
        raise ValueError("output must remain in repository ignored .stela")
    paths = {"drivers/net/ethernet/broadcom/" + name: digest for name, digest in DONORS.items()}
    paths.update(HEADERS)
    texts = {}
    for name, digest in paths.items():
        raw = (original / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("changed pinned original " + name)
        texts[name] = raw.decode()
    source = texts["drivers/net/ethernet/broadcom/tg3.c"]
    setup = body(source, "tg3_setup_copper_phy")
    policy = block(setup, "if (tg3_flag(tp, CLKREQ_BUG)) {")
    invariants = body(source, "tg3_get_invariants")
    flag = block(invariants, "if (lnkctl & PCI_EXP_LNKCTL_CLKREQ_EN) {")
    # Include the complete following else-if clause, rather than clipping its body.
    start = invariants.index(flag)
    finish = start + len(flag)
    suffix = invariants[finish:]
    tail = block(suffix, "else if (tg3_chip_rev_id(tp) == CHIPREV_ID_5717_A0)")
    flag = invariants[start:finish + suffix.index(tail) + len(tail)]
    header = texts["drivers/net/ethernet/broadcom/tg3.h"].split("struct tg3_tx_buffer_desc {", 1)[0] + "\n#endif\n"
    macros = []
    for path, names in [
        ("include/uapi/linux/pci_regs.h", ["PCI_EXP_LNKCTL", "PCI_EXP_LNKCTL_CLKREQ_EN"]),
        ("include/uapi/linux/ethtool.h", ["SPEED_10", "SPEED_100", "SPEED_1000"]),
    ]:
        for name in names:
            match = re.search(r"^#define\s+" + name + r"\s+[^\n]+", texts[path], re.M)
            if not match:
                raise ValueError("missing original macro " + name)
            macros.append(match.group())
    wrapper = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint32_t u32;
typedef uint16_t u16;
#include "donor_constants.h"
struct tg3 {u32 chip,flags;struct tg3 *pdev;struct {u32 active_speed;} link_config;u16 link;unsigned writes;};
#define tg3_asic_rev(tp) ((tp)->chip >> 12)
#define tg3_chip_rev_id(tp) ((tp)->chip)
#define flag_CLKREQ_BUG 1
#define flag_HW_TSO_2 2
#define flag_TSO_CAPABLE 4
#define flag_L1PLLPD_EN 8
#define tg3_flag(tp,name) ((tp)->flags & flag_##name)
#define tg3_flag_set(tp,name) ((tp)->flags |= flag_##name)
#define tg3_flag_clear(tp,name) ((tp)->flags &= ~flag_##name)
'''
    wrapper += "\n" + "\n".join(macros) + "\n"
    wrapper += r'''
static void pcie_capability_clear_word(struct tg3 *pdev,unsigned at,u16 bits) {
 if(at!=PCI_EXP_LNKCTL) abort(); pdev->link &= ~bits; pdev->writes++;
}
static void pcie_capability_set_word(struct tg3 *pdev,unsigned at,u16 bits) {
 if(at!=PCI_EXP_LNKCTL) abort(); pdev->link |= bits; pdev->writes++;
}
'''
    wrapper += "static void derive(struct tg3 *tp) {u16 lnkctl=tp->link;\n" + flag + "\n}\n"
    wrapper += "static void selected(struct tg3 *tp) {\n" + policy + "\n}\n"
    wrapper += r'''
int main(void) {
 const u32 chips[]={CHIPREV_ID_5720_A0,CHIPREV_5761_AX<<8,CHIPREV_ID_5762_A0};
 const u16 initial[]={0x0100,0x0343,0,0x0243};
 const u32 speeds[]={SPEED_10,SPEED_100,SPEED_1000};
 puts("TG3_CLKREQ_V1 36");
 for(unsigned c=0;c<3;c++) for(unsigned i=0;i<4;i++) for(unsigned s=0;s<3;s++) {
  struct tg3 tp={.chip=chips[c],.link=initial[i],.link_config={.active_speed=speeds[s]}};tp.pdev=&tp;
  derive(&tp);selected(&tp);
  printf("CASE %08x %04x %u %u %04x %u\n",tp.chip,initial[i],speeds[s],!!(tp.flags&flag_CLKREQ_BUG),tp.link,tp.writes);
 }
}
'''
    output.mkdir(parents=True, exist_ok=False)
    (output / "donor_constants.h").write_text(header)
    (output / "oracle.c").write_text(wrapper)
    compiler = Path(shutil.which("clang") or "clang").resolve(strict=True)
    executable = output / "oracle"
    command = [str(compiler), "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
               "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(output / "oracle.c"), "-o", str(executable)]
    manifest = {
        "linux_pin": PIN, "sources": paths, "cases": 36,
        "flag_sha256": hashlib.sha256(flag.encode()).hexdigest(),
        "policy_sha256": hashlib.sha256(policy.encode()).hexdigest(),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "wrapper_sha256": hashlib.sha256(wrapper.encode()).hexdigest(),
        "compiler": str(compiler), "compiler_sha256": hashlib.sha256(compiler.read_bytes()).hexdigest(),
        "compiler_version": subprocess.run([str(compiler), "--version"], capture_output=True, check=True, timeout=15).stdout.decode(),
        "python": sys.executable, "cwd": str(Path.cwd()), "command": command,
        "scope": "Complete unchanged flag and per-speed endpoint CLKREQ WORD policy only; no whole PHY/platform/ASPM/hardware claim",
        "status": "Original input admission; compilation pending",
    }
    def save():
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    save()
    try:
        compiled = subprocess.run(command, capture_output=True, check=True, timeout=60)
        (output / "compile-stdout.txt").write_bytes(compiled.stdout)
        (output / "compile-stderr.txt").write_bytes(compiled.stderr)
        manifest["executable_sha256"] = hashlib.sha256(executable.read_bytes()).hexdigest()
        manifest["status"] = "Compiled; execution pending"
        save()
        result = subprocess.run([str(executable)], capture_output=True, check=True, timeout=15)
        (output / "trace.txt").write_bytes(result.stdout)
        (output / "stderr.txt").write_bytes(result.stderr)
        manifest["trace_sha256"] = hashlib.sha256(result.stdout).hexdigest()
        manifest["status"] = "PASS36 unchanged cases under ASan/UBSan"
        save()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        (output / "failure-stdout.txt").write_bytes(error.stdout or b"")
        (output / "failure-stderr.txt").write_bytes(error.stderr or b"")
        manifest["status"] = "FAILED: " + str(error)
        save()
        raise
    print(result.stdout.decode(), end="")


if __name__ == "__main__":
    main()
