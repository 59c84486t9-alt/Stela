#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute the complete unchanged tg3_reset_hw RDMAC mode selection.

Arguments: bounded original broadcom directory, original if_ether.h, fresh output.
Only the three admitted ASIC flag sets are modeled. No packet/offload or native
ownership/hardware qualification follows from this scalar source comparison.
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
ETHER_SHA256 = "3b8e80de0d836b872edf92a63e1c9cf3db0a6faf65637c56fb3210ce0afc895b"


def main():
    donor, ether, output = map(Path, sys.argv[1:])
    root = Path(__file__).resolve().parents[4]
    if not output.resolve().is_relative_to(root / ".stela"):
        raise ValueError("output must remain in ignored repository .stela")
    texts = {}
    for name, digest in DONORS.items():
        raw = (donor / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("changed pinned original " + name)
        texts[name] = raw.decode()
    ether_raw = ether.read_bytes()
    if hashlib.sha256(ether_raw).hexdigest() != ETHER_SHA256:
        raise ValueError("changed original include/uapi/linux/if_ether.h")
    ether_macro = re.search(r"^#define ETH_DATA_LEN\s+[^\n]+", ether_raw.decode(), re.M)
    if not ether_macro:
        raise ValueError("missing original Ethernet payload length")
    reset = body(texts["tg3.c"], "tg3_reset_hw")
    start = reset.index("rdmac_mode = (RDMAC_MODE_ENABLE")
    end = reset.index("if (tg3_asic_rev(tp) == ASIC_REV_5761 ||", start)
    selection = reset[start:end]
    publish = next(line for line in reset.splitlines()
                   if line.strip() == "tw32_f(RDMAC_MODE, rdmac_mode);")
    macro = re.search(r"^#define TG3_TX_BD_DMA_MAX_2K\s+[^\n]+", texts["tg3.c"], re.M)
    if not macro:
        raise ValueError("missing original DMA limit definition")
    header = texts["tg3.h"].split("struct tg3_tx_buffer_desc {", 1)[0] + "\n#endif\n"
    wrapper = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint32_t u32;
#include "donor_constants.h"
struct net_device {u32 mtu;};
struct tg3 {u32 chip,dma_limit;struct net_device *dev;};
#define tg3_asic_rev(tp) ((tp)->chip >> 12)
#define tg3_chip_rev_id(tp) ((tp)->chip)
#define tg3_flag(tp,name) flag_##name(tp)
#define flag_TSO_CAPABLE(tp) 0
#define flag_IS_5788(tp) 0
#define flag_PCI_EXPRESS(tp) 1
#define flag_HW_TSO_1(tp) 0
#define flag_HW_TSO_2(tp) (tg3_asic_rev(tp)==ASIC_REV_5761)
#define flag_HW_TSO_3(tp) (tg3_asic_rev(tp)!=ASIC_REV_5761)
#define flag_57765_PLUS(tp) (tg3_asic_rev(tp)!=ASIC_REV_5761)
static u32 initial;
static u32 read_reg(u32 at) {if(at!=RDMAC_MODE) abort(); return initial;}
static void write_reg(u32 at,u32 value) {
 if(at!=RDMAC_MODE) abort(); printf("M %08x %08x\n",at,value);
}
#define tr32(at) read_reg(at)
#define tw32_f(at,value) write_reg(at,value)
'''
    wrapper += "\n" + macro.group() + "\n" + ether_macro.group() + "\n"
    wrapper += "static void selected(struct tg3 *tp) {u32 rdmac_mode;\n" + selection + publish + "\n}\n"
    wrapper += r'''
int main(void) {
 const u32 chips[]={CHIPREV_ID_5720_A0,CHIPREV_5761_AX<<8,CHIPREV_ID_5762_A0};
 const u32 inputs[]={0,0x01230840,0x89abcdec,0x3ffffffc};
 struct net_device dev={.mtu=ETH_DATA_LEN};
 puts("TG3_RDMA_MODE_V1 12");
 for(unsigned c=0;c<3;c++) for(unsigned i=0;i<4;i++) {
  struct tg3 tp={.chip=chips[c],.dev=&dev};initial=inputs[i];
  printf("CASE %08x %08x\n",tp.chip,initial);selected(&tp);puts("END");
 }
}
'''
    output.mkdir(parents=True, exist_ok=False)
    (output / "donor_constants.h").write_text(header)
    (output / "oracle.c").write_text(wrapper)
    (output / "if_ether.h").write_bytes(ether_raw)
    compiler = Path(shutil.which("clang") or "clang").resolve(strict=True)
    exe = output / "oracle"
    command = [str(compiler), "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
               "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
               str(output / "oracle.c"), "-o", str(exe)]
    manifest = {
        "linux_pin": PIN, "donors": DONORS, "ether_sha256": ETHER_SHA256,
        "selection_sha256": hashlib.sha256(selection.encode()).hexdigest(),
        "publication_sha256": hashlib.sha256(publish.encode()).hexdigest(),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "wrapper_sha256": hashlib.sha256(wrapper.encode()).hexdigest(),
        "compiler": str(compiler), "compiler_sha256": hashlib.sha256(compiler.read_bytes()).hexdigest(),
        "compiler_version": subprocess.run([str(compiler), "--version"], check=True,
                                            capture_output=True, timeout=15).stdout.decode(),
        "python": sys.executable, "cwd": str(Path.cwd()), "command": command, "cases": 12,
        "scope": "complete original RDMAC mode selection for three declared ASICs only; no TSO/packet/ownership/hardware claim",
        "rust_comparison": "UNRUN until coordinated emitted-binary gate",
        "c_status": "original input admission; compilation pending",
    }
    def save():
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    save()
    try:
        compiled = subprocess.run(command, check=True, capture_output=True, timeout=60)
        (output / "compile-stdout.txt").write_bytes(compiled.stdout)
        (output / "compile-stderr.txt").write_bytes(compiled.stderr)
        manifest["executable_sha256"] = hashlib.sha256(exe.read_bytes()).hexdigest()
        manifest["c_status"] = "compiled; execution pending"
        save()
        result = subprocess.run([str(exe)], check=True, capture_output=True, timeout=15)
        (output / "trace.txt").write_bytes(result.stdout)
        (output / "stderr.txt").write_bytes(result.stderr)
        manifest["trace_sha256"] = hashlib.sha256(result.stdout).hexdigest()
        manifest["c_status"] = "PASS12 original cases under ASan/UBSan"
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
