#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute unchanged original BCM5761 NVM/RCB/threshold/PHY/reset selections.

Arguments: bounded original broadcom directory, fresh ignored output directory.
This checks selected software effects, never physical hardware or PCI power.
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


def main():
    donor, output = map(Path, sys.argv[1:])
    root = Path(__file__).resolve().parents[4]
    if not output.resolve().is_relative_to(root / ".stela"):
        raise ValueError("output must remain in ignored repository .stela")
    texts = {}
    for name, digest in DONORS.items():
        raw = (donor / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("changed pinned original " + name)
        texts[name] = raw.decode()
    functions = {name: body(texts["tg3.c"], name) for name in [
        "tg3_get_5761_nvram_info", "tg3_tx_rcbs_disable",
        "tg3_rx_ret_rcbs_disable", "tg3_setup_rxbd_thresholds",
        "tg3_phy_auxctl_read", "tg3_phy_auxctl_write", "tg3_phy_toggle_auxctl_smdsp",
    ]}
    reset = body(texts["tg3.c"], "tg3_reset_hw")
    phy = body(texts["tg3.c"], "tg3_phy_reset")
    blocks = {
        "reserve": block(reset, "if (tg3_asic_rev(tp) == ASIC_REV_5761 ||\n\t    tg3_asic_rev(tp) == ASIC_REV_5784 ||"),
        "corruption": block(reset, "if (tg3_asic_rev(tp) == ASIC_REV_5719 ||\n\t    tg3_asic_rev(tp) == ASIC_REV_5720 ||\n\t    tg3_asic_rev(tp) == ASIC_REV_5762) {"),
        "clock": block(phy, "if (tg3_chip_rev(tp) == CHIPREV_5784_AX ||\n\t    tg3_chip_rev(tp) == CHIPREV_5761_AX) {"),
        "jitter": block(phy, "if (tp->phy_flags & TG3_PHYFLG_JITTER_BUG) {"),
    }
    # Complete contiguous source control selection, including its else branch.
    start = reset.index("if (tg3_asic_rev(tp) == ASIC_REV_5761)\n\t\ttw32(SNDDATAC_MODE,")
    end = reset.index("\n\tval = SNDBDI_MODE_ENABLE", start)
    blocks["engines"] = reset[start:end]
    header = texts["tg3.h"].split("struct tg3_tx_buffer_desc {", 1)[0] + "\n#endif\n"
    names = {"TG3_PHYFLG_JITTER_BUG", "TG3_PHYFLG_ADJUST_TRIM", "JEDEC_ATMEL", "JEDEC_ST",
             "TG3_NVRAM_SIZE_256KB", "TG3_NVRAM_SIZE_512KB", "TG3_NVRAM_SIZE_1MB", "TG3_NVRAM_SIZE_2MB"}
    macros = [line for line in texts["tg3.h"].splitlines()
              if re.match(r"#define\s+(\w+)", line)
              and re.match(r"#define\s+(\w+)", line).group(1) in names]
    if len(macros) != len(names):
        raise ValueError("missing original PHY flag definitions")
    wrapper = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint32_t u32;
#include "donor_constants.h"
struct tg3 {u32 chip,rx_std_max_post,rx_pending,rx_jumbo_pending;
 u32 nvram_jedecnum,nvram_pagesize,nvram_size,flags,phy_flags;};
#define tg3_asic_rev(tp) ((tp)->chip >> 12)
#define tg3_chip_rev(tp) ((tp)->chip >> 8)
#define tg3_chip_rev_id(tp) ((tp)->chip)
#define tg3_flag(tp,name) flag_##name(tp)
#define flag_5705_PLUS(tp) 1
#define flag_5717_PLUS(tp) 0
#define flag_57765_CLASS(tp) 0
#define flag_57765_PLUS(tp) 0
#define flag_5750_PLUS(tp) 1
#define flag_5780_CLASS(tp) 0
#define flag_JUMBO_CAPABLE(tp) 0
#define flag_LRG_PROD_RING_CAP(tp) 0
#define flag_HW_TSO_1(tp) 0
#define flag_HW_TSO_2(tp) 1
#define flag_HW_TSO_3(tp) 0
enum { NVRAM_BUFFERED=1, FLASH=2, NO_NVRAM_ADDR_TRANS=4, PROTECTED_NVRAM=8 };
#define tg3_flag_set(tp,name) ((tp)->flags |= name)
#define min(a,b) ((a)<(b)?(a):(b))
#define max_t(type,a,b) ((type)(a)>(type)(b)?(type)(a):(type)(b))
#define udelay(us) ((void)(us))
static u32 regs[0x8000/4],aux[8],selector;
static u32 read_reg(u32 at) {if(at>=0x8000 || at%4) abort(); return regs[at/4];}
static void write_reg(u32 at,u32 value) {
 if(at>=0x8000 || at%4) abort(); regs[at/4]=value;
 printf("M %08x %08x\n",at,value);
}
#define tr32(at) read_reg(at)
#define tw32(at,value) write_reg(at,value)
#define tw32_f(at,value) write_reg(at,value)
static void tg3_write_mem(struct tg3 *tp,u32 at,u32 value) {
 (void)tp;printf("S %08x %08x\n",at,value);
}
static int tg3_readphy(struct tg3 *tp,u32 at,u32 *v) {
 (void)tp; if(at!=0x18) abort(); *v=aux[selector]; return 0;
}
static int tg3_writephy(struct tg3 *tp,u32 at,u32 value) {
 (void)tp; printf("W %08x %08x\n",at,value);
 if(at==0x18) {
  if((value&0x8007)==7) selector=(value>>12)&7;
  else aux[value&7]=value&~0x8007;
 }
 return 0;
}
'''
    wrapper += "\n" + "\n".join(macros) + "\n" + "\n".join(functions.values())
    wrapper += "\nstatic void selected(struct tg3 *tp) {u32 val;\n"
    wrapper += "\n".join(blocks.values()) + "\n}\n"
    wrapper += r'''
int main(void) {
 const u32 initial[]={0,0xfffffffe,0x93dba951,0x01230840,0x280c0c04,0xffeffff0,0x0010000b,0x55555555};
 const u32 clocks[]={0xa0110000,0x5a000000};
 const u32 straps[]={0x00800003,0x00800000,0x00800002,0x00800001,
  0x00000003,0x00000000,0x00000002,0x00000001,
  0x02800001,0x02800000,0x02800002,0x02800003,
  0x02000001,0x02000000,0x02000002,0x02000003};
 for(unsigned s=0;s<16;s++) for(unsigned c=0;c<2;c++) {
  struct tg3 tp={.chip=CHIPREV_5761_AX<<8,.rx_std_max_post=511,.rx_pending=511,
   .rx_jumbo_pending=100,.phy_flags=TG3_PHYFLG_JITTER_BUG};
  for(unsigned i=0;i<sizeof(regs)/sizeof(regs[0]);i++) regs[i]=0;
  for(unsigned i=0;i<8;i++) aux[i]=0; selector=0;
  regs[NVRAM_CFG1/4]=straps[s]|0x80000000;
  regs[TG3_RDMA_RSRVCTRL_REG/4]=initial[s%8];
  regs[TG3_CPMU_LSPD_1000MB_CLK/4]=clocks[c];
  printf("CASE %08x %08x %08x\n",straps[s],initial[s%8],clocks[c]);
  tg3_get_5761_nvram_info(&tp);
  printf("N %08x %08x %08x %08x\n",tp.nvram_pagesize,tp.nvram_jedecnum,tp.nvram_size,tp.flags);
  tg3_tx_rcbs_disable(&tp);tg3_rx_ret_rcbs_disable(&tp);
  tg3_setup_rxbd_thresholds(&tp);selected(&tp);puts("END");
 }
}
'''
    output.mkdir(parents=True, exist_ok=False)
    (output / "donor_constants.h").write_text(header)
    (output / "oracle.c").write_text(wrapper)
    exe = output / "oracle"
    compiler = Path(shutil.which("clang") or "clang").resolve(strict=True)
    command = [str(compiler), "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
               "-Wno-unused-parameter", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
               str(output / "oracle.c"), "-o", str(exe)]
    manifest = {
        "linux_pin": PIN, "donors": DONORS,
        "unchanged_sections": {n: hashlib.sha256(v.encode()).hexdigest() for n, v in dict(functions, **blocks).items()},
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "wrapper_sha256": hashlib.sha256(wrapper.encode()).hexdigest(),
        "compiler": str(compiler),
        "compiler_sha256": hashlib.sha256(compiler.read_bytes()).hexdigest(),
        "compiler_version": subprocess.run([str(compiler), "--version"], check=True,
                                            capture_output=True, timeout=15).stdout.decode(),
        "python": sys.executable, "cwd": str(Path.cwd()),
        "command": command, "cases": 32,
        "scope": "selected unchanged source NVM/RCB/threshold/PHY/reset effects; no whole-driver, native ownership, PM or hardware proof",
        "rust_comparison": "UNRUN until coordinated emitted-binary gate",
        "c_status": "admitted original inputs; compile pending",
    }
    def save():
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    save()
    try:
        compile_result = subprocess.run(command, check=True, capture_output=True, timeout=60)
        (output / "compile-stdout.txt").write_bytes(compile_result.stdout)
        (output / "compile-stderr.txt").write_bytes(compile_result.stderr)
        manifest["executable_sha256"] = hashlib.sha256(exe.read_bytes()).hexdigest()
        manifest["c_status"] = "compiled; source execution pending"
        save()
        result = subprocess.run([str(exe)], check=True, capture_output=True, timeout=15)
        (output / "trace.txt").write_bytes(result.stdout)
        (output / "stderr.txt").write_bytes(result.stderr)
        manifest["trace_sha256"] = hashlib.sha256(result.stdout).hexdigest()
        manifest["c_status"] = "PASS 32 selected source cases under ASan/UBSan"
        save()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        (output / "failure-stdout.txt").write_bytes(error.stdout or b"")
        (output / "failure-stderr.txt").write_bytes(error.stderr or b"")
        manifest["c_status"] = "FAILED: " + str(error)
        save()
        raise
    print("PASS 32 original-source cases under ASan/UBSan")


if __name__ == "__main__":
    main()
