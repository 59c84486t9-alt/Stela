#!/usr/bin/env python3
"""UNRUN original-Linux 5720/5762 packet-setup comparison, no hardware.

Extract complete original RCB-disable/RX-threshold helpers and two unchanged
whole reset_hw blocks. The wrapper supplies actual observed initial register
words and flags for the admitted profiles; no translated implementation is an
oracle. Arguments: unchanged tg3.c/h directory, fresh ignored output directory.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from tg3_transport_oracle import DONORS, PIN, body


def block(source, anchor):
    start = source.index(anchor)
    opening = source.index("{", start)
    end, depth = opening + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def main():
    donor, output = map(Path, sys.argv[1:])
    texts = {}
    for name, digest in DONORS.items():
        raw = (donor / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("changed pinned donor " + name)
        texts[name] = raw.decode()
    functions = {name: body(texts["tg3.c"], name) for name in [
        "tg3_tx_rcbs_disable", "tg3_rx_ret_rcbs_disable", "tg3_setup_rxbd_thresholds"]}
    reset = body(texts["tg3.c"], "tg3_reset_hw")
    blocks = {
        "reserve": block(reset, "if (tg3_asic_rev(tp) == ASIC_REV_5761 ||\n\t    tg3_asic_rev(tp) == ASIC_REV_5784 ||"),
        "corruption": block(reset, "if (tg3_asic_rev(tp) == ASIC_REV_5719 ||\n\t    tg3_asic_rev(tp) == ASIC_REV_5720 ||\n\t    tg3_asic_rev(tp) == ASIC_REV_5762) {")}
    header = texts["tg3.h"].split("struct tg3_tx_buffer_desc {", 1)[0] + "\n#endif\n"
    wrapper = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint32_t u32;
#include "donor_constants.h"
struct tg3 {u32 chip,rx_std_max_post,rx_pending,rx_jumbo_pending;};
#define tg3_asic_rev(tp) ((tp)->chip >> 12)
#define tg3_chip_rev_id(tp) ((tp)->chip)
#define tg3_flag(tp,name) flag_##name(tp)
#define flag_5705_PLUS(tp) 1
#define flag_5717_PLUS(tp) (tg3_asic_rev(tp)==ASIC_REV_5720)
#define flag_57765_CLASS(tp) 0
#define flag_57765_PLUS(tp) 1
#define flag_5750_PLUS(tp) 1
#define flag_5780_CLASS(tp) 0
#define flag_JUMBO_CAPABLE(tp) 1
#define min(a,b) ((a)<(b)?(a):(b))
#define max_t(type,a,b) ((type)(a)>(type)(b)?(type)(a):(type)(b))
static u32 regs[0x8000/4];
static u32 read_reg(u32 at) {if(at>=0x8000 || at%4) abort(); return regs[at/4];}
static void write_reg(u32 at,u32 value) {
 if(at>=0x8000 || at%4) abort(); regs[at/4]=value;
 printf("M %08x %08x\n",at,value);
}
#define tr32(at) read_reg(at)
#define tw32(at,value) write_reg(at,value)
static void tg3_write_mem(struct tg3 *tp,u32 at,u32 value) {
 (void)tp;printf("S %08x %08x\n",at,value);
}
'''
    wrapper += "\n".join(functions.values())
    wrapper += "\nstatic void reset_selected(struct tg3 *tp) {u32 val;\n" + "\n".join(blocks.values()) + "\n}\n"
    wrapper += r'''
int main(void) {
 const u32 chips[]={CHIPREV_ID_5720_A0,CHIPREV_ID_5762_A0};
 const u32 initial[]={0,0xfffffffe,0x93dba951,0x01230840,0x280c0c04,0xffeffff0,0x0010000b,0x55555555};
 const u32 lso[]={0,0x00100080};
 for(unsigned c=0;c<2;c++) for(unsigned r=0;r<8;r++) for(unsigned l=0;l<2;l++) {
  struct tg3 tp={.chip=chips[c],.rx_std_max_post=2047,.rx_pending=2047,.rx_jumbo_pending=100};
  for(unsigned i=0;i<sizeof(regs)/sizeof(regs[0]);i++) regs[i]=0;
  regs[TG3_RDMA_RSRVCTRL_REG/4]=initial[r];regs[TG3_RDMA_RSRVCTRL_REG2/4]=initial[r];
  regs[TG3_LSO_RD_DMA_CRPTEN_CTRL/4]=lso[l];regs[TG3_LSO_RD_DMA_CRPTEN_CTRL2/4]=lso[l];
  printf("CASE %08x %08x %08x\n",chips[c],initial[r],lso[l]);
  tg3_tx_rcbs_disable(&tp);tg3_rx_ret_rcbs_disable(&tp);
  tg3_setup_rxbd_thresholds(&tp);reset_selected(&tp);puts("END");
 }
 return 0;
}
'''
    output.mkdir(parents=True, exist_ok=False)
    (output / "donor_constants.h").write_text(header)
    (output / "oracle.c").write_text(wrapper)
    # Future finite gate must bind compiler/SDK/process ownership separately.
    subprocess.run(["clang", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                    "-Wno-unused-parameter", "-fsanitize=address,undefined",
                    str(output / "oracle.c"), "-o", str(output / "oracle")], check=True)
    with (output / "trace.txt").open("wb") as destination:
        subprocess.run([str(output / "oracle")], stdout=destination, check=True)
    evidence = {"scope": "selected original packet setup only; no hardware/firmware/whole-driver claim",
                "pin": PIN, "donors": DONORS, "cases": 32,
                "unchanged_sections": {name: hashlib.sha256(value.encode()).hexdigest()
                                       for name, value in dict(functions, **blocks).items()}}
    (output / "source.json").write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
