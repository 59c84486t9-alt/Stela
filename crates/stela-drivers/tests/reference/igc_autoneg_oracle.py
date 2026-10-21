#!/usr/bin/env python3
"""Execute unchanged pinned Linux igc advertisement code, without a kernel.

Supply the ignored Linux source directory and an ignored output directory.
The callback models register storage only; the actual donor chooses every
advertisement bit. No device, electrical link or complete Linux init is run.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

PIN = "a804c5742bff224d4cb4d25dd383554d598be32b"
DONORS = {'igc_phy.c': 'd7b4134d93906a0d3d1694166930d1802359858322958b59f174805b4a846fc6', 'igc_defines.h': '685c087a1bc8f392c8374fef3d7e8fccf26dc7ac80f375163f5e74e1c871596a', 'igc_regs.h': '68ae816aea172fe45854db679758fef106c032757ba73af7691f0ee794da6609'}


def body(source, name):
    match = re.search(r"^static s32 " + name + r"\([^;]+?\n\{", source, re.M)
    if not match:
        raise ValueError(name)
    end = match.end()
    level = 1
    while level:
        level += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end]


source, output = map(Path, sys.argv[1:])
manifest = json.loads((source / "manifest.json").read_text())
assert manifest["linux_commit"] == PIN
for item in manifest["sources"]:
    assert hashlib.sha256((source / item["path"]).read_bytes()).hexdigest() == item["sha256"]
for name, digest in DONORS.items():
    assert hashlib.sha256((source / name).read_bytes()).hexdigest() == digest
donor = body((source / "igc_phy.c").read_text(), "igc_phy_setup_autoneg")
output.mkdir(parents=True, exist_ok=True)
(output / "linux").mkdir(exist_ok=True)
# This helper uses no bitfield operations; leave its kernel-only include
# empty rather than changing any donor header bytes.
(output / "linux" / "bitfield.h").write_text("/* Unused by the selected donor helper. */\n")
wrapper = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int32_t s32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U << (l)) & (~0U >> (31-(h))))
#define hw_dbg(...) ((void)0)
#include "igc_defines.h"
enum { igc_fc_none, igc_fc_rx_pause, igc_fc_tx_pause, igc_fc_full };
struct igc_hw;
struct ops {
 s32 (*read_reg)(struct igc_hw *,u32,u16*);
 s32 (*write_reg)(struct igc_hw *,u32,u16);
};
struct igc_phy_info { struct ops ops; u16 autoneg_mask,autoneg_advertised; };
struct igc_hw {
 struct igc_phy_info phy;
 struct { int current_mode; } fc;
 u16 registers[3];
};
static unsigned index_of(u32 reg) {
 switch (reg) {
 case PHY_AUTONEG_ADV: return 0;
 case PHY_1000T_CTRL: return 1;
 case (STANDARD_AN_REG_MASK<<MMD_DEVADDR_SHIFT)|IGC_ANEG_MULTIGBT_AN_CTRL: return 2;
 default: abort();
 }
}
static s32 read_reg(struct igc_hw*h,u32 r,u16*v){*v=h->registers[index_of(r)];return 0;}
static s32 write_reg(struct igc_hw*h,u32 r,u16 v){h->registers[index_of(r)]=v;return 0;}
'''
# The register macro is in igc_regs.h, whose other macros are not needed.
wrapper += "#include \"igc_regs.h\"\n" + donor + r'''
int main(void) {
 unsigned seed=0x9125843;
 for(unsigned i=0;i<4096;i++) {
  struct igc_hw h={0};
  u16 input[3];
  h.phy.ops.read_reg=read_reg; h.phy.ops.write_reg=write_reg;
  h.phy.autoneg_mask=AUTONEG_ADVERTISE_SPEED_DEFAULT_2500;
  h.phy.autoneg_advertised=AUTONEG_ADVERTISE_SPEED_DEFAULT_2500;
  h.fc.current_mode=igc_fc_none;
  for(unsigned n=0;n<3;n++) {seed=seed*1664525U+1013904223U; input[n]=h.registers[n]=seed>>16;}
  if(igc_phy_setup_autoneg(&h)) abort();
  printf("%04x %04x %04x %04x %04x %04x\n",input[0],input[1],input[2],h.registers[0],h.registers[1],h.registers[2]);
 }
}
'''
# index_of uses the register macro before the function is defined.
wrapper = wrapper.replace('#include "igc_defines.h"', '#include "igc_defines.h"\n#include "igc_regs.h"')
c = output / "oracle.c"
c.write_text(wrapper)
binary = output / "oracle"
subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-g", "-fsanitize=address,undefined", "-I", str(source.resolve()), "-I", str(output.resolve()), str(c), "-o", str(binary)], check=True)
trace = subprocess.check_output([str(binary.resolve())])
(output / "trace.txt").write_bytes(trace)
(output / "manifest.json").write_text(json.dumps({
    "linux_commit": PIN,
    "donor_function_sha256": hashlib.sha256(donor.encode()).hexdigest(),
    "wrapper_sha256": hashlib.sha256(c.read_bytes()).hexdigest(),
    "trace_sha256": hashlib.sha256(trace).hexdigest(),
    "cases": 4096,
    "scope": "unchanged igc_phy_setup_autoneg, actual source constants; modeled callbacks; fc_none/default2500",
}, indent=2) + "\n")
print(hashlib.sha256(trace).hexdigest())
