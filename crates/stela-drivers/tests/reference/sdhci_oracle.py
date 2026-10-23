#!/usr/bin/env python3
"""Execute unchanged pinned Linux SDHCI clock and SD-CSD decoder functions.

Usage: sdhci_oracle.py FLAT_OR_NESTED_DONOR_DIRECTORY FRESH_OUTPUT_DIRECTORY
Baseline clock profile disables programmable/preset/vendor quirks. Synthetic
cards only exercise accepted SDSC/SDHC fields. This does not execute Linux I/O.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
paths = {
    "drivers/mmc/host/sdhci.c": "186305e102bd32df419ff80669e6018d6b3a9e4310c3101193413970355b9857",
    "drivers/mmc/host/sdhci.h": "4b3a252cecc039b22e56c37ec95ad2959bee52934594666708c4a7f118afe4af",
    "drivers/mmc/core/sd.c": "58b3dcdf23327edbb7c8f1c4a4c10654b2ac20b1c1a921a6f6ec6b17d1d69fd7",
}
manifest = json.loads((source / "source.json").read_text())
assert manifest["revision"] == "a804c5742bff224d4cb4d25dd383554d598be32b"
pinned = {item["path"]: item["sha256"] for item in manifest["files"]}
texts = {}
for path in paths:
    raw = (source / path).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == paths[path] == pinned[path], path
    texts[path] = raw.decode()
out.mkdir(parents=True, exist_ok=False)
fragments = []

def function(path, name):
    raw = texts[path]
    match = re.search(r"^(?:static )?(?:u16|int) " + name + r"\([^;{}]*\)\n\{", raw, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (raw[at] == "{") - (raw[at] == "}")
        at += 1
    body = raw[match.start():at]
    fragments.append(dict(path=path, name=name, start=match.start(), end=at,
                          sha256=hashlib.sha256(body.encode()).hexdigest()))
    return body

clock = function("drivers/mmc/host/sdhci.c", "sdhci_calc_clk")
sd = function("drivers/mmc/core/sd.c", "mmc_decode_csd")
fields = sorted(set(re.findall(r"csd->(\w+)", sd)))
macros = []
for name in sorted(set(re.findall(r"\bSDHCI_[A-Z0-9_]+\b", clock)) - {"SDHCI_QUIRK2_CLOCK_DIV_ZERO_BROKEN"}):
    match = re.search(r"^#define\s+" + name + r"\s+(.+)$", texts["drivers/mmc/host/sdhci.h"], re.M)
    assert match, name
    macros.append("#define " + name + " " + match[1])
c = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t sector_t;
#define FIELD_GET(mask, value) (((value)&(mask)) >> __builtin_ctz(mask))
#define GENMASK(hi,lo) (((~0U) << (lo)) & ((~0U) >> (31-(hi))))
#define BIT(n) (1U << (n))
#define max_t(type,a,b) ((type)(a) > (type)(b) ? (type)(a) : (type)(b))
#define SDHCI_QUIRK2_CLOCK_DIV_ZERO_BROKEN 1
#define pr_err(...) ((void)0)
struct sdhci_host {unsigned version, max_clk, clk_mul, quirks2; bool preset_enabled;};
static u16 sdhci_readw(struct sdhci_host *h,int at) {(void)h;(void)at;return 0;}
static u16 sdhci_get_preset_value(struct sdhci_host *h) {(void)h;return 0;}
static const unsigned tran_exp[]={10000,100000,1000000,10000000,0,0,0,0};
static const unsigned tran_mant[]={0,10,12,13,15,20,25,30,35,40,45,50,55,60,70,80};
static const unsigned taac_exp[]={1,10,100,1000,10000,100000,1000000,10000000};
static const unsigned taac_mant[]={0,10,12,13,15,20,25,30,35,40,45,50,55,60,70,80};
static uint32_t unstuff_bits(const uint32_t words[4],unsigned start,unsigned size) {
 unsigned n=3-start/32,shift=start%32;
 uint64_t value=(uint64_t)words[n]>>shift;
 if(shift+size>32)value|=(uint64_t)words[n-1]<<(32-shift);
 return value&((1ULL<<size)-1);
}
'''
c += "\n".join(macros)
c += "\nstruct mmc_csd {" + "".join("uint64_t " + name + ";" for name in fields) + "};\n"
c += "struct mmc_card {struct mmc_csd csd;u32 raw_csd[4];unsigned erase_size,flags;};\n"
c += "\n".join("#define mmc_card_set_" + name + "(card) ((card)->flags |= " + str(1 << bit) + ")" for bit, name in enumerate(["readonly", "blockaddr", "ult_capacity", "ext_capacity"]))
c += "\n" + clock + "\n" + sd + r'''
static void put(u32 out[4],unsigned start,unsigned count,u32 value) {
 unsigned n=3-start/32,shift=start%32;
 uint64_t mask=(1ULL<<count)-1;
 out[n]=(out[n]&~(u32)(mask<<shift))|(value<<shift);
 if(shift+count>32)out[n-1]=(out[n-1]&~(u32)(mask>>(32-shift)))|(value>>(32-shift));
}
int main(void) {
 const unsigned bases[]={1000000,25000000,50000000,100000000,255000000};
 const unsigned requested[]={100000,400000,20000000,25000000,50000000,52000000};
 for(unsigned v=0;v<6;v++)for(unsigned b=0;b<5;b++)for(unsigned r=0;r<6;r++) {
  struct sdhci_host h={.version=v,.max_clk=bases[b]};unsigned actual=0;
  u16 field=sdhci_calc_clk(&h,requested[r],&actual);
  printf("C %u %u %u %u %u\n",v,bases[b],requested[r],field,actual);
 }
 for(unsigned structure=0;structure<2;structure++)for(unsigned size=0;size<128;size++)for(unsigned blk=9;blk<12;blk++) {
  struct mmc_card card={0};put(card.raw_csd,126,2,structure);put(card.raw_csd,96,8,0x32);
  put(card.raw_csd,84,12,0x414);put(card.raw_csd,80,4,blk);put(card.raw_csd,22,4,blk);
  if(structure==0){put(card.raw_csd,62,12,size);put(card.raw_csd,47,3,3);}
  else put(card.raw_csd,48,22,size);
  int result=mmc_decode_csd(&card,false);
  unsigned long long blocks=card.csd.capacity;
  if(structure==0)blocks<<=card.csd.read_blkbits-9;
  printf("S %u %u %u %d %llu %llu\n",structure,size,blk,result,blocks,(unsigned long long)card.csd.max_dtr);
 }
 return 0;
}
'''
(out / "oracle.c").write_text(c)
subprocess.run(["clang", "-std=gnu11", "-O2", "-fsanitize=address,undefined", str(out / "oracle.c"), "-o", str(out / "oracle")], check=True)
trace = subprocess.check_output([str(out / "oracle")])
(out / "trace.txt").write_bytes(trace)
(out / "receipt.json").write_text(json.dumps(dict(revision=manifest["revision"], sources={p:pinned[p] for p in paths}, fragments=fragments, cases=len(trace.splitlines()), trace_sha256=hashlib.sha256(trace).hexdigest()), indent=2)+"\n")
