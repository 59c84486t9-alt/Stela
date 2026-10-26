#!/usr/bin/env python3
"""Run unchanged Linux v4 address-capability, DMA-control and ADMA descriptor code.

Usage: sdhci_adma_oracle.py DONOR_DIRECTORY FRESH_OUTPUT_DIRECTORY
The shim supplies MMIO and zeroed descriptor RAM; no device DMA executes.
"""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

PIN = "cc9de5d4b5ab6459f5774946aa3195ad51236fa8"
HASHES = {
    "drivers/mmc/host/sdhci.c": "186305e102bd32df419ff80669e6018d6b3a9e4310c3101193413970355b9857",
    "drivers/mmc/host/sdhci.h": "4b3a252cecc039b22e56c37ec95ad2959bee52934594666708c4a7f118afe4af",
}
donor, out = map(Path, sys.argv[1:])
texts = {}
for path, digest in HASHES.items():
    raw = (donor / path).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, path
    texts[path] = raw.decode()
out.mkdir(parents=True, exist_ok=False)
fragments = []


def function(name):
    text = texts["drivers/mmc/host/sdhci.c"]
    match = re.search(r"^(?:static )?(?:inline )?(?:void|bool) " + name + r"\([^;{}]*\)\n\{", text, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    body = text[match.start():end]
    fragments.append(dict(name=name, start=match.start(), end=end,
                          sha256=hashlib.sha256(body.encode()).hexdigest()))
    return body


bodies = [function(name) for name in ["sdhci_can_64bit_dma", "sdhci_config_dma", "sdhci_adma_write_desc", "sdhci_set_adma_addr"]]
macros = []
for name in sorted(set(re.findall(r"\bSDHCI_[A-Z0-9_]+\b", "\n".join(bodies)))):
    match = re.search(r"^#define\s+" + name + r"\s+(.+)$", texts["drivers/mmc/host/sdhci.h"], re.M)
    assert match, name
    macros.append("#define " + name + " " + match[1])
c = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t dma_addr_t;
#define cpu_to_le16(v) ((u16)(v))
#define cpu_to_le32(v) ((u32)(v))
#define lower_32_bits(v) ((u32)(v))
#define upper_32_bits(v) ((u32)((v)>>32))
struct sdhci_adma2_64_desc {u16 cmd,len;u32 addr_lo,addr_hi;};
struct sdhci_host {unsigned version,caps,flags,desc_sz;bool v4_mode;u8 control;u16 control2;u32 address_low,address_high;};
static u8 sdhci_readb(struct sdhci_host *h,unsigned at) {(void)at;return h->control;}
static u16 sdhci_readw(struct sdhci_host *h,unsigned at) {(void)at;return h->control2;}
static void sdhci_writeb(struct sdhci_host *h,u8 v,unsigned at) {(void)at;h->control=v;}
static void sdhci_writew(struct sdhci_host *h,u16 v,unsigned at) {(void)at;h->control2=v;}
static void sdhci_writel(struct sdhci_host *h,u32 v,unsigned at) {if(at==0x58)h->address_low=v;else if(at==0x5c)h->address_high=v;}
'''
c += "\n".join(macros) + "\n" + "\n".join(bodies)
c += r'''
int main(void) {
    for(unsigned version=2;version<=5;++version) for(unsigned cap=0;cap<4;++cap)
        for(unsigned length=512;length<=65536;length*=128)
            for(unsigned high=0;high<2;++high) {
                struct sdhci_host h={.version=version,.caps=((cap&1)?0x10000000:0)|((cap&2)?0x08000000:0),
                    .v4_mode=true,.control=0x3f,.control2=0x1088};
                bool wide=sdhci_can_64bit_dma(&h);
                h.flags=SDHCI_USE_ADMA|SDHCI_REQ_USE_DMA|(wide?SDHCI_USE_64_BIT_DMA:0);
                h.desc_sz=wide?16:8;
                sdhci_config_dma(&h);
                uint64_t storage[4]={0}; void *descriptor=storage;
                dma_addr_t address=high?0x12345678000ULL:0x12345000ULL;
                sdhci_adma_write_desc(&h,&descriptor,address,(int)length,0x23);
                h.address_high=0xfeed1234;
                sdhci_set_adma_addr(&h,address);
                unsigned char *bytes=(unsigned char*)storage;
                printf("D %u %u %u %u %u %u %u %u %u %u ",version,cap,length,high,wide,h.control,h.control2,h.desc_sz,h.address_low,h.address_high);
                for(unsigned i=0;i<h.desc_sz;++i) printf("%02x",bytes[i]);
                putchar('\n');
            }
    return 0;
}
'''
(out / "oracle.c").write_text(c)
compiler = shutil.which("clang") or shutil.which("gcc")
assert compiler, "local C compiler required"
command = [compiler, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
           "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
           str(out / "oracle.c"), "-o", str(out / "oracle")]
compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
(out / "compile.log").write_text(compiled.stdout + compiled.stderr)
compiled.check_returncode()
run = subprocess.run([str(out / "oracle")], capture_output=True, text=True, timeout=30)
(out / "stderr.log").write_text(run.stderr)
run.check_returncode()
(out / "records.txt").write_text(run.stdout)
assert len(run.stdout.splitlines()) == 64
(out / "report.json").write_text(json.dumps(dict(pin=PIN,sources=HASHES,fragments=fragments,
    records=64,command=command,output_sha256=hashlib.sha256(run.stdout.encode()).hexdigest(),
    limitations=["MMIO and zeroed descriptor RAM modeled; no device DMA execution"]),indent=2)+"\n")
print(json.dumps(dict(records=64,output=str(out / "records.txt"))))
