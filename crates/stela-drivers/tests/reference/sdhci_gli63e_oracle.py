#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Run complete unchanged GL9763E PHY/LPN/signaling/strobe functions.

Usage: sdhci_gli63e_oracle.py VERIFIED_REFERENCE_ROOT FRESH_OUTPUT_DIRECTORY
The extra native idle-CQE inventory/ownership refusal is separate model evidence.
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
    "drivers/mmc/host/sdhci-pci-gli.c": "b23e3fcbb565a92b3b867f3347614f70a0fb8e193a3917ace4bf9f4c991cdbc3",
    "drivers/mmc/host/sdhci.h": "4b3a252cecc039b22e56c37ec95ad2959bee52934594666708c4a7f118afe4af",
    "include/linux/mmc/host.h": "48ddebc041d079a90ba43628d106acbd2b0a09bbe459deca9d7a73ae561945cc",
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
    path = "drivers/mmc/host/sdhci-pci-gli.c"
    text = texts[path]
    match = re.search(r"^static void " + name + r"\([^;{}]*\)\n\{", text, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    body = text[match.start():end]
    fragments.append(dict(path=path, name=name, sha256=hashlib.sha256(body.encode()).hexdigest()))
    return body


bodies = [function(name) for name in [
    "sdhci_gli_mask_replay_timer_timeout", "gl9763e_hs400_enhanced_strobe",
    "gl9763e_set_low_power_negotiation", "sdhci_set_gl9763e_signaling", "gl9763e_hw_setting",
]]
definitions = {}
for text in texts.values():
    definitions.update(re.findall(r"^#define\s+([A-Za-z][A-Za-z0-9_]+)\s+(.+)$", text.replace("\\\n", ""), re.M))
pattern = r"\b(?:SDHCI|MMC|PCIE_GLI|GLI)_[A-Za-z0-9_]+\b"
names = set(re.findall(pattern, "\n".join(bodies)))
while True:
    previous = set(names)
    for name in previous:
        assert name in definitions, name
        names.update(re.findall(pattern, definitions[name]))
    if names == previous:
        break
c = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef uint16_t u16; typedef uint32_t u32;
#define BIT(n) (1U << (n))
#define GENMASK(h,l) ((~0U << (l)) & (~0U >> (31-(h))))
#define FIELD_PREP(m,v) (((u32)(v) << __builtin_ctz(m)) & (m))
#define PCI_EXT_CAP_ID_ERR 1
#define PCI_ERR_COR_MASK 0x14
#define PCI_ERR_COR_REP_TIMER BIT(12)
static u32 cfg[1024], regs[384];
struct pci_dev {int unused;};
struct sdhci_pci_chip {struct pci_dev *pdev;};
struct sdhci_pci_slot {struct sdhci_pci_chip *chip;};
struct sdhci_host {int unused;};
struct mmc_host {struct sdhci_host *host;};
struct mmc_ios {bool enhanced_strobe;};
#define mmc_priv(m) ((m)->host)
static int pci_find_ext_capability(struct pci_dev *p,int cap) {(void)p;if(cap!=1)abort();return 0x100;}
static void pci_read_config_dword(struct pci_dev *p,unsigned at,u32 *v) {(void)p;*v=cfg[at/4];}
static void pci_write_config_dword(struct pci_dev *p,unsigned at,u32 v) {(void)p;if(at!=0x884&&(cfg[0x884/4]&0xf0000)!=0x20000)abort();cfg[at/4]=v;}
static u32 sdhci_readl(struct sdhci_host *h,unsigned at) {(void)h;return regs[at/4];}
static void sdhci_writel(struct sdhci_host *h,u32 v,unsigned at) {(void)h;regs[at/4]=v;}
static u16 sdhci_readw(struct sdhci_host *h,unsigned at) {(void)h;return (u16)(regs[at/4]>>((at%4)*8));}
static void sdhci_writew(struct sdhci_host *h,u16 v,unsigned at) {(void)h;unsigned shift=(at%4)*8;regs[at/4]=(regs[at/4]&~(0xffffU<<shift))|((u32)v<<shift);}
'''
c += "\n".join("#define " + name + " " + definitions[name] for name in sorted(names)) + "\n"
c += "\n".join(bodies)
c += r'''
int main(void) {
 const u32 seeds[]={0,1,0x12345678,0xdeadbeef,0xa5a5a5a5,0x5a5a5a5a,0xffff0000,0x7fffffff,0xffffffff};
 const unsigned addresses[]={0x884,0x8e0,0x960,0x8a4,0x934,0x114,0x8a0};
 struct pci_dev p={0};struct sdhci_pci_chip chip={&p};struct sdhci_pci_slot slot={&chip};
 struct sdhci_host h={0};struct mmc_host m={&h};struct mmc_ios ios={false};
 for(unsigned s=0;s<9;++s)for(unsigned enable=0;enable<2;++enable) {
  memset(cfg,0,sizeof cfg);memset(regs,0,sizeof regs);
  for(unsigned i=0;i<7;++i)cfg[addresses[i]/4]=seeds[s];
  regs[0x52c/4]=seeds[s];
  gl9763e_hw_setting(&slot);gl9763e_set_low_power_negotiation(&slot,enable);
  gl9763e_hs400_enhanced_strobe(&m,&ios);
  printf("P %u %u",seeds[s],enable);
  for(unsigned i=0;i<7;++i)printf(" %u",cfg[addresses[i]/4]);
  printf(" %u\n",regs[0x52c/4]);
 }
 for(unsigned s=0;s<9;++s) {
  regs[0x3c/4]=(seeds[s]&0xffff)<<16;
  sdhci_set_gl9763e_signaling(&h,MMC_TIMING_MMC_HS);
  printf("S %u %u\n",seeds[s]&0xffff,sdhci_readw(&h,0x3e));
 }
 return 0;
}
'''
(out / "oracle.c").write_text(c)
compiler = shutil.which("clang") or shutil.which("gcc")
assert compiler
command = [compiler, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(out / "oracle.c"), "-o", str(out / "oracle")]
compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
(out / "compile.log").write_text(compiled.stdout + compiled.stderr)
compiled.check_returncode()
result = subprocess.run([str(out / "oracle")], capture_output=True, text=True, timeout=60)
(out / "stderr.log").write_text(result.stderr)
result.check_returncode()
assert len(result.stdout.splitlines()) == 27
(out / "records.txt").write_text(result.stdout)
(out / "report.json").write_text(json.dumps(dict(pin=PIN, sources=HASHES, fragments=fragments, records=27, command=command, output_sha256=hashlib.sha256(result.stdout.encode()).hexdigest(), limitations=[
    "Modeled protected PCI and MMIO; no physical host/card execution",
    "PHY/LPN final words, enhanced-strobe disable and MMC_HS signaling only; fast MMC/CQE requests/IRQ/PM remain unqualified",
    "Native additionally gates/checks card clock and verifies all register writes; idle CQE ownership refusal is tested separately and is not Linux task-drain equivalence",
]), indent=2)+"\n")
print(json.dumps(dict(records=27, output=str(out / "records.txt"))))
