#!/usr/bin/env python3
"""Run unchanged pinned Linux PCI DMA predicates, mask and segment setup.

Usage: xhci_dma_oracle.py FLAT_DONOR_DIRECTORY NEW_OUTPUT_DIRECTORY
PCI identities, a successful DMA-mask backend and allocation-request recording
are fixtures. This does not execute physical PCI or Linux DMA allocation.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

source, out = map(Path, sys.argv[1:])
expected = {
    "xhci.c": "dbc9e7c61efdf32566145eadc70ad3a255f3be08e811dad053b321ea11df8062",
    "xhci-mem.c": "abfe6f6f70bdeaf7a279a734bdab034ef014f329785ccb8c5f5cf3e763320198",
    "xhci-pci.c": "56659d07018ff7ae99334e910065c7bf46f80deb65c4445443ee52313422d6e8",
    "xhci.h": "44ca06ce699192d60302896df23ef3ee243abe979ac5f3c759de9830ec311cc0",
    "xhci-caps.h": "096eb25ef1cceefe6a54f0e661b585ac19fa102db9b9807c4073c660cd452b43",
    "pci_ids.h": "020fac001871c0f8441c1294f787231fb6cfbf2c55915ca8f918262e2db4487c",
}
text = {}
for name, sha in expected.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == sha, name
    text[name] = raw.decode()
out.mkdir(exist_ok=False, parents=True)
fragments = []


def fragment(file, start, end):
    raw = text[file]
    at = raw.index(start)
    stop = raw.index(end, at + len(start))
    body = raw[at:stop]
    fragments.append(dict(file=file, start=at, end=stop,
                          sha256=hashlib.sha256(body.encode()).hexdigest()))
    return body


pci = "\n".join([
    fragment("xhci-pci.c", "\tif (pdev->vendor == PCI_VENDOR_ID_VIA && pdev->device == PCI_DEVICE_ID_VIA_VL805) {", "\n\n\tif (pdev->vendor == PCI_VENDOR_ID_ASMEDIA"),
    fragment("xhci-pci.c", "\tif (pdev->vendor == PCI_VENDOR_ID_ASMEDIA &&\n\t\tpdev->device == PCI_DEVICE_ID_ASMEDIA_1042A_XHCI) {", "\n\tif (pdev->vendor == PCI_VENDOR_ID_ASMEDIA &&\n\t    (pdev->device"),
    fragment("xhci-pci.c", "\tif (pdev->vendor == PCI_VENDOR_ID_ASMEDIA &&\n\t    (pdev->device", "\n\n\tif (pdev->vendor == PCI_VENDOR_ID_ASMEDIA"),
    fragment("xhci-pci.c", "\tif (pdev->vendor == PCI_VENDOR_ID_ZHAOXIN) {", "\n\n\tif (pdev->vendor == PCI_VENDOR_ID_CDNS"),
])
mask = fragment("xhci.c", "\tif (xhci->quirks & XHCI_NO_64BIT_SUPPORT)", "\n\n\tspin_lock_init(&xhci->lock);")
segment = fragment("xhci-mem.c", "\tif (xhci->quirks & XHCI_TRB_OVERFETCH)\n", "\n\tif (!xhci->segment_pool)")
tokens = set(re.findall(r"\b(?:PCI_VENDOR_ID_|PCI_DEVICE_ID_|XHCI_|HCC_)[A-Z0-9_]+\b", pci + mask + segment))
tokens.update(["TRBS_PER_SEGMENT", "TRB_SEGMENT_SIZE"])
definitions = {}
for raw in text.values():
    for match in re.finditer(r"^#define\s+(\w+)\s+([^\n]+)", raw, re.M):
        definitions[match[1]] = match[0]
macros = "\n".join(definitions[name] for name in sorted(tokens))
header = r'''
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#define BIT(n) (1u << (n))
#define BIT_ULL(n) (UINT64_C(1) << (n))
#define DMA_BIT_MASK(n) ((n)==64 ? UINT64_MAX : ((UINT64_C(1) << (n))-1))
#define xhci_dbg(...) ((void)0)
struct device { int unused; };
struct pci_dev { uint16_t vendor,device; };
struct xhci_hcd { uint64_t quirks; unsigned dma_mask_bits,hcc_params,page_size; void *segment_pool; };
static unsigned bits, coherent;
static size_t bytes,alignment,boundary;
static int dma_set_mask(struct device *dev,uint64_t value) {
 (void)dev; bits=__builtin_popcountll(value); return 0;
}
static void dma_set_coherent_mask(struct device *dev,uint64_t value) {
 (void)dev; coherent=__builtin_popcountll(value);
}
static void *dma_pool_create(const char *name,struct device *dev,size_t size,size_t align,size_t limit) {
 (void)name;(void)dev;bytes=size;alignment=align;boundary=limit;return (void*)1;
}
'''
c = header + macros + "\nstatic void pci(struct xhci_hcd *xhci,struct pci_dev *pdev) {\n" + pci + "\n}\n"
c += "static int mask(struct xhci_hcd *xhci,struct device *dev) { int retval;\n" + mask + "\nreturn 0;\n}\n"
c += "static void segment(struct xhci_hcd *xhci,struct device *dev) {\n" + segment + "\n}\n"
c += r'''
int main(void) {
 const uint16_t vendors[]={0x1b21,0x1106,0x1d17,0x8086,0xffff};
 const uint16_t devices[]={0x1142,0x1242,0x2142,0x3242,0x3483,0x9202,0x9203,0x1042,0x3042,0,0xffff};
 for(size_t v=0;v<sizeof(vendors)/sizeof(*vendors);v++)
  for(size_t d=0;d<sizeof(devices)/sizeof(*devices);d++)
   for(unsigned ac64=0;ac64<2;ac64++) {
    struct pci_dev pdev={vendors[v],devices[d]}; struct device dev={0};
    struct xhci_hcd xhci={.dma_mask_bits=64,.hcc_params=ac64,.page_size=4096};
    pci(&xhci,&pdev); if(mask(&xhci,&dev))return 2; segment(&xhci,&dev);
    printf("%u %u %u %u %u %zu %zu %zu\n",pdev.vendor,pdev.device,ac64,bits,coherent,bytes,alignment,boundary);
   }
 return 0;
}
'''
(out / "oracle.c").write_text(c)
(out / "fragments.json").write_text(json.dumps(fragments, indent=2) + "\n")
subprocess.run(["clang", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(out / "oracle.c"), "-o", str(out / "oracle")], check=True)
with (out / "trace.txt").open("wb") as trace:
    subprocess.run([str(out / "oracle")], stdout=trace, check=True)
raw = (out / "trace.txt").read_bytes()
assert len(raw.splitlines()) == 110
print(json.dumps(dict(rows=110,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())))
