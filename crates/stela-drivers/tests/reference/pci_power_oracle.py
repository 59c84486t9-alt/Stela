#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright 1993 -- 1997 Drew Eckhardt, Frederic Potter, David Mosberger-Tang
# Copyright 1997 -- 2000 Martin Mares <mj@ucw.cz>
# Copyright (c) 2026 Stela contributors
"""Execute complete unchanged pinned Linux PCI PM functions in a bounded model."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

PIN = "cc9de5d4b5ab6459f5774946aa3195ad51236fa8"
SOURCES = {
    "drivers/pci/pci.c": "030e56923d6d7662fc697a30f97b7034545670e537ff50323bd39c7a6d589e18",
    "include/uapi/linux/pci_regs.h": "51d2a1344da2a56e913e9d69b3b5d90eaaf4fb0bf96e672a5674ea819182c69b",
}


def function(text, name):
    declaration = re.search(r"^(?:static )?(?:int|void) " + name + r"\(", text, re.M)
    if declaration is None:
        raise ValueError("missing complete function: " + name)
    start = declaration.start()
    end = text.index("{", start) + 1
    depth = 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    raw = {}
    for name, digest in SOURCES.items():
        raw[name] = (args.linux / name).read_bytes()
        if hashlib.sha256(raw[name]).hexdigest() != digest:
            raise SystemExit("original pinned source integrity mismatch: " + name)
    definitions = {
        name: function(raw["drivers/pci/pci.c"].decode(), name)
        for name in ("pci_power_up", "pci_set_low_power_state", "__pci_pme_active")
    }
    args.out.mkdir(parents=True, exist_ok=False)
    prefix = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "pci_regs.h"
typedef uint16_t u16;
typedef unsigned pci_power_t;
enum { PCI_D0=0, PCI_D1, PCI_D2, PCI_D3hot, PCI_D3cold, PCI_UNKNOWN };
enum { PCI_PM_D2_DELAY=200, PCIE_RESET_READY_POLL_MS=60000 };
struct pci_dev { unsigned pm_cap, current_state, pme_support, d1_support, d2_support; };
static u16 csr, raw_store;
static unsigned stores, elapsed;
#define PCI_POSSIBLE_ERROR(value) ((value)==(__typeof__(value))~0u)
#define pci_dbg(...) ((void)0)
#define pci_info_ratelimited(...) ((void)0)
#define pci_err(...) ((void)0)
static bool pci_dev_is_disconnected(struct pci_dev *dev) { (void)dev;return false; }
static void platform_pci_set_power_state(struct pci_dev *dev,unsigned state) {(void)dev;(void)state;}
static unsigned platform_pci_get_power_state(struct pci_dev *dev) {(void)dev;return PCI_UNKNOWN;}
static void pci_read_config_word(struct pci_dev *dev,unsigned offset,u16 *value) {
    if(offset!=dev->pm_cap+PCI_PM_CTRL)abort();*value=csr;
}
static void pci_write_config_word(struct pci_dev *dev,unsigned offset,u16 value) {
    if(offset!=dev->pm_cap+PCI_PM_CTRL)abort();
    raw_store=value;++stores;
    const u16 rw=PCI_PM_CTRL_STATE_MASK|PCI_PM_CTRL_PME_ENABLE|PCI_PM_CTRL_DATA_SEL_MASK;
    csr=(csr&~(rw|PCI_PM_CTRL_PME_STATUS))|(value&rw)
        |((csr&PCI_PM_CTRL_PME_STATUS)&~(value&PCI_PM_CTRL_PME_STATUS));
}
static void pci_dev_d3_sleep(struct pci_dev *dev) {(void)dev;elapsed+=10000;}
static void udelay(unsigned us) {elapsed+=us;}
static int pci_dev_wait(struct pci_dev *dev,char *name,int timeout) {(void)dev;(void)name;(void)timeout;return 0;}
'''
    suffix = r'''
int main(void) {
    for(unsigned state=0;state<=3;state+=3)
    for(unsigned select=0;select<16;++select)
    for(unsigned scale=0;scale<4;++scale)
    for(unsigned noreset=0;noreset<2;++noreset)
    for(unsigned pending=0;pending<2;++pending)
    for(unsigned active=0;active<2;++active) {
        unsigned before=state|(select<<9)|(scale<<13)|(noreset<<3)|(pending<<15)|(active<<8);
        for(unsigned enable=0;enable<2;++enable) {
            struct pci_dev dev={.pm_cap=0x60,.current_state=state,.pme_support=1};
            csr=before;raw_store=0;stores=elapsed=0;
            __pci_pme_active(&dev,enable);
            if(stores!=1)abort();
            printf("pme,%u,%u,%u,%u,%u,0\n",before,enable,raw_store,csr,elapsed);
        }
        struct pci_dev dev={.pm_cap=0x60,.current_state=state,.pme_support=1};
        csr=before;raw_store=0;stores=elapsed=0;
        int ret=state?pci_power_up(&dev):pci_set_low_power_state(&dev,PCI_D3hot,false);
        if(stores!=1)abort();
        printf("%s,%u,0,%u,%u,%u,%d\n",state?"up":"low",before,raw_store,csr,elapsed,ret);
    }
    return 0;
}
'''
    cfile = args.out / "oracle.c"
    cfile.write_text(prefix + "\n".join(definitions.values()) + suffix)
    # Exact original header bytes, copied solely into this small output folder.
    (args.out / "pci_regs.h").write_bytes(raw["include/uapi/linux/pci_regs.h"])
    executable = args.out / "oracle"
    command = [args.cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
               "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
               str(cfile), "-o", str(executable)]
    subprocess.run(command, check=True, timeout=60)
    trace = subprocess.check_output([str(executable)], timeout=30)
    (args.out / "trace.csv").write_bytes(trace)
    rows = len(trace.splitlines())
    if rows != 3072:
        raise SystemExit("wrong source record count: " + str(rows))
    receipt = {
        "pin": PIN, "sources": SOURCES, "rows": rows, "compile": command,
        "functions": {name: hashlib.sha256(text.encode()).hexdigest() for name, text in definitions.items()},
        "trace_sha256": hashlib.sha256(trace).hexdigest(),
        "harness_sha256": hashlib.sha256(cfile.read_bytes()).hexdigest(),
        "substitutions": ["PCI config access and W1C/RO hardware peer", "fixed 10ms D3 timing", "logging",
                          "stable platform rail/no-disconnect admission", "already-ready PCI reset wait"],
        "limits": ["no native resources, MMIO, DMA, IRQ, firmware or physical device execution",
                   "Linux low-power store replays pending PME_Status; native transition intentionally preserves it",
                   "native PME writes omit read-only/reserved bits while preserving identical modeled hardware effects"],
    }
    (args.out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"rows": rows, "trace": str(args.out / "trace.csv"), "sha256": receipt["trace_sha256"]}))


if __name__ == "__main__":
    main()
