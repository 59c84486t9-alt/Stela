#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only OR BSD-3-Clause
# AMD MP2 source authors: Shyam Sundar S K, Elie Morisse,
# Nehal Bakulchandra Shah. Native harness original Stela code.
"""Run unchanged pinned AMD MP2 command and event functions under sanitizers.

Only PCI logging, locking and MMIO services are substituted. This is a protocol
oracle, not a Linux runtime, MP2 firmware emulator or cryptographic/physical test.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

PIN = "a804c5742bff224d4cb4d25dd383554d598be32b"
HASHES = {
    "drivers/i2c/busses/i2c-amd-mp2-pci.c": "455f0a2af4b40b5d74c84a356d7965970cab5b2b449a5c81cdcf3ce20201fcf5",
    "drivers/i2c/busses/i2c-amd-mp2-plat.c": "329dc41c44f532bcd55e2446037beb66915f964ebc5dae0cc443999caa129b41",
    "drivers/i2c/busses/i2c-amd-mp2.h": "efc4be4f6e91543551727289afe589737a9c082ab296bc3db7255722e9906ab0",
}


def declaration(source, marker):
    start = source.index(marker)
    opened = source.index("{", start)
    depth = 1
    end = opened + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    sources = {}
    for name, digest in HASHES.items():
        raw = subprocess.check_output(["git", "-C", str(args.linux.resolve()), "show", f"{PIN}:{name}"], timeout=30)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise SystemExit(f"source integrity mismatch: {name}")
        (args.out / Path(name).name).write_bytes(raw)
        sources[name] = raw.decode()
    header = sources["drivers/i2c/busses/i2c-amd-mp2.h"]
    source = sources["drivers/i2c/busses/i2c-amd-mp2-pci.c"]
    markers = ["static int amd_mp2_cmd(", "int amd_mp2_bus_enable_set(",
               "static void amd_mp2_cmd_rw_fill(", "int amd_mp2_rw(",
               "static void amd_mp2_pci_check_rw_event(", "static void __amd_mp2_process_event("]
    bodies = [declaration(source, marker) for marker in markers]
    declarations = header[header.index("enum {\n\t/* MP2 C2P"):header.index("/**\n * struct amd_i2c_common")]
    prefix = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
#define __iomem
#define unlikely(x) (x)
#define pci_err(...) ((void)0)
#define pci_dbg(...) ((void)0)
struct pci_dev { unsigned unused; };
struct i2c_msg { unsigned addr, len; u8 *buf; };
static void writel(u32 v,void *p) { memcpy(p,&v,4); }
static void writeq(u64 v,void *p) { memcpy(p,&v,8); }
static void memcpy_toio(void *p,const void *b,size_t n) { memcpy(p,b,n); }
static void memcpy_fromio(void *b,const void *p,size_t n) { memcpy(b,p,n); }
'''
    shim = r'''
struct amd_mp2_dev { struct pci_dev *pci_dev; void *mmio; };
struct amd_i2c_common {
    union i2c_event eventval;
    struct amd_mp2_dev *mp2_dev;
    struct i2c_msg *msg;
    enum i2c_cmd reqcmd;
    u8 cmd_success, bus_id;
    enum speed_enum i2c_speed;
    u64 dma_addr;
};
static void amd_mp2_c2p_mutex_lock(struct amd_i2c_common *c) { (void)c; }
'''
    suffix = r'''
int main(void) {
    static u8 regs[0x10700], bytes[4096];
    struct amd_mp2_dev dev={.mmio=regs};
    struct i2c_msg msg={.addr=0x2c,.buf=bytes};
    for(unsigned n=0;n<sizeof bytes;++n) bytes[n]=(u8)(n*17+3);
    for(unsigned bus=0;bus<2;++bus) for(unsigned speed=0;speed<5;++speed) {
        struct amd_i2c_common c={.mp2_dev=&dev,.msg=&msg,.bus_id=bus,.i2c_speed=speed,.dma_addr=0x123456789abcdef0ULL};
        for(unsigned enable=0;enable<2;++enable) {
            memset(regs,0,sizeof regs);amd_mp2_bus_enable_set(&c,enable);
            u32 word;memcpy(&word,regs+(bus?AMD_C2P_MSG1:AMD_C2P_MSG0),4);
            printf("P,%u,%u,%u,%08x\n",bus,speed,enable,word);
        }
        for(unsigned length=1;length<=4095;++length) for(unsigned op=0;op<2;++op) {
            memset(regs,0,sizeof regs);msg.len=length;
            amd_mp2_rw(&c,op);
            u32 word;memcpy(&word,regs+(bus?AMD_C2P_MSG1:AMD_C2P_MSG0),4);
            u64 payload;memcpy(&payload,regs+AMD_C2P_MSG2,8);
            printf("C,%u,%u,%u,%u,%08x,%016llx\n",bus,speed,op,length,word,(unsigned long long)payload);
        }
    }
    // Deliberately vary fields the donor ignores. The receipt records this
    // limitation rather than promoting an uncorrelated response into success.
    msg.len=17;
    for(unsigned op=0;op<2;++op) for(unsigned response=0;response<4;++response)
    for(unsigned status=0;status<32;++status) for(unsigned bus=0;bus<16;++bus)
    for(unsigned memory=0;memory<2;++memory) {
        struct amd_i2c_common c={.mp2_dev=&dev,.msg=&msg,.reqcmd=op};
        c.eventval.ul=response|(status<<2)|(memory<<7)|(bus<<8)|(17<<12)|(0x2cU<<24);
        __amd_mp2_process_event(&c);
        printf("E,%u,%08x,%u\n",op,c.eventval.ul,c.cmd_success);
    }
    return 0;
}
'''
    harness = prefix + declarations + shim + "\n".join(bodies) + suffix
    (args.out / "oracle.c").write_text(harness)
    command = [args.cc, "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(args.out / "oracle.c"), "-o", str(args.out / "oracle")]
    (args.out / "compiler-command.json").write_text(json.dumps(command) + "\n")
    compiled = subprocess.run(command, capture_output=True, timeout=120)
    (args.out / "compiler-stdout.txt").write_bytes(compiled.stdout)
    (args.out / "compiler-stderr.txt").write_bytes(compiled.stderr)
    compiled.check_returncode()
    run = subprocess.run([str((args.out / "oracle").resolve())], capture_output=True, timeout=60)
    (args.out / "trace.csv").write_bytes(run.stdout)
    (args.out / "stderr.txt").write_bytes(run.stderr)
    run.check_returncode()
    receipt = {"pin": PIN, "sources": HASHES,
               "extracted_functions": {marker: hashlib.sha256(body.encode()).hexdigest() for marker, body in zip(markers, bodies)},
               "cases": len(run.stdout.splitlines()), "trace_sha256": hashlib.sha256(run.stdout).hexdigest(), "compiler_command": command,
               "oracle_limits": ["PCI logging/locking/MMIO services replaced, no actual firmware/IRQ/physical qualification",
                                 "Donor event acceptance ignores event bus/memory; native path requires correlated fields",
                                 "Donor copies inline reads even after length/address mismatch; native outputs remain private until matching success",
                                 "Donor maps/unmaps on timeout without completion proof; native retains the entire owner",
                                 "No combined repeated START field/proof in firmware command; individual message API only"]}
    (args.out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
