#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only OR BSD-3-Clause
# Copyright (c) 2020, Advanced Micro Devices, Inc.
# Source author: Sanjay R Mehta <sanju.mehta@amd.com>
"""Compile complete unchanged AMD SPI FIFO functions against a bounded peer.

Use the original source directory supplied by the repository source inventory,
not the patched GPU working tree. Nothing in the Linux checkout is modified.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

PIN = "cc9de5d4b5ab6459f5774946aa3195ad51236fa8"
SOURCE = "drivers/spi/spi-amd.c"
SHA256 = "e292210d5af8482f5b34bfa22f8e155ef1873e277abf81293bd824d055c1a52d"


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
    raw = (args.linux / SOURCE).read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA256:
        raise SystemExit("pinned original source integrity mismatch")
    args.out.mkdir(parents=True, exist_ok=False)
    source = raw.decode()
    names = [
        "amd_spi_readreg8", "amd_spi_writereg8", "amd_spi_setclear_reg8",
        "amd_spi_readreg32", "amd_spi_writereg32", "amd_spi_setclear_reg32",
        "amd_spi_select_chip", "amd_spi_clear_chip", "amd_spi_clear_fifo_ptr",
        "amd_spi_set_opcode", "amd_spi_set_rx_count", "amd_spi_set_tx_count",
        "amd_spi_busy_wait", "amd_spi_execute_opcode", "amd_spi_host_setup",
        "amd_set_spi_freq", "amd_spi_fifo_xfer",
    ]
    definitions = {}
    for name in names:
        match = re.search(r"^static(?: inline)? [\w *]+\b" + name + r"\(", source, re.M)
        if not match:
            raise SystemExit("missing complete function: " + name)
        definitions[name] = declaration(source, match.group())
    constants = "\n".join(re.findall(r"^#define AMD_SPI_.*$", source, re.M))
    types = "\n".join(declaration(source, marker) + ";" for marker in [
        "enum amd_spi_speed {", "struct amd_spi_freq {",
        "static const struct amd_spi_freq amd_spi_freq[] = {",
    ])
    prefix = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;
typedef uint32_t u32;
#define __iomem
#define BIT(n) (1u << (n))
#define GENMASK(hi,lo) ((~0u << (lo)) & (~0u >> (31 - (hi))))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
enum { AMD_SPI_V1 = 1, AMD_SPI_V2 = 2, AMD_HID2_SPI = 3 };
struct amd_spi { void *io_remap_addr; unsigned version, speed_hz; };
struct spi_controller { struct amd_spi *data; };
struct spi_device { struct spi_controller *controller; unsigned max_speed_hz; u8 chip_select; };
struct spi_transfer { const void *tx_buf; void *rx_buf; unsigned len, speed_hz; struct spi_transfer *next; };
struct list_head { struct spi_transfer *first; };
struct spi_message { struct spi_device *spi; struct list_head transfers; int status; unsigned actual_length; };
#define list_for_each_entry(pos, head, member) for ((pos) = (head)->first; (pos); (pos) = (pos)->next)
static void *spi_controller_get_devdata(struct spi_controller *host) { return host->data; }
static u8 spi_get_chipselect(struct spi_device *device, unsigned index) { if (index) abort(); return device->chip_select; }
static void spi_finalize_current_message(struct spi_controller *host) { (void)host; }
static u8 regs[0xc6], wire_tx[70];
static unsigned version, pending, completed, wire_opcode, wire_rx, wire_len, wire_cs, wire_hz, triggers;
static u32 load32(unsigned offset) { u32 value; memcpy(&value,regs+offset,4); return value; }
static void capture(unsigned opcode) {
    if (pending) abort();
    wire_opcode=opcode;wire_len=regs[0x48];wire_rx=regs[0x4b];wire_cs=regs[0x1d]&3;
    if (wire_len+wire_rx>=70) abort();
    memcpy(wire_tx,regs+0x80,wire_len);
    switch ((load32(0x20)>>20)&15) {
    case 0:wire_hz=66660000;break;case 1:wire_hz=33330000;break;
    case 2:wire_hz=22220000;break;case 3:wire_hz=16660000;break;
    case 4:if(!(load32(0x20)&1))abort();wire_hz=100000000;break;
    case 5:wire_hz=800000;break;case 7:switch((load32(0x6c)>>8)&63){
        case 4:wire_hz=50000000;break;case 50:wire_hz=4000000;break;
        case 63:wire_hz=3170000;break;default:abort();}break;default:abort();
    }
    pending=3;++triggers;
}
static u32 busy(void) {
    if(!pending)return 0;
    if(--pending)return 1u<<31;
    for(unsigned i=0;i<wire_rx;++i)regs[0x80+wire_len+i]=(u8)(wire_opcode+i)^0xa5;
    ++completed;return 0;
}
static unsigned offset(void *address,unsigned bytes) {
    uintptr_t delta=(uintptr_t)address-(uintptr_t)regs;
    if(delta+bytes>sizeof regs)abort();return (unsigned)delta;
}
static u8 readb(void *address) { return regs[offset(address,1)]; }
static void writeb(u8 value,void *address) {
    unsigned at=offset(address,1);regs[at]=value;
    if(at==0x47 && (value&128)){if(version!=2)abort();regs[at]&=0x7f;capture(regs[0x45]);}
}
static u32 readl(void *address) {
    unsigned at=offset(address,4);u32 value=load32(at);
    if((version==1&&at==0)||(version==2&&at==0x4c))value=(value&~(1u<<31))|busy();
    return value;
}
static void writel(u32 value,void *address) {
    unsigned at=offset(address,4);u32 stored=at==0?value&~((1u<<16)|(1u<<20)):value;
    memcpy(regs+at,&stored,4);
    if(at==0&&(value&(1u<<16))){if(version!=1)abort();capture(value&255);}
}
#define readl_poll_timeout(address,val,cond,delay,timeout) ({ \
    int result=-ETIMEDOUT; \
    for(unsigned polls=0;polls<8;++polls){(val)=readl(address);if(cond){result=0;break;}} \
    result; })
'''
    suffix = r'''
int main(void) {
    static const unsigned speeds[]={100000000,66660000,50000000,33330000,22220000,16660000,4000000,3170000,800000};
    for(version=1;version<=2;++version)for(unsigned txlen=0;txlen<70;++txlen)
    for(unsigned rxlen=0;rxlen<70-txlen;++rxlen){
        memset(regs,0,sizeof regs);memset(wire_tx,0,sizeof wire_tx);
        pending=completed=wire_opcode=wire_rx=wire_len=wire_cs=wire_hz=triggers=0;
        regs[0x1d]=0xb0;
        u8 tx[70],rx[70];tx[0]=0x90;memset(rx,0xe7,sizeof rx);
        for(unsigned i=0;i<txlen;++i)tx[i+1]=(u8)(i*37+91);
        unsigned cs=(txlen+rxlen)%4,limit=speeds[(txlen+rxlen)%9];
        struct amd_spi controller={.io_remap_addr=regs,.version=version};
        struct spi_controller host={.data=&controller};
        struct spi_device device={.controller=&host,.max_speed_hz=limit,.chip_select=(u8)cs};
        struct spi_transfer read={.rx_buf=rx,.len=rxlen};
        struct spi_transfer write={.tx_buf=tx,.len=txlen+1,.next=rxlen?&read:NULL};
        struct spi_message message={.spi=&device,.transfers={.first=&write}};
        if(amd_spi_host_setup(&device))abort();
        amd_spi_select_chip(&controller,(u8)cs);
        int result=amd_spi_fifo_xfer(&controller,&host,&message);
        if(result||message.status||triggers!=1||wire_len!=txlen||wire_rx!=rxlen)abort();
        printf("%u,%u,%u,%u,%u,%u,%d,%u,%u,",version,cs,limit,wire_opcode,txlen,rxlen,result,message.actual_length,wire_hz);
        for(unsigned i=0;i<wire_len;++i)printf("%02x",wire_tx[i]);
        putchar(',');for(unsigned i=0;i<rxlen;++i)printf("%02x",rx[i]);
        printf(",%u,%u\n",regs[0x1d],completed);
    }
    return 0;
}
'''
    c_file = args.out / "oracle.c"
    c_file.write_text(prefix + constants + "\n" + types + "\n" + "\n".join(definitions.values()) + suffix)
    command = [args.cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(c_file), "-o", str(args.out / "oracle")]
    (args.out / "compiler-command.json").write_text(json.dumps(command) + "\n")
    result = subprocess.run(command, capture_output=True, timeout=120)
    (args.out / "compiler-stdout.txt").write_bytes(result.stdout)
    (args.out / "compiler-stderr.txt").write_bytes(result.stderr)
    result.check_returncode()
    result = subprocess.run([str((args.out / "oracle").resolve())], capture_output=True, timeout=60)
    (args.out / "trace.csv").write_bytes(result.stdout)
    (args.out / "stderr.txt").write_bytes(result.stderr)
    result.check_returncode()
    receipt = {
        "pin": PIN, "source": SOURCE, "source_sha256": SHA256,
        "unchanged_functions": {name: hashlib.sha256(body.encode()).hexdigest() for name, body in definitions.items()},
        "cases": len(result.stdout.splitlines()), "trace_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "oracle_limits": [
            "MMIO, list traversal, logging/finalization, calibrated waits, kernel device/platform registration are substituted services",
            "Ordinary V1/V2 FIFO opcode, TX then RX, mode0/8-bit/single-line only; no SPI-mem dual/quad or HID2 DMA",
            "Source FIFO TX-only path returns before BUSY completion; native awaits completion before publication/release",
            "Source V2 cleanup zeros selector byte; native preserves unrelated upper bits",
            "Error retention/deadlines, native UC mappings, electrical device behavior and hardware qualification are separate native peer/platform evidence",
        ],
    }
    (args.out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"cases": receipt["cases"], "trace_sha256": receipt["trace_sha256"]}))


if __name__ == "__main__":
    main()
