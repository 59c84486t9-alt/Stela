#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Source: AMD SPI, Copyright 2020 AMD, Sanjay R Mehta; SPI memory core,
# Copyright 2018 Exceet Electronics GmbH and Bootlin, Boris Brezillon.
# AMD version header: Copyright 2025 AMD, Krishnamoorthi M; SPI memory
# header authors Peter Pan and Boris Brezillon.
"""Run complete unchanged AMD V1/V2 memory functions and SPI memory admission.

Usage: amd_spi_memory_oracle.py VERIFIED_REFERENCE_ROOT FRESH_OUTPUT_DIRECTORY
The peer models byte-addressed memory, volatile MMIO and BUSY completion.
No physical memory peripheral, kernel registration or HID2 DMA executes.
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
    "drivers/spi/spi-amd.c": "e292210d5af8482f5b34bfa22f8e155ef1873e277abf81293bd824d055c1a52d",
    "drivers/spi/spi-amd.h": "db09e01464df37a1bb1998645bce6c7b94b9973f11ffca1d5f76dd0e3ea5c39e",
    "drivers/spi/spi-mem.c": "8e6f8e0cdc4db532d6f4043f7911ca1329b5c2b6b9d985aa1dab3e61c37bbdbe",
    "include/linux/spi/spi-mem.h": "6eec7f73a3f5f9e098c1a22628d713b02441b5cb55b6c2093282f91f628b2d6a",
    "include/uapi/linux/spi/spi.h": "17745572b53f5e5d70366f20114350c6a5afa12ef07f44aff92f7d542698ccbb",
}
donor, out = map(Path, sys.argv[1:])
texts = {}
for path, digest in HASHES.items():
    raw = (donor / path).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, path
    texts[path] = raw.decode()
out.mkdir(parents=True, exist_ok=False)
fragments = []


def declaration(path, marker):
    text = texts[path]
    start = text.index(marker)
    end, depth = text.index("{", start) + 1, 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


def function(path, name):
    match = re.search(r"^(?:static(?: inline)? )?(?:bool|void|int|u8|u16|u32|u64)\s+" + name + r"\(", texts[path], re.M)
    assert match, name
    body = declaration(path, match.group())
    fragments.append(dict(path=path, name=name, sha256=hashlib.sha256(body.encode()).hexdigest()))
    return body


amd = "drivers/spi/spi-amd.c"
mem = "drivers/spi/spi-mem.c"
functions = [function(mem, name) for name in ["spi_check_buswidth_req", "spi_mem_check_buswidth", "spi_mem_default_supports_op", "spi_mem_adjust_op_freq"]]
functions += [function(amd, name) for name in [
    "amd_spi_readreg8", "amd_spi_writereg8", "amd_spi_setclear_reg8",
    "amd_spi_readreg32", "amd_spi_writereg32", "amd_spi_setclear_reg32",
    "amd_spi_readreg64", "amd_spi_writereg64", "amd_spi_select_chip", "amd_spi_clear_fifo_ptr",
    "amd_spi_set_opcode", "amd_spi_set_rx_count", "amd_spi_set_tx_count", "amd_spi_busy_wait",
    "amd_spi_execute_opcode", "amd_set_spi_freq", "amd_is_spi_read_cmd_4b", "amd_is_spi_read_cmd",
    "amd_is_spi_write_cmd", "amd_spi_supports_op", "amd_spi_adjust_op_size", "amd_spi_set_addr",
    "amd_spi_mem_data_out", "amd_spi_mem_data_in", "amd_set_spi_addr_mode", "amd_spi_exec_mem_op",
]]
constants = "\n".join(re.findall(r"^#define AMD_SPI_.*$", texts[amd], re.M))
for name in ["SPI_TX_DUAL", "SPI_TX_QUAD", "SPI_TX_OCTAL", "SPI_RX_DUAL", "SPI_RX_QUAD", "SPI_RX_OCTAL"]:
    match = re.search(r"^#define\s+" + name + r"\s+(.+)$", texts["include/uapi/linux/spi/spi.h"], re.M)
    assert match, name
    constants += "\n#define " + name + " " + match[1]
types = "\n".join(declaration(amd, marker) + ";" for marker in ["enum amd_spi_speed {", "struct amd_spi_freq {", "static const struct amd_spi_freq amd_spi_freq[] = {"])
versions = declaration("drivers/spi/spi-amd.h", "enum amd_spi_versions {") + ";"
c = r'''
/* SPDX-License-Identifier: GPL-2.0-only
 * AMD SPI: Copyright (c) 2020 AMD; Sanjay R Mehta.
 * AMD version header: Copyright (c) 2025 AMD; Krishnamoorthi M.
 * SPI memory core/header: Copyright (C) 2018 Exceet Electronics GmbH and
 * Bootlin; authors Peter Pan and Boris Brezillon.
 * UAPI SPI constants retain GPL-2.0-or-later WITH Linux-syscall-note.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
#define __iomem
#define BIT(n) (1U<<(n))
#define _BITUL(n) (1UL<<(n))
#define GENMASK(h,l) ((~0U<<(l))&(~0U>>(31-(h))))
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define ENOTSUPP 524
#define dev_err(...) ((void)0)
#define fallthrough __attribute__((fallthrough))
#define clamp_val(v,lo,hi) ((v)>(hi)?(hi):(v))
enum {SPI_MEM_NO_DATA,SPI_MEM_DATA_IN,SPI_MEM_DATA_OUT};
struct spi_controller_mem_caps {bool dtr,ecc,swap16,per_op_freq;};
#define spi_mem_controller_is_capable(c,cap) ((c)->mem_caps && (c)->mem_caps->cap)
struct amd_spi;
struct spi_controller {struct amd_spi *data;unsigned min_speed_hz;const struct spi_controller_mem_caps *mem_caps;};
struct spi_device {struct spi_controller *controller;unsigned max_speed_hz;u32 mode;};
struct spi_mem {struct spi_device *spi;};
struct spi_mem_op {
 struct {u16 opcode;u8 nbytes,buswidth;bool dtr;} cmd;
 struct {u64 val;u8 nbytes,buswidth;bool dtr;} addr;
 struct {u8 nbytes,buswidth;bool dtr;} dummy;
 struct {unsigned nbytes,dir;u8 buswidth;bool dtr,ecc,swap16;union {void *in;const void *out;} buf;} data;
 unsigned max_freq;
};
static void *spi_controller_get_devdata(struct spi_controller *c) {return c->data;}
static u8 regs[0xc6],flash[256],wire_tx[70];
static unsigned version,pending,wire_opcode,wire_len,wire_rx,wire_chip,wire_hz,wire_mode;
static unsigned address_length;
static u32 load32(unsigned at) {u32 v;memcpy(&v,regs+at,4);return v;}
static unsigned offset(void *p,unsigned bytes) {uintptr_t at=(uintptr_t)p-(uintptr_t)regs;if(at+bytes>sizeof regs)abort();return (unsigned)at;}
static void capture(unsigned opcode) {
 if(pending)abort();wire_opcode=opcode;wire_len=regs[0x48];wire_rx=regs[0x4b];wire_chip=regs[0x1d]&3;wire_mode=load32(0x50)&1;
 if(wire_len+wire_rx>70)abort();memcpy(wire_tx,regs+0x80,wire_len);
 switch((load32(0x20)>>20)&15) {
 case 0:wire_hz=66660000;break;case 1:wire_hz=33330000;break;case 2:wire_hz=22220000;break;case 3:wire_hz=16660000;break;
 case 4:if(!(load32(0x20)&1))abort();wire_hz=100000000;break;case 5:wire_hz=800000;break;
 case 7:switch((load32(0x6c)>>8)&63){case 4:wire_hz=50000000;break;case 50:wire_hz=4000000;break;case 63:wire_hz=3170000;break;default:abort();}break;
 default:abort();}pending=3;
}
static u32 busy(void) {
 if(!pending)return 0;if(--pending)return 1U<<31;
 unsigned address=0;for(unsigned i=0;i<address_length;++i)address=(address<<8)|wire_tx[i];
 if(wire_rx)for(unsigned i=0;i<wire_rx;++i)regs[0x80+wire_len+i]=flash[(address+i)&255];
 else if(wire_opcode==2||wire_opcode==0x84)for(unsigned i=address_length;i<wire_len;++i)flash[(address+i-address_length)&255]=wire_tx[i];
 return 0;
}
static u8 readb(void *p) {return regs[offset(p,1)];}
static void writeb(u8 v,void *p) {unsigned at=offset(p,1);regs[at]=v;if(at==0x47&&(v&128)){regs[at]&=127;capture(regs[0x45]);}}
static u32 readl(void *p) {unsigned at=offset(p,4);u32 v=load32(at);if((version==1&&at==0)||(version==2&&at==0x4c))v=(v&~(1U<<31))|busy();return v;}
static void writel(u32 v,void *p) {unsigned at=offset(p,4);u32 stored=at==0?v&~((1U<<16)|(1U<<20)):v;memcpy(regs+at,&stored,4);if(at==0&&(v&(1U<<16)))capture(v&255);}
static u64 readq(void *p) {u64 v;memcpy(&v,regs+offset(p,8),8);return v;}
static void writeq(u64 v,void *p) {memcpy(regs+offset(p,8),&v,8);}
#define readl_poll_timeout(p,val,cond,delay,timeout) ({int result=-ETIMEDOUT;for(unsigned i=0;i<8;++i){(val)=readl(p);if(cond){result=0;break;}}result;})
static void amd_spi_hiddma_write(struct amd_spi *s,const struct spi_mem_op *o) {(void)s;(void)o;abort();}
static void amd_spi_hiddma_read(struct amd_spi *s,const struct spi_mem_op *o) {(void)s;(void)o;abort();}
'''
c += constants + "\n" + versions + "\n"
c += 'struct amd_spi {void *io_remap_addr;u64 phy_dma_buf;void *dma_virt_addr;enum amd_spi_versions version;unsigned speed_hz;};\n'
c += types + "\n" + "\n".join(functions)
c += r'''
static void hex(const u8 *data,unsigned length) {if(!length){putchar('-');return;}for(unsigned i=0;i<length;++i)printf("%02x",data[i]);}
int main(void) {
 const unsigned commands[]={3,0x0b,0x3b,0xbb,0x6b,0xeb,0x0c,0x3c,0xbc,0x6c,0xec,0x9f,2,0x84,6,0xa0};
 const unsigned sizes[]={1,7,8,9,31,63,64};
 const unsigned rates[]={0,799999,800000,900000,3169999,3170000,4000000,16660000,22220000,33330000,50000000,65000000,66660000,100000000,101000000};
 const unsigned maxima[]={20000000,65000000,100000000};
 unsigned serial=0;
 for(version=1;version<=2;++version)for(unsigned ci=0;ci<16;++ci)for(unsigned si=0;si<(ci>=14?1:7);++si)for(unsigned fi=0;fi<15;++fi)
 for(unsigned tx=1;tx<=4;tx*=2)for(unsigned rx=1;rx<=4;rx*=2) {
  unsigned opcode=commands[ci],direction=ci<12?SPI_MEM_DATA_IN:ci<14?SPI_MEM_DATA_OUT:SPI_MEM_NO_DATA;
  unsigned bytes=ci>=14?0:sizes[si],four=opcode==0x0c||opcode==0x3c||opcode==0xbc||opcode==0x6c||opcode==0xec;
  address_length=opcode==0x9f||opcode==6?0:opcode==0x84?2:opcode==0xa0?8:four?4:3;
  unsigned dummy=direction!=SPI_MEM_DATA_IN||opcode==3||opcode==0x9f?0:opcode==0xeb?3:opcode==0xec?2:1;
  u64 address=address_length==8?0x0102030405060708ULL:address_length==4?0x01020035:address_length==3?0x020035:address_length==2?0x2350:0;
  unsigned lanes=opcode==0xbb||opcode==0xbc?2:opcode==0xeb||opcode==0xec?4:1;
  unsigned receive=opcode==0x3b||opcode==0xbb||opcode==0x3c||opcode==0xbc?2:opcode==0x6b||opcode==0xeb||opcode==0x6c||opcode==0xec?4:1;
  memset(regs,0,sizeof regs);memset(wire_tx,0,sizeof wire_tx);pending=wire_len=wire_rx=wire_opcode=wire_chip=wire_hz=wire_mode=0;
  for(unsigned i=0;i<256;++i)flash[i]=(u8)(i*7);
  u64 buffer[8];u8 *data=(u8*)buffer;for(unsigned i=0;i<64;++i)data[i]=direction==SPI_MEM_DATA_IN?0xa5:(u8)(i*11+opcode);
  unsigned chip=serial%4,maximum=maxima[serial%3];u32 initial=0xa5a50000|(serial&1);memcpy(regs+0x50,&initial,4);regs[0x1d]=0x80;
  struct amd_spi controller={.io_remap_addr=regs,.version=version};
  const struct spi_controller_mem_caps caps={.per_op_freq=true};
  struct spi_controller host={.data=&controller,.min_speed_hz=800000,.mem_caps=&caps};
  unsigned mode=(tx==4?SPI_TX_QUAD:tx==2?SPI_TX_DUAL:0)|(rx==4?SPI_RX_QUAD:rx==2?SPI_RX_DUAL:0);
  struct spi_device device={.controller=&host,.max_speed_hz=maximum,.mode=mode};struct spi_mem memory={.spi=&device};
  struct spi_mem_op op={.cmd={.opcode=opcode,.nbytes=1,.buswidth=1},.addr={.val=address,.nbytes=address_length,.buswidth=lanes},.dummy={.nbytes=dummy,.buswidth=lanes},.data={.nbytes=bytes,.dir=direction,.buswidth=direction==SPI_MEM_DATA_IN?receive:1,.buf.in=data},.max_freq=rates[fi]};
  spi_mem_adjust_op_freq(&memory,&op);if(amd_spi_adjust_op_size(&memory,&op)||op.data.nbytes!=bytes)abort();
  bool supported=amd_spi_supports_op(&memory,&op);
  if(supported){amd_spi_select_chip(&controller,chip);if(amd_spi_exec_mem_op(&memory,&op))abort();if(amd_spi_busy_wait(&controller)||pending)abort();}
  printf("%c %u %u %u %u %u %u %u %u %u %llu %u %u %u ",supported?'M':'U',version,opcode,address_length,dummy,bytes,direction,rates[fi],maximum,chip,(unsigned long long)address,initial,wire_hz,wire_mode);
  hex(wire_tx,wire_len);putchar(' ');hex(data,direction==SPI_MEM_DATA_IN&&supported?bytes:0);putchar(' ');
  u8 changed[64];for(unsigned i=0;i<bytes;++i)changed[i]=flash[((unsigned)address+i)&255];hex(changed,direction==SPI_MEM_DATA_OUT&&supported?bytes:0);putchar(' ');
  for(unsigned i=0;i<64;++i)data[i]=(u8)(i*11+opcode);hex(data,direction==SPI_MEM_DATA_OUT?bytes:0);printf(" %u %u\n",tx,rx);++serial;
 }
 return 0;
}
'''
(out / "oracle.c").write_text(c)
compiler = shutil.which("clang") or shutil.which("gcc")
assert compiler
command = [compiler, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-Wno-sign-compare", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(out / "oracle.c"), "-o", str(out / "oracle")]
compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
(out / "compile.log").write_text(compiled.stdout + compiled.stderr)
compiled.check_returncode()
result = subprocess.run([str(out / "oracle")], capture_output=True, text=True, timeout=60)
(out / "stderr.log").write_text(result.stderr)
result.check_returncode()
(out / "records.txt").write_text(result.stdout)
assert len(result.stdout.splitlines()) == 27000
(out / "report.json").write_text(json.dumps(dict(pin=PIN, sources=HASHES, fragments=fragments, records=27000, operations=sum(line.startswith("M ") for line in result.stdout.splitlines()), command=command, output_sha256=hashlib.sha256(result.stdout.encode()).hexdigest(), limitations=[
    "MMIO, BUSY observation and a byte-addressed memory peripheral are modeled; no physical/electrical qualification",
    "Only AMD V1/V2; any HID2 branch aborts, no DMA or IRQ executes",
    "Input peripheral/controller admits standard one-byte SDR, no DTR/ECC/swap16; complete SPI memory frequency/width admission functions execute",
    "Source selector helper admits the fixture's requested chip before the memory hook, which does not select it itself; native integrates selection",
    "Source TX hook returns before BUSY completion; fixture drains through unchanged busy_wait; native waits within its whole-operation deadline",
    "Comparison captures wire address mode; native additionally restores the original address-mode epoch and preserves upper CS bits",
    "Only headers/data fitting70 FIFO bytes execute; native validates that combined bound and refuses write dummy phases instead of using source's ambiguous write-offset/count behavior",
    "Native access failures, deadline containment, ownership/mapping services and peripheral semantics beyond this tiny peer remain separate evidence",
]), indent=2)+"\n")
print(json.dumps(dict(records=27000, output=str(out / "records.txt"))))
