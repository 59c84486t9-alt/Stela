#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Original driver notices: Stephen Street / StreetFire Sound Labs (2005),
# Intel Corporation (2013,2021), Russell King (2003, SSP interface).
"""Run complete unchanged LPSS setup/CS/clock/word functions under sanitizers."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from amd_spi_oracle import declaration

PIN = "cc9de5d4b5ab6459f5774946aa3195ad51236fa8"
HASHES = {
    "drivers/spi/spi-pxa2xx.c": "986cc86352cf739b1ff25cd92921679005381fe57559f98d0338b5c3ba763e34",
    "drivers/spi/spi-pxa2xx.h": "011221bcaae0b8ca2634c3b2624b83b8a7bd94b37427fcd95548b3db705d5ec3",
    "include/linux/pxa2xx_ssp.h": "9d860f4d8e3ffac69864de02855739c00f8fc7d82e56f649bd5a528369423ff1",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    texts = {}
    for path, digest in HASHES.items():
        raw = (args.linux / path).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise SystemExit("pinned original source integrity mismatch: " + path)
        texts[path] = raw.decode()
    args.out.mkdir(parents=True, exist_ok=False)
    source = texts["drivers/spi/spi-pxa2xx.c"]
    header = texts["drivers/spi/spi-pxa2xx.h"]
    ssp = texts["include/linux/pxa2xx_ssp.h"]
    names = ["lpss_get_config", "is_lpss_ssp", "is_quark_x1000_ssp", "is_mrfld_ssp", "pxa2xx_spi_update", "pxa2xx_spi_txfifo_full", "pxa2xx_configure_sscr0", "__lpss_ssp_read_priv", "__lpss_ssp_write_priv", "__lpss_ssp_update_priv", "lpss_ssp_setup", "lpss_ssp_select_cs", "lpss_ssp_cs_control", "null_writer", "null_reader", "u8_writer", "u8_reader", "u16_writer", "u16_reader", "u32_writer", "u32_reader", "ssp_get_clk_div", "setup"]
    bodies = {}
    for name in ["pxa2xx_spi_read", "pxa2xx_spi_write", "read_SSSR_bits"]:
        match = re.search(r"^static inline [\w *]+\b" + name + r"\(", header, re.M)
        bodies[name] = declaration(header, match.group())
    for name in names:
        match = re.search(r"^static(?: inline)?[\w\s*]+\b" + name + r"\(", source, re.M)
        if not match:
            raise SystemExit("missing complete function: " + name)
        bodies[name] = declaration(source, match.group())
    constants = "\n".join(line for line in re.findall(r"^#define (?:SS\w*|QUARK_\w*|CE4100_\w*|RX_THRESH_\w*|TX_THRESH_\w*|SFIFO\w*|LPSS_\w*)[^\n]*", ssp + source, re.M) if not line.rstrip().endswith("\\"))
    types = "\n".join([
        declaration(ssp, "enum pxa_ssp_type {") + ";",
        declaration(source, "struct chip_data {") + ";",
        declaration(source, "struct lpss_config {") + ";",
        declaration(source, "static const struct lpss_config lpss_platforms[] = {") + ";",
    ])
    prefix = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef unsigned uint;
#define BIT(n) (1u<<(n))
#define GENMASK(hi,lo) ((~0u<<(lo))&(~0u>>(31-(hi))))
#define DIV_ROUND_UP(a,b) (((a)+(b)-1)/(b))
#define min(a,b) ((a)<(b)?(a):(b))
#define WARN_ON(x) do{if(x)abort();}while(0)
#define SPI_CPHA 1
#define SPI_CPOL 2
#define SPI_LOOP 32
#define dev_err(...) ((void)0)
#define GFP_KERNEL 0
#define kzalloc_obj(type) calloc(1,sizeof(type))
'''
    shim = r'''
struct ssp_device {enum pxa_ssp_type type;void *mmio_base;};
struct pxa2xx_spi_controller {unsigned enable_dma;};
struct spi_controller {void *data;u32 max_speed_hz;};
struct spi_device {struct spi_controller *controller;struct chip_data *chip;unsigned mode;u8 cs;};
struct driver_data {struct ssp_device *ssp;enum pxa_ssp_type ssp_type;struct spi_controller *controller;struct pxa2xx_spi_controller *controller_info;void *lpss_base;void *tx,*tx_end,*rx,*rx_end;u8 n_bytes;};
static void *spi_controller_get_devdata(struct spi_controller *c){return c->data;}
static void *spi_get_ctldata(struct spi_device *s){return s->chip;}
static void spi_set_ctldata(struct spi_device *s,struct chip_data *c){s->chip=c;}
static bool spi_controller_is_target(struct spi_controller *c){(void)c;return false;}
static u8 spi_get_chipselect(struct spi_device *s,unsigned i){if(i)abort();return s->cs;}
static u32 regs[0x900/4],wire[8],response[8],fifo[16];
static unsigned count,head,tail;static uint64_t delay_ns;
static unsigned at(void *p){uintptr_t offset=(uintptr_t)p-(uintptr_t)regs;if(offset&3||offset+4>sizeof regs)abort();return (unsigned)offset;}
static u32 readl(void *p){
    unsigned offset=at(p);
    if(offset==8)return (head!=tail?8u:0u)|4u;
    if(offset==0x10){if(head==tail)abort();return fifo[(head++)%16];}
    return regs[offset/4];
}
static void writel(u32 value,void *p){
    unsigned offset=at(p);
    if(offset==0x10){
        if(count>=8||tail-head>=16)abort();
        unsigned bits=(regs[0]&15)+1+((regs[0]&(1u<<20))?16:0);
        u32 mask=~0u>>(32-bits);wire[count]=value&mask;
        response[count]=((regs[1]&4)?value:((value<<1)|(value>>31))^0x5a5a5a5a)&mask;
        fifo[(tail++)%16]=response[count++];return;
    }
    if(offset!=8)regs[offset/4]=value;
}
static u32 pxa_ssp_read_reg(struct ssp_device *s,u32 offset){return readl((u8*)s->mmio_base+offset);}
static void pxa_ssp_write_reg(struct ssp_device *s,u32 offset,u32 value){writel(value,(u8*)s->mmio_base+offset);}
static void ndelay(unsigned n){delay_ns+=n;}
'''
    suffix = r'''
int main(void){
    static const unsigned bit_sizes[]={4,5,7,8,9,12,16,17,20,24,25,31,32};
    static const unsigned rates[]={50000000,25000000,4000000,1000000,12208,0xffffffffu};
    for(unsigned profile=0;profile<6;++profile){
        const struct lpss_config *p=&lpss_platforms[profile];
        printf("P,%u,%u,%d,%d,%u,%u,%u,%u,%u,%u\n",profile,p->offset,p->reg_cs_ctrl,p->reg_capabilities,p->rx_threshold,p->tx_threshold_lo,p->tx_threshold_hi,p->cs_sel_shift,p->cs_sel_mask,p->cs_clk_stays_gated);
        for(unsigned b=0;b<sizeof(bit_sizes)/sizeof(bit_sizes[0]);++b)
        for(unsigned mode=0;mode<4;++mode)for(unsigned direction=0;direction<3;++direction)
        for(unsigned rate=0;rate<sizeof(rates)/sizeof(rates[0]);++rate){
            memset(regs,0,sizeof regs);count=head=tail=0;delay_ns=0;
            regs[(p->offset+p->reg_cs_ctrl)/4]=0x80000042;regs[(p->offset+0x38)/4]=0x12345670;
            unsigned bits=bit_sizes[b],width=bits<=8?1:bits<=16?2:4;
            unsigned cs=p->cs_sel_mask?1:0;
            u32 tx[8]={0},rx[8];memset(rx,0xe7,sizeof rx);
            for(unsigned n=0;n<8;++n){u32 value=0x12345678+n*0x10101;memcpy((u8*)tx+n*width,&value,width);}
            struct ssp_device s={.type=LPSS_LPT_SSP+profile,.mmio_base=regs};
            struct pxa2xx_spi_controller info={0};struct chip_data chip={0};
            struct spi_controller controller={.max_speed_hz=50000000};
            struct driver_data d={.ssp=&s,.ssp_type=s.type,.controller=&controller,.controller_info=&info,.tx=tx,.tx_end=(u8*)tx+8*width,.rx=rx,.rx_end=(u8*)rx+8*width,.n_bytes=(u8)width};
            controller.data=&d;
            struct spi_device spi={.controller=&controller,.chip=&chip,.mode=mode|((bits%2==0)?SPI_LOOP:0),.cs=(u8)cs};
            if(setup(&spi))abort();lpss_ssp_setup(&d);lpss_ssp_cs_control(&spi,true);
            unsigned divider=ssp_get_clk_div(&d,rates[rate]);
            if(is_quark_x1000_ssp(&d))abort();
            pxa2xx_spi_update(&d,SSCR0,~0u,pxa2xx_configure_sscr0(&d,divider<<8,(u8)bits)|128);
            pxa2xx_spi_update(&d,SSCR1,~0u,chip.cr1|chip.threshold);
            int(*writer)(struct driver_data*)=direction==1?null_writer:width==1?u8_writer:width==2?u16_writer:u32_writer;
            int(*reader)(struct driver_data*)=direction==2?null_reader:width==1?u8_reader:width==2?u16_reader:u32_reader;
            while(writer(&d))reader(&d);
            if(!reader(&d)||count!=8||head!=tail)abort();
            lpss_ssp_cs_control(&spi,false);
            printf("W,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,",profile,bits,mode,direction,rates[rate],cs,regs[0],regs[1],chip.lpss_rx_threshold,chip.lpss_tx_threshold);
            for(unsigned n=0;n<8;++n)printf("%08x",wire[n]);
            putchar(',');if(direction!=2)for(unsigned n=0;n<8*width;++n)printf("%02x",((u8*)rx)[n]);
            printf(",%u,%llu\n",regs[(p->offset+p->reg_cs_ctrl)/4],(unsigned long long)delay_ns);
        }
    }
    return 0;
}
'''
    c_file = args.out / "oracle.c"
    c_file.write_text(prefix + constants + "\n" + types + "\n" + shim + "\n" + "\n".join(bodies.values()) + suffix)
    command = [args.cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(c_file), "-o", str(args.out / "oracle")]
    compiled = subprocess.run(command, capture_output=True, timeout=60)
    (args.out / "compiler.log").write_bytes(compiled.stdout + compiled.stderr)
    compiled.check_returncode()
    ran = subprocess.run([str((args.out / "oracle").resolve())], capture_output=True, timeout=60)
    (args.out / "trace.csv").write_bytes(ran.stdout)
    (args.out / "stderr.log").write_bytes(ran.stderr)
    ran.check_returncode()
    report = dict(pin=PIN, sources=HASHES, functions={name: hashlib.sha256(body.encode()).hexdigest() for name, body in bodies.items()}, records=len(ran.stdout.splitlines()), trace_sha256=hashlib.sha256(ran.stdout).hexdigest(), command=command, oracle_limits=["MMIO/clock/delay/framework/target/allocation services substituted; actual source LPSS setup/CS/clock/word functions unchanged", "Polled native transfer orchestration is independent of Linux IRQ/DMA orchestration; both consume actual complete source word helpers", "NULL-direction source pointer cursors advance over real dummy storage to avoid hosted NULL-pointer arithmetic; actual null_writer/null_reader stay unchanged", "No native PCI/ACPI/reset/remap/power/PM/electrical qualification; shared Mapping service separately qualified"])
    (args.out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(records=report["records"], functions=len(bodies), trace_sha256=report["trace_sha256"])))


if __name__ == "__main__":
    main()
