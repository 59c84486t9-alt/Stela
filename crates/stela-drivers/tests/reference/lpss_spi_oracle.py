#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Source notices: Intel Corporation (2014,2015); Canonical Ltd (2010-2011),
# Mike Turquette / Linaro Ltd (2011-2012). See bus/THIRD_PARTY.md.
"""Compile unchanged PCI SPI inventory, private reset and clock functions."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from amd_spi_oracle import declaration

PIN = "cc9de5d4b5ab6459f5774946aa3195ad51236fa8"
HASHES = {
    "drivers/mfd/intel-lpss.c": "45df525f3ff3284273db07abeb332216abea6116f713c4149b3b07b17ca654ed",
    "drivers/mfd/intel-lpss-pci.c": "dc160da049c264330fac485e91bcce3fb02d9d27ce7a6d1586bad74a7cfc4056",
    "drivers/clk/clk-fractional-divider.c": "c842f59f7194b226868fd4f25695ff1fb8e131417c345fb37b14dfbd72250b7f",
    "drivers/clk/clk-gate.c": "60eb418cb5522b9713ffd294b16dda37942fda3ad8729ce33e30de5497708860",
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
    bodies = {}
    for path, markers in [
        ("drivers/mfd/intel-lpss.c", ["static bool intel_lpss_has_idma(", "static void intel_lpss_set_remap_addr(", "static void intel_lpss_deassert_reset(", "static void intel_lpss_init_dev("]),
        ("drivers/clk/clk-fractional-divider.c", ["static inline u32 clk_fd_readl(", "static void clk_fd_get_div(", "static unsigned long clk_fd_recalc_rate("]),
        ("drivers/clk/clk-gate.c", ["static inline u32 clk_gate_readl(", "static inline void clk_gate_writel(", "static void clk_gate_endisable("]),
    ]:
        for marker in markers:
            bodies[marker] = declaration(texts[path], marker)
    source = texts["drivers/mfd/intel-lpss-pci.c"]
    start = source.index("static const struct property_entry spt_spi_properties[]")
    table = source.index("static const struct pci_device_id intel_lpss_pci_ids[]", start)
    end = source.index("\n};", table) + len("\n};")
    inventory = source[start:end]
    prefix = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;typedef uint64_t u64;typedef uint64_t resource_size_t;typedef uintptr_t kernel_ulong_t;
#define BIT(n) (1u<<(n))
#define GENMASK(hi,lo) ((~0u<<(lo))&(~0u>>(31-(hi))))
#define do_div(value,divisor) ((value)/=(divisor))
#define spin_lock_irqsave(lock,flags) ((void)(lock),(flags)=0)
#define spin_unlock_irqrestore(lock,flags) ((void)(lock),(void)(flags))
#define __acquire(lock) ((void)(lock))
#define __release(lock) ((void)(lock))
struct property_entry {const char *name;u32 value;};
struct software_node {const struct property_entry *properties;};
struct resource {resource_size_t start;};
struct intel_lpss_platform_info {u32 clk_rate;const char *clk_con_id;const struct software_node *swnode;struct resource *mem;};
struct pci_device_id {unsigned vendor,device;kernel_ulong_t driver_data;};
#define PROPERTY_ENTRY_U32(name,value) {name,value}
#define PROPERTY_ENTRY_BOOL(name) {name,1}
#define PCI_VDEVICE(vend,id) .vendor=0x8086,.device=id
#define LPSS_SPT_SSP 14
#define LPSS_BXT_SSP 15
#define LPSS_CNL_SSP 16
#define LPSS_PRIV_RESETS 4
#define LPSS_PRIV_RESETS_FUNC 3
#define LPSS_PRIV_RESETS_IDMA 4
#define LPSS_PRIV_REMAP_ADDR 0x40
#define LPSS_PRIV_CAPS_NO_IDMA BIT(8)
#define LPSS_PRIV_SSP_REG 0x20
#define LPSS_PRIV_SSP_REG_DIS_DMA_FIN 1
enum intel_lpss_dev_type {LPSS_DEV_I2C,LPSS_DEV_UART,LPSS_DEV_SPI};
struct intel_lpss {const struct intel_lpss_platform_info *info;enum intel_lpss_dev_type type;void *priv;u32 caps;};
struct clk_hw {void *owner;};struct u32_fract {u32 numerator,denominator;};
struct clk_fractional_divider {struct clk_hw hw;void *reg,*lock;unsigned flags,mshift,mwidth,nshift,nwidth;};
struct clk_gate {struct clk_hw hw;void *reg,*lock;unsigned flags,bit_idx;};
#define to_clk_fd(hw) ((struct clk_fractional_divider*)(hw)->owner)
#define to_clk_gate(hw) ((struct clk_gate*)(hw)->owner)
/* Fixed LPSS little-endian/nonzero-based/no-inversion path. Alternate flag
 * services compile unchanged branches but are not an exercised qualification. */
#define CLK_FRAC_DIVIDER_ZERO_BASED 1
#define CLK_FRAC_DIVIDER_BIG_ENDIAN 2
#define CLK_GATE_SET_TO_DISABLE 1
#define CLK_GATE_HIWORD_MASK 2
#define CLK_GATE_BIG_ENDIAN 4
static u32 reset_regs[64],offsets[8],values[8];static unsigned count;
static u32 readl(void *p){return *(u32*)p;}
static void writel(u32 value,void *p){
    uintptr_t at=(uintptr_t)p-(uintptr_t)reset_regs;
    if(at<sizeof reset_regs){if(at%4||count>=8)abort();offsets[count]=(u32)at;values[count++]=value;}
    *(u32*)p=value;
}
static u32 ioread32be(void *p){return __builtin_bswap32(readl(p));}
static void iowrite32be(u32 value,void *p){writel(__builtin_bswap32(value),p);}
static void lo_hi_writeq(u64 value,void *p){writel((u32)value,p);writel((u32)(value>>32),(unsigned char*)p+4);}
'''
    suffix = r'''
static u32 property(const struct intel_lpss_platform_info *info,const char *name){
    for(const struct property_entry *p=info->swnode->properties;p->name;++p)if(!strcmp(p->name,name))return p->value;
    return 0;
}
int main(void){
    for(const struct pci_device_id *id=intel_lpss_pci_ids;id->device;++id){
        const struct intel_lpss_platform_info *info=(const void*)id->driver_data;
        if(info!=&spt_spi_info&&info!=&bxt_spi_info&&info!=&cnl_spi_info&&info!=&tgl_spi_info)continue;
        printf("P,%u,%u,%u\n",id->device,info->clk_rate,property(info,"intel,spi-pxa2xx-type"));
    }
    const u64 bases[]={0x80000000ULL,0x100000000ULL,0x123450000000ULL,0x7fffe1234000ULL};
    for(unsigned absent=0;absent<2;++absent)for(unsigned b=0;b<4;++b){
        memset(reset_regs,0xa5,sizeof reset_regs);count=0;
        struct resource resource={.start=bases[b]};struct intel_lpss_platform_info info={.mem=&resource};
        struct intel_lpss lpss={.info=&info,.type=LPSS_DEV_SPI,.priv=reset_regs,.caps=(2<<4)|(absent?BIT(8):0)};
        intel_lpss_init_dev(&lpss);
        printf("R,%u,%llu",absent,(unsigned long long)bases[b]);
        for(unsigned n=0;n<count;++n)printf(",%u:%u",offsets[n]+0x200,values[n]);putchar('\n');
    }
    const u32 roots[]={100000000,120000000};
    const unsigned pairs[][2]={{0,0},{0,1},{1,0},{1,1},{1,2},{1,3},{2,3},{3,2},{32767,32767},{32767,1}};
    for(unsigned root=0;root<2;++root)for(unsigned pair=0;pair<10;++pair)for(unsigned enabled=0;enabled<2;++enabled){
        u32 clock=(pairs[pair][0]<<1)|(pairs[pair][1]<<16)|(enabled?0x80000001u:0);
        u32 original=clock;
        struct clk_fractional_divider divider={.reg=&clock,.mshift=1,.mwidth=15,.nshift=16,.nwidth=15};divider.hw.owner=&divider;
        unsigned long rate=clk_fd_recalc_rate(&divider.hw,roots[root]);
        struct clk_gate gate={.reg=&clock,.bit_idx=0};gate.hw.owner=&gate;
        clk_gate_endisable(&gate.hw,1);u32 on0=clock;
        gate.bit_idx=31;clk_gate_endisable(&gate.hw,1);u32 on31=clock;
        clk_gate_endisable(&gate.hw,0);u32 off31=clock;
        gate.bit_idx=0;clk_gate_endisable(&gate.hw,0);u32 off0=clock;
        printf("C,%u,%u,%llu,%u,%u,%u,%u\n",roots[root],original,(unsigned long long)rate,on0,on31,off31,off0);
    }
    return 0;
}
'''
    path = args.out / "oracle.c"
    path.write_text(prefix + inventory + "\n" + "\n".join(bodies.values()) + suffix)
    command = [args.cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(path), "-o", str(args.out / "oracle")]
    compiled = subprocess.run(command, capture_output=True, timeout=60)
    (args.out / "compiler.log").write_bytes(compiled.stdout + compiled.stderr)
    compiled.check_returncode()
    ran = subprocess.run([str((args.out / "oracle").resolve())], capture_output=True, timeout=60)
    (args.out / "trace.csv").write_bytes(ran.stdout)
    (args.out / "stderr.log").write_bytes(ran.stderr)
    ran.check_returncode()
    report = dict(pin=PIN, sources=HASHES, functions={name:hashlib.sha256(body.encode()).hexdigest() for name,body in bodies.items()}, inventory_sha256=hashlib.sha256(inventory.encode()).hexdigest(), records=len(ran.stdout.splitlines()), trace_sha256=hashlib.sha256(ran.stdout).hexdigest(), command=command, oracle_limits=["Complete original PCI property/info/table declarations and ten unchanged private-reset/clock functions; kernel POD,locking,MMIO and fixed LPSS flag services substituted", "Native gate/reset retirement faults and real original Function/Mapping retirement are separate models; no controller, board, electrical, PM, IRQ or DMA qualification"])
    (args.out / "report.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(dict(records=report["records"], functions=len(bodies), trace_sha256=report["trace_sha256"])))


if __name__=="__main__":
    main()
