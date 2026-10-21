#!/usr/bin/env python3
"""Execute unchanged Linux NHI preparation helpers and exact PCI match table.

Usage: thunderbolt_controller_oracle.py PINNED_SOURCE_DIRECTORY OUTPUT_DIRECTORY
Generated C/binary/trace remain ignored. PCI/MMIO/clock captures model successful
reset and firmware startup. This is source effect evidence, not real PCI/ACPI,
IRQ handler drain, CM ownership, native IOMMU attachment or physical qualification.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import sys
source, out = map(Path, sys.argv[1:])
hashes = {
    "pci.c": "6a0269d971c416f3021b6b14176c776e81bd0fe42018ae559458007520c1d650",
    "nhi.c": "5b680a6d921d9f7ec5dd48e5348e645b1bdca66273119cc9b5bdece899a09169",
    "nhi.h": "f0026407a0005510e34cb331dba9b4a360bb93bdb5c63cd0cec0f2273fdc1e5c",
    "nhi_regs.h": "e98150dae51b46c1d83d92c0de0fe2b925e61e220a1a14d8cd200a153fc81e45",
    "include_linux_pci_ids.h": "020fac001871c0f8441c1294f787231fb6cfbf2c55915ca8f918262e2db4487c",
}
texts = {}
for name, digest in hashes.items():
    raw = (source / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, name
    texts[name] = raw.decode()
out.mkdir(parents=True, exist_ok=True)

def function(filename, name):
    text = texts[filename]
    match = re.search(r"^(?:static )?(?:void|int) [^;{}]*?\b" + name + r"\([^;{}]*?\)\n\{", text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    return text[match.start():at]

text = texts["pci.c"]
start = text.index("static struct pci_device_id nhi_ids[] = {")
at, depth = text.index("{", start) + 1, 1
while depth:
    depth += (text[at] == "{") - (text[at] == "}")
    at += 1
ids = text[start:at + 1]
names = re.findall(r"PCI_VDEVICE\(INTEL, (PCI_DEVICE_ID_\w+)\)", ids)
assert len(names) == 32
nhi_macros = "\n".join(line for line in texts["nhi.h"].splitlines() if line.startswith("#define PCI_") or line.startswith("#define QUIRK_"))
register_macros = "\n".join(line for line in texts["nhi_regs.h"].splitlines() if line.startswith("#define "))
prelude = r'''// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2018 Intel Corporation
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t ktime_t;
typedef uintptr_t kernel_ulong_t;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) ((~0U>>(31-(h)))&(~0U<<(l)))
#define FIELD_GET(mask,value) (((value)&(mask))>>__builtin_ctz(mask))
#define dev_dbg(...) ((void)0)
#define dev_warn(...) ((void)0)
#define PCI_ANY_ID (~0U)
#define PCI_VDEVICE(v,d) .vendor=PCI_VENDOR_ID_##v,.device=(d),.subvendor=PCI_ANY_ID,.subdevice=PCI_ANY_ID
#define PCI_DEVICE_CLASS(c,m) .vendor=PCI_ANY_ID,.device=PCI_ANY_ID,.subvendor=PCI_ANY_ID,.subdevice=PCI_ANY_ID,.class=(c),.class_mask=(m)
struct tb_nhi_ops { int unused; };
static const struct tb_nhi_ops icl_nhi_ops={0};
struct pci_device_id { u32 vendor,device,subvendor,subdevice,class,class_mask; kernel_ulong_t driver_data; };
struct pci_dev {u32 vendor,device,config[1024];};
struct tb_nhi {void *dev; unsigned char *iobase; unsigned quirks,hop_count;};
struct tb_nhi_pci {struct tb_nhi nhi;};
#define to_pci_dev(dev) ((struct pci_dev *)(dev))
static unsigned char bar[0x40000] __attribute__((aligned(4)));
static struct pci_dev pdev;
static struct tb_nhi_pci host;
static u32 enables[128],pending[128];
static unsigned pc,nm;
static struct {unsigned offset;u32 value;} plog[16],mlog[256];
static ktime_t now,reset_clear_at,ready_at;
static ktime_t ktime_get(void){return now;}
static ktime_t ktime_add_ms(ktime_t a,unsigned b){return a+b;}
static bool ktime_before(ktime_t a,ktime_t b){return a<b;}
static void msleep(unsigned ms){now+=ms;}
static void usleep_range(unsigned a,unsigned b){(void)b;now+=(a+999)/1000;}
static bool host_reset=true;
'''
stubs = r'''
static int pci_read_config_dword(struct pci_dev *p,unsigned offset,u32 *value){*value=p->config[offset/4];if(offset==VS_CAP_9 && now>=ready_at)*value|=VS_CAP_9_FW_READY;return 0;}
static int pci_write_config_dword(struct pci_dev *p,unsigned offset,u32 value){if(pc>=16)abort();plog[pc].offset=offset;plog[pc++].value=value;p->config[offset/4]=value;if(offset==VS_CAP_22 && value&VS_CAP_22_FORCE_POWER)ready_at=now+6;return 0;}
static u32 ioread32(const void *pointer){
    size_t offset=(const unsigned char *)pointer-bar;
    if(offset>=sizeof(bar))abort();
    if(offset>=REG_RING_INTERRUPT_BASE && offset<REG_RING_INTERRUPT_BASE+4*RING_INTERRUPT_REG_COUNT((&host.nhi)))return enables[(offset-REG_RING_INTERRUPT_BASE)/4];
    if(offset>=REG_RING_NOTIFY_BASE && offset<REG_RING_NOTIFY_BASE+4*RING_NOTIFY_REG_COUNT((&host.nhi))){unsigned i=(offset-REG_RING_NOTIFY_BASE)/4;u32 v=pending[i];if(host.nhi.quirks&QUIRK_AUTO_CLEAR_INT)pending[i]=0;return v;}
    if(offset==REG_RESET && now>=reset_clear_at)*(u32*)(bar+REG_RESET)=0;
    return *(const u32*)pointer;
}
static void iowrite32(u32 value,void *pointer){
    size_t offset=(unsigned char*)pointer-bar;if(offset>=sizeof(bar)||nm>=256)abort();mlog[nm].offset=offset;mlog[nm++].value=value;
    if(!(host.nhi.quirks&QUIRK_AUTO_CLEAR_INT) && offset>=REG_RING_INTERRUPT_MASK_CLEAR_BASE && offset<REG_RING_INTERRUPT_MASK_CLEAR_BASE+4*RING_INTERRUPT_REG_COUNT((&host.nhi))){enables[(offset-REG_RING_INTERRUPT_MASK_CLEAR_BASE)/4]&=~value;return;}
    if((host.nhi.quirks&QUIRK_AUTO_CLEAR_INT) && offset>=REG_RING_INTERRUPT_BASE && offset<REG_RING_INTERRUPT_BASE+4*RING_INTERRUPT_REG_COUNT((&host.nhi))){enables[(offset-REG_RING_INTERRUPT_BASE)/4]=value;return;}
    if(!(host.nhi.quirks&QUIRK_AUTO_CLEAR_INT) && offset>=REG_RING_INT_CLEAR && offset<REG_RING_INT_CLEAR+4*RING_NOTIFY_REG_COUNT((&host.nhi))){pending[(offset-REG_RING_INT_CLEAR)/4]&=~value;return;}
    *(u32*)pointer=value;if(offset==REG_RESET)reset_clear_at=now+50;
}
'''
main = r'''
static const struct pci_device_id *match(unsigned vendor,unsigned device,unsigned class){
    for(const struct pci_device_id *id=nhi_ids;id->vendor||id->device||id->class;id++)if((id->vendor==vendor||id->vendor==PCI_ANY_ID)&&(id->device==device||id->device==PCI_ANY_ID)&&((id->class^class)&id->class_mask)==0)return id;
    return NULL;
}
int main(void){
    unsigned devices[]={DEVICE_LIST};unsigned versions[]={0x20,0x40},hops[]={8,16,33,64,1023};
    for(unsigned d=0;d<sizeof(devices)/sizeof(devices[0])+3;d++)for(unsigned v=0;v<2;v++)for(unsigned h=0;h<5;h++){
        memset(&pdev,0,sizeof(pdev));memset(&host,0,sizeof(host));memset(bar,0,sizeof(bar));memset(plog,0,sizeof(plog));memset(mlog,0,sizeof(mlog));
        unsigned vendor=d<sizeof(devices)/sizeof(devices[0])?0x8086:(d==sizeof(devices)/sizeof(devices[0])?0x1022:(d==sizeof(devices)/sizeof(devices[0])+1?0x1b21:0x8086));
        unsigned device=d<sizeof(devices)/sizeof(devices[0])?devices[d]:(vendor==0x1022?0x1668:(vendor==0x1b21?0x2426:0x1137));unsigned class=0x0c0340;
        const struct pci_device_id *id=match(vendor,device,class);if(!id)abort();
        pdev.vendor=vendor;pdev.device=device;pdev.config[VS_CAP_22/4]=0x98ab5678;pdev.config[VS_CAP_16/4]=0xdead1234;
        host.nhi.dev=&pdev;host.nhi.iobase=bar;host.nhi.hop_count=hops[h];*(u32*)(bar+REG_CAPS)=(versions[v]<<16)|hops[h];for(unsigned i=0;i<128;i++)enables[i]=pending[i]=~0U;
        now=pc=nm=0;reset_clear_at=ready_at=~0ULL;nhi_pci_check_quirks(&host);
        nhi_reset(&host.nhi);nhi_disable_interrupts(&host.nhi);if(id->driver_data && icl_nhi_resume(&host.nhi))abort();
        unsigned family=id->driver_data?1:(id->class_mask?2:0);
        printf("C %u %u %u %u %u %u %u",vendor,device,class,versions[v],hops[h],family,pc);for(unsigned i=0;i<pc;i++)printf(" %u %u",plog[i].offset,plog[i].value);printf(" %u",nm);for(unsigned i=0;i<nm;i++)printf(" %u %u",mlog[i].offset,mlog[i].value);puts("");
    }
    return 0;
}
'''.replace("DEVICE_LIST", ",".join(names))
unit = out / "linux-thunderbolt-controller.c"
functions = [function("pci.c", "nhi_pci_check_quirks"),function("nhi.c", "nhi_mask_interrupt"),function("nhi.c", "nhi_clear_interrupt"),function("nhi.c", "nhi_disable_interrupts"),function("nhi.c", "nhi_reset"),function("pci.c", "icl_nhi_force_power"),function("pci.c", "icl_nhi_set_ltr"),function("pci.c", "icl_nhi_resume")]
unit.write_text(prelude + texts["include_linux_pci_ids.h"] + nhi_macros + "\n" + register_macros + stubs + "\n".join(functions) + ids + main)
exe = out / "linux-thunderbolt-controller"
subprocess.run(["cc", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined", str(unit), "-o", str(exe)], check=True)
trace = out / "trace.txt"
with trace.open("wb") as stream:
    subprocess.run([str(exe.resolve())], stdout=stream, check=True)
print(f"{trace}: {hashlib.sha256(trace.read_bytes()).hexdigest()}")
