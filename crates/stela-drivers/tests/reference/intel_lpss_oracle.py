#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2015 Intel Corporation; original source authors are retained below.
"""Execute unchanged pinned Intel LPSS reset/remap helpers under sanitizers.

Donor authors: Andy Shevchenko, Mika Westerberg, Heikki Krogerus, Jarkko Nikula.
Only ordered MMIO services and the source structure declarations are substituted.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

PIN = "a804c5742bff224d4cb4d25dd383554d598be32b"
SOURCE = "drivers/mfd/intel-lpss.c"
SHA256 = "45df525f3ff3284273db07abeb332216abea6116f713c4149b3b07b17ca654ed"
DONORS = {
    SOURCE: SHA256,
    "drivers/mfd/intel-lpss.h": "9620923ce932a9d22bc2bdee5a0cc0e2e7a637b240df7adc83612abceffd7c1a",
    "drivers/mfd/intel-lpss-pci.c": "dc160da049c264330fac485e91bcce3fb02d9d27ce7a6d1586bad74a7cfc4056",
    "drivers/mfd/intel-lpss-acpi.c": "70aed09645bc86a78b2662e7e72bcfe0f9e350a7c62fdea120fb37754aacc244",
    "drivers/acpi/x86/lpss.c": "9bb9afed6c5f9a2081acc208c239f97237a3c2870e290384baac82ba8c0234da",
}


def function(source, marker):
    start = source.index(marker)
    opened = source.index("{", start)
    end, depth = opened + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def profile_oracle(source, out, cc):
    # Compile the complete unchanged declarations (all properties, info groups
    # and PCI rows). Substitute only kernel POD/property/table services; no
    # device or property result is generated from the Rust implementation.
    start = source.index("static const struct property_entry spt_spi_properties[]")
    table = source.index("static const struct pci_device_id intel_lpss_pci_ids[]", start)
    end = source.index("\n};", table) + len("\n};")
    declarations = source[start:end]
    prefix = r"""
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uintptr_t kernel_ulong_t;
struct property_entry {const char *name;uint32_t value;};
struct software_node {const struct property_entry *properties;};
struct intel_lpss_platform_info {uint32_t clk_rate;const char *clk_con_id;const struct software_node *swnode;};
struct pci_device_id {unsigned vendor,device;kernel_ulong_t driver_data;};
#define PROPERTY_ENTRY_U32(name,value) {name,value}
#define PROPERTY_ENTRY_BOOL(name) {name,1}
#define PCI_VDEVICE(vend,id) .vendor=0x8086,.device=id
/* Non-I2C SSP type metadata is never selected or executed by this oracle. */
#define LPSS_SPT_SSP 1
#define LPSS_BXT_SSP 2
#define LPSS_CNL_SSP 3
"""
    suffix = r"""
static uint32_t property(const struct intel_lpss_platform_info *info,const char *name) {
    for(const struct property_entry *p=info->swnode->properties;p->name;++p)
        if(!strcmp(p->name,name))return p->value;
    return UINT32_MAX;
}
int main(void) {
    for(const struct pci_device_id *id=intel_lpss_pci_ids;id->device;++id) {
        const struct intel_lpss_platform_info *info=(const void *)id->driver_data;
        if(info!=&spt_i2c_info && info!=&cnl_i2c_info && info!=&bxt_i2c_info &&
           info!=&apl_i2c_info && info!=&glk_i2c_info && info!=&ehl_i2c_info)continue;
        printf("%u,%u,%u,%u,%u\n",id->device,info->clk_rate,
            property(info,"i2c-sda-hold-time-ns"),
            property(info,"i2c-sda-falling-time-ns"),
            property(info,"i2c-scl-falling-time-ns"));
    }
    return 0;
}
"""
    path = out / "profile-oracle.c"
    path.write_text(prefix + declarations + suffix)
    command = [cc, "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined",
               "-fno-sanitize-recover=all", str(path), "-o", str(out / "profile-oracle")]
    (out / "profile-compiler-command.json").write_text(json.dumps(command) + "\n")
    compiled = subprocess.run(command, capture_output=True, timeout=120)
    (out / "profile-compiler-stdout.txt").write_bytes(compiled.stdout)
    (out / "profile-compiler-stderr.txt").write_bytes(compiled.stderr)
    compiled.check_returncode()
    run = subprocess.run([str((out / "profile-oracle").resolve())], capture_output=True, timeout=60)
    (out / "profiles.csv").write_bytes(run.stdout)
    (out / "profile-stderr.txt").write_bytes(run.stderr)
    run.check_returncode()
    count = len(run.stdout.splitlines())
    if count != 190:
        raise SystemExit(f"unexpected actual-source PCI I2C count: {count}")
    return {"declarations_sha256": hashlib.sha256(declarations.encode()).hexdigest(),
            "profiles": count, "trace_sha256": hashlib.sha256(run.stdout).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    sources = {}
    for source, expected in DONORS.items():
        raw = subprocess.check_output(
            ["git", "-C", str(args.linux.resolve()), "show", f"{PIN}:{source}"], timeout=30
        )
        if hashlib.sha256(raw).hexdigest() != expected:
            raise SystemExit(f"pinned source hash mismatch: {source}")
        sources[source] = raw
        saved = args.out / "donors" / source
        saved.parent.mkdir(parents=True, exist_ok=True)
        saved.write_bytes(raw)
    raw = sources[SOURCE]
    (args.out / "intel-lpss.c").write_bytes(raw)
    markers = ["static bool intel_lpss_has_idma(", "static void intel_lpss_set_remap_addr(", "static void intel_lpss_deassert_reset(", "static void intel_lpss_init_dev("]
    bodies = [function(raw.decode(), marker) for marker in markers]
    prefix = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t u32;
typedef uint64_t resource_size_t;
#define BIT(n) (1U<<(n))
#define LPSS_PRIV_RESETS 0x04
#define LPSS_PRIV_RESETS_IDMA BIT(2)
#define LPSS_PRIV_RESETS_FUNC 0x3
#define LPSS_PRIV_REMAP_ADDR 0x40
#define LPSS_PRIV_CAPS_NO_IDMA BIT(8)
#define LPSS_PRIV_SSP_REG 0x20
#define LPSS_PRIV_SSP_REG_DIS_DMA_FIN BIT(0)
enum intel_lpss_dev_type {LPSS_DEV_I2C,LPSS_DEV_UART,LPSS_DEV_SPI};
struct resource {resource_size_t start;};
struct intel_lpss_platform_info {struct resource *mem;};
struct intel_lpss {
    const struct intel_lpss_platform_info *info;
    enum intel_lpss_dev_type type;
    void *priv;
    u32 caps;
};
static unsigned regs[64],offsets[8],count;
static u32 values[8];
static void writel(u32 value,void *pointer) {
    uintptr_t offset=(uintptr_t)pointer-(uintptr_t)regs;
    if(offset>=sizeof regs || offset%4 || count>=8)abort();
    offsets[count]=offset;values[count++]=value;regs[offset/4]=value;
}
static void lo_hi_writeq(uint64_t value,void *pointer) {
    writel((u32)value,pointer);writel((u32)(value>>32),(unsigned char*)pointer+4);
}
'''
    suffix = r'''
int main(void) {
    const uint64_t bases[]={0x80000000ULL,0x100000000ULL,0x123450000ULL,0x7fffe1234000ULL};
    for(unsigned type=0;type<3;++type)for(unsigned absent=0;absent<2;++absent)
    for(unsigned old=0;old<256;++old)for(unsigned b=0;b<4;++b) {
        memset(regs,0xa5,sizeof regs);regs[1]=old;count=0;
        struct resource mem={.start=bases[b]};
        struct intel_lpss_platform_info info={.mem=&mem};
        struct intel_lpss lpss={.info=&info,.type=type,.priv=regs,.caps=(type<<4)|(absent?BIT(8):0)};
        intel_lpss_init_dev(&lpss);
        printf("%u,%u,%u,%llu",type,absent,old,(unsigned long long)bases[b]);
        for(unsigned n=0;n<count;++n)printf(",%u:%u",offsets[n],values[n]);
        putchar('\n');
    }
    return 0;
}
'''
    path = args.out / "oracle.c"
    path.write_text(prefix + "\n".join(bodies) + suffix)
    command = [args.cc, "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(path), "-o", str(args.out / "oracle")]
    (args.out / "compiler-command.json").write_text(json.dumps(command) + "\n")
    compiled = subprocess.run(command, capture_output=True, timeout=120)
    (args.out / "compiler-stdout.txt").write_bytes(compiled.stdout)
    (args.out / "compiler-stderr.txt").write_bytes(compiled.stderr)
    compiled.check_returncode()
    run = subprocess.run([str((args.out / "oracle").resolve())], capture_output=True, timeout=60)
    (args.out / "trace.csv").write_bytes(run.stdout)
    (args.out / "stderr.txt").write_bytes(run.stderr)
    run.check_returncode()
    receipt = {"pin": PIN, "source": SOURCE, "source_sha256": SHA256, "donors": DONORS,
               "functions": {marker: hashlib.sha256(body.encode()).hexdigest() for marker, body in zip(markers, bodies)},
               "cases": len(run.stdout.splitlines()), "trace_sha256": hashlib.sha256(run.stdout).hexdigest(),
               "oracle_limits": ["Four unchanged private reset/remap helpers; source I2C/UART/SPI type, optional IDMA and old reset/base variation; complete unchanged PCI properties/info/table declarations report all190 exact I2C profiles",
                                 "MMIO/structure services substituted; no PCI, AML, IRQ, child clock/timing, power, DMA, physical or lifecycle qualification",
                                 "Native source scope may admit only I2C; no UART/SPI implementation credit from these donor cases"]}
    receipt["pci_profiles"] = profile_oracle(sources["drivers/mfd/intel-lpss-pci.c"].decode(), args.out, args.cc)
    (args.out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
