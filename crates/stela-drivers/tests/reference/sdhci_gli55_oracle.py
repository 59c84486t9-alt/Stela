#!/usr/bin/env python3
"""Execute unchanged GL9755 PCI PHY/PLL, dual-power and reset functions.

Usage: sdhci_gli55_oracle.py VERIFIED_DONOR_DIRECTORY FRESH_OUTPUT_DIRECTORY
PCI/MMIO accessors, elapsed delays, common clock-enable and power transition
services are modeled. No physical power, DMA, IRQ or UHS-II transport executes.
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
    "drivers/mmc/host/sdhci.c": "186305e102bd32df419ff80669e6018d6b3a9e4310c3101193413970355b9857",
    "drivers/mmc/host/sdhci.h": "4b3a252cecc039b22e56c37ec95ad2959bee52934594666708c4a7f118afe4af",
    "drivers/mmc/host/sdhci-uhs2.h": "828ac888b5abaa5cbef581a2f11b187d6443380efc35c1e5ca7a093b631d9c27",
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


def function(path, name):
    text = texts[path]
    match = re.search(r"^(?:static )?(?:inline )?(?:void|bool|u16|int) " + name + r"\([^;{}]*\)\n\{", text, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    body = text[match.start():end]
    fragments.append(dict(path=path, name=name, start=match.start(), end=end,
                          sha256=hashlib.sha256(body.encode()).hexdigest()))
    return body


gli = "drivers/mmc/host/sdhci-pci-gli.c"
bodies = [function("drivers/mmc/host/sdhci.c", "sdhci_calc_clk")]
bodies += [function(gli, name) for name in [
    "gl9755_wt_on", "gl9755_wt_off", "gl9755_disable_ssc_pll", "gl9755_set_pll",
    "gl9755_ssc_enable", "gl9755_set_ssc", "gl9755_set_ssc_pll_205mhz",
    "gl9755_set_ssc_pll_100mhz", "gl9755_set_ssc_pll_50mhz", "sdhci_gl9755_set_clock",
    "gl9755_hw_setting", "gl9755_vendor_init", "sdhci_gli_overcurrent_event_enable",
    "gl9755_set_power", "sdhci_wait_clock_stable", "sdhci_gli_enable_internal_clock",
    "sdhci_gli_wait_software_reset_done", "sdhci_gli_uhs2_reset_sd_tran", "sdhci_gl9755_reset",
]]
definitions = {}
for text in texts.values():
    for match in re.finditer(r"^#define\s+([A-Za-z][A-Za-z0-9_]+)\s+(.+)$", text.replace("\\\n", ""), re.M):
        definitions[match[1]] = match[2]
pattern = r"\b(?:SDHCI|MMC|PCI_GLI|GLI)_[A-Za-z0-9_]+\b"
names = set(re.findall(pattern, "\n".join(bodies)))
names -= {"MMC_POWER_OFF"}
while True:
    previous = set(names)
    for name in previous:
        assert name in definitions, name
        names.update(re.findall(pattern, definitions[name]))
    if names == previous:
        break
macros = "\n".join("#define " + name + " " + definitions[name] for name in sorted(names))
c = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
#define BIT(n) (1U << (n))
#define GENMASK(h,l) ((~0U << (l)) & (~0U >> (31-(h))))
#define FIELD_GET(m,v) (((v)&(m)) >> __builtin_ctz(m))
#define FIELD_PREP(m,v) (((u32)(v) << __builtin_ctz(m)) & (m))
#define max_t(t,a,b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define pr_err(...) ((void)0)
#define WARN(...) ((void)0)
#define mmc_hostname(x) "GL9755-oracle"
#define MMC_POWER_OFF 0
#define PCI_D3hot 3
#define PCI_D0 0
struct pci_dev { u32 regs[1024]; struct { void *of_node; } dev; };
struct sdhci_pci_chip { struct pci_dev *pdev; };
struct sdhci_pci_slot { struct sdhci_pci_chip *chip; };
struct mmc_ios {unsigned timing;};
struct mmc_host {struct mmc_ios ios; unsigned actual_clock; bool uhs2_sd_tran;};
struct sdhci_host {
    u32 regs[0x300/4]; struct mmc_host *mmc; struct sdhci_pci_slot *slot;
    unsigned version,max_clk,clk_mul,quirks2,clock,ier,pwr; bool preset_enabled;
    unsigned power[4],time[4],count,elapsed,resets;
};
static struct sdhci_host *current;
static struct sdhci_pci_slot *sdhci_priv(struct sdhci_host *h) {return h->slot;}
static bool of_property_read_bool(void *node,const char *name) {(void)node;(void)name;return false;}
static void pci_read_config_dword(struct pci_dev *d,unsigned at,u32 *v) {*v=d->regs[at/4];}
static void pci_write_config_dword(struct pci_dev *d,unsigned at,u32 v) {d->regs[at/4]=v;}
static void pci_set_power_state(struct pci_dev *d,unsigned state) {(void)d;(void)state;}
static void sdhci_gli_mask_replay_timer_timeout(struct pci_dev *d) {(void)d;}
static u32 sdhci_readl(struct sdhci_host *h,unsigned at) {return h->regs[at/4];}
static u16 sdhci_readw(struct sdhci_host *h,unsigned at) {return (u16)(h->regs[at/4] >> ((at&3)*8));}
static u8 sdhci_readb(struct sdhci_host *h,unsigned at) {return (u8)(h->regs[at/4] >> ((at&3)*8));}
static void sdhci_writel(struct sdhci_host *h,u32 v,unsigned at) {h->regs[at/4]=v;}
static void sdhci_writew(struct sdhci_host *h,u16 v,unsigned at) {
    if (at==0x2c && (v&1)) v|=2;
    unsigned shift=(at&3)*8; h->regs[at/4]=(h->regs[at/4]&~(65535U<<shift))|((u32)v<<shift);
}
static void sdhci_writeb(struct sdhci_host *h,u8 v,unsigned at) {
    if (at==0x29) {h->power[h->count]=v;h->time[h->count++]=h->elapsed;}
    if (at==0x2f) {++h->resets;v=0;}
    unsigned shift=(at&3)*8;h->regs[at/4]=(h->regs[at/4]&~(255U<<shift))|((u32)v<<shift);
}
static void mdelay(unsigned n) {current->elapsed+=n;}
static void sdhci_enable_clk(struct sdhci_host *h,u16 v) {sdhci_writew(h,v|7,0x2c);}
static u16 sdhci_get_preset_value(struct sdhci_host *h) {(void)h; return 0;}
static u8 sdhci_get_vdd_value(unsigned vdd) {return (u8)vdd;}
static void sdhci_dumpregs(struct sdhci_host *h) {(void)h;}
static void sdhci_uhs2_reset(struct sdhci_host *h,unsigned mask) {(void)h;(void)mask;}
static void sdhci_uhs2_clear_set_irqs(struct sdhci_host *h,unsigned a,unsigned b) {(void)h;(void)a;(void)b;}
#define read_poll_timeout_atomic(op,val,cond,delay,timeout,sleep,...) ((val=op(__VA_ARGS__)), (cond)?0:-ETIMEDOUT)
'''
c += macros + "\n" + "\n".join(bodies)
c += r'''
static void seed_pci(struct pci_dev *d,u32 seed) {
    const unsigned regs[]={0x800,0x44,0x48,0x64,0x68,0x6c,0x70,0x78};
    for (unsigned j=0;j<8;++j) d->regs[regs[j]/4]=seed;
}
int main(void) {
    const u32 seeds[]={0,0x01420304,0x5a5a5a5a,0xa5a5a5a5};
    for (unsigned i=0;i<4;++i) {
        struct pci_dev d={0};struct sdhci_pci_chip chip={.pdev=&d};struct sdhci_pci_slot slot={.chip=&chip};
        struct mmc_host m={0};struct sdhci_host h={.mmc=&m,.slot=&slot};current=&h;
        seed_pci(&d,seeds[i]);gl9755_hw_setting(&slot);gl9755_vendor_init(&h);
        printf("P %u",seeds[i]);const unsigned regs[]={0x800,0x44,0x48,0x64,0x68,0x6c,0x70,0x78};
        for(unsigned j=0;j<8;++j) printf(" %u",d.regs[regs[j]/4]);puts("");
        for(unsigned off=0;off<2;++off)for(unsigned timing=3;timing<=6;++timing) {
            const unsigned clocks[]={0,400000,25000000,50000000,100000000,200000000};
            for(unsigned k=0;k<6;++k) {
                struct mmc_host n={.ios={.timing=timing}};
                struct sdhci_host g={.mmc=&n,.slot=&slot,.version=2,.max_clk=200000000};current=&g;
                seed_pci(&d,seeds[i]);d.regs[0x78/4]=(d.regs[0x78/4]&~(1U<<26))|(off<<26);
                sdhci_gl9755_set_clock(&g,clocks[k]);
                printf("C %u %u %u %u %u %u %u %u\n",seeds[i],off,timing,clocks[k],n.actual_clock,d.regs[0x64/4],d.regs[0x68/4],sdhci_readw(&g,0x2c));
            }
        }
    }
    const unsigned volts[]={10,12,14};
    for(unsigned i=0;i<3;++i)for(unsigned off=0;off<2;++off) {
        struct mmc_host m={0};struct sdhci_host h={.mmc=&m,.pwr=off?255:0};current=&h;
        h.regs[0x34/4]=0x12345678;h.regs[0x38/4]=0;
        gl9755_set_power(&h,off?0:1,volts[i]);
        printf("W %u %u %u",volts[i],off,h.count);
        for(unsigned j=0;j<h.count;++j) printf(" %u %u",h.power[j],h.time[j]);
        printf(" %u %u\n",h.elapsed,sdhci_readl(&h,0x34));
    }
    const unsigned masks[]={1,2,4,6};
    for(unsigned i=0;i<4;++i) {
        struct mmc_host m={0};struct sdhci_host h={.mmc=&m};current=&h;
        sdhci_gl9755_reset(&h,masks[i]);
        printf("R %u %u %u %u\n",masks[i],h.resets,sdhci_readw(&h,0x2c),sdhci_readw(&h,0x3e));
    }
    return 0;
}
'''
(out / "oracle.c").write_text(c)
compiler = shutil.which("clang") or shutil.which("gcc")
assert compiler, "local C compiler required"
command = [compiler, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
           "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
           str(out / "oracle.c"), "-o", str(out / "oracle")]
compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
(out / "compile.log").write_text(compiled.stdout + compiled.stderr)
compiled.check_returncode()
run = subprocess.run([str(out / "oracle")], capture_output=True, text=True, timeout=30)
(out / "stderr.log").write_text(run.stderr)
run.check_returncode()
(out / "records.txt").write_text(run.stdout)
assert len(run.stdout.splitlines()) == 206
(out / "report.json").write_text(json.dumps(dict(pin=PIN, sources=HASHES, fragments=fragments,
    records=206, command=command, output_sha256=hashlib.sha256(run.stdout.encode()).hexdigest(),
    limitations=["PCI/MMIO reads, elapsed delays, clock enable and reset ACKs modeled",
                 "PCI core D3/D0, AER discovery/masking wrapper services modeled separately",
                 "No physical power, IRQ, DMA or UHS-II transport execution",
                 "Native polling intentionally leaves SignalEnable zero rather than enabling CPU IRQ"]), indent=2)+"\n")
print(json.dumps(dict(records=206, output=str(out / "records.txt"))))
