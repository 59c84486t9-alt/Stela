#!/usr/bin/env python3
"""Execute complete unchanged GL9750 PHY, clock and tuning donor functions.

Usage: sdhci_gli_oracle.py DONOR_DIRECTORY FRESH_OUTPUT_DIRECTORY
MMIO, the shared clock-enable service and tuning completion are modeled. This
does not execute Linux PCI power management, IRQs or physical card signaling.
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
    "gl9750_wt_on", "gl9750_wt_off", "gli_set_9750", "gli_set_9750_rx_inv",
    "__sdhci_execute_tuning_9750", "gl9750_disable_ssc_pll", "gl9750_set_pll",
    "gl9750_ssc_enable", "gl9750_set_ssc", "gl9750_set_ssc_pll_205mhz",
    "gl9750_set_ssc_pll_100mhz", "gl9750_set_ssc_pll_50mhz", "sdhci_gl9750_set_clock",
]]
definitions = {}
for text in texts.values():
    for match in re.finditer(r"^#define\s+([A-Z][A-Z0-9_]+)\s+(.+)$", text, re.M):
        definitions[match[1]] = match[2]
names = set(re.findall(r"\b(?:SDHCI|MMC_TIMING|GLI)_[A-Z0-9_]+\b", "\n".join(bodies)))
while True:
    previous = set(names)
    for name in previous:
        assert name in definitions, name
        names.update(re.findall(r"\b(?:SDHCI|MMC_TIMING|GLI)_[A-Z0-9_]+\b", definitions[name]))
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
#define pr_info(...) ((void)0)
#define mmc_hostname(x) "GL9750-oracle"
struct mmc_ios {unsigned timing;};
struct mmc_host {struct mmc_ios ios; unsigned actual_clock;};
struct sdhci_host {
    u32 regs[0x900/4]; struct mmc_host *mmc;
    unsigned version,max_clk,clk_mul,quirks2; bool preset_enabled;
    int tuning_done; unsigned iterations,bad_phase,silent_phase,round,commands;
};
static u32 sdhci_readl(struct sdhci_host *h,unsigned at) {return h->regs[at/4];}
static u16 sdhci_readw(struct sdhci_host *h,unsigned at) {return (u16)(h->regs[at/4] >> ((at&3)*8));}
static void sdhci_writel(struct sdhci_host *h,u32 v,unsigned at) {h->regs[at/4]=v;}
static void sdhci_writew(struct sdhci_host *h,u16 v,unsigned at) {
    unsigned shift=(at&3)*8; h->regs[at/4]=(h->regs[at/4]&~(65535U<<shift))|((u32)v<<shift);
}
static void mdelay(unsigned n) {(void)n;}
static void sdhci_enable_clk(struct sdhci_host *h,u16 v) {sdhci_writew(h,v|7,0x2c);}
static u16 sdhci_get_preset_value(struct sdhci_host *h) {(void)h; return 0;}
'''
c += macros + r'''
static void sdhci_start_tuning(struct sdhci_host *h) {
    u16 c=sdhci_readw(h,SDHCI_HOST_CONTROL2);
    sdhci_writew(h,(c&~SDHCI_CTRL_TUNED_CLK)|SDHCI_CTRL_EXEC_TUNING,SDHCI_HOST_CONTROL2);
    h->round=0;
}
static void sdhci_send_tuning(struct sdhci_host *h,u32 op) {
    (void)op; ++h->commands; ++h->round;
    unsigned phase=!!(sdhci_readl(h,SDHCI_GLI_9750_MISC)&SDHCI_GLI_9750_MISC_RX_INV);
    h->tuning_done=!(h->silent_phase==2 || (h->silent_phase==1 && !phase));
    if (h->tuning_done && h->round==h->iterations) {
        u16 c=sdhci_readw(h,SDHCI_HOST_CONTROL2)&~SDHCI_CTRL_EXEC_TUNING;
        if (!(h->bad_phase && !phase)) c|=SDHCI_CTRL_TUNED_CLK;
        sdhci_writew(h,c,SDHCI_HOST_CONTROL2);
    }
}
static void sdhci_reset_tuning(struct sdhci_host *h) {
    u16 c=sdhci_readw(h,SDHCI_HOST_CONTROL2)&~(SDHCI_CTRL_TUNED_CLK|SDHCI_CTRL_EXEC_TUNING);
    sdhci_writew(h,c,SDHCI_HOST_CONTROL2);
}
static void sdhci_abort_tuning(struct sdhci_host *h,u32 op) {(void)op; sdhci_reset_tuning(h);}
'''
c += "\n".join(bodies)
c += r'''
static void seed_host(struct sdhci_host *h,u32 seed) {
    const unsigned regs[]={0x800,0x860,0x864,0x86c,0x874,0x878,0x510,0x540,0x544};
    for (unsigned i=0;i<sizeof(regs)/sizeof(regs[0]);++i) h->regs[regs[i]/4]=seed;
    sdhci_writew(h,128,0x3e);
}
int main(void) {
    const u32 seeds[]={0,0x01420304,0x5a5a5a5a,0xa5a5a5a5};
    for (unsigned i=0;i<4;++i) {
        struct mmc_host m={0}; struct sdhci_host h={.mmc=&m}; seed_host(&h,seeds[i]);
        gli_set_9750(&h);
        printf("P %u",seeds[i]);
        const unsigned regs[]={0x800,0x860,0x864,0x86c,0x874,0x878,0x510,0x540,0x544};
        for (unsigned j=0;j<9;++j) printf(" %u",h.regs[regs[j]/4]);
        printf(" %u\n",sdhci_readw(&h,0x3e));
        for (unsigned off=0;off<2;++off) for (unsigned timing=3;timing<=6;++timing) {
            const unsigned clocks[]={0,400000,25000000,50000000,100000000,200000000};
            for (unsigned k=0;k<6;++k) {
                struct mmc_host n={.ios={.timing=timing}};
                struct sdhci_host g={.mmc=&n,.version=2,.max_clk=200000000}; seed_host(&g,seeds[i]);
                g.regs[0x878/4]=(g.regs[0x878/4]&~(1U<<26))|(off<<26);
                sdhci_gl9750_set_clock(&g,clocks[k]);
                printf("C %u %u %u %u %u %u %u %u\n",seeds[i],off,timing,clocks[k],n.actual_clock,g.regs[0x864/4],g.regs[0x86c/4],sdhci_readw(&g,0x2c));
            }
        }
    }
    for (unsigned n=1;n<=41;++n) for (unsigned bad=0;bad<3;++bad) {
        struct mmc_host m={0}; struct sdhci_host h={.mmc=&m,.iterations=n,.bad_phase=bad==1,.silent_phase=bad==2};
        int result=__sdhci_execute_tuning_9750(&h,19);
        printf("T %u %u %d %u %u\n",n,bad,result,h.commands,!!(h.regs[0x878/4]&8));
    }
    struct mmc_host m={0}; struct sdhci_host h={.mmc=&m,.iterations=3,.silent_phase=2};
    int result=__sdhci_execute_tuning_9750(&h,19);
    printf("T 3 3 %d %u %u\n",result,h.commands,!!(h.regs[0x878/4]&8));
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
assert len(run.stdout.splitlines()) == 320
(out / "report.json").write_text(json.dumps(dict(pin=PIN,sources=HASHES,fragments=fragments,
    records=320,command=command,output_sha256=hashlib.sha256(run.stdout.encode()).hexdigest(),
    limitations=["MMIO/clock-enable/completed tuning iterations are modeled",
                 "no Linux PCI power, interrupt or physical signaling execution"]),indent=2)+"\n")
print(json.dumps(dict(records=320,output=str(out / "records.txt"))))
