#!/usr/bin/env python3
"""Run unchanged GL9767 ordinary SD PHY/clock/power/reset donor functions.

Usage: sdhci_gli67_oracle.py VERIFIED_DONOR_DIRECTORY FRESH_OUTPUT_DIRECTORY
The exact atomic-poll macro also exposes the donor PCI-return-status alias.
Register-ACK poll records deliberately qualify a stronger native policy.
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
    "include/linux/iopoll.h": "9edf274f8555e266233ba151942af51e83ad175d885478556075258044dd3a0b",
    "include/linux/pci.h": "9ebdc70b5918c62e69de4e6ecaaee4b55554665a9ac0f45fd043d0d8b4fcce8c",
}
donor, out = map(Path, sys.argv[1:])
texts = {}
for path, digest in HASHES.items():
    raw = (donor / path).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, path
    texts[path] = raw.decode()
out.mkdir(parents=True, exist_ok=False)
fragments = []
prototype = next(line for line in texts["include/linux/pci.h"].splitlines() if line.startswith("int pci_read_config_dword("))
fragments.append(dict(path="include/linux/pci.h", name="pci_read_config_dword ABI", sha256=hashlib.sha256(prototype.encode()).hexdigest()))


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
bodies = [function("drivers/mmc/host/sdhci.c", name) for name in ["sdhci_calc_clk", "sdhci_set_power_noreg", "sdhci_set_power"]]
bodies += [function(gli, name) for name in [
    "sdhci_gli_overcurrent_event_enable", "gl9767_vhs_read", "gl9767_vhs_write",
    "gl9767_ssc_enable", "gl9767_set_ssc", "gl9767_set_pll", "gl9767_set_ssc_pll_205mhz",
    "gl9767_disable_ssc_pll", "gl9767_set_low_power_negotiation", "sdhci_gl9767_set_clock",
    "sdhci_gl9767_set_card_detect_debounce_time", "sdhci_gl9767_card_event", "gli_set_9767",
    "gl9767_hw_setting", "gl9767_vendor_init", "sdhci_gl9767_set_power", "sdhci_gl9767_reset",
]]
macros = []
for name in ["poll_timeout_us_atomic", "read_poll_timeout_atomic"]:
    lines = texts["include/linux/iopoll.h"].splitlines()
    at = next(i for i, line in enumerate(lines) if line.startswith("#define " + name + "("))
    body = []
    while True:
        body.append(lines[at]); at += 1
        if not body[-1].endswith("\\"):
            break
    block = "\n".join(body)
    fragments.append(dict(path="include/linux/iopoll.h", name=name, sha256=hashlib.sha256(block.encode()).hexdigest()))
    macros.append(block)
definitions = {}
for text in texts.values():
    definitions.update(re.findall(r"^#define\s+([A-Za-z][A-Za-z0-9_]+)\s+(.+)$", text.replace("\\\n", ""), re.M))
pattern = r"\b(?:SDHCI|MMC|PCIE_GLI|GLI)_[A-Za-z0-9_]+\b"
names = set(re.findall(pattern, "\n".join(bodies))) - {"MMC_POWER_OFF"}
while True:
    previous = set(names)
    for name in previous:
        assert name in definitions, name
        names.update(re.findall(pattern, definitions[name]))
    if names == previous:
        break
macros += ["#define " + name + " " + definitions[name] for name in sorted(names)]
c = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;typedef uint64_t u64;typedef int64_t s64;
#define BIT(n) (1U << (n))
#define GENMASK(h,l) ((~0U << (l)) & (~0U >> (31-(h))))
#define FIELD_GET(m,v) (((v)&(m)) >> __builtin_ctz(m))
#define FIELD_PREP(m,v) (((u32)(v) << __builtin_ctz(m)) & (m))
#define max_t(t,a,b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define pr_err(...) ((void)0)
#define pr_warn(...) ((void)0)
#define WARN(...) ((void)0)
#define mmc_hostname(x) "GL9767-oracle"
#define MMC_POWER_OFF 0
#define IS_ERR(x) true
#define NSEC_PER_USEC 1000
#define barrier() ((void)0)
#define cpu_relax() ((void)0)
struct pci_dev {u32 regs[1024];unsigned ack_poll,reads;};
struct sdhci_pci_chip {struct pci_dev *pdev;};
struct sdhci_pci_slot {struct sdhci_pci_chip *chip;};
struct mmc_ios {unsigned timing;};
struct mmc_host {struct mmc_ios ios;unsigned actual_clock;bool uhs2_sd_tran;struct {void *vmmc;} supply;};
struct sdhci_host {u32 regs[0x600/4];struct mmc_host *mmc;struct sdhci_pci_slot *slot;
 unsigned version,max_clk,clk_mul,quirks,quirks2,clock,ier,pwr;bool preset_enabled;
 unsigned power[4],count,elapsed,resets;};
static struct sdhci_host *current;
static struct sdhci_pci_slot *sdhci_priv(struct sdhci_host *h) {return h->slot;}
static bool mmc_card_uhs2(struct mmc_host *m) {return m->uhs2_sd_tran;}
static int pci_read_config_dword(struct pci_dev *d,unsigned at,u32 *v) {
    *v=d->regs[at/4];if(at==0x8e4 && ++d->reads<d->ack_poll)*v|=1;return 0;
}
static void pci_write_config_dword(struct pci_dev *d,unsigned at,u32 v) {d->regs[at/4]=v;if(at==0x8e4)d->reads=0;}
static u32 sdhci_readl(struct sdhci_host *h,unsigned at) {return h->regs[at/4];}
static u16 sdhci_readw(struct sdhci_host *h,unsigned at) {return (u16)(h->regs[at/4]>>((at&3)*8));}
static void sdhci_writel(struct sdhci_host *h,u32 v,unsigned at) {h->regs[at/4]=v;}
static void sdhci_writew(struct sdhci_host *h,u16 v,unsigned at) {unsigned shift=(at&3)*8;h->regs[at/4]=(h->regs[at/4]&~(65535U<<shift))|((u32)v<<shift);}
static void sdhci_writeb(struct sdhci_host *h,u8 v,unsigned at) {
 if(at==0x29)h->power[h->count++]=v;if(at==0x2f){++h->resets;v=0;}
 unsigned shift=(at&3)*8;h->regs[at/4]=(h->regs[at/4]&~(255U<<shift))|((u32)v<<shift);
}
static void mdelay(unsigned n) {current->elapsed+=n*1000;}
static void udelay(unsigned n) {current->elapsed+=n;}
static void usleep_range(unsigned a,unsigned b) {(void)b;udelay(a);}
static void sdhci_enable_clk(struct sdhci_host *h,u16 v) {sdhci_writew(h,v|7,0x2c);}
static u16 sdhci_get_preset_value(struct sdhci_host *h) {(void)h;return 0;}
static u8 sdhci_get_vdd_value(unsigned vdd) {return (u8)vdd;}
static void sdhci_set_power_reg(struct sdhci_host *h,unsigned m,unsigned v) {(void)h;(void)m;(void)v;}
static void sdhci_runtime_pm_bus_off(struct sdhci_host *h) {(void)h;}
static void sdhci_runtime_pm_bus_on(struct sdhci_host *h) {(void)h;}
static void sdhci_gl9767_uhs2_phy_reset(struct sdhci_host *h,bool asserted) {(void)h;(void)asserted;}
static void __gl9767_uhs2_set_power(struct sdhci_host *h,unsigned m,unsigned v) {(void)h;(void)m;(void)v;}
static void sdhci_gli_enable_internal_clock(struct sdhci_host *h) {sdhci_writew(h,3,0x2c);sdhci_writew(h,4096,0x3e);}
static void sdhci_gli_uhs2_reset_sd_tran(struct sdhci_host *h) {(void)h;}
static void sdhci_gli_wait_software_reset_done(struct sdhci_host *h,u8 mask) {(void)h;(void)mask;}
static void sdhci_uhs2_reset(struct sdhci_host *h,u8 mask) {(void)h;(void)mask;}
static void sdhci_reset(struct sdhci_host *h,u8 mask) {sdhci_writeb(h,mask,0x2f);}
'''
c += "\n".join(macros) + "\n" + "\n".join(bodies)
c += r'''
static void seed_pci(struct pci_dev *d,u32 seed) {
 const unsigned regs[]={0x884,0x888,0x8a0,0x8d0,0x8e0,0x90c,0x938,0x93c,0x944,0x948,0x95c,0x964};
 for(unsigned j=0;j<12;++j)d->regs[regs[j]/4]=seed;
}
static u32 reset_register(struct pci_dev *d) {return ++d->reads<d->ack_poll?1:0;}
int main(void) {
 const u32 seeds[]={0,0x01420304,0x5a5a5a5a,0xa5a5a5a5};
 for(unsigned i=0;i<4;++i)for(unsigned present=0;present<2;++present) {
  struct pci_dev d={0};struct sdhci_pci_chip chip={.pdev=&d};struct sdhci_pci_slot slot={.chip=&chip};
  struct mmc_host m={0};struct sdhci_host h={.mmc=&m,.slot=&slot};current=&h;seed_pci(&d,seeds[i]);
  h.regs[0x508/4]=seeds[i];h.regs[0x510/4]=seeds[i];h.regs[0x24/4]=present<<16;
  gli_set_9767(&h);gl9767_hw_setting(&slot);gl9767_vendor_init(&h);sdhci_gl9767_card_event(&h);
  printf("P %u %u",seeds[i],present);
  const unsigned regs[]={0x884,0x888,0x8a0,0x8d0,0x8e0,0x90c,0x938,0x93c,0x944,0x948,0x95c,0x964};
  for(unsigned j=0;j<12;++j)printf(" %u",d.regs[regs[j]/4]);printf(" %u %u\n",h.regs[0x508/4],h.regs[0x510/4]);
 }
 for(unsigned i=0;i<4;++i)for(unsigned enable=0;enable<2;++enable)for(unsigned timing=3;timing<=6;++timing) {
  const unsigned clocks[]={0,400000,25000000,50000000,100000000,200000000};
  for(unsigned k=0;k<6;++k) {
   struct pci_dev d={0};struct sdhci_pci_chip chip={.pdev=&d};struct sdhci_pci_slot slot={.chip=&chip};
   struct mmc_host m={.ios={.timing=timing}};struct sdhci_host h={.mmc=&m,.slot=&slot,.version=2,.max_clk=200000000};current=&h;
   seed_pci(&d,seeds[i]);d.regs[0x888/4]=(d.regs[0x888/4]&~2U)|(enable<<1);
   sdhci_gl9767_set_clock(&h,clocks[k]);
   printf("C %u %u %u %u %u %u %u %u %u\n",seeds[i],enable,timing,clocks[k],m.actual_clock,d.regs[0x938/4],d.regs[0x93c/4],sdhci_readw(&h,0x2c),d.regs[0x8a0/4]);
  }
 }
 const unsigned volts[]={10,12,14};
 for(unsigned i=0;i<3;++i)for(unsigned off=0;off<2;++off) {
  struct pci_dev d={0};struct sdhci_pci_chip chip={.pdev=&d};struct sdhci_pci_slot slot={.chip=&chip};
  struct mmc_host m={0};struct sdhci_host h={.mmc=&m,.slot=&slot,.pwr=off?255:0};current=&h;d.regs[0x944/4]=0x55ff;
  h.regs[0x34/4]=0x12345678;sdhci_gl9767_set_power(&h,off?0:1,volts[i]);
  printf("W %u %u %u",volts[i],off,h.count);for(unsigned j=0;j<h.count;++j)printf(" %u",h.power[j]);
  printf(" %u %u\n",h.regs[0x34/4],d.regs[0x944/4]);
 }
 for(unsigned ack=1;ack<=6;++ack) {
  struct pci_dev d={.ack_poll=ack};struct sdhci_pci_chip chip={.pdev=&d};struct sdhci_pci_slot slot={.chip=&chip};
  struct mmc_host m={0};struct sdhci_host h={.mmc=&m,.slot=&slot};current=&h;
  sdhci_gl9767_reset(&h,1);printf("A %u %u %u\n",ack,d.reads,h.resets);
  d.reads=0;u32 value;h.elapsed=0;
  int result=read_poll_timeout_atomic(reset_register,value,!(value&1),1,5,true,&d);
  printf("D %u %d %u %u\n",ack,result,d.reads,h.elapsed);
 }
 return 0;
}
'''
(out / "oracle.c").write_text(c)
compiler = shutil.which("clang") or shutil.which("gcc")
assert compiler
command = [compiler, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
           "-fsanitize=address,undefined", "-fno-omit-frame-pointer", str(out / "oracle.c"), "-o", str(out / "oracle")]
compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
(out / "compile.log").write_text(compiled.stdout + compiled.stderr)
compiled.check_returncode()
run = subprocess.run([str(out / "oracle")], capture_output=True, text=True, timeout=30)
(out / "stderr.log").write_text(run.stderr)
run.check_returncode()
(out / "records.txt").write_text(run.stdout)
assert len(run.stdout.splitlines()) == 218
(out / "report.json").write_text(json.dumps(dict(pin=PIN, sources=HASHES, fragments=fragments,
    records=218, command=command, output_sha256=hashlib.sha256(run.stdout.encode()).hexdigest(),
    limitations=["Ordinary SD only; UHS-II/SD Express transport services never execute",
                 "VDD selector normalization, common clock/reset services modeled; full clock-enable separately qualified",
                 "Native polling intentionally keeps CPU SignalEnable zero",
                 "Donor reset status-alias anomaly is retained by complete function/macro: A records always continue after PCI returnstatus0",
                 "D records use actual register observation with the complete pinned macro; native deliberately requires this stronger ACK policy",
                 "No physical power/PCI/DMA/IRQ execution"]), indent=2)+"\n")
print(json.dumps(dict(records=218, output=str(out / "records.txt"))))
