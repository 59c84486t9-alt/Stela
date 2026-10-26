#!/usr/bin/env python3
"""Run complete unchanged sdhci_enable_clk including v4.1 PLL and deadlines.

Usage: sdhci_clock_oracle.py VERIFIED_DONOR_DIRECTORY FRESH_OUTPUT_DIRECTORY
MMIO stability and monotonic time are independent modeled services.
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
    "drivers/mmc/host/sdhci.c": "186305e102bd32df419ff80669e6018d6b3a9e4310c3101193413970355b9857",
    "drivers/mmc/host/sdhci.h": "4b3a252cecc039b22e56c37ec95ad2959bee52934594666708c4a7f118afe4af",
}
donor, out = map(Path, sys.argv[1:])
texts = {}
for path, digest in HASHES.items():
    raw = (donor / path).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, path
    texts[path] = raw.decode()
text = texts["drivers/mmc/host/sdhci.c"]
match = re.search(r"^void sdhci_enable_clk\([^;{}]*\)\n\{", text, re.M)
assert match
end, depth = match.end(), 1
while depth:
    depth += (text[end] == "{") - (text[end] == "}")
    end += 1
body = text[match.start():end]
definitions = dict(re.findall(r"^#define\s+([A-Z][A-Z0-9_]+)\s+(.+)$", texts["drivers/mmc/host/sdhci.h"], re.M))
names = set(re.findall(r"\bSDHCI_[A-Z0-9_]+\b", body))
macros = "\n".join("#define " + name + " " + definitions[name] for name in sorted(names))
c = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
typedef uint16_t u16;typedef uint64_t ktime_t;
#define BIT(n) (1U<<(n))
#define pr_err(...) ((void)0)
#define mmc_hostname(x) "clock-oracle"
struct sdhci_host {unsigned version;bool v4_mode;u16 control,writes[3];unsigned count,first,second;uint64_t now,started;};
static struct sdhci_host *current;
static ktime_t ktime_get(void) {return current->now;}
static ktime_t ktime_add_ms(ktime_t t,unsigned ms) {return t+(uint64_t)ms*1000;}
static bool ktime_after(ktime_t a,ktime_t b) {return a>b;}
static void udelay(unsigned us) {current->now+=us;}
static void sdhci_writew(struct sdhci_host *h,u16 v,unsigned at) {(void)at;h->writes[h->count++]=v&~2;h->control=v&~2;h->started=h->now;}
static u16 sdhci_readw(struct sdhci_host *h,unsigned at) {(void)at;unsigned delay=(h->control&8)?h->second:h->first;return h->control|((h->now-h->started>=delay)?2:0);}
static void sdhci_err_stats_inc(struct sdhci_host *h,unsigned type) {(void)h;(void)type;}
static void sdhci_dumpregs(struct sdhci_host *h) {(void)h;}
#define CTRL_TIMEOUT 0
'''
c += macros + "\n" + body
c += r'''
int main(void) {
    const unsigned versions[]={2,4,4,5},v4s[]={0,0,1,1},delays[]={0,500,120000,180000},fields[]={0,0x100,0xffc0};
    for(unsigned p=0;p<4;++p)for(unsigned f=0;f<3;++f)for(unsigned a=0;a<4;++a)for(unsigned b=0;b<4;++b) {
        struct sdhci_host h={.version=versions[p],.v4_mode=v4s[p],.first=delays[a],.second=delays[b]};current=&h;
        sdhci_enable_clk(&h,(u16)fields[f]);
        printf("%u %u %u %u %u %u %u",h.version,h.v4_mode,fields[f],h.first,h.second,h.control,h.count);
        for(unsigned i=0;i<h.count;++i)printf(" %u",h.writes[i]);puts("");
    }
    return 0;
}
'''
out.mkdir(parents=True, exist_ok=False)
(out / "oracle.c").write_text(c)
compiler = shutil.which("clang") or shutil.which("gcc")
assert compiler
command = [compiler, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
           "-fsanitize=address,undefined", "-fno-omit-frame-pointer", str(out / "oracle.c"), "-o", str(out / "oracle")]
compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
(out / "compile.log").write_text(compiled.stdout + compiled.stderr)
compiled.check_returncode()
run = subprocess.run([str(out / "oracle")], capture_output=True, text=True, timeout=30)
(out / "stderr.log").write_text(run.stderr)
run.check_returncode()
(out / "records.txt").write_text(run.stdout)
assert len(run.stdout.splitlines()) == 192
(out / "report.json").write_text(json.dumps(dict(pin=PIN, sources=HASHES,
    function=dict(name="sdhci_enable_clk", start=match.start(), end=end, sha256=hashlib.sha256(body.encode()).hexdigest()),
    records=192, command=command, output_sha256=hashlib.sha256(run.stdout.encode()).hexdigest(),
    limitations=["MMIO stability and monotonic time modeled", "no physical clock or IRQ execution",
                 "read-only STABLE bit normalized from write trace", "register write-ignore failures qualified separately in native peer"]), indent=2)+"\n")
print(json.dumps(dict(records=192, output=str(out / "records.txt"))))
