#!/usr/bin/env python3
"""Run unchanged pinned Linux UHS signaling and hardware-tuning decision code.

Usage: sdhci_uhs_oracle.py DONOR_DIRECTORY FRESH_OUTPUT_DIRECTORY
The shim models HC2 reads/writes and completed tuning iterations. It does not
execute Linux command submission, electrical transitions, interrupts or timers.
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


def function(name):
    text = texts["drivers/mmc/host/sdhci.c"]
    match = re.search(r"^(?:void|int) " + name + r"\([^;{}]*\)\n\{", text, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    body = text[match.start():end]
    fragments.append(dict(name=name, start=match.start(), end=end,
                          sha256=hashlib.sha256(body.encode()).hexdigest()))
    return body


signaling = function("sdhci_set_uhs_signaling")
tuning = function("__sdhci_execute_tuning")
macros = []
for name in sorted(set(re.findall(r"\b(?:SDHCI|MMC_TIMING)_[A-Z0-9_]+\b", signaling + tuning))):
    match = re.search(r"^#define\s+" + name + r"\s+(.+)$",
                      texts["drivers/mmc/host/sdhci.h"] + texts["include/linux/mmc/host.h"], re.M)
    assert match, name
    macros.append("#define " + name + " " + match[1])
c = r'''
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
typedef uint16_t u16; typedef uint32_t u32;
#define pr_debug(...) ((void)0)
#define pr_info(...) ((void)0)
#define mmc_hostname(x) "source-oracle"
struct sdhci_host {
    u16 control;
    int tuning_loop_count, tuning_done, tuning_delay;
    unsigned iterations, no_clock, silent, commands;
};
static u16 sdhci_readw(struct sdhci_host *h, unsigned at) {(void)at; return h->control;}
static void sdhci_writew(struct sdhci_host *h, u16 v, unsigned at) {(void)at; h->control=v;}
static void mdelay(unsigned n) {(void)n;}
'''
c += "\n".join(macros) + "\n"
c += r'''
static void sdhci_send_tuning(struct sdhci_host *h, u32 opcode) {
    (void)opcode; ++h->commands;
    h->tuning_done = !h->silent;
    if (!h->silent && h->commands == h->iterations) {
        h->control &= ~SDHCI_CTRL_EXEC_TUNING;
        if (!h->no_clock) h->control |= SDHCI_CTRL_TUNED_CLK;
    }
}
static void sdhci_reset_tuning(struct sdhci_host *h) {
    h->control &= ~(SDHCI_CTRL_EXEC_TUNING | SDHCI_CTRL_TUNED_CLK);
}
static void sdhci_abort_tuning(struct sdhci_host *h, u32 opcode) {
    (void)opcode; sdhci_reset_tuning(h);
}
'''
c += signaling + "\n" + tuning + "\n"
c += r'''
int main(void) {
    const unsigned seeds[] = {0,16,32,48,256,512,16384,32768};
    for (unsigned i=0;i<sizeof(seeds)/sizeof(seeds[0]);++i)
        for (unsigned mode=0;mode<4;++mode) {
            struct sdhci_host h = {.control=(u16)(seeds[i]|8)};
            sdhci_set_uhs_signaling(&h, MMC_TIMING_UHS_SDR12 + mode);
            printf("T %u %u %u\n",seeds[i],mode,h.control);
        }
    for (unsigned n=1;n<=41;++n)
        for (unsigned no_clock=0;no_clock<2;++no_clock) {
            struct sdhci_host h = {.control=SDHCI_CTRL_EXEC_TUNING,
                .tuning_loop_count=40,.iterations=n,.no_clock=no_clock};
            int result=__sdhci_execute_tuning(&h,19);
            printf("C %u %u 0 %d %u\n",n,no_clock,result,h.commands);
        }
    struct sdhci_host h = {.control=SDHCI_CTRL_EXEC_TUNING,.tuning_loop_count=40,.silent=1};
    int result=__sdhci_execute_tuning(&h,19);
    printf("C 1 0 1 %d %u\n",result,h.commands);
    return 0;
}
'''
(out / "oracle.c").write_text(c)
compiler = shutil.which("clang") or shutil.which("gcc")
assert compiler, "a local C compiler is required"
compile_command = [compiler, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                   "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                   str(out / "oracle.c"), "-o", str(out / "oracle")]
compiled = subprocess.run(compile_command, capture_output=True, text=True, timeout=60)
(out / "compile.log").write_text(compiled.stdout + compiled.stderr)
compiled.check_returncode()
ran = subprocess.run([str(out / "oracle")], capture_output=True, text=True, timeout=30)
(out / "stderr.log").write_text(ran.stderr)
ran.check_returncode()
(out / "records.txt").write_text(ran.stdout)
records = ran.stdout.splitlines()
assert len(records) == 115
report = dict(pin=PIN, sources=HASHES, fragments=fragments, compile=compile_command,
              records=len(records), output_sha256=hashlib.sha256(ran.stdout.encode()).hexdigest(),
              limitations=["MMIO and completed tuning iterations are modeled",
                           "no Linux command submission, electrical transition, interrupt or timer execution"])
(out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(dict(records=len(records), output=str(out / "records.txt"))))
