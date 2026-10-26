#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# MMC core: Copyright 2003-2004 Russell King, 2005-2007 Pierre Ossman;
# MMCv4 support Copyright 2006 Philip Langdale. All Rights Reserved.
# Host retuning: Copyright 2003 Russell King, 2007-2008 Pierre Ossman,
# 2010 Linus Walleij.
"""Run complete unchanged explicit MMC HS200/HS400 retuning procedures.

Usage: mmc_retune_oracle.py VERIFIED_REFERENCE_ROOT FRESH_OUTPUT_DIRECTORY
Command/busy/PHY effects are separate actual-controller native evidence.
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
    "drivers/mmc/core/host.c": "934fa12c7aa9d25f19a8c344afe4c3d4c1da5ad25bc95a86e7a01585a614b51e",
    "drivers/mmc/core/mmc.c": "fc69b95ffbc277a7c1f293fb32e182f0230efc825ac07df8364da89e9fed5f54",
    "include/linux/mmc/mmc.h": "50a03b69f2a0c19c7c24d69d5a537fa76defdfc6a9cc7738a1c7d8751bdd5775",
    "include/linux/mmc/host.h": "48ddebc041d079a90ba43628d106acbd2b0a09bbe459deca9d7a73ae561945cc",
    "include/linux/mmc/card.h": "5ee9c8ea19d93fdb513b00f0a2306b0af4161158e5144dc9899e41b015094c97",
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
    match = re.search(r"^(?:static )?(?:void|int) " + name + r"\([^;{}]*\)\n\{", text, re.M)
    assert match, name
    end, depth = match.end(), 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    body = text[match.start():end]
    fragments.append(dict(path=path, name=name, sha256=hashlib.sha256(body.encode()).hexdigest()))
    return body


bodies = [function("drivers/mmc/core/mmc.c", name) for name in [
    "mmc_set_bus_speed", "mmc_select_hs400", "mmc_hs200_to_hs400", "mmc_hs400_to_hs200",
]]
bodies += [function("drivers/mmc/core/host.c", "mmc_retune")]

definitions = {}
for text in texts.values():
    definitions.update(re.findall(r"^#define\s+([A-Za-z][A-Za-z0-9_]+)\s+(.+)$", text.replace("\\\n", ""), re.M))
pattern = r"\b(?:MMC|EXT_CSD)_[A-Za-z0-9_]+\b"
names = set(re.findall(pattern, "\n".join(bodies))) - {"MMC_CMD_RETRIES"}
names.update(["MMC_SIGNAL_VOLTAGE_180", "EXT_CSD_CARD_TYPE_HS200_1_8V", "EXT_CSD_CARD_TYPE_HS400_1_8V"])
while True:
    previous = set(names)
    for name in previous:
        assert name in definitions, name
        names.update(re.findall(pattern, definitions[name]))
    if names == previous:
        break
header = texts["include/linux/mmc/mmc.h"]
host_header = texts["drivers/mmc/core/host.c"]
c = host_header[:host_header.index("*/") + 2] + "\n" + header[:header.index("*/") + 2] + r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
typedef uint8_t u8;
#define BIT(n) (1U << (n))
#define pr_err(...) ((void)0)
#define pr_warn(...) ((void)0)
#define mmc_hostname(h) "MMC-timing-oracle"
/* Retries are an unused recording argument, not executed policy. */
#define MMC_CMD_RETRIES 3
#define ENOTSUPP 524
struct mmc_host;struct mmc_card;
struct mmc_ios {unsigned timing,signal_voltage,clock,bus_width,vdd;bool enhanced_strobe;};
struct mmc_host_ops {
 void (*hs400_downgrade)(struct mmc_host *);
 void (*hs400_prepare_ddr)(struct mmc_host *);
 int (*execute_hs400_tuning)(struct mmc_host *,struct mmc_card *);
 void (*hs400_complete)(struct mmc_host *);
 void (*hs400_enhanced_strobe)(struct mmc_host *,struct mmc_ios *);
 void (*prepare_hs400_tuning)(struct mmc_host *,struct mmc_ios *);
};
struct mmc_host {struct mmc_ios ios;const struct mmc_host_ops *ops;struct mmc_card *card;unsigned retune_now,need_retune,doing_retune;};
struct mmc_ext_csd {
 unsigned generic_cmd6_time,hs_max_dtr,hs200_max_dtr;
 u8 raw_pwr_cl_26_195,raw_pwr_cl_52_195,raw_pwr_cl_ddr_52_195,raw_pwr_cl_200_195;
 u8 raw_pwr_cl_26_360,raw_pwr_cl_52_360,raw_pwr_cl_ddr_52_360,raw_pwr_cl_200_360,raw_pwr_cl_ddr_200_360;
};
struct mmc_card {struct mmc_host *host;struct mmc_ext_csd ext_csd;struct {unsigned max_dtr;} csd;unsigned mmc_avail_type,drive_strength;};
static void event(char k,unsigned a,unsigned b) {printf(" %c%u:%u",k,a,b);}
static int __mmc_switch(struct mmc_card *c,u8 set,u8 i,u8 v,unsigned time,unsigned timing,bool status,bool busy,int retries) {(void)c;(void)set;(void)time;(void)timing;(void)busy;(void)retries;if(status)abort();event('W',i,v);return 0;}
static int mmc_switch_status(struct mmc_card *c,bool fatal) {(void)c;event('S',fatal,0);return 0;}
static int mmc_switch(struct mmc_card *c,u8 set,u8 i,u8 v,unsigned time) {int e=__mmc_switch(c,set,i,v,time,0,false,true,3);return e?e:mmc_switch_status(c,true);}
static void mmc_set_timing(struct mmc_host *h,unsigned v) {h->ios.timing=v;event('T',v,0);}
static void mmc_set_clock(struct mmc_host *h,unsigned v) {h->ios.clock=v;event('C',v,0);}
static void mmc_retune_disable(struct mmc_host *h) {(void)h;abort();}
static void mmc_retune_enable(struct mmc_host *h) {(void)h;abort();}
static int mmc_execute_tuning(struct mmc_card *c) {(void)c;event('Q',21,0);return 0;}
'''
c += "\n".join("#define " + name + " " + definitions[name] for name in sorted(names)) + "\n"
c += r'''
static bool mmc_card_hs(struct mmc_card *c) {return c->host->ios.timing==MMC_TIMING_MMC_HS;}
static bool mmc_card_hs200(struct mmc_card *c) {return c->host->ios.timing==MMC_TIMING_MMC_HS200;}
static bool mmc_card_hs400(struct mmc_card *c) {return c->host->ios.timing==MMC_TIMING_MMC_HS400;}
'''
c += "\n".join(bodies)
c += r'''
int main(void) {
 const struct mmc_host_ops ops={0};
 for(unsigned hs400=0;hs400<2;++hs400)for(unsigned faster=0;faster<2;++faster)
 for(unsigned drive=0;drive<4;++drive) {
  struct mmc_host h={.ios={.clock=200000000,.signal_voltage=MMC_SIGNAL_VOLTAGE_180,.bus_width=MMC_BUS_WIDTH_8,.timing=hs400?MMC_TIMING_MMC_HS400:MMC_TIMING_MMC_HS200},.ops=&ops,.retune_now=1,.need_retune=1};
  struct mmc_card c={.host=&h,.mmc_avail_type=EXT_CSD_CARD_TYPE_HS200_1_8V|EXT_CSD_CARD_TYPE_HS400_1_8V,.drive_strength=drive,.ext_csd={.generic_cmd6_time=10,.hs_max_dtr=faster?52000000:26000000,.hs200_max_dtr=200000000}};
  h.card=&c;
  printf("R %u %u %u",hs400,faster,drive);
  if(mmc_retune(&h)||h.doing_retune||h.retune_now||h.need_retune)abort();
  putchar('\n');
 }
 return 0;
}
'''
(out / "oracle.c").write_text(c)
compiler = shutil.which("clang") or shutil.which("gcc")
assert compiler
command = [compiler, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(out / "oracle.c"), "-o", str(out / "oracle")]
compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
(out / "compile.log").write_text(compiled.stdout + compiled.stderr)
compiled.check_returncode()
result = subprocess.run([str(out / "oracle")], capture_output=True, text=True, timeout=60)
(out / "stderr.log").write_text(result.stderr)
result.check_returncode()
assert len(result.stdout.splitlines()) == 16
(out / "records.txt").write_text(result.stdout)
(out / "report.json").write_text(json.dumps(dict(pin=PIN, sources=HASHES, fragments=fragments, records=16, command=command, output_sha256=hashlib.sha256(result.stdout.encode()).hexdigest(), limitations=[
    "Five complete unchanged mmc_retune/downgrade/restore/bus-speed functions; explicit serialized requested-retune host flags",
    "Switch/busy/tuning/controller callbacks recorded, not physical execution; actual native peers execute CMD21 and changed ADMA payloads separately",
    "Successful HS200/non-ESHS400 at1.8V, source HS26/52 and preserved drive fields; other host callbacks null as source GL9763E profile",
    "No IRQ/CRC request producer, automatic replay, software-busy retry/fallback, enhanced strobe or PM qualification",
]), indent=2)+"\n")
print(json.dumps(dict(records=16, output=str(out / "records.txt"))))
