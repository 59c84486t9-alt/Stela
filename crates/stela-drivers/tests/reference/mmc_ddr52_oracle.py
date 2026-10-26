#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright 2003-2004 Russell King, 2005-2007 Pierre Ossman;
# MMCv4 support Copyright 2006 Philip Langdale. All Rights Reserved.
"""Run unchanged MMC DDR52 procedures and complete hardware-busy switch path.

Usage: mmc_ddr52_oracle.py VERIFIED_REFERENCE_ROOT FRESH_OUTPUT_DIRECTORY
Recording command/voltage/width boundaries do not execute physical hardware.
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
    "drivers/mmc/core/mmc.c": "fc69b95ffbc277a7c1f293fb32e182f0230efc825ac07df8364da89e9fed5f54",
    "drivers/mmc/core/mmc_ops.c": "21ce493f0638b9b778af03ed01be9780ca5bcff12ec0e365a112af0137ad193f",
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


bodies = [function("drivers/mmc/core/mmc_ops.c", name) for name in [
    "mmc_switch_status_error", "mmc_switch_status", "__mmc_switch", "mmc_switch",
]]
bodies += [function("drivers/mmc/core/mmc.c", name) for name in [
    "__mmc_select_powerclass", "mmc_set_bus_speed", "mmc_select_hs", "mmc_select_hs_ddr",
]]
definitions = {}
for text in texts.values():
    for name, parameters, value in re.findall(r"^#define\s+([A-Za-z][A-Za-z0-9_]*)(\([^\n]*?\))?\s+(.+)$", text.replace("\\\n", ""), re.M):
        definitions[name] = (parameters, value)
pattern = r"\b(?:MMC|EXT_CSD|R1)_[A-Za-z0-9_]+\b"
external = {"MMC_CMD_RETRIES", "MMC_BUSY_CMD6"}
names = set(re.findall(pattern, "\n".join(bodies))) - external
names.update(["MMC_CAP_WAIT_WHILE_BUSY", "MMC_SIGNAL_VOLTAGE_330"])
while True:
    previous = set(names)
    for name in previous:
        assert name in definitions, name
        names.update(set(re.findall(pattern, definitions[name][1])) - external)
    if names == previous:
        break
header = texts["include/linux/mmc/mmc.h"]
c = header[:header.index("*/") + 2] + r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
typedef uint8_t u8;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define pr_err(...) ((void)0)
#define pr_warn(...) ((void)0)
#define mmc_hostname(h) "MMC-DDR52-oracle"
#define MMC_CMD_RETRIES 3
/* The unexecuted software-busy branch aborts; its enum value is immaterial. */
#define MMC_BUSY_CMD6 0
struct mmc_host;
struct mmc_host_ops {bool (*card_busy)(struct mmc_host *);};
struct mmc_ios {unsigned timing,signal_voltage,clock,bus_width,vdd;};
struct mmc_host {struct mmc_ios ios;const struct mmc_host_ops *ops;unsigned caps;};
struct mmc_command {unsigned opcode,arg;};
struct mmc_ext_csd {
 unsigned generic_cmd6_time,hs_max_dtr,hs200_max_dtr;
 u8 raw_pwr_cl_26_195,raw_pwr_cl_52_195,raw_pwr_cl_ddr_52_195,raw_pwr_cl_200_195;
 u8 raw_pwr_cl_26_360,raw_pwr_cl_52_360,raw_pwr_cl_ddr_52_360,raw_pwr_cl_200_360,raw_pwr_cl_ddr_200_360;
};
struct mmc_card {struct mmc_host *host;struct mmc_ext_csd ext_csd;struct {unsigned max_dtr;} csd;unsigned mmc_avail_type;};
static void event(char k,unsigned a,unsigned b) {printf(" %c%u:%u",k,a,b);}
static void mmc_set_timing(struct mmc_host *h,unsigned v) {h->ios.timing=v;event('T',v,0);}
static void mmc_set_clock(struct mmc_host *h,unsigned v) {h->ios.clock=v;event('C',v,0);}
static int mmc_set_signal_voltage(struct mmc_host *h,unsigned v) {h->ios.signal_voltage=v;event('V',v,0);return 0;}
static int mmc_send_status(struct mmc_card *c,u32 *status) {(void)c;event('S',1,0);*status=0x900;return 0;}
static bool mmc_host_is_spi(struct mmc_host *h) {(void)h;return false;}
static void mmc_retune_hold(struct mmc_host *h) {(void)h;}
static void mmc_retune_release(struct mmc_host *h) {(void)h;}
static bool mmc_prepare_busy_cmd(struct mmc_host *h,struct mmc_command *c,unsigned t) {(void)h;(void)c;(void)t;return true;}
static int mmc_wait_for_cmd(struct mmc_host *h,struct mmc_command *c,unsigned retries) {(void)h;(void)retries;if(c->opcode!=6||c->arg>>24!=3)abort();event('W',c->arg>>16&255,c->arg>>8&255);return 0;}
static void mmc_delay(unsigned t) {(void)t;abort();}
static int mmc_poll_for_busy(struct mmc_card *c,unsigned t,bool retry,int kind) {(void)c;(void)t;(void)retry;(void)kind;abort();}
static void width(struct mmc_card *c) {c->host->ios.bus_width=3;event('B',8,0);}
'''
c += "\n".join("#define " + name + definitions[name][0] + " " + definitions[name][1] for name in sorted(names)) + "\n"
c += r'''
static bool mmc_card_hs(struct mmc_card *c) {return c->host->ios.timing==MMC_TIMING_MMC_HS;}
static bool mmc_card_hs200(struct mmc_card *c) {(void)c;return false;}
static bool mmc_card_hs400(struct mmc_card *c) {(void)c;return false;}
'''
c += "\n".join(bodies)
c += r'''
int main(void) {
 const struct mmc_host_ops ops={0};
 for(unsigned voltage=0;voltage<2;++voltage)for(unsigned power=0;power<16;++power) {
  struct mmc_host h={.ios={.clock=400000,.signal_voltage=MMC_SIGNAL_VOLTAGE_330,.vdd=voltage?7:20},.ops=&ops,.caps=MMC_CAP_WAIT_WHILE_BUSY|MMC_CAP_1_8V_DDR};
  struct mmc_card c={.host=&h,.mmc_avail_type=EXT_CSD_CARD_TYPE_DDR_1_8V,.ext_csd={.generic_cmd6_time=10,.hs_max_dtr=52000000,.raw_pwr_cl_52_195=((power+9)%16)<<4,.raw_pwr_cl_52_360=((power+11)%16)<<4,.raw_pwr_cl_ddr_52_195=((power+5)%16)<<4,.raw_pwr_cl_ddr_52_360=power<<4}};
  printf("D %u %u",voltage,power);
  if(mmc_select_hs(&c))abort();mmc_set_bus_speed(&c);width(&c);
  if(mmc_select_hs_ddr(&c)||__mmc_select_powerclass(&c,EXT_CSD_DDR_BUS_WIDTH_8))abort();
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
assert len(result.stdout.splitlines()) == 32
(out / "records.txt").write_text(result.stdout)
(out / "report.json").write_text(json.dumps(dict(pin=PIN, sources=HASHES, fragments=fragments, records=32, command=command, output_sha256=hashlib.sha256(result.stdout.encode()).hexdigest(), limitations=[
    "Eight complete unchanged procedures execute the R1b hardware-busy branch; command/voltage/width/timing boundaries are recorded, no physical hardware",
    "Native controller/card peers separately exercise actual busy, immutable-width validation, pads, changed payloads and failed transition containment",
    "Only successful 1.8-V eight-pin DDR52; no 1.2V or software-busy polling/retry/error-fallback qualification; unexecuted busy-poll boundary aborts",
]), indent=2)+"\n")
print(json.dumps(dict(records=32, output=str(out / "records.txt"))))
