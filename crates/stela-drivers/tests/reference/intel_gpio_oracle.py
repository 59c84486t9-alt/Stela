#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run unchanged pinned Intel GPIO functions over explicit register primitives.

The comparison covers register encodings/addressing, not kernel structure ABI,
locking implementation, real interrupt delivery, electrical timing or admission.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import signal
from amd_gpio_oracle import Evidence, digest

PIN = "cc9de5d4b5ab6459f5774946aa3195ad51236fa8"
DONORS = {
    "drivers/pinctrl/intel/pinctrl-intel.c": "c9ff3608b8662df154d8dbc266ab4d049cbccd91b2c422d91423371fbda9eddc",
    "drivers/pinctrl/intel/pinctrl-intel.h": "1759570d3a97da19eefd73723bb14ced6b3c391b52cbc5bd4456e909d275823a",
    "include/linux/pinctrl/pinconf-generic.h": "fd7ce25e1d63aa48169bbe08b98b2e7bdfbf12ff0bed0deb3547781aa170c0fb",
    "include/vdso/time64.h": "7bea2fb74771207f25d0d7659867388c65b74479e0aa7903c4ad0c7e8fac5834",
}


def function(source, name):
    match = re.search(r"\b" + re.escape(name) + r"\([^;{}]*\)\n\{", source)
    if match is None:
        raise ValueError("missing complete original function " + name)
    start = source.rfind("\n\n", 0, match.start()) + 2
    end, depth = match.end(), 1
    while depth and end < len(source):
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    if depth:
        raise ValueError("unterminated original function " + name)
    return source[start:end]


def macros(source):
    lines = source.splitlines(keepends=True)
    result, index = [], 0
    while index < len(lines):
        if lines[index].startswith("#define"):
            result.append(lines[index])
            while lines[index].rstrip().endswith("\\"):
                index += 1
                result.append(lines[index])
        index += 1
    return "".join(result)


PREFIX = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
#define __iomem
#define BIT(n) (1u << (n))
#define GENMASK(h,l) ((~0u << (l)) & (~0u >> (31-(h))))
#define ENOTSUPP 524
#define dev_warn(...) ((void)0)
static void hold(int *lock) { (void)lock; }
#define guard(kind) hold
static unsigned long order_base_2(unsigned long v) {
    return v < 2 ? 0 : (sizeof(v)*8 - __builtin_clzl(v-1));
}
struct intel_padgroup { unsigned int reg_num,base,size; int gpio_base; unsigned int padown_num; };
struct intel_community { unsigned int barno,padown_offset,padcfglock_offset,hostown_offset,is_offset,ie_offset,features,pin_base; size_t npins; const struct intel_padgroup *gpps; size_t ngpps; void *regs,*pad_regs; };
struct intel_pinctrl { struct intel_community *communities; size_t ncommunities; int lock; void *dev; };
static unsigned int writes;
static u32 readl(const void *p) { return *(const u32 *)p; }
static void writel(u32 v, void *p) { ++writes; *(u32 *)p=v; }
'''

MAIN = r'''
static u32 regs[4096];
static struct intel_padgroup groups[] = { {0,0,24,0,0}, {1,24,24,24,4} };
static struct intel_community community = { .padown_offset=0x20,.padcfglock_offset=0xa0,.hostown_offset=0xd0,.pin_base=0,.npins=48,.gpps=groups,.ngpps=2,.regs=regs,.pad_regs=regs+1024 };
static struct intel_pinctrl controller = { .communities=&community,.ncommunities=1 };
int main(void) {
    unsigned int count=0;
    const u32 seeds[]={0,1,2,0x100,0x200,0x300,0x40000000,0xa0800303};
    puts("INTEL_GPIO cc9de5d4b5ab6459f5774946aa3195ad51236fa8");
    for(unsigned s=0;s<8;s++)for(unsigned d=0;d<3;d++) {
        u32 input=seeds[s]&~(PADCFG0_PMODE_MASK|PADCFG0_GPIROUTIOXAPIC|PADCFG0_GPIROUTSCI|PADCFG0_GPIROUTSMI|PADCFG0_GPIROUTNMI);
        u32 value=input;
        if(d==1)value|=1;
        value=__intel_gpio_set_direction(value,d==0,d==1);
        printf("D %08x %u %08x\n",input,d,value);++count;
    }
    const unsigned strength[]={0,1,833,952,1000,4000,5000,20000,800,12345};
    for(unsigned rev=0;rev<2;rev++)for(unsigned s=0;s<4;s++)for(unsigned kind=0;kind<3;kind++)for(unsigned a=0;a<10;a++) {
        memset(regs,0,sizeof(regs));community.features=rev?3:0;writes=0;
        u32 seed=seeds[s+4];regs[1025]=seed;
        enum pin_config_param p=kind==0?PIN_CONFIG_BIAS_DISABLE:kind==1?PIN_CONFIG_BIAS_PULL_UP:PIN_CONFIG_BIAS_PULL_DOWN;
        int result=intel_config_set_pull(&controller,0,pinconf_to_config_packed(p,strength[a]));
        printf("P %u %08x %u %u %d %08x %u\n",rev,seed,kind,strength[a],result,regs[1025],writes);++count;
    }
    const unsigned durations[]={0,1,31,32,124,125,156,157,249,250,251,499,500,1000,15625,31250,62500,100000,500000,1000000,1024000,1024001,2000000,0xffffffff};
    for(unsigned rev=0;rev<2;rev++)for(unsigned s=0;s<4;s++)for(unsigned a=0;a<24;a++) {
        memset(regs,0,sizeof(regs));community.features=rev?3:0;writes=0;
        u32 seed=seeds[s+4];regs[1024]=seed;regs[1026]=0x80000020;
        int result=intel_config_set_debounce(&controller,0,durations[a]);
        printf("B %u %08x %u %d %08x %08x %u\n",rev,seed,durations[a],result,regs[1024],regs[1026],writes);++count;
    }
    const unsigned pins[]={0,7,8,23,24,47};
    const u32 owners[]={0,1,7,8,15,0x10,0x10000000,0xffffffff};
    for(unsigned rev=0;rev<2;rev++)for(unsigned p=0;p<6;p++)for(unsigned a=0;a<8;a++) {
        memset(regs,0,sizeof(regs));community.features=rev?PINCTRL_FEATURE_3BIT_PAD_OWN:0;
        unsigned pin=pins[p];
        const struct intel_padgroup *group=intel_community_get_padgroup(&community,pin);
        unsigned local=pin-group->base;
        unsigned offset=rev?0x20+pin*4:0x20+group->padown_num*4+(local/8)*4;
        regs[offset/4]=owners[a];
        printf("O %u %u %08x %u\n",rev,pin,owners[a],intel_pad_owned_by_host(&controller,pin));++count;
    }
    printf("DONE %u\n",count);
    return 0;
}
'''


def generate(evidence, args):
    texts = {}
    for name, expected in DONORS.items():
        raw = (args.linux / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("pinned input mismatch: " + name)
        texts[name] = raw.decode()
    evidence.record["donors"] = DONORS
    source = texts["drivers/pinctrl/intel/pinctrl-intel.c"]
    generic = texts["include/linux/pinctrl/pinconf-generic.h"]
    names = ["intel_get_community", "intel_community_get_padgroup", "intel_get_padcfg", "intel_pad_owned_by_host", "__intel_gpio_set_direction", "intel_config_set_pull", "intel_config_set_debounce"]
    helpers = {name: function(source, name) for name in names}
    helpers.update((name, function(generic, name)) for name in ["pinconf_to_config_param", "pinconf_to_config_argument", "pinconf_to_config_packed"])
    enum = re.search(r"enum pin_config_param \{.*?\n\};", generic, re.S).group()
    constants = macros(source) + "\n" + "\n".join(re.findall(r"^#define PINCTRL_FEATURE_[^\n]*", texts["drivers/pinctrl/intel/pinctrl-intel.h"], re.M))
    constants += "\n" + re.search(r"^#define NSEC_PER_USEC[^\n]*", texts["include/vdso/time64.h"], re.M).group()
    constants += "\n" + re.search(r"^#define PIN_CONF_PACKED[^\n]*", generic, re.M).group()
    helper_text = "\n\n".join(helpers[name] for name in ["pinconf_to_config_param", "pinconf_to_config_argument", "pinconf_to_config_packed", *names])
    (evidence.root / "original-functions.c").write_text(helper_text)
    evidence.record["whole_original_functions"] = {name: hashlib.sha256(value.encode()).hexdigest() for name, value in helpers.items()}
    path = evidence.root / "oracle.c"
    path.write_text(PREFIX + constants + "\n" + enum + "\n" + helper_text + "\n" + MAIN)
    binary = evidence.root / "oracle"
    evidence.command("compiler", [args.cc, "--version"], 10)
    evidence.command("compile", [args.cc, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer", str(path), "-o", str(binary)], 60)
    before = {str(path): digest(path), str(binary): digest(binary)}
    trace = evidence.command("execute", [str(binary)], 30)
    if before != {str(path): digest(path), str(binary): digest(binary)}:
        raise ValueError("oracle source/binary drift")
    if (evidence.root / "execute.stderr").read_bytes():
        raise ValueError("oracle emitted unexpected runtime diagnostics")
    lines = trace.decode().splitlines()
    if lines[0] != "INTEL_GPIO " + PIN or lines[-1] != "DONE 552" or len(lines) != 554:
        raise ValueError("unexpected original comparison count")
    with args.output.open("xb") as out:
        out.write(trace)
    evidence.record.update(trace_sha256=digest(args.output), artifact_admission=before, stable=True, records=552)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    evidence = Evidence(args.output.resolve())
    evidence.record.update(pin=PIN, harness_sha256=digest(Path(__file__)), executor_sha256=digest(Path(__file__).with_name("amd_gpio_oracle.py")), limits=__doc__)
    def interrupted(signum, _frame):
        evidence.cancellation = signum
    previous = [signal.signal(sig, interrupted) for sig in [signal.SIGTERM, signal.SIGINT]]
    try:
        generate(evidence, args)
        evidence.record["status"] = "passed"
    except BaseException as error:
        evidence.record.update(status="failed", error=str(error))
        raise
    finally:
        evidence.record["finished_utc"] = datetime.now(timezone.utc).isoformat()
        evidence.save()
        for sig, handler in zip([signal.SIGTERM, signal.SIGINT], previous):
            signal.signal(sig, handler)


if __name__ == "__main__":
    main()
