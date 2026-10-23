#!/usr/bin/env python3
"""Compile unchanged pinned acp70 init bodies against an independent MMIO model.

SOURCE ONLY until the central gate owner runs this script. This is a software
oracle for the exclusive no-SoundWire subset, never physical audio evidence.
"""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile

PIN = "a804c5742bff224d4cb4d25dd383554d598be32b"
DONORS = {
    "sound/soc/amd/ps/ps-common.c": "fef7db192ee9f241be950dde0e5fe393035644e01f3c833a68fc36b18bea8435",
    "sound/soc/amd/ps/acp63.h": "73fa37eefdb58e4a25b2499263bd772c2bfe4010c53c43336ba656f4f5fa0d4b",
    "include/sound/acp63_chip_offset_byte.h": "920b1783108e347a30f45dd57cfc5ead74d624821107b8dcf4c37fc30844da3a",
}
FUNCTIONS = (
    "acp70_power_on", "acp70_reset", "acp70_enable_sdw_host_wake_interrupts",
    "acp70_enable_interrupts", "acp70_init",
)
DEFINES = {
    "ACP_PGFSM_STATUS", "ACP_PGFSM_CONTROL", "ACP_CONTROL", "ACP_SOFT_RESET",
    "ACP_EXTERNAL_INTR_ENB", "ACP_EXTERNAL_INTR_CNTL", "ACP_EXTERNAL_INTR_CNTL1",
    "ACP_SW0_WAKE_EN", "ACP_SW1_WAKE_EN", "ACP_ZSC_DSP_CTRL", "ACP_PME_EN",
    "ACP70_PGFSM_STATUS_MASK", "ACP70_PGFSM_CNTL_POWER_ON_MASK", "DELAY_US",
    "ACP70_TIMEOUT", "ACP_SOFT_RESET_SOFTRESET_AUDDONE_MASK", "ACP_ERROR_IRQ",
    "ACP70_SDW_HOST_WAKE_MASK",
}


def function(source, name):
    # Keep each actual C body byte-for-byte: no reimplementation of donor logic.
    match = re.search(r"^static [^\n]+\b" + re.escape(name) + r"\([^;]*?\n\{", source, re.M)
    if match is None:
        raise RuntimeError(f"missing original body: {name}")
    start = source.index("{", match.start())
    depth = 1
    end = start + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux-gitdir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    sources = {}
    for name, expected in DONORS.items():
        data = subprocess.check_output(["git", f"--git-dir={args.linux_gitdir}", "show", f"{PIN}:{name}"])
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise RuntimeError(f"donor SHA-256 mismatch: {name}: {actual}")
        sources[name] = data.decode()
    definitions = {}
    for source in sources.values():
        for line in source.splitlines():
            match = re.match(r"#define\s+(\w+)\s+(.+)$", line)
            if match and match[1] in DEFINES:
                if match[1] in definitions:
                    raise RuntimeError(f"duplicate donor definition {match[1]}")
                definitions[match[1]] = line
    if set(definitions) != DEFINES:
        raise RuntimeError(f"missing donor definitions: {DEFINES - set(definitions)}")
    prelude = r'''
#include <stdint.h>
#include <stdio.h>
typedef uint32_t u32;
#define __iomem
#define BIT(n) (1U << (n))
struct device { unsigned unused; };
#define dev_err(dev, ...) do { (void)(dev); } while (0)
static u32 regs[0x11000 / 4];
'''
    model = r'''
static u32 readl(const void *address) { return *(const u32 *)address; }
static void writel(u32 value, void *address) {
    unsigned offset = (unsigned)((unsigned char *)address - (unsigned char *)regs);
    printf("w %04x %08x\n", offset, value);
    if (offset == ACP_PGFSM_CONTROL && value == ACP70_PGFSM_CNTL_POWER_ON_MASK)
        regs[ACP_PGFSM_STATUS / 4] = 0;
    else if (offset == ACP_SOFT_RESET)
        value = value ? ACP_SOFT_RESET_SOFTRESET_AUDDONE_MASK : 0;
    *(u32 *)address = value;
}
// Independent synchronous register model: original poll condition is evaluated
// unchanged. A permanently nonready value terminates with a timeout; native
// elapsed-time/deadline behavior is tested separately by the Rust model.
#define readl_poll_timeout(address, val, condition, delay, budget) ({ \
    int result = -110; \
    for (unsigned poll = 0; poll != 10; ++poll) { \
        val = readl(address); \
        if (condition) { result = 0; break; } \
    } \
    result; \
})
'''
    runner = r'''
int main(void) {
    const u32 statuses[] = {0, 1, 2, 0x80, 0x100};
    struct device dev = {0};
    for (unsigned test = 0; test != sizeof(statuses) / sizeof(statuses[0]); ++test) {
        for (unsigned word = 0; word != sizeof(regs) / sizeof(regs[0]); ++word) regs[word] = 0;
        regs[ACP_PGFSM_STATUS / 4] = statuses[test];
        printf("case %08x\n", statuses[test]);
        int result = acp70_init(regs, &dev);
        printf("result %d\n", result);
    }
    return 0;
}
'''
    body = "\n".join(function(sources["sound/soc/amd/ps/ps-common.c"], name) for name in FUNCTIONS)
    source = prelude + "\n".join(definitions[name] for name in sorted(definitions)) + model + body + runner
    with tempfile.TemporaryDirectory(prefix="stela-acp70-oracle-") as temporary:
        directory = Path(temporary)
        c_file = directory / "oracle.c"
        binary = directory / "oracle"
        c_file.write_text(source)
        subprocess.run([args.cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", str(c_file), "-o", str(binary)], check=True)
        trace = subprocess.check_output([str(binary)], text=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(f"linux {PIN}\n" + trace)
    print(args.output)


if __name__ == "__main__":
    main()
