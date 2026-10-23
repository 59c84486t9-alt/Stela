#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""UNRUN: execute the unchanged pinned CNL notification acknowledgement body.

Only the native-register access environment is modeled. The donor C function
and its register macros are extracted verbatim after whole-file hash checks.
This bounded oracle does not emulate SOF firmware, ROM, PCM or physical audio.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

PIN = "a804c5742bff224d4cb4d25dd383554d598be32b"
DONORS = {
    "sound/soc/sof/intel/cnl.c": "05a2e471c1f602251eb13d026ecf62d315cb07d55c34fd6564f3a6c7e527ef27",
    "sound/soc/sof/intel/hda.h": "f377dbb6688b331a11b3a673d02540f70d86ba386a117660937d00a98ae60186",
}


def donor(git_dir, name):
    data = subprocess.check_output(["git", f"--git-dir={git_dir}", "show", f"{PIN}:{name}"])
    if hashlib.sha256(data).hexdigest() != DONORS[name]:
        raise SystemExit(f"donor hash mismatch: {name}")
    return data.decode()


def function(source, name):
    match = re.search(r"static void " + re.escape(name) + r"\([^)]*\)\s*\{", source)
    if not match:
        raise SystemExit(f"missing original function {name}")
    depth = 1
    end = match.end()
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux-git-dir", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = donor(args.linux_git_dir, "sound/soc/sof/intel/cnl.c")
    header = donor(args.linux_git_dir, "sound/soc/sof/intel/hda.h")
    names = ["CNL_DSP_IPC_BASE", "CNL_DSP_REG_HIPCTDR", "CNL_DSP_REG_HIPCTDA", "CNL_DSP_REG_HIPCTDR_BUSY", "CNL_DSP_REG_HIPCTDA_DONE"]
    macros = []
    for name in names:
        match = re.search(r"^#define\s+" + name + r"\s+.*$", header, re.MULTILINE)
        if not match:
            raise SystemExit(f"missing original macro {name}")
        macros.append(match.group())
    program = """#include <stdint.h>
#include <stdio.h>
#define BIT(n) (1u << (n))
#define HDA_DSP_BAR 0
struct snd_sof_dev { unsigned unused; };
static uint32_t registers[256];
static void snd_sof_dsp_update_bits_forced(struct snd_sof_dev *s, int bar,
                                         unsigned offset, uint32_t mask, uint32_t bits) {
    (void)s; (void)bar;
    uint32_t value = (registers[offset] & ~mask) | bits;
    printf("%x %08x\\n", offset, value);
    registers[offset] = value;
}
""" + "\n".join(macros) + "\n" + function(source, "cnl_ipc_host_done") + """
int main(void) {
    struct snd_sof_dev device = {0};
    registers[CNL_DSP_REG_HIPCTDR] = 0xf0000000;
    cnl_ipc_host_done(&device);
    return 0;
}
"""
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="intel-sof-reference-", dir=args.output.parent) as scratch:
        c_file = Path(scratch) / "original.c"
        binary = Path(scratch) / "original"
        c_file.write_text(program)
        subprocess.run([os.environ.get("CC", "clang"), "-std=c11", "-Wall", "-Wextra", "-Werror", str(c_file), "-o", str(binary)], check=True)
        args.output.write_bytes(subprocess.check_output([str(binary)]))


if __name__ == "__main__":
    main()
