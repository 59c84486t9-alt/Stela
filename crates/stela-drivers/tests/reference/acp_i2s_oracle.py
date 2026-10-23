#!/usr/bin/env python3
"""Unchanged pinned ACP3x/5x DMA configuration bodies against a write model.

Authoring is source-only. The central gate owner separately executes this tool
and the matching ignored Rust comparison. No donor logic is reimplemented.
"""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile

PIN = "a804c5742bff224d4cb4d25dd383554d598be32b"
DONORS = {
    "raven/acp3x-pcm-dma.c": "76a3580529fba8bed801045774b790a7ce4194bb119c1d75cd05a7de9e305b4f",
    "raven/acp3x.h": "d10c03acef745035b061830e336a64eb805b50002486a7ac61a38b84e1697fd1",
    "raven/chip_offset_byte.h": "7bfdf16f51fda109706dfece6dcb4d058386ce1c5fb787febe46fa8f3ff29cde",
    "vangogh/acp5x-pcm-dma.c": "1837417696446a4fc80429c6f6774dd1b95fdaefc0c5dbdf4c385c90a943d61a",
    "vangogh/acp5x.h": "4a0a4f58538dd6f78e4e7f06e773d2c3ee6d88e160e381eba45a178a353a8b45",
    "vangogh/vg_chip_offset_byte.h": "ea318408cfe95c5f797624bb28d57ef4c3604e9a3633f65d09dedf78cd9d12cc",
}


def original_function(source, name):
    match = re.search(r"^static void " + re.escape(name) + r"\([^;]*?\n\{", source, re.M)
    if match is None:
        raise RuntimeError(f"missing unchanged body: {name}")
    position = source.index("{", match.start()) + 1
    depth = 1
    while depth:
        depth += (source[position] == "{") - (source[position] == "}")
        position += 1
    return source[match.start():position]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux-gitdir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    sources = {}
    for donor, expected in DONORS.items():
        data = subprocess.check_output(["git", f"--git-dir={args.linux_gitdir}", "show", f"{PIN}:sound/soc/amd/{donor}"])
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError(f"pinned donor hash mismatch: {donor}")
        sources[donor] = data.decode()
    trace = f"linux {PIN}\n"
    with tempfile.TemporaryDirectory(prefix="stela-acp-i2s-oracle-") as temporary:
        directory = Path(temporary)
        for folder, prefix, header, revision, write in [
            ("raven", "acp3x", "chip_offset_byte.h", 0, "rv_writel"),
            ("vangogh", "acp5x", "vg_chip_offset_byte.h", 0x50, "acp_writel"),
        ]:
            # Original constant lines are copied, not converted into a second
            # hand-maintained register inventory. No Linux function is replaced.
            definitions = []
            for name in [f"{folder}/{prefix}.h", f"{folder}/{header}"]:
                for line in sources[name].splitlines():
                    if re.match(r"#define\s+\w+\s+", line):
                        if line.endswith("\\"):
                            raise RuntimeError("unexpected multiline donor definition")
                        definitions.append(line)
            prelude = r'''
#include <stdint.h>
#include <stdio.h>
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint64_t dma_addr_t;
#define BIT(n) (1U << (n))
#define PAGE_SIZE 4096
#define SNDRV_PCM_STREAM_PLAYBACK 0
#define SNDRV_PCM_STREAM_CAPTURE 1
#define lower_32_bits(v) ((u32)(v))
#define upper_32_bits(v) ((u32)((v) >> 32))
// The real original body uses absolute register names and base-relative
// wrappers. Reserve the complete namespace so its pointer arithmetic is valid.
static unsigned char register_namespace[0x1251000];
'''
            types = f'''
struct i2s_stream_instance {{
    u16 num_pages;
    u16 i2s_instance;
    dma_addr_t dma_addr;
    void *{prefix}_base;
}};
static void {write}(u32 value, void *address) {{
    unsigned offset = (unsigned)((unsigned char *)address - register_namespace - 0x1240000);
    printf("w %04x %08x\\n", offset, value);
}}
'''
            body = original_function(sources[f"{folder}/{prefix}-pcm-dma.c"], f"config_{prefix}_dma")
            runner = f'''
int main(void) {{
    for (unsigned slot = 0; slot != 4; ++slot) {{
        printf("case {revision:02x} %u\\n", slot);
        struct i2s_stream_instance rtd = {{
            .num_pages = 3,
            .i2s_instance = slot < 2 ? 1 : 2,
            .dma_addr = UINT64_C(0x180020000),
            .{prefix}_base = register_namespace,
        }};
        config_{prefix}_dma(&rtd, slot % 2);
    }}
    return 0;
}}
'''
            c_file = directory / f"{prefix}.c"
            binary = directory / prefix
            c_file.write_text(prelude + "\n".join(definitions) + types + body + runner)
            subprocess.run([args.cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", str(c_file), "-o", str(binary)], check=True)
            trace += subprocess.check_output([str(binary)], text=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(trace)
    print(args.output)


if __name__ == "__main__":
    main()
