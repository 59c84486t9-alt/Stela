#!/usr/bin/env python3
"""Run the pinned rtw88 country lookup for all two-byte inputs.

Usage: script REFERENCE_RTW88_DIRECTORY OUTPUT_DIRECTORY
No firmware, regulatory authority, or hardware accesses are involved.
"""
import hashlib
import json
import pathlib
import subprocess
import sys

PIN = "a804c5742bff224d4cb4d25dd383554d598be32b"
HASHES = {
    "main.h": "313a4522a87ef4797e65de177ff23dd08f02f33e51ce9636604a5c43015c7f6e",
    "regd.c": "d12704ef1123132bd881d5831f4d996a0e0dab5a81a460ed87baac671ca7fd0d",
}
reference, output = map(pathlib.Path, sys.argv[1:])
sources = {}
for name, expected in HASHES.items():
    data = (reference / name).read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError(f"{name}: expected {expected}, found {actual}")
    sources[name] = data.decode()
output.mkdir(parents=True, exist_ok=True)
manifest = {"linux_revision": PIN, "files": HASHES, "symbols": []}


def take(name, start, end):
    source = sources[name]
    begin = source.index(start)
    text = source[begin:source.index(end, begin)]
    manifest["symbols"].append({
        "file": name, "start": start,
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
    })
    return text


parts = [
    take("main.h", "enum rtw_regulatory_domains {", "\nenum rtw_txq_flags"),
    take("main.h", "struct rtw_regulatory {", "\nenum rtw_regd_state"),
    take("regd.c", "#define COUNTRY_REGD_ENT", "\n#define rtw_dbg_regd_dump"),
    take("regd.c", "static const struct rtw_regulatory rtw_reg_ww", "\nstatic void rtw_regd_apply_hw_cap_flags"),
    take("regd.c", "static bool rtw_reg_match", "\nstatic\nvoid rtw_regd_notifier"),
]
preamble = """#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
#define __nonstring __attribute__((nonstring))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
"""
wrapper = """
int main(void)
{
    for (unsigned int first = 0; first < 256; first++) {
        for (unsigned int second = 0; second < 256; second++) {
            char alpha2[2] = {(char)first, (char)second};
            const struct rtw_regulatory *reg = rtw_reg_find_by_name(alpha2);
            u8 row[4] = {first, second, reg->txpwr_regd_2g, reg->txpwr_regd_5g};
            if (fwrite(row, sizeof(row), 1, stdout) != 1)
                return 1;
        }
    }
    return fflush(stdout) != 0;
}
"""
c_source = output / "oracle.c"
c_source.write_text(preamble + "\n".join(parts) + wrapper)
subprocess.run([
    "clang", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
    "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
    str(c_source), "-o", str(output / "oracle"),
], check=True)
trace = subprocess.check_output([str(output / "oracle")])
if len(trace) != 65536 * 4:
    raise ValueError(f"unexpected trace length: {len(trace)}")
(output / "trace.bin").write_bytes(trace)
manifest["cases"] = 65536
manifest["trace_bytes"] = len(trace)
manifest["trace_sha256"] = hashlib.sha256(trace).hexdigest()
(output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps({key: manifest[key] for key in ["cases", "trace_bytes", "trace_sha256"]}))
