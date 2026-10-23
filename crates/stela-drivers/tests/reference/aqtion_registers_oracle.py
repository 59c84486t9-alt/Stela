#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Stela contributors
"""Bounded unchanged-Linux AQtion LLH comparison. Authored status: UNRUN.

Usage: aqtion_registers_oracle.py ATLANTIC_DIRECTORY FRESH_IGNORED_OUTPUT_DIRECTORY
Only register encodings/results are covered, not firmware or device operation.
No donor address/mask/shift arithmetic is reproduced in this Python or callback.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

COMMIT = "a804c5742bff224d4cb4d25dd383554d598be32b"
HASHES = {
    "aq_hw_utils.c": "d28153e839b7a7945956ec30adbe8eb5136328fb1f822a33f4ef3324510cae8f",
    "hw_atl/hw_atl_llh.c": "26921d261d50b1b66911671d398cb257c00ef099461398697d76f9935633358d",
    "hw_atl/hw_atl_llh.h": "793a169539219160043485a8cfcf40ffc4a32bc2f3ffee9faa1758634aab6920",
    "hw_atl/hw_atl_llh_internal.h": "81f10e0620c9b7114892bf06e115d2c9e18b6988c6078c592a68cfb3c44d74d6",
    "hw_atl2/hw_atl2_llh.c": "6a1d5b6a7026432e07c5d27791c062eb89fb7acf459df99a0fbc11a91a175e42",
    "hw_atl2/hw_atl2_llh.h": "3a701f3b50ba457990de2388fa35564ea123d418c98c2844c0dfff9434dff5b1",
    "hw_atl2/hw_atl2_llh_internal.h": "e06ac483e88579def956af0d00ddbceac498993480962af86ba074dcea6ab67d",
}
INITIAL = (0, 0xA5C35A3C, 0x5A3CA5C3)  # Never the Rust removed-device sentinel.
RINGS = (0, 7, 31)
FILTERS = (0, 16, 32)
TCS = (0, 1, 3)
SCALAR = (0,)
BIT = (0, 1)
WORD = (0, 0x12345678, 0xFFFFFFFF)
TAIL = (0, 63, 8191)
# Explicit input domain, independent of the Rust Field table. Values fit the
# declared donor field widths; these are not complete legal queue configurations.
# (original helper, call shape, indexes, input values; getters use a zero marker)
CASES = (
    ("hw_atl_rdm_rx_desc_en_set", "set-indexed", RINGS, BIT),
    ("hw_atl_reg_rx_dma_desc_base_addresslswset", "set-indexed", RINGS, WORD),
    ("hw_atl_reg_rx_dma_desc_base_addressmswset", "set-indexed", RINGS, WORD),
    ("hw_atl_rdm_rx_desc_len_set", "set-indexed", RINGS, (0, 1, 1023)),
    ("hw_atl_rdm_rx_desc_data_buff_size_set", "set-indexed", RINGS, (0, 1, 31)),
    ("hw_atl_rdm_rx_desc_head_buff_size_set", "set-indexed", RINGS, (0, 1, 31)),
    ("hw_atl_rdm_rx_desc_head_splitting_set", "set-indexed", RINGS, BIT),
    ("hw_atl_reg_rx_dma_desc_tail_ptr_set", "set-indexed", RINGS, TAIL),
    ("hw_atl_tdm_tx_desc_en_set", "set-indexed", RINGS, BIT),
    ("hw_atl_reg_tx_dma_desc_base_addresslswset", "set-indexed", RINGS, WORD),
    ("hw_atl_reg_tx_dma_desc_base_addressmswset", "set-indexed", RINGS, WORD),
    ("hw_atl_tdm_tx_desc_len_set", "set-indexed", RINGS, (0, 1, 1023)),
    ("hw_atl_tdm_tx_desc_head_ptr_get", "get-indexed", RINGS, (0,)),
    ("hw_atl_reg_tx_dma_desc_tail_ptr_set", "set-indexed", RINGS, TAIL),
    ("hw_atl_rpfl2_uc_flr_en_set", "set-indexed", FILTERS, BIT),
    ("hw_atl_rpfl2unicast_flr_act_set", "set-indexed", FILTERS, (0, 1, 7)),
    ("hw_atl_rpfl2unicast_dest_addresslsw_set", "set-indexed", FILTERS, WORD),
    ("hw_atl_rpfl2unicast_dest_addressmsw_set", "set-indexed", FILTERS, (0, 1, 65535)),
    ("hw_atl_rpb_rx_pkt_buff_size_per_tc_set", "set-indexed", TCS, (0, 1, 511)),
    ("hw_atl_rpb_rx_buff_hi_threshold_per_tc_set", "set-indexed", TCS, (0, 1, 16383)),
    ("hw_atl_tpb_tx_pkt_buff_size_per_tc_set", "set-indexed", TCS, (0, 1, 255)),
    ("hw_atl_tpb_tx_buff_hi_threshold_per_tc_set", "set-indexed", TCS, (0, 1, 8191)),
    ("hw_atl_rdm_rx_dma_desc_cache_init_done_get", "get", SCALAR, (0,)),
    ("hw_atl2_rpfl2_uc_flr_tag_set", "set-indexed", FILTERS, (0, 1, 63)),
    ("hw_atl2_rpfl2_bc_flr_tag_set", "set", SCALAR, (0, 1, 63)),
    ("hw_atl2_rpf_rss_hash_type_set", "set", SCALAR, (0, 1, 511)),
    ("hw_atl2_rpf_act_rslvr_section_en_set", "set", SCALAR, (0, 1, 65535)),
    ("hw_atl2_rpf_act_rslvr_section_en_get", "get", SCALAR, (0,)),
)
EXPECTED_CASES = 600
SCOPE = (
    "28 unchanged LLH helpers plus unchanged aq_hw_write_reg_bit/read_reg_bit; "
    "raw single-word callback only; 600 independent input cases. "
    "In-range field encodings only: Linux does not mask oversized values but Rust does. "
    "No all-ones initial reads: Rust treats u32::MAX as removal. "
    "Linux may elide unchanged writes; compare addresses/results, not exact write counts. "
    "No RX descriptor-head getter comparison (no existing Rust Field); TX head is covered. "
    "No firmware, reset, timing, ordering, BAR/PCI ownership, MMIO faults, DMA, "
    "descriptor/payload lifecycle, interrupts, link, packets, power, guest integration "
    "or physical device qualification; no register coverage/completion claim."
)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def function(raw, name):
    """Extract an exact contiguous original definition, including its signature."""
    matches = list(re.finditer(
        rb"^(?:void|u32)\s+" + name.encode() + rb"\([^;{}]*\)\n\{", raw, re.M))
    if len(matches) != 1:
        raise ValueError(f"expected one original definition: {name}")
    match = matches[0]
    at, depth = match.end(), 1
    while depth and at < len(raw):
        depth += (raw[at] == ord("{")) - (raw[at] == ord("}"))
        at += 1
    if depth:
        raise ValueError(f"unterminated original definition: {name}")
    return raw[match.start():at]


# Independently authored raw callback. It knows no register fields or offsets.
# A callback records the donor-selected address; a second distinct address aborts.
PRELUDE = r'''// SPDX-License-Identifier: GPL-2.0-only
// Wrapper authored by Stela; included donor definitions remain unchanged.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "donor/hw_atl/hw_atl_llh.h"
#include "donor/hw_atl/hw_atl_llh_internal.h"
#include "donor/hw_atl2/hw_atl2_llh.h"
#include "donor/hw_atl2/hw_atl2_llh_internal.h"
struct aq_hw_s { u32 word, address, reads, writes; bool seen; };
static void observe(struct aq_hw_s *hw, u32 address) {
    if (address % 4 || address >= 0x10000) abort();
    if (hw->seen && hw->address != address) abort();
    hw->address = address;
    hw->seen = true;
}
static u32 aq_hw_read_reg(struct aq_hw_s *hw, u32 address) {
    observe(hw, address);
    if (++hw->reads > 1 || hw->writes) abort();
    return hw->word;
}
static void aq_hw_write_reg(struct aq_hw_s *hw, u32 address, u32 value) {
    observe(hw, address);
    if (++hw->writes > 1) abort();
    hw->word = value;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    out = args.out.resolve()
    repo = Path(__file__).resolve().parents[4]
    if not out.is_relative_to(repo / ".stela") or out.exists():
        raise ValueError("output must be a fresh directory under this repo's ignored .stela/")
    subprocess.run(["git", "-C", str(repo), "check-ignore", "--quiet", "--", str(out)],
                   check=True, timeout=10)
    texts = {}
    for name, digest in HASHES.items():
        raw = (source / name).read_bytes()  # Missing inputs fail before output creation.
        if sha256(raw) != digest:
            raise ValueError(f"wrong pinned donor SHA-256: {name}")
        texts[name] = raw
    if len(CASES) != 28 or sum(len(ix) * len(vs) * len(INITIAL)
                              for _, _, ix, vs in CASES) != EXPECTED_CASES:
        raise ValueError("unexpected case inventory")
    out.mkdir(parents=True, exist_ok=False)
    for name, raw in texts.items():
        target = out / "donor" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    types = out / "include/linux/types.h"
    types.parent.mkdir(parents=True)
    types.write_text("#include <stdint.h>\ntypedef uint8_t u8;\ntypedef uint16_t u16;\n"
                     "typedef uint32_t u32;\ntypedef uint64_t u64;\n")
    definitions = [("aq_hw_utils.c", "aq_hw_write_reg_bit"),
                   ("aq_hw_utils.c", "aq_hw_read_reg_bit")]
    definitions += [("hw_atl2/hw_atl2_llh.c" if name.startswith("hw_atl2_")
                     else "hw_atl/hw_atl_llh.c", name) for name, _, _, _ in CASES]
    extracts, includes = {}, []
    for file, name in definitions:
        body = function(texts[file], name)
        target = out / "bodies" / (name + ".c")
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(body)
        extracts[name] = {"source": file, "file": str(target.relative_to(out)),
                          "sha256": sha256(body)}
        includes.append(f'#include "bodies/{name}.c"\n')
    inputs, switches = [], []
    for case_id, (name, shape, indexes, values) in enumerate(CASES):
        call_args = {"set-indexed": "&hw, c.value, c.index", "set": "&hw, c.value",
                     "get-indexed": "&hw, c.index", "get": "&hw"}[shape]
        call = f"{name}({call_args})"
        statement = f"result = {call}" if shape.startswith("get") else call
        switches.append(f"case {case_id}: {statement}; break;\n")
        for index in indexes:
            for initial in INITIAL:
                for value in values:
                    inputs.append(f'{{"{name}",{case_id}u,{index}u,{initial}u,{value}u}}')
    code = PRELUDE + "".join(includes) + '''
struct input { const char *name; u32 id, index, initial, value; };
static const struct input cases[] = {
''' + ",\n".join(inputs) + '''
};
int main(void) {
    if (puts("AQTION_REGISTERS_V1 600") == EOF) abort();
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        struct input c = cases[i];
        struct aq_hw_s hw = {.word = c.initial};
        u32 result = 0;
        switch (c.id) {
''' + "".join(switches) + '''
        default: abort();
        }
        if (!hw.seen || hw.reads + hw.writes == 0) abort();
        if (printf("%s %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32
                   " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 "\\n",
                   c.name, c.index, c.initial, c.value, hw.address,
                   hw.word, result, hw.reads, hw.writes) < 0) abort();
    }
    if (puts("END 600") == EOF || fflush(stdout)) abort();
    return 0;
}
'''
    cpath, binary = out / "wrapper.c", out / "aqtion-registers"
    cpath.write_text(code)
    compile_cmd = ["clang", "-std=c11", "-O1", "-g", "-fsanitize=address,undefined",
                   "-fno-sanitize-recover=all", "-fno-omit-frame-pointer",
                   "-I", str(out / "include"), str(cpath), "-o", str(binary)]
    run_cmd = [str(binary)]
    manifest = {
        "status": "UNRUN", "linux_commit": COMMIT, "source": str(source),
        "source_sha256": HASHES, "extracts": extracts, "scope": SCOPE,
        "helpers": 28, "case_count": EXPECTED_CASES, "cases": CASES,
        "initial_words": INITIAL, "wrapper_sha256": sha256(code.encode()),
        "types_shim_sha256": sha256(types.read_bytes()),
        "script_sha256": sha256(Path(__file__).read_bytes()),
        "commands": {"generate": [sys.executable, str(Path(__file__).resolve()),
                                  str(source), str(out)],
                     "compile": compile_cmd, "run": run_cmd},
        "timeouts_seconds": {"compile": 60, "run": 15},
        "environment": {"ASAN_OPTIONS": "detect_leaks=0:halt_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1"},
        "trace_columns": "helper index initial value address final result reads writes",
        "rust_comparison": "UNRUN",
    }
    manifest_path = out / "manifest.json"

    def save():
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    save()  # Retain source/commands even if compilation or execution fails.
    env = dict(os.environ, **manifest["environment"])
    for stage, command, timeout in [("compile", compile_cmd, 60), ("run", run_cmd, 15)]:
        manifest["status"] = stage.upper() + "_STARTED"
        save()
        try:
            receipt = subprocess.run(command, capture_output=True, timeout=timeout, env=env)
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b"", error.stderr or b""
            (out / (stage + ".stdout")).write_bytes(stdout)
            (out / (stage + ".stderr")).write_bytes(stderr)
            manifest[stage] = {"stdout_sha256": sha256(stdout),
                               "stderr_sha256": sha256(stderr)}
            manifest["status"] = stage.upper() + "_TIMEOUT"
            save()
            raise
        (out / (stage + ".stdout")).write_bytes(receipt.stdout)
        (out / (stage + ".stderr")).write_bytes(receipt.stderr)
        manifest[stage] = {"returncode": receipt.returncode,
                           "stdout_sha256": sha256(receipt.stdout),
                           "stderr_sha256": sha256(receipt.stderr)}
        manifest["status"] = stage.upper() + ("_OK" if receipt.returncode == 0 else "_FAILED")
        save()
        receipt.check_returncode()
    trace = receipt.stdout
    # Check framing/count only here; strict independent input/output validation
    # belongs to the Rust comparison. Never compute expected fields in Python.
    lines = trace.splitlines()
    if (len(lines) != EXPECTED_CASES + 2 or lines[0] != b"AQTION_REGISTERS_V1 600"
            or lines[-1] != b"END 600"):
        manifest["status"] = "INVALID_TRACE"
        save()
        raise ValueError("unexpected trace framing/count")
    (out / "trace.txt").write_bytes(trace)
    manifest["trace"] = {"sha256": sha256(trace), "bytes": len(trace),
                         "case_count": EXPECTED_CASES}
    manifest["binary_sha256"] = sha256(binary.read_bytes())
    manifest["status"] = "C_ORACLE_EXECUTED_RUST_COMPARISON_UNRUN"
    save()
    print(manifest_path)


if __name__ == "__main__":
    main()
