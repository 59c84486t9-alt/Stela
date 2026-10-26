#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute unchanged pinned Cypress interval/calibration command functions.

The transport and empty-output services are modeled. This qualifies command
bytes, lengths and budgets, not physical calibration, sensor accuracy or the
complete Linux power policy. Native FIFO/lifecycle/failure tests are separate.
Usage: cyapa_controls_oracle.py <pinned-source-root> <new-evidence-directory>
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

PIN = "cc9de5d4b5ab6459f5774946aa3195ad51236fa8"
HASHES = {
    "cyapa.h": "35afa87b2e4d8837ceeae7f8c33f3e01a8a0fc9760edd1f14cfaeb71c268fec9",
    "cyapa_gen5.c": "cad1c2818e09911ea4dec91f617e4204a1d8226daed388849f48bc549619488a",
    "cyapa_gen6.c": "ad865d1fee9993314ee7d57a90c735cf21501e90385568267416422d3ea24634",
}
FUNCTIONS = {
    "cyapa_gen5.c": [
        "cyapa_gen5_set_interval_time", "cyapa_gen5_get_interval_time",
        "cyapa_pip_resume_scanning", "cyapa_pip_suspend_scanning",
        "cyapa_pip_calibrate_pwcs",
    ],
    "cyapa_gen6.c": ["cyapa_gen6_set_interval_setting", "cyapa_gen6_get_interval_setting"],
}


def declaration(source, marker):
    start = source.index(marker)
    at = source.index("{", start) + 1
    depth = 1
    while depth:
        depth += (source[at] == "{") - (source[at] == "}")
        at += 1
    return source[start:at]


PREFIX = r'''
// SPDX-License-Identifier: GPL-2.0-only
// Unchanged Cypress bodies: Copyright (C) 2014-2015 Cypress Semiconductor, Inc.
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint16_t __le16;
typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define CYAPA_TSG_MAX_CMD_SIZE 256
#define PIP_OUTPUT_REPORT_ADDR 4
#define PIP_APP_CMD_REPORT_ID 0x2f
#define PIP_CMD_CALIBRATE 0x28
#define GEN5_CMD_SET_PARAMETER 6
#define GEN5_CMD_GET_PARAMETER 5
#define GEN5_PARAMETER_ACT_INTERVL_ID 0x4d
#define GEN5_PARAMETER_ACT_INTERVL_SIZE 1
#define GEN5_PARAMETER_ACT_LFT_INTERVL_ID 0x4f
#define GEN5_PARAMETER_ACT_LFT_INTERVL_SIZE 2
#define GEN5_PARAMETER_LP_INTRVL_ID 0x4c
#define GEN5_PARAMETER_LP_INTRVL_SIZE 2
#define GEN6_SET_POWER_MODE_INTERVAL 0x47
#define GEN6_GET_POWER_MODE_INTERVAL 0x48
#define VALID_CMD_RESP_HEADER(r,c) ((r)[2] == 0x1f && (r)[3] == 0 && ((r)[4] & 0x7f) == (c))
#define PIP_CMD_COMPLETE_SUCCESS(r) ((r)[5] == 0)
#define cyapa_sort_tsg_pip_app_resp_data NULL
struct cyapa { int unused; };
struct gen6_interval_setting { u16 active_interval, lp1_interval, lp2_interval; };
static const char *kind;
static unsigned value;
static void put_unaligned_le16(u16 value, void *output) {
    u8 *p = output; p[0] = value; p[1] = value >> 8;
}
static void put_unaligned_le32(u32 value, void *output) {
    u8 *p = output; for (unsigned i = 0; i < 4; ++i) p[i] = value >> (i * 8);
}
static u16 get_unaligned_le16(const void *input) {
    const u8 *p = input; return p[0] | (u16)p[1] << 8;
}
static void cyapa_empty_pip_output_data(struct cyapa *c, void *a, void *b, void *d) {
    (void)c; (void)a; (void)b; (void)d;
}
static int cyapa_i2c_pip_cmd_irq_sync(struct cyapa *c, const u8 *cmd, int length,
        u8 *response, int *response_length, int timeout, void *sort, bool irq) {
    (void)c; (void)sort;
    printf("%s %u ", kind, value);
    for (int i = 0; i < length; ++i) printf("%02x", cmd[i]);
    printf(" %d %u\n", timeout, irq);
    memset(response, 0, *response_length);
    response[2] = 0x1f; response[4] = cmd[6] | 0x80;
    if (cmd[6] == 6) { response[5] = cmd[7]; response[6] = cmd[8]; }
    if (cmd[6] == 5) {
        response[5] = cmd[7]; response[6] = 2;
        put_unaligned_le16(value, response + 7);
    }
    if (cmd[6] == 0x47) memcpy(response + 5, cmd + 7, 6);
    if (cmd[6] == 0x48) {
        put_unaligned_le16(8, response + 5);
        put_unaligned_le16(30, response + 7);
        put_unaligned_le16(value, response + 9);
    }
    return 0;
}
'''
SUFFIX = r'''
int main(void) {
    struct cyapa device = {0};
    for (value = 20; value <= 1000; ++value) {
        kind = "g5set";
        assert(cyapa_gen5_set_interval_time(&device, 0x4c, value) == 0);
        kind = "g5get";
        u16 actual = 0;
        assert(cyapa_gen5_get_interval_time(&device, 0x4c, &actual) == 0);
        assert(actual == value);
        if (value == 30 || value == 50) continue;
        struct gen6_interval_setting intervals = {8, 30, value};
        kind = "g6set";
        assert(cyapa_gen6_set_interval_setting(&device, &intervals) == 0);
        assert(intervals.active_interval == 8 && intervals.lp1_interval == 30 && intervals.lp2_interval == value);
        kind = "g6get";
        assert(cyapa_gen6_get_interval_setting(&device, &intervals) == 0);
        assert(intervals.active_interval == 8 && intervals.lp1_interval == 30 && intervals.lp2_interval == value);
    }
    kind = "calibrate";
    for (value = 0; value <= 2; value += 2)
        assert(cyapa_pip_calibrate_pwcs(&device, value) == 0);
    kind = "scan"; value = 3; assert(cyapa_pip_suspend_scanning(&device) == 0);
    kind = "scan"; value = 4; assert(cyapa_pip_resume_scanning(&device) == 0);
    return 0;
}
'''


def main():
    root, output = map(Path, sys.argv[1:])
    output.mkdir(parents=True, exist_ok=False)
    sources = {}
    for name, expected in HASHES.items():
        raw = (root / "drivers/input/mouse" / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected, name
        sources[name] = raw.decode()
    bodies = [declaration(sources["cyapa_gen5.c"], "struct " + name + " {") + " __packed;"
              for name in ["pip_app_cmd_head", "gen5_app_set_parameter_data", "gen5_app_get_parameter_data"]]
    functions = {}
    for name, names in FUNCTIONS.items():
        for function in names:
            match = re.search(r"^(?:static )?int " + function + r"\(", sources[name], re.M)
            assert match, function
            body = declaration(sources[name], match.group())
            bodies.append(body)
            functions[function] = hashlib.sha256(body.encode()).hexdigest()
    generated = output / "oracle.c"
    generated.write_text(PREFIX + "\n".join(bodies) + SUFFIX)
    binary = output / "oracle"
    subprocess.run(["clang", "-std=gnu11", "-O1", "-g", "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer", str(generated), "-o", str(binary)], check=True, timeout=60)
    result = subprocess.run([str(binary.resolve())], capture_output=True, text=True, check=True, timeout=60)
    (output / "records.txt").write_text(result.stdout)
    (output / "manifest.json").write_text(json.dumps({
        "pin": PIN, "sources": HASHES, "unchanged_functions": functions,
        "records": len(result.stdout.splitlines()),
        "oracle_limit": ["Transport/IRQ/drain and positive device replies are modeled.",
                         "Only command functions execute, not whole Linux power policy or actual calibration.",
                         "Native readback/status/failure checks deliberately exceed unchecked Linux reply extents."],
    }, indent=2) + "\n")
    print(f"{len(result.stdout.splitlines())} unchanged-source command records")


if __name__ == "__main__":
    main()
