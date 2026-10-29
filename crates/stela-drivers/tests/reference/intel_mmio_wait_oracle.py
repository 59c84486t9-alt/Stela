#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Original Xe source copyright 2022 Intel Corporation.
"""Compare complete original Xe polling with the actual native C adapter.

--flags contains a JSON array of actual driver C compiler flags, including the
canonical generated asm/include directories. No configuration is synthesized.
The fixture models register/clock/delay boundaries, not physical timing.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

PIN = "cc9de5d4b5ab6459f5774946aa3195ad51236fa8"
DONOR = "drivers/gpu/drm/xe/xe_mmio.c"
SHA256 = "8ebf27aafa9ad03a06d68179bf566d06e10a8d63dece557e02cea3df0884ce71"
GROUP_SHA256 = "a8c0cf96a83524185d7d198dd5f6a6919ae692ffc2aa47efa63c98ff13e9ba2e"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux", type=Path, required=True)
    parser.add_argument("--flags", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[4]
    intel = root / "crates/stela-driver-gpu/src/intel"
    donor = (args.linux / DONOR).read_bytes()
    if hashlib.sha256(donor).hexdigest() != SHA256:
        raise SystemExit("pinned original Xe MMIO source integrity mismatch")
    flags = json.loads(args.flags.read_text())
    if not isinstance(flags, list) or not all(isinstance(v, str) for v in flags):
        raise SystemExit("compiler flags must be a JSON string array")
    if any(v in {"-c", "-o", "-E", "-S"} for v in flags):
        raise SystemExit("compiler flags must not select an input/output mode")
    text = donor.decode()
    group = text[text.index("#define __XE_MMIO_WAIT_MAX_BACKOFF_100MS"):text.index("/**\n * xe_mmio_wait32()")]
    if hashlib.sha256(group.encode()).hexdigest() != GROUP_SHA256:
        raise SystemExit("complete original polling group integrity mismatch")
    args.out.mkdir(parents=True, exist_ok=False)
    oracle = args.out / "original.c"
    oracle.write_text(text[:text.index("#include")] + '''#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/minmax.h>
#include <linux/timekeeping.h>
#include "xe_mmio.h"
#include "regs/xe_reg_defs.h"
u32 original_read32(struct xe_mmio *, struct xe_reg);
void original_udelay(unsigned long);
void original_usleep_range(unsigned long, unsigned long);
#undef udelay
#undef usleep_range
#define xe_mmio_read32 original_read32
#define udelay original_udelay
#define usleep_range original_usleep_range
''' + group + '''int original_wait32(struct xe_mmio *mmio, struct xe_reg reg, u32 mask, u32 value,
                    u32 timeout, u32 *out, bool atomic)
{ return __xe_mmio_wait32(mmio, reg, mask, value, timeout, out, atomic, true); }
''')
    paths = [intel / "mmio.c", oracle, intel / "tests/mmio_wait_oracle.c"]
    base = [args.cc, *flags, "-isystem", str(intel), "-isystem", str(args.linux / "drivers/gpu/drm/xe")]
    result = dict(scope="Complete unchanged original private poll core vs actual native wait: ordered register/clock/delay transcript comparisons; modeled boundaries only",
                  donor=dict(pin=PIN, path=DONOR, sha256=SHA256, group_sha256=GROUP_SHA256), builds=[])
    for path in paths:
        # Linux does not apply Stela's owned-C conversion diagnostics to its
        # original function bodies. Keep those diagnostics on both owned units.
        command = base + (["-Wno-conversion", "-Wno-sign-conversion"] if path == oracle else ["-Wconversion", "-Wsign-conversion"])
        command += ["-c", str(path), "-o", str(args.out / (path.stem + ".o"))]
        built = subprocess.run(command, cwd=root / "crates/stela-drivers", capture_output=True, text=True)
        result["builds"].append(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                                      command=command, exit=built.returncode, stderr=built.stderr))
        if built.returncode:
            break
    success = False
    if len(result["builds"]) == 3 and all(row["exit"] == 0 for row in result["builds"]):
        command = [args.cc, "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                   *[str(args.out / (path.stem + ".o")) for path in paths], "-o", str(args.out / "test")]
        linked = subprocess.run(command, capture_output=True, text=True)
        result["link"] = dict(command=command, exit=linked.returncode, stderr=linked.stderr)
        if linked.returncode == 0:
            result["binary_sha256"] = hashlib.sha256((args.out / "test").read_bytes()).hexdigest()
            ran = subprocess.run([str(args.out / "test")], capture_output=True, text=True, timeout=30)
            result["run"] = dict(exit=ran.returncode, stdout=ran.stdout, stderr=ran.stderr)
            success = ran.returncode == 0
    (args.out / "measurement.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(dict(output=str(args.out), passed=success, run=result.get("run"))))
    raise SystemExit(0 if success else 1)


if __name__ == "__main__":
    main()
