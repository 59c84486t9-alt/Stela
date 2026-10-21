#!/usr/bin/env python3
"""Run bounded M1 AMX correctness probes on an explicitly authorized SSH host.

Only ordinary clang builds and EL0 instructions are used. Sources and receipts
stay local; generated remote scratch is removed after its hashes are retained.
"""

import argparse
import datetime
import hashlib
import io
import json
from pathlib import Path
import re
import shlex
import subprocess
import tarfile


REFERENCE = "483714bb051da088d08a66724b22dd08a5db3c99"
SOURCES = ["ldst.c", "extr.c", "fma.c", "fms.c", "genlut.c", "mac16.c",
           "matfp.c", "matint.c", "vecfp.c", "vecint.c"]
EXTRA_PINS = {
    "test.c": "cdb919d1e5af2bbae190334a45b027bacd95988fd0a9c9f0c9e6b70128212168",
    "aarch64.h": "b4014d2eef73df15112783ce84cd326a09f68e762fe44241e2e692246713f38b",
}
PREFIX = "/tmp/stela-cpu-reference-20261021"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote", required=True, help="explicitly authorized user@host")
    parser.add_argument("--corsix", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="new ignored evidence directory")
    parser.add_argument("--chains", type=int, default=128)
    parser.add_argument("--steps", type=int, default=256)
    args = parser.parse_args()
    if not 1 <= args.chains <= 4096 or not 128 <= args.steps <= 4096:
        parser.error("chains must be 1..4096; steps 128..4096 cover all FP environments")
    here = Path(__file__).resolve().parent
    pins = dict(re.findall(r'"([\w.]+)",\s*"([0-9a-f]{64})"',
                           here.with_suffix(".rs").read_text()))
    pins.update(EXTRA_PINS)
    if set(pins) != set(SOURCES + ["LICENSE", "emulate.h", "test.c", "aarch64.h"]):
        raise RuntimeError("unexpected reference source inventory")
    files = {name: (args.corsix / name).read_bytes() for name in pins}
    for name, expected in pins.items():
        if sha(files[name]) != expected:
            raise RuntimeError(f"reference source {name} differs from {REFERENCE}")
    files["native.c"] = (here / "native.c").read_bytes()
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "native.c").write_bytes(files["native.c"])
    (args.output / "native.py").write_bytes(Path(__file__).read_bytes())
    receipt = {
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "remote": args.remote, "reference_commit": REFERENCE,
        "source_sha256": {name: sha(data) for name, data in files.items()},
        "runner_sha256": sha(Path(__file__).read_bytes()),
        "scope": "M1 behavior only; identity/build recorded separately; no timing claim",
        "environment": "64 FPCR rounding/DN/FZ/FZ16/AHP combinations x two FPSR seeds",
        "limits": ["bounded random operands", "safe aligned transfer domain",
                   "no privileged controls, faults or memory ordering qualification",
                   "no other chip/build qualification", "C reference; not direct Rust execution"],
        "runs": [],
    }

    def retain():
        (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")

    def remote(argv, *, data=None, timeout=30):
        return subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                               args.remote, shlex.join(argv)], input=data,
                              capture_output=True, timeout=timeout)

    def record(name, result):
        (args.output / f"{name}.stdout").write_bytes(result.stdout)
        (args.output / f"{name}.stderr").write_bytes(result.stderr)
        item = {"name": name, "exit": result.returncode,
                "stdout_sha256": sha(result.stdout), "stderr_sha256": sha(result.stderr)}
        receipt["runs"].append(item)
        retain()
        return item

    identity = remote(["sh", "-c", "uname -m; sw_vers; "
                       "sysctl hw.model machdep.cpu.brand_string hw.ncpu hw.memsize; "
                       "clang --version; sysctl hw.optional.arm.FEAT_FP16 "
                       "hw.optional.arm.FEAT_BF16 hw.optional.arm.FEAT_DotProd "
                       "hw.optional.arm.FEAT_I8MM hw.optional.arm.FEAT_LSE "
                       "hw.optional.arm.FEAT_PAuth"])
    record("identity", identity)
    if identity.returncode or b"arm64\n" not in identity.stdout or b"Apple M1" not in identity.stdout:
        raise RuntimeError("requires the explicitly authorized arm64 M1 reference")
    allocated = remote(["python3", "-c", "import pathlib,tempfile; "
                        f"pathlib.Path({PREFIX!r}).mkdir(exist_ok=True); "
                        f"print(tempfile.mkdtemp(prefix='amx-',dir={PREFIX!r}))"])
    if allocated.returncode:
        raise RuntimeError(allocated.stderr.decode())
    scratch = allocated.stdout.decode().strip()
    if not scratch.startswith(PREFIX + "/amx-") or "/" in scratch[len(PREFIX) + 1:]:
        raise RuntimeError("invalid remote scratch path")
    receipt["scratch"] = scratch
    retain()
    try:
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            for name, data in files.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                tar.addfile(entry, io.BytesIO(data))
        copied = remote(["tar", "-xf", "-", "-C", scratch], data=archive.getvalue())
        if copied.returncode:
            raise RuntimeError(copied.stderr.decode())
        hashes = remote(["shasum", "-a", "256"] + [scratch + "/" + n for n in files])
        record("remote-sources", hashes)
        actual = {Path(line.split(maxsplit=1)[1]).name: line.split()[0]
                  for line in hashes.stdout.decode().splitlines()}
        if hashes.returncode or actual != receipt["source_sha256"]:
            raise RuntimeError("remote source hash mismatch")
        compiler = ["clang", "-O2", "-march=armv8.2-a+fp16", "-I", scratch,
                    scratch + "/native.c"] + [scratch + "/" + n for n in SOURCES]
        compiler += ["-o", scratch + "/native-amx"]
        receipt["compiler_argv"] = compiler
        syntax = remote(["clang", "-O2", "-march=armv8.2-a+fp16", "-I", scratch,
                         "-Wall", "-Wextra", "-Werror", "-fsyntax-only", scratch + "/native.c"],
                        timeout=60)
        record("strict-wrapper", syntax)
        if syntax.returncode:
            raise RuntimeError("strict native wrapper check failed")
        built = remote(compiler, timeout=90)  # One compile process; never parallel jobs.
        record("compile", built)
        if built.returncode:
            raise RuntimeError("native compile failed")
        binary_hash = remote(["shasum", "-a", "256", scratch + "/native-amx"])
        record("binary-hash", binary_hash)
        if binary_hash.returncode or not re.match(rb"^[0-9a-f]{64} ", binary_hash.stdout):
            raise RuntimeError("native binary hash unavailable")
        disassembly = remote(["otool", "-tvV", scratch + "/native-amx"])
        record("disassembly", disassembly)
        words = re.findall(rb"\.long\s+0x(00201[0-9a-f]{3})", disassembly.stdout)
        operations = {(int(word, 16) >> 5) & 31 for word in words}
        if disassembly.returncode or operations != set(range(23)):
            raise RuntimeError("actual binary does not expose every declared AMX operation")
        if b"_corsix_unbounded_main:" in disassembly.stdout:
            raise RuntimeError("unbounded upstream test entry unexpectedly retained")
        receipt["inspected_native_operations"] = sorted(operations)
        # Remote supervision kills forked children on timeout or hangup.
        supervisor = """import os,signal,subprocess,sys
p=subprocess.Popen(sys.argv[1:],start_new_session=True)
def interrupted(signum, frame): raise InterruptedError(signum)
signal.signal(signal.SIGHUP, interrupted)
signal.signal(signal.SIGTERM, interrupted)
try: result=p.wait(timeout=180)
except BaseException:
 try: os.killpg(p.pid,signal.SIGKILL)
 except ProcessLookupError: pass
 p.wait(); raise
sys.exit(result)
"""
        tests = [("invalid-bounds", ["0", "1"], 2, 0, None),
                 ("injected-mismatch", ["1", "1", "--inject-mismatch"], 1, 22, "mismatch"),
                 ("injected-status", ["1", "1", "--inject-status-mismatch"], 1, 22, "mismatch"),
                 ("injected-signal", ["1", "1", "--inject-signal"], 1, 22, "signal"),
                 ("native-random", [str(args.chains), str(args.steps)], 0, 22, "pass"),
                 ("native-fp-edges", ["1", "1", "--fp-edges"], 0, 6, "pass")]
        for name, operands, expected, count, wanted in tests:
            result = remote(["python3", "-c", supervisor, scratch + "/native-amx"] + operands,
                            timeout=190)
            record(name, result)
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            if result.returncode != expected:
                raise RuntimeError(f"{name} exited {result.returncode}, expected {expected}")
            if len(rows) != count or any(row["status"] != wanted for row in rows):
                raise RuntimeError(f"{name} did not produce all{count} {wanted} records")
            print(f"{name}: exit {result.returncode}, {len(rows)} records", flush=True)
        receipt["qualified_random_steps"] = 22 * args.chains * args.steps
        receipt["qualified_fp_edge_steps"] = 6 * 24576
    finally:
        cleanup = remote(["python3", "-c", "import shutil,sys; shutil.rmtree(sys.argv[1])", scratch])
        record("cleanup", cleanup)
        if cleanup.returncode:
            raise RuntimeError("remote scratch cleanup failed; see retained receipt")
    retain()


if __name__ == "__main__":
    main()
