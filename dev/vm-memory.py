#!/usr/bin/env python3
"""Assemble our original ARM memory fixture, AOT compile, then check RAM in QEMU."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from evidence import ROOT, write_evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", choices=("scalar", "pair"), default="scalar")
    args = parser.parse_args()
    subprocess.run([str(ROOT / "dev/cargo"), "build", "--locked", "-p", "stela-cli"], check=True)
    cli = ROOT / "target/debug/stela"
    assembly = ROOT / "tests/fixtures" / ("pair.S" if args.fixture == "pair" else "memory.S")
    with tempfile.TemporaryDirectory(prefix="stela-vm-memory-") as temporary:
        directory = Path(temporary)
        object_path = directory / "memory.o"
        subprocess.run(["clang", "--target=arm64-apple-macos", "-c", str(assembly), "-o", str(object_path)], check=True)
        rows = json.loads(subprocess.check_output([str(cli), "binary-text", str(object_path)]))
        if len(rows) != 1 or len(rows[0]["slice"]["sections"]) != 1:
            raise AssertionError("Unexpected original fixture layout")
        section = rows[0]["slice"]["sections"][0]
        if section["name"] != "__text":
            raise AssertionError("Expected fixture text section")
        source = bytes.fromhex(section["data_hex"])
        input_path = directory / "memory.arm64"
        input_path.write_bytes(source)
        prepared = json.loads(subprocess.check_output([str(cli), "prepare-leaf", str(input_path)]))
    native_path = Path(prepared["directory"]) / "native.bin"
    checks = ["0x8000=40", "0x8008=42", "0x8010=42", "0x8ff0=42", "0x60f8=0x9000"]
    if args.fixture == "pair":
        checks = ["0x8000=40", "0x8008=2", "0x8010=0x0000000200000028", "0x8018=0x7fffffff80000000",
                  "0x8020=0xffffffff80000000", "0x8028=0x7fffffff", "0x8ff0=40", "0x8ff8=2", "0x60f8=0x9000"]
    arguments = [sys.executable, str(ROOT / "dev/vm.py"), "smoke", "--native", str(native_path)]
    for check in checks:
        arguments.extend(["--expect-memory", check])
    observed = json.loads(subprocess.check_output(arguments))
    report = {"kind": "assembled_arm_memory_fixture_in_x86_vm", "fixture": args.fixture, "passed": True,
              "assembly_sha256": hashlib.sha256(assembly.read_bytes()).hexdigest(),
              "arm_source_sha256": hashlib.sha256(source).hexdigest(), "aot_cache_key": prepared["key"],
              "translation_manifest": prepared["manifest"], "native_artifact": str(native_path), "vm": observed,
              "limits": "Original Stela fixture and identity-mapped RAM only. QEMU debug evidence, not macOS boot or a native performance benchmark."}
    destination = ROOT / ".stela/vm" / ("pair-smoke-report.json" if args.fixture == "pair" else "memory-smoke-report.json")
    write_evidence(destination, report)
    print(json.dumps({"report": str(destination), "passed": True, "guest_x0": observed["expected_result"],
                      "checked_memory_locations": len(observed["memory_checks"]), "native_artifact": str(native_path)}, indent=2))


if __name__ == "__main__":
    main()
