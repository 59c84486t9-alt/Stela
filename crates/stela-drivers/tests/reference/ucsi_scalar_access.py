#!/usr/bin/env python3
"""Check the actual production UCSI scalar access code emitted for native x64.

Uses x86_64-unknown-uefi and optimized wrapper functions around the production
access helpers. Requires a single native-width CCI load and CONTROL store.
Usage: python3 ucsi_scalar_access.py OUTPUT_DIRECTORY
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

out = Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=True)
source = Path(__file__).resolve().parents[2] / "src/usb/typec/ucsi/acpi/access.rs"
fixture = f'''#![no_std]
#[path = {json.dumps(str(source))}] mod access;
use core::ptr::NonNull;
#[unsafe(no_mangle)] pub unsafe extern "C" fn stela_ucsi_version(base: *mut u8) -> u16 {{ unsafe {{ access::version(NonNull::new_unchecked(base)) }} }}
#[unsafe(no_mangle)] pub unsafe extern "C" fn stela_ucsi_cci(base: *mut u8) -> u32 {{ unsafe {{ access::cci(NonNull::new_unchecked(base)) }} }}
#[unsafe(no_mangle)] pub unsafe extern "C" fn stela_ucsi_control(base: *mut u8, value: u64) {{ unsafe {{ access::control(NonNull::new_unchecked(base), value) }} }}
'''
(out / "scalar.rs").write_text(fixture)
subprocess.run(["rustc", "--crate-type=lib", "--edition=2024", "--target=x86_64-unknown-uefi", "-Copt-level=3", "--emit=asm", str(out / "scalar.rs"), "-o", str(out / "scalar.s")], check=True)
assembly = (out / "scalar.s").read_text()
expected = {"version": r"movzwl\s+\(%rcx\),\s*%eax", "cci": r"movl\s+4\(%rcx\),\s*%eax", "control": r"movq\s+%rdx,\s*8\(%rcx\)"}
instructions = {}
for name, pattern in expected.items():
    match = re.search(r"^stela_ucsi_" + name + r":\n(.*?)(?=^\s*\.def\s|\Z)", assembly, re.M | re.S)
    assert match, name
    body = match.group(1)
    operations = [line.strip() for line in body.splitlines() if re.match(r"^\s+(mov[a-z]*|retq)\s", line) or line.strip() == "retq"]
    assert len(operations) == 2 and re.fullmatch(pattern, operations[0]) and operations[1] == "retq", (name, operations)
    instructions[name] = operations[0]
manifest = {"target": "x86_64-unknown-uefi", "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "assembly_sha256": hashlib.sha256((out / "scalar.s").read_bytes()).hexdigest(), "instructions": instructions}
(out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps(manifest))
