#!/usr/bin/env python3
"""Compare tiny real universal command entry points across three execution paths.

Only /usr/bin/true and /usr/bin/false are selected. Strict instruction-pattern
checks precede execution of their extracted x86 entry points. This harness is
not a general application loader or permission to call arbitrary app functions.
"""
import ctypes
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from differential import ROOT, executable, native, reference, states
from evidence import write_evidence


def entry_code(row):
    entry = row["entry_guest_address"]
    for section in row["sections"]:
        data = bytes.fromhex(section["data_hex"])
        offset = entry - section["guest_address"] if entry is not None else -1
        if 0 <= offset < len(data):
            return entry, data[offset:]
    raise RuntimeError("Entry point not found in a text section")


def check_native_pattern(code, expected):
    instructions = [(mnemonic, operands) for _, _, mnemonic, operands in Cs(CS_ARCH_X86, CS_MODE_64).disasm_lite(code,0)]
    move = ("xor","eax, eax") if expected == 0 else ("mov","eax, 1")
    allowed = [("push","rbp"),("mov","rbp, rsp"),move,("pop","rbp"),("ret","")]
    if instructions != allowed:
        raise RuntimeError(f"Unreviewed native entry pattern: {instructions}")


def main():
    subprocess.run([str(ROOT / "dev/cargo"), "build", "--locked", "-p", "stela-cli"], check=True)
    cli = ROOT / "target/debug/stela"
    reports = []
    with tempfile.TemporaryDirectory(prefix="stela-paired-") as temporary:
        for index, path in enumerate(map(Path,["/usr/bin/true","/usr/bin/false"])):
            entries = json.loads(subprocess.check_output([str(cli),"binary-text",str(path)]))
            arm = next(e["slice"] for e in entries if e["slice"]["artifact"]["architecture"] in ("arm64","arm64e"))
            intel = next(e["slice"] for e in entries if e["slice"]["artifact"]["architecture"] == "x86_64")
            base, source = entry_code(arm)
            _, original = entry_code(intel)
            expected_exit = subprocess.run([str(path)],check=False).returncode
            if expected_exit != index:
                raise RuntimeError("Unexpected installed command behavior")
            check_native_pattern(original,expected_exit)
            with executable(original) as address:
                original_result = ctypes.CFUNCTYPE(ctypes.c_int)(address)()
            if original_result != expected_exit:
                raise AssertionError("Original x86 entry disagrees with command exit status")
            directory = Path(temporary)
            input_path = directory / f"{index}.arm64"
            input_path.write_bytes(source)
            prepared = json.loads(subprocess.check_output([str(cli),"prepare-leaf",str(input_path),"--guest-base",hex(base)]))
            output = Path(prepared["directory"])
            emitted = (output / "native.bin").read_bytes()
            for initial in states():
                # Reference runner uses a low mapping but these leafs contain
                # no PC-relative instructions. The compiler map keeps real PCs.
                reference_result = reference(source,initial)
                native_result = native(emitted,initial)
                if reference_result != native_result or native_result["x"][0] != original_result:
                    raise AssertionError(f"Three-way comparison failed for {path}")
            reports.append({"path":str(path),"file_sha256":hashlib.sha256(path.read_bytes()).hexdigest(),
                            "arm_slice_sha256":arm["artifact"]["sha256"],"x86_slice_sha256":intel["artifact"]["sha256"],
                            "arm_entry":base,"arm_instruction_count":len(source)//4,
                            "translated_native_sha256":hashlib.sha256(emitted).hexdigest(),
                            "compiler_source_sha256":prepared["manifest"]["identity"]["compiler_source_sha256"],
                            "aot_cache_key":prepared["key"],"aot_cache_hit":prepared["cache_hit"],
                            "native_artifact":str(output / "native.bin"),
                            "original_x86_result":original_result,"process_exit_status":expected_exit,
                            "state_comparisons":len(states()),"passed":True})
    report={"kind":"paired_real_command_leafs","passed":True,"files":reports,
            "limits":"Only the tiny entry functions of true/false are translated. No complete Mach-O app loading or macOS ABI adaptation is demonstrated."}
    destination=ROOT / ".stela/paired-leaves-report.json"
    write_evidence(destination,report)
    print(json.dumps(report,indent=2))


if __name__ == "__main__":
    main()
