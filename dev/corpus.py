#!/usr/bin/env python3
"""Profile paired ARM/x86 Mach-O slices without executing app code.

Linear disassembly is a prioritization aid; inline data and unreachable code
may occur inside text sections. This is not a translation-completion metric.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess

from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_ARM, CS_MODE_64

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUTS = [
    "/usr/bin/true", "/usr/bin/false", "/usr/bin/uname", "/usr/bin/sed", "/usr/bin/awk",
    "/System/Applications/Calculator.app/Contents/MacOS/Calculator",
    "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit",
    "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / ".stela/corpus-report.json")
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Report exists; use a new --output path to preserve evidence.")
    subprocess.run([str(ROOT / "dev/cargo"), "build", "--locked", "-p", "stela-cli"], check=True)
    reports = []
    combined = {"arm64": Counter(), "x86_64": Counter()}
    for path in args.files or map(Path, DEFAULT_INPUTS):
        process = subprocess.run([str(ROOT / "target/debug/stela"), "binary-text", str(path)], capture_output=True, text=True)
        if process.returncode:
            reports.append({"path":str(path),"error":process.stderr.strip()})
            continue
        slices = json.loads(process.stdout)
        rows = []
        symbol_sets = {}
        for entry in slices:
            row = entry["slice"]
            architecture = row["artifact"]["architecture"]
            if architecture not in ("arm64", "arm64e", "x86_64"):
                continue
            family = "arm64" if architecture.startswith("arm") else "x86_64"
            decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM) if family == "arm64" else Cs(CS_ARCH_X86, CS_MODE_64)
            decoder.skipdata = True
            histogram = Counter()
            invalid_bytes = 0
            text_bytes = 0
            for section in row["sections"]:
                data = bytes.fromhex(section["data_hex"])
                text_bytes += len(data)
                for _, size, mnemonic, _ in decoder.disasm_lite(data, section["guest_address"]):
                    if mnemonic.startswith("."):
                        invalid_bytes += size
                    else:
                        histogram[mnemonic] += 1
            combined[family].update(histogram)
            symbol_sets[family] = set(row["defined_text_symbols"])
            rows.append({"architecture":architecture,"source_sha256":row["artifact"]["sha256"],
                         "text_bytes":text_bytes,"linear_instructions":sum(histogram.values()),
                         "invalid_or_data_bytes":invalid_bytes,"mnemonics":dict(histogram.most_common()),
                         "arm64_text_words":entry["arm64_text_words"],
                         "recognized_leaf_words":entry["recognized_leaf_words"],
                         "defined_text_symbols":len(row["defined_text_symbols"])})
        common = sorted(symbol_sets.get("arm64",set()) & symbol_sets.get("x86_64",set()))
        reports.append({"path":str(path),"file_sha256":hashlib.sha256(path.read_bytes()).hexdigest(),
                        "paired_architectures":set(symbol_sets)=={"arm64","x86_64"},
                        "common_defined_text_symbols":len(common),"common_symbol_sample":common[:20],"slices":rows})
    result = {"schema_version":1,"kind":"universal_macho_instruction_corpus", "files":reports,
              "histograms":{k:dict(v.most_common()) for k,v in combined.items()},
              "limits":"Linear text disassembly and leaf-encoding recognition only; no app has been translated or behaviorally verified by this report."}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({"report":str(args.output),"inputs":len(reports),
                      "paired_binaries":sum(r.get("paired_architectures",False) for r in reports),
                      "errors":sum("error" in r for r in reports),
                      "top_arm64":combined["arm64"].most_common(16)},indent=2))
    if any("error" in r for r in reports):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
