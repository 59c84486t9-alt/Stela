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
import re
import subprocess
import sys

import capstone
from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_ARM, CS_MODE_64
from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_MEM

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUTS = [
    "/usr/bin/true", "/usr/bin/false", "/usr/bin/uname", "/usr/bin/sed", "/usr/bin/awk",
    "/System/Applications/Calculator.app/Contents/MacOS/Calculator",
    "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit",
    "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
]

REGISTER = re.compile(r"\b(?:[xw][0-9]+|[vqdshbzp][0-9]+|sp|wsp|xzr|wzr|fp|lr|nzcv)\b")
IMMEDIATE = re.compile(r"#[-+]?(?:0x[0-9a-f]+|\d+(?:\.\d*)?(?:e[-+]?\d+)?)")
PATTERN_LENGTHS = (2, 3, 4)
PATTERN_LIMITS = (
    "Static linear-disassembly candidates, not execution frequencies or proven basic blocks. "
    "Windows split at section ends, decode gaps, known symbol/entry/direct-branch targets "
    "and control transfers. Missing indirect entries, function-start metadata and embedded "
    "data can still affect results. Register renaming preserves explicit W/X and V/Z aliases; "
    "immediate values are generalized, so equal templates do not establish equivalent semantics. "
    "Register-access edges reflect Capstone metadata, which can omit implicit effects; they "
    "are not an optimizer legality or liveness analysis. No guest code executes."
)


def register_key(name):
    """Architectural overlap for candidate grouping, not a semantic register model."""
    name = {"fp": "x29", "lr": "x30", "wsp": "sp"}.get(name, name)
    if re.fullmatch(r"[xw](?:[0-9]|[12][0-9]|30)", name):
        return "gpr", int(name[1:])
    if re.fullmatch(r"[vqdshbz](?:[0-9]|[12][0-9]|3[01])", name):
        return "vector", int(name[1:])
    if re.fullmatch(r"p(?:[0-9]|1[0-5])", name):
        return "predicate", int(name[1:])
    return "special", name


def pattern_template(instructions):
    renamed = {"gpr": {}, "vector": {}, "predicate": {}}

    def rename(match):
        name = match.group()
        family, key = register_key(name)
        if family == "special":
            return name
        identifiers = renamed[family]
        index = identifiers.setdefault(key, len(identifiers))
        prefix = "x" if name in ("fp", "lr") else name[0]
        return f"{prefix}{{{family[0]}{index}}}"

    template = []
    for instruction in instructions:
        operands = IMMEDIATE.sub("#imm", instruction.op_str)
        operands = REGISTER.sub(rename, operands)
        template.append(f"{instruction.mnemonic} {operands}".rstrip())
    return " ; ".join(template), {family: len(keys) for family, keys in renamed.items()}


def is_control_transfer(instruction):
    # Include authenticated transfers/traps even when decoder group metadata is absent.
    mnemonic = instruction.mnemonic
    return (any(group in instruction.groups for group in (
                capstone.CS_GRP_JUMP, capstone.CS_GRP_CALL, capstone.CS_GRP_RET,
                capstone.CS_GRP_INT, capstone.CS_GRP_IRET))
            or mnemonic in {"b", "bl", "br", "blr", "cbz", "cbnz", "tbz", "tbnz",
                            "braa", "braaz", "brab", "brabz", "blraa", "blraaz",
                            "blrab", "blrabz", "ret", "retaa", "retab", "eret",
                            "eretaa", "eretab", "svc", "hvc", "smc", "brk", "hlt",
                            "udf", "dcps1", "dcps2", "dcps3", "drps"}
            or mnemonic.startswith(("b.", "bc.")))


def decode_section(data, base):
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail = True
    decoder.skipdata = True
    return list(decoder.disasm(data, base))


def direct_targets(decoded):
    targets = set()
    for instruction in decoded:
        if instruction.id and is_control_transfer(instruction):
            operands = [operand.imm for operand in instruction.operands if operand.type == ARM64_OP_IMM]
            # TBZ/TBNZ also carry a bit-number immediate; the last operand is the target.
            if operands and instruction.mnemonic not in {
                    "svc", "hvc", "smc", "brk", "hlt", "udf", "dcps1", "dcps2", "dcps3"}:
                targets.add(operands[-1])
    return targets


def section_runs(data, base, known_entries, decoded=None):
    """Decode one section; keep candidate windows inside all known flow boundaries."""
    if decoded is None:
        decoded = decode_section(data, base)
    entries = set(known_entries) | direct_targets(decoded)
    runs, run = [], []
    decoded_bytes = 0
    for instruction in decoded:
        if (not instruction.id or instruction.size != 4 or instruction.address % 4
                or instruction.address in entries
                or (run and run[-1].address + run[-1].size != instruction.address)):
            if run:
                runs.append(run)
                run = []
        if not instruction.id or instruction.size != 4 or instruction.address % 4:
            continue
        decoded_bytes += instruction.size
        run.append(instruction)
        if is_control_transfer(instruction):
            runs.append(run)
            run = []
    if run:
        runs.append(run)
    return runs, len(data) - decoded_bytes


class PatternProfile:
    def __init__(self):
        self.counts = {length: Counter() for length in PATTERN_LENGTHS}
        self.examples = {}
        self.register_counts = {}
        self.section_count = self.run_count = self.instructions = self.invalid_bytes = 0
        self.memory_instructions = self.vector_instructions = 0

    def add_slice(self, row):
        entries = set(row["defined_text_symbols"].values())
        if row["entry_guest_address"] is not None:
            entries.add(row["entry_guest_address"])
        # Cross-section direct targets also split windows in their destination section.
        for section in row["sections"]:
            entries.update(direct_targets(decode_section(bytes.fromhex(section["data_hex"]),
                                                        section["guest_address"])))
        for section in row["sections"]:
            self.section_count += 1
            runs, invalid = section_runs(bytes.fromhex(section["data_hex"]),
                                         section["guest_address"], entries)
            self.invalid_bytes += invalid
            for run in runs:
                self.run_count += 1
                self.instructions += len(run)
                for instruction in run:
                    self.memory_instructions += any(op.type == ARM64_OP_MEM for op in instruction.operands)
                    self.vector_instructions += any(
                        register_key(match.group())[0] in ("vector", "predicate")
                        for match in REGISTER.finditer(instruction.op_str))
                for length in PATTERN_LENGTHS:
                    for offset in range(len(run) - length + 1):
                        window = run[offset:offset + length]
                        template, registers = pattern_template(window)
                        self.counts[length][template] += 1
                        self.register_counts[template] = registers
                        if template not in self.examples:
                            writes, dependencies = {}, []
                            for index, instruction in enumerate(window):
                                reads, updated = instruction.regs_access()
                                for register in reads:
                                    key = register_key(instruction.reg_name(register))
                                    if key in writes:
                                        dependencies.append({"producer": writes[key], "consumer": index,
                                                             "register_family": key[0]})
                                for register in updated:
                                    writes[register_key(instruction.reg_name(register))] = index
                            self.examples[template] = {
                                "slice_sha256": row["artifact"]["sha256"],
                                "architecture": row["artifact"]["architecture"],
                                "section": section["name"], "guest_pc": window[0].address,
                                "source_hex": b"".join(i.bytes for i in window).hex(),
                                "instructions": [f"{i.mnemonic} {i.op_str}".rstrip() for i in window],
                                "capstone_read_after_write_edges": dependencies,
                            }

    def report(self, limit):
        return {"kind": "arm64_static_instruction_patterns", "candidate_instructions": self.instructions,
                "sections": self.section_count, "boundary_delimited_runs": self.run_count,
                "invalid_or_undecoded_bytes": self.invalid_bytes,
                "memory_operand_instructions": self.memory_instructions,
                "vector_or_predicate_operand_instructions": self.vector_instructions,
                "windows": {str(length): {
                    "occurrences": sum(counts.values()), "distinct_templates": len(counts),
                    "top": [{"template": template, "occurrences": count,
                             "distinct_explicit_registers": self.register_counts[template],
                             "example": self.examples[template]}
                            for template, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]]}
                    for length, counts in self.counts.items()}, "limits": PATTERN_LIMITS}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / ".stela/corpus-report.json")
    parser.add_argument("--patterns", action="store_true", help="Collect ARM operand/dependency pattern candidates")
    parser.add_argument("--pattern-limit", type=int, default=50, help="Top templates retained per window length")
    args = parser.parse_args()
    if not 1 <= args.pattern_limit <= 1000:
        parser.error("--pattern-limit must be between 1 and 1000")
    if args.output.exists():
        raise SystemExit("Report exists; use a new --output path to preserve evidence.")
    subprocess.run([str(ROOT / "dev/cargo"), "build", "--locked", "-p", "stela-cli"], check=True)
    reports = []
    compiler_source = None
    cli = ROOT / "target/debug/stela"
    cli_sha256 = hashlib.sha256(cli.read_bytes()).hexdigest()
    patterns = PatternProfile() if args.patterns else None
    combined = {"arm64": Counter(), "x86_64": Counter()}
    for path in args.files or map(Path, DEFAULT_INPUTS):
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        process = subprocess.run([str(cli), "binary-text", str(path)], capture_output=True, text=True)
        if before != hashlib.sha256(path.read_bytes()).hexdigest():
            raise RuntimeError(f"Input changed during corpus scan: {path}")
        if process.returncode:
            reports.append({"path":str(path),"error":process.stderr.strip()})
            continue
        slices = json.loads(process.stdout)
        rows = []
        symbol_sets = {}
        for entry in slices:
            if compiler_source is None:
                compiler_source = entry["compiler_source_sha256"]
            if compiler_source != entry["compiler_source_sha256"]:
                raise RuntimeError("Compiler changed during corpus scan")
            row = entry["slice"]
            architecture = row["artifact"]["architecture"]
            if architecture not in ("arm64", "arm64e", "x86_64"):
                continue
            family = "arm64" if architecture.startswith("arm") else "x86_64"
            if patterns is not None and family == "arm64":
                patterns.add_slice(row)
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
        reports.append({"path":str(path),"file_sha256":before,
                        "paired_architectures":set(symbol_sets)=={"arm64","x86_64"},
                        "common_defined_text_symbols":len(common),"common_symbol_sample":common[:20],"slices":rows})
    if cli_sha256 != hashlib.sha256(cli.read_bytes()).hexdigest():
        raise RuntimeError("CLI changed during corpus scan")
    result = {"schema_version":2,"kind":"universal_macho_instruction_corpus", "files":reports,
              "compiler_source_sha256":compiler_source,
              "cli_sha256":cli_sha256, "harness_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "python_version":sys.version, "capstone_version":capstone.__version__,
              "capstone_core_version":capstone.cs_version(),
              "histograms":{k:dict(v.most_common()) for k,v in combined.items()},
              "limits":"Linear text disassembly and leaf-encoding recognition only; no app has been translated or behaviorally verified by this report."}
    if patterns is not None:
        result["arm64_patterns"] = patterns.report(args.pattern_limit)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open("x") as stream:
        stream.write(json.dumps(result,indent=2)+"\n")
    print(json.dumps({"report":str(args.output),"inputs":len(reports),
                      "paired_binaries":sum(r.get("paired_architectures",False) for r in reports),
                      "errors":sum("error" in r for r in reports),
                      "top_arm64":combined["arm64"].most_common(16)},indent=2))
    if any("error" in r for r in reports):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
