#!/usr/bin/env python3
"""Execute two unchanged, PAC-free windows from the pinned Darwin kernel.

This generates the original-byte reference for the optional Rust Darwin ABI
replay. It exercises return formatting, not a complete function or syscall.
The kernel is supplied locally; no Apple instruction bytes are embedded here.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct

import unicorn
from unicorn import (
    Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_READ, UC_PROT_WRITE,
    UC_PROT_EXEC, UC_HOOK_CODE, UC_HOOK_MEM_WRITE,
)
from unicorn import arm64_const as arm

from evidence import write_evidence


ROOT = Path(__file__).resolve().parents[1]
KERNEL_SHA256 = "ca55ea8c4c86170e870380ae5501b8b43adb2d2d3db28be4531b3040653be203"
REFERENCE_COMMIT = "f6217f891ac0bb64f3d375211650a4c1ff8ca1ea"
PAGE_PC = 0xfffffe000a633000
PAGE_OFFSET = 0x362f000
ENTRY_START = 0xfffffe000a633688
ENTRY_END = 0xfffffe000a633694
RETURN_START = 0xfffffe000a63386c
RETURN_END = 0xfffffe000a633980
FUNCTION_START = 0xfffffe000a633828
FUNCTION_END = 0xfffffe000a6339fc
RESTART_HELPER = 0xfffffe000a633884
SYSENT, SAVED, UTHREAD = 0x100000, 0x200000, 0x300000
MASK64 = (1 << 64) - 1
RETURN_TYPES = [
    "none", "int", "unsigned_int", "offset", "address", "size",
    "signed_size", "unsigned64",
]
RETURN_PAIRS = [
    (0, 0), (1, 0), (0x7fffffff, 0x80000000), (0x80000000, 0x7fffffff),
    (0xffffffff, 0xffffffff), (0xffffffff, 1), (0, 0xffffffff),
    (0x89abcdef, 0x01234567), (0x01234567, 0x89abcdef),
]
ERRNOS = [1, 4, 9, 22, 78, 0x7fffffff]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def put(data, format_string, offset, *values):
    struct.pack_into(format_string, data, offset, *values)


def guest_state(data, pc=None):
    return {
        "registers": {
            "x": [u64(data, 8 + index * 8) for index in range(31)],
            "sp": u64(data, 0x100),
            "nzcv": u32(data, 0x110),
            "reserved": u32(data, 0x114),
        },
        "pc": u64(data, 0x108) if pc is None else pc,
    }


def saved_state(flags, return_type):
    data = bytearray(
        (index * 73 + flags * 11 + return_type * 7) & 255
        for index in range(0x140)
    )
    put(data, "<II", 0, 0x15, 74)
    for index in range(31):
        value = (
            0xdeadbeef12340000 + index * 0x102030405
            + flags * 0x10001 + return_type
        ) & MASK64
        put(data, "<Q", 8 + index * 8, value)
    put(data, "<Q", 8 + 16 * 8, 4)
    put(data, "<Q", 0x100, 0x40010000)
    put(data, "<Q", 0x108, 0x10000c)
    put(data, "<I", 0x110, flags << 28)
    put(data, "<I", 0x114, 0xa5c39e71)
    return data


def mathematical_result(after_entry, kind, return_type, values, error):
    """Independent arithmetic check; the exported outputs come from Unicorn."""
    expected = bytearray(after_entry)
    if kind == "success":
        if return_type in (1, 2):
            normalized = [
                value if return_type == 2 or value < 0x80000000
                else value - (1 << 32)
                for value in values
            ]
            put(expected, "<QQ", 8, *(value & MASK64 for value in normalized))
        elif return_type in range(3, 8):
            put(expected, "<QQ", 8, values[0] | values[1] << 32, 0)
    elif kind == "error":
        put(expected, "<QQ", 8, error, 0)
        put(expected, "<I", 0x110, u32(expected, 0x110) | 0x20000000)
    return expected


class FormatterProbe:
    def __init__(self, kernel):
        self.harness_sha256 = sha256(Path(__file__).read_bytes())
        self.kernel = kernel.resolve()
        data = self.kernel.read_bytes()
        actual_hash = sha256(data)
        if actual_hash != KERNEL_SHA256:
            raise ValueError(
                f"Expected pinned 26A434 kernel SHA256 {KERNEL_SHA256}; "
                f"received {actual_hash}"
            )
        self.kernel_snapshot_sha256 = actual_hash
        self.code = data[PAGE_OFFSET:PAGE_OFFSET + 4096]
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.uc.mem_map(PAGE_PC, 4096, UC_PROT_READ | UC_PROT_EXEC)
        self.uc.mem_write(PAGE_PC, self.code)
        for base in (SYSENT, SAVED, UTHREAD):
            self.uc.mem_map(base, 4096, UC_PROT_READ | UC_PROT_WRITE)
        self.trace = []
        self.writes = []
        self.cases = []
        self.paths = []
        self.path_ids = {}
        self.restart = []
        self.uc.hook_add(UC_HOOK_CODE, self.on_code)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self.on_write)

    def on_code(self, uc, pc, size, unused):
        self.trace.append(pc)

    def on_write(self, uc, access, address, size, value, unused):
        self.writes.append({
            "offset": address - SAVED,
            "bytes": size,
            "value": value & ((1 << (8 * size)) - 1),
        })

    def instruction(self, pc):
        return bytes(self.uc.mem_read(pc, 4))

    def clear_trace(self):
        self.trace.clear()
        self.writes.clear()

    def path_id(self):
        key = tuple(self.trace)
        if key not in self.path_ids:
            self.path_ids[key] = len(self.paths)
            self.paths.append({
                "id": len(self.paths),
                "pcs": [hex(pc) for pc in self.trace],
                "instruction_bytes": [
                    self.instruction(pc).hex() for pc in self.trace
                ],
            })
        return self.path_ids[key]

    def run_case(self, kind, flags, return_type, values, error):
        before = saved_state(flags, return_type)
        sysent = bytearray(4096)
        put(sysent, "<I", 0x10, return_type)
        uthread = bytearray(4096)
        put(uthread, "<II", 0x40, *values)
        for address, buffer in ((SAVED, before), (SYSENT, sysent), (UTHREAD, uthread)):
            self.uc.mem_write(address, bytes(buffer))
        for index in range(31):
            self.uc.reg_write(
                getattr(arm, "UC_ARM64_REG_X" + str(index)),
                (0x456789ab00000000 + index * 0x10101) & MASK64,
            )
        self.uc.reg_write(arm.UC_ARM64_REG_SP, 0x40400000)
        self.uc.reg_write(arm.UC_ARM64_REG_PSTATE, 0x3c5)
        self.uc.reg_write(arm.UC_ARM64_REG_X19, SAVED)

        self.clear_trace()
        self.uc.emu_start(ENTRY_START, ENTRY_END, count=16)
        assert self.uc.reg_read(arm.UC_ARM64_REG_PC) == ENTRY_END
        assert self.trace == list(range(ENTRY_START, ENTRY_END, 4))
        after_entry = bytes(self.uc.mem_read(SAVED, len(before)))
        expected_entry = bytearray(before)
        put(expected_entry, "<I", 0x110, (flags << 28) & ~0x20000000)
        assert after_entry == expected_entry
        entry_writes = list(self.writes)

        self.clear_trace()
        arguments = (
            (arm.UC_ARM64_REG_X0, SYSENT),
            (arm.UC_ARM64_REG_X1, SAVED),
            (arm.UC_ARM64_REG_X2, UTHREAD),
            (arm.UC_ARM64_REG_X3, error & 0xffffffff),
        )
        for register, value in arguments:
            self.uc.reg_write(register, value)
        end = RESTART_HELPER if kind == "restart" else RETURN_END
        self.uc.emu_start(RETURN_START, end, count=128)
        assert self.uc.reg_read(arm.UC_ARM64_REG_PC) == end
        assert all(RETURN_START <= pc < FUNCTION_END for pc in self.trace)
        assert all(
            self.instruction(pc) == self.code[pc - PAGE_PC:pc - PAGE_PC + 4]
            for pc in self.trace
        )
        assert not any(
            int.from_bytes(self.instruction(pc), "little") & 0xfc000000 == 0x94000000
            for pc in self.trace
        ), "No BL/helper may execute"

        after = bytes(self.uc.mem_read(SAVED, len(before)))
        assert bytes(self.uc.mem_read(SYSENT, 4096)) == sysent
        assert bytes(self.uc.mem_read(UTHREAD, 4096)) == uthread
        assert bytes(self.uc.mem_read(PAGE_PC, 4096)) == self.code
        assert all(
            write["offset"] in (8, 16, 0x110) and write["bytes"] in (4, 8)
            for write in self.writes
        )
        path_id = self.path_id()

        if kind == "restart":
            assert after == after_entry and self.writes == []
            self.restart.append({
                "input_nzcv": flags << 28,
                "path_id": path_id,
                "stop_pc": hex(end),
                "blocking_instruction": self.instruction(end).hex(),
                "reason": (
                    "Original BL to 0xfffffe0009eb9bd4 would execute next; "
                    "no helper/PAC bypass attempted."
                ),
                "saved_state_unchanged_after_entry": True,
            })
            return

        expected = mathematical_result(after_entry, kind, return_type, values, error)
        assert after == expected, (kind, flags, return_type, values, error)
        if kind == "success":
            completion = {"kind": "success", "values": list(values)}
        elif kind == "error":
            completion = {"kind": "error", "errno": error}
        else:
            completion = {"kind": "just_return"}
        self.cases.append({
            "id": len(self.cases),
            "kind": kind,
            "prototype": {"argument_count": 8, "return_type": RETURN_TYPES[return_type]},
            "completion": completion,
            "initial_adapter_state": guest_state(before, 0x100008),
            "kernel_saved_pc_precondition": 0x10000c,
            "original_after_entry_state": guest_state(after_entry),
            "original_observed_state": guest_state(after),
            "saved_buffer_before_hex": bytes(before).hex(),
            "saved_buffer_after_hex": after.hex(),
            "entry_writes": entry_writes,
            "formatter_writes": list(self.writes),
            "path_id": path_id,
            "adapter_comparable": kind != "just_return",
        })

    def run(self):
        for flags in range(16):
            for return_type in range(8):
                for values in RETURN_PAIRS:
                    self.run_case("success", flags, return_type, values, 0)
                for error in ERRNOS:
                    self.run_case("error", flags, return_type, (0x89abcdef, 0x01234567), error)
                self.run_case("just_return", flags, return_type, (0x89abcdef, 0x01234567), -2)
            self.run_case("restart", flags, 1, (0x89abcdef, 0x01234567), -1)
        return self.report()

    def report(self):
        harness_end_sha256 = sha256(Path(__file__).read_bytes())
        kernel_end_sha256 = sha256(self.kernel.read_bytes())
        assert harness_end_sha256 == self.harness_sha256, "Generator changed during execution"
        assert kernel_end_sha256 == self.kernel_snapshot_sha256, "Kernel changed during execution"
        counts = {
            kind: sum(case["kind"] == kind for case in self.cases)
            for kind in ("success", "error", "just_return")
        }
        counts.update({
            "ordinary_adapter_comparable": counts["success"] + counts["error"],
            "restart_blocked_before_helper": len(self.restart),
            "distinct_formatter_paths": len(self.paths),
        })
        normalized_cases = []
        for case in self.cases:
            if not case["adapter_comparable"]:
                continue
            initial = case["initial_adapter_state"]["registers"]
            observed = case["original_observed_state"]
            normalized_cases.append({
                "original_case_id": case["id"],
                "return_type": case["prototype"]["return_type"],
                "completion": case["completion"],
                "input": {
                    "x0": initial["x"][0], "x1": initial["x"][1],
                    "nzcv": initial["nzcv"],
                    "exception_return_pc": case["kernel_saved_pc_precondition"],
                },
                "output": {
                    "x0": observed["registers"]["x"][0],
                    "x1": observed["registers"]["x"][1],
                    "nzcv": observed["registers"]["nzcv"], "pc": observed["pc"],
                },
            })
        return {
            "schema_version": 1,
            "status": "passed",
            "evidence_kind": "original_unchanged_Apple_code_bounded_interior_Unicorn_execution",
            "kernel_path": str(self.kernel),
            "kernel_sha256": KERNEL_SHA256,
            "kernel_snapshot_sha256": self.kernel_snapshot_sha256,
            "unicorn_version": unicorn.__version__,
            "harness_sha256": self.harness_sha256,
            "source_integrity": {
                "harness_start_sha256": self.harness_sha256,
                "harness_end_sha256": harness_end_sha256,
                "kernel_start_sha256": self.kernel_snapshot_sha256,
                "kernel_end_sha256": kernel_end_sha256,
            },
            "reference_commit": REFERENCE_COMMIT,
            "code_page": {
                "va": hex(PAGE_PC), "file_offset": hex(PAGE_OFFSET),
                "bytes": 4096, "sha256": sha256(self.code),
                "mapped_permissions": "read+execute",
            },
            "entry_window": {
                "start": hex(ENTRY_START), "end_exclusive": hex(ENTRY_END),
                "sha256": sha256(self.code[ENTRY_START - PAGE_PC:ENTRY_END - PAGE_PC]),
                "instructions": [
                    "ldr w8,[x19,#0x110]", "and w8,w8,#0xdfffffff",
                    "str w8,[x19,#0x110]",
                ],
            },
            "return_window": {
                "start": hex(RETURN_START), "stop_before_epilogue": hex(RETURN_END),
                "function_start_not_executed": hex(FUNCTION_START),
                "function_sha256": sha256(
                    self.code[FUNCTION_START - PAGE_PC:FUNCTION_END - PAGE_PC]
                ),
            },
            "preconditions": [
                "Synthetic owned buffers at SYSENT 0x100000/SAVED 0x200000/UTHREAD 0x300000, each 4096 bytes RW and nonexecutable.",
                "Synthetic savedstate64 header flavor 0x15; only LP64 interior entry is exercised. Savedstate PAC jophash is arbitrary and never validated.",
                "Hardware-preferred saved guest PC is 0x10000c (SVC at 0x100008); this probe never executes SVC, exception entry or exception return.",
                "CPU PSTATE initialized to 0x3c5 (EL1h, DAIF masked); kernel GPRs and stack are synthetic. Formatter arithmetic changes host CPU flags independently of saved CPSR.",
                "Execute unchanged entry clear-C window separately, then harness supplies formatter arguments X0=sysent,X1=savedstate,X2=uthread,W3=completion. No intervening kernel handler or call sequence is modeled.",
                "All 16 original guest NZCV combinations are covered; success depends on entry clearing C, rather than return formatter independently clearing C.",
                "Synthetic retval pairs cover signed/unsigned32 boundaries and packed64 patterns; maxint error is a formatter-domain boundary, not a claim of an assigned Darwin errno.",
            ],
            "counts": counts,
            "assertions": [
                "Every executed original instruction byte equals pinned file bytes before and after execution. No Apple code patching.",
                "No helper BL/PAC/prologue/epilogue instruction executed.",
                "Entire 0x140-byte savedstate buffer equals independently calculated mathematical normalization; sysent/uthread/code bytes remain unchanged.",
                "All writes restricted to saved X0/X1/CPSR slots. Non-result GPRs, SP, PC, reserved/fault/ESR/jophash/padding bytes preserved.",
            ],
            "limits": [
                "This is bounded emulated execution of two interior code windows, not a complete original function, kernel syscall, PAC or macOS27 behavioral proof.",
                "Original outputs are retained for independent Rust adapter comparison; this harness does not execute or import Rust adapter implementation.",
                "JustReturn observations verify formatter no-op only; adapter deliberately declines context restoration.",
                "Restart is not behaviorally validated: execution stops before first unknown helper BL at 0xfffffe000a633884; no authenticated-state helper is skipped or replaced.",
            ],
            "paths": self.paths,
            "restart_obstacles": self.restart,
            "cases": self.cases,
            "normalized_cases": normalized_cases,
        }


def main():
    if not __debug__:
        raise SystemExit("Run without -O: reference integrity assertions must remain enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--kernel", type=Path,
        default=ROOT / ".stela/26A434/kernelcache.vma2.macho",
        help="Local pinned 26A434 kernel (the exact SHA256 is required)",
    )
    parser.add_argument(
        "--output", type=Path,
        default=ROOT / ".stela/darwin-syscalls/original-formatter.json",
    )
    arguments = parser.parse_args()
    try:
        report = FormatterProbe(arguments.kernel).run()
    except (OSError, ValueError) as error:
        parser.error(str(error))
    archive = write_evidence(arguments.output, report)
    print(json.dumps({
        "path": str(arguments.output.resolve()),
        "sha256": sha256(arguments.output.read_bytes()),
        "snapshot": str(archive),
        "counts": report["counts"],
    }, indent=2))


if __name__ == "__main__":
    main()
