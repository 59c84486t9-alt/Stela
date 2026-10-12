"""Execute the pinned Rosetta AOT library in ARM Unicorn for research only.

Library instructions are never patched. Chained pointers are relocated as a
loader would, and imported calls enter explicit bounded host models. This is
neither an OS loader nor Stela's production runtime. Allocations are monotonic,
poisoned, and never reused; anonymous mappings are zero-filled. Protection and
host-call bounds are enforced, but this is not a complete Darwin allocator or
kernel model (notably, there is no guest errno accessor or demand paging).
"""

import collections
from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct

from unicorn import (
    Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_INVALID,
    UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
)
from unicorn import arm64_const as a

from evidence import ROOT

BASE = 0x10000000
HEAP = 0x20000000
STACK = 0x30000000
HOOK = 0x70000000
STOP = HOOK + 0xF000
HEAP_SIZE = 0x2000000
STACK_SIZE = 0x100000
PAGE = 0x4000
MAX_ALLOCATION = 0x800000
MAX_MAPPING = 0x2000000
MASK64 = (1 << 64) - 1
PINNED_SHA256 = "2285868ea879cc62d7dbde393a161f2b7452e94a74cb92be2df2d9465df03208"
P = ROOT / ".stela/rosetta/26A434/expanded-verified/RosettaUpdateAuto.pkg/Payload/Library/Apple/usr/lib/libRosettaAot.dylib"
REG = [getattr(a, f"UC_ARM64_REG_X{i}") for i in range(31)]


def _range(data, offset, size, label):
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError(f"{label} exceeds its containing region")
    return data[offset:offset + size]


def _unpack(fmt, data, offset, label):
    return struct.unpack(fmt, _range(data, offset, struct.calcsize(fmt), label))


def _cstring(data, offset, label):
    _range(data, offset, 1, label)
    end = data.find(b"\0", offset)
    if end < 0:
        raise ValueError(f"unterminated {label}")
    return data[offset:end].decode("utf-8", errors="strict")


@dataclass(frozen=True)
class Segment:
    vm: int
    size: int
    file_offset: int
    file_size: int
    protection: int


def _parse_macho(data):
    """Parse only the pinned library's little-endian ARM64 dylib layout."""
    magic, cpu, subtype, kind, count, command_bytes, flags, reserved = _unpack(
        "<8I", data, 0, "Mach-O header"
    )
    if (magic, cpu, kind) != (0xFEEDFACF, 0x100000C, 6):
        raise ValueError("expected little-endian ARM64 Mach-O dylib")
    if count > 4096:
        raise ValueError("excessive load-command count")
    commands = _range(data, 32, command_bytes, "load commands")
    segments, symtab, fixups = [], None, None
    at = 0
    for _ in range(count):
        cmd, size = _unpack("<II", commands, at, "load command")
        if size < 8 or size % 8:
            raise ValueError("invalid load-command size")
        command = _range(commands, at, size, "load command")
        if cmd == 0x19:
            vm, vs, fo, fs, maxprot, prot, sections, segflags = _unpack(
                "<QQQQiiII", command, 24, "segment"
            )
            if size != 72 + sections * 80:
                raise ValueError("segment section count does not match command")
            if not vs or vm % PAGE or vs % PAGE or fs > vs:
                raise ValueError("unsupported segment extent/alignment")
            if prot & ~7 or maxprot & ~7 or prot & ~maxprot or prot & 6 == 6:
                raise ValueError("unsupported segment protections")
            if vm + vs > HEAP - BASE:
                raise ValueError("library segment exceeds reserved image window")
            _range(data, fo, fs, "segment file bytes")
            if any(vm < s.vm + s.size and s.vm < vm + vs for s in segments):
                raise ValueError("overlapping library segments")
            segments.append(Segment(vm, vs, fo, fs, prot))
        elif cmd == 2:
            if symtab is not None or size != 24:
                raise ValueError("duplicate or malformed symbol table")
            symtab = _unpack("<4I", command, 8, "symbol table")
        elif cmd == 0x80000034:
            if fixups is not None or size != 16:
                raise ValueError("duplicate or malformed chained fixups")
            offset, length = _unpack("<II", command, 8, "chained fixups")
            fixups = _range(data, offset, length, "chained fixups")
        at += size
    if at != command_bytes or not segments or symtab is None or fixups is None:
        raise ValueError("incomplete Mach-O metadata")
    symoff, nsyms, stroff, strsize = symtab
    symbols = _range(data, symoff, nsyms * 16, "symbols")
    strings = _range(data, stroff, strsize, "symbol strings")
    exports = {}
    for i in range(nsyms):
        name, kind, section, desc, address = _unpack("<IBBHQ", symbols, i * 16, "symbol")
        if kind & 0xE == 0xE and not kind & 0xE0:
            text = _cstring(strings, name, "symbol name")
            if text in exports:
                raise ValueError("duplicate defined symbol")
            if not any(s.vm <= address < s.vm + s.size for s in segments):
                raise ValueError("defined symbol outside image")
            exports[text] = address
    return segments, exports, fixups


def _parse_fixups(data, segments, fixups):
    """Return (imports, pointer patches), with every chain confined to its page.

    Only DYLD_CHAINED_IMPORT and DYLD_CHAINED_PTR_64_OFFSET are modeled.
    Layout reference: apple-oss-distributions/dyld/include/mach-o/fixup-chains.h
    (pointer64 bind addends are unsigned 0..255).
    Patch destinations refer to image-relative addresses; targets are tagged
    tuples ("bind", ordinal, unsigned_addend) or ("rebase", image_offset, high8).
    """
    version, starts, imports, symbols, count, form, sform = _unpack(
        "<7I", fixups, 0, "fixup header"
    )
    if version != 0 or form != 1 or sform != 0 or count > (STOP - HOOK) // 16:
        raise ValueError("unsupported chained-fixup formats/count")
    table = _range(fixups, imports, count * 4, "import table")
    names = []
    for i in range(count):
        value, = _unpack("<I", table, i * 4, "import")
        names.append(_cstring(fixups, symbols + (value >> 9), "import name"))
    segment_count, = _unpack("<I", fixups, starts, "fixup starts")
    if segment_count != len(segments):
        raise ValueError("fixup segment count mismatch")
    offsets = _range(fixups, starts + 4, segment_count * 4, "segment start offsets")
    patches, seen = [], set()
    for index, segment in enumerate(segments):
        relative, = _unpack("<I", offsets, index * 4, "segment start offset")
        if not relative:
            continue
        if not segment.protection & UC_PROT_WRITE:
            raise ValueError("fixups into non-writable library segment")
        offset = starts + relative
        size, page, fmt, vm, maximum, pages = _unpack("<IHHQIH", fixups, offset, "segment starts")
        record = _range(fixups, offset, size, "segment starts record")
        if size < 22 + pages * 2 or page != PAGE or fmt != 6 or maximum != 0:
            raise ValueError("unsupported segment chain format")
        if vm != segment.vm or pages * page > segment.size:
            raise ValueError("chain pages exceed matching segment")
        for pi in range(pages):
            first, = _unpack("<H", record, 22 + pi * 2, "page start")
            if first == 0xFFFF:
                continue
            if first & 0x8000:
                raise ValueError("multiple chains per page are unsupported")
            within = first
            while True:
                if within + 8 > page or within % 4:
                    raise ValueError("chain pointer crosses page or is unaligned")
                address = vm + pi * page + within
                if address in seen:
                    raise ValueError("overlapping chain pointers")
                seen.add(address)
                file_relative = address - segment.vm
                if file_relative + 8 > segment.file_size:
                    raise ValueError("chain pointer is not file-backed")
                value, = _unpack("<Q", data, segment.file_offset + file_relative, "chain pointer")
                next_delta = ((value >> 51) & 0xFFF) * 4
                if value >> 63:
                    ordinal, addend = value & 0xFFFFFF, (value >> 24) & 0xFF
                    if ordinal >= count or (value >> 32) & 0x7FFFF:
                        raise ValueError("invalid bind ordinal/reserved bits")
                    target = ("bind", ordinal, addend)
                else:
                    target_offset = value & ((1 << 36) - 1)
                    high = (value >> 36) & 0xFF
                    if (value >> 44) & 0x7F:
                        raise ValueError("nonzero rebase reserved bits")
                    if high or not any(s.vm <= target_offset < s.vm + s.size for s in segments):
                        raise ValueError("unsupported rebase target")
                    target = ("rebase", target_offset, high)
                patches.append((address, target))
                if not next_delta:
                    break
                if next_delta < 8:
                    raise ValueError("overlapping chain pointers")
                within += next_delta
    return names, patches


class Harness:
    def __init__(self, path=P):
        path = Path(path)
        if path.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("library exceeds research input limit")
        self.data = path.read_bytes()
        if hashlib.sha256(self.data).hexdigest() != PINNED_SHA256:
            raise ValueError("Rosetta library does not match pinned SHA256")
        self.segments, self.exports, fixups = _parse_macho(self.data)
        names, patches = _parse_fixups(self.data, self.segments, fixups)
        self.u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.u.ctl_set_cpu_model(a.UC_CPU_ARM64_MAX)
        self.u.mem_map(HEAP, HEAP_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.u.mem_map(STACK, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.u.mem_map(HOOK, 0x10000, UC_PROT_READ | UC_PROT_EXEC)
        self.u.mem_write(HOOK, b"\x00\x00\x20\xd4" * (0x10000 // 4))
        self.map_next = 0x100000000
        self.mappings = {}
        self.next = HEAP
        self.allocations = {}
        self.events = []
        self.pcs = collections.deque(maxlen=16)
        self.errno = 0
        for segment in self.segments:
            # mem_write is the loader API and may initialize RX regions.
            self.u.mem_map(BASE + segment.vm, segment.size, segment.protection)
            self.u.mem_write(BASE + segment.vm, self.data[segment.file_offset:segment.file_offset + segment.file_size])
        self.hooks = {HOOK + i * 16: name for i, name in enumerate(names)}
        targets = [HOOK + i * 16 for i in range(len(names))]
        guard = self.blob(struct.pack("<Q", 0x1122334455667788))
        if names.count("___stack_chk_guard") != 1:
            raise ValueError("expected exactly one stack guard import")
        targets[names.index("___stack_chk_guard")] = guard
        self.fixup_counts = {"rebases": 0, "binds": 0}
        for address, target in patches:
            if target[0] == "bind":
                pointer = targets[target[1]] + target[2]
                self.fixup_counts["binds"] += 1
            else:
                pointer = BASE + target[1]
                self.fixup_counts["rebases"] += 1
            self.u.mem_write(BASE + address, struct.pack("<Q", pointer))
        self.u.hook_add(UC_HOOK_CODE, self.code)
        self.u.hook_add(UC_HOOK_MEM_INVALID, self.invalid)

    def alloc(self, size, zero=False):
        if not 0 <= size <= MAX_ALLOCATION:
            raise ValueError(f"allocation size {size}")
        pointer = self.next
        end = pointer + ((max(1, size) + 15) & ~15)
        if end > HEAP + HEAP_SIZE:
            raise ValueError("heap exhausted")
        self.next = end
        self.allocations[pointer] = size
        self.u.mem_write(pointer, (b"\0" if zero else b"\xcd") * max(size, 1))
        return pointer

    def blob(self, data):
        pointer = self.alloc(len(data))
        if data:
            self.u.mem_write(pointer, data)
        return pointer

    def reg(self, index):
        return self.u.reg_read(REG[index])

    def _check_memory(self, pointer, size, write=False):
        if not 0 <= size <= MAX_MAPPING or not 0 <= pointer <= MASK64 or size > MASK64 - pointer:
            raise ValueError("host memory operation exceeds bound")
        if not size:
            return
        regions = [(p, max(1, n), True) for p, n in self.allocations.items()]
        regions += [(p, n, True) for p, n in self.mappings.items()]
        regions += [(STACK, STACK_SIZE, True)]
        regions += [(BASE + s.vm, s.size, bool(s.protection & UC_PROT_WRITE)) for s in self.segments if s.protection & UC_PROT_READ]
        if not any(start <= pointer and pointer + size <= start + length and (writable or not write)
                   for start, length, writable in regions):
            raise ValueError(f"host {'write' if write else 'read'} outside live region: {pointer:#x}+{size}")

    def _bytestring(self, pointer):
        result = bytearray()
        for offset in range(4096):
            self._check_memory(pointer + offset, 1)
            byte = self.u.mem_read(pointer + offset, 1)
            if byte == b"\0":
                return bytes(result)
            result.extend(byte)
        raise ValueError("unterminated string")

    def string(self, pointer):
        return self._bytestring(pointer).decode(errors="replace")

    def invalid(self, u, kind, address, size, value, _):
        raise RuntimeError(
            f"invalid memory kind={kind} address={address:#x} size={size} "
            f"pc={u.reg_read(a.UC_ARM64_REG_PC) - BASE:#x} "
            f"recent={[hex(p - BASE) for p in self.pcs]}"
        )

    def code(self, u, pc, size, _):
        self.pcs.append(pc)
        if pc not in self.hooks:
            if HOOK <= pc < HOOK + 0x10000:
                raise RuntimeError(f"execution at unknown import slot {pc:#x}")
            return
        name = self.hooks[pc]
        args = [self.reg(i) for i in range(6)]
        self.events.append((name, args[:3]))
        result = self._import(name, args)
        if result is not None:
            self.u.reg_write(REG[0], result & MASK64)
        self.u.reg_write(a.UC_ARM64_REG_PC, self.reg(30))

    def _import(self, name, x):
        if name == "__ZnwmSt19__type_descriptor_t":
            return self.alloc(x[0])
        if name == "_malloc_type_calloc":
            return self.alloc(x[0] * x[1], zero=True)
        if name in ("__ZdlPv", "__ZdlPvSt19__type_descriptor_t", "_free"):
            if x[0]:
                if x[0] not in self.allocations:
                    raise ValueError(f"unknown free {x[0]:#x}")
                size = self.allocations.pop(x[0])
                self.u.mem_write(x[0], b"\xdd" * max(1, size))
            return None
        if name in ("_memcpy", "_memmove"):
            if x[2] > MAX_ALLOCATION:
                raise ValueError("copy size exceeds bound")
            self._check_memory(x[0], x[2], write=True)
            self._check_memory(x[1], x[2])
            if name == "_memcpy" and x[2] and x[0] < x[1] + x[2] and x[1] < x[0] + x[2]:
                raise ValueError("overlapping memcpy")
            if x[2]:
                self.u.mem_write(x[0], bytes(self.u.mem_read(x[1], x[2])))
            return x[0]
        if name == "_bzero":
            self._check_memory(x[0], x[1], write=True)
            if x[1]:
                self.u.mem_write(x[0], b"\0" * x[1])
            return None
        if name == "_mmap":
            # Darwin fd contains VM_MAKE_TAG metadata for MAP_ANON, not a file.
            if x[3] != 0x1002 or x[2] != 3 or x[5] != 0 or not 0 < x[1] <= MAX_MAPPING:
                raise ValueError("unsupported mmap shape")
            size = (x[1] + PAGE - 1) & ~(PAGE - 1)
            if sum(self.mappings.values()) + size > 2 * MAX_MAPPING:
                raise ValueError("anonymous mapping budget exhausted")
            pointer = self.map_next
            self.u.mem_map(pointer, size, UC_PROT_READ | UC_PROT_WRITE)
            self.map_next += size + PAGE
            self.mappings[pointer] = size
            return pointer
        if name == "_munmap":
            if x[1] == 0:
                self.errno = 22
                return MASK64
            if self.mappings.get(x[0]) != x[1]:
                raise ValueError("unsupported partial or unknown munmap")
            self.u.mem_unmap(x[0], x[1])
            self.mappings.pop(x[0])
            return 0
        if name == "_strcmp":
            left, right = self._bytestring(x[0]), self._bytestring(x[1])
            for first, second in zip(left + b"\0", right + b"\0"):
                if first != second:
                    return first - second
            return 0
        if name.startswith("_abort") or name == "___stack_chk_fail":
            texts = []
            for pointer in x:
                try:
                    texts.append(self.string(pointer))
                except (ValueError, RuntimeError):
                    pass
            raise RuntimeError(f"abort {texts}")
        raise RuntimeError(f"unmodeled import {name} {x}")

    def call(self, key, args, stack=()):
        matches = [name for name in self.exports if key in name]
        if len(matches) != 1:
            raise ValueError(f"export query {key!r} matched {len(matches)} symbols")
        if len(args) > 8 or len(stack) > 32:
            raise ValueError("call argument count exceeds research ABI")
        pc = BASE + self.exports[matches[0]]
        if not any(BASE + s.vm <= pc < BASE + s.vm + s.size and s.protection & UC_PROT_EXEC for s in self.segments):
            raise ValueError("call target is not executable")
        sp = STACK + 0xF0000
        for register in REG:
            self.u.reg_write(register, 0)
        for index, value in enumerate(args):
            self.u.reg_write(REG[index], value)
        self.u.reg_write(a.UC_ARM64_REG_SP, sp)
        self.u.reg_write(a.UC_ARM64_REG_NZCV, 0)
        self.u.reg_write(REG[30], STOP)
        self.u.mem_write(sp, b"\0" * 256)
        for index, value in enumerate(stack):
            self.u.mem_write(sp + index * 8, struct.pack("<Q", value))
        self.u.emu_start(pc, STOP, timeout=5_000_000, count=2_000_000)
        if self.u.reg_read(a.UC_ARM64_REG_PC) != STOP:
            raise RuntimeError("execution budget expired")
        return self.reg(0)

    def translate(self, code, runtime_base=0x60010000, code_base=0x60000000, ir_flags=0):
        if not 0 < len(code) <= 4096:
            raise ValueError("research input must be 1..4096 x86 bytes")
        if not all(0 <= value <= MASK64 for value in (runtime_base, code_base, ir_flags)):
            raise ValueError("translation parameters exceed uint64")
        # These runtime ABI offsets and the name-table address are observations
        # for this exact hash, not a claimed stable Rosetta API.
        offsets = self.blob(struct.pack("<100I", *(i * 16 for i in range(100))))
        name_table = BASE + 0x54000
        self.call("32register_runtime", [offsets, name_table, 100])
        names = [self.string(struct.unpack("<Q", self.u.mem_read(name_table + i * 8, 8))[0]) for i in range(100)]
        source = self.blob(code)
        entries = self.blob(struct.pack("<I", 0))
        vector = self.blob(struct.pack("<QQQ", entries, entries + 4, entries + 4))
        empty = self.blob(b"\0" * 24)
        image_base = 0x100000000
        module = self.call("9ir_create", [source, image_base, image_base + len(code), image_base,
                                         image_base + len(code), len(code) << 32, 0, 0],
                           [0, ir_flags, vector, empty])
        if self.call("15module_get_size", [module]) != len(code):
            raise ValueError("IR module size does not match input text")
        translation = self.call("9translate", [module])
        data = self.call("19translator_get_data", [translation])
        size = self.call("19translator_get_size", [translation])
        if not 0 < size <= 1024 * 1024:
            raise ValueError("unexpected generated-code size")
        self._check_memory(data, size, write=True)
        self.call("21apply_internal_fixups", [translation, code_base, data])
        self.call("28apply_runtime_routine_fixups", [translation, runtime_base, code_base, data])
        output = bytes(self.u.mem_read(data, size))
        self.call("15translator_free", [translation])
        self.call("11module_free", [module])
        return output, names
