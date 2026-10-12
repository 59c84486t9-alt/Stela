"""Synthetic tests: no Apple binaries or executable host code required."""
import collections
import struct
import unittest

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UcError
from unicorn import arm64_const as a

from rosetta_execution import (
    Harness, Segment, _parse_macho, _parse_fixups, BASE, HEAP, HEAP_SIZE,
    STACK, STACK_SIZE, HOOK, PAGE, REG, MASK64, MAX_MAPPING,
)


def model():
    harness = Harness.__new__(Harness)
    harness.u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    harness.u.mem_map(HEAP, HEAP_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    harness.u.mem_map(STACK, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    harness.u.mem_map(BASE, PAGE, UC_PROT_READ | UC_PROT_EXEC)
    harness.next = HEAP
    harness.map_next = 0x100000000
    harness.allocations = {}
    harness.mappings = {}
    harness.segments = [Segment(0, PAGE, 0, PAGE, UC_PROT_READ | UC_PROT_EXEC)]
    harness.events = []
    harness.pcs = collections.deque(maxlen=16)
    harness.hooks = {HOOK: "_memmove"}
    harness.errno = 0
    return harness


def macho():
    """Small dylib with one RW segment, one export, one chain pointer."""
    data = bytearray(PAGE)
    commands = (
        struct.pack("<II16sQQQQiiII", 0x19, 72, b"__DATA", 0, PAGE, 0, PAGE, 3, 3, 0, 0)
        + struct.pack("<6I", 2, 24, 256, 1, 272, 4)
        + struct.pack("<4I", 0x80000034, 16, 512, 80)
    )
    data[:32] = struct.pack("<8I", 0xFEEDFACF, 0x100000C, 0, 6, 3, len(commands), 0, 0)
    data[32:32 + len(commands)] = commands
    struct.pack_into("<IBBHQ", data, 256, 1, 0xF, 1, 0, 1024)
    data[272:276] = b"\0_f\0"
    fixups = bytearray(80)
    struct.pack_into("<7I", fixups, 0, 0, 28, 60, 64, 1, 1, 0)
    struct.pack_into("<2I", fixups, 28, 1, 8)
    struct.pack_into("<IHHQIH", fixups, 36, 24, PAGE, 6, 0, 0, 1)
    struct.pack_into("<H", fixups, 58, 1024)
    struct.pack_into("<I", fixups, 60, 1)
    fixups[64:69] = b"_foo\0"
    data[512:592] = fixups
    struct.pack_into("<Q", data, 1024, 2048)
    return data


class ParserTests(unittest.TestCase):
    def test_valid_synthetic_macho_and_rebase(self):
        data = macho()
        segments, exports, fixups = _parse_macho(data)
        self.assertEqual(exports, {"_f": 1024})
        self.assertEqual(_parse_fixups(data, segments, fixups), (["_foo"], [(1024, ("rebase", 2048, 0))]))

    def test_bind_addend_is_unsigned_not_arm64e_signed(self):
        data = macho()
        struct.pack_into("<Q", data, 1024, (1 << 63) | (255 << 24))
        segments, _, fixups = _parse_macho(data)
        self.assertEqual(_parse_fixups(data, segments, fixups)[1], [(1024, ("bind", 0, 255))])

    def test_truncated_structures_fail(self):
        data = macho()
        for length in (0, 31, 40, 100, 1024, PAGE - 1):
            with self.subTest(length=length), self.assertRaises(ValueError):
                _parse_macho(data[:length])

    def test_load_command_and_symbol_bounds(self):
        for offset, value in ((36, 7), (20, 8), (16, 4097), (32 + 72 + 8, PAGE), (256, 999)):
            data = macho()
            struct.pack_into("<I", data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                _parse_macho(data)

    def test_chain_metadata_bounds_and_formats(self):
        for offset, fmt, value in (
            (512 + 4, "I", 80), (512 + 16, "I", 100000),
            (512 + 28, "I", 2), (512 + 40, "H", 4096),
            (512 + 42, "H", 1), (512 + 58, "H", 0x8000),
            (512 + 58, "H", PAGE - 4), (512 + 60, "I", 0x7FFFFF << 9),
        ):
            data = macho()
            struct.pack_into("<" + fmt, data, offset, value)
            segments, _, fixups = _parse_macho(data)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                _parse_fixups(data, segments, fixups)

    def test_pointer_bounds_reserved_bits_and_overlaps(self):
        for pointer in (PAGE, 1 << 44, (1 << 63) | 1, (1 << 63) | (1 << 32), (4095 << 51) | 2048, (1 << 51) | 2048):
            data = macho()
            struct.pack_into("<Q", data, 1024, pointer)
            segments, _, fixups = _parse_macho(data)
            with self.subTest(pointer=pointer), self.assertRaises(ValueError):
                _parse_fixups(data, segments, fixups)

    def test_fixups_cannot_patch_original_code(self):
        data = macho()
        struct.pack_into("<i", data, 32 + 60, 5)
        struct.pack_into("<i", data, 32 + 56, 5)
        segments, _, fixups = _parse_macho(data)
        with self.assertRaisesRegex(ValueError, "non-writable"):
            _parse_fixups(data, segments, fixups)


class HostModelTests(unittest.TestCase):
    def setUp(self):
        self.h = model()

    def invoke(self, name, *args):
        return self.h._import(name, list(args) + [0] * (6 - len(args)))

    def test_allocations_are_poisoned_calloc_zeroed_and_freed_checked(self):
        p = self.invoke("__ZnwmSt19__type_descriptor_t", 17)
        q = self.invoke("_malloc_type_calloc", 3, 7)
        self.assertEqual(bytes(self.h.u.mem_read(p, 17)), b"\xcd" * 17)
        self.assertEqual(bytes(self.h.u.mem_read(q, 21)), bytes(21))
        self.invoke("_free", p)
        self.assertEqual(bytes(self.h.u.mem_read(p, 17)), b"\xdd" * 17)
        with self.assertRaises(ValueError):
            self.invoke("_free", p)
        with self.assertRaises(ValueError):
            self.h._check_memory(p, 1)
        self.invoke("_free", 0)
        for n in (-1, 0x800001, MASK64):
            with self.assertRaises(ValueError):
                self.h.alloc(n)
        with self.assertRaises(ValueError):
            self.invoke("_malloc_type_calloc", MASK64, 2)

    def test_copy_and_zero_require_live_writable_ranges(self):
        p = self.h.blob(b"abcdef")
        self.assertEqual(self.invoke("_memmove", p + 1, p, 5), p + 1)
        self.assertEqual(bytes(self.h.u.mem_read(p, 6)), b"aabcde")
        with self.assertRaisesRegex(ValueError, "overlapping"):
            self.invoke("_memcpy", p + 1, p, 5)
        for name, args in (("_memcpy", (p, p, 7)), ("_bzero", (p, 7)),
                           ("_bzero", (BASE, 1)), ("_bzero", (0, MASK64))):
            with self.subTest(name=name, args=args), self.assertRaises(ValueError):
                self.invoke(name, *args)
        self.assertEqual(self.invoke("_memcpy", p, 0, 0), p)
        self.invoke("_bzero", 0, 0)
        self.invoke("_bzero", p, 6)
        self.assertEqual(bytes(self.h.u.mem_read(p, 6)), bytes(6))

    def test_strcmp_uses_unsigned_bytes_and_null_termination(self):
        p, q = self.h.blob(b"\xff\0"), self.h.blob(b"\x01\0")
        self.assertEqual(self.invoke("_strcmp", p, q), 254)
        self.assertEqual(self.invoke("_strcmp", q, p), -254)
        self.assertEqual(self.invoke("_strcmp", p, p), 0)
        bad = self.h.blob(b"x" * 4096)
        with self.assertRaisesRegex(ValueError, "unterminated"):
            self.h.string(bad)

    def test_mmap_metadata_zero_fill_permissions_and_munmap_errno(self):
        p = self.invoke("_mmap", 0x100000000, 1, 3, 0x1002, 0xEC000000, 0)
        self.assertEqual(self.h.mappings, {p: PAGE})
        self.assertEqual(bytes(self.h.u.mem_read(p, PAGE)), bytes(PAGE))
        region = next(r for r in self.h.u.mem_regions() if r[0] == p)
        self.assertEqual(region[2], UC_PROT_READ | UC_PROT_WRITE)
        self.assertEqual(self.invoke("_munmap", 0, 0), MASK64)
        self.assertEqual(self.h.errno, 22)
        self.assertIn(p, self.h.mappings)
        with self.assertRaises(ValueError):
            self.invoke("_munmap", p, 1)
        self.assertEqual(self.invoke("_munmap", p, PAGE), 0)
        self.assertEqual(self.h.mappings, {})
        with self.assertRaises(ValueError):
            self.h._check_memory(p, 1)

    def test_mmap_rejects_unmodeled_shapes_and_exhaustion(self):
        valid = [0, PAGE, 3, 0x1002, 0xE6000000, 0]
        for index, value in ((1, 0), (1, MAX_MAPPING + 1), (2, 7), (3, 0x1012), (3, 0x1001), (5, 1)):
            args = valid.copy()
            args[index] = value
            with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                self.invoke("_mmap", *args)
        self.invoke("_mmap", 0, MAX_MAPPING, 3, 0x1002, 0, 0)
        self.invoke("_mmap", 0, MAX_MAPPING, 3, 0x1002, 0, 0)
        with self.assertRaisesRegex(ValueError, "budget"):
            self.invoke("_mmap", *valid)

    def test_guest_cannot_write_text_or_execute_heap_and_stack(self):
        # STR X1,[X0] targets the same RX page that contains the instruction.
        self.h.u.mem_write(BASE, struct.pack("<I", 0xF9000001))
        self.h.u.reg_write(REG[0], BASE)
        with self.assertRaises(UcError):
            self.h.u.emu_start(BASE, BASE + 4, count=1)
        for address in (HEAP, STACK):
            self.h.u.mem_write(address, struct.pack("<I", 0xD503201F))
            with self.subTest(address=address), self.assertRaises(UcError):
                self.h.u.emu_start(address, address + 4, count=1)

    def test_import_hook_returns_pointer_and_unsupported_slots_trap(self):
        p = self.h.blob(b"xyz")
        q = self.h.alloc(3)
        for i, value in enumerate((q, p, 3)):
            self.h.u.reg_write(REG[i], value)
        self.h.u.reg_write(REG[30], 1234)
        self.h.code(self.h.u, HOOK, 4, None)
        self.assertEqual(self.h.reg(0), q)
        self.assertEqual(self.h.u.reg_read(a.UC_ARM64_REG_PC), 1234)
        self.assertEqual(self.h.events, [("_memmove", [q, p, 3])])
        with self.assertRaisesRegex(RuntimeError, "unknown import slot"):
            self.h.code(self.h.u, HOOK + 4, 4, None)
        with self.assertRaisesRegex(RuntimeError, "unmodeled import"):
            self.invoke("_unknown")
        with self.assertRaisesRegex(RuntimeError, "abort"):
            self.invoke("_abort")


if __name__ == "__main__":
    unittest.main()
