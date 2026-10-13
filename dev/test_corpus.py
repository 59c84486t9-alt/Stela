"""Pattern-profile boundaries and grouping; synthetic instructions, no Apple inputs."""
import unittest

import corpus


def words(*values):
    return b"".join(value.to_bytes(4, "little") for value in values)


def profile(data, symbols=None, extra_sections=()):
    result = corpus.PatternProfile()
    result.add_slice({"artifact": {"sha256": "a" * 64, "architecture": "arm64"},
                      "entry_guest_address": 0x1000,
                      "defined_text_symbols": symbols or {},
                      "sections": [{"name": "__text", "guest_address": 0x1000,
                                    "data_hex": data.hex()}, *extra_sections]})
    return result.report(50)


class PatternTests(unittest.TestCase):
    def test_register_aliases_and_widths(self):
        self.assertEqual(corpus.register_key("w7"), corpus.register_key("x7"))
        self.assertEqual(corpus.register_key("q7"), corpus.register_key("z7"))
        self.assertEqual(corpus.register_key("d7"), corpus.register_key("v7"))
        self.assertEqual(corpus.register_key("lr"), corpus.register_key("x30"))
        self.assertNotEqual(corpus.register_key("x7"), corpus.register_key("v7"))
        self.assertNotEqual(corpus.register_key("p7"), corpus.register_key("v7"))
        self.assertEqual(corpus.register_key("sp"), corpus.register_key("wsp"))
        self.assertEqual(corpus.register_key("xzr")[0], "special")

    def test_renamed_registers_group_but_changed_dependencies_do_not(self):
        # ADRP X0; ADD X0,X0,#0 versus the same operations on X7.
        first = corpus.decode_section(words(0x90000000, 0x91000000), 0x1000)
        renamed = corpus.decode_section(words(0x90000007, 0x910000e7), 0x1000)
        independent = corpus.decode_section(words(0x90000000, 0x91000021), 0x1000)
        template, registers = corpus.pattern_template(first)
        self.assertEqual(template, "adrp x{g0}, #imm ; add x{g0}, x{g0}, #imm")
        self.assertEqual(corpus.pattern_template(renamed), (template, registers))
        self.assertNotEqual(corpus.pattern_template(independent)[0], template)
        self.assertEqual(registers["gpr"], 1)

    def test_immediates_generalized_vector_arrangements_retained(self):
        first = corpus.decode_section(words(0x91000400), 0x1000)
        second = corpus.decode_section(words(0x91000800), 0x1000)
        self.assertEqual(corpus.pattern_template(first), corpus.pattern_template(second))
        vectors = corpus.decode_section(words(0x4ea11c20, 0x0ea11c20), 0x1000)
        template, registers = corpus.pattern_template(vectors)
        self.assertIn(".16b", template)
        self.assertIn(".8b", template)
        self.assertEqual(registers["vector"], 2)
        stack32 = corpus.decode_section(words(0x110007ff), 0x1000)
        stack64 = corpus.decode_section(words(0x910007ff), 0x1000)
        self.assertNotEqual(corpus.pattern_template(stack32)[0], corpus.pattern_template(stack64)[0])

    def test_overlapping_windows_and_stable_example_identity(self):
        result = profile(words(0x90000000, 0x91000000, 0x91000400, 0xd65f03c0))
        self.assertEqual(result["candidate_instructions"], 4)
        self.assertEqual([result["windows"][str(n)]["occurrences"] for n in (2, 3, 4)], [3, 2, 1])
        row = next(row for row in result["windows"]["2"]["top"] if row["template"].startswith("adrp"))
        self.assertEqual(row["example"]["guest_pc"], 0x1000)
        self.assertEqual(row["example"]["source_hex"], words(0x90000000, 0x91000000).hex())
        self.assertEqual(row["example"]["slice_sha256"], "a" * 64)
        self.assertEqual(row["example"]["capstone_read_after_write_edges"],
                         [{"producer": 0, "consumer": 1, "register_family": "gpr"}])

    def test_symbol_entry_splits_run(self):
        result = profile(words(0xd503201f, 0xd503201f, 0xd503201f, 0xd65f03c0), {"_second": 0x1008})
        self.assertEqual(result["windows"]["2"]["occurrences"], 2)
        self.assertEqual(result["windows"]["3"]["occurrences"], 0)

    def test_direct_target_splits_preceding_fallthrough(self):
        # B 0x1010 followed by four words; no window may cross into that target.
        result = profile(words(0x14000004, 0xd503201f, 0xd503201f, 0xd503201f, 0xd65f03c0))
        self.assertEqual(result["windows"]["2"]["occurrences"], 2)
        self.assertEqual(result["windows"]["4"]["occurrences"], 0)

    def test_direct_target_from_other_section_splits_run(self):
        result = profile(words(0xd503201f, 0xd503201f, 0xd503201f, 0xd65f03c0),
                         extra_sections=({"name": "__stubs", "guest_address": 0x2000,
                                          "data_hex": words(0x17fffc02).hex()},))
        self.assertEqual(result["sections"], 2)
        self.assertEqual(result["windows"]["2"]["occurrences"], 2)
        self.assertEqual(result["windows"]["3"]["occurrences"], 0)

    def test_calls_authenticated_returns_and_traps_end_runs(self):
        for control in (0x94000000, 0xd65f03c0, 0xd65f0fff, 0xd63f0000,
                        0xd73f0801, 0xd4001001, 0xd4200000, 0x00000000):
            with self.subTest(word=hex(control)):
                result = profile(words(0x91000400, control, 0x91000400, 0xd65f03c0))
                self.assertEqual(result["windows"]["3"]["occurrences"], 0)

    def test_decode_gaps_and_trailing_bytes_end_runs(self):
        result = profile(words(0xd503201f, 0xffffffff, 0x91000400, 0xd65f03c0) + b"\x00\x01")
        self.assertEqual(result["invalid_or_undecoded_bytes"], 6)
        self.assertEqual(result["candidate_instructions"], 3)
        self.assertEqual(result["windows"]["2"]["occurrences"], 1)

    def test_tbz_uses_branch_target_not_bit_number(self):
        decoded = corpus.decode_section(words(0x36000040), 0x1000)
        self.assertEqual(corpus.direct_targets(decoded), {0x1008})
        trap = corpus.decode_section(words(0xd4001001), 0x1000)
        self.assertEqual(corpus.direct_targets(trap), set())

    def test_sections_never_join_and_limit_does_not_truncate_totals(self):
        result = profile(words(0x91000400, 0xd65f03c0),
                         extra_sections=({"name": "__other", "guest_address": 0x1008,
                                          "data_hex": words(0x91000421, 0xd65f03c0).hex()},))
        self.assertEqual(result["windows"]["2"]["occurrences"], 2)
        self.assertEqual(result["windows"]["2"]["distinct_templates"], 1)
        self.assertEqual(result["windows"]["3"]["occurrences"], 0)
        collector = corpus.PatternProfile()
        collector.add_slice({"artifact": {"sha256": "a" * 64, "architecture": "arm64"},
                             "entry_guest_address": 0x1000, "defined_text_symbols": {},
                             "sections": [{"name": "__text", "guest_address": 0x1000,
                                           "data_hex": words(0x90000000, 0x91000000, 0xd65f03c0).hex()}]})
        limited = collector.report(1)["windows"]["2"]
        self.assertEqual(limited["occurrences"], 2)
        self.assertEqual(limited["distinct_templates"], 2)
        self.assertEqual(len(limited["top"]), 1)


if __name__ == "__main__":
    unittest.main()
