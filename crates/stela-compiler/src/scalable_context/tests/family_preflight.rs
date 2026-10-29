//! Every streaming SVE family admits its forms under one contract: a reserved
//! encoding refuses with the family's reason, a valid form refuses outside
//! streaming mode and behind an unvalidated MOVPRFX, and the plain leaf path
//! never takes it.
use super::*;
use alloc::string::String;

const MOVPRFX_PREDICATED_Z0_Z1: u32 = 0x0410_2020;

struct Family {
    reserved_reason: &'static str,
    reserved: &'static [u32],
    valid: u32,
    /// MOVPRFX forms that cannot prefix `valid`.
    prefixes: &'static [u32],
    vector_bytes: usize,
}

const FAMILIES: [Family; 7] = [
    Family {
        reserved_reason: "reserved streaming integer comparison",
        // CMPEQ (wide) with doubleword elements.
        reserved: &[0x24c0_2020],
        // CMPEQ P0.B, P0/Z, Z1.B, Z0.B.
        valid: 0x2400_2020,
        prefixes: &[MOVPRFX_Z0_Z1],
        vector_bytes: 32,
    },
    Family {
        reserved_reason: "reserved streaming integer arithmetic",
        // SDIV byte, UDIV halfword, SADDLB byte, ADD (immediate) byte LSL 8.
        reserved: &[0x0414_0000, 0x0455_0000, 0x4500_0000, 0x2520_e000],
        // ADD Z0.S, Z1.S, Z2.S.
        valid: 0x0422_0020,
        prefixes: &[MOVPRFX_Z0_Z1],
        vector_bytes: 32,
    },
    Family {
        reserved_reason: "reserved streaming integer saturation",
        // SQADD (immediate) byte LSL 8, SABDLB byte.
        reserved: &[0x2524_e000, 0x4500_3000],
        // SQADD Z0.S, Z1.S, Z2.S.
        valid: 0x0422_1020,
        prefixes: &[MOVPRFX_Z0_Z1, MOVPRFX_PREDICATED_Z0_Z1],
        vector_bytes: 32,
    },
    Family {
        reserved_reason: "reserved streaming integer-bit",
        // REVB/REVH/REVW with sizes they do not take.
        reserved: &[
            0x0524_8020,
            0x0525_8020,
            0x0565_8020,
            0x0526_8020,
            0x0566_8020,
            0x05a6_8020,
        ],
        // CLS Z0.B, P0/M, Z1.B.
        valid: 0x0418_a020,
        prefixes: &[MOVPRFX_Z0_Z1],
        vector_bytes: 16,
    },
    Family {
        reserved_reason: "reserved streaming integer product",
        // SMULLB byte, PMULLB word.
        reserved: &[0x4500_7000, 0x4580_6800],
        // MUL Z0.S, Z1.S, Z2.S.
        valid: 0x0422_6020,
        prefixes: &[MOVPRFX_Z0_Z1],
        vector_bytes: 32,
    },
    Family {
        reserved_reason: "reserved streaming integer shift",
        // LSL with a reserved size, ASR with doublewords.
        reserved: &[0x0403_8000, 0x04d8_8000],
        // LSL Z0.B, P0/M, Z0.B, #0.
        valid: 0x0403_8100,
        prefixes: &[MOVPRFX_Z0_Z1],
        vector_bytes: 16,
    },
    Family {
        reserved_reason: "reserved streaming width-conversion",
        // SSHLLB and SQXTNB with a reserved size.
        reserved: &[0x4500_a000, 0x4520_4000],
        // SSHLLB Z0.H, Z1.B, #0.
        valid: 0x4508_a020,
        prefixes: &[MOVPRFX_Z0_Z1],
        vector_bytes: 16,
    },
];

fn refusal(input: &[u32], bytes: usize, streaming: bool) -> String {
    crate::testing::context_leaf(
        &words(input),
        GuestAddress(0),
        profile(bytes, streaming),
        TargetCpu::Baseline,
    )
    .unwrap_err()
    .to_string()
}

#[test]
fn streaming_families_refuse_reserved_non_streaming_and_prefixed_inputs() {
    for family in FAMILIES {
        let bytes = family.vector_bytes;
        for &word in family.reserved {
            let reason = refusal(&[NOP, word, RET_X30], bytes, true);
            assert!(
                reason.contains(family.reserved_reason),
                "{word:#x}: {reason}"
            );
        }
        for bytes in [16, 32, 64, 128, 256] {
            let reason = refusal(&[family.valid, RET_X30], bytes, false);
            assert!(reason.contains("streaming mode required"), "{reason}");
        }
        for &prefix in family.prefixes {
            let reason = refusal(&[prefix, family.valid, RET_X30], bytes, true);
            assert!(reason.contains("MOVPRFX pair validation"), "{reason}");
        }
        assert!(
            crate::testing::leaf(&words(&[family.valid, RET_X30]), GuestAddress(0)).is_err(),
            "{:#x}",
            family.valid
        );
    }
}
