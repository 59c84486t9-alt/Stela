//! Source descriptor references produce policy data, never arrival/completion.
//! Base1019d1c..34,101a0f8..11c,101a1a4..c4,101a3a8..40c;
//! AMCC100471c..4890, control1004d70..4eb0; AGX101dcf0..dd30;
//! ANE1018da0..de0. These are facts about native software, not GPU execution.
use crate::Result;
use alloc::vec::Vec;
use stela_contracts::refuse;

/// A semantic source24-byte counter reference; raw type/provider are held.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CounterReference {
    pub kind: u32,
    pub provider: u32,
    pub start: u32,
    pub width: u32,
    pub flags: u32,
    pub scale: u32,
}
impl CounterReference {
    pub(super) const fn local(start: u32, width: u32) -> Self {
        Self {
            kind: 2,
            provider: 0,
            start,
            width,
            flags: 0,
            scale: 0,
        }
    }
}
/// Source-derived P20/P28 desired bits. This value contains no pending update,
/// observation, counter generation, lifecycle or ACK permission.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CounterSelection {
    bits: u128,
    references: Vec<CounterReference>,
}
impl CounterSelection {
    pub fn bits(&self) -> u128 {
        self.bits
    }
    pub fn references(&self) -> &[CounterReference] {
        &self.references
    }
    pub(super) fn initialized(
        references: Vec<CounterReference>,
        freshness_arm: u8,
    ) -> Result<Self> {
        let mut result = Self {
            bits: u128::from(freshness_arm == 1),
            references,
        };
        for r in &result.references {
            if r.kind == 2 && r.provider == 0 {
                let entry = r.start >> 6;
                if entry >= 128 {
                    return Err(refuse!(
                        "native counter reference exceeds two source selection words"
                    ));
                }
                result.bits |= 1u128 << entry;
            }
        }
        Ok(result)
    }
    pub(super) fn replace(&mut self, bits: u128) {
        self.bits = bits;
    }
}

/// MC source control transforms desired bits and expected counter masks.
/// Expected is policy data, independent of an arrived frame or copied receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct McSelection {
    pub desired: u128,
    pub expected: u128,
    pub control: u32,
    pub frames: u32,
}
impl McSelection {
    /// Original10045c4 selects f3 when native control/override is nonzero,
    /// otherwise cfg470. This is not a public runstate or completion setter.
    pub fn control_word(control: u32, override_word: u32, configured: u32) -> u32 {
        if control != 0 || override_word != 0 {
            0xf3
        } else {
            configured
        }
    }
    pub(super) fn resolve(
        previous: u128,
        base_banks: u32,
        banks: u32,
        lanes: u32,
        control: u32,
        descriptors: &[CounterReference; 8],
    ) -> Result<Self> {
        let prefix = base_banks
            .checked_mul(8)
            .ok_or(refuse!("MC source prefix overflow"))?;
        if prefix > 128 || lanes == 0 {
            return Err(refuse!("MC source selection geometry exceeds native words"));
        }
        let frames = banks
            .checked_sub(base_banks)
            .and_then(|x| x.checked_mul(lanes))
            .ok_or(refuse!("MC source bank geometry is inconsistent"))?;
        let stride = 8 / lanes; // Original W32 UDIV; do not round.
        let mut desired = if prefix == 128 {
            previous
        } else {
            previous & ((1u128 << prefix) - 1)
        };
        for frame in 0..frames {
            let bit_base = prefix
                .wrapping_add(stride.wrapping_mul(frame))
                .wrapping_mul(64);
            for (index, r) in descriptors.iter().enumerate() {
                if control & (1 << index) == 0 || r.width == 0 || r.kind != 2 || r.provider != 0 {
                    continue;
                }
                let bit = bit_base.wrapping_add(r.start) >> 6;
                if bit >= 128 {
                    return Err(refuse!(
                        "MC source control reference exceeds selection words"
                    ));
                }
                desired |= 1u128 << bit;
            }
        }
        let expected = if prefix >= 128 { 0 } else { desired >> prefix };
        Ok(Self {
            desired,
            expected,
            control,
            frames,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    #[test]
    fn initialization_uses_local_entry_references_not_width_or_all_ones() {
        let refs = vec![
            CounterReference::local(32, 32),
            CounterReference::local(64, 32),
            CounterReference {
                provider: 1,
                ..CounterReference::local(200, 32)
            },
            CounterReference {
                kind: 3,
                ..CounterReference::local(300, 32)
            },
        ];
        let x = CounterSelection::initialized(refs, 0).unwrap();
        assert_eq!(x.bits(), 3);
        assert_eq!(x.references().len(), 4);
        assert_eq!(
            CounterSelection::initialized(Vec::new(), 1).unwrap().bits(),
            1
        );
        assert!(CounterSelection::initialized(vec![CounterReference::local(8192, 1)], 0).is_err());
    }
    #[test]
    fn mc_source_control_preserves_prefix_and_computes_expected_without_arrival() {
        let refs = core::array::from_fn(|i| CounterReference::local(i as u32 * 32, 32));
        let x = McSelection::resolve(u128::MAX, 2, 14, 2, 3, &refs).unwrap();
        assert_eq!(x.frames, 24);
        assert_eq!(x.desired & 0xffff, 0xffff);
        assert_eq!(
            x.expected,
            (0..24).fold(0u128, |x, i| x | (1u128 << (4 * i)))
        );
        let y = McSelection::resolve(x.desired, 2, 14, 2, 0xf3, &refs).unwrap();
        assert_eq!(y.expected & 15, 13);
        assert_eq!(McSelection::control_word(0, 0, 3), 3);
        assert_eq!(McSelection::control_word(0, 1, 3), 0xf3);
        assert!(McSelection::resolve(0, 2, 1, 2, 3, &refs).is_err());
    }
}

#[cfg(all(test, feature = "std"))]
mod original_tests {
    #[test]
    #[ignore = "oracle: STELA_TEST_PMP_T8112"]
    fn original_t8112_platform_control_and_evaluation_operands_match_native_contract() {
        use sha2::{Digest, Sha256};
        let pmp = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&pmp)),
            "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
        );
        let word = |va: usize| {
            u32::from_le_bytes(pmp[va - 0xfff000..va - 0xfff000 + 4].try_into().unwrap())
        };
        for (va, offset, base, value, scale) in [
            (0x100f884, 0x5a8, 20, 8, 8),
            (0x100f88c, 0x808, 20, 9, 8),
            (0x100f894, 0x5b8, 20, 10, 8),
            (0x1011404, 0x298, 24, 23, 4),
            (0x1011554, 0, 19, 8, 8),
            (0x1011574, 8, 19, 8, 8),
            (0x1011588, 16, 19, 8, 8),
        ] {
            let opcode = word(va);
            assert_eq!((opcode >> 5) & 31, base);
            assert_eq!(opcode & 31, value);
            assert_eq!(((opcode >> 10) & 4095) * scale, offset);
        }
        for va in [0x100f8ac, 0x100f8c8] {
            let op = word(va);
            assert_eq!(op >> 26, 0x25);
            let imm = ((op << 6) as i32 >> 6) as i64;
            assert_eq!(va as i64 + imm * 4, 0x1011160);
        }
        assert_eq!(word(0x101c548), 0xf9000109); //full64 enable store
        assert_eq!(word(0x101c65c), 0xf900011f); //full64 disable store
        assert_eq!(word(0x10113bc), 0x52801e09); //F0 observer mask
        assert_eq!(word(0x1011600), 0x4b080088); //W32 elapsed subtraction
        assert_eq!(word(0x1011604), 0x11006129); //W32 threshold+24
        assert_eq!(word(0x1046ab8 + 0x278), 2); //AMCC prefix banks
        assert_eq!(word(0x1046ab8 + 0x470), 3); //MC default selector
        assert_eq!(word(0x1034380), 8);
        assert_eq!(word(0x1034384), 2); //source defaults, not observations
    }
}
