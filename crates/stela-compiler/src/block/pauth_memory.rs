//! Generic-key PAC and authenticated data-load decoding.
//! Profile controls and process key material belong to the runtime.
use serde::Serialize;

const REGISTER_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 5;
const MODIFIER_SHIFT: u32 = 16;
const PACGA_MASK: u32 = 0xffe0_fc00;
const PACGA: u32 = 0x9ac0_3000;
const LOAD_MASK: u32 = 0xff20_0400;
const LOAD: u32 = 0xf820_0400;
const LOAD_KEY_B: u32 = 1 << 23;
const LOAD_WRITEBACK: u32 = 1 << 11;
const LOAD_SIGN: u32 = 1 << 22;
const LOAD_IMMEDIATE_SHIFT: u32 = 12;
const LOAD_IMMEDIATE_MASK: u32 = 0x1ff;
const LOAD_SIGN_VALUE: i32 = 1 << 9;
const LOAD_SCALE: u32 = 3;
const MIN_LOAD_DISPLACEMENT: i32 = -LOAD_SIGN_VALUE << LOAD_SCALE;
const MAX_LOAD_DISPLACEMENT: i32 = (LOAD_SIGN_VALUE - 1) << LOAD_SCALE;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GenericCode {
    pub destination: u8,
    pub source: u8,
    /// Register31 selects SP here; source31 selects XZR.
    pub modifier: u8,
}

impl GenericCode {
    pub const fn is_valid(self) -> bool {
        self.destination <= REGISTER_MASK as u8
            && self.source <= REGISTER_MASK as u8
            && self.modifier <= REGISTER_MASK as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DataKey {
    A,
    B,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Load {
    pub key: DataKey,
    pub destination: u8,
    /// Register31 selects SP; destination31 selects XZR.
    pub base: u8,
    pub displacement: i32,
    pub writeback: bool,
}

impl Load {
    pub const fn is_valid(self) -> bool {
        self.destination <= REGISTER_MASK as u8
            && self.base <= REGISTER_MASK as u8
            && self.displacement >= MIN_LOAD_DISPLACEMENT
            && self.displacement <= MAX_LOAD_DISPLACEMENT
            && self.displacement % (1 << LOAD_SCALE) == 0
    }

    /// The declared implementation chooses the permitted UNDEF constraint.
    pub const fn undefined_overlap(self) -> bool {
        self.writeback && self.base == self.destination && self.base != REGISTER_MASK as u8
    }

    pub const fn canonical_id(self) -> &'static str {
        match (self.key, self.writeback) {
            (DataKey::A, false) => "LDRAA_64_ldst_pac",
            (DataKey::A, true) => "LDRAA_64W_ldst_pac",
            (DataKey::B, false) => "LDRAB_64_ldst_pac",
            (DataKey::B, true) => "LDRAB_64W_ldst_pac",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Instruction {
    GenericCode(GenericCode),
    Load(Load),
}

pub fn decode(word: u32) -> Option<Instruction> {
    let destination = (word & REGISTER_MASK) as u8;
    let source = ((word >> SOURCE_SHIFT) & REGISTER_MASK) as u8;
    if word & PACGA_MASK == PACGA {
        return Some(Instruction::GenericCode(GenericCode {
            destination,
            source,
            modifier: ((word >> MODIFIER_SHIFT) & REGISTER_MASK) as u8,
        }));
    }
    if word & LOAD_MASK != LOAD {
        return None;
    }
    let immediate = ((word >> LOAD_IMMEDIATE_SHIFT) & LOAD_IMMEDIATE_MASK) as i32;
    let signed = immediate
        - if word & LOAD_SIGN != 0 {
            LOAD_SIGN_VALUE
        } else {
            0
        };
    Some(Instruction::Load(Load {
        key: if word & LOAD_KEY_B == 0 {
            DataKey::A
        } else {
            DataKey::B
        },
        destination,
        base: source,
        displacement: signed << LOAD_SCALE,
        writeback: word & LOAD_WRITEBACK != 0,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_code_preserves_all_register_roles() {
        for destination in 0..=REGISTER_MASK {
            for source in 0..=REGISTER_MASK {
                for modifier in 0..=REGISTER_MASK {
                    let word = PACGA
                        | destination
                        | (source << SOURCE_SHIFT)
                        | (modifier << MODIFIER_SHIFT);
                    assert_eq!(
                        decode(word),
                        Some(Instruction::GenericCode(GenericCode {
                            destination: destination as u8,
                            source: source as u8,
                            modifier: modifier as u8,
                        }))
                    );
                }
            }
        }
    }

    #[test]
    fn loads_cover_complete_offsets_keys_writeback_and_register_roles() {
        for key in [0, LOAD_KEY_B] {
            for writeback in [0, LOAD_WRITEBACK] {
                for immediate in 0..(LOAD_SIGN_VALUE as u32 * 2) {
                    let offset = (immediate as i32
                        - if immediate < LOAD_SIGN_VALUE as u32 {
                            0
                        } else {
                            LOAD_SIGN_VALUE * 2
                        })
                        * (1 << LOAD_SCALE);
                    let fields = ((immediate & LOAD_IMMEDIATE_MASK) << LOAD_IMMEDIATE_SHIFT)
                        | if immediate & LOAD_SIGN_VALUE as u32 == 0 {
                            0
                        } else {
                            LOAD_SIGN
                        };
                    for (base, destination) in [(0, 1), (1, 1), (30, 31), (31, 0), (31, 31)] {
                        let word =
                            LOAD | key | writeback | fields | (base << SOURCE_SHIFT) | destination;
                        let Some(Instruction::Load(load)) = decode(word) else {
                            panic!("load declined")
                        };
                        assert_eq!(load.displacement, offset);
                        assert_eq!(load.base, base as u8);
                        assert_eq!(load.destination, destination as u8);
                        assert_eq!(load.key, if key == 0 { DataKey::A } else { DataKey::B });
                        assert_eq!(load.writeback, writeback != 0);
                        assert_eq!(
                            load.undefined_overlap(),
                            writeback != 0 && base == destination && base != REGISTER_MASK
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn reserved_fixed_neighbors_decline() {
        for fixed in 0..u32::BITS {
            let bit = 1 << fixed;
            for (mask, opcode) in [(PACGA_MASK, PACGA), (LOAD_MASK, LOAD)] {
                if mask & bit != 0 {
                    assert_eq!(decode(opcode ^ bit), None);
                }
            }
        }
    }
}
