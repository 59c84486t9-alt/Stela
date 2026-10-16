//! EOR3, BCAX, RAX1 and XAR.
const REGISTER_MASK: u32 = 31;
const DESTINATION_SHIFT: u32 = 0;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const THIRD_SHIFT: u32 = 10;
const XAR_ROTATION_SHIFT: u32 = 10;
const XAR_ROTATION_MASK: u32 = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Eor3 { third: u8 },
    Bcax { third: u8 },
    Rax1,
    Xar { rotation: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    pub left: u8,
    pub right: u8,
}

#[derive(Clone, Copy)]
enum Encoding {
    Eor3,
    Bcax,
    Rax1,
    Xar,
}

impl Encoding {
    const ALL: &'static [Self] = &[Self::Eor3, Self::Bcax, Self::Rax1, Self::Xar];

    fn facts(self) -> (u32, u32) {
        match self {
            Self::Eor3 => (0xffe08000, 0xce000000),
            Self::Bcax => (0xffe08000, 0xce200000),
            Self::Rax1 => (0xffe0fc00, 0xce608c00),
            Self::Xar => (0xffe00000, 0xce800000),
        }
    }

    fn kind(self, word: u32) -> Kind {
        let third = register(word, THIRD_SHIFT);
        match self {
            Self::Eor3 => Kind::Eor3 { third },
            Self::Bcax => Kind::Bcax { third },
            Self::Rax1 => Kind::Rax1,
            Self::Xar => Kind::Xar {
                rotation: ((word >> XAR_ROTATION_SHIFT) & XAR_ROTATION_MASK) as u8,
            },
        }
    }
}

/// Every register and immediate within the four exact fixed-bit masks is valid.
/// Same-named SVE forms remain another encoding class and receive no support here.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let encoding = Encoding::ALL.iter().copied().find(|encoding| {
        let (mask, value) = encoding.facts();
        word & mask == value
    })?;
    Some(Ok(Operand {
        kind: encoding.kind(word),
        destination: register(word, DESTINATION_SHIFT),
        left: register(word, LEFT_SHIFT),
        right: register(word, RIGHT_SHIFT),
    }))
}

fn register(word: u32, shift: u32) -> u8 {
    ((word >> shift) & REGISTER_MASK) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_register_role_preserves_v31_and_source_aliases() {
        for encoding in Encoding::ALL {
            let (_, base) = encoding.facts();
            for register in 0..32 {
                let word = base | register | (register << LEFT_SHIFT) | (register << RIGHT_SHIFT);
                let decoded = decode(word).unwrap().unwrap();
                assert_eq!(decoded.destination, register as u8);
                assert_eq!(decoded.left, register as u8);
                assert_eq!(decoded.right, register as u8);
            }
        }
        // Independently sweep all four fields, including third sources and V31.
        for base in [0xce000000, 0xce200000] {
            for destination in 0..32 {
                for source in 0..32 {
                    for (left, right, third) in [(source, 2, 3), (1, source, 3), (1, 2, source)] {
                        let operand = decode(
                            base | destination
                                | (left << LEFT_SHIFT)
                                | (right << RIGHT_SHIFT)
                                | (third << THIRD_SHIFT),
                        )
                        .unwrap()
                        .unwrap();
                        assert_eq!(operand.destination, destination as u8);
                        assert_eq!(operand.left, left as u8);
                        assert_eq!(operand.right, right as u8);
                        assert_eq!(
                            operand.kind,
                            if base == 0xce000000 {
                                Kind::Eor3 { third: third as u8 }
                            } else {
                                Kind::Bcax { third: third as u8 }
                            }
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn known_words_decode_distinct_operand_roles_and_fourth_field() {
        for (word, kind) in [
            (0xce020c20, Kind::Eor3 { third: 3 }),
            (0xce220c20, Kind::Bcax { third: 3 }),
            (0xce628c20, Kind::Rax1),
            (0xce82fc20, Kind::Xar { rotation: 63 }),
        ] {
            assert_eq!(
                decode(word),
                Some(Ok(Operand {
                    kind,
                    destination: 0,
                    left: 1,
                    right: 2
                }))
            );
        }
        for encoding in Encoding::ALL {
            let (_, base) = encoding.facts();
            for register in 0..32 {
                for (destination, left, right) in
                    [(register, 1, 2), (0, register, 2), (0, 1, register)]
                {
                    let operand =
                        decode(base | destination | (left << LEFT_SHIFT) | (right << RIGHT_SHIFT))
                            .unwrap()
                            .unwrap();
                    assert_eq!(
                        (operand.destination, operand.left, operand.right),
                        (destination as u8, left as u8, right as u8)
                    );
                }
            }
        }
    }

    #[test]
    fn xar_immediate_is_direct_zero_through_sixty_three() {
        for rotation in 0..64 {
            let operand = decode(
                0xce800000
                    | (rotation << XAR_ROTATION_SHIFT)
                    | (31 << RIGHT_SHIFT)
                    | (31 << LEFT_SHIFT)
                    | 31,
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                operand.kind,
                Kind::Xar {
                    rotation: rotation as u8
                }
            );
            assert_eq!(
                (operand.destination, operand.left, operand.right),
                (31, 31, 31)
            );
        }
    }

    #[test]
    fn fixed_bits_are_exact_and_sve_forms_are_not_classic_sha3() {
        for word in [0x04203800, 0x04603800, 0x4520f400, 0x04203400, 0xce600000] {
            assert!(decode(word).is_none(), "{word:08x}");
        }
        for encoding in Encoding::ALL {
            let (mask, base) = encoding.facts();
            for bit in 0..32 {
                if mask & (1 << bit) == 0 {
                    continue;
                }
                let changed = base ^ (1 << bit);
                let belongs_to_another_form = Encoding::ALL.iter().any(|other| {
                    let (other_mask, other_value) = other.facts();
                    changed & other_mask == other_value
                });
                assert_eq!(
                    decode(changed).is_some(),
                    belongs_to_another_form,
                    "{changed:08x}"
                );
            }
        }
    }
}
