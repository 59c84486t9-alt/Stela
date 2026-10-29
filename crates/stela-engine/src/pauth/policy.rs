//! PAC bit layouts. The process profile is VA47 with instruction TBI off and
//! data TBI on; a translation regime can select others (Arm ARM `AddPAC` and
//! `Auth`: the bottom PAC bit is 64 - TnSZ of the half that bit 55, or bit 63
//! without TBI, selects; the top bit is 55 with TBI and 63 without).
const ADDRESS_BITS: u32 = 47;
#[cfg(test)]
const ADDRESS_MASK: u64 = (1 << ADDRESS_BITS) - 1;
const REGION_SHIFT: u32 = 55;
const REGION_BIT: u64 = 1 << REGION_SHIFT;
const DATA_TOP_SHIFT: u32 = 55;
const INSTRUCTION_TOP_SHIFT: u32 = 63;
const POISON_FIELD_MASK: u64 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Classic,
    Enhanced,
    Faulting,
    FaultingCombined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    Instruction,
    Data,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    A,
    B,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authentication {
    pub pointer: u64,
    pub authenticated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    /// Architectural PAC failure syndrome low two bits (data::key_number).
    pub code: u8,
}

/// Where the PAC field sits in one pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// The bottom PAC bit: 64 - TnSZ.
    pub address_bits: u32,
    /// 55 when the top byte is ignored, 63 otherwise.
    pub top_shift: u32,
}

impl Layout {
    pub(super) const fn extension_mask(self) -> u64 {
        let below_top = if self.top_shift == 63 {
            u64::MAX
        } else {
            (1 << (self.top_shift + 1)) - 1
        };
        below_top & !((1 << self.address_bits) - 1)
    }
    const fn pac_mask(self) -> u64 {
        self.extension_mask() & !REGION_BIT
    }
    const fn poison_shift(self) -> u32 {
        self.top_shift - 2
    }
}

impl Domain {
    /// The process profile's fixed layout.
    pub const fn layout(self) -> Layout {
        Layout {
            address_bits: ADDRESS_BITS,
            top_shift: match self {
                Self::Instruction => INSTRUCTION_TOP_SHIFT,
                Self::Data => DATA_TOP_SHIFT,
            },
        }
    }
    #[cfg(test)]
    const fn extension_mask(self) -> u64 {
        self.layout().extension_mask()
    }
    #[cfg(test)]
    const fn pac_mask(self) -> u64 {
        self.layout().pac_mask()
    }
}

pub fn signing_input(layout: Layout, pointer: u64) -> u64 {
    let extension = if pointer & (1 << layout.top_shift) != 0 {
        layout.extension_mask()
    } else {
        0
    };
    (pointer & !layout.extension_mask()) | extension
}

pub fn authentication_input(layout: Layout, pointer: u64) -> u64 {
    (pointer & !layout.extension_mask())
        | if pointer & REGION_BIT != 0 {
            layout.extension_mask()
        } else {
            0
        }
}

/// `pac` is ComputePAC(signing_input(layout,pointer),modifier,key).
pub fn sign(version: Version, layout: Layout, pointer: u64, mut pac: u64) -> u64 {
    let extension = signing_input(layout, pointer) & layout.extension_mask();
    if version == Version::Classic {
        let field = pointer & layout.extension_mask();
        if field != 0 && field != layout.extension_mask() {
            pac ^= 1 << (layout.top_shift - 1);
        }
        (pointer & !layout.extension_mask()) | (extension & REGION_BIT) | (pac & layout.pac_mask())
    } else {
        ((pointer ^ (pac & layout.pac_mask())) & !REGION_BIT) | (extension & REGION_BIT)
    }
}

/// `pac` is ComputePAC(authentication_input(layout,pointer),modifier,key).
/// FPAC faults standalone AUT; FPACCOMBINE additionally faults LDRA and transfers.
pub fn authenticate(
    version: Version,
    domain: Domain,
    layout: Layout,
    side: Side,
    combined: bool,
    pointer: u64,
    pac: u64,
) -> Result<Authentication, Failure> {
    let original = authentication_input(layout, pointer);
    if version == Version::Classic {
        let authenticated = (pac ^ pointer) & layout.pac_mask() == 0;
        let poison = match side {
            Side::A => 1,
            Side::B => 2,
        };
        let shift = layout.poison_shift();
        return Ok(Authentication {
            pointer: if authenticated {
                original
            } else {
                (original & !(POISON_FIELD_MASK << shift)) | (poison << shift)
            },
            authenticated,
        });
    }
    let pointer = pointer ^ (pac & layout.pac_mask());
    let authenticated = (pointer ^ original) & layout.extension_mask() == 0;
    let faulting =
        version == Version::FaultingCombined || (version == Version::Faulting && !combined);
    if faulting && !authenticated {
        return Err(Failure {
            code: (u8::from(domain == Domain::Data) << 1) | u8::from(side == Side::B),
        });
    }
    Ok(Authentication {
        pointer,
        authenticated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regime_layouts_follow_tnsz_and_tbi() {
        // A 39-bit TTBR1 kernel pointer without TBI: PAC in bits 63:56 and 54:39.
        let kernel = Layout {
            address_bits: 39,
            top_shift: 63,
        };
        assert_eq!(kernel.pac_mask(), 0xff7f_ff80_0000_0000);
        assert_eq!(kernel.poison_shift(), 61);
        let pointer = 0xffff_ff80_1234_5678_u64;
        let signed = sign(Version::Classic, kernel, pointer, 0x0123_4567_89ab_cdef);
        assert_eq!(signed & !kernel.pac_mask(), pointer & !kernel.pac_mask());
        assert_eq!(
            authenticate(
                Version::Classic,
                Domain::Instruction,
                kernel,
                Side::A,
                false,
                signed,
                0x0123_4567_89ab_cdef
            )
            .unwrap(),
            Authentication {
                pointer,
                authenticated: true
            }
        );
        // TBI keeps the top byte and moves the poison to bits 54:53.
        let tagged = Layout {
            address_bits: 39,
            top_shift: 55,
        };
        assert_eq!(tagged.pac_mask(), 0x007f_ff80_0000_0000);
        assert_eq!(tagged.poison_shift(), 53);
        assert_eq!(Domain::Data.layout().pac_mask(), 0x007f_8000_0000_0000);
    }

    #[test]
    fn enhanced_sign_xors_existing_noncanonical_fields_without_corrupting_pac() {
        for domain in [Domain::Instruction, Domain::Data] {
            for pointer in [0, ADDRESS_MASK, u64::MAX, REGION_BIT, 1 << ADDRESS_BITS] {
                let pac = 0x1234_5678_9abc_def0;
                let signed = sign(Version::Enhanced, domain.layout(), pointer, pac);
                assert_eq!(
                    signed & !domain.extension_mask(),
                    pointer & !domain.extension_mask()
                );
                assert_eq!(
                    signed & domain.pac_mask(),
                    (pointer ^ pac) & domain.pac_mask()
                );
                assert_eq!(
                    signed & REGION_BIT,
                    signing_input(domain.layout(), pointer) & REGION_BIT
                );
            }
        }
    }

    #[test]
    fn canonical_roundtrips_and_failure_policies_are_distinct() {
        for domain in [Domain::Instruction, Domain::Data] {
            for side in [Side::A, Side::B] {
                for canonical in [0x1234, !0xfu64] {
                    for version in [
                        Version::Classic,
                        Version::Enhanced,
                        Version::Faulting,
                        Version::FaultingCombined,
                    ] {
                        let pac = 0x5a5a_a5a5_1234_9876;
                        let signed = sign(version, domain.layout(), canonical, pac);
                        assert_eq!(
                            authenticate(version, domain, domain.layout(), side, true, signed, pac),
                            Ok(Authentication {
                                pointer: canonical,
                                authenticated: true
                            })
                        );
                        for bit in ADDRESS_BITS..u64::BITS {
                            if domain.pac_mask() & (1 << bit) == 0 {
                                continue;
                            }
                            for combined in [false, true] {
                                let result = authenticate(
                                    version,
                                    domain,
                                    domain.layout(),
                                    side,
                                    combined,
                                    signed ^ (1 << bit),
                                    pac,
                                );
                                let faulting = version == Version::FaultingCombined
                                    || (version == Version::Faulting && !combined);
                                if faulting {
                                    assert_eq!(
                                        result,
                                        Err(Failure {
                                            code: (u8::from(domain == Domain::Data) << 1)
                                                | u8::from(side == Side::B)
                                        })
                                    );
                                } else {
                                    assert!(!result.unwrap().authenticated);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
