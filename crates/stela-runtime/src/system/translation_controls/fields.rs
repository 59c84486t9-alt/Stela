//! Storage and readback of the translation-control fields.
//!
//! Reserved bits keep their last written value wherever the architecture allows
//! that choice, so a readback never implies an active feature.

use super::Register;

const fn bits(msb: u32, lsb: u32) -> u64 {
    (u64::MAX >> (63 - msb)) & (u64::MAX << lsb)
}

// SCTLR.SA, for the scalar data-control consumer.
pub(super) const SCTLR_SA_MASK: u64 = sctlr::SA;

pub(super) mod sctlr {
    use super::bits;
    pub const M: u64 = 1 << 0;
    pub const A: u64 = 1 << 1;
    pub const C: u64 = 1 << 2;
    pub const SA: u64 = 1 << 3;
    pub const SA0: u64 = 1 << 4;
    pub const CP15BEN: u64 = 1 << 5;
    pub const NAA: u64 = 1 << 6;
    pub const ITD: u64 = 1 << 7;
    pub const SED: u64 = 1 << 8;
    pub const UMA: u64 = 1 << 9;
    pub const EN_RCTX: u64 = 1 << 10;
    pub const EOS: u64 = 1 << 11;
    pub const I: u64 = 1 << 12;
    pub const EN_DB: u64 = 1 << 13;
    pub const DZE: u64 = 1 << 14;
    pub const UCT: u64 = 1 << 15;
    pub const NTWI: u64 = 1 << 16;
    pub const RESERVED_17: u64 = 1 << 17;
    pub const NTWE: u64 = 1 << 18;
    pub const WXN: u64 = 1 << 19;
    pub const TSCXT: u64 = 1 << 20;
    pub const IESB: u64 = 1 << 21;
    pub const EIS: u64 = 1 << 22;
    pub const SPAN: u64 = 1 << 23;
    pub const E0E: u64 = 1 << 24;
    pub const EE: u64 = 1 << 25;
    pub const UCI: u64 = 1 << 26;
    pub const EN_DA: u64 = 1 << 27;
    pub const NTLSMD: u64 = 1 << 28;
    pub const LSMAOE: u64 = 1 << 29;
    pub const EN_IB: u64 = 1 << 30;
    pub const EN_IA: u64 = 1 << 31;
    pub const CMOW: u64 = 1 << 32;
    pub const MSC_EN: u64 = 1 << 33;
    pub const EN_FPM: u64 = 1 << 34;
    pub const BT0: u64 = 1 << 35;
    pub const BT1: u64 = 1 << 36;
    pub const ITFSB: u64 = 1 << 37;
    pub const TCF0: u64 = bits(39, 38);
    pub const TCF: u64 = bits(41, 40);
    pub const ATA0: u64 = 1 << 42;
    pub const ATA: u64 = 1 << 43;
    pub const DSSBS: u64 = 1 << 44;
    pub const TWED_EN: u64 = 1 << 45;
    pub const TWEDEL: u64 = bits(49, 46);
    pub const RESERVED_53_50: u64 = bits(53, 50);
    pub const EN_ASR: u64 = 1 << 54;
    pub const EN_AS0: u64 = 1 << 55;
    pub const EN_ALS: u64 = 1 << 56;
    pub const EPAN: u64 = 1 << 57;
    pub const TCSO0: u64 = 1 << 58;
    pub const TCSO: u64 = 1 << 59;
    pub const EN_TP2: u64 = 1 << 60;
    pub const NMI: u64 = 1 << 61;
    pub const SPINTMASK: u64 = 1 << 62;
    pub const TIDCP: u64 = 1 << 63;

    pub const CORE: u64 = M | A | C | SA | SA0 | UMA | I | DZE | UCT | NTWI | NTWE | WXN | UCI;
    pub const PAUTH: u64 = EN_DB | EN_DA | EN_IB | EN_IA;
    pub const PAN: u64 = SPAN | EPAN;
    pub const EXS: u64 = EOS | EIS;
    pub const ENDIAN: u64 = E0E | EE;
    pub const ALWAYS_RESERVED: u64 = RESERVED_17 | RESERVED_53_50;
    pub const ABSENT_OTHER: u64 = CP15BEN
        | NAA
        | ITD
        | SED
        | EN_RCTX
        | TSCXT
        | IESB
        | NTLSMD
        | LSMAOE
        | CMOW
        | MSC_EN
        | EN_FPM
        | BT0
        | BT1
        | ITFSB
        | TCF0
        | TCF
        | ATA0
        | ATA
        | TWED_EN
        | TWEDEL
        | EN_ASR
        | EN_AS0
        | EN_ALS
        | TCSO0
        | TCSO
        | EN_TP2
        | NMI
        | SPINTMASK
        | TIDCP;
}

pub(super) mod tcr {
    use super::bits;
    pub const T0SZ: u64 = bits(5, 0);
    pub const RESERVED_6: u64 = 1 << 6;
    pub const EPD0: u64 = 1 << 7;
    pub const IRGN0: u64 = bits(9, 8);
    pub const ORGN0: u64 = bits(11, 10);
    pub const SH0: u64 = bits(13, 12);
    pub const TG0: u64 = bits(15, 14);
    pub const T1SZ: u64 = bits(21, 16);
    pub const A1: u64 = 1 << 22;
    pub const EPD1: u64 = 1 << 23;
    pub const IRGN1: u64 = bits(25, 24);
    pub const ORGN1: u64 = bits(27, 26);
    pub const SH1: u64 = bits(29, 28);
    pub const TG1: u64 = bits(31, 30);
    pub const IPS: u64 = bits(34, 32);
    pub const RESERVED_35: u64 = 1 << 35;
    pub const AS: u64 = 1 << 36;
    pub const TBI0: u64 = 1 << 37;
    pub const TBI1: u64 = 1 << 38;
    pub const HA: u64 = 1 << 39;
    pub const HD: u64 = 1 << 40;
    pub const HPD0: u64 = 1 << 41;
    pub const HPD1: u64 = 1 << 42;
    pub const HWU059: u64 = 1 << 43;
    pub const HWU060: u64 = 1 << 44;
    pub const HWU061: u64 = 1 << 45;
    pub const HWU062: u64 = 1 << 46;
    pub const HWU159: u64 = 1 << 47;
    pub const HWU160: u64 = 1 << 48;
    pub const HWU161: u64 = 1 << 49;
    pub const HWU162: u64 = 1 << 50;
    pub const TBID0: u64 = 1 << 51;
    pub const TBID1: u64 = 1 << 52;
    pub const NFD0: u64 = 1 << 53;
    pub const NFD1: u64 = 1 << 54;
    pub const E0PD0: u64 = 1 << 55;
    pub const E0PD1: u64 = 1 << 56;
    pub const TCMA0: u64 = 1 << 57;
    pub const TCMA1: u64 = 1 << 58;
    pub const DS: u64 = 1 << 59;
    pub const MTX0: u64 = 1 << 60;
    pub const MTX1: u64 = 1 << 61;
    pub const RESERVED_63_62: u64 = bits(63, 62);
    pub const CORE: u64 = T0SZ
        | EPD0
        | IRGN0
        | ORGN0
        | SH0
        | TG0
        | T1SZ
        | A1
        | EPD1
        | IRGN1
        | ORGN1
        | SH1
        | TG1
        | IPS
        | TBI0
        | TBI1;
    pub const PAUTH: u64 = TBID0 | TBID1;
    pub const ALWAYS_RESERVED: u64 = RESERVED_6 | RESERVED_35 | RESERVED_63_62;
    pub const ABSENT_OTHER: u64 = HA
        | HD
        | HPD0
        | HPD1
        | HWU059
        | HWU060
        | HWU061
        | HWU062
        | HWU159
        | HWU160
        | HWU161
        | HWU162
        | NFD0
        | NFD1
        | E0PD0
        | E0PD1
        | TCMA0
        | TCMA1
        | DS
        | MTX0
        | MTX1;
}

mod ttbr {
    use super::bits;
    // Both TTBR pages, fieldset 1 (D128 absent). Root alignment is checked at
    // access time; this is not a mask of ignored low bits.
    pub const CNP: u64 = 1;
    pub const BADDR: u64 = bits(47, 1);
    pub const ASID_LOW: u64 = bits(55, 48);
    pub const ASID_HIGH: u64 = bits(63, 56);
}

mod mair {
    // AArch64-mair_el1.xml fieldset_0-63_0, Attr<n> at [8*n+7:8*n].
    pub const ATTR: [u64; 8] = [
        0xff,
        0xff00,
        0xff0000,
        0xff000000,
        0xff00000000,
        0xff0000000000,
        0xff000000000000,
        0xff00000000000000,
    ];
    pub const ALL: u64 =
        ATTR[0] | ATTR[1] | ATTR[2] | ATTR[3] | ATTR[4] | ATTR[5] | ATTR[6] | ATTR[7];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    Absent,
    Present,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PanFeatures {
    Absent,
    Pan3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsidBits {
    Eight,
    Sixteen,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endianness {
    LittleOnly,
    MixedEl0El1,
}

/// Facts from the CPU implementation, never derived from an MSR value. This
/// profile requires AArch64-only EL0/EL1, no EL2 or EL3, at most 48-bit PA and
/// no FEAT_PAuth_EnhCtl; the optional features are below. Every other
/// conditional feature on these register pages is absent: TIDCP1, NMI, SME, the
/// MTE and LS64 families, TWED, BTI, FPMR, MOPS, CMOW, LSMAOC, IESB,
/// CSV2_2/CSV2_1p2, SPECRES, LSE2, AA32EL0, LPA2, D128, E0PD, SVE, HPDS/HPDS2,
/// HAF/HAFDBS, TTCNP and any TCR2 extension affecting these controls. PAN3
/// means FEAT_PAN and FEAT_PAN3; Absent means neither. Other combinations need
/// another profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BaseEl1FeatureFacts {
    pub pauth: Presence,
    pub pan: PanFeatures,
    pub ssbs: Presence,
    pub exs: Presence,
    pub asid_bits: AsidBits,
    pub endianness: Endianness,
}

/// The source and owner ledger binding. Non-empty metadata is checked for
/// structure only; the machine owner authenticates the ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceBinding {
    pub id: &'static str,
    pub sha256: [u8; 32],
}

impl EvidenceBinding {
    fn valid(self) -> bool {
        !self.id.trim().is_empty() && self.sha256.iter().any(|byte| *byte != 0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyProvenance {
    pub cpu_features: EvidenceBinding,
    pub implementation_choices: EvidenceBinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldError {
    MissingPolicyProvenance,
    IncoherentCpuProfile(&'static str),
    NonExhaustiveOrOverlappingClassification,
    InconsistentStorageClassification,
    InvalidInitialReadback { register: Register, bits: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Masks {
    read_stored: u64,
    read_zero: u64,
    read_one: u64,
    write_stored: u64,
    write_ignored: u64,
    effect_readback: u64,
    effect_zero: u64,
    effect_one: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RegisterPolicy {
    register: Register,
    masks: Masks,
    facts: BaseEl1FeatureFacts,
    provenance: PolicyProvenance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AppliedWrite {
    pub readback: u64,
    /// Feature-filtered consumer input, not a complete effective MMU context.
    pub effective: u64,
}

fn partition(masks: &[u64]) -> bool {
    let mut seen = 0;
    for mask in masks {
        if seen & mask != 0 {
            return false;
        }
        seen |= mask;
    }
    seen == u64::MAX
}

impl RegisterPolicy {
    /// Choose writable reserved bits with preserved readback where permitted.
    /// TCR granule readback returns the programmed value; consumers still
    /// implement the effective fallback.
    pub(super) fn base_el1(
        register: Register,
        facts: BaseEl1FeatureFacts,
        provenance: PolicyProvenance,
    ) -> Result<Self, FieldError> {
        let (effect_readback, effect_zero, effect_one) = match register {
            Register::SctlrEl1 => {
                let pauth = if facts.pauth == Presence::Present {
                    sctlr::PAUTH
                } else {
                    0
                };
                let pan = if facts.pan == PanFeatures::Pan3 {
                    sctlr::PAN
                } else {
                    0
                };
                let ssbs = if facts.ssbs == Presence::Present {
                    sctlr::DSSBS
                } else {
                    0
                };
                let exs = if facts.exs == Presence::Present {
                    sctlr::EXS
                } else {
                    0
                };
                let endian = if facts.endianness == Endianness::MixedEl0El1 {
                    sctlr::ENDIAN
                } else {
                    0
                };
                let one = sctlr::EXS & !exs;
                let active = sctlr::CORE | pauth | pan | ssbs | exs | endian;
                let zero = sctlr::ALWAYS_RESERVED
                    | sctlr::ABSENT_OTHER
                    | (sctlr::PAUTH & !pauth)
                    | (sctlr::PAN & !pan)
                    | (sctlr::DSSBS & !ssbs)
                    | (sctlr::ENDIAN & !endian);
                (active, zero, one)
            }
            Register::TcrEl1 => {
                let pauth = if facts.pauth == Presence::Present {
                    tcr::PAUTH
                } else {
                    0
                };
                let asid = if facts.asid_bits == AsidBits::Sixteen {
                    tcr::AS
                } else {
                    0
                };
                (
                    tcr::CORE | pauth | asid,
                    tcr::ALWAYS_RESERVED
                        | tcr::ABSENT_OTHER
                        | (tcr::PAUTH & !pauth)
                        | (tcr::AS & !asid),
                    0,
                )
            }
            Register::Ttbr0El1 | Register::Ttbr1El1 => {
                let high = if facts.asid_bits == AsidBits::Sixteen {
                    ttbr::ASID_HIGH
                } else {
                    0
                };
                (
                    ttbr::BADDR | ttbr::ASID_LOW | high,
                    ttbr::CNP | (ttbr::ASID_HIGH & !high),
                    0,
                )
            }
            Register::MairEl1 => (mair::ALL, 0, 0),
        };
        Self::checked(
            register,
            facts,
            provenance,
            Masks {
                read_stored: u64::MAX,
                read_zero: 0,
                read_one: 0,
                write_stored: u64::MAX,
                write_ignored: 0,
                effect_readback,
                effect_zero,
                effect_one,
            },
        )
    }

    // Arbitrary classifiers stay private: provenance strings do not authorize
    // callers to turn unsupported architectural features into ignored writes.
    fn checked(
        register: Register,
        facts: BaseEl1FeatureFacts,
        provenance: PolicyProvenance,
        masks: Masks,
    ) -> Result<Self, FieldError> {
        if !provenance.cpu_features.valid() || !provenance.implementation_choices.valid() {
            return Err(FieldError::MissingPolicyProvenance);
        }
        if !partition(&[masks.read_stored, masks.read_zero, masks.read_one])
            || !partition(&[masks.write_stored, masks.write_ignored])
            || !partition(&[masks.effect_readback, masks.effect_zero, masks.effect_one])
        {
            return Err(FieldError::NonExhaustiveOrOverlappingClassification);
        }
        if masks.write_stored & !masks.read_stored != 0 {
            return Err(FieldError::InconsistentStorageClassification);
        }
        Ok(Self {
            register,
            masks,
            facts,
            provenance,
        })
    }

    pub(super) fn validate_initial(&self, readback: u64) -> Result<(), FieldError> {
        let invalid = (readback & self.masks.read_zero) | (!readback & self.masks.read_one);
        if invalid != 0 {
            return Err(FieldError::InvalidInitialReadback {
                register: self.register,
                bits: invalid,
            });
        }
        Ok(())
    }

    /// Apply a write to the fields. `old` is the owner's validated readback.
    pub(super) fn apply(&self, old: u64, operand: u64) -> Result<AppliedWrite, FieldError> {
        self.validate_initial(old)?;
        let stored = (old & !self.masks.write_stored) | (operand & self.masks.write_stored);
        let readback = (stored & self.masks.read_stored) | self.masks.read_one;
        Ok(AppliedWrite {
            readback,
            effective: self.effective(readback),
        })
    }

    pub(super) fn effective(&self, readback: u64) -> u64 {
        (readback & self.masks.effect_readback) | self.masks.effect_one
    }
}

#[cfg(test)]
mod tests {
    //! Translation-control field storage.

    use super::*;

    fn facts() -> BaseEl1FeatureFacts {
        BaseEl1FeatureFacts {
            pauth: Presence::Absent,
            pan: PanFeatures::Absent,
            ssbs: Presence::Absent,
            exs: Presence::Absent,
            asid_bits: AsidBits::Eight,
            endianness: Endianness::LittleOnly,
        }
    }

    fn provenance() -> PolicyProvenance {
        PolicyProvenance {
            cpu_features: EvidenceBinding {
                id: "synthetic test CPU facts",
                sha256: [1; 32],
            },
            implementation_choices: EvidenceBinding {
                id: "synthetic test policy choices",
                sha256: [2; 32],
            },
        }
    }

    fn policy(register: Register) -> RegisterPolicy {
        RegisterPolicy::base_el1(register, facts(), provenance()).unwrap()
    }

    #[test]
    fn selected_profiles_partition_every_bit_for_every_feature_combination() {
        let registers = [
            Register::SctlrEl1,
            Register::TcrEl1,
            Register::Ttbr0El1,
            Register::Ttbr1El1,
            Register::MairEl1,
        ];
        for selected in 0_u8..64 {
            let present = |bit| {
                if selected & (1u8 << bit) == 0u8 {
                    Presence::Absent
                } else {
                    Presence::Present
                }
            };
            let facts = BaseEl1FeatureFacts {
                pauth: present(0),
                pan: if selected & 2 == 0 {
                    PanFeatures::Absent
                } else {
                    PanFeatures::Pan3
                },
                ssbs: present(2),
                exs: present(3),
                asid_bits: if selected & 16 == 0 {
                    AsidBits::Eight
                } else {
                    AsidBits::Sixteen
                },
                endianness: if selected & 32 == 0 {
                    Endianness::LittleOnly
                } else {
                    Endianness::MixedEl0El1
                },
            };
            for register in registers {
                let policy = RegisterPolicy::base_el1(register, facts, provenance()).unwrap();
                assert_eq!(policy.facts, facts);
                assert_eq!(policy.provenance, provenance());
                assert_eq!(policy.masks.read_stored, u64::MAX);
                assert_eq!(policy.masks.write_stored, u64::MAX);
                for operand in [0, u64::MAX, 0x1200_1000_fc14_793d, 0x0008_0022_6511_a511] {
                    let result = policy.apply(!operand, operand).unwrap();
                    assert_eq!(result.readback, operand);
                    assert_eq!(result.effective & policy.masks.effect_zero, 0);
                    assert_eq!(
                        result.effective & policy.masks.effect_one,
                        policy.masks.effect_one
                    );
                }
            }
        }
    }

    #[test]
    fn inactive_reserved_fields_store_legal_writes_without_fabricating_active_features() {
        let sctlr = policy(Register::SctlrEl1);
        let operand = sctlr::EN_TP2
            | sctlr::EPAN
            | sctlr::DSSBS
            | sctlr::PAUTH
            | sctlr::ALWAYS_RESERVED
            | sctlr::EE
            | sctlr::E0E;
        let result = sctlr.apply(0, operand).unwrap();
        assert_eq!(result.readback, operand);
        assert_eq!(result.effective, sctlr::EOS | sctlr::EIS);

        let tcr = policy(Register::TcrEl1);
        let operand = tcr::TBID0 | tcr::TBID1 | tcr::AS | tcr::DS | tcr::ALWAYS_RESERVED;
        assert_eq!(
            tcr.apply(0, operand).unwrap(),
            AppliedWrite {
                readback: operand,
                effective: 0
            }
        );
    }

    #[test]
    fn optional_active_controls_are_retained_for_their_real_consumers() {
        let facts = BaseEl1FeatureFacts {
            pauth: Presence::Present,
            pan: PanFeatures::Pan3,
            ssbs: Presence::Present,
            exs: Presence::Present,
            asid_bits: AsidBits::Sixteen,
            endianness: Endianness::MixedEl0El1,
        };
        let sctlr = RegisterPolicy::base_el1(Register::SctlrEl1, facts, provenance()).unwrap();
        let operand = sctlr::PAUTH | sctlr::PAN | sctlr::DSSBS | sctlr::EXS | sctlr::ENDIAN;
        assert_eq!(
            sctlr.apply(0, operand).unwrap(),
            AppliedWrite {
                readback: operand,
                effective: operand
            }
        );
        assert_eq!(sctlr.apply(operand, 0).unwrap().effective, 0);
        let tcr = RegisterPolicy::base_el1(Register::TcrEl1, facts, provenance()).unwrap();
        let operand = tcr::PAUTH | tcr::AS;
        assert_eq!(tcr.apply(0, operand).unwrap().effective, operand);
    }

    #[test]
    fn absent_exs_retains_readback_but_supplies_implicit_exception_synchronization_controls() {
        let policy = policy(Register::SctlrEl1);
        assert_eq!(policy.apply(0, 0).unwrap().readback, 0);
        assert_eq!(policy.effective(0) & sctlr::EXS, sctlr::EXS);
        assert_eq!(policy.apply(0, sctlr::EXS).unwrap().readback, sctlr::EXS);
    }

    #[test]
    fn ttbr_keeps_low_root_bits_and_separates_readback_from_asid_and_cnp_effects() {
        for register in [Register::Ttbr0El1, Register::Ttbr1El1] {
            let policy = policy(register);
            let operand = ttbr::ASID_HIGH | ttbr::ASID_LOW | 0x3fff;
            let result = policy.apply(0, operand).unwrap();
            assert_eq!(result.readback, operand);
            assert_eq!(result.effective, ttbr::ASID_LOW | 0x3ffe);
            assert_eq!(result.effective & ttbr::ASID_HIGH, 0);
            assert_eq!(result.effective & ttbr::CNP, 0);
        }
    }

    #[test]
    fn sixteen_bit_asid_input_retains_upper_byte_for_canonical_tcr_as_selection() {
        let facts = BaseEl1FeatureFacts {
            asid_bits: AsidBits::Sixteen,
            ..facts()
        };
        let policy = RegisterPolicy::base_el1(Register::Ttbr1El1, facts, provenance()).unwrap();
        assert_eq!(
            policy.apply(0, ttbr::ASID_HIGH).unwrap().effective,
            ttbr::ASID_HIGH
        );
    }

    #[test]
    fn tcr_keeps_intermediate_and_reserved_granule_encodings_for_canonical_access_policy() {
        let policy = policy(Register::TcrEl1);
        // TG0=0b11 is reserved. TG1=0b00 is reserved. This layer stores the
        // selected programmed-value readback; it supplies no fallback granule.
        let operand = tcr::TG0 | tcr::IPS | tcr::T0SZ | tcr::T1SZ;
        assert_eq!(
            policy.apply(0, operand).unwrap(),
            AppliedWrite {
                readback: operand,
                effective: operand
            }
        );
    }

    #[test]
    fn mair_preserves_every_attribute_without_admitting_its_memory_semantics() {
        let policy = policy(Register::MairEl1);
        let operand = 0x0c08_04ff_00bb_44ff;
        assert_eq!(
            policy.apply(0, operand).unwrap(),
            AppliedWrite {
                readback: operand,
                effective: operand
            }
        );
        for (index, mask) in mair::ATTR.into_iter().enumerate() {
            assert_eq!(mask, 0xff_u64 << (index * 8));
        }
    }

    #[test]
    fn provenance_must_be_explicit_and_structurally_complete() {
        let mut proof = provenance();
        proof.cpu_features.id = "  ";
        assert_eq!(
            RegisterPolicy::base_el1(Register::SctlrEl1, facts(), proof),
            Err(FieldError::MissingPolicyProvenance)
        );
        let mut proof = provenance();
        proof.implementation_choices.sha256 = [0; 32];
        assert_eq!(
            RegisterPolicy::base_el1(Register::SctlrEl1, facts(), proof),
            Err(FieldError::MissingPolicyProvenance)
        );
    }

    #[test]
    fn private_mechanism_rejects_incomplete_overlapping_or_inconsistent_classes() {
        let good = policy(Register::SctlrEl1);
        let mut masks = good.masks;
        masks.effect_zero &= !sctlr::EN_TP2;
        assert_eq!(
            RegisterPolicy::checked(Register::SctlrEl1, facts(), provenance(), masks),
            Err(FieldError::NonExhaustiveOrOverlappingClassification)
        );
        let mut masks = good.masks;
        masks.effect_zero |= sctlr::M;
        assert_eq!(
            RegisterPolicy::checked(Register::SctlrEl1, facts(), provenance(), masks),
            Err(FieldError::NonExhaustiveOrOverlappingClassification)
        );
        let mut masks = good.masks;
        masks.read_stored &= !sctlr::M;
        masks.read_zero |= sctlr::M;
        assert_eq!(
            RegisterPolicy::checked(Register::SctlrEl1, facts(), provenance(), masks),
            Err(FieldError::InconsistentStorageClassification)
        );
    }

    #[test]
    fn private_constant_readback_policy_validates_initial_state_and_ignores_only_selected_bits() {
        let mut masks = policy(Register::SctlrEl1).masks;
        masks.read_stored &= !(sctlr::M | sctlr::C);
        masks.read_zero = sctlr::M;
        masks.read_one = sctlr::C;
        masks.write_stored &= !(sctlr::M | sctlr::C);
        masks.write_ignored = sctlr::M | sctlr::C;
        let policy =
            RegisterPolicy::checked(Register::SctlrEl1, facts(), provenance(), masks).unwrap();
        assert_eq!(
            policy.validate_initial(sctlr::M),
            Err(FieldError::InvalidInitialReadback {
                register: Register::SctlrEl1,
                bits: sctlr::M | sctlr::C,
            })
        );
        assert!(policy.apply(sctlr::M, 0).is_err());
        let result = policy.apply(sctlr::C, sctlr::M | sctlr::A).unwrap();
        assert_eq!(result.readback, sctlr::C | sctlr::A);
    }
}
