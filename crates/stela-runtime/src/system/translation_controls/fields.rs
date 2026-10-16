//! Storage and readback of the translation-control fields.
//!
//! Reserved bits keep their last written value wherever the architecture allows
//! that choice, so a readback never implies an active feature.

use super::Register;

const fn bits(msb: u32, lsb: u32) -> u64 {
    (u64::MAX >> (63 - msb)) & (u64::MAX << lsb)
}

// Narrow shared field identity for the original scalar data-control consumer.
pub(super) const SCTLR_SA_MASK: u64 = sctlr::SA;

mod sctlr {
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
    // Both TTBR pages, fieldset_1: D128 absent/disabled. Alignment is an access-
    // time canonical root decision. This is not an all-low-14-bits-ignore mask.
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

/// Facts supplied by the actual CPU/implementation owner, never derived from
/// an MSR literal. This named profile requires AArch64-only EL0/EL1, no EL2/EL3,
/// PA <= 48 bits and no FEAT_PAuth_EnhCtl. Optional selected features are below.
/// All other conditional features on these June pages are explicitly absent:
/// TIDCP1, NMI, SME, MTE families, LS64 families, TWED, BTI, FPMR, MOPS, CMOW,
/// LSMAOC, IESB, CSV2_2/CSV2_1p2, SPECRES, LSE2, AA32EL0, LPA2, D128, E0PD,
/// SVE, HPDS/HPDS2, HAF/HAFDBS, TTCNP and any TCR2 extension affecting controls.
/// PAN3 selects FEAT_PAN and FEAT_PAN3 together; Absent selects neither.
/// Unsupported actual feature combinations require another reviewed profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BaseEl1FeatureFacts {
    pub pauth: Presence,
    pub pan: PanFeatures,
    pub ssbs: Presence,
    pub exs: Presence,
    pub asid_bits: AsidBits,
    pub endianness: Endianness,
}

/// Immutable source/owner ledger binding. Nonempty metadata is only structural
/// validation: the composing machine owner must authenticate the actual ledger.
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
    /// Select the source-permitted writable-reserved/readback implementation.
    /// TCR granule readback selects the source-permitted programmed value;
    /// canonical consumers must still implement the selected effective fallback.
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

    /// Pure field application. `old` is the actual owner's validated readback;
    /// no bank, side effect, exception, or successful service is created here.
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
mod tests;
