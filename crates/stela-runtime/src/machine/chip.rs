//! The Apple CPU a machine models. Each chip's architectural features are
//! Apple clang's export for it (`isa/apple-codegen-profiles.json`), closed
//! under the AARCHMRS implications by `cargo xtask system-matrix`; the
//! generated accessors decide a feature only some chips have through
//! [`Chip::implemented`], and [`Chip::admit`] makes an instruction form the
//! chip lacks UNDEFINED (or a NOP, where Arm decodes it so).
use super::system::generated::{CAPS, CHIPS, Feature};
use alloc::{vec, vec::Vec};

#[rustfmt::skip]
mod forms;
#[rustfmt::skip]
mod checks;

/// An access check a form's Execute pseudocode makes (Arm
/// `AArch64_CheckFPEnabled`, `AArch64_CheckFPAdvSIMDEnabled`,
/// `CheckSVEEnabled`, `CheckNonStreamingSVEEnabled`,
/// `CheckStreamingSVEEnabled`, `CheckStreamingSVEAndZAEnabled`,
/// `CheckSMEEnabled`, `CheckSMEAndZAEnabled`, `CheckSMEZT0Enabled` and
/// `CheckFPMREnabled`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    Fp,
    FpAdvSimd,
    Sve,
    NonStreamingSve,
    StreamingSve,
    StreamingSveAndZa,
    Sme,
    SmeAndZa,
    SmeZt0,
    Fpmr,
}

/// The words a check variant covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WordClass {
    Any,
    /// imm5 (`checks::IMM5`) has one bit set, or not: SMOV's and UMOV's
    /// `index == 0`.
    SingleImm5(bool),
}

struct CheckVariant {
    /// Bit `n` set for chip `n`.
    chips: u8,
    class: WordClass,
    checks: &'static [Check],
}

struct CheckForm {
    value: u32,
    variants: &'static [CheckVariant],
}

/// The forms of one encoding mask, sorted by value.
struct CheckGroup {
    mask: u32,
    forms: &'static [CheckForm],
}

/// One A64 form some chips lack (`forms::ABSENT`).
struct AbsentForm {
    value: u32,
    /// Bit `n` set when chip `n` lacks the form.
    chips: u8,
    /// Arm decodes the form as NOP, not UNDEFINED, without its feature.
    nop: bool,
    /// (mask, value, chips): forms those chips have that keep their words.
    unless: &'static [(u32, u32, u8)],
}

/// The absent forms of one encoding mask, sorted by value.
struct AbsentGroup {
    mask: u32,
    forms: &'static [AbsentForm],
}

/// `UDF #0`: an absent form's word is UNDEFINED as UDF is (EC 0x00, ISS 0).
const UDF: u32 = 0;
const NOP: u32 = 0xd503_201f;

/// Whether `word` is in one of the A64 top-level groups Arm leaves
/// unallocated, op1 (bits 28:25) 0b0001 or 0b0011 (Arm ARM DDI 0487 C4.1),
/// which execute as UNDEFINED. The op0 0, op1 0b0000 reserved group is not
/// among them: Apple's GXF and AMX instructions are encoded there.
fn unallocated_group(word: u32) -> bool {
    matches!((word >> 25) & 0xf, 0b0001 | 0b0011)
}

/// A chip's absent-form groups indexed by bits 31:21 of the word, in
/// [`forms::ABSENT`] order, so that [`AdmitTable::admit`] searches only the
/// groups whose forms share a word's prefix; most prefixes have none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmitTable {
    chip: Chip,
    /// The range of `groups` for each prefix, and its end.
    starts: Vec<u32>,
    groups: Vec<u16>,
}

impl AdmitTable {
    const SHIFT: u32 = 21;
    const PREFIXES: usize = 1 << (32 - Self::SHIFT);

    /// [`Chip::admit`] of the table's chip.
    pub fn admit(&self, word: u32) -> u32 {
        if unallocated_group(word) {
            return UDF;
        }
        let prefix = (word >> Self::SHIFT) as usize;
        let groups = &self.groups[self.starts[prefix] as usize..self.starts[prefix + 1] as usize];
        self.chip.admit_in(
            word,
            groups
                .iter()
                .map(|&group| &forms::ABSENT[usize::from(group)]),
        )
    }
}

/// An Apple CPU, in the order of the generated per-chip tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Chip {
    AppleM1,
    AppleM2,
    AppleM3,
    AppleM4,
    AppleM5,
    AppleM6,
}

impl Chip {
    pub const ALL: [Chip; 6] = [
        Chip::AppleM1,
        Chip::AppleM2,
        Chip::AppleM3,
        Chip::AppleM4,
        Chip::AppleM5,
        Chip::AppleM6,
    ];

    /// The Mac14,3 (J473AP) M2 Mac mini's chip.
    pub const DEFAULT: Chip = Chip::AppleM2;

    /// Apple clang's `-mcpu` name.
    pub const fn name(self) -> &'static str {
        CHIPS[self as usize]
    }

    /// Apple clang's architectural features for the chip
    /// (`isa/apple-codegen-profiles.json`), the cap of what it advertises.
    pub fn cap(self) -> &'static [&'static str] {
        CAPS[self as usize]
    }

    /// The chip's [`AdmitTable`].
    pub fn admit_table(self) -> AdmitTable {
        const PREFIX: u32 = AdmitTable::PREFIXES as u32 - 1;
        let bit = 1u8 << self as u8;
        let mut by_prefix = vec![Vec::new(); AdmitTable::PREFIXES];
        for (index, group) in forms::ABSENT.iter().enumerate() {
            let index = u16::try_from(index).expect("fewer than 65536 absent-form groups");
            // Every prefix that agrees with a form on the group's mask.
            let free = !(group.mask >> AdmitTable::SHIFT) & PREFIX;
            for form in group.forms.iter().filter(|form| form.chips & bit != 0) {
                let fixed = form.value >> AdmitTable::SHIFT & !free;
                let mut varying = free;
                loop {
                    let groups: &mut Vec<u16> = &mut by_prefix[(fixed | varying) as usize];
                    if groups.last() != Some(&index) {
                        groups.push(index);
                    }
                    if varying == 0 {
                        break;
                    }
                    varying = (varying - 1) & free;
                }
            }
        }
        let mut starts = Vec::with_capacity(AdmitTable::PREFIXES + 1);
        let mut groups = Vec::new();
        for prefix in by_prefix {
            starts.push(groups.len() as u32);
            groups.extend(prefix);
        }
        starts.push(groups.len() as u32);
        AdmitTable {
            chip: self,
            starts,
            groups,
        }
    }

    /// The word the chip executes for `word`: the word itself, `UDF #0` for a
    /// form the chip lacks or a word in an unallocated top-level group, or NOP
    /// for an absent form Arm decodes as NOP.
    pub fn admit(self, word: u32) -> u32 {
        if unallocated_group(word) {
            return UDF;
        }
        self.admit_in(word, forms::ABSENT.iter())
    }

    /// The first of `groups` holding a form this chip lacks that `word` is.
    fn admit_in<'a>(self, word: u32, groups: impl Iterator<Item = &'a AbsentGroup>) -> u32 {
        let bit = 1u8 << self as u8;
        for group in groups {
            let Ok(index) = group
                .forms
                .binary_search_by_key(&(word & group.mask), |form| form.value)
            else {
                continue;
            };
            let form = &group.forms[index];
            let kept = form
                .unless
                .iter()
                .any(|(mask, value, chips)| chips & bit != 0 && word & mask == *value);
            if form.chips & bit != 0 && !kept {
                return if form.nop { NOP } else { UDF };
            }
        }
        word
    }

    /// The access checks `word` makes on this chip, in order; none for a
    /// word no checked form claims. The most specific encoding wins, as in
    /// Arm's decode tables.
    pub fn checks(self, word: u32) -> &'static [Check] {
        let bit = 1u8 << self as u8;
        for group in checks::CHECKS {
            let Ok(index) = group
                .forms
                .binary_search_by_key(&(word & group.mask), |form| form.value)
            else {
                continue;
            };
            let single = ((word & checks::IMM5) >> checks::IMM5.trailing_zeros()).count_ones() == 1;
            return group.forms[index]
                .variants
                .iter()
                .find(|variant| {
                    variant.chips & bit != 0
                        && match variant.class {
                            WordClass::Any => true,
                            WordClass::SingleImm5(wanted) => wanted == single,
                        }
                })
                .map_or(&[], |variant| variant.checks);
        }
        &[]
    }

    /// The (mask, value) of every form with a variant on this chip, and that
    /// variant's checks, for tests covering classes of forms.
    #[cfg(test)]
    pub fn check_forms(self) -> Vec<(u32, u32, &'static [Check])> {
        let bit = 1u8 << self as u8;
        checks::CHECKS
            .iter()
            .flat_map(|group| {
                group.forms.iter().flat_map(move |form| {
                    form.variants
                        .iter()
                        .filter(move |variant| variant.chips & bit != 0)
                        .map(move |variant| (group.mask, form.value, variant.checks))
                })
            })
            .collect()
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|chip| chip.name() == name)
    }

    /// Whether the chip has `feature`: `Ok(false)` without it, `Ok(true)`
    /// when the engine implements it, and the reason to stop when the chip
    /// has a feature the engine does not implement yet.
    pub fn implemented(self, feature: Feature) -> Result<bool, &'static str> {
        if !feature.on(self) {
            Ok(false)
        } else if engine_implements(feature) {
            Ok(true)
        } else {
            Err(feature.unimplemented())
        }
    }
}

/// The chip the runtime's unit tests build their default CPUs and machines
/// for: `STELA_TEST_CHIP`, or [`Chip::DEFAULT`]. Each call appends the
/// running test's name to the file `STELA_TEST_CHIP_LOG` names, so that
/// `cargo xtask progress`, which runs the tests once per chip, credits a test
/// on a chip only when it ran there. A test that fixes its chip does not
/// call it.
#[cfg(test)]
pub fn test_chip() -> Chip {
    extern crate std;
    use std::io::Write;
    let chip = std::env::var("STELA_TEST_CHIP").map_or(Chip::DEFAULT, |name| {
        Chip::from_name(&name).unwrap_or_else(|| panic!("STELA_TEST_CHIP {name} names no chip"))
    });
    if let (Ok(log), Some(test)) = (
        std::env::var("STELA_TEST_CHIP_LOG"),
        std::thread::current().name(),
    ) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .unwrap_or_else(|error| panic!("STELA_TEST_CHIP_LOG {log}: {error}"));
        // One write per line, so the parallel tests' appends never interleave.
        file.write_all(alloc::format!("{test}\n").as_bytes())
            .unwrap_or_else(|error| panic!("STELA_TEST_CHIP_LOG {log}: {error}"));
    }
    chip
}

/// Whether the engine implements a feature that only some chips have: every
/// feature the M2 has; the M3's FEAT_HCX, FEAT_NV and FEAT_NV2; the M4's
/// Armv8.7 (FEAT_AFP, FEAT_PAN3, FEAT_WFxT and FEAT_XS), the activity
/// monitors FEAT_AMUv1 and FEAT_AMUv1p1 (`machine::amu`) and FEAT_SME with
/// FEAT_SME2, FEAT_SME_F64F64 and FEAT_SME_I16I64, whose streaming mode, ZA,
/// ZT0 and instructions the engine runs (`engine::scalable`); the M5's
/// FEAT_SME2p1, FEAT_SME_B16B16, FEAT_SME_F16F16 and FEAT_SVE_B16B16 too,
/// FEAT_SPECRES2, FEAT_MTE and FEAT_MTE2 (Allocation Tags and synchronous
/// Tag Checks) and the instruction-only FEAT_CSSC and FEAT_HBC; and the M6's
/// FEAT_SME_LUTv2, FEAT_FPACCOMBINE, FEAT_FP8 with FEAT_FPMR (the AdvSIMD
/// FP8 conversions), FEAT_CPA (whose arithmetic the engine completes),
/// FEAT_PAuth_LR with FEAT_SCTLR2 (PACM and the two-modifier PAC forms),
/// FEAT_RASv2 with FEAT_FGT2 (the error record group status and its trap) and
/// the instruction-only FEAT_FAMINMAX and FEAT_LUT, whose forms the
/// system-mode compiler admits.
const fn engine_implements(feature: Feature) -> bool {
    match feature {
        Feature::FEAT_AMUv1p1
        | Feature::FEAT_BF16
        | Feature::FEAT_ECV
        | Feature::FEAT_FGT
        | Feature::FEAT_FPAC
        | Feature::FEAT_I8MM
        | Feature::FEAT_PAuth2
        | Feature::FEAT_SSBS
        | Feature::FEAT_SSBS2
        | Feature::v8Ap6
        | Feature::v8Ap7
        | Feature::FEAT_NV
        | Feature::FEAT_NV2
        | Feature::FEAT_HCX
        | Feature::FEAT_AFP
        | Feature::FEAT_CPA
        | Feature::FEAT_CSSC
        | Feature::FEAT_FAMINMAX
        | Feature::FEAT_HBC
        | Feature::FEAT_FPACCOMBINE
        | Feature::FEAT_LUT
        | Feature::FEAT_PAN3
        | Feature::FEAT_PAuth_LR
        | Feature::FEAT_SCTLR2
        | Feature::FEAT_FGT2
        | Feature::FEAT_RASv2
        | Feature::FEAT_SPECRES2
        | Feature::FEAT_WFxT
        | Feature::FEAT_XS
        | Feature::FEAT_SME
        | Feature::FEAT_SME2
        | Feature::FEAT_AMUv1
        | Feature::FEAT_FP8
        | Feature::FEAT_FPMR
        | Feature::FEAT_MTE
        | Feature::FEAT_MTE2
        | Feature::FEAT_SME2p1
        | Feature::FEAT_SME_B16B16
        | Feature::FEAT_SME_F16F16
        | Feature::FEAT_SME_F64F64
        | Feature::FEAT_SME_I16I64
        | Feature::FEAT_SME_LUTv2
        | Feature::FEAT_SVE_B16B16 => true,
        Feature::FEAT_SME_F8F16 | Feature::FEAT_SME_F8F32 => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn the_admit_table_answers_as_the_full_search() {
        for chip in Chip::ALL {
            let table = chip.admit_table();
            for group in forms::ABSENT {
                for form in group.forms {
                    for word in [form.value, form.value | !group.mask] {
                        assert_eq!(table.admit(word), chip.admit(word), "{chip:?} {word:#x}");
                    }
                }
            }
            // A deterministic spread of words, and the unallocated groups.
            let mut word = 0x2545_f491_u32;
            for _ in 0..20_000 {
                word ^= word << 13;
                word ^= word >> 17;
                word ^= word << 5;
                assert_eq!(table.admit(word), chip.admit(word), "{chip:?} {word:#x}");
            }
            assert_eq!(table.admit(0xe7ff_deff), UDF);
            assert_eq!(table.admit(0xf940_0020), 0xf940_0020); // ldr x0, [x1]
        }
    }

    #[test]
    fn chips_follow_the_generated_tables_and_the_m2_implements_all_it_has() {
        for (index, chip) in Chip::ALL.into_iter().enumerate() {
            assert_eq!(chip as usize, index);
            assert_eq!(Chip::from_name(chip.name()), Some(chip));
        }
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../isa/apple-codegen-profiles.json");
        let profiles: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        for chip in Chip::ALL {
            let cap: Vec<&str> = profiles["profiles"][chip.name()]["architectural_features"]
                .as_array()
                .unwrap()
                .iter()
                .map(|feature| feature.as_str().unwrap())
                .collect();
            assert_eq!(chip.cap(), cap, "{chip:?}");
        }
        // The default chip implements every feature it has, as before any
        // other chip was modeled; a later chip's addition stops explicitly.
        for feature in Feature::ALL {
            assert_ne!(
                Chip::DEFAULT.implemented(feature),
                Err(feature.unimplemented())
            );
        }
        assert_eq!(Chip::AppleM2.implemented(Feature::FEAT_HCX), Ok(false));
        assert_eq!(Chip::AppleM3.implemented(Feature::FEAT_HCX), Ok(true));
        assert_eq!(Chip::AppleM4.implemented(Feature::FEAT_SME), Ok(true));
        assert_eq!(Chip::AppleM4.implemented(Feature::FEAT_MTE2), Ok(false));
        assert_eq!(Chip::AppleM5.implemented(Feature::FEAT_MTE2), Ok(true));
        assert_eq!(Chip::AppleM1.implemented(Feature::FEAT_FGT), Ok(false));
    }

    #[test]
    fn each_form_makes_its_pseudocodes_access_checks() {
        use Check::*;
        // clang-assembled words.
        for (word, checks) in [
            (0x4ea2_8420, &[FpAdvSimd][..]),     // add v0.4s, v1.4s, v2.4s
            (0x1e22_2820, &[Fp]),                // fadd s0, s1, s2
            (0x0e01_2c20, &[Fp]),                // smov w0, v1.b[0]: index 0
            (0x0e03_2c20, &[FpAdvSimd]),         // smov w0, v1.b[1]
            (0x0e04_3c20, &[Fp]),                // umov w0, v1.s[0]
            (0x5e22_dc20, &[Fp]),                // fmulx s0, s1, s2: one element
            (0x4e22_dc20, &[FpAdvSimd]),         // fmulx v0.4s, v1.4s, v2.4s
            (0x3dc0_0020, &[Fp]),                // ldr q0, [x1]
            (0x8081_2000, &[StreamingSveAndZa]), // fmopa za0.s, ...
            (0xe100_0000, &[SmeAndZa]),          // ldr za[w12, 0], [x0]
            (0xe11f_8000, &[Sme, SmeZt0]),       // ldr zt0, [x0]
            (0x04bf_5820, &[Sme]),               // rdsvl x0, #1
            (0x0422_0020, &[Sve]),               // add z0.b, z1.b, z2.b
            (0xa400_a000, &[Sve]),               // ld1b {z0.b}, p0/z, [x0]
            (0x8b02_0020, &[]),                  // add x0, x1, x2
        ] {
            assert_eq!(Chip::AppleM4.checks(word), checks, "{word:#x}");
        }
        // pmullb z0.q, z1.d, z2.d: esize 128, and no Apple chip has
        // FEAT_SSVE_AES, so it is illegal in streaming mode.
        assert_eq!(Chip::AppleM4.checks(0x4502_6820), [NonStreamingSve]);
    }

    #[test]
    fn a_form_the_chip_lacks_is_undefined_or_its_nop() {
        // bfcvt h0, s1 (FEAT_BF16, from the M2) and abs x0, x1 (FEAT_CSSC,
        // from the M5).
        for (word, first) in [(0x1e63_4020, Chip::AppleM2), (0xdac0_2020, Chip::AppleM5)] {
            for chip in Chip::ALL {
                let expected = if chip < first { UDF } else { word };
                assert_eq!(chip.admit(word), expected, "{word:#x} {chip:?}");
            }
        }
        // PACM (FEAT_PAuth_LR, M6) is a NOP without its feature, as Arm
        // decodes it, though the HINT space it sits in is on every chip.
        assert_eq!(Chip::AppleM2.admit(0xd503_24ff), NOP);
        assert_eq!(Chip::AppleM6.admit(0xd503_24ff), 0xd503_24ff);
        // RETAASPPCR (FEAT_PAuth_LR) is UNDEFINED before the M6, except for
        // the RETAA encoding it overlaps.
        assert_eq!(Chip::AppleM2.admit(0xd65f_0be2), UDF);
        assert_eq!(Chip::AppleM2.admit(0xd65f_0bff), 0xd65f_0bff);
        // XNU's 0xe7ffdeff (op1 0b0011) and a word with op1 0b0001 are in
        // unallocated groups.
        for word in [0xe7ff_deff, 0x0200_0000] {
            for chip in Chip::ALL {
                assert_eq!(chip.admit(word), UDF, "{word:#x} {chip:?}");
            }
        }
        // Forms every chip has, and words no form claims, pass unchanged.
        for word in [0x8b02_0020, 0xd503_201f, 0xd503_3f9f, 0x0020_1420] {
            for chip in Chip::ALL {
                assert_eq!(chip.admit(word), word, "{word:#x} {chip:?}");
            }
        }
    }
}
