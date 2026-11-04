//! The Apple CPU a machine models. Each chip's architectural features are
//! Apple clang's export for it, closed under the AARCHMRS implications; the
//! generated accessors decide a feature only some chips have through
//! [`Chip::implemented`], and [`Chip::admit`] makes an instruction form the
//! chip lacks UNDEFINED (or a NOP, where Arm decodes it so), as
//! [`Chip::admit_table`] does for a PE whose identification withholds
//! features its chip has.
use crate::Refusal;
use crate::cpu_features::{CAPS, CHIPS, Feature};
use crate::refuse;
use alloc::{vec, vec::Vec};

#[rustfmt::skip]
mod forms;
#[rustfmt::skip]
mod checks;
mod check_index;

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
    /// The chip-varying features the form requires, in disjunctive normal
    /// form over [`Feature`] bits: met when a PE presents every feature of
    /// one term. A chip that has the form has what it requires. A condition
    /// on an encoding field counts as met (the checklist does not place the
    /// field); [`Chip::admit_table`] refuses a PE for which that admits
    /// words needing a withheld feature (`forms::FIELD_CONDITIONED`).
    requires: &'static [u64],
    /// (mask, value, chips, requires): forms those chips have that keep
    /// their words where the PE presents what they require.
    unless: &'static [(u32, u32, u8, &'static [u64])],
}

/// Whether `presented` features meet a form's `requires`.
fn met(requires: &[u64], presented: u64) -> bool {
    requires.iter().any(|term| term & !presented == 0)
}

/// The absent forms of one encoding mask, sorted by value.
struct AbsentGroup {
    mask: u32,
    forms: &'static [AbsentForm],
}

/// The slice of one mask's sorted forms that contains its absent
/// candidates for one instruction prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AdmitRange {
    group: u16,
    first: u16,
    end: u16,
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

/// The absent-form groups of a chip whose PE withholds some of its features,
/// indexed by bits 31:21 of the word, in [`forms::ABSENT`] order, so that
/// [`AdmitTable::admit`] searches only the groups whose forms share a word's
/// prefix; most prefixes have none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmitTable {
    chip: Chip,
    /// The [`Feature`] bits the PE's identification withholds.
    withheld: u64,
    /// The chip's features without them.
    presented: u64,
    /// One packed start and end in `groups` per prefix. Zero preserves the
    /// word, and `UNALLOCATED` returns UDF without searching any groups.
    spans: Vec<u32>,
    groups: Vec<AdmitRange>,
}

impl AdmitTable {
    const SHIFT: u32 = 21;
    const PREFIXES: usize = 1 << (32 - Self::SHIFT);
    const UNALLOCATED: u32 = u32::MAX;

    /// The immutable chip policy used to construct this table.
    pub fn chip(&self) -> Chip {
        self.chip
    }

    /// [`Chip::admit`] of the table's chip, where the forms of the features
    /// its PE withholds are absent too.
    pub fn admit(&self, word: u32) -> u32 {
        let prefix = (word >> Self::SHIFT) as usize;
        let span = match self.spans[prefix] {
            0 => return word,
            Self::UNALLOCATED => return UDF,
            span => span,
        };
        let start = (span & u32::from(u16::MAX)) as usize;
        let end = (span >> u16::BITS) as usize;
        self.chip.admit_in(
            word,
            self.presented,
            self.groups[start..end].iter().map(|range| {
                let group = &forms::ABSENT[usize::from(range.group)];
                let forms = &group.forms[usize::from(range.first)..usize::from(range.end)];
                (group.mask, forms)
            }),
        )
    }

    /// The [`Feature`] bits the table's PE withholds.
    pub fn withheld(&self) -> u64 {
        self.withheld
    }
}

/// An Apple CPU, in the order of the generated per-chip tables.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Chip {
    /// T8103, T6000 to T6002.
    AppleM1,
    /// T8112, T6020 to T6022.
    AppleM2,
    /// T8122, T6030 to T6034.
    AppleM3,
    /// T8132, T6040, T6041, and the A18 Pro's T8140, whose Apple clang
    /// `-mcpu=apple-a18` export is the M4's (`machine::soc` gives the rest).
    AppleM4,
    /// T8142 and the T6050 (M5 Pro, Max and Ultra), which XNU builds alike.
    AppleM5,
    /// T8152.
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

    /// Apple clang's architectural features for the chip, the cap of what it
    /// advertises.
    pub fn cap(self) -> &'static [&'static str] {
        CAPS[self as usize]
    }

    /// The chip's [`Feature`] bits.
    pub fn features(self) -> u64 {
        Feature::ALL
            .into_iter()
            .filter(|feature| feature.on(self))
            .fold(0, |bits, feature| bits | 1 << feature as u64)
    }

    /// The [`AdmitTable`] of a PE of the chip whose identification withholds
    /// the `withheld` [`Feature`] bits (`identification::withheld`), or why
    /// there is none: the PE presents what some forms' words need for one
    /// value of an encoding field the table does not place, but withholds
    /// what they need for the others (an SME2 PE without FEAT_SME_I16I64).
    pub fn admit_table(self, withheld: u64) -> Result<AdmitTable, Refusal> {
        const PREFIX: u32 = AdmitTable::PREFIXES as u32 - 1;
        let bit = 1u8 << self as u8;
        let presented = self.features() & !withheld;
        if forms::FIELD_CONDITIONED
            .iter()
            .any(|(requires, strict)| met(requires, presented) && !met(strict, presented))
        {
            return Err(refuse!(
                "the identification withholds a feature only some encodings of a \
                        form it presents need, which the admit table cannot tell apart"
            ));
        }
        let mut by_prefix = vec![Vec::new(); AdmitTable::PREFIXES];
        for (index, group) in forms::ABSENT.iter().enumerate() {
            let index = u16::try_from(index).expect("fewer than 65536 absent-form groups");
            // Every prefix that agrees with a form on the group's mask.
            let free = !(group.mask >> AdmitTable::SHIFT) & PREFIX;
            let absent =
                |form: &AbsentForm| form.chips & bit != 0 || !met(form.requires, presented);
            for (position, form) in group
                .forms
                .iter()
                .enumerate()
                .filter(|(_, form)| absent(form))
            {
                let end = u16::try_from(position + 1).expect("form ranges fit in u16");
                let fixed = form.value >> AdmitTable::SHIFT & !free;
                let mut varying = free;
                loop {
                    let groups: &mut Vec<AdmitRange> = &mut by_prefix[(fixed | varying) as usize];
                    if let Some(last) = groups.last_mut()
                        && last.group == index
                    {
                        // The slice can include present forms between its
                        // first and last absent candidates.
                        last.end = end;
                    } else {
                        groups.push(AdmitRange {
                            group: index,
                            first: end - 1,
                            end,
                        });
                    }
                    if varying == 0 {
                        break;
                    }
                    varying = (varying - 1) & free;
                }
            }
        }
        let mut spans = Vec::with_capacity(AdmitTable::PREFIXES);
        let mut groups = Vec::new();
        for (prefix, matches) in by_prefix.into_iter().enumerate() {
            let span = if unallocated_group((prefix as u32) << AdmitTable::SHIFT) {
                AdmitTable::UNALLOCATED
            } else if matches.is_empty() {
                0
            } else {
                let start = groups.len() as u32;
                groups.extend(matches);
                let end = u16::try_from(groups.len()).expect("absent-form group spans fit in u16");
                start | (u32::from(end) << u16::BITS)
            };
            spans.push(span);
        }
        Ok(AdmitTable {
            chip: self,
            withheld,
            presented,
            spans,
            groups,
        })
    }

    /// The word the chip executes for `word`: the word itself, `UDF #0` for a
    /// form the chip lacks or a word in an unallocated top-level group, or NOP
    /// for an absent form Arm decodes as NOP.
    pub fn admit(self, word: u32) -> u32 {
        if unallocated_group(word) {
            return UDF;
        }
        self.admit_in(
            word,
            self.features(),
            forms::ABSENT.iter().map(|group| (group.mask, group.forms)),
        )
    }

    /// The first of `groups` holding a form that `word` is and that this
    /// chip lacks, or that a PE presenting the `presented` features does.
    fn admit_in<'a>(
        self,
        word: u32,
        presented: u64,
        groups: impl Iterator<Item = (u32, &'a [AbsentForm])>,
    ) -> u32 {
        let bit = 1u8 << self as u8;
        for (mask, forms) in groups {
            let Ok(index) = forms.binary_search_by_key(&(word & mask), |form| form.value) else {
                continue;
            };
            let form = &forms[index];
            let kept = form.unless.iter().any(|(mask, value, chips, requires)| {
                chips & bit != 0 && word & mask == *value && met(requires, presented)
            });
            let absent = form.chips & bit != 0 || !met(form.requires, presented);
            if absent && !kept {
                return if form.nop { NOP } else { UDF };
            }
        }
        word
    }

    /// The access checks `word` makes on this chip, in order; none for a
    /// word no checked form claims. The most specific encoding wins, as in
    /// Arm's decode tables.
    pub fn checks(self, word: u32) -> &'static [Check] {
        self.checks_in(word, check_index::groups(word))
    }

    fn checks_in(
        self,
        word: u32,
        groups: impl IntoIterator<Item = &'static CheckGroup>,
    ) -> &'static [Check] {
        let bit = 1u8 << self as u8;
        for group in groups {
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
    #[cfg(any(test, feature = "test-support"))]
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
}

/// The chip the runtime's unit tests build their default CPUs and machines
/// for: `STELA_TEST_CHIP`, or [`Chip::DEFAULT`]. A test that fixes its chip
/// does not call it.
#[cfg(any(test, feature = "test-support"))]
pub fn test_chip() -> Chip {
    extern crate std;
    std::env::var("STELA_TEST_CHIP").map_or(Chip::DEFAULT, |name| {
        Chip::from_name(&name).unwrap_or_else(|| panic!("STELA_TEST_CHIP {name} names no chip"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_admit_table_answers_as_the_full_search() {
        for chip in Chip::ALL {
            let table = chip.admit_table(0).unwrap();
            assert_eq!(table.chip(), chip);
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

    /// A PE that withholds a feature its chip has lacks the feature's forms,
    /// as a chip without it does.
    #[test]
    fn withheld_features_make_their_forms_absent() {
        // `requires` counts in Feature bits, and every chip that has a form
        // has what it requires.
        let names: Vec<&str> = Feature::ALL.iter().map(|feature| feature.name()).collect();
        assert_eq!(names, forms::FEATURES);
        for chip in Chip::ALL {
            let bit = 1u8 << chip as u8;
            for form in forms::ABSENT.iter().flat_map(|group| group.forms) {
                if form.chips & bit == 0 {
                    assert!(
                        met(form.requires, chip.features()),
                        "{chip:?} {:#x}",
                        form.value
                    );
                }
            }
        }
        let withholding = |chip: Chip, prefix: &str| {
            Feature::ALL
                .into_iter()
                .filter(|feature| feature.on(chip) && feature.name().starts_with(prefix))
                .fold(0, |bits, feature| bits | 1 << feature as u64)
        };
        // SMSTART is an MSR to PSTATE, UNDEFINED without the PE's SME state
        // (Registers::write_pstate_field); the SME forms are absent.
        let fmopa = 0x8081_2000; // fmopa za0.s, p0/m, p1/m, z0.s, z0.s
        let rdsvl = 0x04bf_5820; // rdsvl x0, #1
        let full = Chip::AppleM4.admit_table(0).unwrap();
        let without_sme = Chip::AppleM4
            .admit_table(withholding(Chip::AppleM4, "FEAT_SME"))
            .unwrap();
        for word in [fmopa, rdsvl] {
            assert_eq!(full.admit(word), word);
            assert_eq!(without_sme.admit(word), UDF, "{word:#x}");
            assert_eq!(Chip::AppleM3.admit(word), UDF);
        }
        let irg = 0x9adf_1020; // irg x0, x1
        let without_tags = Chip::AppleM5
            .admit_table(withholding(Chip::AppleM5, "FEAT_MTE"))
            .unwrap();
        assert_eq!(
            without_tags.withheld(),
            withholding(Chip::AppleM5, "FEAT_MTE")
        );
        assert_eq!(Chip::AppleM5.admit_table(0).unwrap().admit(irg), irg);
        assert_eq!(without_tags.admit(irg), UDF);
        // A hint whose feature is withheld is a NOP, as Arm decodes it.
        let pacm = 0xd503_24ff;
        let without_pacm = Chip::AppleM6
            .admit_table(withholding(Chip::AppleM6, "FEAT_PAuth_LR"))
            .unwrap();
        assert_eq!(Chip::AppleM6.admit(pacm), pacm);
        assert_eq!(without_pacm.admit(pacm), NOP);
        // What the PE presents keeps its words.
        let add = 0x8b02_0020;
        assert_eq!(without_sme.admit(add), add);
        assert_eq!(without_tags.admit(add), add);
        // SME2's sz 1 words need FEAT_SME_I16I64 or FEAT_SME_F64F64, which
        // the table cannot place, so withholding either alone is refused.
        for chip in [Chip::AppleM4, Chip::AppleM5, Chip::AppleM6] {
            for alone in ["FEAT_SME_I16I64", "FEAT_SME_F64F64"] {
                assert!(
                    chip.admit_table(withholding(chip, alone)).is_err(),
                    "{chip:?} {alone}"
                );
            }
            assert!(chip.admit_table(0).is_ok());
        }
    }

    #[test]
    fn chip_names_round_trip_in_table_order() {
        for (index, chip) in Chip::ALL.into_iter().enumerate() {
            assert_eq!(chip as usize, index);
            assert_eq!(Chip::from_name(chip.name()), Some(chip));
        }
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
