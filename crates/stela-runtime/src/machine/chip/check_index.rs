//! Immutable prefix candidates for the generated access-check decoder. The
//! generated mask order and full per-word matches remain authoritative.
use super::{AdmitTable, CheckGroup, checks};

const PREFIXES: usize = AdmitTable::PREFIXES;
const PREFIX_MASK: u32 = PREFIXES as u32 - 1;
const GROUP_WORDS: usize = checks::CHECKS.len().div_ceil(u64::BITS as usize);
type PrefixBits = [[u64; GROUP_WORDS]; PREFIXES];

// This temporary bitmap exists only during constant evaluation. Enumerating
// each form's feasible unmasked prefixes avoids scanning every form for every
// prefix, and deduplicates groups without retaining a runtime bitmap.
const GROUP_REFERENCES: usize = group_references();

struct Index {
    starts: [u32; PREFIXES + 1],
    groups: [u16; GROUP_REFERENCES],
}
static INDEX: Index = compact();

const fn prefix_groups() -> PrefixBits {
    let mut prefixes = [[0; GROUP_WORDS]; PREFIXES];
    let mut group_index = 0;
    while group_index < checks::CHECKS.len() {
        let group = &checks::CHECKS[group_index];
        let free = !(group.mask >> AdmitTable::SHIFT) & PREFIX_MASK;
        let mut form_index = 0;
        while form_index < group.forms.len() {
            let fixed = group.forms[form_index].value >> AdmitTable::SHIFT & !free;
            let mut varying = free;
            loop {
                prefixes[(fixed | varying) as usize][group_index / u64::BITS as usize] |=
                    1 << (group_index % u64::BITS as usize);
                if varying == 0 {
                    break;
                }
                varying = (varying - 1) & free;
            }
            form_index += 1;
        }
        group_index += 1;
    }
    prefixes
}

const fn group_references() -> usize {
    let prefixes = prefix_groups();
    let mut total = 0;
    let mut prefix = 0;
    while prefix < PREFIXES {
        let mut word = 0;
        while word < GROUP_WORDS {
            total += prefixes[prefix][word].count_ones() as usize;
            word += 1;
        }
        prefix += 1;
    }
    total
}

const fn compact() -> Index {
    assert!(checks::CHECKS.len() <= u16::MAX as usize + 1);
    assert!(GROUP_REFERENCES <= u32::MAX as usize);
    let mut index = Index {
        starts: [0; PREFIXES + 1],
        groups: [0; GROUP_REFERENCES],
    };
    let mut next = 0;
    let prefixes = prefix_groups();
    let mut prefix = 0;
    while prefix < PREFIXES {
        index.starts[prefix] = next as u32;
        let mut word = 0;
        while word < GROUP_WORDS {
            let mut bits = prefixes[prefix][word];
            while bits != 0 {
                // Ascending original group indices preserve specificity and
                // the first-match rule, including empty per-chip variants.
                index.groups[next] =
                    (word * u64::BITS as usize + bits.trailing_zeros() as usize) as u16;
                next += 1;
                bits &= bits - 1;
            }
            word += 1;
        }
        prefix += 1;
    }
    index.starts[PREFIXES] = next as u32;
    assert!(next == GROUP_REFERENCES);
    index
}

#[inline]
pub(super) fn groups(word: u32) -> impl Iterator<Item = &'static CheckGroup> {
    let prefix = (word >> AdmitTable::SHIFT) as usize;
    INDEX.groups[INDEX.starts[prefix] as usize..INDEX.starts[prefix + 1] as usize]
        .iter()
        .map(|&index| &checks::CHECKS[usize::from(index)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::Chip;

    #[test]
    fn compact_prefix_candidates_are_complete_unique_and_in_original_order() {
        assert_eq!(INDEX.starts[0], 0);
        assert_eq!(INDEX.starts[PREFIXES] as usize, GROUP_REFERENCES);
        for prefix in 0..PREFIXES {
            let candidates =
                &INDEX.groups[INDEX.starts[prefix] as usize..INDEX.starts[prefix + 1] as usize];
            assert!(candidates.windows(2).all(|pair| pair[0] < pair[1]));
            for (group_index, group) in checks::CHECKS.iter().enumerate() {
                let mask = group.mask >> AdmitTable::SHIFT;
                let possible = group
                    .forms
                    .iter()
                    .any(|form| prefix as u32 & mask == form.value >> AdmitTable::SHIFT & mask);
                assert_eq!(candidates.contains(&(group_index as u16)), possible);
            }
        }
    }

    fn compare(word: u32) {
        for chip in Chip::ALL {
            assert_eq!(
                chip.checks(word),
                chip.checks_in(word, checks::CHECKS),
                "{chip:?} {word:#010x}"
            );
        }
    }

    #[test]
    fn indexed_checks_match_full_search_for_forms_free_bits_and_imm5_classes() {
        for group in checks::CHECKS {
            for form in group.forms {
                compare(form.value);
                compare(form.value | !group.mask);
                let mut free = !group.mask;
                while free != 0 {
                    let bit = free.isolate_lowest_one();
                    compare(form.value | bit);
                    free &= free - 1;
                }
                // Both SingleImm5 classes and every lane encoding retain the
                // original variant selection after the prefix narrows groups.
                if form
                    .variants
                    .iter()
                    .any(|variant| matches!(variant.class, super::super::WordClass::SingleImm5(_)))
                {
                    for imm5 in 0..=checks::IMM5 >> checks::IMM5.trailing_zeros() {
                        compare(
                            (form.value & !checks::IMM5) | imm5 << checks::IMM5.trailing_zeros(),
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn indexed_checks_match_full_search_for_raw_words_and_integer_prefixes() {
        let mut word = 0x2545_f491_u32;
        for _ in 0..20_000 {
            word ^= word << 13;
            word ^= word >> 17;
            word ^= word << 5;
            compare(word);
        }
        for word in [0x9100_0400, 0xf940_0020, 0x5400_0001, 0x1400_0000] {
            assert_eq!(groups(word).count(), 0);
            compare(word);
        }
    }
}
