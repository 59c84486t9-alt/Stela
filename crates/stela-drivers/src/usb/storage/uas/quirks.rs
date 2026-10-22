//! Exact enclosure policies from pinned Linux unusual_uas.h and uas-detect.h.
// SPDX-License-Identifier: GPL-2.0-only AND GPL-2.0-or-later
// Copyright Hans de Goede 2013; Matthew Dharm 2000-2002;
// Adam J. Richter/Yggdrasil Computing, Inc. 2000.
const NO_REPORT_OPCODES: u8 = 1;
const NO_SAME: u8 = 2;
const IGNORE: u8 = 4;
const NO_REPORT_LUNS: u8 = 8;
const NO_ATA: u8 = 16;
const BROKEN_FUA: u8 = 32;
const ALWAYS_SYNC: u8 = 64;
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Flags(u8);
impl Flags {
    #[cfg(test)]
    pub fn bits(self) -> u8 {
        self.0
    }
    pub fn from_id(vendor: u16, product: u16, revision: u16) -> Self {
        Self(
            DEVICES
                .iter()
                .find(|&&(v, p, lo, hi, _)| {
                    v == vendor && p == product && (lo..=hi).contains(&revision)
                })
                .map_or(0, |&(_, _, _, _, flags)| flags)
                | if vendor == 0x0bc2 { NO_ATA } else { 0 },
        )
    }
    pub fn ignored(self) -> bool {
        self.0 & IGNORE != 0
    }
    pub fn report_luns_permitted(self) -> bool {
        self.0 & NO_REPORT_LUNS == 0
    }
    pub fn always_sync(self) -> bool {
        self.0 & ALWAYS_SYNC != 0
    }
    pub fn needs_sync(self, cdb: &[u8], data_out: bool) -> bool {
        self.always_sync()
            && (data_out
                || cdb.first().is_some_and(|op| {
                    matches!(
                        op,
                        0x04 | 0x07
                            | 0x19
                            | 0x0a
                            | 0x2a
                            | 0x2e
                            | 0xaa
                            | 0xae
                            | 0x89
                            | 0x8a
                            | 0x8e
                            | 0x9c
                            | 0x41
                            | 0x93
                            | 0x42
                    )
                })
                || variable_action(cdb).is_some_and(|action| matches!(action, 0x0b..=0x0d)))
    }
    pub fn permits(self, cdb: &[u8]) -> bool {
        let Some(&op) = cdb.first() else {
            return false;
        };
        let variable = variable_action(cdb);
        if op == 0x7f && (variable.is_none() || variable == Some(7)) || op == 0x53 {
            return false;
        }
        // The transport has one data direction; bidirectional XDWRITEREAD is
        // unsupported. Unknown variable actions on constrained bridges cannot
        // bypass an operation-specific policy through an undecoded alias.
        if op == 0x7f
            && self.0 & (BROKEN_FUA | NO_SAME | ALWAYS_SYNC) != 0
            && !variable.is_some_and(|action| matches!(action, 0x09..=0x0d))
        {
            return false;
        }
        let fua = if op == 0x7f && variable.is_some_and(|action| matches!(action, 0x09..=0x0c)) {
            cdb.get(10).copied().unwrap_or(8) & 8 != 0
        } else {
            matches!(
                op,
                0x28 | 0x2a | 0x2e | 0xa8 | 0xaa | 0xae | 0x88 | 0x89 | 0x8a | 0x8e | 0x9c
            ) && cdb.get(1).copied().unwrap_or(8) & 8 != 0
        };
        !((self.0 & NO_ATA != 0 && (matches!(op, 0xa1 | 0x85) || variable == Some(0x1ff0)))
            || (self.0 & NO_REPORT_OPCODES != 0
                && op == 0xa3
                && cdb.get(1).is_none_or(|action| action & 0x1f == 0x0c))
            || (self.0 & NO_SAME != 0 && (matches!(op, 0x41 | 0x93) || variable == Some(0x0d)))
            || (self.0 & NO_REPORT_LUNS != 0 && op == 0xa0)
            || (self.0 & BROKEN_FUA != 0 && fua)
            || (self.always_sync()
                && matches!(op, 0x1a | 0x5a)
                && cdb
                    .get(2)
                    .is_none_or(|page| matches!(page & 0x3f, 8 | 0x3f))))
    }
}
fn variable_action(cdb: &[u8]) -> Option<u16> {
    if cdb.first() != Some(&0x7f)
        || cdb.len() < 12
        || cdb.len() != usize::from(cdb[7]) + 8
        || cdb[7] & 3 != 0
    {
        return None;
    }
    let action = u16::from_be_bytes([cdb[8], cdb[9]]);
    if matches!(action, 0x09..=0x0d | 0x1ff0) && cdb.len() != 32 {
        return None;
    }
    Some(action)
}

const DEVICES: &[(u16, u16, u16, u16, u8)] = &[
    (0x054c, 0x087d, 0x0000, 0x9999, NO_REPORT_OPCODES),
    (0x059f, 0x105f, 0x0000, 0x9999, NO_REPORT_OPCODES | NO_SAME),
    (0x059f, 0x1061, 0x0000, 0x9999, NO_REPORT_OPCODES | NO_SAME),
    (0x0781, 0x55e8, 0x0000, 0x9999, IGNORE),
    (0x090c, 0x2000, 0x0000, 0x9999, IGNORE),
    (0x0984, 0x0301, 0x0128, 0x0128, IGNORE),
    (0x0b05, 0x1932, 0x0000, 0x9999, IGNORE),
    (0x0bc2, 0x331a, 0x0000, 0x9999, NO_REPORT_LUNS),
    (0x125f, 0xa94a, 0x0160, 0x0160, NO_ATA),
    (0x13fd, 0x3940, 0x0000, 0x0309, NO_ATA),
    (0x152d, 0x0539, 0x0000, 0x9999, NO_REPORT_OPCODES),
    (
        0x152d,
        0x0567,
        0x0000,
        0x9999,
        BROKEN_FUA | NO_REPORT_OPCODES,
    ),
    (0x152d, 0x0578, 0x0000, 0x9999, BROKEN_FUA),
    (0x152d, 0x0583, 0x0000, 0x9999, NO_REPORT_OPCODES),
    (0x154b, 0xf009, 0x0000, 0x9999, NO_ATA | NO_REPORT_OPCODES),
    (0x154b, 0xf00b, 0x0000, 0x9999, NO_ATA),
    (0x154b, 0xf00d, 0x0000, 0x9999, NO_ATA),
    (0x17ef, 0x3899, 0x0000, 0x9999, IGNORE),
    (0x2109, 0x0711, 0x0000, 0x9999, NO_ATA),
    (0x2537, 0x1068, 0x0000, 0x9999, IGNORE),
    (0x357d, 0x7788, 0x0000, 0x9999, NO_REPORT_OPCODES | IGNORE),
    (0x4971, 0x1012, 0x0000, 0x9999, IGNORE),
    (0x4971, 0x8017, 0x0000, 0x9999, NO_REPORT_OPCODES),
    (0x4971, 0x8024, 0x0000, 0x9999, ALWAYS_SYNC),
];
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_id_revision_boundaries_retain_each_source_policy() {
        assert_eq!(DEVICES.len(), 24);
        for &(v, p, lo, hi, flags) in DEVICES {
            for revision in [lo, hi] {
                assert_eq!(
                    Flags::from_id(v, p, revision).0,
                    flags | if v == 0x0bc2 { NO_ATA } else { 0 }
                );
            }
            if lo > 0 {
                assert_eq!(
                    Flags::from_id(v, p, lo - 1).0,
                    if v == 0x0bc2 { NO_ATA } else { 0 }
                );
            }
            if hi < u16::MAX {
                assert_eq!(
                    Flags::from_id(v, p, hi + 1).0,
                    if v == 0x0bc2 { NO_ATA } else { 0 }
                );
            }
        }
    }
    #[test]
    fn raw_commands_cannot_bypass_known_enclosure_restrictions() {
        assert!(!Flags::from_id(0x0bc2, 0x331a, 0).permits(&[0xa0; 12]));
        assert!(!Flags::from_id(0x0bc2, 0x1234, 0).permits(&[0x85; 16]));
        assert!(!Flags::from_id(0x152d, 0x0567, 0).permits(&[0xa3, 0x0c]));
        assert!(!Flags::from_id(0x152d, 0x0578, 0).permits(&[0x2a, 8]));
        assert!(Flags::from_id(0x152d, 0x0578, 0).permits(&[0x2a, 0]));
        assert!(Flags::from_id(0x4971, 0x8024, 0).always_sync());
    }
}
