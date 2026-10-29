// SPDX-License-Identifier: GPL-2.0-only
//! The codec writes a bus reset restores, as Linux sound/hda/core/regmap.c
//! caches codec state for `regcache_sync` on codec resume.
//! Copyright (c) 2015 Takashi Iwai <tiwai@suse.de>.
use super::Verb;
use alloc::vec::Vec;

/// Codec writes beyond this many distinct targets are not kept.
const CAPACITY: usize = 4096;
const SET_FORMAT: u32 = 0x2;
const SET_AMP: u32 = 0x3;
const SET_COEF: u32 = 0x4;
const SET_COEF_INDEX: u32 = 0x5;
/// 12-bit verbs 0x700-0x7ff set codec state; pin sense execution (0x709)
/// and function reset (0x7ff) are actions, never restored.
const SET: u32 = 0x7;
const PIN_SENSE: u32 = 0x709;
const RESET: u32 = 0x7ff;

#[derive(Clone, Copy)]
struct Entry {
    key: u64,
    verbs: [u32; 2],
    count: usize,
}

/// Latest write per target, in issue order. A coefficient write is kept with
/// the index it was written at, which must have been set on its node since
/// the node's last coefficient access, as Linux's helpers always do.
#[derive(Default)]
pub(super) struct Writes {
    entries: Vec<Entry>,
    /// Per (codec, node): the coefficient index the next access uses.
    indexes: Vec<(u8, u8, u16)>,
    incomplete: bool,
}

impl Writes {
    pub(super) fn remember(&mut self, verb: Verb) {
        let raw = verb.raw();
        let codec = (raw >> 28) as u8;
        let node = ((raw >> 20) & 0x7f) as u8;
        let target = u64::from(raw >> 20) << 32;
        let short = (raw >> 8) & 0xfff;
        let entry = match (raw >> 16) & 15 {
            SET_FORMAT => Entry {
                key: target | u64::from(SET_FORMAT << 12),
                verbs: [raw, 0],
                count: 1,
            },
            // Direction, side and index select the amplifier.
            SET_AMP => Entry {
                key: target | u64::from(SET_AMP << 12 | (raw >> 8) & 0xff),
                verbs: [raw, 0],
                count: 1,
            },
            SET_COEF_INDEX => {
                self.set_index(codec, node, Some(raw as u16));
                return;
            }
            SET_COEF => {
                let Some(index) = self.index(codec, node) else {
                    self.incomplete = true;
                    return;
                };
                self.set_index(codec, node, None);
                Entry {
                    key: target | u64::from(SET_COEF << 12) | u64::from(index) << 16,
                    verbs: [
                        (raw & 0xfff0_0000) | SET_COEF_INDEX << 16 | u32::from(index),
                        raw,
                    ],
                    count: 2,
                }
            }
            // Coefficient reads move the index too.
            0xc => {
                self.set_index(codec, node, None);
                return;
            }
            SET if short != PIN_SENSE && short != RESET => Entry {
                key: target | u64::from(short),
                verbs: [raw, 0],
                count: 1,
            },
            _ => return,
        };
        if let Some(at) = self.entries.iter().position(|e| e.key == entry.key) {
            self.entries.remove(at);
        } else if self.entries.len() == CAPACITY {
            self.incomplete = true;
            return;
        }
        self.entries.push(entry);
    }

    fn index(&self, codec: u8, node: u8) -> Option<u16> {
        self.indexes
            .iter()
            .find(|&&(c, n, _)| (c, n) == (codec, node))
            .map(|&(_, _, index)| index)
    }
    fn set_index(&mut self, codec: u8, node: u8, index: Option<u16>) {
        self.indexes.retain(|&(c, n, _)| (c, n) != (codec, node));
        if let Some(index) = index {
            self.indexes.push((codec, node, index));
        }
    }

    /// Whether every write so far can be restored.
    pub(super) fn complete(&self) -> bool {
        !self.incomplete
    }

    pub(super) fn replay(&self) -> Vec<Verb> {
        self.entries
            .iter()
            .flat_map(|e| e.verbs[..e.count].iter().copied().map(Verb::from_raw))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(verbs: &[Verb]) -> Vec<u32> {
        verbs.iter().map(|v| v.raw()).collect()
    }

    #[test]
    fn the_latest_write_per_target_replays_in_order_like_regcache_sync() {
        let mut writes = Writes::default();
        for verb in [
            Verb::short(0, 2, 0x701, 1),
            Verb::long(0, 3, 0x3, 0xb000 | 0x20),
            Verb::long(0, 3, 0x3, 0x9000 | 0x10),
            Verb::short(0, 2, 0xf00, 9),
            Verb::short(0, 2, 0x709, 0),
            Verb::short(0, 1, 0x7ff, 0),
            Verb::long(0, 0x20, 0x5, 7),
            Verb::long(0, 0x20, 0x4, 0x1234),
            Verb::short(0, 2, 0x701, 2),
            Verb::long(0, 3, 0x3, 0xb000 | 0x30),
        ] {
            writes.remember(verb.unwrap());
        }
        assert!(writes.complete());
        assert_eq!(
            raw(&writes.replay()),
            [
                0x0033_9010,
                0x0205_0007,
                0x0204_1234,
                0x0027_0102,
                0x0033_b030
            ]
        );
        // A coefficient write without a fresh index cannot be keyed.
        writes.remember(Verb::long(0, 0x20, 0x4, 1).unwrap());
        assert!(!writes.complete());
    }
}
