//! Pure native cache quota policy, with requested and assigned limits distinct.
//!
//! Original 26A434 t8112pmp SHA256
//! b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//! VA100326c..1003664 joins raw44-byte rows to actual low9 quota seeds;
//! VA1003924..1003ab4 consumes low12 requests or low32 byte budget >>17;
//! VA1003ee8..10040b0 rebuilds defaults and allocates by source tier/class.
//! VA1003cbc..1003ee8 publishes low12 responses and programs scaled targets.
//! The source report is docs/research/apple-mcc.md, with exact original windows
//! in .stela/goal-20261022/memory/t8112-zero-pmp-contract-r1. No firmware runs.
//!
//! This owner computes policy only. Dirty snapshots describe work; they are
//! not hardware receipts. The caller must perform actual programming/publication
//! before consuming their matching clear. No PTD, IRQ, readiness, capacity,
//! occupancy, ACK or independently required event housekeeping is supplied.
use alloc::{rc::Rc, vec::Vec};

pub const GROUPS: usize = 32;
pub const ROW_BYTES: usize = 44;
const WORDS: usize = ROW_BYTES / 4;
const RESPONSE_BLOCKS: usize = GROUPS / 4;
const NO_GROUP: u32 = 0xffff;
const QUOTA_MASK: u32 = 0x1ff;
const LANE_MASK: u32 = 0xfff;
const RETAIN_FLAG: u32 = 1 << 1;
type Error = &'static str;

/// Exact supported source row+0x18 encodings. Lane flags do not select these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Class1 = 1,
    Class2 = 2,
    Class3 = 3,
}
impl Class {
    fn parse(word: u32) -> Result<Self, Error> {
        match word {
            1 => Ok(Self::Class1),
            2 => Ok(Self::Class2),
            3 => Ok(Self::Class3),
            _ => Err("native cache row has an unsupported source class"),
        }
    }
}

/// Supplied software configuration and retained source quota-word observations.
/// The caller owns their provenance and join to the actual quota resource;
/// numbers here never assert Apple reset state or cache capacity. The pinned
/// T8112 software defaults are budget/reference64, hardware_scale0,
/// hardware_multiplier0, feature_word0 and zero slot_flags. Seeds remain actual
/// caller-supplied full32 words, never inferred from the raw table's limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inputs {
    pub budget: u32,
    pub reference: u32,
    /// Raw source config+0x78 byte: nonzero scales seeds; exactly1 scales writes.
    pub hardware_scale: u8,
    pub hardware_multiplier: u32,
    pub feature_word: u32,
    /// Raw group-slot flags; no producer or mutable flag setter is invented.
    pub slot_flags: [u32; GROUPS],
    pub quota_words: [u32; GROUPS],
}
impl Inputs {
    /// VA1003dcc..1003de0: W32 ceil division, including wrapping numerator and
    /// A64 UDIV's zero-divisor result. Retain this unmasked value for the source
    /// old-target comparison; actual word construction later masks low9.
    pub fn hardware_units(&self, target: u32) -> u32 {
        if self.hardware_scale == 1 {
            udiv(
                target
                    .wrapping_add(self.hardware_multiplier)
                    .wrapping_sub(1),
                self.hardware_multiplier,
            )
        } else {
            target
        }
    }
}
fn udiv(numerator: u32, denominator: u32) -> u32 {
    numerator.checked_div(denominator).unwrap_or(0)
}

/// Every original word/order/duplicate is retained, including opaque+0x24 and
/// the complete flags word+0x28. Derived seeds do not overwrite these bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    words: [u32; WORDS],
    class: Class,
    group: Option<u8>,
    seeded_limit: u32,
    seeded_assigned: u32,
}
impl Row {
    pub fn source_words(&self) -> &[u32; WORDS] {
        &self.words
    }
    pub fn class(&self) -> Class {
        self.class
    }
    pub fn group(&self) -> Option<u8> {
        self.group
    }
    pub fn tier(&self) -> u32 {
        self.words[2]
    }
    pub fn seeded_limit(&self) -> u32 {
        self.seeded_limit
    }
    pub fn seeded_assigned(&self) -> u32 {
        self.seeded_assigned
    }
}

/// Immutable observation of one active source group, in128-KiB policy units.
/// None of these fields measures resident entries or disjoint reservations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Group {
    pub row: usize,
    pub ceiling: u32,
    pub requested: u32,
    pub assigned: u32,
    pub hardware_target: u32,
    pub slot_flags: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirtyMasks {
    pub hardware: u32,
    pub responses: u32,
}

/// Pending source hardware work, bound to this policy and dirty revision.
/// It grants no hardware authority and is deliberately neither Copy nor Clone.
#[derive(Debug)]
pub struct HardwareUpdate {
    owner: Rc<()>,
    revision: u64,
    group: u8,
    target: u32,
    scaled_units: u32,
}
impl HardwareUpdate {
    pub fn group(&self) -> u8 {
        self.group
    }
    pub fn target(&self) -> u32 {
        self.target
    }
    pub fn scaled_units(&self) -> u32 {
        self.scaled_units
    }
}

/// Pending full64 four-lane response. Complete only after actual publication;
/// clearing a block consumes its exact dirty membership and revision.
#[derive(Debug)]
pub struct ResponseBlock {
    owner: Rc<()>,
    revision: u64,
    block: u8,
    dirty: u32,
    packed: u64,
}
impl ResponseBlock {
    pub fn block(&self) -> u8 {
        self.block
    }
    pub fn dirty_mask(&self) -> u32 {
        self.dirty
    }
    pub fn packed(&self) -> u64 {
        self.packed
    }
}

/// Retained pure policy. There is no Clone/reset-to-ready/effectful backend.
/// The service owns source order: defaults -> publish/program -> allocate ->
/// publish/program. In particular op1 can expose seeded intermediate responses.
#[derive(Debug)]
pub struct Policy {
    owner: Rc<()>,
    inputs: Inputs,
    rows: Vec<Row>,
    groups: [Option<Group>; GROUPS],
    raw_lanes: [Option<u16>; GROUPS],
    active: u32,
    dirty: DirtyMasks,
    revision: u64,
    hardware_revision: [u64; GROUPS],
    response_revision: [u64; RESPONSE_BLOCKS],
}
impl Policy {
    /// Parse/qualify the complete source property before installing any state.
    /// Initial requested fields are zero. Runs defaults, deliberately not the
    /// allocator: their source-visible publications are separate service work.
    pub fn new(raw_rows: &[u8], inputs: Inputs) -> Result<Self, Error> {
        let (records, tail) = raw_rows.as_chunks::<ROW_BYTES>();
        if !tail.is_empty() || u32::try_from(records.len()).is_err() {
            return Err("native cache table is not complete source44-byte rows");
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(records.len())
            .map_err(|_| "native cache source table allocation failed")?;
        for record in records {
            let (fields, _) = record.as_chunks::<4>();
            let words = core::array::from_fn(|index| u32::from_le_bytes(fields[index]));
            let class = Class::parse(words[6])?;
            let group = match words[3] {
                NO_GROUP => None,
                value if value < GROUPS as u32 => Some(value as u8),
                _ => return Err("native cache row group is neither0..31 norFFFF"),
            };
            let mut limit = words[7];
            let mut assigned = words[8];
            if let Some(group) = group {
                limit = inputs.quota_words[usize::from(group)] & QUOTA_MASK;
                if inputs.hardware_scale != 0 {
                    limit = limit.wrapping_mul(inputs.hardware_multiplier);
                }
                if class == Class::Class1 {
                    assigned = limit;
                }
            }
            rows.push(Row {
                words,
                class,
                group,
                seeded_limit: limit,
                seeded_assigned: assigned,
            });
        }
        let mut policy = Self {
            owner: Rc::new(()),
            inputs,
            rows,
            groups: [None; GROUPS],
            raw_lanes: [None; GROUPS],
            active: 0,
            dirty: DirtyMasks {
                hardware: 0,
                responses: 0,
            },
            revision: 0,
            hardware_revision: [0; GROUPS],
            response_revision: [0; RESPONSE_BLOCKS],
        };
        policy.defaults()?;
        Ok(policy)
    }
    pub fn inputs(&self) -> &Inputs {
        &self.inputs
    }
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }
    pub fn active_groups(&self) -> u32 {
        self.active
    }
    pub fn group(&self, group: u8) -> Option<&Group> {
        self.groups.get(usize::from(group)).and_then(Option::as_ref)
    }
    pub fn request_lane(&self, group: u8) -> Result<Option<u16>, Error> {
        Ok(self.raw_lanes[group_index(group)?])
    }
    pub fn dirty_masks(&self) -> DirtyMasks {
        self.dirty
    }

    /// Caller has consumed the source PTD/new-data metadata. Retain the full
    /// lane, even for ignored groups/classes. Return true for every eligible
    /// update, including an unchanged numeric request (VA1003a38); this tells
    /// the caller to run allocation. Flags13:12 and upper bits do not pick class.
    pub fn set_request(&mut self, group: u8, raw_lane: u16) -> Result<bool, Error> {
        let index = group_index(group)?;
        self.raw_lanes[index] = Some(raw_lane);
        let Some(slot) = self.groups[index].as_mut() else {
            return Ok(false);
        };
        if self.rows[slot.row].class == Class::Class1 {
            return Ok(false);
        }
        slot.requested = u32::from(raw_lane) & LANE_MASK;
        Ok(true)
    }

    /// VA1003a9c..1003aa8: only low32 payload bytes, floored to128-KiB units.
    /// Does not rebuild/publish defaults or allocate. The caller composes those
    /// separate phases; zero-way selection does not supply this command.
    pub fn set_budget_payload(&mut self, payload: u64) {
        self.inputs.budget = (payload as u32) >> 17;
    }

    /// VA1003ee8..1003f7c: first row/group, source W32 multiply and UDIV,
    /// seeded assigned and independent hardware ceiling. Preserve requests and
    /// flags across budget changes. Every active group dirties both outputs.
    pub fn defaults(&mut self) -> Result<(), Error> {
        let revision = self.next_revision()?;
        let mut active = 0;
        for (row_index, row) in self.rows.iter().enumerate() {
            let Some(group) = row.group else { continue };
            let index = usize::from(group);
            let bit = 1u32 << group;
            if active & bit != 0 {
                continue;
            }
            active |= bit;
            let ceiling = if row.words[10] & 1 != 0 {
                udiv(
                    self.inputs.budget.wrapping_mul(row.seeded_limit),
                    self.inputs.reference,
                )
            } else {
                row.seeded_limit
            };
            let requested = self.groups[index].map_or(0, |slot| slot.requested);
            self.groups[index] = Some(Group {
                row: row_index,
                ceiling,
                requested,
                assigned: row.seeded_assigned,
                hardware_target: ceiling,
                slot_flags: self.inputs.slot_flags[index],
            });
            self.hardware_revision[index] = revision;
            self.response_revision[index / 4] = revision;
        }
        self.active = active;
        self.dirty.hardware |= active;
        self.dirty.responses |= active;
        self.revision = revision;
        Ok(())
    }

    /// MC startup VA1004138..100416c clears current active requests before
    /// rebuilding defaults. Retain actual last-input lane provenance; these
    /// zeroes are software lifecycle effects, not newly received PTD lanes.
    /// Actual defaults publication and metric registration remain the caller's
    /// effects before allocation. Preflight revision exhaustion before clearing.
    pub fn start_defaults(&mut self) -> Result<(), Error> {
        self.next_revision()?;
        for slot in self.groups.iter_mut().flatten() {
            slot.requested = 0;
        }
        self.defaults()
    }

    /// VA1003f80..10040b0: full original first-row tier/class policy. Same-tier
    /// limits overlap; only completed higher tiers reduce remaining budget.
    /// Class1/feature-retained groups do not enter the dynamic sums. Outputs
    /// remain dirty until actual service explicitly completes matching work.
    pub fn allocate(&mut self) -> Result<(), Error> {
        let revision = self.next_revision()?;
        let mut seen = 0;
        let mut higher = 0u32;
        let mut tier_sum = 0u32;
        let mut last_tier = 0;
        for row in &self.rows {
            let Some(group) = row.group else { continue };
            let index = usize::from(group);
            let bit = 1u32 << group;
            if seen & bit != 0 {
                continue;
            }
            seen |= bit;
            let slot = self.groups[index].as_mut().unwrap();
            let retained = row.class == Class::Class1
                || (self.inputs.feature_word != 0 && slot.slot_flags & RETAIN_FLAG != 0);
            if !retained {
                if last_tier != row.tier() {
                    higher = higher.wrapping_add(tier_sum);
                    tier_sum = 0;
                }
                let assigned = if self.inputs.budget <= higher {
                    0
                } else {
                    (self.inputs.budget - higher)
                        .min(slot.ceiling)
                        .min(slot.requested)
                };
                if slot.hardware_target != assigned
                    && (row.class == Class::Class3
                        || (self.inputs.feature_word != 0 && slot.slot_flags & RETAIN_FLAG != 0))
                {
                    slot.hardware_target = assigned;
                    self.dirty.hardware |= bit;
                    self.hardware_revision[index] = revision;
                }
                slot.assigned = assigned;
                tier_sum = tier_sum.wrapping_add(assigned);
                last_tier = row.tier();
            }
            self.dirty.responses |= bit;
            self.response_revision[index / 4] = revision;
        }
        self.revision = revision;
        Ok(())
    }

    pub fn hardware_update(&self, group: u8) -> Result<Option<HardwareUpdate>, Error> {
        let index = group_index(group)?;
        if self.dirty.hardware & (1u32 << group) == 0 {
            return Ok(None);
        }
        let target = self.groups[index].unwrap().hardware_target;
        Ok(Some(HardwareUpdate {
            owner: self.owner.clone(),
            revision: self.hardware_revision[index],
            group,
            target,
            scaled_units: self.inputs.hardware_units(target),
        }))
    }
    pub fn response_block(&self, block: u8) -> Result<Option<ResponseBlock>, Error> {
        let index = block_index(block)?;
        let dirty = self.dirty.responses & block_mask(block);
        if dirty == 0 {
            return Ok(None);
        }
        Ok(Some(ResponseBlock {
            owner: self.owner.clone(),
            revision: self.response_revision[index],
            block,
            dirty,
            packed: self.packed_block(index),
        }))
    }

    /// Clear only the matching actual completed hardware operation. A token
    /// from another policy, an overwritten phase or already consumed work
    /// refuses without changing masks. This method itself programs nothing.
    pub fn complete_hardware(&mut self, update: HardwareUpdate) -> Result<(), Error> {
        let index = usize::from(update.group);
        let bit = 1u32 << update.group;
        if !Rc::ptr_eq(&self.owner, &update.owner)
            || self.dirty.hardware & bit == 0
            || self.hardware_revision[index] != update.revision
            || self.groups[index].is_none_or(|slot| slot.hardware_target != update.target)
            || self.inputs.hardware_units(update.target) != update.scaled_units
        {
            return Err("native cache hardware clear is foreign, stale or already consumed");
        }
        self.dirty.hardware &= !bit;
        Ok(())
    }
    /// Clear exactly the dirty members of a matching actual four-lane PTD
    /// publication. Other blocks and pending hardware work remain unchanged.
    pub fn complete_response(&mut self, response: ResponseBlock) -> Result<(), Error> {
        let index = usize::from(response.block);
        let mask = block_mask(response.block);
        if !Rc::ptr_eq(&self.owner, &response.owner)
            || self.response_revision[index] != response.revision
            || self.dirty.responses & mask != response.dirty
            || response.dirty == 0
            || self.packed_block(index) != response.packed
        {
            return Err("native cache response clear is foreign, stale or already consumed");
        }
        self.dirty.responses &= !response.dirty;
        Ok(())
    }
    fn packed_block(&self, block: usize) -> u64 {
        (0..4).fold(0, |packed, lane| {
            let assigned = self.groups[block * 4 + lane].map_or(0, |slot| slot.assigned);
            packed | (u64::from(assigned & LANE_MASK) << (lane * 16))
        })
    }
    fn next_revision(&self) -> Result<u64, Error> {
        self.revision
            .checked_add(1)
            .ok_or("native cache policy dirty revision exhausted")
    }
}
fn group_index(group: u8) -> Result<usize, Error> {
    let index = usize::from(group);
    if index < GROUPS {
        Ok(index)
    } else {
        Err("native cache group is outside0..31")
    }
}
fn block_index(block: u8) -> Result<usize, Error> {
    let index = usize::from(block);
    if index < RESPONSE_BLOCKS {
        Ok(index)
    } else {
        Err("native cache response block is outside0..7")
    }
}
fn block_mask(block: u8) -> u32 {
    0xfu32 << (u32::from(block) * 4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn inputs() -> Inputs {
        Inputs {
            budget: 64,
            reference: 64,
            hardware_scale: 0,
            hardware_multiplier: 0,
            feature_word: 0,
            slot_flags: [0; GROUPS],
            quota_words: [64; GROUPS],
        }
    }
    fn row(group: u32, tier: u32, class: u32) -> [u32; WORDS] {
        [77, 9, tier, group, 7, 13, class, 8192, 0, 0xfeed, 0]
    }
    fn encoded(rows: &[[u32; WORDS]]) -> Vec<u8> {
        rows.iter()
            .flat_map(|row| row.iter().flat_map(|word| word.to_le_bytes()))
            .collect()
    }
    fn policy(rows: &[[u32; WORDS]]) -> Policy {
        Policy::new(&encoded(rows), inputs()).unwrap()
    }
    // These tests consume pure dirty work only to exercise bookkeeping; no
    // hardware/PTD implementation or real completion is inferred from this.
    fn clear_work(policy: &mut Policy) {
        for group in 0..GROUPS as u8 {
            if let Some(update) = policy.hardware_update(group).unwrap() {
                policy.complete_hardware(update).unwrap();
            }
        }
        for block in 0..RESPONSE_BLOCKS as u8 {
            if let Some(response) = policy.response_block(block).unwrap() {
                policy.complete_response(response).unwrap();
            }
        }
    }

    #[test]
    fn startup_clears_requests_without_fabricating_new_input_lanes() {
        let mut p = policy(&[row(0, 1, 3), row(1, 2, 1)]);
        p.set_request(0, 0x2014).unwrap();
        p.allocate().unwrap();
        clear_work(&mut p);
        assert_eq!(p.group(0).unwrap().assigned, 20);
        p.start_defaults().unwrap();
        assert_eq!(p.group(0).unwrap().requested, 0);
        assert_eq!(p.group(0).unwrap().hardware_target, 64);
        assert_eq!(p.request_lane(0).unwrap(), Some(0x2014));
        assert_eq!(p.group(1).unwrap().assigned, 64);
        assert_eq!(
            p.dirty_masks(),
            DirtyMasks {
                hardware: 3,
                responses: 3
            }
        );
        p.allocate().unwrap();
        assert_eq!(p.group(0).unwrap().assigned, 0);
        assert_eq!(p.group(1).unwrap().assigned, 64);
        p.set_request(0, 20).unwrap();
        p.revision = u64::MAX;
        assert!(p.start_defaults().is_err());
        assert_eq!(p.group(0).unwrap().requested, 20);
    }
    #[test]
    fn raw_rows_duplicates_sentinel_and_opaque_words_remain_exact() {
        let first = row(3, 7, 2);
        let mut duplicate = row(3, 99, 1);
        duplicate[8] = 123;
        duplicate[10] = 0xabcd;
        let sentinel = row(NO_GROUP, u32::MAX, 3);
        let rows = [first, duplicate, sentinel];
        let p = policy(&rows);
        assert_eq!(p.rows().len(), rows.len());
        for (retained, original) in p.rows().iter().zip(rows) {
            assert_eq!(retained.source_words(), &original);
        }
        assert_eq!(p.rows()[1].seeded_limit(), 64);
        assert_eq!(p.rows()[1].seeded_assigned(), 64);
        assert_eq!(p.rows()[2].group(), None);
        assert_eq!(p.rows()[2].seeded_limit(), 8192);
        assert_eq!(p.active_groups(), 1 << 3);
        assert_eq!(p.group(3).unwrap().row, 0);
        assert_eq!(p.group(3).unwrap().assigned, 0);
        assert_eq!(p.dirty_masks().hardware, 1 << 3);
        assert_eq!(p.dirty_masks().responses, 1 << 3);
    }

    #[test]
    fn actual_full_word_seeds_replace_raw_limits_and_only_class1_assigned() {
        let mut rows = [row(0, 1, 1), row(1, 1, 2), row(2, 1, 3)];
        rows[0][8] = 1024;
        rows[1][8] = 12345;
        rows[2][8] = 23;
        let mut source = inputs();
        source.quota_words = [0xc0ab_0180; GROUPS];
        let p = Policy::new(&encoded(&rows), source).unwrap();
        assert_eq!(p.inputs().quota_words[0], 0xc0ab_0180);
        for retained in p.rows() {
            assert_eq!(retained.seeded_limit(), 384);
            assert_eq!(retained.source_words()[7], 8192);
        }
        assert_eq!(p.group(0).unwrap().assigned, 384);
        assert_eq!(p.group(1).unwrap().assigned, 12345);
        assert_eq!(p.group(2).unwrap().assigned, 23);
        assert_eq!(p.group(0).unwrap().hardware_target, 384);
        assert_eq!(p.hardware_update(0).unwrap().unwrap().scaled_units(), 384);
        // Publication masks12 bits independently of either hardware width.
        assert_eq!(
            p.response_block(0).unwrap().unwrap().packed(),
            384 | ((12345u64 & 0xfff) << 16) | (23 << 32)
        );
    }

    #[test]
    fn full_allocator_overlaps_same_tier_and_reduces_only_lower_tiers() {
        let rows = [row(3, 3, 1), row(0, 1, 2), row(1, 1, 3), row(2, 2, 3)];
        let mut p = policy(&rows);
        clear_work(&mut p);
        assert!(p.set_request(0, 40).unwrap());
        assert!(p.set_request(1, 40).unwrap());
        assert!(p.set_request(2, 32).unwrap());
        assert!(!p.set_request(3, 0x2001).unwrap());
        p.allocate().unwrap();
        assert_eq!(p.group(0).unwrap().assigned, 40);
        assert_eq!(p.group(1).unwrap().assigned, 40);
        assert_eq!(p.group(2).unwrap().assigned, 0);
        assert_eq!(p.group(3).unwrap().assigned, 64);
        assert_eq!(p.group(0).unwrap().hardware_target, 64);
        assert_eq!(p.group(1).unwrap().hardware_target, 40);
        assert_eq!(p.group(2).unwrap().hardware_target, 0);
        assert_eq!(p.group(3).unwrap().hardware_target, 64);
        assert_eq!(
            p.dirty_masks(),
            DirtyMasks {
                hardware: 6,
                responses: 15
            }
        );
    }

    #[test]
    fn dynamic_minimum_uses_remaining_ceiling_and_requested_independently() {
        let mut source = inputs();
        source.quota_words[1] = 9;
        let mut p = Policy::new(
            &encoded(&[row(0, 1, 2), row(1, 2, 3), row(2, 3, 3)]),
            source,
        )
        .unwrap();
        p.set_request(0, 50).unwrap();
        p.set_request(1, 20).unwrap();
        p.set_request(2, 20).unwrap();
        p.allocate().unwrap();
        assert_eq!(p.group(0).unwrap().assigned, 50);
        assert_eq!(p.group(1).unwrap().assigned, 9);
        assert_eq!(p.group(2).unwrap().assigned, 5);
    }

    #[test]
    fn class1_nonzero_policy_is_retained_when_dynamic_budget_is_zero() {
        let mut p = policy(&[row(0, 1, 2), row(1, 3, 1)]);
        p.set_request(0, 64).unwrap();
        p.set_budget_payload(0);
        p.defaults().unwrap();
        p.allocate().unwrap();
        assert_eq!(p.group(0).unwrap().assigned, 0);
        assert_eq!(p.group(0).unwrap().hardware_target, 64);
        assert_eq!(p.group(1).unwrap().assigned, 64);
        assert_eq!(p.group(1).unwrap().hardware_target, 64);
    }

    #[test]
    fn lane_flags_zero_two_and_upper_bits_do_not_select_policy_class() {
        let mut p = policy(&[row(0, 1, 2), row(1, 1, 1)]);
        assert!(p.set_request(0, 17).unwrap());
        p.allocate().unwrap();
        let first = *p.group(0).unwrap();
        clear_work(&mut p);
        assert!(p.set_request(0, 0x2011).unwrap());
        assert_eq!(p.request_lane(0).unwrap(), Some(0x2011));
        p.allocate().unwrap();
        assert_eq!(p.group(0).unwrap(), &first);
        assert_ne!(p.dirty_masks().responses, 0);
        // Even identical eligible input requires source allocation/publication.
        clear_work(&mut p);
        assert!(p.set_request(0, 0x2011).unwrap());
        p.allocate().unwrap();
        assert_ne!(p.dirty_masks().responses, 0);
        assert!(p.set_request(0, 0xffff).unwrap());
        assert_eq!(p.group(0).unwrap().requested, 4095);
        assert_eq!(p.request_lane(0).unwrap(), Some(0xffff));
        assert!(!p.set_request(1, 0x2007).unwrap());
        assert_eq!(p.request_lane(1).unwrap(), Some(0x2007));
        assert_eq!(p.group(1).unwrap().requested, 0);
        assert!(!p.set_request(31, 0x2009).unwrap());
        assert_eq!(p.request_lane(31).unwrap(), Some(0x2009));
        assert!(p.group(31).is_none());
    }

    #[test]
    fn source_feature_guard_retains_only_when_word_and_slot_bit1_are_set() {
        for (feature, flags, retained) in [
            (0, 2, false),
            (1, 0, false),
            (1, 1, false),
            (7, 0x102, true),
        ] {
            let mut source = inputs();
            source.feature_word = feature;
            source.slot_flags[0] = flags;
            let mut r = row(0, 1, 2);
            r[8] = 41;
            let mut p = Policy::new(&encoded(&[r, row(1, 2, 3)]), source).unwrap();
            clear_work(&mut p);
            p.set_request(0, 17).unwrap();
            p.set_request(1, 64).unwrap();
            p.allocate().unwrap();
            assert_eq!(p.group(0).unwrap().assigned, if retained { 41 } else { 17 });
            assert_eq!(p.group(0).unwrap().hardware_target, 64);
            // Retained groups never consume the lower tier's budget.
            assert_eq!(p.group(1).unwrap().assigned, if retained { 64 } else { 47 });
            assert_eq!(p.group(0).unwrap().slot_flags, flags);
        }
    }

    #[test]
    fn op1_floor_low32_and_defaults_intermediate_are_separate_phases() {
        let mut r = row(0, 1, 3);
        r[8] = 11;
        r[10] = 1;
        let mut p = policy(&[r]);
        p.set_request(0, 9).unwrap();
        p.allocate().unwrap();
        assert_eq!(p.group(0).unwrap().assigned, 9);
        clear_work(&mut p);
        p.set_budget_payload(0xfeed_beef_0041_ffff);
        assert_eq!(p.inputs().budget, 32);
        assert_eq!(p.inputs().reference, 64);
        assert_eq!(p.group(0).unwrap().assigned, 9);
        assert_eq!(
            p.dirty_masks(),
            DirtyMasks {
                hardware: 0,
                responses: 0
            }
        );
        p.defaults().unwrap();
        assert_eq!(p.group(0).unwrap().ceiling, 32);
        assert_eq!(p.group(0).unwrap().requested, 9);
        assert_eq!(p.group(0).unwrap().assigned, 11);
        assert_eq!(p.group(0).unwrap().hardware_target, 32);
        let response = p.response_block(0).unwrap().unwrap();
        assert_eq!(response.packed(), 11);
        p.complete_response(response).unwrap();
        p.allocate().unwrap();
        assert_eq!(p.group(0).unwrap().assigned, 9);
        assert_eq!(p.group(0).unwrap().hardware_target, 9);
        assert_eq!(p.response_block(0).unwrap().unwrap().packed(), 9);
        p.set_budget_payload(0x1234_5678_0001_ffff);
        assert_eq!(p.inputs().budget, 0);
    }

    #[test]
    fn defaults_and_hardware_scaling_preserve_w32_wrap_and_udiv_zero() {
        let mut r = row(0, 1, 3);
        r[10] = 1;
        let mut source = inputs();
        source.quota_words[0] = u32::MAX;
        source.hardware_scale = 1;
        source.hardware_multiplier = u32::MAX;
        source.budget = 2;
        source.reference = 3;
        let p = Policy::new(&encoded(&[r]), source).unwrap();
        assert_eq!(p.rows()[0].seeded_limit(), u32::MAX - 510);
        assert_eq!(p.group(0).unwrap().ceiling, 1_431_655_424);
        assert_eq!(p.hardware_update(0).unwrap().unwrap().scaled_units(), 0);
        // ceil arithmetic wraps before UDIV, rather than using a wider host add.
        assert_eq!(source.hardware_units(u32::MAX), 0);
        source.reference = 0;
        let p = Policy::new(&encoded(&[r]), source).unwrap();
        assert_eq!(p.group(0).unwrap().ceiling, 0);
        source.hardware_multiplier = 0;
        assert_eq!(source.hardware_units(17), 0);
        assert_eq!(udiv(123, 0), 0);
    }

    #[test]
    fn raw_scaling_byte_uses_nonzero_seed_but_exactly_one_write_condition() {
        let mut source = inputs();
        source.hardware_scale = 2;
        source.hardware_multiplier = 1000;
        source.quota_words[0] = 511;
        let p = Policy::new(&encoded(&[row(0, 1, 2)]), source).unwrap();
        let update = p.hardware_update(0).unwrap().unwrap();
        assert_eq!(p.rows()[0].seeded_limit(), 511_000);
        assert_eq!(update.target(), 511_000);
        assert_eq!(update.scaled_units(), 511_000);
        assert_ne!(update.scaled_units(), update.scaled_units() & QUOTA_MASK);
    }

    #[test]
    fn completed_hardware_and_response_clear_only_their_own_pending_work() {
        let mut p = policy(&[row(0, 1, 3), row(1, 1, 3), row(31, 2, 1)]);
        let response = p.response_block(0).unwrap().unwrap();
        assert_eq!(response.block(), 0);
        assert_eq!(response.dirty_mask(), 3);
        let other = p.response_block(7).unwrap().unwrap();
        assert_eq!(other.packed(), 64 << 48);
        p.complete_response(response).unwrap();
        assert_eq!(
            p.dirty_masks(),
            DirtyMasks {
                hardware: 0x8000_0003,
                responses: 0x8000_0000
            }
        );
        let update = p.hardware_update(0).unwrap().unwrap();
        assert_eq!(update.group(), 0);
        p.complete_hardware(update).unwrap();
        assert_eq!(p.dirty_masks().hardware, 0x8000_0002);
        p.complete_response(other).unwrap();
        assert!(p.response_block(0).unwrap().is_none());
        assert!(p.response_block(7).unwrap().is_none());
        assert!(p.hardware_update(0).unwrap().is_none());
        assert!(p.hardware_update(1).unwrap().is_some());
        assert!(p.hardware_update(31).unwrap().is_some());
    }

    #[test]
    fn stale_foreign_and_replayed_clears_refuse_without_changing_masks() {
        let mut a = policy(&[row(0, 1, 3)]);
        let mut b = policy(&[row(0, 1, 3)]);
        let before = b.dirty_masks();
        assert!(
            b.complete_hardware(a.hardware_update(0).unwrap().unwrap())
                .is_err()
        );
        assert!(
            b.complete_response(a.response_block(0).unwrap().unwrap())
                .is_err()
        );
        assert_eq!(b.dirty_masks(), before);
        let stale_hw = a.hardware_update(0).unwrap().unwrap();
        let stale_rsp = a.response_block(0).unwrap().unwrap();
        a.defaults().unwrap(); // Same values and dirty mask; new phase/revision.
        let before = a.dirty_masks();
        assert!(a.complete_hardware(stale_hw).is_err());
        assert!(a.complete_response(stale_rsp).is_err());
        assert_eq!(a.dirty_masks(), before);
        let hw1 = a.hardware_update(0).unwrap().unwrap();
        let hw2 = a.hardware_update(0).unwrap().unwrap();
        let rsp1 = a.response_block(0).unwrap().unwrap();
        let rsp2 = a.response_block(0).unwrap().unwrap();
        a.complete_hardware(hw1).unwrap();
        a.complete_response(rsp1).unwrap();
        assert!(a.complete_hardware(hw2).is_err());
        assert!(a.complete_response(rsp2).is_err());
        assert_eq!(
            a.dirty_masks(),
            DirtyMasks {
                hardware: 0,
                responses: 0
            }
        );
    }

    #[test]
    fn same_block_reallocation_invalidates_response_but_not_unchanged_hardware() {
        let mut p = policy(&[row(0, 1, 2), row(3, 1, 3)]);
        let hw = p.hardware_update(0).unwrap().unwrap();
        let response = p.response_block(0).unwrap().unwrap();
        p.set_request(3, 17).unwrap();
        p.allocate().unwrap();
        let before = p.dirty_masks();
        assert!(p.complete_response(response).is_err());
        assert_eq!(p.dirty_masks(), before);
        p.complete_hardware(hw).unwrap();
        assert_eq!(p.dirty_masks().hardware, 1 << 3);
    }

    #[test]
    fn malformed_tables_and_invalid_operations_are_atomic() {
        for group in [32, 0x10000, u32::MAX] {
            assert!(Policy::new(&encoded(&[row(group, 1, 2)]), inputs()).is_err());
        }
        for class in [0, 4, u32::MAX] {
            assert!(Policy::new(&encoded(&[row(0, 1, class)]), inputs()).is_err());
            assert!(Policy::new(&encoded(&[row(NO_GROUP, 1, class)]), inputs()).is_err());
        }
        for bytes in [vec![0; 1], vec![0; ROW_BYTES - 1], vec![0; ROW_BYTES + 1]] {
            assert!(Policy::new(&bytes, inputs()).is_err());
        }
        let mut p = policy(&[row(0, 1, 2)]);
        let before = (*p.group(0).unwrap(), p.dirty_masks(), p.inputs);
        assert!(p.set_request(32, 17).is_err());
        assert!(p.request_lane(32).is_err());
        assert!(p.hardware_update(32).is_err());
        assert!(p.response_block(8).is_err());
        assert_eq!((*p.group(0).unwrap(), p.dirty_masks(), p.inputs), before);
        p.revision = u64::MAX;
        assert!(p.defaults().is_err());
        assert!(p.allocate().is_err());
        assert_eq!((*p.group(0).unwrap(), p.dirty_masks(), p.inputs), before);
    }

    #[test]
    fn empty_source_table_has_no_synthesized_active_group_or_dirty_work() {
        let mut p = Policy::new(&[], inputs()).unwrap();
        p.allocate().unwrap();
        p.set_budget_payload(u64::MAX);
        p.defaults().unwrap();
        assert_eq!(p.active_groups(), 0);
        assert_eq!(
            p.dirty_masks(),
            DirtyMasks {
                hardware: 0,
                responses: 0
            }
        );
        assert!(p.rows().is_empty());
        for group in 0..GROUPS as u8 {
            assert!(p.group(group).is_none());
            assert!(p.hardware_update(group).unwrap().is_none());
        }
    }

    #[test]
    #[cfg(feature = "std")]
    #[ignore = "requires original T8112 PMP and J473 DT via STELA_TEST_PMP_T8112 and STELA_TEST_MCC_J473_DT"]
    fn original_t8112_cache_rows_seeds_defaults_and_allocator_match_source_windows() {
        use crate::machine::adt::Node;
        use sha2::{Digest, Sha256};
        let pmp = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&pmp)),
            "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
        );
        for (start, end, expected) in [
            (
                0x426c,
                0x472c,
                "e4971d2db1643fd5fa9412d278d2dbb1ea177f902bba9ec22d4dc41c0fd62a7b",
            ),
            (
                0x47a4,
                0x4cbc,
                "c65d5dc752b1592321cc44d79ed14fe0eb386cedb02d33772cfaa98bb0dd0966",
            ),
            (
                0x4cbc,
                0x4ee8,
                "9d7f54726ce6b42b4f802022a6f3fb0902a2a53cb1f57bdfb028513d67d99ad7",
            ),
            (
                0x4ee8,
                0x50b0,
                "d4a3edc6cb531a9edfc4f9882e79b380cf99198abc49634bce3019240d6ea873",
            ),
        ] {
            assert_eq!(hex::encode(Sha256::digest(&pmp[start..end])), expected);
        }
        let dt = std::fs::read(std::env::var("STELA_TEST_MCC_J473_DT").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&dt)),
            "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
        );
        let root = Node::root(&dt).unwrap();
        let raw = root
            .child("arm-io")
            .unwrap()
            .child("pmp")
            .unwrap()
            .child("iop-pmp-nub")
            .unwrap()
            .property("mcache-stream")
            .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(raw)),
            "1daa6222994ef3c8b22c87d2f4a3c3b2f224ec486093c42f8953a1544f1b8cab"
        );
        let word = |offset| u32::from_le_bytes(pmp[offset..offset + 4].try_into().unwrap());
        let mut source = inputs();
        source.budget = word(0x46f88);
        source.reference = word(0x46f88);
        source.hardware_scale = pmp[0x46f90];
        source.hardware_multiplier = word(0x46f94);
        source.feature_word = word(0x352b0);
        assert_eq!(
            (
                source.budget,
                source.reference,
                source.hardware_scale,
                source.hardware_multiplier,
                source.feature_word
            ),
            (64, 64, 0, 0, 0)
        );
        // Authored actual-owner input, deliberately not an original reset claim.
        source.quota_words = core::array::from_fn(|group| 0x400a_0100 + group as u32);
        let mut p = Policy::new(raw, source).unwrap();
        assert_eq!(p.rows().len(), 22);
        assert_eq!(p.active_groups().count_ones(), 16);
        assert_eq!(p.rows()[0].source_words()[7], 8192);
        assert_eq!(p.rows()[0].seeded_limit(), 266);
        assert_eq!(p.group(13).unwrap().row, 7);
        assert_eq!(p.group(14).unwrap().row, 11);
        assert_eq!(p.group(8).unwrap().row, 16);
        assert_eq!(p.group(1).unwrap().row, 19);
        let reencoded: Vec<u8> = p
            .rows()
            .iter()
            .flat_map(|row| {
                row.source_words()
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
            })
            .collect();
        assert_eq!(reencoded, raw);
        for group in 0..GROUPS as u8 {
            let eligible = p
                .group(group)
                .is_some_and(|slot| p.rows()[slot.row].class() != Class::Class1);
            assert_eq!(p.set_request(group, 0x2020).unwrap(), eligible);
        }
        clear_work(&mut p);
        p.allocate().unwrap();
        for group in [10, 4, 18, 2, 3, 11, 17, 13, 5, 7, 14] {
            assert_eq!(p.group(group).unwrap().assigned, 32);
            assert_eq!(
                p.group(group).unwrap().hardware_target,
                256 + u32::from(group)
            );
        }
        for group in [16, 15, 19] {
            assert_eq!(p.group(group).unwrap().assigned, 0);
            assert_eq!(p.group(group).unwrap().hardware_target, 0);
        }
        for group in [8, 1] {
            assert_eq!(p.group(group).unwrap().assigned, 256 + u32::from(group));
        }
    }
}
