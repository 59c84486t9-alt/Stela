//! Pure native cache quota policy, with requested and assigned limits distinct.
//!
//! Original 26A434 t8112pmp SHA256
//! b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//! VA100326c..1003664 joins raw44-byte rows to low9 quota seeds;
//! VA1003924..1003ab4 consumes low12 requests or low32 byte budget >>17;
//! VA1003ee8..10040b0 rebuilds defaults and allocates by source tier/class.
//! VA1003cbc..1003ee8 publishes low12 responses and programs scaled targets.
//! The source report is docs/research/apple-mcc.md, with original windows
//! in .stela/goal-20261022/memory/t8112-zero-pmp-contract-r1. No firmware runs.
//!
//! This owner computes policy only. Dirty snapshots describe work; they are
//! not hardware receipts. The caller must perform programming/publication
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

/// Supplied software configuration and kept source quota-word observations.
/// The caller owns their provenance and join to the quota resource;
/// numbers here never assert Apple reset state or cache capacity. The pinned
/// T8112 software defaults are budget/reference64, hardware_scale0,
/// hardware_multiplier0, feature_word0 and zero slot_flags. Seeds remain
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
    /// A64 UDIV's zero-divisor result. Keep this unmasked value for the source
    /// old-target comparison; word construction later masks low9.
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

/// Every original word/order/duplicate is held, including opaque+0x24 and
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
/// It grants no hardware permission and is neither Copy nor Clone.
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

/// Pending full64 four-lane response. Complete only after publication;
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

/// Pure policy. There is no Clone/reset-to-ready/effectful backend.
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
    /// Parse/check the complete source property before installing any state.
    /// Initial requested fields are zero. Runs defaults, not the
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

    /// Caller has consumed the source PTD/new-data metadata. Keep the full
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
    /// rebuilding defaults. Keep last-input lane provenance; these
    /// zeroes are software lifecycle effects, not newly received PTD lanes.
    /// Defaults publication and metric registration remain the caller's
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
    /// Class1/feature-kept groups do not enter the dynamic sums. Outputs
    /// remain dirty until service explicitly completes matching work.
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

    /// Clear only the matching completed hardware operation. A token
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
    /// Clear exactly the dirty members of a matching four-lane PTD
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
mod tests;
