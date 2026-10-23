use super::super::power::DeviceTable;
use super::{CounterReference, CounterSelection, Interpolation, McSelection};
use alloc::{vec, vec::Vec};

const SOURCE_IDS: [u32; 18] = [
    1, 2, 16, 17, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 18,
];

/// Registry ordinal, never a source ID or PMGR canonical domain number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ordinal(u8);
impl Ordinal {
    pub fn new(value: u8) -> Option<Self> {
        (value < 18).then_some(Self(value))
    }
    pub fn index(self) -> usize {
        usize::from(self.0)
    }
    pub fn bit(self) -> u64 {
        1 << self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slice {
    pub start: u32,
    pub count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hook {
    Initialize,
    Start,
    Stop,
    Capture,
    Postprocess,
    Trace,
}
/// Software configuration cells read by the original evaluator. A caller
/// applies the actual native registry write; these carry no hardware state.
/// The unqualified P18 freshness-arm producer is deliberately absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Configuration {
    Hysteresis(u32),
    PeriodShift(u32),
    FreshnessCheck(u8),
    AggregateResetFlag(u8),
}
impl Configuration {
    pub fn source_offset(self) -> u32 {
        match self {
            Self::Hysteresis(_) => 0x260,
            Self::PeriodShift(_) => 0x50,
            Self::FreshnessCheck(_) => 0x5c,
            Self::AggregateResetFlag(_) => 0x26,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Descriptor {
    pub(super) ordinal: Ordinal,
    pub(super) raw: [u32; 31],
    pub(super) aggregate: u64,
    pub(super) counters: Option<Slice>,
    pub(super) interrupt_class: u32,
    pub(super) mode: u32,
    pub(super) request_trace_id: u32,
    pub(super) controller: Option<u8>,
    pub(super) other_controllers: [Option<u8>; 4],
    pub(super) controller_states: u32,
    pub(super) provider: Option<u64>,
    pub(super) freshness_check: u8,
    pub(super) hysteresis: u32,
    pub(super) period_shift: u32,
    pub(super) observer: Option<u64>,
    pub(super) observer_write: u8,
    pub(super) aggregate_reset_flag: u8,
    pub(super) parent: Option<Ordinal>,
    pub(super) selection: CounterSelection,
    pub(super) interpolation: Option<Interpolation>,
    pub(super) hook_vas: [u64; 6],
}
impl Descriptor {
    pub fn ordinal(&self) -> Ordinal {
        self.ordinal
    }
    pub fn source_id(&self) -> u32 {
        self.raw[0]
    }
    pub fn raw_soc_device(&self) -> &[u32; 31] {
        &self.raw
    }
    pub fn aggregate_mask(&self) -> u64 {
        self.aggregate
    }
    pub fn counter_slice(&self) -> Option<Slice> {
        self.counters
    }
    pub fn selection(&self) -> &CounterSelection {
        &self.selection
    }
    pub fn state_provider(&self) -> Option<u64> {
        self.provider
    }
    pub fn interrupt_class(&self) -> u32 {
        self.interrupt_class
    }
    pub fn controller(&self) -> Option<u8> {
        self.controller
    }
    pub fn other_controllers(&self) -> [Option<u8>; 4] {
        self.other_controllers
    }
    pub fn other_controller_count(&self) -> usize {
        self.other_controllers
            .iter()
            .position(Option::is_none)
            .unwrap_or(4)
    }
    pub fn mode(&self) -> u32 {
        self.mode
    }
    pub fn observer(&self) -> Option<u64> {
        self.observer
    }
    pub fn hook_va(&self, hook: Hook) -> u64 {
        self.hook_vas[match hook {
            Hook::Initialize => 0,
            Hook::Start => 1,
            Hook::Stop => 2,
            Hook::Capture => 3,
            Hook::Postprocess => 4,
            Hook::Trace => 5,
        }]
    }
    pub(super) fn times(&self) -> (u32, u64) {
        // ARM LSL W32 masks its shift to5bits. Original1019c94..9cc8.
        let ticks = 1u32.wrapping_shl(self.period_shift.wrapping_add(9));
        (ticks / 3, (u64::from(ticks) * 0x38e38e39) >> 36)
    }
}

/// Actual joined source records plus a source-qualified native layout profile.
/// Labels and image hashes are evidence, never runtime dispatch keys.
#[derive(Clone, Debug)]
pub struct Profile {
    pub(super) descriptors: Vec<Descriptor>,
    pub(super) packet: Slice,
    pub(super) enabled: u64,
    pub(super) aggregates: u64,
}
impl Profile {
    /// ADT dvfs-domain is whole28-byte rows; controller indices are their dense
    /// ordinals. Source IDs and source state counts must resolve independently.
    pub fn t8112(
        table: &DeviceTable,
        dvfs_domains: &[u8],
        packet: Slice,
    ) -> Result<Self, &'static str> {
        if table.len() != 18
            || !table
                .records()
                .iter()
                .zip(SOURCE_IDS)
                .all(|(r, id)| r[0] == id)
        {
            return Err("native platform registry differs from qualified T8112 source ordinals");
        }
        if !dvfs_domains.len().is_multiple_of(28)
            || dvfs_domains.is_empty()
            || dvfs_domains.len() / 28 > 32
        {
            return Err("native DVFS domain property is not whole bounded source rows");
        }
        let domains: Vec<(u32, u32)> = dvfs_domains
            .as_chunks::<28>()
            .0
            .iter()
            .map(|r| {
                (
                    u32::from_le_bytes(r[..4].try_into().unwrap()),
                    u32::from_le_bytes(r[4..8].try_into().unwrap()),
                )
            })
            .collect();
        if domains.iter().enumerate().any(|(i, (id, count))| {
            *id == 0 || *count == 0 || *count > 16 || domains[..i].iter().any(|r| r.0 == *id)
        }) {
            return Err("native DVFS source IDs/state counts are ambiguous or unbounded");
        }
        let resolve = |id: u32| -> Result<Option<u8>, &'static str> {
            if id == 0 {
                Ok(None)
            } else {
                domains
                    .iter()
                    .position(|r| r.0 == id)
                    .map(|x| Some(x as u8))
                    .ok_or("native SOC descriptor has no joined DVFS domain")
            }
        };
        let mut descriptors = Vec::new();
        let mut next = packet.start;
        let mut enabled = 0;
        let mut aggregates = 0;
        for (i, raw) in table.records().iter().copied().enumerate() {
            let ordinal = Ordinal(i as u8);
            let aggregate = match i {
                1 => 0xf9f0,
                0 | 2 | 3 => 0xfff0,
                _ => 0,
            };
            if raw[2] & 1 != 0 {
                enabled |= ordinal.bit();
            }
            if aggregate != 0 {
                aggregates |= ordinal.bit();
            }
            let count = raw[3]
                .checked_mul(8)
                .ok_or("native SOC counter slice overflow")?;
            if count > 128 {
                return Err("native platform slice exceeds two evaluator words");
            }
            let counters = if count == 0 {
                None
            } else {
                let s = Slice { start: next, count };
                next = next
                    .checked_add(count)
                    .ok_or("native SOC counter prefix overflow")?;
                Some(s)
            };
            let controller = resolve(raw[6])?;
            let mut others = [None; 4];
            for (j, other) in others.iter_mut().enumerate() {
                *other = resolve(raw[7 + j])?;
            }
            let controller_states = controller.map_or(0, |x| domains[usize::from(x)].1);
            let mode = if matches!(raw[11], 1 | 2) { raw[11] } else { 0 };
            if mode == 1 && (i != 8 || controller_states != 3) {
                return Err("native mode1 needs its qualified joined interpolation table");
            }
            let freshness_check = u8::from(i == 4 || i == 5);
            let mut selection = CounterSelection::initialized(source_references(i), 0)?;
            if i == 1 {
                let control = core::array::from_fn(|j| CounterReference::local(j as u32 * 32, 32));
                let result = McSelection::resolve(selection.bits(), 2, raw[3], 2, 3, &control)?;
                selection.replace(result.desired);
            }
            descriptors.push(Descriptor {
                ordinal,
                raw,
                aggregate,
                counters,
                interrupt_class: if aggregate != 0 {
                    0
                } else {
                    2 + u32::from(freshness_check != 0)
                },
                mode,
                request_trace_id: match i {
                    4 => 0x86090380,
                    5 => 0x86090400,
                    6 => 0x86090480,
                    7 => 0x86090500,
                    _ => 0,
                },
                controller,
                other_controllers: others,
                controller_states,
                provider: match i {
                    4 => Some(0x1044ca0),
                    5 => Some(0x1044e00),
                    6 => Some(0x1044ea8),
                    _ => None,
                },
                freshness_check,
                hysteresis: 0,
                period_shift: 0,
                observer: match i {
                    9 => Some(0x23b710000),
                    10 => Some(0x23b7003c8),
                    _ => None,
                },
                observer_write: 0,
                aggregate_reset_flag: 0,
                parent: if matches!(i, 0..=3 | 16) {
                    None
                } else {
                    Some(Ordinal(1))
                },
                selection,
                interpolation: if mode == 1 {
                    Some(Interpolation::initialized(vec![300, 427, 533])?)
                } else {
                    None
                },
                hook_vas: hooks(i),
            });
        }
        if next
            != packet
                .start
                .checked_add(packet.count)
                .ok_or("native packet range overflow")?
        {
            return Err("native SOC counter slices do not cover actual packet range");
        }
        Ok(Self {
            descriptors,
            packet,
            enabled,
            aggregates,
        })
    }
    pub fn descriptors(&self) -> &[Descriptor] {
        &self.descriptors
    }
    pub fn source_enabled(&self) -> u64 {
        self.enabled
    }
    pub fn aggregate_pass(&self) -> u64 {
        self.aggregates
    }
    pub fn packet_slice(&self) -> Slice {
        self.packet
    }
}
fn hooks(i: usize) -> [u64; 6] {
    let mut result = [
        0x10196cc, 0x101a68c, 0x101a61c, 0x101a780, 0x101ab30, 0x101b074,
    ];
    match i {
        0 => {
            result[0] = 0x10156c4;
            result[3..].copy_from_slice(&[0x1015d8c, 0x1015ecc, 0x101639c]);
        }
        1 => {
            result[0] = 0x1004654;
            result[3..].copy_from_slice(&[0x1004894, 0x10049b0, 0x1004b50]);
        }
        6 => {
            result[0] = 0x101dca0;
            result[3..].copy_from_slice(&[0x101e13c, 0x101e25c, 0x101e424]);
        }
        7 => {
            result[0] = 0x1018d58;
            result[3..].copy_from_slice(&[0x101905c, 0x101918c, 0x101940c]);
        }
        _ => {}
    }
    result
}

// Semantic24-byte counter reference facts, not binary configuration blobs.
// The profile retains nonlocal/provider references too; only kind2/provider0
// contributes local desired bits. Source locations are in the pinned ledger.
fn source_references(ordinal: usize) -> Vec<CounterReference> {
    source_rows(ordinal)
        .iter()
        .map(
            |&(kind, provider, start, width, flags, scale)| CounterReference {
                kind,
                provider,
                start,
                width,
                flags,
                scale,
            },
        )
        .collect()
}
type ReferenceRow = (u32, u32, u32, u32, u32, u32);
fn source_rows(ordinal: usize) -> &'static [ReferenceRow] {
    match ordinal {
        0 => &[
            (1, 0, 0, 0, 0, 0x28000001),
            (1, 0, 1, 0, 0, 0x28000001),
            (1, 2, 0, 0, 1, 0xec000004),
            (1, 3, 0, 0, 1, 0xec000004),
            (1, 1, 1, 0, 0, 0),
            (1, 1, 0, 0, 0, 0),
        ],
        1 => &[
            (2, 0, 0, 32, 1, 0x18000001),
            (2, 0, 32, 32, 1, 0x18000001),
            (1, 0, 0, 0, 0, 1),
            (1, 0, 1, 0, 0, 0x48000001),
            (2, 0, 512, 32, 0, 1),
            (1, 0, 3, 0, 0, 0x48000001),
            (2, 0, 576, 32, 0, 0x8000001),
            (2, 0, 608, 32, 0, 0x8000001),
            (1, 0, 6, 0, 0, 1),
            (1, 0, 7, 0, 0, 1),
            (2, 0, 640, 32, 0, 1),
            (2, 0, 672, 32, 0, 1),
            (1, 0, 10, 0, 0, 1),
            (1, 0, 11, 0, 0, 1),
            (2, 0, 704, 32, 0, 1),
            (2, 0, 736, 32, 0, 1),
            (1, 0, 16, 0, 0, 1),
            (1, 0, 17, 0, 0, 1),
            (1, 0, 20, 0, 0, 1),
            (1, 0, 21, 0, 0, 1),
            (1, 0, 22, 0, 0, 1),
            (1, 0, 23, 0, 0, 1),
            (1, 0, 24, 0, 0, 1),
            (1, 0, 25, 0, 0, 1),
            (1, 0, 28, 0, 0, 1),
            (1, 0, 29, 0, 0, 1),
            (2, 0, 768, 32, 0, 1),
            (2, 0, 800, 32, 0, 1),
            (1, 0, 32, 0, 0, 1),
            (1, 0, 33, 0, 0, 1),
            (1, 0, 34, 0, 0, 1),
            (1, 0, 35, 0, 0, 1),
            (2, 0, 832, 32, 0, 1),
            (2, 0, 864, 32, 0, 1),
            (1, 0, 38, 0, 0, 1),
            (1, 0, 39, 0, 0, 1),
            (2, 0, 896, 32, 0, 1),
            (2, 0, 928, 32, 0, 1),
            (1, 0, 42, 0, 0, 1),
            (1, 0, 43, 0, 0, 1),
            (1, 0, 44, 0, 0, 1),
            (1, 0, 45, 0, 0, 1),
            (1, 0, 46, 0, 0, 1),
            (1, 0, 47, 0, 0, 1),
            (1, 0, 48, 0, 0, 1),
            (2, 0, 0, 32, 0, 0x18000001),
            (2, 0, 32, 32, 0, 0x18000001),
            (1, 1, 0, 0, 0, 0x18000001),
            (1, 1, 1, 0, 0, 0x18000001),
            (2, 0, 64, 32, 0, 0x18000001),
            (2, 0, 96, 32, 0, 0x18000001),
            (2, 0, 192, 32, 0, 0x18000001),
            (2, 0, 224, 32, 0, 0x18000001),
            (2, 0, 128, 32, 0, 0x18000001),
            (2, 0, 160, 32, 0, 0x18000001),
            (1, 1, 8, 0, 0, 0x18000001),
            (1, 1, 9, 0, 0, 0x18000001),
            (1, 1, 10, 0, 0, 0x18000001),
            (1, 1, 11, 0, 0, 0x18000001),
            (1, 1, 12, 0, 0, 0x18000001),
            (1, 1, 13, 0, 0, 0x18000001),
            (1, 1, 14, 0, 0, 0x18000001),
            (1, 1, 15, 0, 0, 0x18000001),
            (1, 2, 0, 0, 0, 0x18000001),
            (1, 2, 1, 0, 0, 0x18000001),
            (1, 2, 2, 0, 0, 0x18000001),
            (1, 2, 3, 0, 0, 0x18000001),
            (1, 2, 4, 0, 0, 0x18000001),
            (1, 2, 5, 0, 0, 0x18000001),
            (1, 2, 6, 0, 0, 0x18000001),
            (1, 2, 7, 0, 0, 0x18000001),
            (1, 2, 8, 0, 0, 0x18000001),
            (1, 2, 9, 0, 0, 0x18000001),
            (1, 2, 10, 0, 0, 0x18000001),
            (1, 2, 11, 0, 0, 0x18000001),
            (1, 2, 12, 0, 0, 0x18000001),
            (1, 2, 13, 0, 0, 0x18000001),
            (1, 2, 14, 0, 0, 0x18000001),
            (1, 2, 15, 0, 0, 0x18000001),
            (1, 3, 0, 0, 0, 0x18000001),
            (1, 3, 1, 0, 0, 0x18000001),
            (1, 3, 2, 0, 0, 0x18000001),
            (1, 3, 3, 0, 0, 0x18000001),
            (1, 3, 4, 0, 0, 0x18000001),
            (1, 3, 5, 0, 0, 0x18000001),
            (1, 3, 6, 0, 0, 0x18000001),
            (1, 3, 7, 0, 0, 0x18000001),
            (1, 3, 8, 0, 0, 0x18000001),
            (1, 3, 9, 0, 0, 0x18000001),
        ],
        2 => &[(4, 0, 0, 0, 0, 0), (1, 0, 7, 0, 0, 0)],
        3 => &[(4, 0, 0, 0, 0, 0), (1, 0, 9, 0, 0, 0), (1, 0, 8, 0, 0, 0)],
        4 => &[
            (3, 0, 2, 0, 1, 0),
            (3, 0, 3, 0, 0, 0),
            (3, 0, 47, 0, 1, 0),
            (3, 0, 48, 0, 1, 0),
        ],
        5 => &[
            (3, 0, 0, 0, 0, 0),
            (3, 0, 1, 0, 0, 0),
            (3, 0, 45, 0, 0, 0),
            (3, 0, 46, 0, 0, 0),
        ],
        6 => &[
            (3, 0, 4, 0, 1, 0),
            (3, 0, 5, 0, 1, 0),
            (3, 0, 49, 0, 1, 0),
            (3, 0, 50, 0, 1, 0),
            (2, 0, 256, 32, 1, 0),
            (2, 0, 288, 32, 1, 0),
            (2, 0, 320, 32, 1, 0),
            (2, 0, 352, 32, 1, 0),
        ],
        7 => &[
            (3, 0, 8, 0, 1, 0),
            (3, 0, 9, 0, 1, 0),
            (3, 0, 51, 0, 1, 0),
            (3, 0, 52, 0, 1, 0),
            (2, 0, 256, 32, 1, 0),
            (2, 0, 288, 32, 1, 0),
            (2, 0, 320, 32, 1, 0),
            (2, 0, 352, 32, 1, 0),
            (2, 0, 384, 32, 1, 0),
            (2, 0, 416, 32, 1, 0),
            (2, 0, 448, 32, 1, 0),
        ],
        8 => &[
            (3, 0, 35, 0, 1, 0),
            (3, 0, 73, 0, 0, 0),
            (3, 0, 74, 0, 0, 0),
            (1, 0, 0, 0, 1, 0xec000004),
            (1, 1, 0, 0, 1, 0xec000004),
        ],
        9 => &[
            (3, 0, 32, 0, 0, 0),
            (3, 0, 33, 0, 0, 0),
            (3, 0, 71, 0, 0, 0),
            (3, 0, 72, 0, 0, 0),
            (4, 0, 0, 0, 0, 0),
            (1, 0, 3, 0, 0, 0),
            (1, 0, 2, 0, 0, 0),
        ],
        10 => &[
            (3, 0, 16, 0, 0, 0),
            (3, 0, 17, 0, 0, 0),
            (3, 0, 59, 0, 0, 0),
            (3, 0, 60, 0, 0, 0),
            (4, 0, 0, 0, 0, 0),
            (1, 0, 5, 0, 0, 0),
            (1, 0, 4, 0, 0, 0),
        ],
        11 => &[
            (3, 0, 30, 0, 1, 0),
            (3, 0, 31, 0, 1, 0),
            (3, 0, 69, 0, 0, 0),
            (3, 0, 70, 0, 0, 0),
            (1, 0, 0, 0, 1, 0xec000004),
        ],
        12 => &[
            (3, 0, 12, 0, 1, 0),
            (3, 0, 13, 0, 1, 0),
            (3, 0, 55, 0, 0, 0),
            (3, 0, 56, 0, 0, 0),
            (4, 0, 0, 0, 0, 0),
            (1, 0, 6, 0, 0, 0),
            (1, 0, 6, 0, 0, 0),
        ],
        13 => &[
            (3, 0, 37, 0, 0, 0),
            (3, 0, 77, 0, 0, 0),
            (3, 0, 78, 0, 0, 0),
            (1, 0, 0, 0, 1, 0xec000004),
        ],
        14 => &[
            (3, 0, 36, 0, 0, 0),
            (3, 0, 75, 0, 0, 0),
            (3, 0, 76, 0, 0, 0),
        ],
        15 => &[
            (3, 0, 20, 0, 0, 0),
            (3, 0, 21, 0, 0, 0),
            (3, 0, 63, 0, 0, 0),
            (3, 0, 64, 0, 0, 0),
        ],
        _ => &[],
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(crate) fn fixture() -> Profile {
        let records: Vec<u8> = SOURCE_IDS
            .iter()
            .enumerate()
            .flat_map(|(i, id)| {
                let mut r = [0u32; 31];
                r[0] = *id;
                r[2] = if i == 16 { 0 } else { 1 };
                r[3] = match i {
                    1 => 14,
                    4..=7 => 1,
                    _ => 0,
                };
                r[6] = match i {
                    0 => 1,
                    1..=3 | 8 | 11..=15 | 17 => 2,
                    9 | 10 => 3,
                    _ => 0,
                };
                r[7] = if matches!(i, 4..=7 | 9 | 10) { 2 } else { 0 };
                r[11] = match i {
                    0..=3 => 0,
                    8 => 1,
                    _ => 2,
                };
                r.into_iter().flat_map(u32::to_le_bytes)
            })
            .collect();
        let table =
            DeviceTable::from_properties(&records, &0x3fff0u64.to_le_bytes(), None).unwrap();
        let dvfs: Vec<u8> = [(1, 5), (2, 3), (3, 4)]
            .into_iter()
            .flat_map(|(id, count)| {
                [id, count, 0, 0, 0, 0, 0]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
            })
            .collect();
        Profile::t8112(
            &table,
            &dvfs,
            Slice {
                start: 16,
                count: 144,
            },
        )
        .unwrap()
    }
    #[test]
    fn joined_profile_keeps_actual_ordinals_slices_provider_and_counter_references() {
        let p = fixture();
        assert_eq!((p.enabled, p.aggregates), (0x2ffff, 15));
        assert_eq!(p.descriptors[1].aggregate, 0xf9f0);
        assert_eq!(
            p.descriptors[1].counters,
            Some(Slice {
                start: 16,
                count: 112
            })
        );
        assert_eq!(
            p.descriptors[4].counters,
            Some(Slice {
                start: 128,
                count: 8
            })
        );
        assert_eq!(p.descriptors[4].selection.bits(), 0);
        assert_eq!(p.descriptors[6].selection.bits(), 0x30);
        assert_eq!(p.descriptors[7].selection.bits(), 0xf0);
        assert_eq!(p.descriptors[1].selection.bits() & 0xffff, 0x7f0f);
        assert_eq!(p.descriptors[4].provider, Some(0x1044ca0));
        assert!(p.descriptors[8].interpolation.is_some());
        assert_eq!(p.descriptors[9].observer, Some(0x23b710000));
        assert_eq!(p.descriptors[10].observer, Some(0x23b7003c8));
        assert_eq!(p.descriptors[0].times(), (170, 7));
    }
    #[test]
    #[cfg(feature = "std")]
    #[ignore = "requires original T8112 PMP and J473 DT via STELA_TEST_PMP_T8112 and STELA_TEST_MCC_J473_DT"]
    fn original_t8112_join_and_selection_match_every_native_counter_reference() {
        use crate::machine::adt::Node;
        use sha2::{Digest, Sha256};
        let pmp = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&pmp)),
            "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
        );
        let dt = std::fs::read(std::env::var("STELA_TEST_MCC_J473_DT").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&dt)),
            "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
        );
        let root = Node::root(&dt).unwrap();
        let nub = root
            .child("arm-io")
            .unwrap()
            .child("pmp")
            .unwrap()
            .child("iop-pmp-nub")
            .unwrap();
        let table = DeviceTable::from_properties(
            nub.property("soc-device").unwrap(),
            nub.property("soc-device-ps-group").unwrap(),
            nub.property("soc-device-die-offset"),
        )
        .unwrap();
        let profile = Profile::t8112(
            &table,
            nub.property("dvfs-domain").unwrap(),
            Slice {
                start: 16,
                count: 144,
            },
        )
        .unwrap();
        let configs = [
            0x1046698, 0x1046ab8, 0x104a868, 0x104abc8, 0x10477d0, 0x1047b08, 0x1047e18, 0x1048410,
            0x1048810, 0x1048c48, 0x1049080, 0x10494b8, 0x1049728, 0x1049a88, 0x1049cf8, 0x1049f68,
            0x104a5f8, 0x104a2b0,
        ];
        let word = |va: usize| {
            u32::from_le_bytes(pmp[va - 0xfff000..va - 0xfff000 + 4].try_into().unwrap())
        };
        let pointer = |va: usize| {
            u64::from_le_bytes(pmp[va - 0xfff000..va - 0xfff000 + 8].try_into().unwrap()) as usize
        };
        let reference = |va: usize| CounterReference {
            kind: word(va),
            provider: word(va + 4),
            start: word(va + 8),
            width: word(va + 12),
            flags: word(va + 16),
            scale: word(va + 20),
        };
        for (i, cfg) in configs.into_iter().enumerate() {
            let mut refs: Vec<_> = (0x8c..0x14c)
                .step_by(24)
                .map(|off| reference(cfg + off))
                .collect();
            let table = pointer(cfg + 0x248);
            if table != 0 {
                for row in 0..word(cfg + 0x240) as usize {
                    refs.extend([
                        reference(table + row * 0xf0 + 0xb4),
                        reference(table + row * 0xf0 + 0xcc),
                    ]);
                }
            }
            if i == 1 {
                refs.extend((0..12).map(|j| reference(cfg + 0x27c + j * 24)));
                refs.extend(
                    (0..word(cfg + 0x39c) as usize)
                        .map(|j| reference(pointer(cfg + 0x3a0) + j * 24)),
                );
            }
            if i == 6 || i == 7 {
                refs.extend(
                    (0..if i == 6 { 4 } else { 7 }).map(|j| reference(cfg + 0x270 + j * 24)),
                );
            }
            refs.retain(|r| r.kind != 0);
            assert_eq!(profile.descriptors[i].selection.references(), refs);
        }
        assert_eq!(
            profile.descriptors[1].selection.bits(),
            fixture().descriptors[1].selection.bits()
        );
        assert_eq!(
            (word(0x1048ab0), word(0x1048ab4), word(0x1048ab8)),
            (300, 427, 533)
        );
    }
}
