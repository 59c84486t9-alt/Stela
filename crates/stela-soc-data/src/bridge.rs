//! Immutable fabric-bridge register roles and validated counter geometry.
//! Layout construction describes offsets, widths and command encodings only.
//! Live kept words, knownness, MMIO writes and completion stay device-owned.
use crate::Result;
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use stela_contracts::bus::Width;
use stela_contracts::refuse;
pub const CONFIG_BYTES: usize = 36;
const SELECTOR_BASE: u64 = 8;
const EVENT_SELECTOR: u64 = 0x208;
const HISTOGRAM_MASK: u64 = 0x280;
const BOUNDARY_BASE: u64 = 0x288;
const BOUNDARY_STRIDE: u64 = 0x18;
const HISTOGRAM_ENABLE: u64 = 0x2b8;
const EVENT_INIT: u64 = 0x2bc;
const EVENT_ENABLE: u64 = 0x2c0;
const SIMPLE_INIT: u64 = 0x14;
const SIMPLE_ENABLE: u64 = 0x18;
const SIMPLE_COUNT: u64 = 0x4000;
const LATENCY_MAX: u64 = 0x4200;
const LATENCY_MIN: u64 = 0x4230;
const EVENT_SUM: u64 = 0x4260;
const HISTOGRAM_BINS: u64 = 0x4290;
const HISTOGRAM_BINS_STRIDE: u64 = 0x30;
const EMPTY: u64 = 0;
const EMPTY_MINIMUM: u64 = u64::MAX;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Configuration,
    Initialize(u32),
    /// A read-only 64-bit accumulator, holding its empty value.
    Sample(u64),
}

#[derive(Debug, Clone)]
pub struct Layout {
    words: BTreeMap<u64, Role>,
    counter_enables: BTreeSet<u64>,
    tuning_masks: BTreeMap<u64, u32>,
}
impl Layout {
    pub fn new(
        fields: &[(u64, u32)],
        header: [u8; 4],
        configs: &[[u8; CONFIG_BYTES]],
        axi: Option<[u8; 4]>,
    ) -> Result<Self> {
        Self::configuration(fields, header, configs, axi, 1)
    }
    fn configuration(
        fields: &[(u64, u32)],
        header: [u8; 4],
        configs: &[[u8; CONFIG_BYTES]],
        axi: Option<[u8; 4]>,
        max_side: u8,
    ) -> Result<Self> {
        let mut words = BTreeMap::new();
        let mut counter_enables = BTreeSet::new();
        for &(offset, _) in fields {
            if !offset.is_multiple_of(4) {
                return Err(refuse!("unaligned bridge tuning field"));
            }
            words.insert(offset, Role::Configuration);
        }
        let bank = u64::from(u16::from_le_bytes([header[0], header[1]]));
        if header[3] != 0 {
            if bank & 3 != 0 || configs.len() != usize::from(header[3]) {
                return Err(refuse!(
                    "unsupported bridge counter flags or partial config selection"
                ));
            }
            for o in [0x410, 0x420, 0x430, bank] {
                words.insert(o, Role::Configuration);
            }
            let mut simple = 0;
            let mut event = 0;
            for config in configs {
                let slot = config[2];
                if slot >= 32 || config[0] > max_side || config[10] > 6 || config[3] > 1 {
                    return Err(refuse!(
                        "unsupported bridge counter selector, side or histogram layout"
                    ));
                }
                let at = |base: u64| bank + base + 8 * u64::from(slot);
                if config[3] == 0 {
                    words.insert(at(SIMPLE_COUNT), Role::Sample(EMPTY));
                    let select = axi.map_or(0x834, |a| u64::from(a[1]) | u64::from(a[3]) << 8);
                    words.insert(select, Role::Configuration);
                    words.insert(
                        bank + SELECTOR_BASE + 4 * u64::from(slot),
                        Role::Configuration,
                    );
                    simple |= 1 << slot;
                } else {
                    // Version3 event 2/3 also programs an upstream selector.
                    if matches!(config[1], 2 | 3) {
                        let base = u16::from_le_bytes([config[8], config[9]]);
                        let base = if base == 0 { 0x748 } else { u64::from(base) };
                        words.insert(base + 0x60 * u64::from(config[0]), Role::Configuration);
                        words.insert(at(LATENCY_MAX), Role::Sample(EMPTY));
                        words.insert(at(LATENCY_MIN), Role::Sample(EMPTY_MINIMUM));
                        words.insert(at(EVENT_SUM), Role::Sample(EMPTY));
                        for i in 0..config[10] {
                            words.insert(
                                bank + HISTOGRAM_BINS
                                    + HISTOGRAM_BINS_STRIDE * u64::from(slot)
                                    + 8 * u64::from(i),
                                Role::Sample(EMPTY),
                            );
                        }
                    }
                    words.insert(
                        bank + EVENT_SELECTOR + 4 * u64::from(slot),
                        Role::Configuration,
                    );
                    if config[1] == 0 {
                        for o in [0x408, 0x418, 0x41c, 0x420, 0x424, 0x428] {
                            words.insert(bank + o, Role::Configuration);
                        }
                        words.insert(at(EVENT_SUM), Role::Sample(EMPTY));
                    }
                    if config[10] != 0 {
                        words.insert(
                            bank + HISTOGRAM_MASK + 4 * u64::from(slot),
                            Role::Configuration,
                        );
                        for k in 0..config[10] {
                            words.insert(
                                bank + BOUNDARY_BASE
                                    + BOUNDARY_STRIDE * u64::from(slot)
                                    + 4 * u64::from(k),
                                Role::Configuration,
                            );
                        }
                    }
                    if config[1] == 0 || config[11] != 0 {
                        words.insert(bank + HISTOGRAM_ENABLE, Role::Configuration);
                        counter_enables.insert(bank + HISTOGRAM_ENABLE);
                    }
                    event |= 1 << slot;
                }
            }
            if simple != 0 {
                words.insert(bank + SIMPLE_INIT, Role::Initialize(simple));
                words.insert(bank + SIMPLE_ENABLE, Role::Configuration);
                counter_enables.insert(bank + SIMPLE_ENABLE);
            }
            if event != 0 {
                words.insert(bank + EVENT_INIT, Role::Initialize(event));
                words.insert(bank + EVENT_ENABLE, Role::Configuration);
                counter_enables.insert(bank + EVENT_ENABLE);
            }
        } else if !configs.is_empty() {
            return Err(refuse!(
                "bridge without counters has selected counter configurations"
            ));
        }
        Ok(Self {
            words,
            counter_enables,
            tuning_masks: fields.iter().copied().collect(),
        })
    }
    /// Original T6000 version3 side field accepts the complete source byte.
    /// DT view extents must be checked independently by the parser.
    pub fn t6000(
        fields: &[(u64, u32)],
        header: [u8; 4],
        configs: &[[u8; CONFIG_BYTES]],
        axi: Option<[u8; 4]>,
    ) -> Result<Self> {
        Self::configuration(fields, header, configs, axi, u8::MAX)
    }
    pub fn counter_enables(&self) -> impl Iterator<Item = u64> + '_ {
        self.counter_enables.iter().copied()
    }
    pub fn is_counter_enable(&self, offset: u64) -> bool {
        self.counter_enables.contains(&offset)
    }
    pub fn tuning_mask(&self, offset: u64) -> Option<u32> {
        self.tuning_masks.get(&offset).copied()
    }
    /// Each described register as (offset, bytes).
    pub fn spans(&self) -> Vec<(u64, u64)> {
        self.words
            .iter()
            .map(|(&o, role)| (o, role.width().bytes()))
            .collect()
    }
    pub fn role(&self, o: u64, w: Width) -> Result<Role> {
        let role = self.words.get(&o).copied().ok_or(refuse!(
            "fabric bridge word has no described configuration or sample contract"
        ))?;
        if w != role.width() {
            return Err(refuse!(
                "fabric bridge configuration is full32 and samples are full64"
            ));
        }
        Ok(role)
    }
}
impl Role {
    pub fn width(self) -> Width {
        match self {
            Role::Sample(_) => Width::Double,
            _ => Width::Word,
        }
    }
}

pub mod tunables;
