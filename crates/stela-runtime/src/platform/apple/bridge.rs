//! Generic fabric bridge configuration, not a device-name dispatch model.
//! DT `bridge-reg-index` + bridge number selects `reg`; `bridge-counters`
//! headers select 36-byte `bridge-counter-configs` records and bank offsets.
//! The SoC layout catalog contains only the hardware register fields decoded
//! from `applyBridgeTunables` (kernel file 0x2fa6590), its descriptor lists,
//! and `_tunableh_apply_configuration` (0x2bbb64c). Configuration is a masked
//! RMW performed by software: each described full32 word retains all writes.
//!
//! Version3 event configuration follows `_enableBridgeEventCounters`
//! (0x2b96214..0x2b96b6c). Selector/filter/limit/boundary words are retained;
//! +0x14/+0x2bc accept only the selected initialization bitmap. Their readback
//! and electrical pulse/ack lifecycle are not established, so reads refuse.
//! Bit3 of the global configuration is retained: the survey does not
//! establish a self-clearing status bit.
//!
//! `_saveBridgeEventCounters` (0xfffffe0009b9aec0) samples each selected
//! counter with single 64-bit loads from bank+0x4000: a simple counter's
//! count at +0x4000+8s; a latency event's max, min and sum at +0x4200,
//! +0x4230 and +0x4260 (+8s) and its `rec[10]` histogram bins at
//! +0x4290+0x30s+8i; a bandwidth-filter event's count at +0x4260+8s. The
//! values only feed IOReporters. The emulated fabric carries no traffic,
//! so every accumulator is empty: counts, sums, maxima and bins read 0, and
//! a minimum reads all ones. The kernel seeds its own minimum with that
//! value (0xfffffe00076e1d70) and keeps min(stored, sample), so an empty
//! sample leaves its no-sample state. The hardware's empty minimum is
//! inferred, not recovered. Samples are read-only. Other widths and
//! unselected slots refuse.
//!
//! T6000 uses its separate source-selected field catalog and explicit supplied
//! handoff image. Unprovided configuration/sample words refuse; source masks
//! cannot supply preserved bits. Native counter enabling/reset retirement
//! remain explicit refusals, so no empty accumulator or readiness is invented.
//!
//! Stela's existing T8112 model hands off zero idle/disabled configuration, without conditional iBoot
//! tuning. Header flag variants, other layouts and unknown registers refuse.
use super::regfile::Held;
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError, stela_contracts::bus::Width,
    stela_contracts::bus::refuse,
};
pub mod tunables;
const NAME: &str = "fabric-bridge";
const CONFIG_BYTES: usize = 36;
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
enum Role {
    Configuration,
    Initialize(u32),
    /// A read-only 64-bit accumulator, holding its empty value.
    Sample(u64),
}
#[derive(Debug, Clone)]
pub struct Bridge {
    words: BTreeMap<u64, Role>,
    values: Held,
    known: Option<BTreeSet<u64>>,
    counter_enables: BTreeSet<u64>,
    tuning_masks: BTreeMap<u64, u32>,
}
impl Bridge {
    pub fn new(
        fields: &[(u64, u32)],
        header: [u8; 4],
        configs: &[[u8; CONFIG_BYTES]],
        axi: Option<[u8; 4]>,
    ) -> Result<Self, &'static str> {
        Self::configuration(fields, header, configs, axi, 1)
    }
    fn configuration(
        fields: &[(u64, u32)],
        header: [u8; 4],
        configs: &[[u8; CONFIG_BYTES]],
        axi: Option<[u8; 4]>,
        max_side: u8,
    ) -> Result<Self, &'static str> {
        let mut words = BTreeMap::new();
        let mut counter_enables = BTreeSet::new();
        for &(offset, _) in fields {
            if !offset.is_multiple_of(4) {
                return Err("unaligned bridge tuning field");
            }
            words.insert(offset, Role::Configuration);
        }
        let bank = u64::from(u16::from_le_bytes([header[0], header[1]]));
        if header[3] != 0 {
            if bank & 3 != 0 || configs.len() != usize::from(header[3]) {
                return Err("unsupported bridge counter flags or partial config selection");
            }
            for o in [0x410, 0x420, 0x430, bank] {
                words.insert(o, Role::Configuration);
            }
            let mut simple = 0;
            let mut event = 0;
            for config in configs {
                let slot = config[2];
                if slot >= 32 || config[0] > max_side || config[10] > 6 || config[3] > 1 {
                    return Err("unsupported bridge counter selector, side or histogram layout");
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
            return Err("bridge without counters has selected counter configurations");
        }
        Ok(Self {
            words,
            values: Held::default(),
            known: None,
            counter_enables,
            tuning_masks: fields.iter().copied().collect(),
        })
    }
    /// Actual T6000 source-selected fields and supplied handoff words. Missing
    /// values stay unknown. Captured disabled samples may be read, but this
    /// model cannot enable a native fabric event source or retire its reset.
    pub fn t6000(
        profile: super::pmgr::t6000::tunables::Profile,
        id: usize,
        header: [u8; 4],
        configs: &[[u8; CONFIG_BYTES]],
        axi: Option<[u8; 4]>,
        image: &[(u64, Width, u64)],
    ) -> Result<Self, &'static str> {
        let fields = profile.fields(id)?;
        // Native M1 version3 programming zero-extends the whole side byte at
        // kernel 0x2b3a674, then computes base + 0x60*side. J314s actually
        // supplies side3. Final spans must still fit each actual DT view.
        let mut model = Self::configuration(&fields, header, configs, axi, u8::MAX)?;
        let mut known = BTreeSet::new();
        for &(offset, width, value) in image {
            let role = model.role(offset, width)?;
            if matches!(role, Role::Initialize(_)) {
                return Err("T6000 bridge command image has no qualified readback");
            }
            if value & !width.mask() != 0 || !known.insert(offset) {
                return Err("T6000 bridge image has an oversized or duplicate word");
            }
            if model.counter_enables.contains(&offset) && value != 0 {
                return Err("T6000 bridge handoff has enabled unowned counter effects");
            }
            model.values.set(offset, value);
        }
        model.known = Some(known);
        Ok(model)
    }

    /// Each described register as (offset, bytes).
    pub fn spans(&self) -> Vec<(u64, u64)> {
        self.words
            .iter()
            .map(|(&o, role)| (o, role.width().bytes()))
            .collect()
    }
    fn role(&self, o: u64, w: Width) -> Result<Role, &'static str> {
        let role = self
            .words
            .get(&o)
            .copied()
            .ok_or("fabric bridge word has no described configuration or sample contract")?;
        if w != role.width() {
            return Err("fabric bridge configuration is full32 and samples are full64");
        }
        Ok(role)
    }
}
impl Role {
    fn width(self) -> Width {
        match self {
            Role::Sample(_) => Width::Double,
            _ => Width::Word,
        }
    }
}
impl MmioDevice for Bridge {
    fn advance_policy(&self) -> super::bus::AdvancePolicy {
        super::bus::AdvancePolicy::Passive
    }
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(&mut self, o: u64, w: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let fail = |r| refuse(NAME, o, w, Direction::Read, r);
        match self.role(o, w).map_err(fail)? {
            Role::Configuration => {
                if self.known.as_ref().is_some_and(|known| !known.contains(&o)) {
                    return Err(fail("T6000 bridge configuration handoff word is unknown"));
                }
                Ok(self.values.get(o))
            }
            Role::Initialize(_) => Err(fail(
                "bridge initialization command readback is not established",
            )),
            Role::Sample(empty) => {
                if let Some(known) = &self.known {
                    if !known.contains(&o) {
                        return Err(fail("T6000 bridge sample handoff word is unknown"));
                    }
                    if self
                        .counter_enables
                        .iter()
                        .any(|enable| !known.contains(enable) || self.values.get(*enable) != 0)
                    {
                        return Err(fail(
                            "T6000 bridge sample has no qualified disabled counter state",
                        ));
                    }
                    return Ok(self.values.get(o));
                }
                Ok(empty)
            }
        }
    }
    fn write(&mut self, o: u64, w: Width, v: u64, _: &mut Access<'_>) -> Result<(), MmioError> {
        let fail = |r| refuse(NAME, o, w, Direction::Write, r);
        match self.role(o, w).map_err(fail)? {
            Role::Configuration => {
                if self.known.is_some() && self.counter_enables.contains(&o) && v != 0 {
                    return Err(fail(
                        "T6000 bridge native counter event effects are not connected",
                    ));
                }
                if let Some(known) = &self.known
                    && let Some(&mask) = self.tuning_masks.get(&o)
                {
                    if !known.contains(&o) && mask != u32::MAX {
                        return Err(fail(
                            "T6000 bridge masked write requires its unknown preserved fields",
                        ));
                    }
                    if known.contains(&o) && (self.values.get(o) ^ v) & !u64::from(mask) != 0 {
                        return Err(fail(
                            "T6000 bridge write changes fields outside the qualified tuning masks",
                        ));
                    }
                }
                self.values.set(o, v & w.mask());
                if let Some(known) = &mut self.known {
                    known.insert(o);
                }
            }
            Role::Initialize(mask) => {
                if self.known.is_some() && v != 0 {
                    return Err(fail(
                        "T6000 bridge native counter reset retirement is not qualified",
                    ));
                }
                // Initialization empties the selected accumulators, which
                // no traffic fills.
                if v & !u64::from(mask) != 0 {
                    return Err(fail(
                        "bridge initialization names an unconfigured counter slot",
                    ));
                }
            }
            Role::Sample(_) => return Err(fail("bridge samples are read-only")),
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use stela_contracts::interrupt::InterruptLatch;
    #[test]
    fn tuning_and_dt_selected_configuration_hold_without_claiming_command_readback() {
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        let mut pmsg = [0; 36];
        pmsg[1] = 7;
        let mut event = [0; 36];
        event[1] = 2;
        event[2] = 1;
        event[3] = 1;
        event[10] = 6;
        event[11] = 1;
        let mut b = Bridge::new(
            &[(0, 0x103)],
            [0, 0x80, 0, 2],
            &[pmsg, event],
            Some([0, 0x20, 0x18, 9]),
        )
        .unwrap();
        for o in [
            0, 0x920, 0x748, 0x8000, 0x8008, 0x820c, 0x8284, 0x82a0, 0x82b4, 0x82b8,
        ] {
            assert_eq!(b.read(o, Width::Word, &mut a), Ok(0));
            b.write(o, Width::Word, 0x8765_4321, &mut a).unwrap();
            assert_eq!(b.read(o, Width::Word, &mut a), Ok(0x8765_4321));
        }
        b.write(0x8014, Width::Word, 1, &mut a).unwrap();
        b.write(0x82bc, Width::Word, 2, &mut a).unwrap();
        assert!(b.read(0x8014, Width::Word, &mut a).is_err());
        assert!(b.write(0x82bc, Width::Word, 4, &mut a).is_err());
        assert!(b.read(0x82e0, Width::Word, &mut a).is_err());
        assert!(b.write(0, Width::Double, 0, &mut a).is_err());
        // Simple slot 0 and event slot 1 sample their empty accumulators.
        assert_eq!(b.read(0xc000, Width::Double, &mut a), Ok(0));
        assert_eq!(b.read(0xc208, Width::Double, &mut a), Ok(0));
        assert_eq!(b.read(0xc238, Width::Double, &mut a), Ok(u64::MAX));
        assert_eq!(b.read(0xc268, Width::Double, &mut a), Ok(0));
        for i in 0..6 {
            assert_eq!(b.read(0xc2c0 + 8 * i, Width::Double, &mut a), Ok(0));
        }
        assert!(b.read(0xc2f0, Width::Double, &mut a).is_err());
        assert!(b.read(0xc000, Width::Word, &mut a).is_err());
        assert!(b.write(0xc000, Width::Double, 0, &mut a).is_err());
        // Slot 1 is an event counter only.
        assert!(b.read(0xc008, Width::Double, &mut a).is_err());
        assert!(Bridge::new(&[], [1, 0x80, 0, 1], &[pmsg], None).is_err());
    }
    #[test]
    fn t6000_actual_configuration_retains_only_known_words_and_never_invents_counter_effects() {
        use super::super::pmgr::t6000::tunables::Profile;
        let profile = Profile::new(0x6000, 8, 0).unwrap();
        let mut irq = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut irq);
        let mut config = [0; 36];
        config[1] = 7;
        let mut model = Bridge::t6000(
            profile,
            0,
            [0, 0x80, 0, 1],
            &[config],
            None,
            &[
                (0, Width::Word, 0xffff_fffe),
                (0x10, Width::Word, 0x1234_5678),
                (0xc000, Width::Double, 1234),
            ],
        )
        .unwrap();
        assert_eq!(model.read(0, Width::Word, &mut access), Ok(0xffff_fffe));
        assert!(model.read(0x14, Width::Word, &mut access).is_err());
        assert!(model.write(0x14, Width::Word, 1, &mut access).is_err());
        for row in profile.program(0).unwrap() {
            if row.offset == 0 {
                let before = model.read(0, Width::Word, &mut access).unwrap() as u32;
                model
                    .write(0, Width::Word, u64::from(row.apply(before)), &mut access)
                    .unwrap();
            }
        }
        assert_eq!(model.read(0, Width::Word, &mut access), Ok(0xffff_fffd));
        let tuned = (0x1234_5678 & !0x0fff_0000) | 0x000d_0000;
        model.write(0x10, Width::Word, tuned, &mut access).unwrap();
        assert_eq!(model.read(0x10, Width::Word, &mut access), Ok(tuned));
        assert!(
            model
                .write(0x10, Width::Word, tuned ^ 1, &mut access)
                .is_err()
        );
        assert_eq!(model.read(0x10, Width::Word, &mut access), Ok(tuned));
        assert!(model.read(0xc000, Width::Double, &mut access).is_err());
        model.write(0x8018, Width::Word, 0, &mut access).unwrap();
        assert_eq!(model.read(0xc000, Width::Double, &mut access), Ok(1234));
        assert!(model.write(0x8018, Width::Word, 1, &mut access).is_err());
        assert_eq!(model.read(0x8018, Width::Word, &mut access), Ok(0));
        assert!(model.write(0x8014, Width::Word, 1, &mut access).is_err());
        assert_eq!(model.read(0xc000, Width::Double, &mut access), Ok(1234));
        assert!(
            Bridge::t6000(
                profile,
                0,
                [0, 0x80, 0, 1],
                &[config],
                None,
                &[(0x8018, Width::Word, 1)]
            )
            .is_err()
        );
        assert!(
            Bridge::t6000(
                profile,
                0,
                [0; 4],
                &[],
                None,
                &[(0, Width::Word, 1), (0, Width::Word, 2)]
            )
            .is_err()
        );
        assert!(Bridge::t6000(profile, 0, [0; 4], &[], None, &[(0x10, Width::Double, 1)]).is_err());
    }
}
