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
//! Stela hands off zero idle/disabled configuration, without conditional iBoot
//! tuning. Header flag variants, other layouts and unknown registers refuse.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use super::regfile::Held;
use alloc::{collections::BTreeMap, vec::Vec};
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
}
impl Bridge {
    pub fn new(
        fields: &[(u64, u32)],
        header: [u8; 4],
        configs: &[[u8; CONFIG_BYTES]],
        axi: Option<[u8; 4]>,
    ) -> Result<Self, &'static str> {
        let mut words = BTreeMap::new();
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
                if slot >= 32 || config[0] > 1 || config[10] > 6 || config[3] > 1 {
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
                    }
                    event |= 1 << slot;
                }
            }
            if simple != 0 {
                words.insert(bank + SIMPLE_INIT, Role::Initialize(simple));
                words.insert(bank + SIMPLE_ENABLE, Role::Configuration);
            }
            if event != 0 {
                words.insert(bank + EVENT_INIT, Role::Initialize(event));
                words.insert(bank + EVENT_ENABLE, Role::Configuration);
            }
        } else if !configs.is_empty() {
            return Err("bridge without counters has selected counter configurations");
        }
        Ok(Self {
            words,
            values: Held::default(),
        })
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
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(&mut self, o: u64, w: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let fail = |r| refuse(NAME, o, w, Direction::Read, r);
        match self.role(o, w).map_err(fail)? {
            Role::Configuration => Ok(self.values.get(o)),
            Role::Initialize(_) => Err(fail(
                "bridge initialization command readback is not established",
            )),
            Role::Sample(empty) => Ok(empty),
        }
    }
    fn write(&mut self, o: u64, w: Width, v: u64, _: &mut Access<'_>) -> Result<(), MmioError> {
        let fail = |r| refuse(NAME, o, w, Direction::Write, r);
        match self.role(o, w).map_err(fail)? {
            Role::Configuration => self.values.set(o, v & w.mask()),
            Role::Initialize(mask) => {
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
    use crate::platform::apple::interrupt::InterruptLatch;
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
}
