//! The PMP's PTD bank: the power management coprocessor's shared table of
//! 64-bit entries (J473AP `/arm-io/mcc` `reg[pmp_ptd_reg_idx]` and
//! `/arm-io/pmgr` `reg[39]`, `0x3b3c0000`), which the PMP firmware and the
//! AP's drivers exchange readings and requests through. The bank's ranges
//! are the `ptd-range` records of the PMP's nub (`/arm-io/pmp/
//! iop-pmp-nub`): `(id, first entry, entries, interrupt, name[16])`.
//!
//! As the 26A434 J473AP `ApplePTD` and `AppleMemCacheController` drivers
//! use it:
//!
//! - `16 * entry` is the entry's value and `+8` its metadata, both
//!   published by the PMP; `_readPTD` hands raw metadata bit 1 to its
//!   clients as the entry's valid bit (decoded bit 54);
//! - `0x10000 + 8 * entry` is the AP's update slot for the entry, which the
//!   PMP reads;
//! - from `0x18000`, one bit per entry: interrupt status (read 32 or 64
//!   bits at a time), enable (`0x18200`) and disable (`0x18300`), written
//!   32 bits at a time; from `0x18400`, a 4-bit route per entry.
//!
//! The machine runs no PMP firmware; this model performs its PTD duties
//! that the AP's drivers wait for:
//!
//! - `PMP-STATUS` reads 1, valid: the boot firmware started the PMP, and
//!   `ApplePMGR::_waitForPMPReadyActionGatedv2` panics while it reads 0;
//! - an update of a `SOC-DEV-PS-REQ` entry, a request vector of device
//!   power states, publishes the same vector in the matching
//!   `SOC-DEV-PS-ACK` entry: every requested state is reached at once
//!   (`_pmpWriteDashBoardSetDeviceState` polls for it, for 15 s);
//! - the memory cache's `MC-DRV-TO-CTRL` holds five quota request words
//!   and two command words, and `MC-CTRL-TO-DRV` five quota responses and
//!   the command acknowledgement (`MCPolicyMgrPMP`'s default counts). The
//!   driver writes command word 1, then word 0, whose bits 11:0 are the
//!   command's sequence and bits 15:12 its class. Writing word 0 runs the
//!   command: class 0 grants every 16-bit request lane its requested units
//!   (bits 11:0) in the matching response lane, class 1 states the cache
//!   size available, and both then publish the sequence as the
//!   acknowledgement the driver's queue waits for. Other classes refuse.
//!
//! Every other update slot only holds what the AP wrote. Published entries
//! raise no interrupt, as the AIC input a route selects is not known:
//! interrupt status reads 0, enables and routes hold what is written.
//! Accesses outside the bank's entries refuse.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use super::regfile::Held;
use alloc::string::String;

const NAME: &str = "ptd";

/// The bank's span, and its update slots' offset.
pub const PTD_BYTES: u64 = 0x20000;
pub const UPDATE_OFFSET: u64 = 0x10000;

const ENTRY: u64 = 16;
const SLOT: u64 = 8;
const IRQ_STATUS: u64 = 0x18000;
const IRQ_ENABLE: u64 = 0x18200;
const IRQ_DISABLE: u64 = 0x18300;
const IRQ_ROUTE: u64 = 0x18400;

/// Raw metadata bit 1: the entry holds a published value.
const VALID: u64 = 1 << 1;

/// `MCPolicyMgrPMP`'s default lane counts: quota requests, command words,
/// quota responses and acknowledgements.
const QUOTAS: u32 = 5;
const COMMAND_WORDS: u32 = 2;
const ACKS: u32 = 1;
const SEQUENCE: u64 = 0xfff;
const LANE_UNITS: u64 = 0xfff;

/// A `ptd-range` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range {
    pub id: u32,
    pub start: u32,
    pub count: u32,
    pub name: String,
}

/// The ranges the model gives meaning to, by first entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Layout {
    status: u32,
    requests: (u32, u32),
    acks: u32,
    memory_cache: Option<(u32, u32)>,
}

#[derive(Debug, Clone)]
pub struct Ptd {
    entries: u32,
    layout: Layout,
    values: Held,
    metadata: Held,
    updates: Held,
    enabled: Held,
    routes: Held,
}

impl Ptd {
    pub fn new(ranges: &[Range]) -> Result<Self, &'static str> {
        let named = |name: &str| ranges.iter().find(|range| range.name == name);
        let entries = ranges
            .iter()
            .map(|range| range.start.checked_add(range.count))
            .try_fold(0u32, |end, range_end| {
                range_end.map(|range_end| end.max(range_end))
            })
            .ok_or("PTD range beyond the entry space")?;
        if u64::from(entries) * ENTRY > UPDATE_OFFSET {
            return Err("PTD ranges beyond the bank's entries");
        }
        let status = named("PMP-STATUS").ok_or("PTD has no PMP-STATUS range")?;
        let requests = named("SOC-DEV-PS-REQ").ok_or("PTD has no SOC-DEV-PS-REQ range")?;
        let acks = named("SOC-DEV-PS-ACK").ok_or("PTD has no SOC-DEV-PS-ACK range")?;
        if status.count == 0 || requests.count != acks.count {
            return Err("PTD device power-state requests and acknowledgements differ");
        }
        let memory_cache = match (named("MC-DRV-TO-CTRL"), named("MC-CTRL-TO-DRV")) {
            (None, None) => None,
            (Some(driver), Some(controller))
                if driver.count >= QUOTAS + COMMAND_WORDS && controller.count >= QUOTAS + ACKS =>
            {
                Some((driver.start, controller.start))
            }
            _ => return Err("PTD memory cache ranges lack their quota and command entries"),
        };
        let mut ptd = Self {
            entries,
            layout: Layout {
                status: status.start,
                requests: (requests.start, requests.count),
                acks: acks.start,
                memory_cache,
            },
            values: Held::default(),
            metadata: Held::default(),
            updates: Held::default(),
            enabled: Held::default(),
            routes: Held::default(),
        };
        ptd.publish(status.start, 1);
        Ok(ptd)
    }

    fn publish(&mut self, entry: u32, value: u64) {
        self.values.set(u64::from(entry), value);
        self.metadata.set(u64::from(entry), VALID);
    }

    fn bit_words(&self) -> u64 {
        u64::from(self.entries).div_ceil(32) * 4
    }

    fn route_words(&self) -> u64 {
        u64::from(self.entries).div_ceil(8) * 4
    }

    /// The PMP's response to the AP's update of `entry`.
    fn update(&mut self, entry: u32, value: u64) -> Result<(), &'static str> {
        self.updates.set(u64::from(entry), value);
        let (first, count) = self.layout.requests;
        if (first..first + count).contains(&entry) {
            self.publish(self.layout.acks + (entry - first), value);
        }
        if let Some((driver, controller)) = self.layout.memory_cache
            && entry == driver + QUOTAS
        {
            match (value >> 12) & 0xf {
                0 => {
                    for quota in 0..QUOTAS {
                        let request = self.updates.get(u64::from(driver + quota));
                        let granted = (0..4)
                            .map(|lane| request & (LANE_UNITS << (16 * lane)))
                            .fold(0, |granted, lane| granted | lane);
                        self.publish(controller + quota, granted);
                    }
                }
                1 => {}
                _ => return Err("memory cache command of an unknown class"),
            }
            self.publish(controller + QUOTAS, value & SEQUENCE);
        }
        Ok(())
    }

    fn entry(&self, offset: u64, base: u64, stride: u64) -> Option<u32> {
        let index = offset.checked_sub(base)? / stride;
        (index < u64::from(self.entries)).then_some(index as u32)
    }
}

fn refused(offset: u64, width: Width, direction: Direction, reason: &'static str) -> MmioError {
    refuse(NAME, offset, width, direction, reason)
}

impl MmioDevice for Ptd {
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let words = self.bit_words();
        let refusal = refused(
            offset,
            width,
            Direction::Read,
            "PTD register without described meaning",
        );
        match offset {
            _ if offset < UPDATE_OFFSET && width == Width::Double && offset.is_multiple_of(8) => {
                let entry = self.entry(offset, 0, ENTRY).ok_or(refusal)?;
                let held = if offset.is_multiple_of(ENTRY) {
                    &self.values
                } else {
                    &self.metadata
                };
                Ok(held.get(u64::from(entry)))
            }
            _ if (UPDATE_OFFSET..IRQ_STATUS).contains(&offset)
                && width == Width::Double
                && offset.is_multiple_of(SLOT) =>
            {
                let entry = self.entry(offset, UPDATE_OFFSET, SLOT).ok_or(refusal)?;
                Ok(self.updates.get(u64::from(entry)))
            }
            _ if (IRQ_STATUS..IRQ_STATUS + words).contains(&offset)
                && offset.is_multiple_of(width.bytes())
                && matches!(width, Width::Word | Width::Double) =>
            {
                Ok(0)
            }
            _ if (IRQ_ENABLE..IRQ_ENABLE + words).contains(&offset)
                && width == Width::Word
                && offset.is_multiple_of(4) =>
            {
                Ok(self.enabled.get(offset - IRQ_ENABLE))
            }
            _ if (IRQ_ROUTE..IRQ_ROUTE + self.route_words()).contains(&offset)
                && width == Width::Word
                && offset.is_multiple_of(4) =>
            {
                Ok(self.routes.get(offset - IRQ_ROUTE))
            }
            _ => Err(refusal),
        }
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let words = self.bit_words();
        let refusal = |reason| refused(offset, width, Direction::Write, reason);
        match offset {
            _ if (UPDATE_OFFSET..IRQ_STATUS).contains(&offset)
                && width == Width::Double
                && offset.is_multiple_of(SLOT) =>
            {
                let entry = self
                    .entry(offset, UPDATE_OFFSET, SLOT)
                    .ok_or_else(|| refusal("PTD update beyond the bank's entries"))?;
                self.update(entry, value).map_err(refusal)
            }
            _ if width != Width::Word || !offset.is_multiple_of(4) => {
                Err(refusal("PTD register without described meaning"))
            }
            _ if (IRQ_ENABLE..IRQ_ENABLE + words).contains(&offset) => {
                let word = offset - IRQ_ENABLE;
                self.enabled.set(word, self.enabled.get(word) | value);
                Ok(())
            }
            _ if (IRQ_DISABLE..IRQ_DISABLE + words).contains(&offset) => {
                let word = offset - IRQ_DISABLE;
                self.enabled.set(word, self.enabled.get(word) & !value);
                Ok(())
            }
            _ if (IRQ_ROUTE..IRQ_ROUTE + self.route_words()).contains(&offset) => {
                self.routes.set(offset - IRQ_ROUTE, value);
                Ok(())
            }
            _ => Err(refusal("PTD register without described meaning")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;
    use alloc::vec::Vec;

    /// The J473AP ranges the model gives meaning to, and one it does not.
    fn ranges() -> Vec<Range> {
        [
            (2, 1, 1, "PMP-STATUS"),
            (10, 160, 4, "SOC-DEV-PS-REQ"),
            (11, 164, 4, "SOC-DEV-PS-ACK"),
            (14, 194, 7, "MC-DRV-TO-CTRL"),
            (30, 208, 6, "MC-CTRL-TO-DRV"),
            (68, 244, 1, "MC-CTRL-TO-SMC"),
        ]
        .into_iter()
        .map(|(id, start, count, name)| Range {
            id,
            start,
            count,
            name: name.into(),
        })
        .collect()
    }

    #[test]
    fn the_pmp_is_ready_and_acknowledges_device_power_states() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut ptd = Ptd::new(&ranges()).unwrap();
        assert_eq!(ptd.read(0x10, Width::Double, &mut access), Ok(1));
        assert_eq!(ptd.read(0x18, Width::Double, &mut access), Ok(VALID));
        let ack = 165 * ENTRY;
        assert_eq!(ptd.read(ack, Width::Double, &mut access), Ok(0));
        ptd.write(
            UPDATE_OFFSET + 161 * SLOT,
            Width::Double,
            0b1010,
            &mut access,
        )
        .unwrap();
        assert_eq!(ptd.read(ack, Width::Double, &mut access), Ok(0b1010));
        assert_eq!(ptd.read(ack + 8, Width::Double, &mut access), Ok(VALID));
        // Turning devices off is acknowledged too.
        ptd.write(UPDATE_OFFSET + 161 * SLOT, Width::Double, 0, &mut access)
            .unwrap();
        assert_eq!(ptd.read(ack, Width::Double, &mut access), Ok(0));
        // Other updates only hold.
        ptd.write(UPDATE_OFFSET + 244 * SLOT, Width::Double, 0xa, &mut access)
            .unwrap();
        assert_eq!(
            ptd.read(UPDATE_OFFSET + 244 * SLOT, Width::Double, &mut access),
            Ok(0xa)
        );
        assert_eq!(ptd.read(244 * ENTRY, Width::Double, &mut access), Ok(0));
        assert!(ptd.read(245 * ENTRY, Width::Double, &mut access).is_err());
        assert!(ptd.read(0x10, Width::Word, &mut access).is_err());
    }

    #[test]
    fn memory_cache_commands_grant_quotas_and_acknowledge_their_sequence() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut ptd = Ptd::new(&ranges()).unwrap();
        let update = |entry: u64| UPDATE_OFFSET + entry * SLOT;
        // Quota 1 asks 0x12 units with selector 2.
        ptd.write(update(194), Width::Double, (0x2012) << 16, &mut access)
            .unwrap();
        ptd.write(update(200), Width::Double, 0, &mut access)
            .unwrap();
        assert_eq!(ptd.read(213 * ENTRY, Width::Double, &mut access), Ok(0));
        ptd.write(update(199), Width::Double, 0x0007, &mut access)
            .unwrap();
        assert_eq!(
            ptd.read(208 * ENTRY, Width::Double, &mut access),
            Ok(0x12 << 16)
        );
        assert_eq!(ptd.read(213 * ENTRY, Width::Double, &mut access), Ok(7));
        assert_eq!(
            ptd.read(213 * ENTRY + 8, Width::Double, &mut access),
            Ok(VALID)
        );
        // A class 1 command acknowledges without granting.
        ptd.write(update(199), Width::Double, 0x1008, &mut access)
            .unwrap();
        assert_eq!(ptd.read(213 * ENTRY, Width::Double, &mut access), Ok(8));
        assert!(
            ptd.write(update(199), Width::Double, 0x2009, &mut access)
                .is_err()
        );
    }

    #[test]
    fn interrupt_registers_hold_and_raise_nothing() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut ptd = Ptd::new(&ranges()).unwrap();
        ptd.write(IRQ_ENABLE, Width::Word, 0b110, &mut access)
            .unwrap();
        ptd.write(IRQ_DISABLE, Width::Word, 0b100, &mut access)
            .unwrap();
        assert_eq!(ptd.read(IRQ_ENABLE, Width::Word, &mut access), Ok(0b10));
        ptd.write(IRQ_ROUTE, Width::Word, 0xb0, &mut access)
            .unwrap();
        assert_eq!(ptd.read(IRQ_ROUTE, Width::Word, &mut access), Ok(0xb0));
        assert_eq!(ptd.read(IRQ_STATUS, Width::Double, &mut access), Ok(0));
        assert!(ptd.write(IRQ_STATUS, Width::Word, 0, &mut access).is_err());
        assert!(
            ptd.read(IRQ_ENABLE + 0x20, Width::Word, &mut access)
                .is_err()
        );
    }

    #[test]
    fn a_bank_without_the_pmp_ranges_refuses() {
        let without = |name: &str| -> Vec<Range> {
            ranges()
                .into_iter()
                .filter(|range| range.name != name)
                .collect()
        };
        assert!(Ptd::new(&without("PMP-STATUS")).is_err());
        assert!(Ptd::new(&without("SOC-DEV-PS-ACK")).is_err());
        assert!(Ptd::new(&without("MC-CTRL-TO-DRV")).is_err());
        assert!(
            Ptd::new(
                &without("MC-CTRL-TO-DRV")
                    .into_iter()
                    .filter(|range| range.name != "MC-DRV-TO-CTRL")
                    .collect::<Vec<_>>()
            )
            .is_ok()
        );
    }
}
