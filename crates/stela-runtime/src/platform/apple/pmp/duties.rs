//! The PMP firmware's PTD duties that the AP's drivers wait for, modeled
//! behaviorally: the machine runs no PMP firmware, and [`super::native`]'s
//! owner is not mounted. The PMP publishes through the bank's update alias
//! (`0x10000 + 8 * entry`), as the AP does.
//!
//! - `PMP-STATUS` reads 1: the boot firmware started the PMP. Original
//!   26A434 T8112 PMP stores 1 into that update slot when its startup
//!   completes (`0x94d8`). ApplePMGR's `_waitForPMPReadyActionGatedv2`
//!   (KC file 0x2b979dc) polls the entry through `ApplePTD::_readPTD`
//!   (0x2bc036c) and panics after 30 seconds while it reads 0. The first
//!   access to the bank publishes it, which no AP observation precedes.
//! - An update of a `SOC-DEV-PS-REQ` entry, a request vector of device
//!   power states, is published in the matching `SOC-DEV-PS-ACK` entry:
//!   every requested state is reached at once (`_pmpWriteDashBoardSetDevice
//!   State`, 0x2b98c6c, polls for it for 15 seconds). PMP-managed devices'
//!   models follow no PMP power sequencing, so the acknowledgement grants
//!   no other effect.
//!
//! Every other update, the memory cache's commands among them, only holds
//! what the AP wrote.
use core::cell::Cell;
use {
    crate::platform::apple::ptd::transport::Ptd, stela_contracts::bus::Access,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError, stela_contracts::bus::Width,
    stela_soc_data::ptd::Range, stela_soc_data::ptd::UPDATE_OFFSET,
};

const STATUS: &str = "PMP-STATUS";
const REQUESTS: &str = "SOC-DEV-PS-REQ";
const ACKS: &str = "SOC-DEV-PS-ACK";
const SLOT: u64 = 8;

/// The ranges the duties give meaning to, by first entry.
pub struct Duties {
    status: u32,
    requests: (u32, u32),
    acks: u32,
    started: Cell<bool>,
}

impl Duties {
    /// The duties of a bank with these ranges; `None` when it has no
    /// `PMP-STATUS`, which no driver then waits for.
    pub fn new(ranges: &[Range]) -> Result<Option<Self>, &'static str> {
        let named = |name: &str| ranges.iter().find(|range| range.name == name);
        let Some(status) = named(STATUS) else {
            return Ok(None);
        };
        let requests = named(REQUESTS).ok_or("PTD has no SOC-DEV-PS-REQ range")?;
        let acks = named(ACKS).ok_or("PTD has no SOC-DEV-PS-ACK range")?;
        if requests.count != acks.count {
            return Err("PTD device power-state requests and acknowledgements differ");
        }
        Ok(Some(Self {
            status: status.start,
            requests: (requests.start, requests.count),
            acks: acks.start,
            started: Cell::new(false),
        }))
    }

    /// Publish `PMP-STATUS` once, before the AP's first observation.
    pub fn start(&self, bank: &Ptd, access: &mut Access<'_>) -> Result<(), MmioError> {
        if self.started.get() {
            return Ok(());
        }
        publish(bank, self.status, 1, access)?;
        self.started.set(true);
        Ok(())
    }

    /// The PMP's response to the AP's write of `value` at bank `offset`.
    pub fn written(
        &self,
        bank: &Ptd,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let Some(entry) = offset
            .checked_sub(UPDATE_OFFSET)
            .filter(|within| width == Width::Double && within.is_multiple_of(SLOT))
            .map(|within| within / SLOT)
        else {
            return Ok(());
        };
        let (first, count) = self.requests;
        match u32::try_from(entry) {
            Ok(entry) if (first..first + count).contains(&entry) => {
                publish(bank, self.acks + (entry - first), value, access)
            }
            _ => Ok(()),
        }
    }
}

fn publish(bank: &Ptd, entry: u32, value: u64, access: &mut Access<'_>) -> Result<(), MmioError> {
    bank.clone().write(
        UPDATE_OFFSET + u64::from(entry) * SLOT,
        Width::Double,
        value,
        access,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use {stela_contracts::bus::LifecycleState, stela_contracts::interrupt::InterruptLatch};

    fn range(id: u32, start: u32, count: u32, name: &str) -> Range {
        Range {
            id,
            start,
            count,
            name: name.into(),
        }
    }
    fn ranges() -> Vec<Range> {
        vec![
            range(1, 0, 1, "NULL"),
            range(2, 1, 1, STATUS),
            range(10, 160, 4, REQUESTS),
            range(11, 164, 4, ACKS),
        ]
    }
    fn bank() -> Ptd {
        let lifecycle = LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        };
        Ptd::initialized(384, &ranges(), lifecycle, [None; 16]).unwrap()
    }

    #[test]
    fn status_is_published_once_and_requests_are_acknowledged() {
        let duties = Duties::new(&ranges()).unwrap().unwrap();
        let mut bank = bank();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 5, &mut latch);
        assert_eq!(bank.read(16, Width::Double, &mut access), Ok(0));
        duties.start(&bank, &mut access).unwrap();
        duties.start(&bank, &mut access).unwrap();
        // ApplePTD::_readPTD consumes the whole entry with one LDP.
        assert_eq!(bank.consume_entry(1, &mut access).unwrap().value, 1);
        assert_eq!(bank.requests().len(), 1);

        let request = UPDATE_OFFSET + 162 * SLOT;
        bank.write(request, Width::Double, 0x3f0f, &mut access)
            .unwrap();
        duties
            .written(&bank, request, Width::Double, 0x3f0f, &mut access)
            .unwrap();
        assert_eq!(bank.consume_entry(166, &mut access).unwrap().value, 0x3f0f);

        // Other updates only hold what the AP wrote.
        let other = UPDATE_OFFSET + 2 * SLOT;
        bank.write(other, Width::Double, 7, &mut access).unwrap();
        duties
            .written(&bank, other, Width::Double, 7, &mut access)
            .unwrap();
        assert_eq!(bank.requests().len(), 4);
    }

    #[test]
    fn a_bank_without_status_has_no_duties_and_unpaired_ranges_refuse() {
        assert!(Duties::new(&ranges()[..1]).unwrap().is_none());
        let mut short = ranges();
        short[3].count = 3;
        assert!(Duties::new(&short).is_err());
    }
}
