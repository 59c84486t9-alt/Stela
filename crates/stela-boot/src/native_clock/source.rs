//! Source selection: the invariant TSC at the boot's calibrated rate, an
//! exclusively owned HPET, or the bounded PM fixture. No bootstrap Cpu.
use super::{WorkError, counter::Counter, pm};
use alloc::{boxed::Box, rc::Rc, sync::Arc};
pub(crate) use stela_boot_core::hpet::ElapsedBounds;
pub(super) use stela_boot_core::source_health::Health;
use stela_drivers::bus::pci::power::{Error as TimerError, Interval, Timer};

#[derive(Clone)]
pub(crate) enum Prepared {
    Pm(pm::Prepared),
    Hpet(Arc<Counter>),
    Tsc(Tsc),
}

/// The invariant TSC at the boot's calibrated rate.
#[derive(Clone, Copy)]
pub(crate) struct Tsc(stela_boot_core::tsc::NominalRate);

impl Tsc {
    fn new(hz: u64) -> Result<Self, WorkError> {
        if !crate::cpu::INVARIANT_TSC.present() {
            return Err(WorkError::Unavailable);
        }
        stela_boot_core::tsc::NominalRate::new(hz)
            .map(Self)
            .map_err(|_| WorkError::Unavailable)
    }
}

/// Process-only physical minimum from a retained native HPET handoff.
struct HpetMinimum(Arc<Counter>);

struct HpetInterval {
    counter: Arc<Counter>,
    start: u64,
    ticks: u64,
}

impl Interval for HpetInterval {
    fn elapsed(&self) -> Result<bool, TimerError> {
        self.counter
            .check_process()
            .map_err(|_| TimerError::Clock)?;
        let now = self.counter.read_irq().map_err(|_| TimerError::Clock)?;
        let elapsed = now.wrapping_sub(self.start);
        if elapsed > u64::MAX / 2 {
            return Err(TimerError::Clock);
        }
        Ok(elapsed >= self.ticks)
    }
}

impl HpetMinimum {
    fn target(&self, microseconds: u64) -> Result<u64, WorkError> {
        self.0.check_process()?;
        let ns = microseconds
            .checked_mul(1_000)
            .ok_or(WorkError::Exhausted)?;
        let ticks = self.0.ticks_for_minimum_ns(ns)?;
        if ticks > u64::MAX / 2 {
            return Err(WorkError::Exhausted);
        }
        Ok(ticks)
    }

    fn validate(&self) -> Result<(), WorkError> {
        // Cover the longest PCI power readiness interval before admitting use.
        self.target(60_000_000)?;
        let start = self.0.read_irq()?;
        self.0.progress_after(start)?;
        Ok(())
    }
}

// SAFETY: the exclusive native counter retains its source and verifies root,
// process and power continuity. Only conservative HPET ticks satisfy a wait.
unsafe impl Timer for HpetMinimum {
    fn check(&self) -> Result<(), TimerError> {
        self.validate().map_err(|_| TimerError::Clock)
    }

    fn wait_us(&self, microseconds: u64) -> Result<(), TimerError> {
        let mut remaining = self.target(microseconds).map_err(|_| TimerError::Clock)?;
        let mut current = self.0.read_irq().map_err(|_| TimerError::Clock)?;
        while remaining != 0 {
            let mut next = self.0.read_irq().map_err(|_| TimerError::Clock)?;
            if next == current {
                next = self
                    .0
                    .progress_after(current)
                    .map_err(|_| TimerError::Clock)?;
            }
            let elapsed = next.wrapping_sub(current);
            if elapsed > u64::MAX / 2 {
                return Err(TimerError::Clock);
            }
            remaining = remaining.saturating_sub(elapsed);
            current = next;
        }
        Ok(())
    }

    fn begin_interval(&self, microseconds: u64) -> Result<Option<Box<dyn Interval>>, TimerError> {
        let ticks = self.target(microseconds).map_err(|_| TimerError::Clock)?;
        let start = self.0.read_irq().map_err(|_| TimerError::Clock)?;
        Ok(Some(Box::new(HpetInterval {
            counter: self.0.clone(),
            start,
            ticks,
        })))
    }
}

#[derive(Debug)]
pub(crate) enum Observation {
    InvariantTsc {
        hz: u64,
    },
    BoundedPm {
        fadt_sha256: [u8; 32],
        port: u16,
        mask: u32,
        hz: u64,
    },
    Hpet64 {
        table_sha256: [u8; 32],
        base: u64,
        block_id: u32,
        number: u8,
        period_fs: u32,
    },
}
impl Observation {
    pub(super) fn debug_fields(&self, record: &mut core::fmt::DebugStruct<'_, '_>) {
        match self {
            Self::InvariantTsc { hz } => {
                record.field("tsc_hz", hz);
            }
            Self::BoundedPm {
                fadt_sha256,
                port,
                mask,
                hz,
            } => {
                record
                    .field("fadt_sha256", fadt_sha256)
                    .field("pm_port", port)
                    .field("pm_mask", mask)
                    .field("pm_hz", hz);
            }
            Self::Hpet64 {
                table_sha256,
                base,
                block_id,
                number,
                period_fs,
            } => {
                record
                    .field("hpet_sha256", table_sha256)
                    .field("hpet_base", base)
                    .field("hpet_block_id", block_id)
                    .field("hpet_number", number)
                    .field("hpet_period_fs", period_fs);
            }
        }
    }
}
impl Prepared {
    /// The invariant TSC at `hz`, the boot's calibrated rate.
    pub(crate) fn tsc(hz: u64) -> Result<Self, WorkError> {
        Tsc::new(hz).map(Self::Tsc)
    }
    pub(crate) fn from_fadt(table: &[u8]) -> Result<Self, WorkError> {
        pm::Prepared::from_fadt(table).map(Self::Pm)
    }
    pub(crate) fn exclusive_hpet(
        owner: crate::native_mmio::ExclusiveHpet,
    ) -> Result<Self, WorkError> {
        Counter::attach_exclusive(owner).map(|counter| Self::Hpet(Arc::new(counter)))
    }
    pub(crate) fn exclusive_native_hpet(
        owner: crate::native_mmio::NativeExclusiveHpet,
    ) -> Result<Self, WorkError> {
        Counter::attach_native_exclusive(owner).map(|counter| Self::Hpet(Arc::new(counter)))
    }
    #[cfg(feature = "diagnostics")]
    pub(crate) fn standalone_hpet(owner: crate::paging::config::Hpet) -> Result<Self, WorkError> {
        Counter::attach_standalone(owner).map(|counter| Self::Hpet(Arc::new(counter)))
    }

    pub(crate) fn pci_minimum(&self) -> Result<Rc<dyn Timer>, WorkError> {
        let counter = self.hpet_counter().ok_or(WorkError::Unavailable)?;
        let minimum = HpetMinimum(counter.clone());
        minimum.validate()?;
        Ok(Rc::new(minimum))
    }

    pub(crate) fn hpet_counter(&self) -> Option<&Arc<super::HpetCounter>> {
        match self {
            Self::Hpet(counter) => Some(counter),
            Self::Pm(_) | Self::Tsc(_) => None,
        }
    }
    pub(super) fn continuous_period(&self) -> Result<u32, WorkError> {
        match self {
            Self::Hpet(counter) => counter.continuous_period(),
            Self::Tsc(tsc) => Ok(tsc.0.period_fs()),
            Self::Pm(_) => Err(WorkError::Unavailable),
        }
    }
    pub(super) fn elapsed_bounds(&self, ticks: u64) -> Result<ElapsedBounds, WorkError> {
        match self {
            Self::Hpet(counter) => counter.elapsed_bounds(ticks),
            Self::Tsc(tsc) => tsc
                .0
                .elapsed_bounds(ticks)
                .map_err(|_| WorkError::Exhausted),
            Self::Pm(_) => Err(WorkError::Unavailable),
        }
    }
    pub(super) fn ticks_for_minimum_ns(&self, minimum_ns: u64) -> Result<u64, WorkError> {
        match self {
            Self::Hpet(counter) => counter.ticks_for_minimum_ns(minimum_ns),
            Self::Tsc(tsc) => tsc
                .0
                .ticks_for_minimum_ns(minimum_ns)
                .map_err(|_| WorkError::Exhausted),
            Self::Pm(_) => Err(WorkError::Unavailable),
        }
    }

    /// # Safety
    /// Every real PM sample gap, including masked original execution and VMM/
    /// firmware interruptions, obeys max_gap_ns. This is only the existing
    /// explicit bounded fixture compatibility path, never arbitrary WQ entry.
    pub(crate) unsafe fn qualify_bounded(self, max_gap_ns: u64) -> Result<Self, WorkError> {
        match self {
            // SAFETY: caller supplies the complete PM source gap bound.
            Self::Pm(pm) => unsafe { pm.qualify_bounded(max_gap_ns) }.map(Self::Pm),
            Self::Tsc(tsc) => Ok(Self::Tsc(tsc)),
            Self::Hpet(counter) => {
                counter.check_process()?;
                Ok(Self::Hpet(counter))
            }
        }
    }
    pub(super) fn admit(
        &self,
        identity: &Arc<crate::engine::host::RootIdentity>,
    ) -> Result<(), WorkError> {
        match self {
            Self::Pm(pm) => pm.admit(),
            Self::Tsc(tsc) => Tsc::new(tsc.0.hz()).map(|_| ()),
            Self::Hpet(counter) => {
                counter.check_process()?;
                if counter
                    .identity()
                    .is_none_or(|owner| !Arc::ptr_eq(owner, identity))
                {
                    return Err(WorkError::WrongCpu);
                }
                Ok(())
            }
        }
    }
    /// # Safety
    /// Original source and CPU/root lifetime are held; caller excludes
    /// its own IRQs while mutating the serialized previous/elapsed sample pair.
    pub(super) unsafe fn read(&self) -> Result<u64, WorkError> {
        match self {
            // SAFETY: caller supplies original kept PM/CPU ownership.
            Self::Pm(pm) => unsafe { pm.read() }.map(u64::from),
            Self::Hpet(counter) => counter.read_irq(),
            Self::Tsc(_) => Ok(super::tsc::fenced()),
        }
    }
    pub(super) fn progress_after(&self, previous: u64) -> Result<u64, WorkError> {
        match self {
            Self::Hpet(counter) => counter.progress_after(previous),
            Self::Tsc(_) => loop {
                let current = super::tsc::fenced();
                if current != previous {
                    return self.delta(previous, current).map(|_| current);
                }
                core::hint::spin_loop();
            },
            // The separate bounded PM fixture keeps its existing wrap/gap
            // contract; it can never mint a continuous CounterEpoch.
            Self::Pm(pm) => {
                // SAFETY: caller holds the original bounded PM/CPU lease.
                unsafe { pm.read() }.map(u64::from)
            }
        }
    }
    pub(super) fn delta(&self, previous: u64, current: u64) -> Result<u64, WorkError> {
        match self {
            Self::Pm(pm) => pm.delta(previous as u32, current as u32),
            Self::Hpet(_) | Self::Tsc(_) => {
                let delta = current.wrapping_sub(previous);
                if delta > u64::MAX / 2 {
                    return Err(WorkError::CorruptContext);
                }
                Ok(delta)
            }
        }
    }
    pub(super) fn ns(&self, ticks: u64) -> Result<u64, WorkError> {
        match self {
            Self::Pm(_) => pm::ns(ticks),
            Self::Hpet(counter) => counter.ns(ticks),
            Self::Tsc(tsc) => tsc.0.ns(ticks).map_err(|_| WorkError::Exhausted),
        }
    }
    pub(super) fn observation(&self) -> Observation {
        match self {
            Self::Tsc(tsc) => Observation::InvariantTsc { hz: tsc.0.hz() },
            Self::Pm(pm) => Observation::BoundedPm {
                fadt_sha256: pm.fadt_sha256,
                port: pm.port,
                mask: pm.mask,
                hz: pm::HZ,
            },
            Self::Hpet(counter) => {
                let descriptor = counter.descriptor();
                Observation::Hpet64 {
                    table_sha256: descriptor.table_sha256(),
                    base: descriptor.registers().start(),
                    block_id: descriptor.block_id(),
                    number: descriptor.number(),
                    period_fs: counter.period_fs(),
                }
            }
        }
    }
}
