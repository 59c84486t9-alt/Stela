//! Actual retained source selection. No nominal TSC/frequency or bootstrap Cpu.
use super::{WorkError, counter::Counter, pm};
use alloc::sync::Arc;
mod health;
pub(super) use health::Health;
pub(crate) use stela_boot_core::hpet::ElapsedBounds;

#[derive(Clone)]
pub(crate) enum Prepared {
    Pm(pm::Prepared),
    Hpet(Arc<Counter>),
}
#[derive(Debug)]
pub(crate) enum Observation {
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
    pub(crate) fn hpet_counter(&self) -> Option<&Arc<super::HpetCounter>> {
        match self {
            Self::Hpet(counter) => Some(counter),
            Self::Pm(_) => None,
        }
    }
    pub(super) fn continuous_period(&self) -> Result<u32, WorkError> {
        match self {
            Self::Hpet(counter) => counter.continuous_period(),
            Self::Pm(_) => Err(WorkError::Unavailable),
        }
    }
    pub(super) fn elapsed_bounds(&self, ticks: u64) -> Result<ElapsedBounds, WorkError> {
        match self {
            Self::Hpet(counter) => counter.elapsed_bounds(ticks),
            Self::Pm(_) => Err(WorkError::Unavailable),
        }
    }

    /// # Safety
    /// Every real PM sample gap, including masked original execution and VMM/
    /// firmware interruptions, obeys max_gap_ns. This is only the existing
    /// explicit bounded fixture compatibility path, never arbitrary WQ entry.
    pub(crate) unsafe fn qualify_bounded(self, max_gap_ns: u64) -> Result<Self, WorkError> {
        match self {
            // SAFETY: caller supplies the complete actual PM source gap bound.
            Self::Pm(pm) => unsafe { pm.qualify_bounded(max_gap_ns) }.map(Self::Pm),
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
            Self::Hpet(counter) => {
                counter.check_process()?;
                if !Arc::ptr_eq(counter.identity(), identity) {
                    return Err(WorkError::WrongCpu);
                }
                Ok(())
            }
        }
    }
    /// # Safety
    /// Exact original source and CPU/root lifetime are retained; caller excludes
    /// its own IRQs while mutating the serialized previous/elapsed sample pair.
    pub(super) unsafe fn read(&self) -> Result<u64, WorkError> {
        match self {
            // SAFETY: caller supplies original retained PM/CPU ownership.
            Self::Pm(pm) => unsafe { pm.read() }.map(u64::from),
            Self::Hpet(counter) => counter.read_irq(),
        }
    }
    pub(super) fn progress_after(&self, previous: u64) -> Result<u64, WorkError> {
        match self {
            Self::Hpet(counter) => counter.progress_after(previous),
            // The separate bounded PM fixture retains its existing wrap/gap
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
            Self::Hpet(_) => {
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
        }
    }
    pub(super) fn observation(&self) -> Observation {
        match self {
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
