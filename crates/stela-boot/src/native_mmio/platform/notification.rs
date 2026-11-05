//! Direct-delivery observations in the original single-BSP diagnostic scope.
use super::*;
use crate::{
    handoff::Handoff,
    native_dma::firmware_state::{self, Found, Kind},
};
use core::mem::ManuallyDrop;
use stela_drivers::bus::{
    irq::posted_msi::{Error as IrqError, NotificationDomain},
    mmio::owned::Mapping,
};

struct Registers {
    kind: Kind,
    base: usize,
    mapping: Mapping,
}

impl Registers {
    fn inactive(&self) -> bool {
        firmware_state::inspect_registers(
            self.kind,
            // SAFETY: this original UC mapping covers all the selected
            // unit's aligned registers and stays installed through check.
            |offset| unsafe { ((self.base + offset) as *const u32).read_volatile() },
            // SAFETY: the same retained UC mapping covers the aligned AMD-Vi
            // registers selected for the 64-bit read.
            |offset| unsafe { ((self.base + offset) as *const u64).read_volatile() },
        ) == Found::Inactive
    }
}

pub(crate) struct InactiveNotification {
    scope: Arc<RootProcessScope>,
    registers: ManuallyDrop<Vec<Registers>>,
    lost: AtomicBool,
}

// SAFETY: the same original process scope checks CPU and the exact active
// root before register access. Each real unit is retained in its UC mapping
// and the caller excludes every remapping writer. Checks only read bounded
// registers and atomic metadata, including from IRQ context. An abandoned
// guard keeps the original mappings and captures.
unsafe impl NotificationDomain for InactiveNotification {
    fn check(&self) -> Result<(), IrqError> {
        self.scope.check_irq_cpu().map_err(|_| IrqError::Context)?;
        self.scope
            .context()
            .check_current()
            .map_err(|_| IrqError::Context)?;
        if self.lost.load(Ordering::Acquire) {
            return Err(IrqError::RootFailed);
        }
        if self.registers.iter().any(|registers| !registers.inactive()) {
            self.lost.store(true, Ordering::Release);
            return Err(IrqError::RootFailed);
        }
        if self.lost.load(Ordering::Acquire) {
            return Err(IrqError::RootFailed);
        }
        Ok(())
    }
}

impl InactiveNotification {
    /// # Safety
    /// All former users have joined, no route was published, and the same
    /// original context and remapping-writer exclusion still hold.
    pub(crate) unsafe fn retire(self: Arc<Self>) -> Result<(), Error> {
        let mut owner = Arc::try_unwrap(self).map_err(|_| Error::Busy)?;
        owner.scope.check().map_err(failed)?;
        owner.check().map_err(failed)?;
        for registers in owner.registers.iter_mut() {
            // SAFETY: unique original owner, with all physical users joined.
            unsafe { registers.mapping.retire() }?;
        }
        // SAFETY: all of this owner's register views withdrew successfully.
        unsafe { ManuallyDrop::drop(&mut owner.registers) };
        Ok(())
    }
}

impl ScopedSource {
    /// # Safety
    /// The diagnostic retains the original handoff and scoped aperture on
    /// the sole BSP. Every original remapper's format/reset writers remain
    /// excluded until notification retirement, including firmware and SMM.
    pub(crate) unsafe fn pin_inactive_notification(
        &self,
        handoff: &'static Handoff,
        session: &Session,
    ) -> Result<Arc<InactiveNotification>, Error> {
        if !Arc::ptr_eq(&session.source, &self.platform) {
            return Err(Error::Unavailable);
        }
        session.scope.check().map_err(failed)?;
        let scope = session.scope.clone();
        // SAFETY: caller supplies the original retained handoff.
        let wire = unsafe { super::super::captured(handoff) }?;
        if !ptr::eq(wire, self.platform.resources.wire) {
            return Err(Error::Unavailable);
        }
        let units = handoff
            .inactive_firmware_units
            .original_units()
            .ok_or(Error::Unavailable)?;
        let mut registers = Vec::new();
        registers
            .try_reserve_exact(units.len())
            .map_err(|_| Error::Exhausted)?;
        let observed = (|| {
            for unit in units {
                let bytes = match unit.kind {
                    Kind::Vtd => PAGE,
                    Kind::AmdVi => 4 * PAGE,
                };
                let span = PhysicalSpan::new(unit.base, bytes)?;
                if !unit.base.is_multiple_of(PAGE)
                    || !wire.excludes_memory(span.start(), span.end())
                {
                    return Err(Error::OutsideResource);
                }
                let (resource, _) = self.register_handoff(span)?;
                let mapping = self.authority.map(
                    resource,
                    0,
                    bytes as usize,
                    CacheAttribute::Uncached,
                    Protection::ReadOnly,
                )?;
                // Place the actual owner in the list before addressing its window.
                let registers = registers.push_mut(Registers {
                    kind: unit.kind,
                    base: 0,
                    mapping,
                });
                registers.base = registers.mapping.address(0, bytes as usize)?.as_ptr() as usize;
                if !registers.inactive() {
                    return Err(Error::InvalidPlatformReply);
                }
            }
            Ok(())
        })();
        if let Err(error) = observed {
            for mut unit in registers {
                // SAFETY: read-only observations finished synchronously and
                // no notification guard or route has been published.
                unsafe { unit.mapping.retire() }?;
            }
            return Err(error);
        }
        let owner = Arc::new(InactiveNotification {
            scope,
            registers: ManuallyDrop::new(registers),
            lost: AtomicBool::new(false),
        });
        crate::output::arguments(format_args!(
            "CHECK native-mmio notification owner=original inactive_units={}\n",
            units.len()
        ));
        Ok(owner)
    }
}
