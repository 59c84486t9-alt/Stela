//! AHCI-only owned controller timing and failed construction custody.
use super::*;
use crate::bus::pci::power::{self, Timer};
use alloc::boxed::Box;
use core::{
    cell::RefCell,
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
};

enum Phase {
    Ready,
    Acting,
    Failed(BlockError),
}
pub(super) struct Control {
    pub(super) function: RefCell<Option<Function>>,
    pub(super) minimum: Rc<dyn Timer>,
    phase: RefCell<Phase>,
}
impl Control {
    pub(super) fn ready(&self) -> Result<(), BlockError> {
        match &*self.phase.borrow() {
            Phase::Ready => Ok(()),
            Phase::Acting => Err(BlockError::PciPower(power::Error::Interrupted)),
            Phase::Failed(error) => Err(error.clone()),
        }
    }
    pub(super) fn retained(&self) -> bool {
        !matches!(*self.phase.borrow(), Phase::Ready)
    }
    pub(super) fn fail(&self, error: BlockError) {
        *self.phase.borrow_mut() = Phase::Failed(error);
    }
    pub(super) fn check(&self) -> Result<(), BlockError> {
        self.ready()?;
        *self.phase.borrow_mut() = Phase::Acting;
        match self.minimum.check() {
            Ok(()) => {
                *self.phase.borrow_mut() = Phase::Ready;
                Ok(())
            }
            Err(error) => {
                let error = BlockError::PciPower(error);
                self.fail(error.clone());
                Err(error)
            }
        }
    }
    /// Phase closes BEFORE the provider callback and the register transition.
    /// A failed minimum never authorizes the following register read/write.
    pub(super) fn wait_after(&self, us: u64, effect: impl FnOnce()) -> Result<(), BlockError> {
        self.ready()?;
        *self.phase.borrow_mut() = Phase::Acting;
        let result = (|| {
            self.minimum.check().map_err(BlockError::PciPower)?;
            effect();
            self.minimum.wait_us(us).map_err(BlockError::PciPower)
        })();
        match result {
            Ok(()) => {
                *self.phase.borrow_mut() = Phase::Ready;
                Ok(())
            }
            Err(error) => {
                self.fail(error.clone());
                Err(error)
            }
        }
    }
    #[cfg(test)]
    pub(super) fn model(minimum: Rc<dyn Timer>) -> Rc<Self> {
        Rc::new(Self {
            function: RefCell::new(None),
            minimum,
            phase: RefCell::new(Phase::Ready),
        })
    }
}

/// The SAME owned PCI function and minimum timer, plus failed port resources.
/// Disks retain the control independently; this has no backedge from control
/// into disks/ports and cannot form a controller/resource ownership cycle.
pub struct Host {
    pub(super) control: Rc<Control>,
    pub(super) retained_ports: Vec<PortRefusal>,
}
impl Host {
    pub(super) fn new(function: Function, minimum: Rc<dyn Timer>) -> Self {
        Self {
            control: Rc::new(Control {
                function: RefCell::new(Some(function)),
                minimum,
                phase: RefCell::new(Phase::Ready),
            }),
            retained_ports: Vec::new(),
        }
    }
    /// Timing failure is terminal for this controller's existing disks too.
    pub fn check(&self) -> Result<(), BlockError> {
        self.control.ready()
    }
}

/// Active DMA resources retain their exact controller/timer after an uncertain
/// timing transition or a failed disk. The healthy existing lifetime is kept.
pub(super) struct DmaResource<T> {
    value: ManuallyDrop<T>,
    owner: ManuallyDrop<Rc<Control>>,
    retain: Rc<Cell<bool>>,
}
impl<T> DmaResource<T> {
    pub(super) fn new(value: T, owner: Rc<Control>, retain: Rc<Cell<bool>>) -> Self {
        Self {
            value: ManuallyDrop::new(value),
            owner: ManuallyDrop::new(owner),
            retain,
        }
    }
}
impl<T> Deref for DmaResource<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}
impl<T> DerefMut for DmaResource<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}
impl<T> Drop for DmaResource<T> {
    fn drop(&mut self) {
        if !self.retain.get() && !self.owner.retained() {
            // SAFETY: unique fields; keep actual controller/context until value
            // release completes. Unwind retains the still-owned context field.
            unsafe {
                ManuallyDrop::drop(&mut self.value);
                ManuallyDrop::drop(&mut self.owner)
            };
        }
    }
}

pub(super) struct PortBuild {
    pub(super) owner: Rc<Control>,
    pub(super) port: Mmio,
    pub(super) commands: Option<DmaBuffer>,
    pub(super) table: Option<DmaBuffer>,
    pub(super) bounce: Option<DmaBuffer>,
    pub(super) disk: Option<AhciDisk>,
}
pub(super) struct PortRefusal {
    pub(super) error: BlockError,
    _kept: crate::Retained<Box<PortBuild>>,
}
impl PortRefusal {
    pub(super) fn new(error: BlockError, kept: crate::Retained<Box<PortBuild>>) -> Self {
        Self { error, _kept: kept }
    }
}
pub(super) struct Build {
    pub(super) host: Host,
    pub(super) hba: Option<Mmio>,
    pub(super) disks: Vec<AhciDisk>,
    pub(super) failures: Vec<(u32, BlockError)>,
}
/// An actual whole failed AHCI construction, never successful empty attachment.
/// Default Drop retains function, timer, partial port and all prior disks.
pub struct AttachRefusal {
    pub error: BlockError,
    _kept: crate::Retained<Box<Build>>,
}
impl AttachRefusal {
    pub(super) fn new(error: BlockError, kept: crate::Retained<Box<Build>>) -> Self {
        kept.host.control.fail(error.clone());
        Self { error, _kept: kept }
    }
}
impl core::fmt::Debug for AttachRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AttachRefusal")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl core::fmt::Display for AttachRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.error.fmt(f)
    }
}
