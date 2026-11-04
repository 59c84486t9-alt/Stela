//! Source-owned configuration custody, separate from noncyclic physical pins.
//! Neither phase can be manufactured from Address/window/Mapping descriptors.
use crate::bus::{
    mmio::owned::{Error as MappingError, Resource},
    pci::{Address, ConfigError, ConfigFailure, EcamWindow, assignment::AdmissionClose},
};
mod operation;
use alloc::boxed::Box;
use core::{
    any::Any,
    cell::{Cell, RefCell},
    mem::ManuallyDrop,
};
pub use operation::{CompletionCheck, ConfigOperation};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Read {
        offset: u16,
        width: usize,
    },
    Write {
        offset: u16,
        width: usize,
        value: u32,
    },
}
/// Owned retained original config/source epoch; no writer or entered borrow.
///
/// # Safety
/// Retain the actual original physical slot, config claim, executable/root
/// backing and exact source generation. No guessed BDF/address/name/number
/// may reconstruct it. check must validate original context/admission before
/// source access, without native effects or callbacks. retain clones actual
/// storage custody; Drop cannot acknowledge hardware/DMA/IRQ retirement. Keep
/// unfinished/uncertain resources according to the original source contract.
pub unsafe trait ConfigEpoch: Any + Send + Sync {
    fn check(&self) -> Result<(), MappingError>;
    fn retain(&self) -> Result<Box<dyn ConfigEpoch>, MappingError>;
    fn same_epoch(&self, other: &dyn ConfigEpoch) -> Result<bool, MappingError>;
    fn as_any(&self) -> &dyn Any;
}
/// Unique original config writer and physical-function control, kept OUTSIDE
/// MMIO resource inventories. Its physical reservation projection must have no
/// backedge to this config/mapping/control object.
///
/// # Safety
/// Own the actual original function/root/bridge/config/reset/assignment claim,
/// including complete source/fabric writer exclusion and firmware/runtime
/// reservations. resource is the SAME actual source-issued ECAM reservation,
/// never a numerically equivalent replacement. begin validates exact original
/// current owner plus access/effect policy and obtains a counted real use
/// atomically with close before any volatile operation. Deny
/// relocation/reset/reassignment/bridge mutation while real users remain, with
/// a typed BEFORE-effect failure. No native callback or mutable loan survives
/// check. retain_epoch returns true retained original storage/code authority.
/// Ordinary Drop must retain/quarantine actual hardware/control obligations.
pub unsafe trait ConfigCustody: Any {
    fn address(&self) -> Address;
    fn window(&self) -> EcamWindow;
    fn resource(&self) -> &Resource;
    /// Atomically admit and count this bounded actual operation with close.
    /// Return a use of the SAME original physical product/ancestors; no heap
    /// allocation or mutable/entered borrow survives return (IRQ-safe path).
    fn begin(&self, operation: Operation) -> Result<ConfigOperation, ConfigError>;
    fn retirement_context(&self) -> Result<(), MappingError>;
    fn retain_epoch(&self) -> Result<Box<dyn ConfigEpoch>, MappingError>;
}
/// # Safety
/// This is an actual slot from the sole prepublication whole-fabric producer,
/// held through real global source/unit retirement. Enforce original BME/routing
/// seals; no driver/DMA/IRQ/engine-enable promotion can be obtained from it.
pub unsafe trait PrepublicationCustody: ConfigCustody {}
/// # Safety
/// Actual complete root/source/unit retirement and source-owned topology
/// promotion produced this SAME original slot/mapping exactly once. Retain
/// original bridge assignment and native resource/control obligations; presence
/// of a config object, stop reason, callback, bool or chosen Vec is not proof.
pub unsafe trait DriverCustody: ConfigCustody {}

/// IO admission state moves with the affine grant, including safe extraction
/// and reattachment. A new Region cannot erase an old failure or BME seal.
pub(super) struct State {
    pub(super) terminal: Cell<Option<ConfigError>>,
    close: RefCell<Option<AdmissionClose>>,
    pub(super) operation: RefCell<Option<ConfigOperation>>,
    pub(super) waiting: Cell<Option<ConfigError>>,
    pub(super) acting: Cell<bool>,
    pub(super) effect: Cell<super::super::ConfigEffect>,
    pub(super) master_sealed: Cell<bool>,
    pub(super) routing_seal: Cell<Option<([u32; 7], u16)>>,
}
impl State {
    pub(super) fn close_metadata(&self) {
        if let Some(close) = self.close.borrow().as_ref() {
            close.close();
        }
        if let Ok(operation) = self.operation.try_borrow()
            && let Some(operation) = operation.as_ref()
        {
            operation.close_metadata();
        }
    }
    pub(super) fn admission_close(&self) -> Result<AdmissionClose, MappingError> {
        self.close
            .borrow()
            .as_ref()
            .map(AdmissionClose::retain_close)
            .ok_or(MappingError::Retired)
    }
    pub(super) fn dismiss_close(&self) {
        if let Some(close) = self.close.borrow_mut().take() {
            close.dismiss();
        }
    }
    fn new(close: AdmissionClose) -> Self {
        Self {
            terminal: Cell::new(None),
            close: RefCell::new(Some(close)),
            operation: RefCell::new(None),
            waiting: Cell::new(None),
            acting: Cell::new(false),
            effect: Cell::new(super::super::ConfigEffect::None),
            master_sealed: Cell::new(false),
            routing_seal: Cell::new(None),
        }
    }
}
/// Original owned prepublication custody. No successful default/native model
/// implementation is supplied; only the real root producer may implement it.
pub struct PrepublicationGrant {
    original: ManuallyDrop<Box<dyn PrepublicationCustody>>,
    returned: bool,
    state: ManuallyDrop<Box<State>>,
}
/// Original final driver custody from actual whole-fabric promotion, not a
/// compatibility constructor that accepts an unpublished or raw config view.
pub struct DriverGrant {
    original: ManuallyDrop<Box<dyn DriverCustody>>,
    returned: bool,
    state: ManuallyDrop<Box<State>>,
}
impl PrepublicationGrant {
    /// Recover the same source controller for a consuming phase transition.
    /// Matching the Rust type supplies no resource or epoch provenance; the
    /// controller still owns those original products and must validate them.
    /// A mismatch returns this unchanged grant without closing its admission.
    /// # Safety
    /// This consumes the complete grant state too. No failure/seal may be
    /// bypassed: all old users must retire and the source phase transaction
    /// must preserve every original obligation before constructing a new grant.
    pub unsafe fn into_typed<P: PrepublicationCustody>(mut self) -> Result<P, Self> {
        if (**self.original).type_id() != core::any::TypeId::of::<P>() {
            return Err(self);
        }
        self.state.dismiss_close();
        self.returned = true;
        // SAFETY: this affine grant transfers the complete controller once.
        let original = unsafe { ManuallyDrop::take(&mut self.original) };
        // SAFETY: Any's exact TypeId above identifies P, including its concrete
        // allocation layout. Only the trait-object metadata is discarded. No
        // field, mapping, reservation or lifetime is reconstructed or released.
        Ok(*unsafe { Box::from_raw(Box::into_raw(original).cast::<P>()) })
    }
    /// Change a private source controller without replacing its grant's
    /// terminal/seal state or reconstructing its physical products.
    pub fn update_typed<P: PrepublicationCustody, R>(
        &mut self,
        update: impl FnOnce(&mut P) -> R,
    ) -> Option<R> {
        if (**self.original).type_id() != core::any::TypeId::of::<P>() {
            return None;
        }
        let original = &mut **self.original as *mut dyn PrepublicationCustody;
        // SAFETY: exact Any type above and this affine grant's unique mutable
        // borrow; no allocation, lifetime or original control is replaced.
        Some(update(unsafe { &mut *original.cast::<P>() }))
    }
    /// # Safety
    /// The preowned close must belong to the same actual assignment and
    /// ancestor graph as the boxed custody. Capture it before mapping or
    /// configuration effects. The caller owns the original custody allocation.
    pub unsafe fn from_boxed<P: PrepublicationCustody>(
        original: Box<P>,
        close: AdmissionClose,
    ) -> Self {
        let original: Box<dyn PrepublicationCustody> = original;
        // Keep original custody even if allocating the operation state fails.
        let original = ManuallyDrop::new(original);
        Self {
            state: ManuallyDrop::new(Box::new(State::new(close))),
            original,
            returned: false,
        }
    }
    /// # Safety
    /// All represented native users/mappings have retired or this unexposed
    /// original graph is being transferred intact to its real source owner.
    /// Returning custody acknowledges no hardware/DMA/root completion itself.
    /// The source phase transition must preserve terminal errors and seals;
    /// extracting a controller cannot authorize recreating unsealed IO.
    pub unsafe fn into_original(mut self) -> Box<dyn PrepublicationCustody> {
        // SAFETY: one consumed grant, never cloned, no implicit native release.
        self.state.dismiss_close();
        self.returned = true;
        // SAFETY: the consumed grant transfers this same original controller
        // once; caller preserves every live-user, terminal and seal obligation.
        unsafe { ManuallyDrop::take(&mut self.original) }
    }
}
impl DriverGrant {
    pub fn admission_close(&self) -> Result<AdmissionClose, MappingError> {
        self.state.admission_close()
    }
    /// # Safety
    /// The preowned close must belong to the same actual assignment and
    /// ancestor graph as the boxed custody. Capture it before mapping or
    /// configuration effects. The caller owns the original custody allocation.
    pub unsafe fn from_boxed<P: DriverCustody>(original: Box<P>, close: AdmissionClose) -> Self {
        let original: Box<dyn DriverCustody> = original;
        // Keep original custody even if allocating the operation state fails.
        let original = ManuallyDrop::new(original);
        Self {
            state: ManuallyDrop::new(Box::new(State::new(close))),
            original,
            returned: false,
        }
    }
    /// # Safety
    /// All actual driver/config/BAR/map/IRQ/DMA/callback users have stopped and
    /// been joined, or the complete unchanged owning graph transfers intact.
    /// Source-specific final retirement still requires actual original proof.
    /// The source must preserve all terminal/seal state before any new grant.
    pub unsafe fn into_original(mut self) -> Box<dyn DriverCustody> {
        // SAFETY: one consumed actual source grant, no metadata reconstruction.
        self.state.dismiss_close();
        self.returned = true;
        // SAFETY: the consumed grant transfers this same original controller
        // once; caller preserves every live-user, terminal and seal obligation.
        unsafe { ManuallyDrop::take(&mut self.original) }
    }
}
pub(super) trait Grant {
    fn custody(&self) -> &dyn ConfigCustody;
    fn state(&self) -> &State;
}
impl Grant for PrepublicationGrant {
    fn custody(&self) -> &dyn ConfigCustody {
        &**self.original
    }
    fn state(&self) -> &State {
        &self.state
    }
}
impl Grant for DriverGrant {
    fn custody(&self) -> &dyn ConfigCustody {
        &**self.original
    }
    fn state(&self) -> &State {
        &self.state
    }
}
pub(super) fn foreign_grant() -> ConfigError {
    ConfigError::before_effect(ConfigFailure::ForeignGrant)
}
impl Drop for PrepublicationGrant {
    fn drop(&mut self) {
        if self.returned {
            // SAFETY: explicit owner transfer dismissed the state projection.
            unsafe { ManuallyDrop::drop(&mut self.state) };
        } else {
            self.state.close_metadata();
        }
        // Abandonment retains the original controller and parked state.
    }
}
impl Drop for DriverGrant {
    fn drop(&mut self) {
        if self.returned {
            // SAFETY: explicit owner transfer dismissed the state projection.
            unsafe { ManuallyDrop::drop(&mut self.state) };
        } else {
            self.state.close_metadata();
        }
    }
}
