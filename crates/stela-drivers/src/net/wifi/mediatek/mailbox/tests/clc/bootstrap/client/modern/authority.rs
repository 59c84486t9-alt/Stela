//! Authority for the same stateful simulated PCI requester, never physical
//! permission. The model's revocation and source allocations obey held guards.
use super::*;
use crate::net::wifi::regulatory::{self as reg, AssociationUse};
use alloc::rc::Rc;
use core::cell::{Cell, RefCell};

pub(super) struct AuthorityState {
    hardware: Cell<bool>,
    os: Cell<bool>,
    pub(super) allowed: Cell<bool>,
    pub(super) revision: Cell<u64>,
    native: reg::NativeContext,
    context: Arc<station::AssociationContext>,
    response: Arc<Mutex<Response>>,
    // Retain this exact requester registry independently of diagnostic numbers.
    _memory: Arc<Mutex<Memory>>,
    pub(super) windows: RefCell<Vec<(usize, usize)>>,
    pub(super) allocations: Cell<usize>,
}
pub(super) struct Hardware(Rc<AuthorityState>);
pub(super) struct Os(Rc<AuthorityState>);
pub(super) struct HardwareGuard {
    state: Rc<AuthorityState>,
    start: usize,
}
pub(super) struct OsGuard(Rc<AuthorityState>);
impl Drop for HardwareGuard {
    fn drop(&mut self) {
        assert!(!self.state.os.get());
        let end = self.state.response.lock().unwrap().client_commands.len();
        self.state.windows.borrow_mut().push((self.start, end));
        self.state.hardware.set(false);
    }
}
impl Drop for OsGuard {
    fn drop(&mut self) {
        assert!(self.0.hardware.get());
        self.0.os.set(false);
    }
}
impl reg::HardwareLease for HardwareGuard {
    fn context(&self) -> reg::NativeContext {
        self.state.native
    }
    fn lookup_channel(&mut self, band: Band, number: u16) -> Option<wifi::Channel> {
        (band == CHANNEL.band && number == CHANNEL.number).then_some(CHANNEL)
    }
    fn allows(&mut self, _: reg::Operation) -> bool {
        false
    }
    fn allows_association(&mut self, operation: &reg::AssociationOperation<'_>) -> bool {
        assert!(self.state.hardware.get() && self.state.os.get());
        let response = self.state.response.lock().unwrap();
        self.state.allowed.get()
            && core::ptr::eq(operation.context(), self.state.context.as_ref())
            && response.regulatory_domain
            && !response.regulatory_power.is_empty()
            && operation
                .context()
                .negotiated()
                .local()
                .local_he_source_maps()
                .is_some()
            && matches!(
                operation.context().definition().width,
                Width::Mhz20 | Width::Mhz40 | Width::Mhz80 | Width::Mhz160
            )
    }
}
impl reg::OsLease for OsGuard {
    fn revision(&self) -> u64 {
        self.0.revision.get()
    }
    fn allows(&mut self, _: reg::Operation) -> bool {
        false
    }
    fn allows_association(&mut self, operation: &reg::AssociationOperation<'_>) -> bool {
        assert!(self.0.hardware.get() && self.0.os.get());
        self.0.allowed.get() && core::ptr::eq(operation.context(), self.0.context.as_ref())
    }
}
// SAFETY: only this single-threaded model's requester is qualified. Revocation
// respects these held guards; this supplies no physical platform authority.
unsafe impl reg::HardwarePolicy for Hardware {
    type Lease<'a> = HardwareGuard;
    fn acquire(&mut self) -> Option<Self::Lease<'_>> {
        assert!(!self.0.os.get());
        if self.0.hardware.replace(true) {
            return None;
        }
        let start = self.0.response.lock().unwrap().client_commands.len();
        Some(HardwareGuard {
            state: self.0.clone(),
            start,
        })
    }
}
// SAFETY: model OS authority belongs to that exact retained requester/context
// and remains inside its hardware guard, including real packet allocations.
unsafe impl reg::OsPolicy for Os {
    type Lease<'a> = OsGuard;
    fn acquire(&mut self, native: reg::NativeContext) -> Option<Self::Lease<'_>> {
        assert!(self.0.hardware.get());
        if native != self.0.native || self.0.os.replace(true) {
            return None;
        }
        Some(OsGuard(self.0.clone()))
    }
}
pub(super) type Owner = reg::Owner<Hardware, Os>;
pub(super) fn authority(
    driver: &Client<Bar, Q, NativeGuard>,
    model: &Model,
) -> (Owner, Rc<AuthorityState>) {
    let state = Rc::new(AuthorityState {
        hardware: Cell::new(false),
        os: Cell::new(false),
        allowed: Cell::new(true),
        revision: Cell::new(1),
        native: reg::NativeContext {
            device: Arc::as_ptr(&model.memory) as usize as u64,
            reset_epoch: 1,
            firmware_epoch: 1,
            policy_revision: 1,
        },
        context: driver.modern_context().unwrap().clone(),
        response: model.response.clone(),
        _memory: model.memory.clone(),
        windows: RefCell::new(Vec::new()),
        allocations: Cell::new(0),
    });
    let owner = reg::Owner::new(Hardware(state.clone()), Os(state.clone())).unwrap();
    (owner, state)
}
pub(super) fn admit(
    owner: &mut Owner,
    driver: &Client<Bar, Q, NativeGuard>,
    purpose: AssociationUse,
) -> reg::AssociationAdmission {
    owner
        .admit_association(
            driver.station(),
            driver.modern_context().unwrap().clone(),
            purpose,
        )
        .unwrap()
}
pub(super) struct GuardedSource(pub(super) Rc<AuthorityState>);
impl crate::bus::dma::memory::PageSource for GuardedSource {
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: crate::bus::dma::memory::CacheAttribute,
    ) -> Result<crate::bus::dma::memory::PinnedPages, crate::bus::dma::memory::MemoryError> {
        assert!(self.0.hardware.get() && self.0.os.get());
        self.0.allocations.set(self.0.allocations.get() + 1);
        crate::bus::dma::memory::PageSource::allocate(&Source, bytes, alignment, attribute)
    }
}
