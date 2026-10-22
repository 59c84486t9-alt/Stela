//! Owned CPU preparation of the original native device state, before RM.
//! No RM entry, PCI enable, GPU mapping, IRQ, firmware or submission is invoked.
use super::{
    PciHandle,
    services::{MemoryServices, ServiceError},
};
use crate::bus::{
    dma::{mapping::DmaDomain, memory::PageSource},
    mmio::owned::{Resource, ResourceKind},
    pci::{Address, ConfigSpace},
};
use alloc::{
    alloc::{alloc_zeroed, dealloc},
    boxed::Box,
    sync::Arc,
};
use core::{
    alloc::Layout,
    cell::{Cell, UnsafeCell},
    ffi::c_void,
    marker::{PhantomData, PhantomPinned},
    pin::Pin,
    ptr::NonNull,
};
use triomphe::UniqueArc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub address: Address,
    pub vendor: u16,
    pub device: u16,
    pub subsystem_vendor: u16,
    pub subsystem: u16,
    pub virtual_function: bool,
}
/// The index is the actual PCI configuration BAR index, not the original RM role.
pub struct Aperture {
    pub index: u8,
    pub resource: Resource,
}
/// Original REGS/FB/IMEM roles. The C constructor checks their original order
/// against actual BAR encodings; a caller cannot relabel arbitrary resources.
pub struct Apertures {
    pub registers: Aperture,
    pub framebuffer: Aperture,
    pub instance: Option<Aperture>,
}
/// Genuine same-PF power/reset/resource epoch. No implementation is supplied.
///
/// # Safety
/// This owns the actual immutable identity, exclusive D0/parent-bridge/reset/
/// removal epoch and Resources of the SAME function as the owned ConfigSpace.
/// Resources independently retain teardown-critical backing, including canonical
/// mapping quarantine. Their reported spans/kinds/roles are genuine assigned BARs.
/// Exclude every other driver, firmware, DMA, IRQ, reset and configuration user.
/// `check_context` checks the actual allowed process/native CPU without device
/// access, allocation, unwind or reentry. Calls and final release obey the heap,
/// PageSource, domain and resource owners' real context rules. It supplies no
/// allocator, IRQ-context predicate, timer or initialized-RM assertion.
pub unsafe trait Owner: 'static {
    fn identity(&self) -> Identity;
    fn apertures(&self) -> Apertures;
    fn check_context(&self) -> Result<(), i32>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidOwner,
    InvalidResource,
    InvalidLayout,
    OutOfMemory,
    Context(i32),
    Native(u32),
    Services(ServiceError),
    Retired,
}
#[repr(C)]
struct NativeBar {
    physical: u64,
    bytes: u64,
    index: u32,
    prefetchable: u32,
}
#[repr(C)]
struct NativeIdentity {
    domain: u32,
    bus: u32,
    slot: u32,
    function: u32,
    vendor: u32,
    device: u32,
    subsystem_vendor: u32,
    subsystem: u32,
}
const _: () = assert!(size_of::<NativeBar>() == 24 && size_of::<NativeIdentity>() == 32);
unsafe extern "C" {
    fn stela_nvidia_state_layout(bytes: *mut u64, alignment: *mut u64);
    fn stela_nvidia_prepare_device(
        state: *mut c_void,
        handle: *mut c_void,
        identity: &NativeIdentity,
        bars: *const NativeBar,
        count: u32,
    ) -> u32;
    fn stela_nvidia_prepared_device_retirable(state: *const c_void, handle: *const c_void) -> u32;
}
struct State {
    pointer: NonNull<u8>,
    layout: Layout,
}
impl State {
    fn reserve() -> Result<Self, Error> {
        let (mut bytes, mut alignment) = (0, 0);
        // SAFETY: original C type layout query; no native resource access.
        unsafe { stela_nvidia_state_layout(&mut bytes, &mut alignment) };
        let bytes = usize::try_from(bytes).map_err(|_| Error::InvalidLayout)?;
        let alignment = usize::try_from(alignment).map_err(|_| Error::InvalidLayout)?;
        let layout = Layout::from_size_align(bytes, alignment).map_err(|_| Error::InvalidLayout)?;
        if bytes == 0 {
            return Err(Error::InvalidLayout);
        }
        #[cfg(test)]
        tests::reserve()?;
        // SAFETY: exact checked original type layout, existing common allocator.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(Error::OutOfMemory)?;
        Ok(Self { pointer, layout })
    }
    fn raw(&self) -> *mut c_void {
        self.pointer.as_ptr().cast()
    }
}
impl Drop for State {
    fn drop(&mut self) {
        // SAFETY: exact checked allocation; no users remain on known retirement.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}
// Drop order matters: internal references end before their wholly owned targets.
// UnsafeCell prevents a shared Bundle observation freezing the private C-owned
// service/configuration storage. There are no public field projections.
struct Bundle<C: ConfigSpace + 'static> {
    services: UnsafeCell<Option<MemoryServices<'static>>>,
    pci: UnsafeCell<Option<PciHandle<'static>>>,
    state: State,
    config: UnsafeCell<Box<C>>,
    _source: Box<dyn PageSource>,
    owner: Box<dyn Owner>,
    _apertures: Apertures,
    identity: Identity,
    callback_failure: Cell<Option<i32>>,
    _pin: PhantomPinned,
}
impl<C: ConfigSpace + 'static> Bundle<C> {
    fn callback_context(&self) -> Result<(), i32> {
        if let Some(status) = self.callback_failure.get() {
            return Err(status);
        }
        let result = self.owner.check_context();
        if let Err(status) = result {
            // Preserve the first actual callback-context failure. A later
            // successful query cannot certify an effect that was uncertain.
            self.callback_failure.set(Some(status));
        }
        result
    }
}
// These private callbacks reuse the existing three-word PCI ABI and its exact
// failure return, not a ConfigSpace sentinel value or a new transport. The
// native constructor owns no other access to config. Bundle/owner/config are
// stable and callbacks are serialized, with no reentry or public raw escape.
unsafe extern "C" fn checked_read<C: ConfigSpace + 'static>(
    context: *mut c_void,
    offset: u32,
    width: u32,
    value: *mut u32,
) -> u32 {
    // SAFETY: this handle points to its same live private pinned Bundle.
    let this = unsafe { &*context.cast::<Bundle<C>>() };
    if this.callback_context().is_err() {
        return 0;
    }
    // SAFETY: config is disjoint from owner/latch and inside UnsafeCell; its
    // stable owned target has no other Rust/native users. Existing read checks
    // width/range and accesses the actual ConfigSpace with that exact width.
    let config = unsafe { (&**this.config.get() as *const C).cast_mut().cast() };
    let mut result = 0;
    // SAFETY: `config` is this callback's live, exclusive target.
    let status = unsafe { super::read::<C>(config, offset, width, &mut result) };
    if this.callback_context().is_err() {
        return 0;
    }
    if status != 0 {
        // SAFETY: original C shim supplies a live aligned writable u32. Only a
        // qualified successful actual access may publish its returned value.
        unsafe { value.write(result) };
    }
    status
}
unsafe extern "C" fn checked_write<C: ConfigSpace + 'static>(
    context: *mut c_void,
    offset: u32,
    width: u32,
    value: u32,
) -> u32 {
    // SAFETY: same private stable Bundle and serialized/nonreentrant ABI.
    let this = unsafe { &*context.cast::<Bundle<C>>() };
    if this.callback_context().is_err() {
        return 0;
    }
    // SAFETY: exclusive target access through the disjoint UnsafeCell; existing
    // write preserves actual width and performs no read/modify/write substitute.
    let config = unsafe { (&mut **this.config.get() as *mut C).cast() };
    // SAFETY: `config` is this callback's live, exclusive target.
    let status = unsafe { super::write::<C>(config, offset, width, value) };
    if this.callback_context().is_err() {
        return 0;
    }
    status
}
/// Pinned, fully owned prepared metadata. Neither Send nor Sync. No safe C
/// pointer or runtime-ready token escapes, and no method calls original RM.
/// Explicit retirement failure retains the whole bundle. Drop uncertainty
/// deliberately retains that SAME allocation and every actual owner indefinitely;
/// it cannot extend a borrow, fake reset/drain or release partially live state.
pub struct PreparedDevice<C: ConfigSpace + 'static> {
    bundle: Option<Pin<UniqueArc<Bundle<C>>>>,
}
fn native_bar(bar: &Aperture) -> Result<NativeBar, Error> {
    let span = bar.resource.physical_span();
    if bar.index >= 6 || span.start() == 0 {
        return Err(Error::InvalidResource);
    }
    Ok(NativeBar {
        physical: span.start(),
        bytes: span.bytes(),
        index: u32::from(bar.index),
        prefetchable: u32::from(bar.resource.kind() == ResourceKind::PrefetchableMemory),
    })
}
impl<C: ConfigSpace + 'static> PreparedDevice<C> {
    /// Assemble actual native input ownership, without invoking RM.
    ///
    /// # Safety
    /// `owner`, owned `config`, source and attached `domain` describe the SAME
    /// actual PF/reset epoch. The domain/address_limit is its real isolated DMA
    /// policy, not identity DMA or a guessed GPU address width. Actual source
    /// geometry must already be installed before any RM callers. The heap and
    /// all owned dependencies remain valid through final retirement/quarantine.
    /// No caller retains configuration/native aliases or may reenter this scope.
    /// Box/Arc inputs must own their dependencies; borrowed/non-static stand-ins
    /// cannot survive uncertainty and are intentionally excluded.
    pub unsafe fn prepare(
        config: Box<C>,
        owner: Box<dyn Owner>,
        source: Box<dyn PageSource>,
        domain: Arc<dyn DmaDomain>,
        page_shift: u8,
        address_limit: u64,
    ) -> Result<Self, Error> {
        if let Err(status) = owner.check_context() {
            // No allocation or final owner release is safe in an unqualified
            // context. These inputs are already wholly owned; retain all of
            // them without allocating a bundle or extending any borrow.
            core::mem::forget((config, owner, source, domain));
            return Err(Error::Context(status));
        }
        // Keep every dependency and prepared allocation outside this fallible
        // phase. A provider callback may refuse after context is lost; no `?`
        // inside the phase may then release the last actual owner.
        let (mut apertures, mut services, mut state) = (None, None, None);
        let prepared = (|| {
            let identity = owner.identity();
            owner.check_context().map_err(Error::Context)?;
            if identity.vendor != 0x10de
                || identity.device == 0xffff
                || identity.virtual_function
                || identity.address.device >= 32
                || identity.address.function >= 8
            {
                return Err(Error::InvalidOwner);
            }
            apertures = Some(owner.apertures());
            owner.check_context().map_err(Error::Context)?;
            let apertures = apertures.as_ref().expect("prepared apertures");
            if apertures.registers.resource.kind() != ResourceKind::Registers {
                return Err(Error::InvalidResource);
            }
            let mut bars = [
                native_bar(&apertures.registers)?,
                native_bar(&apertures.framebuffer)?,
                NativeBar {
                    physical: 0,
                    bytes: 0,
                    index: 0,
                    prefetchable: 0,
                },
            ];
            let count = if let Some(bar) = &apertures.instance {
                bars[2] = native_bar(bar)?;
                3
            } else {
                2
            };
            for i in 0..count {
                for j in i + 1..count {
                    if bars[i].physical < bars[j].physical + bars[j].bytes
                        && bars[j].physical < bars[i].physical + bars[i].bytes
                    {
                        return Err(Error::InvalidResource);
                    }
                }
            }
            // Metadata callbacks cannot authorize the following provider call.
            owner.check_context().map_err(Error::Context)?;
            // SAFETY: stable owned Box target. The private bundle drops services
            // before source, or BOTH are retained on uncertain context. No
            // internal lifetime or source reference is exposed to a caller.
            let source_ref: &'static dyn PageSource =
                unsafe { &*(&*source as *const dyn PageSource) };
            // SAFETY: caller supplies the actual requester/domain/cache contract.
            // Retain the original Arc until context is checked on either result;
            // the constructor's error may drop only this non-final clone.
            services = Some(
                unsafe {
                    MemoryServices::new(
                        source_ref,
                        Arc::clone(&domain),
                        identity.address,
                        page_shift,
                        address_limit,
                    )
                }
                .map_err(Error::Services)?,
            );
            // A successful geometry callback can still lose context. Do not
            // allocate state or touch configuration until it is requalified.
            owner.check_context().map_err(Error::Context)?;
            state = Some(State::reserve()?);
            // Requalify before the next heap effect; a failed phase still
            // retains this exact reserved State with all dependency owners.
            owner.check_context().map_err(Error::Context)?;
            #[cfg(test)]
            tests::reserve()?;
            let storage =
                UniqueArc::<Bundle<C>>::try_new_uninit().map_err(|_| Error::OutOfMemory)?;
            Ok((identity, bars, count, storage))
        })();
        if let Err(status) = owner.check_context() {
            // Covers success AND error of every callback/reservation above,
            // including source geometry refusal. Retain all exact ownership;
            // no final Arc release, metadata free or allocation is attempted.
            core::mem::forget((
                config, owner, source, domain, apertures, services, state, prepared,
            ));
            return Err(Error::Context(status));
        }
        let (identity, bars, count, mut storage) = prepared?;
        // The service owns another Arc, and the actual context remains valid.
        drop(domain);
        storage.write(Bundle {
            services: UnsafeCell::new(services),
            pci: UnsafeCell::new(None),
            state: state.expect("reserved state"),
            config: UnsafeCell::new(config),
            _source: source,
            owner,
            _apertures: apertures.expect("prepared apertures"),
            identity,
            callback_failure: Cell::new(None),
            _pin: PhantomPinned,
        });
        // SAFETY: every field was initialized once in its final unique allocation.
        let mut bundle = unsafe { Pin::new_unchecked(UniqueArc::assume_init(storage)) };
        // SAFETY: unique unpublished pinned allocation; no native/Rust aliases.
        let this = unsafe { bundle.as_mut().get_unchecked_mut() };
        let context = (this as *mut Bundle<C>).cast();
        // SAFETY: still unpublished. The same existing PciHandle ABI points
        // back to this pinned owned Bundle; no safe reference or raw C pointer
        // escapes. Per-access callbacks qualify actual context and retain the
        // first failure before native preparation may publish any state.
        let pci = unsafe { &mut *this.pci.get() };
        *pci = Some(PciHandle {
            context,
            read: checked_read::<C>,
            write: checked_write::<C>,
            _borrow: PhantomData,
            _pin: PhantomPinned,
        });
        // SAFETY: handle now occupies its final pinned slot until retirement.
        let handle =
            unsafe { Pin::new_unchecked(pci.as_mut().expect("initialized handle")).as_raw() };
        let id = NativeIdentity {
            domain: u32::from(identity.address.segment),
            bus: u32::from(identity.address.bus),
            slot: u32::from(identity.address.device),
            function: u32::from(identity.address.function),
            vendor: u32::from(identity.vendor),
            device: u32::from(identity.device),
            subsystem_vendor: u32::from(identity.subsystem_vendor),
            subsystem: u32::from(identity.subsystem),
        };
        // SAFETY: original C state, pinned actual handle and bounded disjoint
        // CPU inputs. This reads configuration only; error publishes no state.
        let status = unsafe {
            stela_nvidia_prepare_device(this.state.raw(), handle, &id, bars.as_ptr(), count as u32)
        };
        if let Err(status) = this.callback_context() {
            // Configuration callbacks cannot grant a different CPU/context.
            // Retain the same complete reserved bundle if qualification is lost.
            core::mem::forget(bundle);
            return Err(Error::Context(status));
        }
        if status != 0 {
            return Err(Error::Native(status));
        }
        // SAFETY: all fallible reservations/validation finished. Original state
        // has real PCI identity and empty slots; no native caller can access it.
        unsafe {
            Pin::new_unchecked(
                (&mut *this.services.get())
                    .as_mut()
                    .expect("reserved service"),
            )
            .bind(this.state.raw())
        }
        .map_err(Error::Services)?;
        Ok(Self {
            bundle: Some(bundle),
        })
    }
    pub fn identity(&self) -> Option<Identity> {
        self.bundle.as_ref().map(|b| b.identity)
    }
    /// Retire only still-prepared metadata. A real refusal leaves ALL ownership
    /// intact and retryable; this performs no hardware/RM/reset operation.
    pub fn retire(&mut self) -> Result<(), Error> {
        let bundle = self.bundle.as_mut().ok_or(Error::Retired)?;
        if let Some(status) = bundle.callback_failure.get() {
            return Err(Error::Context(status));
        }
        bundle.owner.check_context().map_err(Error::Context)?;
        // SAFETY: exclusive prepared device, no C pointer escaped. Context and
        // the existing services' actual live counters govern final release.
        let this = unsafe { bundle.as_mut().get_unchecked_mut() };
        // SAFETY: `this` is exclusive, and the bound handle never moves out of its cell.
        let handle = unsafe {
            Pin::new_unchecked((&mut *this.pci.get()).as_mut().expect("bound handle")).as_raw()
        };
        // SAFETY: both pointers belong to this live prepared device.
        let status = unsafe { stela_nvidia_prepared_device_retirable(this.state.raw(), handle) };
        if status != 0 {
            return Err(Error::Native(status));
        }
        // SAFETY: `this` is exclusive, and the bound services never move out of their cell.
        unsafe {
            Pin::new_unchecked((&mut *this.services.get()).as_mut().expect("bound service"))
                .unbind()
        }
        .map_err(Error::Services)?;
        self.bundle = None;
        Ok(())
    }
}
impl<C: ConfigSpace + 'static> Drop for PreparedDevice<C> {
    fn drop(&mut self) {
        if self.bundle.is_some() && self.retire().is_err() {
            // Retain actual wholly OWNED state/handles/source/config/resources/
            // reset owner, using existing allocation ownership. No borrow is
            // extended and no quarantine registry or late allocation is added.
            if let Some(bundle) = self.bundle.take() {
                core::mem::forget(bundle);
            }
        }
    }
}
#[cfg(test)]
mod tests {
    //! CPU-only owned canonical resource/config/page models; no RM or hardware.
    use super::*;
    use crate::bus::{
        dma::{
            mapping::{Direction, DmaError, DomainMapping},
            memory::{CacheAttribute, MemoryError, PageBacking, PageGeometry, PinnedPages},
        },
        mmio::owned::{PhysicalSpan, ResourceBacking},
    };
    use alloc::vec::Vec;
    use core::{
        cell::Cell,
        ops::Range,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    extern crate std;
    std::thread_local! { static BUDGET: Cell<Option<usize>> = const {Cell::new(None)}; }
    pub(super) fn reserve() -> Result<(), Error> {
        BUDGET.with(|b| match b.get() {
            Some(0) => Err(Error::OutOfMemory),
            Some(n) => {
                b.set(Some(n - 1));
                Ok(())
            }
            None => Ok(()),
        })
    }
    struct Counts {
        drops: [AtomicUsize; 5],
        context: AtomicBool,
        reads: AtomicUsize,
        lose_context: AtomicBool,
        lose_at: AtomicUsize,
        geometry_failure: AtomicUsize,
        geometry_calls: AtomicUsize,
        metadata_loss: AtomicUsize,
        recover_on_check: AtomicBool,
        writes: AtomicUsize,
        write_width: AtomicUsize,
        write_value: AtomicUsize,
        write_loss: AtomicBool,
    }
    impl Counts {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                drops: core::array::from_fn(|_| AtomicUsize::new(0)),
                context: AtomicBool::new(true),
                reads: AtomicUsize::new(0),
                lose_context: AtomicBool::new(false),
                lose_at: AtomicUsize::new(60),
                geometry_failure: AtomicUsize::new(0),
                geometry_calls: AtomicUsize::new(0),
                metadata_loss: AtomicUsize::new(0),
                recover_on_check: AtomicBool::new(false),
                writes: AtomicUsize::new(0),
                write_width: AtomicUsize::new(0),
                write_value: AtomicUsize::new(0),
                write_loss: AtomicBool::new(false),
            })
        }
        fn values(&self) -> [usize; 5] {
            core::array::from_fn(|i| self.drops[i].load(Ordering::SeqCst))
        }
    }
    struct Config {
        words: [u32; 16],
        counts: Arc<Counts>,
    }
    impl ConfigSpace for Config {
        fn read32(&self, offset: u16) -> u32 {
            self.counts.reads.fetch_add(1, Ordering::SeqCst);
            if usize::from(offset) == self.counts.lose_at.load(Ordering::SeqCst)
                && self.counts.lose_context.load(Ordering::SeqCst)
            {
                self.counts.context.store(false, Ordering::SeqCst);
            }
            self.words[usize::from(offset) / 4]
        }
        fn write32(&mut self, _: u16, value: u32) {
            self.record_write(4, value);
        }
        fn write16(&mut self, _: u16, value: u16) {
            self.record_write(2, u32::from(value));
        }
        fn write8(&mut self, _: u16, value: u8) {
            self.record_write(1, u32::from(value));
        }
    }
    impl Config {
        fn record_write(&self, width: usize, value: u32) {
            self.counts.writes.fetch_add(1, Ordering::SeqCst);
            self.counts.write_width.store(width, Ordering::SeqCst);
            self.counts
                .write_value
                .store(value as usize, Ordering::SeqCst);
            if self.counts.write_loss.load(Ordering::SeqCst) {
                self.counts.context.store(false, Ordering::SeqCst);
            }
        }
    }
    impl Drop for Config {
        fn drop(&mut self) {
            self.counts.drops[1].fetch_add(1, Ordering::SeqCst);
        }
    }
    struct Backing {
        span: PhysicalSpan,
        kind: ResourceKind,
        counts: Arc<Counts>,
    }
    // SAFETY: immutable distinct synthetic resource labels; never a native grant.
    unsafe impl ResourceBacking for Backing {
        fn physical_span(&self) -> PhysicalSpan {
            self.span
        }
        fn kind(&self) -> ResourceKind {
            self.kind
        }
    }
    impl Drop for Backing {
        fn drop(&mut self) {
            self.counts.drops[4].fetch_add(1, Ordering::SeqCst);
        }
    }
    struct Epoch {
        identity: Identity,
        bars: Apertures,
        counts: Arc<Counts>,
    }
    // SAFETY: all input callbacks/resources are bounded CPU-only models in this test.
    unsafe impl Owner for Epoch {
        fn identity(&self) -> Identity {
            if self.counts.metadata_loss.load(Ordering::SeqCst) == 1 {
                self.counts.context.store(false, Ordering::SeqCst);
            }
            self.identity
        }
        fn apertures(&self) -> Apertures {
            if self.counts.metadata_loss.load(Ordering::SeqCst) == 2 {
                self.counts.context.store(false, Ordering::SeqCst);
            }
            let copy = |x: &Aperture| Aperture {
                index: x.index,
                resource: x.resource.clone(),
            };
            Apertures {
                registers: copy(&self.bars.registers),
                framebuffer: copy(&self.bars.framebuffer),
                instance: self.bars.instance.as_ref().map(copy),
            }
        }
        fn check_context(&self) -> Result<(), i32> {
            if self.counts.context.load(Ordering::SeqCst) {
                Ok(())
            } else {
                if self.counts.recover_on_check.swap(false, Ordering::SeqCst) {
                    self.counts.context.store(true, Ordering::SeqCst);
                }
                Err(-77)
            }
        }
    }
    impl Drop for Epoch {
        fn drop(&mut self) {
            self.counts.drops[0].fetch_add(1, Ordering::SeqCst);
        }
    }
    struct Source(Arc<Counts>);
    struct Page {
        pointer: NonNull<u8>,
        physical: [u64; 1],
        layout: Layout,
    }
    // SAFETY: exclusively allocated model bytes, immutable metadata, no hardware.
    unsafe impl Send for Page {}
    // SAFETY: only the retained CPU-model pin accesses these bytes, serialized here.
    unsafe impl Sync for Page {}
    // SAFETY: zeroed aligned CPU allocation with distinct model PA label, pinned to Drop.
    unsafe impl PageBacking for Page {
        fn cpu_base(&self) -> NonNull<u8> {
            self.pointer
        }
        fn physical_pages(&self) -> &[u64] {
            &self.physical
        }
        fn page_shift(&self) -> u8 {
            12
        }
        fn cache_attribute(&self) -> CacheAttribute {
            CacheAttribute::WriteBack
        }
    }
    impl Drop for Page {
        fn drop(&mut self) {
            unsafe { dealloc(self.pointer.as_ptr(), self.layout) }
        }
    }
    impl PageSource for Source {
        fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
            self.0.geometry_calls.fetch_add(1, Ordering::SeqCst);
            match self.0.geometry_failure.load(Ordering::SeqCst) {
                1 => return Err(MemoryError::Unavailable),
                2 => {
                    self.0.context.store(false, Ordering::SeqCst);
                    return Err(MemoryError::Unavailable);
                }
                3 => self.0.context.store(false, Ordering::SeqCst),
                _ => {}
            }
            PageGeometry::base_only(12)
        }
        fn allocate(
            &self,
            bytes: usize,
            alignment: usize,
            cache: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            assert_eq!(
                (bytes, alignment, cache),
                (4096, 4096, CacheAttribute::WriteBack)
            );
            let layout = Layout::from_size_align(4096, 4096).unwrap();
            let pointer =
                NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(MemoryError::OutOfMemory)?;
            PinnedPages::new(
                Box::new(Page {
                    pointer,
                    physical: [0x8000_0000],
                    layout,
                }),
                bytes,
                alignment,
            )
        }
    }
    impl Drop for Source {
        fn drop(&mut self) {
            self.0.drops[2].fetch_add(1, Ordering::SeqCst);
        }
    }
    struct Domain(Arc<Counts>);
    // SAFETY: model explicitly refuses all DMA; no fake successful map or IOVA.
    unsafe impl DmaDomain for Domain {
        unsafe fn map(
            &self,
            _: &PinnedPages,
            _: Direction,
            _: u64,
        ) -> Result<DomainMapping, DmaError> {
            Err(DmaError::IommuUnavailable)
        }
        unsafe fn unmap(&self, _: DomainMapping) -> Result<(), DmaError> {
            panic!("no DMA mappings")
        }
        unsafe fn sync_for_device(
            &self,
            _: DomainMapping,
            _: Range<usize>,
            _: Direction,
        ) -> Result<(), DmaError> {
            panic!("no DMA mappings")
        }
        unsafe fn sync_for_cpu(
            &self,
            _: DomainMapping,
            _: Range<usize>,
            _: Direction,
        ) -> Result<(), DmaError> {
            panic!("no DMA mappings")
        }
    }
    impl Drop for Domain {
        fn drop(&mut self) {
            self.0.drops[3].fetch_add(1, Ordering::SeqCst);
        }
    }
    type Inputs = (
        Box<Config>,
        Box<Epoch>,
        Box<Source>,
        Arc<Domain>,
        Arc<Counts>,
    );
    fn inputs() -> Inputs {
        super::super::page_geometry::tests::initialize_model(12);
        let counts = Counts::new();
        let aperture = |index, start, bytes, kind| Aperture {
            index,
            resource: Resource::new(Box::new(Backing {
                span: PhysicalSpan::new(start, bytes).unwrap(),
                kind,
                counts: counts.clone(),
            })),
        };
        let bars = Apertures {
            registers: aperture(0, 0x1_1000_0000, 0x1_0000, ResourceKind::Registers),
            framebuffer: aperture(
                2,
                0x2_2000_0000,
                0x20_0000,
                ResourceKind::PrefetchableMemory,
            ),
            instance: Some(aperture(
                4,
                0x3_3000_0000,
                0x1_0000,
                ResourceKind::Registers,
            )),
        };
        let identity = Identity {
            address: Address {
                segment: 3,
                bus: 0x42,
                device: 5,
                function: 0,
            },
            vendor: 0x10de,
            device: 0x2684,
            subsystem_vendor: 0x10de,
            subsystem: 0x1234,
            virtual_function: false,
        };
        let mut words = [0; 16];
        words[0] = 0x2684_10de;
        words[2] = 0x0300_0001;
        words[4] = 0x1000_0004;
        words[5] = 1;
        words[6] = 0x2000_000c;
        words[7] = 2;
        words[8] = 0x3000_0004;
        words[9] = 3;
        words[11] = 0x1234_10de;
        (
            Box::new(Config {
                words,
                counts: counts.clone(),
            }),
            Box::new(Epoch {
                identity,
                bars,
                counts: counts.clone(),
            }),
            Box::new(Source(counts.clone())),
            Arc::new(Domain(counts.clone())),
            counts,
        )
    }
    #[test]
    fn original_state_identity_owned_pinning_and_known_retirement() {
        let (config, owner, source, domain, c) = inputs();
        let id = owner.identity;
        let mut d = unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) }
            .unwrap();
        assert_eq!(d.identity(), Some(id));
        assert_eq!(c.reads.load(Ordering::SeqCst), 16);
        assert_eq!(c.writes.load(Ordering::SeqCst), 0);
        assert_eq!(c.values(), [0; 5]);
        let state = d.bundle.as_ref().unwrap().state.raw();
        let moved = Vec::from([d]);
        d = moved.into_iter().next().unwrap();
        assert_eq!(d.bundle.as_ref().unwrap().state.raw(), state);
        d.retire().unwrap();
        assert_eq!(d.identity(), None);
        assert_eq!(c.values(), [1, 1, 1, 1, 3]);
        assert_eq!(d.retire(), Err(Error::Retired));
        drop(d);
        assert_eq!(c.values(), [1, 1, 1, 1, 3]);
    }
    #[test]
    fn mismatched_configuration_bar_roles_context_and_metadata_oom_do_not_bind() {
        for failure in 0..8 {
            let (mut config, mut owner, source, domain, c) = inputs();
            match failure {
                0 => config.words[0] ^= 1,
                1 => config.words[11] ^= 1,
                2 => config.words[4] ^= 0x10000,
                3 => owner.bars.framebuffer.index = 4,
                4 => owner.identity.virtual_function = true,
                5 => c.context.store(false, Ordering::SeqCst),
                6 | 7 => BUDGET.with(|b| b.set(Some(failure - 6))),
                _ => unreachable!(),
            }
            let result =
                unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) };
            BUDGET.with(|b| b.set(None));
            assert!(result.is_err());
            assert_eq!(
                c.values(),
                if failure == 5 {
                    [0; 5]
                } else {
                    [1, 1, 1, 1, 3]
                }
            );
        }
    }
    unsafe extern "C" {
        fn nv_alloc_pages(
            state: *mut c_void,
            count: u32,
            size: u64,
            contiguous: u8,
            cache: u32,
            zeroed: u8,
            unencrypted: u8,
            node: i32,
            ptes: *mut u64,
            private: *mut *mut c_void,
        ) -> u32;
        fn nv_free_pages(
            state: *mut c_void,
            count: u32,
            contiguous: u8,
            cache: u32,
            private: *mut c_void,
        ) -> u32;
    }
    #[test]
    fn real_allocation_counter_refusal_retains_every_owner_and_can_retry() {
        let (config, owner, source, domain, c) = inputs();
        let mut d = unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) }
            .unwrap();
        let state = d.bundle.as_ref().unwrap().state.raw();
        let (mut pa, mut allocation) = (0, core::ptr::null_mut());
        assert_eq!(
            unsafe { nv_alloc_pages(state, 1, 4096, 0, 0, 1, 0, -1, &mut pa, &mut allocation) },
            0
        );
        assert_eq!(pa, 0x8000_0000);
        assert!(matches!(d.retire(), Err(Error::Services(_))));
        assert_eq!(c.values(), [0; 5]);
        assert!(d.identity().is_some());
        assert_eq!(unsafe { nv_free_pages(state, 1, 0, 0, allocation) }, 0);
        d.retire().unwrap();
        assert_eq!(c.values(), [1, 1, 1, 1, 3]);
    }
    #[test]
    fn drop_uncertainty_retains_whole_owned_bundle_without_extending_borrows() {
        let (config, owner, source, domain, c) = inputs();
        let mut d = unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) }
            .unwrap();
        c.context.store(false, Ordering::SeqCst);
        assert_eq!(d.retire(), Err(Error::Context(-77)));
        drop(d);
        assert_eq!(c.values(), [0; 5]); // Intentional permanent owned retention.
        c.context.store(true, Ordering::SeqCst);
        assert_eq!(c.values(), [0; 5]);
    }

    #[test]
    fn lost_context_after_config_and_live_allocation_drop_keep_all_storage_alive() {
        let (config, owner, source, domain, c) = inputs();
        c.lose_context.store(true, Ordering::SeqCst);
        assert!(matches!(
            unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) },
            Err(Error::Context(-77))
        ));
        assert_eq!(c.reads.load(Ordering::SeqCst), 16);
        assert_eq!(c.values(), [0; 5]);
        let (config, owner, source, domain, c) = inputs();
        let mut d = unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) }
            .unwrap();
        let state = d.bundle.as_ref().unwrap().state.raw();
        let (mut pa, mut allocation) = (0, core::ptr::null_mut());
        assert_eq!(
            unsafe { nv_alloc_pages(state, 1, 4096, 0, 0, 1, 0, -1, &mut pa, &mut allocation) },
            0
        );
        assert!(matches!(d.retire(), Err(Error::Services(_))));
        drop(d);
        assert_eq!(c.values(), [0; 5]);
        // This test-only retained token is the actual allocation produced above.
        // Its successful real free after Drop exercises still-live State/services,
        // source and domain, rather than merely observing leaked bookkeeping.
        assert_eq!(unsafe { nv_free_pages(state, 1, 0, 0, allocation) }, 0);
        assert_eq!(c.values(), [0; 5]);
    }
    #[test]
    fn actual_configured_geometry_refusal_precedes_allocation_and_binding() {
        let (config, owner, source, domain, c) = inputs();
        assert!(matches!(
            unsafe { PreparedDevice::prepare(config, owner, source, domain, 13, u64::MAX) },
            Err(Error::Services(_))
        ));
        assert_eq!(c.reads.load(Ordering::SeqCst), 0);
        assert_eq!(c.values(), [1, 1, 1, 1, 3]);
    }

    #[test]
    fn native_failure_and_provider_error_context_loss_retain_all_owned_inputs() {
        let (mut config, owner, source, domain, c) = inputs();
        config.words[0] ^= 1;
        c.lose_context.store(true, Ordering::SeqCst);
        assert!(matches!(
            unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) },
            Err(Error::Context(-77))
        ));
        assert_eq!(c.reads.load(Ordering::SeqCst), 16);
        assert_eq!(c.values(), [0; 5]);
        for failure in 1..=3 {
            let (config, owner, source, domain, c) = inputs();
            c.geometry_failure.store(failure, Ordering::SeqCst);
            BUDGET.with(|b| b.set(Some(2)));
            let result =
                unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) };
            BUDGET.with(|b| {
                assert_eq!(
                    b.get(),
                    Some(2),
                    "no metadata allocation after provider loss"
                );
                b.set(None);
            });
            if failure == 1 {
                assert!(matches!(result, Err(Error::Services(_))));
                assert_eq!(c.values(), [1, 1, 1, 1, 3]);
            } else {
                assert!(matches!(result, Err(Error::Context(-77))));
                assert_eq!(c.values(), [0; 5]);
            }
            assert_eq!(c.reads.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn metadata_context_loss_precedes_provider_allocation_and_config_access() {
        for loss in 1..=2 {
            let (config, owner, source, domain, c) = inputs();
            c.metadata_loss.store(loss, Ordering::SeqCst);
            BUDGET.with(|b| b.set(Some(2)));
            assert!(matches!(
                unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) },
                Err(Error::Context(-77))
            ));
            BUDGET.with(|b| {
                assert_eq!(b.get(), Some(2));
                b.set(None);
            });
            assert_eq!(c.geometry_calls.load(Ordering::SeqCst), 0);
            assert_eq!(c.reads.load(Ordering::SeqCst), 0);
            assert_eq!(c.values(), [0; 5]);
        }
    }

    #[test]
    fn every_config_read_loss_stops_before_the_next_actual_effect() {
        for word in 0..16 {
            for (mismatch, transient) in
                [(false, false), (true, false), (false, true), (true, true)]
            {
                let (mut config, owner, source, domain, c) = inputs();
                if mismatch {
                    config.words[0] ^= 1;
                }
                c.lose_context.store(true, Ordering::SeqCst);
                c.lose_at.store(word * 4, Ordering::SeqCst);
                c.recover_on_check.store(transient, Ordering::SeqCst);
                assert!(matches!(
                    unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) },
                    Err(Error::Context(-77))
                ));
                assert_eq!(c.reads.load(Ordering::SeqCst), word + 1);
                assert_eq!(c.values(), [0; 5]);
            }
        }
    }

    unsafe extern "C" {
        fn os_pci_read_dword(handle: *mut c_void, offset: u32, out: *mut u32) -> u32;
        fn os_pci_write_byte(handle: *mut c_void, offset: u32, value: u8) -> u32;
        fn os_pci_write_word(handle: *mut c_void, offset: u32, value: u16) -> u32;
        fn os_pci_write_dword(handle: *mut c_void, offset: u32, value: u32) -> u32;
    }
    // Test-only projection; the public PreparedDevice exposes no C pointer.
    fn handle(d: &mut PreparedDevice<Config>) -> *mut c_void {
        let this = unsafe { d.bundle.as_mut().unwrap().as_mut().get_unchecked_mut() };
        unsafe { Pin::new_unchecked((&mut *this.pci.get()).as_mut().unwrap()).as_raw() }
    }
    #[test]
    fn actual_pci_callback_failures_widths_and_latched_uncertainty() {
        let (config, owner, source, domain, c) = inputs();
        let mut d = unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) }
            .unwrap();
        // A context refusal before any effect can be retried in the valid context.
        c.context.store(false, Ordering::SeqCst);
        assert_eq!(d.retire(), Err(Error::Context(-77)));
        c.context.store(true, Ordering::SeqCst);
        d.retire().unwrap();
        assert_eq!(c.values(), [1, 1, 1, 1, 3]);
        for failure in 0..=2 {
            let (config, owner, source, domain, c) = inputs();
            let mut d =
                unsafe { PreparedDevice::prepare(config, owner, source, domain, 12, u64::MAX) }
                    .unwrap();
            let h = handle(&mut d);
            assert_eq!(unsafe { os_pci_write_byte(h, 0x40, 0xa5) }, 0);
            assert_eq!(
                (
                    c.write_width.load(Ordering::SeqCst),
                    c.write_value.load(Ordering::SeqCst)
                ),
                (1, 0xa5)
            );
            assert_eq!(unsafe { os_pci_write_word(h, 0x42, 0x8abc) }, 0);
            assert_eq!(
                (
                    c.write_width.load(Ordering::SeqCst),
                    c.write_value.load(Ordering::SeqCst)
                ),
                (2, 0x8abc)
            );
            assert_eq!(unsafe { os_pci_write_dword(h, 0x44, 0x81234567) }, 0);
            assert_eq!(
                (
                    c.write_width.load(Ordering::SeqCst),
                    c.write_value.load(Ordering::SeqCst)
                ),
                (4, 0x81234567)
            );
            if failure == 0 {
                d.retire().unwrap();
                assert_eq!(c.values(), [1, 1, 1, 1, 3]);
                continue;
            }
            if failure == 1 {
                c.context.store(false, Ordering::SeqCst);
            } else {
                c.write_loss.store(true, Ordering::SeqCst);
                c.recover_on_check.store(true, Ordering::SeqCst);
            }
            assert_ne!(unsafe { os_pci_write_dword(h, 0x48, 0xabcdef01) }, 0);
            let reads = c.reads.load(Ordering::SeqCst);
            let writes = c.writes.load(Ordering::SeqCst);
            assert_eq!(writes, if failure == 1 { 3 } else { 4 });
            c.context.store(true, Ordering::SeqCst);
            let mut out = 0x12345678;
            assert_ne!(unsafe { os_pci_read_dword(h, 0, &mut out) }, 0);
            assert_eq!(out, u32::MAX); // Original C shim's explicit failed-read output.
            assert_ne!(unsafe { os_pci_write_dword(h, 0x48, 0) }, 0);
            assert_eq!(c.reads.load(Ordering::SeqCst), reads);
            assert_eq!(c.writes.load(Ordering::SeqCst), writes);
            assert_eq!(d.retire(), Err(Error::Context(-77)));
            drop(d);
            assert_eq!(c.values(), [0; 5]);
        }
    }
}
