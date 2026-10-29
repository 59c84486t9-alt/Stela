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
/// The index is the PCI configuration BAR index, not the original RM role.
pub struct Aperture {
    pub index: u8,
    pub resource: Resource,
}
/// Original REGS/FB/IMEM roles. The C constructor checks their original order
/// against BAR encodings; a caller cannot relabel arbitrary resources.
pub struct Apertures {
    pub registers: Aperture,
    pub framebuffer: Aperture,
    pub instance: Option<Aperture>,
}
/// Same-PF power/reset/resource epoch. No implementation is supplied.
///
/// # Safety
/// This owns the immutable identity, exclusive D0/parent-bridge/reset/
/// removal epoch and Resources of the SAME function as the owned ConfigSpace.
/// Resources independently keep teardown-critical backing, including canonical
/// mapping quarantine. Their reported spans/kinds/roles are assigned BARs.
/// Exclude every other driver, firmware, DMA, IRQ, reset and configuration user.
/// `check_context` checks the allowed process/native CPU without device
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
            // Preserve the first callback-context failure. A later
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
    // width/range and accesses the ConfigSpace with that exact width.
    let config = unsafe { (&**this.config.get() as *const C).cast_mut().cast() };
    let mut result = 0;
    // SAFETY: `config` is this callback's live, exclusive target.
    let status = unsafe { super::read::<C>(config, offset, width, &mut result) };
    if this.callback_context().is_err() {
        return 0;
    }
    if status != 0 {
        // SAFETY: original C shim supplies a live aligned writable u32. Only a
        // checked successful access may publish its returned value.
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
    // write preserves width and performs no read/modify/write substitute.
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
/// Explicit retirement failure keeps the whole bundle. Drop uncertainty
/// keeps that SAME allocation and every owner indefinitely;
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
    /// Assemble native input ownership, without invoking RM.
    ///
    /// # Safety
    /// `owner`, owned `config`, source and attached `domain` describe the SAME
    /// PF/reset epoch. The domain/address_limit is its real isolated DMA
    /// policy, not identity DMA or a guessed GPU address width. Source
    /// geometry must already be installed before any RM callers. The heap and
    /// all owned dependencies remain valid through final retirement/quarantine.
    /// No caller keeps configuration/native aliases or may reenter this scope.
    /// Box/Arc inputs must own their dependencies; borrowed/non-static stand-ins
    /// cannot survive uncertainty and are excluded.
    pub unsafe fn prepare(
        config: Box<C>,
        owner: Box<dyn Owner>,
        source: Box<dyn PageSource>,
        domain: Arc<dyn DmaDomain>,
        page_shift: u8,
        address_limit: u64,
    ) -> Result<Self, Error> {
        if let Err(status) = owner.check_context() {
            // No allocation or final owner release is safe in an unchecked
            // context. These inputs are already wholly owned; keep all of
            // them without allocating a bundle or extending any borrow.
            core::mem::forget((config, owner, source, domain));
            return Err(Error::Context(status));
        }
        // Keep every dependency and prepared allocation outside this fallible
        // phase. A provider callback may refuse after context is lost; no `?`
        // inside the phase may then release the last owner.
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
            // before source, or BOTH are held on uncertain context. No
            // internal lifetime or source reference is exposed to a caller.
            let source_ref: &'static dyn PageSource =
                unsafe { &*(&*source as *const dyn PageSource) };
            // SAFETY: caller supplies the requester/domain/cache contract.
            // Keep the original Arc until context is checked on either result;
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
            // keeps this reserved State with all dependency owners.
            owner.check_context().map_err(Error::Context)?;
            #[cfg(test)]
            tests::reserve()?;
            let storage =
                UniqueArc::<Bundle<C>>::try_new_uninit().map_err(|_| Error::OutOfMemory)?;
            Ok((identity, bars, count, storage))
        })();
        if let Err(status) = owner.check_context() {
            // Covers success AND error of every callback/reservation above,
            // including source geometry refusal. Keep all exact ownership;
            // no final Arc release, metadata free or allocation is attempted.
            core::mem::forget((
                config, owner, source, domain, apertures, services, state, prepared,
            ));
            return Err(Error::Context(status));
        }
        let (identity, bars, count, mut storage) = prepared?;
        // The service owns another Arc, and the context remains valid.
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
        // escapes. Per-access callbacks check context and keep the
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
        // SAFETY: original C state, pinned handle and bounded disjoint
        // CPU inputs. This reads configuration only; error publishes no state.
        let status = unsafe {
            stela_nvidia_prepare_device(this.state.raw(), handle, &id, bars.as_ptr(), count as u32)
        };
        if let Err(status) = this.callback_context() {
            // Configuration callbacks cannot grant a different CPU/context.
            // Keep the same complete reserved bundle if validation is lost.
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
        // the existing services' live counters govern final release.
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
            // Keep wholly OWNED state/handles/source/config/resources/
            // reset owner, using existing allocation ownership. No borrow is
            // extended and no quarantine registry or late allocation is added.
            if let Some(bundle) = self.bundle.take() {
                core::mem::forget(bundle);
            }
        }
    }
}
#[cfg(test)]
mod tests;
