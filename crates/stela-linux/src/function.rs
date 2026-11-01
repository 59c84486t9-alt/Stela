//! A physical PCI function presented to Linux, which then binds any driver
//! matching it (`compat/linux/kernel/pci_host.c`). Configuration space and DMA
//! stay Stela's: the function's owner placed it, and Linux reaches both through
//! the table here. Domain errors retain real allocation pins and stop at the
//! terminal Linux boundary before callers can reuse DMA-visible memory.
use super::catalogue::{self, Authority, PciAuthority};
use super::owner::Errno;
use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec::Vec};
use core::{
    ffi::{c_char, c_int, c_uint, c_void},
    marker::PhantomData,
    mem::ManuallyDrop,
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering},
};
use stela_driver_base::bus::{
    dma::{
        mapping::{Direction, DmaDomain, DmaError, DomainMapping, QuarantineStatus},
        memory::CacheAttribute,
        pages::DmaPages,
    },
    pci::ConfigSpace,
};

/// PCI base address registers.
const BARS: usize = 6;
/// Linux's `DMA_MAPPING_ERROR`.
const MAPPING_ERROR: u64 = u64::MAX;
const PAGE_SHIFT: u8 = 12;
const PAGE_BYTES: u64 = 1 << PAGE_SHIFT;

const PCIBIOS_BAD_REGISTER_NUMBER: c_int = 0x87;

static QUARANTINED_MAPPINGS: AtomicU64 = AtomicU64::new(0);
static QUARANTINED_BYTES: AtomicU64 = AtomicU64::new(0);

/// Linux DMA leases kept without acknowledged domain removal. These counters
/// are cumulative; no reset or reclamation is inferred from quarantine.
pub fn dma_quarantine_status() -> QuarantineStatus {
    QuarantineStatus {
        mappings: QUARANTINED_MAPPINGS.load(Ordering::Relaxed),
        bytes: QUARANTINED_BYTES.load(Ordering::Relaxed),
    }
}

fn count_quarantine(mappings: u64, bytes: u64) {
    let _ = QUARANTINED_MAPPINGS.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(mappings))
    });
    let _ = QUARANTINED_BYTES.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(bytes))
    });
}

fn quarantine<T>(resources: T, mappings: u64, bytes: u64) {
    count_quarantine(mappings, bytes);
    core::mem::forget(resources);
}

/// The function's owner.
pub trait Host {
    type Config: ConfigSpace;
    fn config(&mut self) -> &mut Self::Config;
    /// Move the function's interrupt from its line to a message.
    fn enable_msi(&mut self) -> Result<(), Errno>;
    fn disable_msi(&mut self);
}

/// A memory BAR where its owner placed it. `flags` holds Linux's `IORESOURCE_*`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Region {
    pub start: u64,
    pub size: u64,
    pub flags: u64,
}

/// Where a function sits.
#[derive(Clone, Copy, Default)]
pub struct Placement {
    pub bus: u8,
    pub devfn: u8,
    pub irq: u32,
    /// The highest bus address `domain` hands out.
    pub dma_limit: u64,
    pub regions: [Region; BARS],
}

/// A function's MSI capability (PCI Local Bus 3.0 6.8.1), one message at most.
#[derive(Clone, Copy)]
pub struct Msi {
    capability: u16,
}

impl Msi {
    const CONTROL: u16 = 2;
    const ADDRESS: u16 = 4;
    const ENABLE: u16 = 1;
    const MULTIPLE: u16 = 7 << 4;
    const WIDE: u16 = 1 << 7;

    /// The capability at `capability`.
    pub const fn at(capability: u16) -> Self {
        Self { capability }
    }

    /// Read this capability's control word through its configuration owner.
    pub fn control<C: ConfigSpace>(self, config: &C) -> u16 {
        config.read16(self.capability + Self::CONTROL)
    }

    /// Stop the function sending it.
    pub fn disable<C: ConfigSpace>(self, config: &mut C) {
        let control = self.control(config) & !Self::ENABLE;
        config.write16(self.capability + Self::CONTROL, control);
    }

    /// Set the one message, disabled.
    pub fn program<C: ConfigSpace>(self, config: &mut C, address: u64, data: u16) {
        self.disable(config);
        let wide = self.control(config) & Self::WIDE != 0;
        let at = self.capability + Self::ADDRESS;
        config.write32(at, address as u32);
        if wide {
            config.write32(at + 4, (address >> 32) as u32);
        }
        config.write16(at + if wide { 8 } else { 4 }, data);
    }

    /// Let the function send it.
    pub fn enable<C: ConfigSpace>(self, config: &mut C) {
        let control = self.control(config) & !Self::MULTIPLE | Self::ENABLE;
        config.write16(self.capability + Self::CONTROL, control);
    }
}

/// `struct stela_linux_pci_function`.
#[repr(C)]
struct RawFunction {
    context: *mut c_void,
    read_config: unsafe extern "C" fn(*mut c_void, c_int, c_int, *mut u32) -> c_int,
    write_config: unsafe extern "C" fn(*mut c_void, c_int, c_int, u32) -> c_int,
    dma_map: unsafe extern "C" fn(*mut c_void, u64, usize, c_uint) -> u64,
    dma_unmap: unsafe extern "C" fn(*mut c_void, u64, usize, c_uint),
    enable_msi: unsafe extern "C" fn(*mut c_void) -> c_int,
    disable_msi: unsafe extern "C" fn(*mut c_void),
    dma_limit: u64,
    bus: c_uint,
    devfn: c_uint,
    irq: c_uint,
    regions: [Region; BARS],
    release_context: Option<unsafe extern "C" fn(*mut c_void)>,
    enroll: Option<unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int>,
}

const _: () = assert!(size_of::<RawFunction>() == 240);
const _: () = assert!(core::mem::offset_of!(RawFunction, enroll) == 232);
const _: () = assert!(core::mem::offset_of!(RawFunction, release_context) == 224);

unsafe extern "C" {
    fn stela_linux_pci_attach(function: *const RawFunction, error: *mut c_int) -> *mut c_void;
    fn stela_linux_owner() -> *const super::owner::RawOwner;
    fn stela_linux_pci_bound(device: *const c_void) -> bool;
    fn stela_linux_pci_remove_device(device: *mut c_void);
    fn stela_linux_pci_quarantined_functions() -> u64;
    fn stela_linux_fatal(message: *const c_char) -> !;
    fn stela_linux_page_dma_pin(physical: u64) -> *mut c_void;
    fn stela_linux_page_dma_unpin(pin: *mut c_void);
}

/// Functions whose final device reference ended outside their original
/// quiescent owner. Their C storage, host and DMA roots remain quarantined.
pub fn quarantined_functions() -> u64 {
    // SAFETY: this diagnostic only atomically reads a monotonic C counter.
    unsafe { stela_linux_pci_quarantined_functions() }
}

/// A reference to the Linux catalog's original provider allocation. This
/// retains the entire allocation even if Linux frees a noncompound tail.
struct PagePin(NonNull<c_void>);

impl Drop for PagePin {
    fn drop(&mut self) {
        // SAFETY: pins are released only inside an entered, serialized Linux
        // mapping callback, before map exposure or after successful unmap.
        unsafe { stela_linux_page_dma_unpin(self.0.as_ptr()) };
    }
}

struct Mapping {
    token: DomainMapping,
    _pins: Vec<PagePin>,
}

/// A mapping of pinned Linux allocations, by the address Linux was given.
/// Passthrough domains give one physical range the same address every time, so
/// each address keeps a stack of the mappings at it.
struct Mappings {
    domain: Arc<dyn DmaDomain>,
    limit: u64,
    live: BTreeMap<u64, Vec<Mapping>>,
}

impl Mappings {
    fn pin(physical: u64, size: usize) -> Option<(u64, DmaPages, Vec<PagePin>)> {
        let offset = physical % PAGE_BYTES;
        let end = physical.checked_add(u64::try_from(size).ok()?.max(1))?;
        let physical: Vec<_> = (physical - offset..end)
            .step_by(PAGE_BYTES as usize)
            .collect();
        let mut pins = Vec::new();
        pins.try_reserve_exact(physical.len()).ok()?;
        for &page in &physical {
            // SAFETY: map is called in the serialized entered Linux owner.
            // C checks live PFN ownership and retains its provider allocation.
            pins.push(PagePin(NonNull::new(unsafe {
                stela_linux_page_dma_pin(page)
            })?));
        }
        // SAFETY: every physical page's original allocation is retained by
        // pins until successful unmap, or permanently on uncertain teardown.
        let pages =
            unsafe { DmaPages::from_physical(physical, PAGE_SHIFT, CacheAttribute::WriteBack) }
                .ok()?;
        Some((offset, pages, pins))
    }

    fn map(
        &mut self,
        physical: u64,
        size: usize,
        direction: Direction,
    ) -> Result<Option<u64>, DmaError> {
        let Some((offset, pages, pins)) = Self::pin(physical, size) else {
            return Ok(None);
        };
        // SAFETY: the real allocation pins and domain survive every uncertain
        // failure; Linux's DMA API quiesces the device before explicit unmap.
        let mapping = match unsafe {
            self.domain
                .map(&pages, direction, self.limit.min(MAPPING_ERROR - 1))
        } {
            Ok(mapping) => mapping,
            Err(error) => {
                // DmaError does not distinguish clean refusal from failed
                // invalidation. Keep the real pins and domain in either case.
                quarantine((pins, self.domain.clone()), 1, pages.bytes() as u64);
                return Err(error);
            }
        };
        let address = mapping.address + offset;
        self.live.entry(address).or_default().push(Mapping {
            token: mapping,
            _pins: pins,
        });
        Ok(Some(address))
    }

    fn unmap(&mut self, address: u64) -> Result<(), DmaError> {
        let Some(stack) = self.live.get_mut(&address) else {
            return Ok(());
        };
        let Some(mapping) = stack.last() else {
            return Ok(());
        };
        // SAFETY: Linux's DMA API unmaps only once the device is done.
        // An error leaves the token and provider pins intact.
        unsafe { self.domain.unmap(mapping.token) }?;
        stack.pop();
        if stack.is_empty() {
            self.live.remove(&address);
        }
        Ok(())
    }
}

impl Drop for Mappings {
    fn drop(&mut self) {
        if !self.live.is_empty() {
            // Driver removal is not proof that every domain invalidation
            // succeeded. Preserve active mappings, original provider pins and
            // domain roots; catalog retirement stays busy for these leases.
            let (count, bytes) =
                self.live
                    .values()
                    .flatten()
                    .fold((0u64, 0u64), |totals, mapping| {
                        (
                            totals.0.saturating_add(1),
                            totals.1.saturating_add(mapping.token.bytes as u64),
                        )
                    });
            quarantine(
                (core::mem::take(&mut self.live), self.domain.clone()),
                count,
                bytes,
            );
        }
    }
}

fn direction(linux: c_uint) -> Direction {
    match linux {
        1 => Direction::ToDevice,
        2 => Direction::FromDevice,
        _ => Direction::Bidirectional,
    }
}

struct State<H> {
    host: H,
    mappings: Mappings,
    enrollment: Option<Box<Authority>>,
}

unsafe extern "C" fn release_context<H>(context: *mut c_void) {
    // SAFETY: successful attach transferred this unique Box to C. The final
    // C device release invokes it once, only in the original quiescent owner;
    // no device reference can issue another callback after final release.
    drop(unsafe { Box::from_raw(context.cast::<State<H>>()) });
}

/// # Safety
/// `context` is the state of an [`Attached`] Linux still holds, and Linux, which
/// runs in one context at a time, is in no other callback of it.
unsafe fn state<'a, H>(context: *mut c_void) -> &'a mut State<H> {
    // SAFETY: the caller's contract.
    unsafe { &mut *context.cast() }
}

unsafe extern "C" fn read_config<H: Host>(
    context: *mut c_void,
    offset: c_int,
    size: c_int,
    value: *mut u32,
) -> c_int {
    // SAFETY: the table's context.
    let config = unsafe { state::<H>(context) }.host.config();
    let offset = offset as u16;
    let read = match size {
        1 => u32::from(config.read8(offset)),
        2 => u32::from(config.read16(offset)),
        4 => config.read32(offset),
        _ => return PCIBIOS_BAD_REGISTER_NUMBER,
    };
    // SAFETY: Linux gives a writable result.
    unsafe { *value = read };
    0
}

unsafe extern "C" fn write_config<H: Host>(
    context: *mut c_void,
    offset: c_int,
    size: c_int,
    value: u32,
) -> c_int {
    // SAFETY: the table's context.
    let config = unsafe { state::<H>(context) }.host.config();
    let offset = offset as u16;
    match size {
        1 => config.write8(offset, value as u8),
        2 => config.write16(offset, value as u16),
        4 => config.write32(offset, value),
        _ => return PCIBIOS_BAD_REGISTER_NUMBER,
    }
    0
}

unsafe extern "C" fn dma_map<H: Host>(
    context: *mut c_void,
    physical: u64,
    size: usize,
    linux: c_uint,
) -> u64 {
    // SAFETY: the table's context.
    let state = unsafe { state::<H>(context) };
    match state.mappings.map(physical, size, direction(linux)) {
        Ok(address) => address.unwrap_or(MAPPING_ERROR),
        // The DMA API permits its caller to reuse suballocations immediately
        // after refusal. Allocation pins alone cannot stop slab-slot reuse.
        // DmaError does not certify that a refusal left no translation.
        // SAFETY: the callback is inside its entered Linux owner.
        Err(_) => unsafe {
            stela_linux_fatal(c"DMA map failed without proven retirement".as_ptr())
        },
    }
}

unsafe extern "C" fn dma_unmap<H: Host>(context: *mut c_void, address: u64, _: usize, _: c_uint) {
    // SAFETY: the table's context.
    let state = unsafe { state::<H>(context) };
    if state.mappings.unmap(address).is_err() {
        let bytes = state.mappings.live[&address].last().unwrap().token.bytes;
        count_quarantine(1, bytes as u64);
        // The void DMA API cannot report incomplete invalidation. Stop before
        // the C caller can free/reuse even a suballocation of retained pages.
        // SAFETY: the callback is inside its entered Linux owner.
        unsafe { stela_linux_fatal(c"DMA unmap failed without proven retirement".as_ptr()) };
    }
}

unsafe extern "C" fn enable_msi<H: Host>(context: *mut c_void) -> c_int {
    // SAFETY: the table's context.
    let result = unsafe { state::<H>(context) }.host.enable_msi();
    result.err().unwrap_or(0)
}

unsafe extern "C" fn disable_msi<H: Host>(context: *mut c_void) {
    // SAFETY: the table's context.
    unsafe { state::<H>(context) }.host.disable_msi();
}

unsafe extern "C" fn enroll<H>(context: *mut c_void, device: *mut c_void) -> c_int {
    // SAFETY: the attach call retains this State; take ends the mutable borrow
    // before the generic catalogue can allocate or release any foreign object.
    let authority = unsafe { state::<H>(context) }.enrollment.take();
    let Some(authority) = authority else {
        return -22;
    };
    // SAFETY: C initialized this exact device before the first probe; this
    // canonical process owner still holds the original registration reference.
    match unsafe { catalogue::bind(device, authority) } {
        Ok(()) => 0,
        Err((authority, error)) => {
            // SAFETY: refusal took no state or authority; no callback overlaps this short restore.
            unsafe { state::<H>(context) }.enrollment = Some(authority);
            match error {
                catalogue::Error::Native(error) => error,
                _ => -22,
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttachError {
    Catalogue(catalogue::Error),
    Native(Errno),
}
static RETAINED_PRESENTATIONS: AtomicU64 = AtomicU64::new(0);
/// Refused presentation graphs abandoned without native retirement proof.
/// Observation only: this does not certify reclamation or native progress.
pub fn retained_presentations() -> u64 {
    RETAINED_PRESENTATIONS.load(Ordering::Relaxed)
}
struct Retained<T> {
    _value: ManuallyDrop<T>,
}
impl<T> Retained<T> {
    fn new(value: T) -> Self {
        Self {
            _value: ManuallyDrop::new(value),
        }
    }
}
impl<T> Drop for Retained<T> {
    fn drop(&mut self) {
        // Presentation refusal is not proof that a caller's native host was
        // unexposed. Keep the actual allocation and all source/domain roots.
        let _ = RETAINED_PRESENTATIONS.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            Some(value.saturating_add(1))
        });
    }
}
/// The actual host/domain/authority remain retained on a refused presentation.
/// Drop keeps that graph: no H destructor or native retirement is inferred.
#[must_use = "presentation refusal retains actual native roots; inspect error and retained state"]
pub struct Rejected<H> {
    pub error: AttachError,
    _held: Retained<Box<Held<H>>>,
}
enum Held<H> {
    Before {
        _host: H,
        _authority: Box<PciAuthority>,
    },
    Native {
        _state: Box<State<H>>,
    },
}

/// A function Linux can see. Drop unregisters it in the owner it was attached
/// in. Other C device references retain the host and DMA roots until the final
/// quiescent put in that owner; other final puts quarantine those resources.
pub struct Attached<H> {
    device: NonNull<c_void>,
    _host: PhantomData<H>,
}

impl<H: Host> Attached<H> {
    /// # Safety
    /// In an entered Linux owner, on a Linux task, as a driver may bind here.
    /// That owner and its platform services outlive all escaped device
    /// references, including any quarantined final release. Refusal returns an
    /// errno while retaining the host graph; it proves no native retirement.
    pub unsafe fn new(
        host: H,
        domain: Arc<dyn DmaDomain>,
        placement: Placement,
    ) -> Result<Self, Errno>
    where
        H: 'static,
    {
        // SAFETY: unchanged legacy presentation contract; no canonical
        // catalogue authority is inferred for this pre-migration path.
        unsafe { Self::attach(host, domain, placement, None) }.map_err(|failure| {
            match failure.error {
                AttachError::Native(error) => error,
                _ => -22,
            }
        })
    }

    /// Enroll exact original native source metadata before synchronous probe.
    ///
    /// # Safety
    /// H accesses the exact original OwnedConfig allocation/epoch validated
    /// when authority was made; its actual native grants stay kept. Its exact
    /// manifest target/catalogue were qualified for that same observed native
    /// function/board/source epoch by PciAuthority::new, never guessed labels.
    /// On this canonical owner's checked Linux task. No borrowed config/entered permit
    /// is retained in the authority or held across probe/callback/sleep.
    pub unsafe fn new_catalogued<P: super::owner::Platform, const N: usize>(
        kernel: &super::kernel::KernelOwner<P, N>,
        host: H,
        placement: Placement,
        authority: PciAuthority,
    ) -> Result<Self, Rejected<H>>
    where
        H: 'static,
    {
        // SAFETY: caller is entered; this checks the same actual canonical owner.
        if unsafe { stela_linux_owner() } != kernel.raw() {
            return Err(Rejected {
                error: AttachError::Native(-1),
                _held: Retained::new(Box::new(Held::Before {
                    _host: host,
                    _authority: Box::new(authority),
                })),
            });
        }
        let domain = match authority.domain() {
            Ok(domain) => domain,
            Err(error) => {
                return Err(Rejected {
                    error: AttachError::Catalogue(error),
                    _held: Retained::new(Box::new(Held::Before {
                        _host: host,
                        _authority: Box::new(authority),
                    })),
                });
            }
        };
        // SAFETY: caller's exact native source and canonical task proof.
        unsafe {
            Self::attach(
                host,
                domain,
                placement,
                Some(Box::new(Authority::Pci(authority))),
            )
        }
    }

    unsafe fn attach(
        host: H,
        domain: Arc<dyn DmaDomain>,
        placement: Placement,
        enrollment: Option<Box<Authority>>,
    ) -> Result<Self, Rejected<H>>
    where
        H: 'static,
    {
        let catalogued = enrollment.is_some();
        let state = Box::into_raw(Box::new(State {
            host,
            mappings: Mappings {
                domain,
                limit: placement.dma_limit,
                live: BTreeMap::new(),
            },
            enrollment,
        }));
        let raw = RawFunction {
            context: state.cast(),
            read_config: read_config::<H>,
            write_config: write_config::<H>,
            dma_map: dma_map::<H>,
            dma_unmap: dma_unmap::<H>,
            enable_msi: enable_msi::<H>,
            disable_msi: disable_msi::<H>,
            dma_limit: placement.dma_limit,
            bus: placement.bus.into(),
            devfn: placement.devfn.into(),
            irq: placement.irq,
            regions: placement.regions,
            release_context: Some(release_context::<H>),
            enroll: catalogued.then_some(enroll::<H>),
        };
        let mut error = 0;
        // SAFETY: caller's attach contract; C copies the table and returns a
        // reference only after enrollment/publication. Refusal retains State.
        match NonNull::new(unsafe { stela_linux_pci_attach(&raw, &raw mut error) }) {
            Some(device) => Ok(Self {
                device,
                _host: PhantomData,
            }),
            None => {
                // SAFETY: C refused before publication/probe and explicitly left
                // context ownership with this caller. Any enrolled record was
                // retired by its real device put before returning NULL.
                let state = unsafe { Box::from_raw(state) };
                Err(Rejected {
                    error: AttachError::Native(error),
                    _held: Retained::new(Box::new(Held::Native { _state: state })),
                })
            }
        }
    }

    /// The `struct pci_dev`, for code that names it.
    pub fn device(&self) -> *mut c_void {
        self.device.as_ptr()
    }

    /// Whether a driver took the function.
    ///
    /// # Safety
    /// In an entered Linux owner.
    pub unsafe fn bound(&self) -> bool {
        // SAFETY: the caller's contract, over this function's live device.
        unsafe { stela_linux_pci_bound(self.device.as_ptr()) }
    }
}

impl<H> Drop for Attached<H> {
    fn drop(&mut self) {
        // SAFETY: the type's contract; removal unbinds the driver and drops
        // registration. C's final device release owns State destruction, so
        // outstanding device references retain their callback context.
        unsafe { stela_linux_pci_remove_device(self.device.as_ptr()) };
    }
}

#[cfg(test)]
mod tests;
