//! Native owned BAR0/device-facts/root-GT probe; not firmware or job readiness.
use crate::bus::mmio::owned::{
    Authority, CacheAttribute, Error as MappingError, Mapping, MappingView, Protection, Resource,
    ResourceKind,
};
use alloc::{alloc::alloc_zeroed, alloc::dealloc, boxed::Box};
use core::{alloc::Layout, ffi::c_void, marker::PhantomData, ptr::NonNull};
use triomphe::UniqueArc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciIdentity {
    pub vendor: u16,
    pub device: u16,
    pub class: u32,
    pub revision: u8,
    pub virtual_function: bool,
    pub bar0_start: u64,
    pub bar0_bytes: u64,
}

/// Exclusive native PCI/power/bridge/reset epoch, supplied by the real mount.
/// No implementation or fallback is supplied by this GPU module.
///
/// # Safety
/// Identity/resource metadata is immutable and describes the SAME PCI
/// function and exclusive reservation. The ResourceBacking must itself pin all
/// teardown-critical root/reset/power state: canonical failed-map quarantine
/// can keep it independently of this wrapper. This owner keeps D0/bridge power,
/// excludes removal/relocation/other resets, every other driver/firmware access and all
/// IRQ/submission/DMA/CT users throughout this probe. GuC-only reset is an
/// explicit permitted operation within this exclusive epoch; it never
/// substitutes for draining an active driver or excluding other resets. These
/// prerequisites are not inferred from cleared software flags. `prepare` performs
/// required original device-WA and PCODE/lmem readiness, not a success flag in their place.
/// Ordered naturally-aligned MMIO32 operations must use the provided canonical
/// CPU pointer, honor original read-flush WA and posting/ordering semantics,
/// never conflate it with a physical/guest address and never fail/unwind.
/// The clock is checked monotonic nonnegative nanoseconds and remains below
/// i64::MAX throughout every admitted deadline and sleep/overshoot. GuC
/// MMIO needs up to two seconds per wait and keeps the owner throughout
/// repeated retries; this contract alone does not admit running firmware or its
/// requests. Delay honors atomic/sleepable context. All calls
/// and final Drop occur on the allowed native CPU/process context; no callback
/// may reenter, activate guest services, or manufacture power/IRQ/coherence.
/// `finish` drains probe accesses/posted writes and prevents new accesses
/// but keeps ownership kept until the canonical mapping retires. Error
/// leaves the owner/reservations intact for retry/quarantine. Partial drain
/// effects on error are allowed; finish retries must safely complete that drain.
/// Once retirement begins no other device operations resume. `fatal` fail-stops.
pub unsafe trait ProbeOwner {
    /// Check CPU/process/kept epoch without accessing BAR mappings. This
    /// also runs during an uncertain-unmap retry when BAR access is forbidden.
    fn check_context(&self) -> Result<(), i32>;
    fn identity(&self) -> PciIdentity;
    fn bar0(&self) -> Resource;
    /// Same-function canonical configuration space, kept in this
    /// exclusive power/reset epoch. Unsupported capability is an explicit Err.
    fn config_space(&self) -> Result<&dyn crate::bus::pci::ConfigSpace, i32>;
    /// # Safety
    /// Live canonical UC GSM pointer, naturally aligned/bounded to eight bytes.
    /// Perform one ordered 64-bit MMIO read with the original readq
    /// semantics. No paired-32 fallback, guest access, unwind or invented value.
    /// Err means the width/capability is unavailable before any read; actual
    /// unexpected device-access faults obey the owner's fail-stop contract.
    unsafe fn read64(&self, pointer: NonNull<u64>) -> Result<u64, i32>;
    /// Borrow the same UC register mapping for original
    /// PCODE/lmem/WA preparation. Any kept view must be released by finish.
    fn prepare(
        &self,
        registers: &MappingView,
        platform: u32,
        revision: u32,
        discrete: bool,
    ) -> Result<(), i32>;
    /// # Safety
    /// Pointer is a live canonical UC, aligned, bounded device register.
    unsafe fn read32(&self, pointer: NonNull<u32>) -> u32;
    /// # Safety
    /// Same kept mapping and exclusive ordered-access contract as read32.
    unsafe fn write32(&self, pointer: NonNull<u32>, value: u32);
    fn now_ns(&self) -> i64;
    fn delay_us(&self, minimum: u32, maximum: u32, atomic: bool);
    fn report(&self, domains: u32, wake: bool, status: i32, value: u32);
    fn finish(&self) -> Result<(), i32>;
    fn fatal(&self) -> !;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Mapping(MappingError),
    InvalidOwner,
    OutOfMemory,
    InvalidLayout,
    Native(i32),
    Closing,
    Awake,
}
impl From<MappingError> for Error {
    fn from(value: MappingError) -> Self {
        Self::Mapping(value)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct Facts {
    pub platform: u32,
    pub subplatform: u32,
    pub graphics_verx100: u32,
    pub media_verx100: u32,
    pub graphics_revision: u32,
    pub media_revision: u32,
    pub pci_revision: u32,
    pub tile_count: u32,
    pub dma_bits: u32,
    pub va_bits: u32,
    pub max_gt_per_tile: u32,
    pub discrete: u32,
    pub force_probe_required: u32,
    pub gt_control: u32,
    pub gt_ack: u32,
    pub initialized: u32,
    pub awake: u32,
    pub has_llc: u32,
    pub gt_type: u32,
}

const _: () = assert!(core::mem::size_of::<Facts>() == 76);
const _: () = assert!(core::mem::offset_of!(Facts, has_llc) == 68);
const _: () = assert!(core::mem::offset_of!(Facts, gt_type) == 72);
#[repr(C)]
struct Io {
    check_context: extern "C" fn(*mut c_void) -> i32,
    prepare: extern "C" fn(*mut c_void, u32, u32, bool) -> i32,
    read32: extern "C" fn(*mut c_void, u32) -> u32,
    write32: extern "C" fn(*mut c_void, u32, u32),
    now_ns: extern "C" fn(*mut c_void) -> i64,
    delay_us: extern "C" fn(*mut c_void, u32, u32, bool),
    invariant: extern "C" fn(*mut c_void, bool),
    report: extern "C" fn(*mut c_void, u32, bool, i32, u32),
}
unsafe extern "C" {
    fn stela_intel_activation_guc_reset(
        state: *mut c_void,
        result: &mut super::guc_reset::NativeResult,
    ) -> i32;
    fn stela_intel_activation_pat(state: *mut c_void, result: &mut super::pat::NativeResult)
    -> i32;
    fn stela_intel_activation_wopcm(
        state: *mut c_void,
        bytes: *const u8,
        size: usize,
        output: &mut super::wopcm::NativeResult,
    ) -> i32;
    fn stela_intel_activation_size() -> usize;
    fn stela_intel_activation_alignment() -> usize;
    fn stela_intel_activation_match(
        vendor: u32,
        device: u32,
        class: u32,
        vf: bool,
        force_probe: bool,
    ) -> i32;
    fn stela_intel_activation_init(
        storage: *mut c_void,
        bytes: usize,
        io: &Io,
        context: *mut c_void,
        vendor: u32,
        device: u32,
        class: u32,
        revision: u32,
        bar_bytes: u64,
        vf: bool,
        force_probe: bool,
    ) -> i32;
    fn stela_intel_activation_facts(storage: *const c_void, facts: &mut Facts) -> i32;
    fn stela_intel_activation_wake(storage: *mut c_void) -> i32;
    fn stela_intel_activation_sleep(storage: *mut c_void) -> i32;
}

struct State {
    pointer: NonNull<u8>,
    layout: Layout,
}
impl State {
    fn new() -> Result<Self, Error> {
        // SAFETY: scalar layout queries have no context or device effects.
        let layout = Layout::from_size_align(unsafe { stela_intel_activation_size() }, unsafe {
            stela_intel_activation_alignment()
        })
        .map_err(|_| Error::InvalidLayout)?;
        if layout.size() == 0 {
            return Err(Error::InvalidLayout);
        }
        // SAFETY: nonzero validated layout; standard allocator, no GPU allocator.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(Error::OutOfMemory)?;
        Ok(Self { pointer, layout })
    }
    fn pointer(&self) -> *mut c_void {
        self.pointer.as_ptr().cast()
    }
}
impl Drop for State {
    fn drop(&mut self) {
        // SAFETY: no C calls remain; original standard allocation/layout.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

struct Context {
    owner: Box<dyn ProbeOwner>,
    view: Option<MappingView>,
}
impl Context {
    fn pointer(&self, offset: u32) -> NonNull<u32> {
        let pointer = self
            .view
            .as_ref()
            .and_then(|v| v.address(offset as usize, 4).ok());
        match pointer {
            Some(p) if (p.as_ptr() as usize).is_multiple_of(4) => p.cast(),
            _ => self.owner.fatal(),
        }
    }
}
fn context<'a>(pointer: *mut c_void) -> &'a Context {
    // SAFETY: private IO table is reachable only with its pinned unique context.
    unsafe { &*pointer.cast::<Context>() }
}
extern "C" fn prepare(p: *mut c_void, platform: u32, revision: u32, discrete: bool) -> i32 {
    let c = context(p);
    let view = c.view.as_ref().unwrap_or_else(|| c.owner.fatal());
    c.owner
        .prepare(view, platform, revision, discrete)
        .err()
        .map_or(0, |e| if e < 0 { e } else { -22 })
}
extern "C" fn check_context(p: *mut c_void) -> i32 {
    context(p)
        .owner
        .check_context()
        .err()
        .map_or(0, |e| if e < 0 { e } else { -22 })
}
extern "C" fn read32(p: *mut c_void, offset: u32) -> u32 {
    let c = context(p);
    // SAFETY: bounded canonical view, owner, exclusive probe.
    unsafe { c.owner.read32(c.pointer(offset)) }
}
extern "C" fn write32(p: *mut c_void, offset: u32, value: u32) {
    let c = context(p);
    // SAFETY: same ownership/order proof as read32, original access width32.
    unsafe { c.owner.write32(c.pointer(offset), value) };
}
extern "C" fn now_ns(p: *mut c_void) -> i64 {
    context(p).owner.now_ns()
}
extern "C" fn delay_us(p: *mut c_void, min: u32, max: u32, atomic: bool) {
    context(p).owner.delay_us(min, max, atomic);
}
extern "C" fn invariant(p: *mut c_void, valid: bool) {
    if !valid {
        context(p).owner.fatal();
    }
}
extern "C" fn report(p: *mut c_void, domains: u32, wake: bool, status: i32, value: u32) {
    context(p).owner.report(domains, wake, status, value);
}
static IO: Io = Io {
    check_context,
    prepare,
    read32,
    write32,
    now_ns,
    delay_us,
    invariant,
    report,
};

struct Bundle {
    state: State,
    context: UniqueArc<Context>,
    mapping: Mapping,
}
impl Bundle {
    fn quarantine(self) {
        let Self {
            state,
            context,
            mapping,
        } = self;
        // Canonical Drop records/keeps the mapping quarantine. Independently
        // keep callback storage and the real power/reset owner as well.
        drop(mapping);
        core::mem::forget(context);
        core::mem::forget(state);
    }
}
/// No Send/Sync: one real CPU-affine exclusive probe, no firmware/IRQ/users.
/// Drop quarantines rather than inventing successful sleep/drain/unmap.
pub struct Device {
    bundle: Option<Bundle>,
    closing: bool,
    drained: bool,
    poisoned: bool,
    awake: bool,
    _affinity: PhantomData<*mut ()>,
}
impl Device {
    pub fn open(
        authority: &Authority,
        owner: Box<dyn ProbeOwner>,
        force_probe: bool,
    ) -> Result<Self, Error> {
        let pci = owner.identity();
        owner.check_context().map_err(Error::Native)?;
        // SAFETY: pure source-table policy; no mapping/owner/device effects.
        let matched = unsafe {
            stela_intel_activation_match(
                u32::from(pci.vendor),
                u32::from(pci.device),
                pci.class,
                pci.virtual_function,
                force_probe,
            )
        };
        if matched != 0 {
            return Err(Error::Native(matched));
        }
        let resource = owner.bar0();
        if resource.kind() != ResourceKind::Registers
            || resource.physical_span().start() != pci.bar0_start
            || resource.physical_span().bytes() != pci.bar0_bytes
            || pci.class > 0xffffff
            || pci.bar0_bytes < 16 * 1024 * 1024
        {
            return Err(Error::InvalidOwner);
        }
        // Reserve only the register extent. GSM at BAR+8MiB has a
        // separate same-resource grant/lease; mapping the entire BAR here would
        // overlap it under the canonical mapping permission.
        let bytes = 4 * 1024 * 1024;
        let state = State::new()?;
        // Reserve the maintained alloc-only owner before any mapping effect.
        // Failure drops both the already reserved State and the original owner.
        let mut context_storage =
            UniqueArc::<Context>::try_new_uninit().map_err(|_| Error::OutOfMemory)?;
        let context_address =
            context_storage.write(Context { owner, view: None }) as *mut Context as usize;
        // SAFETY: write initialized the complete Context exactly once. The
        // UniqueArc conversion keeps its allocation and stable C address.
        let mut context = unsafe { UniqueArc::assume_init(context_storage) };
        debug_assert_eq!(context_address, &*context as *const Context as usize);
        let mapping = match authority.map(
            resource,
            0,
            bytes,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        ) {
            Ok(mapping) => mapping,
            Err(error) => {
                // The canonical Error does not certify whether
                // a failed provider call left mappings behind. Keep the
                // power/reset epoch even for an ambiguous failure;
                // no CPU access or fictitious rollback may follow it.
                core::mem::forget(context);
                return Err(error.into());
            }
        };
        let view = match mapping.view(0..4 * 1024 * 1024) {
            Ok(view) => view,
            Err(e) => {
                drop(mapping);
                core::mem::forget(context);
                return Err(e.into());
            }
        };
        context.view = Some(view);
        // SAFETY: allocated/aligned private storage; context/owner/Mapping pinned.
        // C validates original table selection before MMIO; no object escapes.
        let result = unsafe {
            stela_intel_activation_init(
                state.pointer(),
                state.layout.size(),
                &IO,
                (&mut *context as *mut Context).cast(),
                u32::from(pci.vendor),
                u32::from(pci.device),
                pci.class,
                u32::from(pci.revision),
                pci.bar0_bytes,
                pci.virtual_function,
                force_probe,
            )
        };
        let bundle = Bundle {
            state,
            context,
            mapping,
        };
        if result != 0 {
            // prepare may have had hardware effects; no fake rollback.
            bundle.quarantine();
            return Err(Error::Native(result));
        }
        Ok(Self {
            bundle: Some(bundle),
            closing: false,
            drained: false,
            poisoned: false,
            awake: false,
            _affinity: PhantomData,
        })
    }
    fn live(&self) -> Result<&Bundle, Error> {
        if self.closing {
            return Err(Error::Closing);
        }
        self.bundle.as_ref().ok_or(Error::Closing)
    }
    pub fn facts(&self) -> Result<Facts, Error> {
        let mut result = Facts::default();
        // SAFETY: live immutable C state and exact scalar output layout.
        let status =
            unsafe { stela_intel_activation_facts(self.live()?.state.pointer(), &mut result) };
        if status == 0 {
            Ok(result)
        } else {
            Err(Error::Native(status))
        }
    }
    /// Issue the original direct XeLP PAT sequence in this exclusive live
    /// root-primary epoch. No readback, ACK, CPU cache or BO state is implied.
    pub fn program_pat(&mut self) -> Result<super::pat::Programming<'_>, Error> {
        let state = self.live()?.state.pointer();
        if !self.awake || self.poisoned {
            return Err(Error::Awake);
        }
        let mut result = super::pat::NativeResult::default();
        // SAFETY: State keeps same canonical view, descriptor/GT role,
        // exclusive owner and acknowledged wake; stack output before effects.
        let status = unsafe { stela_intel_activation_pat(state, &mut result) };
        if status != 0 {
            if result.writes != 0 {
                self.gsm_poison();
            }
            return Err(Error::Native(status));
        }
        Ok(super::pat::Programming::from_native(self, result))
    }
    /// Explicit original GuC-only reset handshake under the owner's
    /// exclusive no-DMA/no-IRQ/no-CT/no-submission epoch. This is not whole uC
    /// sanitize, driver initialization, software job drain or firmware loading.
    /// A failed exposed reset permanently closes and quarantines this epoch;
    /// no retry, Drop, sleep or finish may release uncertain reset ownership.
    pub fn reset_guc(&mut self) -> Result<super::guc_reset::Handshake<'_>, Error> {
        let state = self.live()?.state.pointer();
        if !self.awake || self.poisoned {
            return Err(Error::Awake);
        }
        let mut result = super::guc_reset::NativeResult::default();
        // SAFETY: same owned State/view and stable Context; acknowledged
        // GT wake, checked clock/context and exclusive real epoch exclude all
        // active users before entry. Stack metadata exists before any effect.
        let status = unsafe { stela_intel_activation_guc_reset(state, &mut result) };
        if status != 0 {
            if result.writes != 0 {
                self.gsm_poison();
            }
            return Err(Error::Native(status));
        }
        Ok(super::guc_reset::Handshake::from_native(self, result))
    }
    /// Acquire the original PF GSM geometry and a separate real same-BAR UC
    /// mapping. Requires acknowledged root GT wake and config-space/
    /// mapping capabilities; establishes neither GGTT initialization nor PAT.
    pub fn probe_gsm<'device>(
        &'device mut self,
        authority: &Authority,
    ) -> Result<super::ggtt::Probe<'device>, Error> {
        self.live()?;
        if !self.awake || self.poisoned {
            return Err(Error::Awake);
        }
        let facts = self.facts()?;
        let bundle = self.live()?;
        bundle
            .context
            .owner
            .check_context()
            .map_err(Error::Native)?;
        let mut offset = 0;
        // SAFETY: original CPU-only policy; checked live device facts.
        let config =
            unsafe { super::ggtt::stela_intel_gsm_config(facts.graphics_verx100, &mut offset) };
        let gmch = match config {
            0 => bundle
                .context
                .owner
                .config_space()
                .map_err(Error::Native)?
                .read16(offset),
            1 => 0,
            error => return Err(Error::Native(error)),
        };
        let identity = bundle.context.owner.identity();
        let geometry =
            super::ggtt::Geometry::from_facts(facts, identity.bar0_bytes, config == 0, gmch)?;
        let resource = bundle.context.owner.bar0();
        if resource.kind() != ResourceKind::Registers
            || resource.physical_span().start() != identity.bar0_start
            || resource.physical_span().bytes() != identity.bar0_bytes
        {
            return Err(Error::InvalidOwner);
        }
        let bytes = usize::try_from(geometry.gsm_bytes).map_err(|_| Error::InvalidOwner)?;
        let offset = usize::try_from(geometry.gsm_offset).map_err(|_| Error::InvalidOwner)?;
        let mapping = match authority.map(
            resource,
            offset,
            bytes,
            CacheAttribute::Uncached,
            Protection::ReadOnly,
        ) {
            Ok(mapping) => mapping,
            Err(error) => {
                // Error does not certify a safe rollback. Existing backing and
                // preallocated Context keep reset/power/forcewake pinned, with
                // no allocation or device access in this uncertainty path.
                self.gsm_poison();
                return Err(error.into());
            }
        };
        let view = match mapping.view(0..bytes) {
            Ok(view) => view,
            Err(error) => {
                self.gsm_poison();
                drop(mapping); // canonical quarantine; never assume unmap.
                return Err(error.into());
            }
        };
        Ok(super::ggtt::Probe::from_native(
            self, geometry, mapping, view,
        ))
    }
    pub(super) fn gsm_check_context(&self) -> Result<(), Error> {
        self.bundle
            .as_ref()
            .ok_or(Error::Closing)?
            .context
            .owner
            .check_context()
            .map_err(Error::Native)
    }
    pub(super) fn gsm_poison(&mut self) {
        self.closing = true;
        self.poisoned = true;
    }
    pub(super) fn gsm_read64(&self, view: &MappingView, offset: usize) -> Result<u64, Error> {
        let bundle = self.live()?;
        if !self.awake || self.poisoned {
            return Err(Error::Awake);
        }
        bundle
            .context
            .owner
            .check_context()
            .map_err(Error::Native)?;
        let pointer = view.address(offset, 8)?;
        if !(pointer.as_ptr() as usize).is_multiple_of(8) {
            return Err(Error::InvalidOwner);
        }
        // SAFETY: same-resource UC lease; checked complete width,
        // original PTE index and native owner/context; exclusive Device borrow.
        unsafe { bundle.context.owner.read64(pointer.cast()) }.map_err(Error::Native)
    }
    /// Original default GuC metadata request, bound to this live
    /// native root main-GT owner. No firmware is uploaded or authenticated.
    pub fn guc_firmware(&self) -> Result<super::firmware::Request<'_>, super::firmware::Error> {
        let identity = self.live()?.context.owner.identity();
        let facts = self.facts()?;
        super::firmware::Request::from_native(self, identity, facts)
    }
    /// Original default HuC request, keeping this root main-GT owner.
    /// Host parsing never establishes firmware availability or WOPCM readiness.
    pub fn huc_firmware(&self) -> Result<super::firmware::HucRequest<'_>, super::firmware::Error> {
        let identity = self.live()?.context.owner.identity();
        let facts = self.facts()?;
        super::firmware::HucRequest::from_native(self, identity, facts)
    }
    /// Partition/read back root-GT WOPCM using the original algorithm.
    /// Requires acknowledged wake. An exposed write failure permanently closes
    /// this epoch and keeps its canonical owner/view; no cleanup can release
    /// forcewake/reset ownership. All result storage is on the stack before IO.
    pub fn prepare_wopcm<'device, 'provider>(
        &'device mut self,
        provider: &'provider dyn stela_driver_core::firmware::Provider,
    ) -> Result<super::wopcm::Preparation<'device, 'provider>, super::wopcm::Error> {
        self.live()?;
        if !self.awake || self.poisoned {
            return Err(Error::Awake.into());
        }
        let (image, metadata, identity, facts) = {
            let request = self.guc_firmware()?;
            let loaded = request.load(provider)?;
            (
                loaded.image(),
                loaded.metadata(),
                loaded.identity(),
                loaded.facts(),
            )
        };
        let mut result = super::wopcm::NativeResult::default();
        // SAFETY: SAME private owned C state and immutable provider CPU
        // span. C independently checks acknowledged GT/role/firmware bounds.
        // Existing State/Context/mapping storage was reserved before all IO;
        // no allocation or owner release follows an exposed failure.
        let status = unsafe {
            stela_intel_activation_wopcm(
                self.live()?.state.pointer(),
                image.bytes().as_ptr(),
                image.bytes().len(),
                &mut result,
            )
        };
        if status != 0 {
            if result.writes != 0 {
                self.poisoned = true;
                self.closing = true;
            }
            return Err(result.error(status));
        }
        Ok(super::wopcm::Preparation::from_native(
            self, image, metadata, identity, facts, result,
        ))
    }
    pub fn wake(&mut self) -> Result<(), Error> {
        let storage = self.live()?.state.pointer();
        if self.awake || self.poisoned {
            return Err(Error::Awake);
        }
        // SAFETY: &mut plus CPU affinity and ProbeOwner exclude all users.
        let status = unsafe { stela_intel_activation_wake(storage) };
        if status != 0 {
            self.poisoned = true;
            return Err(Error::Native(status));
        }
        self.awake = true;
        Ok(())
    }
    pub fn sleep(&mut self) -> Result<(), Error> {
        let storage = self.live()?.state.pointer();
        if !self.awake || self.poisoned {
            return Err(Error::Awake);
        }
        // SAFETY: same exclusive native scope; no concurrent firmware.
        let status = unsafe { stela_intel_activation_sleep(storage) };
        if status != 0 {
            self.poisoned = true;
            return Err(Error::Native(status));
        }
        self.awake = false;
        Ok(())
    }
    pub fn retire(&mut self) -> Result<(), Error> {
        if self.awake || self.poisoned {
            return Err(Error::Awake);
        }
        let bundle = self.bundle.as_mut().ok_or(Error::Closing)?;
        bundle
            .context
            .owner
            .check_context()
            .map_err(Error::Native)?;
        // A real drain can have partial effects before returning an error.
        // Freeze all public device/C operations BEFORE attempting it, keeping
        // the live mapping/view and owners until the drain succeeds.
        self.closing = true;
        if !self.drained {
            bundle.context.owner.finish().map_err(Error::Native)?;
            self.drained = true;
            // No future C/CPU accesses; release our view before unmap.
            drop(bundle.context.view.take());
        }
        // SAFETY: acknowledged sleep, owner drain, no IRQ/submission,
        // CPU-affine &mut exclusion. Failed mappings stay held for retry.
        unsafe { bundle.mapping.retire()? };
        self.bundle = None;
        Ok(())
    }
}
impl Drop for Device {
    fn drop(&mut self) {
        if let Some(bundle) = self.bundle.take() {
            bundle.quarantine();
        }
    }
}
