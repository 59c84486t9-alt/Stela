//! Actual original PF GPU-VRAM discovery acquisition. System firmware RAM and
//! VF protocols remain unavailable until their genuine native owners exist.
use super::{
    native_mmio::{
        AttachedBars, DynamicHardware, Error as WindowError, FileSource, Identity, RegisterWindow,
    },
    vram,
};
use crate::Clock;

// Exact private discovery_tmr.h enum ABI; C/Rust owner fixtures exercise both.
const TMR_VF_OWNER_UNAVAILABLE: c_int = 3;
const TMR_SYSTEM_OWNER_UNAVAILABLE: c_int = 4;
use alloc::vec::Vec;
use core::{
    ffi::{c_int, c_uint, c_void},
    marker::PhantomData,
};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Window(WindowError),
    ClockUnavailable,
    /// Before a region is acquired; may follow real query reads/index writes.
    Query(c_int),
    VfOwnerUnavailable,
    SystemFirmwareOwnerUnavailable,
    /// Query already ran. Allocation failure never rolls back its effects.
    PostQueryAllocation,
    InvalidRegion,
    Read(vram::Error),
    Validation(c_int),
    /// Snapshot already acquired; earlier register effects are not rolled back.
    PostAcquireAllocation,
    Decode(c_int),
}
#[repr(C)]
#[derive(Default)]
struct Region {
    offset: u64,
    vram_bytes: u64,
    size: u32,
    reserved: u32,
}
const _: () = assert!(size_of::<Region>() == 24);
const _: () = assert!(core::mem::offset_of!(Region, size) == 16);
unsafe extern "C" {
    fn stela_amd_discovery_tmr_query(
        registers: *mut c_void,
        bytes: usize,
        asic: u32,
        context: *mut c_void,
        sleep_ms: unsafe extern "C" fn(*mut c_void, c_uint),
        out: &mut Region,
    ) -> c_int;
    fn amdgpu_discovery_binary_validate(binary: *const u8, bytes: usize) -> c_int;
}
unsafe extern "C" fn sleep_ms(context: *mut c_void, milliseconds: c_uint) {
    // SAFETY: acquire lends this exact immutable Clock for the synchronous call.
    let clock = unsafe { &*context.cast::<Clock>() };
    clock.delay(u64::from(milliseconds) * 1000);
}

/// Private immutable original bytes and the same actual device owner borrow.
/// No mutable view is exposed: original in-place register-base conversions must
/// use a separately owned working copy and retain these acquisition bytes.
/// A snapshot is not a TMR reservation, BO, authenticated firmware or GPU READY.
pub struct Snapshot<'owner> {
    words: Vec<u32>,
    region: Region,
    identity: Identity,
    _owner: PhantomData<&'owner ()>,
}
impl Snapshot<'_> {
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: fully initialized private DWORD allocation; only immutable
        // bytes exposed, exact logical extent, no device DMA into this buffer.
        unsafe {
            core::slice::from_raw_parts(self.words.as_ptr().cast(), self.region.size as usize)
        }
    }
    pub fn identity(&self) -> Identity {
        self.identity
    }
    pub fn vram_offset(&self) -> u64 {
        self.region.offset
    }
    pub fn vram_bytes(&self) -> u64 {
        self.region.vram_bytes
    }
}

/// Query the original TMR and acquire its actual PF GPU-VRAM snapshot.
/// All available register/service bounds are checked before first access;
/// mailbox-dependent memory bounds are checked after query and before copying.
/// Original void MM reads provide no transport acknowledgement. Only original
/// signature/checksums/geometry qualify the private bytes, never hardware state.
/// IFWI exhaustion remains nonfatal as in the original driver.
///
/// # Safety
/// The original native owner has selected this discovery bootstrap path on the
/// actual matched ASIC. Preserve its static-IP/optional-file policy; this API
/// cannot bypass a preferred firmware source or admit another device family.
/// Caller holds genuine D0/bridge/reset/removal/MM-index/IRQ exclusion, actual
/// UC ordered MMIO semantics and allowed process/CPU context for the WHOLE
/// query/copy. No concurrent driver/firmware/device mutation may affect source
/// acquisition. The observed RCC extent and selected VRAM source must actually
/// be accessible in this epoch. Actual original TMR/VRAM ownership is retained;
/// this API creates no reservation and never substitutes host PA or DMA IOVA.
/// The same owner cannot reset/rebind/retire while the returned borrow is used.
/// `clock` is the mount's genuine calibrated elapsed-time clock, with its real
/// wait hook/context. The existing delay busy-waits; it is not scheduler sleep.
/// Unexpected access faults follow real platform retention/fail-stop policy;
/// no error or Drop can undo earlier register/index effects.
pub unsafe fn acquire<'owner>(
    bars: &'owner AttachedBars<'_>,
    clock: &Clock,
) -> Result<Snapshot<'owner>, Error> {
    if clock.ticks_per_microsecond == 0 {
        return Err(Error::ClockUnavailable);
    }
    let window = bars.registers().map_err(Error::Window)?;
    // SAFETY: this same borrowed original owner and full acquisition contract.
    unsafe { acquire_window(&window, bars.identity(), clock) }
}

unsafe fn query_storage<'owner>(
    window: &RegisterWindow<'owner>,
    identity: Identity,
    clock: &Clock,
) -> Result<Snapshot<'owner>, Error> {
    if clock.ticks_per_microsecond == 0 {
        return Err(Error::ClockUnavailable);
    }
    // SAFETY: original owner contract above; borrowed mapping retained throughout.
    let registers = unsafe { window.native_base() }.map_err(Error::Window)?;
    let mut region = Region::default();
    // SAFETY: exact scalar ABI and synchronous Clock borrow; native preflight
    // precedes access. No borrowed pointer is retained by the original core.
    let status = unsafe {
        stela_amd_discovery_tmr_query(
            registers.as_ptr().cast(),
            window.bytes(),
            identity.asic_type,
            (clock as *const Clock).cast_mut().cast(),
            sleep_ms,
            &mut region,
        )
    };
    match status {
        0 => {}
        TMR_VF_OWNER_UNAVAILABLE => return Err(Error::VfOwnerUnavailable),
        TMR_SYSTEM_OWNER_UNAVAILABLE => return Err(Error::SystemFirmwareOwnerUnavailable),
        other => return Err(Error::Query(other)),
    }
    if region.reserved != 0
        || region.size == 0
        || !region.size.is_multiple_of(4)
        || region.offset > region.vram_bytes
        || u64::from(region.size) > region.vram_bytes - region.offset
    {
        return Err(Error::InvalidRegion);
    }
    let count = region.size as usize / size_of::<u32>();
    let mut words = Vec::new();
    words
        .try_reserve_exact(count)
        .map_err(|_| Error::PostQueryAllocation)?;
    words.resize(count, 0);
    Ok(Snapshot {
        words,
        region,
        identity,
        _owner: PhantomData,
    })
}

unsafe fn acquire_window<'owner>(
    window: &RegisterWindow<'owner>,
    identity: Identity,
    clock: &Clock,
) -> Result<Snapshot<'owner>, Error> {
    // SAFETY: exact same genuine owner/query exclusion contract as acquire.
    let mut snapshot = unsafe { query_storage(window, identity, clock) }?;
    // SAFETY: actual bounded original VRAM region and exclusive private CPU RAM.
    unsafe {
        vram::read(
            window,
            snapshot.region.vram_bytes,
            snapshot.region.offset,
            &mut snapshot.words,
        )
    }
    .map_err(Error::Read)?;
    validate_snapshot(&snapshot)?;
    Ok(snapshot)
}
fn validate_snapshot(snapshot: &Snapshot<'_>) -> Result<(), Error> {
    // SAFETY: complete actual same-allocation private source bytes, immutable
    // and fully initialized before the original bounded validator runs.
    let status = unsafe {
        amdgpu_discovery_binary_validate(
            snapshot.words.as_ptr().cast(),
            snapshot.region.size as usize,
        )
    };
    if status != 0 {
        return Err(Error::Validation(status));
    }
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Binding {
    offset: u32,
    count: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Shape {
    hw_ip_count: u32,
    instances: u32,
}
/// Original pre-harvest counts and masks, not final topology or Metal limits.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IpCounts {
    pub xcc_mask: u16,
    pub vcn_mask: u16,
    pub jpeg_mask: u16,
    pub vcn_count: u8,
    pub vcn_config: [u8; 4],
    pub sdma_count: i32,
    pub sdma_mask: u32,
    pub vpe_count: u32,
    pub umc_count: i32,
    pub node_count: u32,
}
const _: () = assert!(size_of::<Binding>() == 8);
const _: () = assert!(size_of::<Shape>() == 8);
const _: () = assert!(size_of::<IpCounts>() == 32);
const _: () = assert!(core::mem::offset_of!(IpCounts, sdma_count) == 12);
const _: () = assert!(core::mem::offset_of!(IpCounts, node_count) == 28);
unsafe extern "C" {
    fn stela_amd_discovery_ip_shape() -> Shape;
    fn stela_amd_discovery_ip_decode(
        work: *mut u8,
        bytes: usize,
        versions: *mut u32,
        version_count: usize,
        bindings: *mut Binding,
        binding_count: usize,
        counts: &mut IpCounts,
    ) -> c_int;
}

/// Observed original IP/register facts. This retains the exact admitted source
/// owner, immutable acquisition bytes and one private once-converted copy.
/// No public constructor/conversion from Snapshot or raw bytes exists.
/// Register offsets are facts, not permission to bypass original register
/// routing, bounds, power/reset, firmware or device-context prerequisites.
struct IpData<'owner> {
    snapshot: Snapshot<'owner>,
    work: Vec<u32>,
    versions: Vec<u32>,
    bindings: Vec<Binding>,
    shape: Shape,
    counts: IpCounts,
}
impl IpData<'_> {
    fn source_bytes(&self) -> &[u8] {
        self.snapshot.bytes()
    }
    fn identity(&self) -> Identity {
        self.snapshot.identity()
    }
    fn counts(&self) -> IpCounts {
        self.counts
    }
    fn slot(&self, hw_ip: u32, instance: u32) -> Option<usize> {
        if hw_ip >= self.shape.hw_ip_count || instance >= self.shape.instances {
            return None;
        }
        (hw_ip as usize)
            .checked_mul(self.shape.instances as usize)?
            .checked_add(instance as usize)
    }
    /// Original full version, including variant/subrevision. Zero remains an
    /// original value; WAFLC may provide a version without a register binding.
    fn version(&self, hw_ip: u32, instance: u32) -> Option<u32> {
        self.versions.get(self.slot(hw_ip, instance)?).copied()
    }
    /// None is unbound/out of range; Some(0) is an original zero-segment binding.
    fn register_count(&self, hw_ip: u32, instance: u32) -> Option<u32> {
        let binding = self.bindings.get(self.slot(hw_ip, instance)?)?;
        (binding.offset != u32::MAX).then_some(binding.count)
    }
    /// By-value unaligned-safe load from the private converted CPU allocation.
    /// Never form a Rust &[u32] over the original packed base array.
    fn register_base(&self, hw_ip: u32, instance: u32, segment: u32) -> Option<u32> {
        let binding = self.bindings.get(self.slot(hw_ip, instance)?)?;
        if binding.offset == u32::MAX || segment >= binding.count {
            return None;
        }
        let offset = (binding.offset as usize).checked_add((segment as usize).checked_mul(4)?)?;
        let end = offset.checked_add(4)?;
        let bytes = self.work.len().checked_mul(size_of::<u32>())?;
        if end > bytes {
            return None;
        }
        // SAFETY: checked complete initialized owned allocation, immutable CPU
        // bytes only. No aliasing or device pointer enters this view.
        let work = unsafe { core::slice::from_raw_parts(self.work.as_ptr().cast::<u8>(), bytes) };
        Some(u32::from_ne_bytes(work.get(offset..end)?.try_into().ok()?))
    }
}
fn storage<T: Clone>(count: usize, value: T) -> Result<Vec<T>, Error> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| Error::PostAcquireAllocation)?;
    result.resize(count, value);
    Ok(result)
}

/// Acquire and decode only the original matched dynamic hardware route.
/// Static, preferred-file and manual-attachment routes refuse before effects.
/// This does not initialize NBIO/GMC or publish a working GPU/VM.
///
/// # Safety
/// All genuine source/VRAM/reservation/context and full MM-index/D0/reset/IRQ
/// exclusion requirements of [`acquire`] apply. This exact canonical owner and
/// its real device/reset epoch remain valid through all returned facts. No
/// allocation/Drop undoes query/index effects or releases original TMR ownership.
pub unsafe fn acquire_dynamic_ip<'owner>(
    bars: &'owner AttachedBars<'_>,
    clock: &Clock,
) -> Result<ObservedIp<'owner>, Error> {
    let owner = bars.dynamic_hardware().map_err(Error::Window)?;
    // SAFETY: token holds this exact private admitted window and caller supplies
    // the same genuine acquisition/reset/exclusion contract as acquire.
    let snapshot = unsafe { acquire_window(owner.window(), owner.identity(), clock) }?;
    let data = decode_ip(snapshot)?;
    Ok(ObservedIp {
        data,
        _owner: owner,
    })
}
fn decode_ip(snapshot: Snapshot<'_>) -> Result<IpData<'_>, Error> {
    let mut work = storage(snapshot.words.len(), 0u32)?;
    work.copy_from_slice(&snapshot.words);
    // SAFETY: original compiled storage shape, no device access or callback.
    let shape = unsafe { stela_amd_discovery_ip_shape() };
    let cells = (shape.hw_ip_count as usize)
        .checked_mul(shape.instances as usize)
        .filter(|count| *count > 0)
        .ok_or(Error::PostAcquireAllocation)?;
    let mut versions = storage(cells, 0u32)?;
    let mut bindings = storage(cells, Binding::default())?;
    let mut counts = IpCounts::default();
    // SAFETY: exclusive complete disjoint CPU allocations, checked scalar ABI,
    // original immutable bytes copied once. No raw pointer is retained by C.
    let status = unsafe {
        stela_amd_discovery_ip_decode(
            work.as_mut_ptr().cast(),
            snapshot.bytes().len(),
            versions.as_mut_ptr(),
            versions.len(),
            bindings.as_mut_ptr(),
            bindings.len(),
            &mut counts,
        )
    };
    if status != 0 {
        return Err(Error::Decode(status));
    }
    Ok(IpData {
        snapshot,
        work,
        versions,
        bindings,
        shape,
        counts,
    })
}

/// Observed original hardware IP facts, retaining this privately admitted owner.
/// The raw source/once-converted work ownership and getter semantics are unchanged.
pub struct ObservedIp<'owner> {
    data: IpData<'owner>,
    _owner: DynamicHardware<'owner>,
}
impl ObservedIp<'_> {
    pub fn source_bytes(&self) -> &[u8] {
        self.data.source_bytes()
    }
    pub fn identity(&self) -> Identity {
        self.data.identity()
    }
    pub fn counts(&self) -> IpCounts {
        self.data.counts()
    }
    pub fn version(&self, hw_ip: u32, instance: u32) -> Option<u32> {
        self.data.version(hw_ip, instance)
    }
    pub fn register_count(&self, hw_ip: u32, instance: u32) -> Option<u32> {
        self.data.register_count(hw_ip, instance)
    }
    pub fn register_base(&self, hw_ip: u32, instance: u32, segment: u32) -> Option<u32> {
        self.data.register_base(hw_ip, instance, segment)
    }
}

/// Original outer cleanup required after a selected-file acquisition error.
/// This is a pending service requirement, never an executed status/read result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileFailureDiagnostics {
    /// Original option2 omits the version-register/RAS cleanup branch.
    OmittedByOriginalOption2,
    /// Original non-option2 checks real mmIP_DISCOVERY_VERSION and may query
    /// actual RAS boot status. That device service has not run in this adapter.
    DiscoveryVersionAndRasCheckRequired,
}
#[derive(Debug)]
pub enum FileSourceError {
    Provider(crate::firmware::Error),
    WrongImage,
    Policy(c_int),
    Region(Error),
}
#[derive(Debug)]
pub enum FileError {
    Window(WindowError),
    IdentityEncoding,
    InvalidCatalogName,
    InvalidNativePolicy,
    /// Original query or zeroed storage failed before any provider request.
    Acquire(Error),
    /// File selection/read failed after query/allocation; no hardware fallback.
    Source {
        error: FileSourceError,
        pending: FileFailureDiagnostics,
    },
    /// Source already validated. Later native fact storage failed, with all
    /// earlier query effects retained and no published IP result.
    Ip(Error),
}

// Fixed-width observed PCI labels only; no allocation or guessed GPU family.
struct FileLabel<const N: usize> {
    bytes: [u8; N],
    used: usize,
}
impl<const N: usize> FileLabel<N> {
    fn new() -> Self {
        Self {
            bytes: [0; N],
            used: 0,
        }
    }
    fn as_str(&self) -> &str {
        // SAFETY: Write only copies complete valid UTF-8 strings below.
        unsafe { core::str::from_utf8_unchecked(&self.bytes[..self.used]) }
    }
}
impl<const N: usize> core::fmt::Write for FileLabel<N> {
    fn write_str(&mut self, value: &str) -> core::fmt::Result {
        let end = self
            .used
            .checked_add(value.len())
            .filter(|end| *end <= N)
            .ok_or(core::fmt::Error)?;
        self.bytes[self.used..end].copy_from_slice(value.as_bytes());
        self.used = end;
        Ok(())
    }
}
unsafe extern "C" {
    fn stela_amd_discovery_file_minimum() -> usize;
    fn stela_amd_discovery_file_validate(data: *const u8, bytes: usize, capacity: u32) -> c_int;
}

/// Original exact preferred-file request, minted from this same live privately
/// admitted BAR owner. No Image, Snapshot, path string, tuple or BDF constructor.
/// A request is not firmware authentication, TMR reservation or GPU readiness.
pub struct FileRequest<'owner> {
    owner: FileSource<'owner>,
    name: &'static str,
    hardware: FileLabel<16>,
    revision: FileLabel<40>,
    minimum: usize,
}
impl<'owner> FileRequest<'owner> {
    pub fn new(bars: &'owner AttachedBars<'_>) -> Result<Self, FileError> {
        use core::fmt::Write;
        let owner = bars.source_file().map_err(FileError::Window)?;
        let name = owner
            .filename()
            .to_str()
            .map_err(|_| FileError::InvalidCatalogName)?;
        let mut hardware = FileLabel::new();
        let (vendor, device) = owner.hardware_ids();
        write!(hardware, "pci-{vendor:04x}-{device:04x}")
            .map_err(|_| FileError::IdentityEncoding)?;
        let mut revision = FileLabel::new();
        let (pci_revision, subvendor, subdevice) = owner.revision_ids();
        write!(
            revision,
            "pci-{pci_revision:02x};subsys-{subvendor:04x}-{subdevice:04x}"
        )
        .map_err(|_| FileError::IdentityEncoding)?;
        // SAFETY: actual original compiled header span, no device effects.
        let minimum = unsafe { stela_amd_discovery_file_minimum() };
        if minimum == 0 {
            return Err(FileError::InvalidNativePolicy);
        }
        Ok(Self {
            owner,
            name,
            hardware,
            revision,
            minimum,
        })
    }
    pub fn name(&self) -> &str {
        self.name
    }
    /// Exact manifest equality keys from actual observed PCI fields; not a
    /// declaration that some other device/revision can use this firmware.
    pub fn target(&self) -> crate::firmware::Target<'_> {
        crate::firmware::Target {
            driver: "amd-amdgpu-ip-discovery",
            hardware: self.hardware.as_str(),
            revision: self.revision.as_str(),
            board: None,
        }
    }
    pub fn requirement(&self) -> crate::firmware::Requirement<'_> {
        crate::firmware::Requirement {
            name: self.name(),
            target: self.target(),
            minimum_bytes: self.minimum,
        }
    }
    fn source_error(&self, error: FileSourceError) -> FileError {
        FileError::Source {
            error,
            pending: if self.owner.discovery_option() == 2 {
                FileFailureDiagnostics::OmittedByOriginalOption2
            } else {
                FileFailureDiagnostics::DiscoveryVersionAndRasCheckRequired
            },
        }
    }

    /// Acquire the selected file in original order: real TMR query -> normal
    /// zeroed allocation -> exact provider request -> actual file bounds/checksum
    /// -> copy/region validation. No preferred-source fallback occurs.
    ///
    /// # Safety
    /// All genuine source/VRAM/TMR ownership, calibrated Clock and full D0/reset,
    /// removal/MM-index/IRQ exclusion/context requirements of [`acquire`] hold
    /// for the whole synchronous query/load/copy. Retain the same genuine device
    /// owner/reset epoch through returned facts. A file
    /// cannot bypass query/VF/system-memory services. Original option2 requests
    /// TMR reservation but this adapter cannot create or assert that reservation.
    /// Earlier query/index effects are never rolled back on provider/OOM/error.
    /// A static inventory result does not run fixed-IP initialization or the
    /// original outer version-register/RAS diagnostic service after failures.
    pub unsafe fn acquire<'provider, P: crate::firmware::Provider + ?Sized>(
        self,
        provider: &'provider P,
        clock: &Clock,
    ) -> Result<SelectedFile<'owner, 'provider>, FileError> {
        // SAFETY: same retained admitted window and complete original contract.
        let mut snapshot =
            unsafe { query_storage(self.owner.window(), self.owner.identity(), clock) }
                .map_err(FileError::Acquire)?;
        let requirement = self.requirement();
        let image = provider
            .load(requirement)
            .map_err(|error| self.source_error(FileSourceError::Provider(error)))?;
        if image.name() != requirement.name || image.target() != requirement.target {
            return Err(self.source_error(FileSourceError::WrongImage));
        }
        // SAFETY: actual immutable canonical image allocation and queried extent.
        let status = unsafe {
            stela_amd_discovery_file_validate(
                image.bytes().as_ptr(),
                image.bytes().len(),
                snapshot.region.size,
            )
        };
        if status != 0 {
            return Err(self.source_error(FileSourceError::Policy(status)));
        }
        // SAFETY: complete initialized exclusive CPU Vec, no active aliases.
        // Original file policy already checked actual bytes fit real capacity.
        let destination = unsafe {
            core::slice::from_raw_parts_mut(
                snapshot.words.as_mut_ptr().cast::<u8>(),
                snapshot.region.size as usize,
            )
        };
        destination[..image.bytes().len()].copy_from_slice(image.bytes());
        validate_snapshot(&snapshot)
            .map_err(|error| self.source_error(FileSourceError::Region(error)))?;
        match self.owner.path() {
            super::pci::IpPath::Dynamic => {
                let data = decode_ip(snapshot).map_err(FileError::Ip)?;
                Ok(SelectedFile::Dynamic(FileIp {
                    data,
                    image,
                    _owner: self.owner,
                }))
            }
            super::pci::IpPath::SocStatic => Ok(SelectedFile::Static(FileInventory {
                snapshot,
                image,
                _owner: self.owner,
            })),
            _ => Err(FileError::Window(WindowError::StaticInitializationRequired)),
        }
    }
}

/// Actual privately selected path determines the result. Static inventory has
/// no conversion into dynamic IP facts or permission to override fixed tables.
pub enum SelectedFile<'owner, 'provider> {
    Dynamic(FileIp<'owner, 'provider>),
    Static(FileInventory<'owner, 'provider>),
}
/// Exact canonical Image and real acquired bytes for static optional inventory.
/// This does not run static register/IP setup or sanitize missing inventory.
pub struct FileInventory<'owner, 'provider> {
    snapshot: Snapshot<'owner>,
    image: crate::firmware::Image<'provider>,
    _owner: FileSource<'owner>,
}
impl<'provider> FileInventory<'_, 'provider> {
    pub fn image(&self) -> crate::firmware::Image<'provider> {
        self.image
    }
    /// Copied file plus original zero-filled queried-region tail. Exact original
    /// file bytes/hash/provenance remain separately available via image().
    pub fn acquired_bytes(&self) -> &[u8] {
        self.snapshot.bytes()
    }
    pub fn identity(&self) -> Identity {
        self.snapshot.identity()
    }
    pub fn vram_offset(&self) -> u64 {
        self.snapshot.vram_offset()
    }
    pub fn vram_bytes(&self) -> u64 {
        self.snapshot.vram_bytes()
    }
}
/// Dynamic facts decoded by the SAME original decoder after selected-file
/// acquisition. Original Image/provider and actual device epoch remain borrowed.
pub struct FileIp<'owner, 'provider> {
    data: IpData<'owner>,
    image: crate::firmware::Image<'provider>,
    _owner: FileSource<'owner>,
}
impl<'provider> FileIp<'_, 'provider> {
    pub fn image(&self) -> crate::firmware::Image<'provider> {
        self.image
    }
    pub fn acquired_bytes(&self) -> &[u8] {
        self.data.source_bytes()
    }
    pub fn identity(&self) -> Identity {
        self.data.identity()
    }
    pub fn counts(&self) -> IpCounts {
        self.data.counts()
    }
    pub fn version(&self, hw_ip: u32, instance: u32) -> Option<u32> {
        self.data.version(hw_ip, instance)
    }
    pub fn register_count(&self, hw_ip: u32, instance: u32) -> Option<u32> {
        self.data.register_count(hw_ip, instance)
    }
    pub fn register_base(&self, hw_ip: u32, instance: u32, segment: u32) -> Option<u32> {
        self.data.register_base(hw_ip, instance, segment)
    }
}
