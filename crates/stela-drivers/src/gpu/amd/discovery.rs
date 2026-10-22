//! Linux's IP discovery, run by the unchanged amdgpu_discovery.c on a matched
//! dynamic-path PF. It acquires and checks the discovery binary, then decodes
//! IP versions, register bases, harvesting and the GC, MALL and VCN tables. No
//! IP block is registered or initialized, and no TMR is reserved.
use super::native_mmio::{AttachedBars, Error as WindowError, RegisterWindow};
use crate::{
    Clock,
    firmware::{Provider, Requirement, Target},
};
use alloc::{
    alloc::{alloc, dealloc},
    format,
    string::String,
};
use core::{
    alloc::Layout,
    ffi::{CStr, c_char, c_int, c_void},
    marker::PhantomData,
    mem::MaybeUninit,
    ptr::{self, NonNull},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Window(WindowError),
    OutOfMemory,
    /// The firmware Linux prefers for the binary could not be loaded.
    Firmware(crate::firmware::Error),
    /// A service discovery needed that Stela does not implement yet.
    Unsupported(&'static CStr),
    /// Linux's negative status.
    Native(c_int),
}

/// A GC table field, by its amdgpu_gfx_config or amdgpu_cu_info name.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GfxField {
    MaxShaderEngines,
    MaxCuPerSh,
    MaxShPerSe,
    MaxBackendsPerSe,
    MaxTextureChannelCaches,
    MaxGprs,
    MaxGsThreads,
    GsVgtTableDepth,
    GsPrimBufferDepth,
    DoubleOffchipLdsBuf,
    WaveFrontSize,
    MaxWavesPerSimd,
    MaxScratchSlotsPerCu,
    LdsSize,
    NumScPerSh,
    NumPackerPerSc,
    GcNumTcpPerSa,
    GcNumSdpInterface,
    GcNumTcps,
    GcNumTcpPerWpg,
    GcTcpL1Size,
    GcNumSqcPerWgp,
    GcL1InstructionCacheSizePerSqc,
    GcL1DataCacheSizePerSqc,
    GcGl1cPerSa,
    GcGl1cSizePerInstance,
    GcGl2cPerGpu,
    GcTcpSizePerCu,
    GcTcpCacheLineSize,
    GcInstructionCacheSizePerSqc,
    GcInstructionCacheLineSize,
    GcScalarDataCacheSizePerSqc,
    GcScalarDataCacheLineSize,
    GcTccSize,
    GcTccCacheLineSize,
    GcNumCuPerSqc,
}
const GFX_FIELDS: usize = GfxField::GcNumCuPerSqc as usize + 1;

/// Linux's discovery results, by their amdgpu_device names.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Facts {
    pub mall_size: u64,
    pub umc_active_mask: u64,
    pub harvest_ip_mask: u32,
    pub vcn_harvest: u32,
    pub jpeg_harvest: u32,
    pub m_half_use: u32,
    pub sdma_mask: u32,
    pub vpe_count: u32,
    pub umc_nodes: u32,
    pub vcn_codec_disable: [u32; 4],
    pub sdma_count: i32,
    pub umc_count: i32,
    pub xcc_mask: u16,
    pub vcn_mask: u16,
    pub jpeg_mask: u16,
    pub vcn_count: u8,
    pub vcn_config: [u8; 4],
    gfx: [u32; GFX_FIELDS],
}
const _: () = assert!(size_of::<Facts>() == 224);
const _: () = assert!(core::mem::offset_of!(Facts, gfx) == 80);
impl Facts {
    /// Zero where the GC table does not provide the field, as in Linux.
    pub fn gfx(&self, field: GfxField) -> u32 {
        self.gfx[field as usize]
    }
}

#[repr(C)]
struct Io {
    read32: unsafe extern "C" fn(*mut c_void, u32) -> u32,
    write32: unsafe extern "C" fn(*mut c_void, u32, u32),
    sleep_ms: unsafe extern "C" fn(*mut c_void, u32),
    firmware: unsafe extern "C" fn(*mut c_void, *const c_char, *mut *const u8, *mut usize) -> c_int,
}
#[repr(C)]
struct Device {
    register_bytes: u64,
    asic_type: u32,
    flags: u32,
    apu_flags: u32,
    pci_device: u16,
    pci_revision: u8,
}
const _: () = assert!(size_of::<Device>() == 24);
unsafe extern "C" {
    fn stela_amd_discovery_size() -> usize;
    fn stela_amd_discovery_alignment() -> usize;
    fn stela_amd_discovery_init(
        storage: *mut c_void,
        bytes: usize,
        io: &Io,
        context: *mut c_void,
        device: &Device,
    ) -> c_int;
    fn stela_amd_discovery_unsupported(state: *const c_void) -> *const c_char;
    fn stela_amd_discovery_facts(state: *const c_void, out: *mut Facts);
    fn stela_amd_discovery_version(state: *const c_void, hw_ip: u32, instance: u32) -> u32;
    fn stela_amd_discovery_registers(
        state: *const c_void,
        hw_ip: u32,
        instance: u32,
        segment: u32,
        base: *mut u32,
    ) -> c_int;
    fn stela_amd_discovery_fini(state: *mut c_void);
}

/// The owner's services, lent to the C adapter for the synchronous init call.
struct Services<'a> {
    window: RegisterWindow<'a>,
    clock: &'a Clock,
    provider: &'a dyn Provider,
    hardware: String,
    revision: String,
    failure: Option<Error>,
}
/// # Safety
/// `context` is init's exclusive Services; C makes no reentrant calls.
unsafe fn services<'a>(context: *mut c_void) -> &'a mut Services<'a> {
    // SAFETY: the caller's contract.
    unsafe { &mut *context.cast() }
}
fn dword(services: &mut Services<'_>, register: u32) -> Option<NonNull<u32>> {
    match services.window.direct_dword(register) {
        Ok(pointer) => Some(pointer),
        Err(error) => {
            services.failure.get_or_insert(Error::Window(error));
            None
        }
    }
}
unsafe extern "C" fn read32(context: *mut c_void, register: u32) -> u32 {
    // SAFETY: init lends its Services for this call.
    let services = unsafe { services(context) };
    // SAFETY: a checked, aligned register in the live mapping; discover's
    // caller holds the device exclusively.
    dword(services, register).map_or(u32::MAX, |p| unsafe { p.read_volatile() })
}
unsafe extern "C" fn write32(context: *mut c_void, register: u32, value: u32) {
    // SAFETY: init lends its Services for this call.
    let services = unsafe { services(context) };
    if let Some(pointer) = dword(services, register) {
        // SAFETY: as for read32.
        unsafe { pointer.write_volatile(value) };
    }
}
unsafe extern "C" fn sleep_ms(context: *mut c_void, milliseconds: u32) {
    // SAFETY: init lends its Services for this call.
    let services = unsafe { services(context) };
    services.clock.delay(u64::from(milliseconds) * 1000);
}
unsafe extern "C" fn firmware(
    context: *mut c_void,
    name: *const c_char,
    data: *mut *const u8,
    bytes: *mut usize,
) -> c_int {
    // SAFETY: init lends its Services for this call.
    let services = unsafe { services(context) };
    // SAFETY: Linux passes a NUL-terminated firmware name.
    let Ok(name) = unsafe { CStr::from_ptr(name) }.to_str() else {
        return -1;
    };
    let requirement = Requirement {
        name,
        target: Target {
            driver: "amd-amdgpu-ip-discovery",
            hardware: &services.hardware,
            revision: &services.revision,
            board: None,
        },
        // Linux checks the binary's header and size itself.
        minimum_bytes: 1,
    };
    match services.provider.load(requirement) {
        Ok(image) => {
            // SAFETY: C's output slots; the image outlives init, which copies it.
            unsafe {
                data.write(image.bytes().as_ptr());
                bytes.write(image.bytes().len());
            }
            0
        }
        Err(error) => {
            services.failure.get_or_insert(Error::Firmware(error));
            -1
        }
    }
}

/// A completed discovery. It borrows the attachment, whose device epoch the
/// results describe.
pub struct Discovery<'owner> {
    state: NonNull<c_void>,
    layout: Layout,
    _owner: PhantomData<&'owner ()>,
}

/// Run Linux's discovery for the attachment's matched ASIC: from VRAM through
/// the MM index registers, or from the firmware Linux prefers when the
/// discovery parameter selects it. Linux checks the binary's signature,
/// checksum and table bounds. An access Stela cannot perform yet, such as an
/// indirect register or a binary in system memory, fails the discovery.
///
/// # Safety
/// The caller holds the actual device exclusively, in D0 and with reset,
/// removal and interrupts excluded, for the whole call; no other driver or
/// firmware may change the discovery source meanwhile. `clock` is calibrated.
/// The register and MM index accesses are not undone on failure.
pub unsafe fn discover<'owner>(
    bars: &'owner AttachedBars<'_>,
    clock: &Clock,
    provider: &dyn Provider,
) -> Result<Discovery<'owner>, Error> {
    let (window, admission) = bars.dynamic().map_err(Error::Window)?;
    let (subvendor, subdevice) = admission.subsystem_ids();
    let device = Device {
        register_bytes: window.bytes() as u64,
        asic_type: admission.asic(),
        flags: admission.flags(),
        apu_flags: admission.apu_flags(),
        pci_device: admission.device(),
        pci_revision: admission.revision(),
    };
    let mut services = Services {
        hardware: format!("pci-1002-{:04x}", admission.device()),
        revision: format!(
            "pci-{:02x};subsys-{subvendor:04x}-{subdevice:04x}",
            admission.revision()
        ),
        window,
        clock,
        provider,
        failure: None,
    };
    // SAFETY: pure queries of the adapter's state layout.
    let (size, align) = unsafe { (stela_amd_discovery_size(), stela_amd_discovery_alignment()) };
    let layout = Layout::from_size_align(size, align).map_err(|_| Error::OutOfMemory)?;
    // SAFETY: the adapter's state has a nonzero size.
    let state = NonNull::new(unsafe { alloc(layout) }).ok_or(Error::OutOfMemory)?;
    let io = Io {
        read32,
        write32,
        sleep_ms,
        firmware,
    };
    // SAFETY: owned storage of the queried layout; Services and io outlive
    // this synchronous call, and the caller's contract covers the device.
    let status = unsafe {
        stela_amd_discovery_init(
            state.as_ptr().cast(),
            size,
            &io,
            ptr::from_mut(&mut services).cast(),
            &device,
        )
    };
    if status == 0 {
        return Ok(Discovery {
            state: state.cast(),
            layout,
            _owner: PhantomData,
        });
    }
    // SAFETY: a failed init leaves its literal name; nothing else to release.
    let unsupported = unsafe { stela_amd_discovery_unsupported(state.as_ptr().cast()) };
    // SAFETY: allocated above with this layout.
    unsafe { dealloc(state.as_ptr(), layout) };
    Err(services.failure.unwrap_or_else(|| {
        if unsupported.is_null() {
            Error::Native(status)
        } else {
            // SAFETY: the adapter names services with static literals.
            Error::Unsupported(unsafe { CStr::from_ptr(unsupported) })
        }
    }))
}

impl Discovery<'_> {
    pub fn facts(&self) -> Facts {
        let mut facts = MaybeUninit::uninit();
        // SAFETY: initialized state; C writes every field.
        unsafe {
            stela_amd_discovery_facts(self.state.as_ptr(), facts.as_mut_ptr());
            facts.assume_init()
        }
    }

    /// The full IP version, with variant and subrevision, of an instance of
    /// Linux's enum amd_hw_ip_block_type.
    pub fn version(&self, hw_ip: u32, instance: u32) -> Option<u32> {
        // SAFETY: initialized state; C bounds the indices.
        let version = unsafe { stela_amd_discovery_version(self.state.as_ptr(), hw_ip, instance) };
        (version != 0).then_some(version)
    }

    /// The number of register base segments of an IP instance.
    pub fn register_count(&self, hw_ip: u32, instance: u32) -> Option<u32> {
        // SAFETY: initialized state; C bounds the indices.
        let count = unsafe {
            stela_amd_discovery_registers(self.state.as_ptr(), hw_ip, instance, 0, ptr::null_mut())
        };
        u32::try_from(count).ok()
    }

    pub fn register_base(&self, hw_ip: u32, instance: u32, segment: u32) -> Option<u32> {
        let mut base = 0;
        // SAFETY: initialized state; C bounds the indices and segment.
        let count = unsafe {
            stela_amd_discovery_registers(self.state.as_ptr(), hw_ip, instance, segment, &mut base)
        };
        (u32::try_from(count).is_ok_and(|count| segment < count)).then_some(base)
    }
}

impl Drop for Discovery<'_> {
    fn drop(&mut self) {
        // SAFETY: initialized state, released once, then its storage.
        unsafe {
            stela_amd_discovery_fini(self.state.as_ptr());
            dealloc(self.state.as_ptr().cast(), self.layout);
        }
    }
}
