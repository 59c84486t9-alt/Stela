//! Original AMDGPU PCI matching and phase-specific discovery source selection.
//! This binds identity/policy to an actual borrowed PCI function; it neither
//! reserves resources nor establishes initialization, topology or GPU readiness.
use crate::bus::pci::{Address, ConfigSpace, Function};
use core::ffi::{CStr, c_char, c_int};

/// Actual native build/user/platform policy corresponding to the original probe.
/// These are configuration inputs, not hardware readiness/capability booleans.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub si_built: bool,
    pub cik_built: bool,
    pub radeon_built: bool,
    pub si_support: i32,
    pub cik_support: i32,
    pub experimental: i32,
    pub discovery: i32,
    pub force_asic: i32,
    pub memory_encrypted: bool,
    pub firmware_drivers_only: bool,
    pub modeset: i32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Absent,
    UnsupportedHeader,
    IdentityChanged,
    Native(c_int),
    InvalidNativeResult,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpPath {
    SiStatic,
    CikStatic,
    ViStatic,
    /// Original per-ASIC versions/bases; optional discovery is inventory only.
    SocStatic,
    /// Original discovery consumer is required; source selection is independent.
    Dynamic,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    NotUsed,
    Hardware,
    /// Exact original preferred source; no fallback to hardware on failure.
    Firmware(&'static CStr),
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ConfigIdentity {
    vendor: u32,
    device: u32,
    subvendor: u32,
    subdevice: u32,
    class_code: u32,
    revision: u32,
}
#[repr(C)]
struct NativePolicy {
    si_built: u32,
    cik_built: u32,
    radeon_built: u32,
    si_support: i32,
    cik_support: i32,
    experimental: i32,
    discovery: i32,
    force_asic: i32,
    memory_encrypted: u32,
    firmware_drivers_only: u32,
    modeset: i32,
}
#[repr(C)]
#[derive(Default)]
struct NativeMatch {
    row: u32,
    original_flags: u32,
    asic_type: u32,
    initial_apu_flags: u32,
    ip_path: u32,
    discovery_source: u32,
    filename: *const c_char,
}
const _: () = assert!(size_of::<ConfigIdentity>() == 24);
const _: () = assert!(size_of::<NativePolicy>() == 44);
const _: () = assert!(size_of::<NativeMatch>() == 32);
const _: () = assert!(core::mem::offset_of!(NativeMatch, filename) == 24);
unsafe extern "C" {
    fn stela_amd_pci_match(
        identity: &ConfigIdentity,
        policy: &NativePolicy,
        out: &mut NativeMatch,
    ) -> c_int;
}

/// Private original result. Only actual config matching may construct this.
/// Kept with the real borrowed resource/reset owner by matched attachment.
#[derive(Clone, Copy, Debug)]
pub(super) struct Admission {
    config: ConfigIdentity,
    row: u32,
    original_flags: u32,
    asic_type: u32,
    initial_apu_flags: u32,
    path: IpPath,
    source: Source,
    discovery_option: i32,
}
impl Admission {
    pub(super) fn flags(self) -> u32 {
        self.original_flags
    }
    pub(super) fn asic(self) -> u32 {
        self.asic_type
    }
    pub(super) fn path(self) -> IpPath {
        self.path
    }
    pub(super) fn source(self) -> Source {
        self.source
    }
    pub(super) fn discovery_option(self) -> i32 {
        self.discovery_option
    }
    pub(super) fn firmware_hardware(self) -> (u16, u16) {
        (self.config.vendor as u16, self.config.device as u16)
    }
    pub(super) fn firmware_revision(self) -> (u8, u16, u16) {
        (
            self.config.revision as u8,
            self.config.subvendor as u16,
            self.config.subdevice as u16,
        )
    }
}

/// The original normal-table match and policy result for this exact function.
/// Borrowing prevents mutation/rebinding of its Function while this is retained.
/// Actual platform/resource exclusion remains an unsafe native-owner duty.
pub struct MatchedFunction<'function, C> {
    function: &'function Function<C>,
    admission: Admission,
}
impl<C: ConfigSpace> MatchedFunction<'_, C> {
    pub fn address(&self) -> Address {
        self.function.address
    }
    pub fn revision(&self) -> u8 {
        self.admission.config.revision as u8
    }
    pub fn subsystem_ids(&self) -> (u16, u16) {
        (
            self.admission.config.subvendor as u16,
            self.admission.config.subdevice as u16,
        )
    }
    pub fn matched_row(&self) -> u32 {
        self.admission.row
    }
    pub fn original_flags(&self) -> u32 {
        self.admission.original_flags
    }
    pub fn asic_type(&self) -> u32 {
        self.admission.asic_type
    }
    /// Only flags established at original initial-APU stage. Modern wildcard
    /// matches may be APUs; final classification follows genuine IP discovery.
    pub fn initial_apu_flags(&self) -> u32 {
        self.admission.initial_apu_flags
    }
    pub fn ip_path(&self) -> IpPath {
        self.admission.path
    }
    pub fn source(&self) -> Source {
        self.admission.source
    }
    pub(super) fn function(&self) -> &Function<C> {
        self.function
    }
    pub(super) fn admission(&self) -> Admission {
        self.admission
    }
}

/// Read actual config and apply original normal-table probe/source decisions.
/// No config writes, allocation, hardware activation or firmware acquisition.
/// Linux dynamic IDs/driver_override and forced-ASIC debug paths do not produce
/// this result. Preferred files and static implementations remain explicit.
///
/// # Safety
/// `function` is this native owner's genuine, accessible PCI function in the
/// retained device/reset epoch, with native config/reset/removal exclusion.
/// `policy` is the actual native build/user/platform policy at this probe stage;
/// memory-encryption/firmware-driver arbitration cannot be guessed to admit a
/// device. Existing native resources/firmware/PCI enable ownership is separate.
/// Keep the real owner/epoch stable through all returned dependent objects.
/// This API cannot turn a model ConfigSpace into actual hardware evidence.
pub unsafe fn identify<C: ConfigSpace>(
    function: &mut Function<C>,
    policy: Policy,
) -> Result<MatchedFunction<'_, C>, Error> {
    let labels = (function.vendor, function.device, function.class);
    let config = function.config();
    let ids = config.read32(0);
    if ids as u16 == u16::MAX {
        return Err(Error::Absent);
    }
    if config.read8(0x0e) & 0x7f != 0 {
        return Err(Error::UnsupportedHeader);
    }
    let class_revision = config.read32(8);
    let subsystem = config.read32(0x2c);
    let observed = ConfigIdentity {
        vendor: u32::from(ids as u16),
        device: ids >> 16,
        subvendor: u32::from(subsystem as u16),
        subdevice: subsystem >> 16,
        class_code: class_revision >> 8,
        revision: class_revision & 0xff,
    };
    let actual_class = [
        (class_revision >> 24) as u8,
        (class_revision >> 16) as u8,
        (class_revision >> 8) as u8,
    ];
    if labels != (ids as u16, (ids >> 16) as u16, actual_class) {
        return Err(Error::IdentityChanged);
    }
    let native_policy = NativePolicy {
        si_built: u32::from(policy.si_built),
        cik_built: u32::from(policy.cik_built),
        radeon_built: u32::from(policy.radeon_built),
        si_support: policy.si_support,
        cik_support: policy.cik_support,
        experimental: policy.experimental,
        discovery: policy.discovery,
        force_asic: policy.force_asic,
        memory_encrypted: u32::from(policy.memory_encrypted),
        firmware_drivers_only: u32::from(policy.firmware_drivers_only),
        modeset: policy.modeset,
    };
    let mut matched = NativeMatch::default();
    // SAFETY: exact independently asserted scalar ABI; no borrowed input retained.
    let status = unsafe { stela_amd_pci_match(&observed, &native_policy, &mut matched) };
    if status != 0 {
        return Err(Error::Native(status));
    }
    let path = match matched.ip_path {
        0 => IpPath::SiStatic,
        1 => IpPath::CikStatic,
        2 => IpPath::ViStatic,
        3 => IpPath::SocStatic,
        4 => IpPath::Dynamic,
        _ => return Err(Error::InvalidNativeResult),
    };
    let source = match matched.discovery_source {
        0 if matched.filename.is_null() => Source::NotUsed,
        1 if matched.filename.is_null() => Source::Hardware,
        2 if !matched.filename.is_null() => {
            // SAFETY: successful original C selector returns only its immutable
            // static nul-terminated filename literal, linked for process lifetime.
            Source::Firmware(unsafe { CStr::from_ptr(matched.filename) })
        }
        _ => return Err(Error::InvalidNativeResult),
    };
    Ok(MatchedFunction {
        function,
        admission: Admission {
            config: observed,
            row: matched.row,
            original_flags: matched.original_flags,
            asic_type: matched.asic_type,
            initial_apu_flags: matched.initial_apu_flags,
            path,
            source,
            discovery_option: policy.discovery,
        },
    })
}
