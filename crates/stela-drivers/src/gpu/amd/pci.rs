//! amdgpu's PCI probe admission, run by the unchanged amdgpu_drv.c. This binds
//! the result to a borrowed PCI function; it neither reserves resources
//! nor initializes, enables or claims the device.
use crate::bus::pci::{Address, ConfigSpace, Function};
use core::ffi::c_int;

/// amdgpu's module parameters that decide matching and discovery, with Linux's
/// defaults. As in Linux they are global: each call sets them for every device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    pub exp_hw_support: i32,
    pub discovery: i32,
    pub force_asic_type: i32,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            exp_hw_support: 0,
            discovery: -1,
            force_asic_type: -1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Absent,
    UnsupportedHeader,
    IdentityChanged,
    /// The negative status amdgpu's probe returns.
    Native(c_int),
    InvalidNativeResult,
}

/// How Linux brings up the matched ASIC's IP blocks: from the fixed VI or SOC15
/// tables, or from the IP discovery binary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpPath {
    ViStatic,
    SocStatic,
    Dynamic,
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
    exp_hw_support: i32,
    discovery: i32,
    force_asic_type: i32,
}
#[repr(C)]
#[derive(Default)]
struct NativeMatch {
    row: u32,
    flags: u32,
    asic_type: u32,
    apu_flags: u32,
    ip_path: u32,
}
const _: () = assert!(size_of::<ConfigIdentity>() == 24);
const _: () = assert!(size_of::<NativePolicy>() == 12);
const _: () = assert!(size_of::<NativeMatch>() == 20);
unsafe extern "C" {
    fn stela_amd_pci_match(
        identity: &ConfigIdentity,
        policy: &NativePolicy,
        out: &mut NativeMatch,
    ) -> c_int;
}

/// The probe's result for one function, kept with its BAR owner by
/// matched attachment.
#[derive(Clone, Copy, Debug)]
pub(super) struct Admission {
    config: ConfigIdentity,
    row: u32,
    flags: u32,
    asic_type: u32,
    apu_flags: u32,
    path: IpPath,
}
impl Admission {
    pub(super) fn flags(self) -> u32 {
        self.flags
    }
    pub(super) fn asic(self) -> u32 {
        self.asic_type
    }
    pub(super) fn apu_flags(self) -> u32 {
        self.apu_flags
    }
    pub(super) fn path(self) -> IpPath {
        self.path
    }
    pub(super) fn device(self) -> u16 {
        self.config.device as u16
    }
    pub(super) fn revision(self) -> u8 {
        self.config.revision as u8
    }
    pub(super) fn subsystem_ids(self) -> (u16, u16) {
        (self.config.subvendor as u16, self.config.subdevice as u16)
    }
}

/// The admission of this exact function. Borrowing prevents mutation or
/// rebinding of its Function while this is held.
pub struct MatchedFunction<'function, C> {
    function: &'function Function<C>,
    admission: Admission,
}
impl<C: ConfigSpace> MatchedFunction<'_, C> {
    pub fn address(&self) -> Address {
        self.function.address
    }
    pub fn revision(&self) -> u8 {
        self.admission.revision()
    }
    pub fn subsystem_ids(&self) -> (u16, u16) {
        self.admission.subsystem_ids()
    }
    /// The pciidlist row that matched.
    pub fn matched_row(&self) -> u32 {
        self.admission.row
    }
    /// The row's driver data: ASIC type and AMD_* flags.
    pub fn flags(&self) -> u32 {
        self.admission.flags
    }
    pub fn asic_type(&self) -> u32 {
        self.admission.asic_type
    }
    /// The APU flags Linux sets before IP discovery; a dynamic-path APU is
    /// classified by discovery.
    pub fn apu_flags(&self) -> u32 {
        self.admission.apu_flags
    }
    pub fn ip_path(&self) -> IpPath {
        self.admission.path
    }
    pub(super) fn function(&self) -> &Function<C> {
        self.function
    }
    pub(super) fn admission(&self) -> Admission {
        self.admission
    }
}

/// Read the function's configuration identity and run amdgpu's probe
/// admission on it. Reads configuration space only; Linux's dynamic IDs and
/// driver_override do not apply. A forced ASIC type is refused, since it
/// overrides the probe rather than following it.
///
/// # Safety
/// `function` is this native owner's actual, accessible PCI function, with
/// configuration, reset and removal excluded. Keep that owner and epoch stable
/// while the result and its dependents are used. No other thread may run this
/// concurrently, since `policy` sets amdgpu's global module parameters.
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
        exp_hw_support: policy.exp_hw_support,
        discovery: policy.discovery,
        force_asic_type: policy.force_asic_type,
    };
    let mut matched = NativeMatch::default();
    // SAFETY: scalar inputs and output with asserted layouts; C keeps none,
    // and the caller excludes concurrent use of the module parameters.
    let status = unsafe { stela_amd_pci_match(&observed, &native_policy, &mut matched) };
    if status != 0 {
        return Err(Error::Native(status));
    }
    let path = match matched.ip_path {
        0 => IpPath::ViStatic,
        1 => IpPath::SocStatic,
        2 => IpPath::Dynamic,
        _ => return Err(Error::InvalidNativeResult),
    };
    Ok(MatchedFunction {
        function,
        admission: Admission {
            config: observed,
            row: matched.row,
            flags: matched.flags,
            asic_type: matched.asic_type,
            apu_flags: matched.apu_flags,
            path,
        },
    })
}
