//! Provider-borrowed GuC/HuC metadata selected by a live native Xe device.
//! No BO, firmware status, authentication or hardware upload is established.
use super::activation::{self, Device, Facts, PciIdentity};
use crate::firmware::{Image, Provider, Requirement, Target};
use core::fmt::{self, Write};

const CSS_HEADER_BYTES: usize = 128;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Device(activation::Error),
    Selection(i32),
    InvalidNativeIdentity,
    InvalidCatalogName,
    IdentityEncoding,
    Provider(crate::firmware::Error),
    WrongImage,
    HucAbsent(HucDisposition),
    Parse {
        status: i32,
        diagnostics: Diagnostics,
    },
}
impl From<activation::Error> for Error {
    fn from(value: activation::Error) -> Self {
        Self::Device(value)
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct Diagnostics(u32);
impl Diagnostics {
    pub const GUC_TOO_OLD: u32 = 1 << 0;
    pub const VERSION_MISMATCH: u32 = 1 << 1;
    pub const RECOMMENDED_NEWER: u32 = 1 << 2;
    pub const SHORT_HEADER: u32 = 1 << 3;
    pub const HEADER_SIZE: u32 = 1 << 4;
    pub const SHORT_IMAGE: u32 = 1 << 5;
    pub const CPD_HEADER_LENGTH: u32 = 1 << 8;
    pub const CPD_SHORT_IMAGE: u32 = 1 << 9;
    pub const CPD_MISSING_MANIFEST: u32 = 1 << 10;
    pub const UNREPRESENTABLE: u32 = 1 << 31;
    pub fn bits(self) -> u32 {
        self.0
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Metadata {
    pub release: Version,
    pub submission: Version,
    pub ucode_bytes: u32,
    pub rsa_bytes: u32,
    pub upload_bytes: u32,
    pub private_bytes: u32,
    pub build_type: u32,
    pub diagnostics: Diagnostics,
}
#[repr(C)]
struct Selection {
    name: [u8; 64],
    wanted: Version,
    full_version: u32,
}
const _: () = assert!(core::mem::size_of::<Selection>() == 80);
const _: () = assert!(core::mem::size_of::<Metadata>() == 48);
const _: () = assert!(core::mem::offset_of!(Selection, wanted) == 64);
const _: () = assert!(core::mem::offset_of!(Selection, full_version) == 76);
const _: () = assert!(core::mem::offset_of!(Metadata, submission) == 12);
const _: () = assert!(core::mem::offset_of!(Metadata, ucode_bytes) == 24);
const _: () = assert!(core::mem::offset_of!(Metadata, diagnostics) == 44);
unsafe extern "C" {
    fn stela_intel_guc_select(platform: u32, output: &mut Selection) -> i32;
    fn stela_intel_guc_parse(
        platform: u32,
        bytes: *const u8,
        size: usize,
        output: &mut Metadata,
        diagnostics: &mut u32,
    ) -> i32;
}

// Only bounded Intel identity formatting; no allocation or general registry.
struct Label<const N: usize> {
    bytes: [u8; N],
    used: usize,
}
impl<const N: usize> Label<N> {
    fn new() -> Self {
        Self {
            bytes: [0; N],
            used: 0,
        }
    }
    fn as_str(&self) -> &str {
        // SAFETY: only write_str copies valid UTF-8, preserving whole fragments.
        unsafe { core::str::from_utf8_unchecked(&self.bytes[..self.used]) }
    }
}
impl<const N: usize> Write for Label<N> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self
            .used
            .checked_add(value.len())
            .filter(|&v| v <= N)
            .ok_or(fmt::Error)?;
        self.bytes[self.used..end].copy_from_slice(value.as_bytes());
        self.used = end;
        Ok(())
    }
}

fn identity_labels(identity: PciIdentity, facts: Facts) -> Result<(Label<16>, Label<96>), Error> {
    let mut hardware = Label::new();
    write!(
        hardware,
        "pci-{:04x}-{:04x}",
        identity.vendor, identity.device
    )
    .map_err(|_| Error::IdentityEncoding)?;
    let mut revision = Label::new();
    write!(
        revision,
        "pci-{:02x};gfx-{}.{};media-{}.{};gt-main;tile-0",
        identity.revision,
        facts.graphics_verx100,
        facts.graphics_revision,
        facts.media_verx100,
        facts.media_revision
    )
    .map_err(|_| Error::IdentityEncoding)?;
    Ok((hardware, revision))
}

/// Exact default request from the root main-GT device.
/// The setup manifest must use this same filename and exact target tuple.
pub struct Request<'device> {
    device: &'device Device,
    identity: PciIdentity,
    facts: Facts,
    selection: Selection,
    name_bytes: usize,
    hardware: Label<16>,
    revision: Label<96>,
}
impl<'device> Request<'device> {
    pub(super) fn from_native(
        device: &'device Device,
        identity: PciIdentity,
        facts: Facts,
    ) -> Result<Self, Error> {
        if identity.vendor != 0x8086 || identity.virtual_function || facts.graphics_verx100 == 0 {
            return Err(Error::InvalidNativeIdentity);
        }
        let mut selection = Selection {
            name: [0; 64],
            wanted: Version::default(),
            full_version: 0,
        };
        // SAFETY: private scalar output, exact C layout; source catalog only.
        let status = unsafe { stela_intel_guc_select(facts.platform, &mut selection) };
        if status != 0 {
            return Err(Error::Selection(status));
        }
        let name_bytes = selection
            .name
            .iter()
            .position(|&v| v == 0)
            .filter(|&n| n != 0)
            .ok_or(Error::InvalidCatalogName)?;
        core::str::from_utf8(&selection.name[..name_bytes])
            .map_err(|_| Error::InvalidCatalogName)?;
        let (hardware, revision) = identity_labels(identity, facts)?;
        Ok(Self {
            device,
            identity,
            facts,
            selection,
            name_bytes,
            hardware,
            revision,
        })
    }
    pub fn name(&self) -> &str {
        // SAFETY: constructor validates this immutable, private native copy.
        unsafe { core::str::from_utf8_unchecked(&self.selection.name[..self.name_bytes]) }
    }
    pub fn wanted(&self) -> Version {
        self.selection.wanted
    }
    pub fn full_version_required(&self) -> bool {
        self.selection.full_version != 0
    }
    pub fn target(&self) -> Target<'_> {
        Target {
            driver: "intel-xe-guc",
            hardware: self.hardware.as_str(),
            revision: self.revision.as_str(),
            board: None,
        }
    }
    pub fn requirement(&self) -> Requirement<'_> {
        Requirement {
            name: self.name(),
            target: self.target(),
            minimum_bytes: CSS_HEADER_BYTES,
        }
    }
    pub fn load<'provider>(
        &self,
        provider: &'provider dyn Provider,
    ) -> Result<GucImage<'device, 'provider>, Error> {
        let image = provider.load(self.requirement()).map_err(Error::Provider)?;
        // A safe third-party Provider cannot manufacture Image, but could
        // delegate to a catalog using the wrong requirement. Recheck its reply.
        if image.name() != self.name() || image.target() != self.target() {
            return Err(Error::WrongImage);
        }
        let mut metadata = Metadata::default();
        let mut diagnostics = 0;
        // SAFETY: provider-owned immutable single-allocation CPU slice; packed
        // CSS ABI and checked native extents, exact output layout, no device IO.
        let status = unsafe {
            stela_intel_guc_parse(
                self.facts.platform,
                image.bytes().as_ptr(),
                image.bytes().len(),
                &mut metadata,
                &mut diagnostics,
            )
        };
        if status != 0 {
            return Err(Error::Parse {
                status,
                diagnostics: Diagnostics(diagnostics),
            });
        }
        Ok(GucImage {
            _device: self.device,
            image,
            identity: self.identity,
            facts: self.facts,
            wanted: self.wanted(),
            metadata,
        })
    }
}

/// Format-checked host image with original provenance and borrowed lifetimes.
/// It is not authenticated, GGTT-pinned, loadable or running firmware.
pub struct GucImage<'device, 'provider> {
    _device: &'device Device,
    image: Image<'provider>,
    identity: PciIdentity,
    facts: Facts,
    wanted: Version,
    metadata: Metadata,
}
impl<'provider> GucImage<'_, 'provider> {
    pub fn image(&self) -> Image<'provider> {
        self.image
    }
    pub fn identity(&self) -> PciIdentity {
        self.identity
    }
    pub fn facts(&self) -> Facts {
        self.facts
    }
    pub fn wanted(&self) -> Version {
        self.wanted
    }
    pub fn metadata(&self) -> Metadata {
        self.metadata
    }
}

/// Original default catalog/GT-role disposition, never a load status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HucDisposition {
    Selected,
    Absent,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct HucMetadata {
    pub release: Version,
    pub ucode_bytes: u32,
    pub rsa_bytes: u32,
    pub upload_bytes: u32,
    pub css_offset: u32,
    format: u32,
    pub diagnostics: Diagnostics,
}
impl HucMetadata {
    pub fn has_gsc_headers(self) -> bool {
        self.format == 2
    }
}
#[repr(C)]
struct HucSelection {
    disposition: u32,
    name: [u8; 64],
    wanted: Version,
    full_version: u32,
}
const _: () = assert!(core::mem::size_of::<HucSelection>() == 84);
const _: () = assert!(core::mem::offset_of!(HucSelection, wanted) == 68);
const _: () = assert!(core::mem::size_of::<HucMetadata>() == 36);
const _: () = assert!(core::mem::offset_of!(HucMetadata, css_offset) == 24);
const _: () = assert!(core::mem::offset_of!(HucMetadata, diagnostics) == 32);
unsafe extern "C" {
    fn stela_intel_huc_select_default(
        platform: u32,
        graphics_verx100: u32,
        media_gt: bool,
        output: &mut HucSelection,
    ) -> i32;
    fn stela_intel_huc_parse(
        platform: u32,
        graphics_verx100: u32,
        media_gt: bool,
        bytes: *const u8,
        size: usize,
        output: &mut HucMetadata,
        diagnostics: &mut u32,
    ) -> i32;
}

/// Root-main-GT default. Missing role/catalog never performs a
/// Provider lookup, while failure of a selected image remains a real error.
/// Every request borrows the same live Device; no copied identity is a device.
pub struct HucRequest<'device> {
    device: &'device Device,
    identity: PciIdentity,
    facts: Facts,
    selection: HucSelection,
    disposition: HucDisposition,
    name_bytes: usize,
    hardware: Label<16>,
    revision: Label<96>,
}
impl<'device> HucRequest<'device> {
    pub(super) fn from_native(
        device: &'device Device,
        identity: PciIdentity,
        facts: Facts,
    ) -> Result<Self, Error> {
        if identity.vendor != 0x8086 || identity.virtual_function || facts.graphics_verx100 == 0 {
            return Err(Error::InvalidNativeIdentity);
        }
        let mut selection = HucSelection {
            disposition: 0,
            name: [0; 64],
            wanted: Version::default(),
            full_version: 0,
        };
        // SAFETY: device facts and exact private C scalar output layout.
        let status = unsafe {
            stela_intel_huc_select_default(
                facts.platform,
                facts.graphics_verx100,
                false,
                &mut selection,
            )
        };
        if status != 0 {
            return Err(Error::Selection(status));
        }
        let disposition = match selection.disposition {
            1 => HucDisposition::Selected,
            2 => HucDisposition::Absent,
            _ => return Err(Error::InvalidNativeIdentity),
        };
        let name_bytes = if disposition == HucDisposition::Selected {
            let n = selection
                .name
                .iter()
                .position(|&v| v == 0)
                .filter(|&n| n != 0)
                .ok_or(Error::InvalidCatalogName)?;
            core::str::from_utf8(&selection.name[..n]).map_err(|_| Error::InvalidCatalogName)?;
            n
        } else {
            0
        };
        let (hardware, revision) = identity_labels(identity, facts)?;
        Ok(Self {
            device,
            identity,
            facts,
            selection,
            disposition,
            name_bytes,
            hardware,
            revision,
        })
    }
    pub fn disposition(&self) -> HucDisposition {
        self.disposition
    }
    pub fn name(&self) -> Option<&str> {
        (self.disposition == HucDisposition::Selected).then(|| {
            // SAFETY: constructor validated the immutable private native copy.
            unsafe { core::str::from_utf8_unchecked(&self.selection.name[..self.name_bytes]) }
        })
    }
    pub fn wanted(&self) -> Option<Version> {
        self.name().map(|_| self.selection.wanted)
    }
    pub fn full_version_required(&self) -> bool {
        self.selection.full_version != 0
    }
    pub fn target(&self) -> Target<'_> {
        Target {
            driver: "intel-xe-huc",
            hardware: self.hardware.as_str(),
            revision: self.revision.as_str(),
            board: None,
        }
    }
    pub fn requirement(&self) -> Result<Requirement<'_>, Error> {
        Ok(Requirement {
            name: self.name().ok_or(Error::HucAbsent(self.disposition))?,
            target: self.target(),
            minimum_bytes: CSS_HEADER_BYTES,
        })
    }
    pub fn load<'provider>(
        &self,
        provider: &'provider dyn Provider,
    ) -> Result<HucImage<'device, 'provider>, Error> {
        let requirement = self.requirement()?;
        let image = provider.load(requirement).map_err(Error::Provider)?;
        if image.name() != requirement.name || image.target() != requirement.target {
            return Err(Error::WrongImage);
        }
        let mut metadata = HucMetadata::default();
        let mut diagnostics = 0;
        // SAFETY: original immutable provider CPU span; checked packed parser
        // and exact scalar output. No MMIO, BO status or device DMA is accessed.
        let status = unsafe {
            stela_intel_huc_parse(
                self.facts.platform,
                self.facts.graphics_verx100,
                false,
                image.bytes().as_ptr(),
                image.bytes().len(),
                &mut metadata,
                &mut diagnostics,
            )
        };
        if status != 0 {
            return Err(Error::Parse {
                status,
                diagnostics: Diagnostics(diagnostics),
            });
        }
        Ok(HucImage {
            _device: self.device,
            image,
            identity: self.identity,
            facts: self.facts,
            wanted: self.selection.wanted,
            metadata,
        })
    }
}

/// Format-checked host HuC image keeping canonical provenance and the same
/// Device/provider borrows. This is neither cryptographic authentication nor
/// AVAILABLE/LOADABLE, BO/GGTT storage, DMA completion or WOPCM admission.
/// A later Device-owned bootstrap can keep the independent Image borrow
/// (like GuC preparation) before consuming mutable device ownership; no lifetime
/// erasure or replacement physical/native identity is needed.
pub struct HucImage<'device, 'provider> {
    _device: &'device Device,
    image: Image<'provider>,
    identity: PciIdentity,
    facts: Facts,
    wanted: Version,
    metadata: HucMetadata,
}
impl<'provider> HucImage<'_, 'provider> {
    pub fn image(&self) -> Image<'provider> {
        self.image
    }
    pub fn identity(&self) -> PciIdentity {
        self.identity
    }
    pub fn facts(&self) -> Facts {
        self.facts
    }
    pub fn wanted(&self) -> Version {
        self.wanted
    }
    pub fn metadata(&self) -> HucMetadata {
        self.metadata
    }
}
