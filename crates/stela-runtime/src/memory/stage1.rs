//! AArch64 EL1 stage-1 translation by reading descriptors from physical memory.
//!
//! Supports lower and upper 47/48-bit VA ranges, 4 KiB and 16 KiB granules, up to
//! 48-bit PA, and little-endian Normal write-back tables. No EL2/EL3, stage 2,
//! permission indirection or overlays; callers decline those configurations.
//! The contiguous hint is treated as zero, as the architecture permits. Every
//! walk reads the descriptors afresh; there is no TLB. Follows the Arm
//! pseudocode `AArch64.S1Walk`, `S1CheckPermissions` and related functions.

mod config;
mod disabled;
mod walk;

pub use config::{
    AsidBits, Config, Controls, CpuProfile, Granule, GranuleSupport, Mode, PaBits, RegionConfig,
    TableConfig, VaRegion,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Fetch,
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionLevel {
    El0,
    El1,
}

/// Ordinary access intent. Unprivileged LDTR/STTR and UAO need an explicit
/// instruction-owner adapter; they must not silently become ordinary accesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    pub kind: AccessKind,
    pub exception_level: ExceptionLevel,
    pub raw_virtual_address: u64,
    pub source_pc: u64,
    pub pan: bool,
    pub uao: bool,
    /// Actual source access's natural alignment, computed by its instruction
    /// owner. This is not guessed from a flattened aggregate transfer width.
    pub aligned: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysicalReadError {
    /// A synchronous, non-parity physical external abort on a descriptor read.
    /// RAS, parity errors, and asynchronous delivery need a separate adapter.
    ExternalAbort { external_abort_type: bool },
    /// Host backing, platform, or synchronization limitations are not aborts.
    Platform(&'static str),
}

/// Authoritative physical read boundary, not a flattened virtual table view.
/// Implementations perform one aligned little-endian 64-bit read through their
/// physical backing owner, including its synchronization and lifetime checks.
pub trait PhysicalMemory {
    fn read_descriptor(&self, physical_address: u64) -> Result<u64, PhysicalReadError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    Control(&'static str),
    Access(&'static str),
    Descriptor { level: u8, feature: &'static str },
    PhysicalPlatform(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    AddressSize,
    Translation,
    AccessFlag,
    Permission,
    ExternalAbort,
}

/// The authoritative CPU/exception owner derives ESR/FAR from this provenance.
/// Descriptor PA is diagnostic; FAR remains the original access's raw VA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault {
    pub kind: FaultKind,
    pub level: u8,
    pub access: Access,
    pub virtual_address_valid: bool,
    /// Internal provenance, never the architectural stage-2 `s2fs1walk` bit.
    pub during_walk: bool,
    pub descriptor_address: Option<u64>,
    /// Physical memory's EA classification, only for synchronous external abort.
    pub external_abort_type: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslationError {
    Fault(Fault),
    Unsupported(Unsupported),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shareability {
    NonShareable,
    Outer,
    Inner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    NormalWriteBackReadWriteAllocate,
    NormalWriteThroughReadAllocate,
    NormalNonCacheable,
    DeviceNgnrne,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeOrigin {
    Walk,
    MmuDisabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attributes {
    pub memory_type: MemoryType,
    pub origin: AttributeOrigin,
    /// A reached leaf's MAIR byte; MMU-off attributes are not MAIR-selected.
    pub mair: Option<u8>,
    pub tagged: bool,
    pub xs: bool,
    pub shareability: Shareability,
    pub not_global: bool,
    /// The instruction/fetch owner must apply the selected CPU's BTI behavior.
    pub guarded_page: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permissions {
    pub el0_read: bool,
    pub el0_write: bool,
    pub el0_execute: bool,
    pub el1_read: bool,
    pub el1_write: bool,
    pub el1_execute: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Translation {
    access: Access,
    physical_address: u64,
    /// Remaining bytes in this leaf or flat output, before translation is needed.
    contiguous_bytes: u64,
    attributes: Attributes,
    /// Page permission metadata exists only after a genuine table walk.
    permissions: Option<Permissions>,
    walk: Option<WalkMetadata>,
}

impl Translation {
    pub const fn access(self) -> Access {
        self.access
    }
    pub const fn physical_address(self) -> u64 {
        self.physical_address
    }
    pub const fn contiguous_bytes(self) -> u64 {
        self.contiguous_bytes
    }
    pub const fn attributes(self) -> Attributes {
        self.attributes
    }
    pub const fn permissions(self) -> Option<Permissions> {
        self.permissions
    }
    pub const fn walk(self) -> Option<WalkMetadata> {
        self.walk
    }
}

/// Diagnostic walk provenance; never synthesized for an MMU-disabled output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalkMetadata {
    pub region: VaRegion,
    pub level: u8,
    pub descriptor_address: u64,
    pub descriptor: u64,
    pub asid: u16,
}

pub fn translate(
    config: &Config,
    memory: &(impl PhysicalMemory + ?Sized),
    access: Access,
) -> Result<Translation, TranslationError> {
    walk::translate(config, memory, access)
}

#[cfg(test)]
mod tests;
