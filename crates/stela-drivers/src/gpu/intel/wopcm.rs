//! Original root-main-GT WOPCM partition/readback, not GuC upload/authentication.
use super::{activation, firmware};
use crate::firmware::Image;

pub mod storage;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct Layout {
    pub total_bytes: u32,
    pub guc_base: u32,
    pub guc_bytes: u32,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub(super) struct NativeResult {
    pub layout: Layout,
    pub diagnostics: u32,
    pub writes: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub firmware_diagnostics: u32,
}
const _: () = assert!(core::mem::size_of::<NativeResult>() == 32);
const _: () = assert!(core::mem::offset_of!(NativeResult, writes) == 16);
const _: () = assert!(core::mem::offset_of!(NativeResult, firmware_diagnostics) == 28);

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Device(activation::Error),
    Firmware(firmware::Error),
    Native {
        status: i32,
        diagnostics: u32,
        writes: u32,
        raw_offset: u32,
        raw_size: u32,
        firmware_diagnostics: u32,
    },
}
impl From<activation::Error> for Error {
    fn from(value: activation::Error) -> Self {
        Self::Device(value)
    }
}
impl From<firmware::Error> for Error {
    fn from(value: firmware::Error) -> Self {
        Self::Firmware(value)
    }
}
impl NativeResult {
    pub(super) fn error(self, status: i32) -> Error {
        Error::Native {
            status,
            diagnostics: self.diagnostics,
            writes: self.writes,
            raw_offset: self.raw_offset,
            raw_size: self.raw_size,
            firmware_diagnostics: self.firmware_diagnostics,
        }
    }
}

/// One original verified WOPCM partition in the actual retained native epoch.
/// Both real mutable device ownership and original provider Image stay borrowed.
/// Drop performs no sleep/reset/drain/unmap and never invents rollback of locks.
/// There is no READY, BO, GGTT, authentication, upload or submission capability.
/// A successor bootstrap stage must consume this same preparation/owner.
pub struct Preparation<'device, 'provider> {
    _device: &'device mut activation::Device,
    image: Image<'provider>,
    metadata: firmware::Metadata,
    identity: activation::PciIdentity,
    facts: activation::Facts,
    result: NativeResult,
}
impl<'device, 'provider> Preparation<'device, 'provider> {
    pub(super) fn from_native(
        device: &'device mut activation::Device,
        image: Image<'provider>,
        metadata: firmware::Metadata,
        identity: activation::PciIdentity,
        facts: activation::Facts,
        result: NativeResult,
    ) -> Self {
        Self {
            _device: device,
            image,
            metadata,
            identity,
            facts,
            result,
        }
    }
    pub fn image(&self) -> Image<'provider> {
        self.image
    }
    pub fn metadata(&self) -> firmware::Metadata {
        self.metadata
    }
    pub fn identity(&self) -> activation::PciIdentity {
        self.identity
    }
    pub fn facts(&self) -> activation::Facts {
        self.facts
    }
    pub fn layout(&self) -> Layout {
        self.result.layout
    }
    pub fn diagnostics(&self) -> u32 {
        self.result.diagnostics
    }
    pub fn writes(&self) -> u32 {
        self.result.writes
    }
    pub fn observed_registers(&self) -> (u32, u32) {
        (self.result.raw_offset, self.result.raw_size)
    }
}
