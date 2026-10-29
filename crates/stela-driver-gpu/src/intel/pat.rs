//! Original direct XeLP PAT writes, bound to a live Device epoch.
use super::activation::Device;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct NativeResult {
    pub writes: u32,
    pub n_entries: u32,
    pub cache_none: u16,
    pub cache_wt: u16,
    pub cache_wb: u16,
    pub cache_none_compression: u16,
    pub cache_wb_compression: u16,
    pub reserved: u16,
    pub entries: [u32; 4],
}
const _: () = assert!(core::mem::size_of::<NativeResult>() == 36);
const _: () = assert!(core::mem::offset_of!(NativeResult, entries) == 20);
/// Original issued sequence and cache policy. The borrow keeps the real
/// epoch; this is not an installed/ACK/READY, PTE, DMA or reset-survival token.
/// Drop performs no implicit rollback, sleep or cleanup. Subsequent bootstrap
/// must use this same Device, not a copied numeric index or success boolean.
pub struct Programming<'device> {
    _device: &'device mut Device,
    result: NativeResult,
}
impl<'device> Programming<'device> {
    pub(super) fn from_native(device: &'device mut Device, result: NativeResult) -> Self {
        Self {
            _device: device,
            result,
        }
    }
    pub fn writes_issued(&self) -> u32 {
        self.result.writes
    }
    pub fn entries(&self) -> &[u32; 4] {
        &self.result.entries
    }
    pub fn cache_none(&self) -> u16 {
        self.result.cache_none
    }
    pub fn cache_wt(&self) -> u16 {
        self.result.cache_wt
    }
    pub fn cache_wb(&self) -> u16 {
        self.result.cache_wb
    }
}
