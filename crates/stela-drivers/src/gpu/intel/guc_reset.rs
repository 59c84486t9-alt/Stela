//! Observed original GuC-only hardware reset, retaining the actual Device epoch.
use super::activation::Device;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct NativeResult {
    pub writes: u32,
    pub warnings: u32,
    pub gdrst: u32,
    pub guc_status: u32,
    pub ready_status: u32,
    pub sram_status: u32,
}
const _: () = assert!(core::mem::size_of::<NativeResult>() == 24);
const _: () = assert!(core::mem::offset_of!(NativeResult, guc_status) == 12);

/// The original GDRST clear and MIA-in-reset observations from this explicit
/// operation. The exclusive borrow retains the same canonical owner and wake.
/// This does not implement `xe_uc_sanitize_reset` or establish whole-device DMA
/// quiescence, CT/job drain, firmware authentication or GGTT readiness. Drop
/// performs no reset, rollback, sleep or implicit cleanup.
pub struct Handshake<'device> {
    _device: &'device mut Device,
    result: NativeResult,
}
impl<'device> Handshake<'device> {
    pub(super) fn from_native(device: &'device mut Device, result: NativeResult) -> Self {
        Self {
            _device: device,
            result,
        }
    }
    pub fn writes_issued(&self) -> u32 {
        self.result.writes
    }
    pub fn gdrst_observed(&self) -> u32 {
        self.result.gdrst
    }
    pub fn guc_status_observed(&self) -> u32 {
        self.result.guc_status
    }
}
