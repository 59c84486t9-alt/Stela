//! The actual resource adapter over boot-core's firmware HPET decoder.
use stela_boot_core::hpet;
use stela_drivers::{bus::mmio::owned::PhysicalSpan, platform::work::WorkError};

/// Validated original table description; this wrapper grants no device access.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Descriptor(hpet::Descriptor);
impl Descriptor {
    pub(crate) fn from_sdt(table: &[u8]) -> Result<Self, WorkError> {
        hpet::Descriptor::from_sdt(table)
            .map(Self)
            .map_err(|_| WorkError::Unavailable)
    }
    pub(crate) fn registers(self) -> PhysicalSpan {
        // The core constructor checked nonzero page alignment and the complete
        // 1024-byte extent; PhysicalSpan has the same nonempty/overflow checks.
        PhysicalSpan::new(self.0.base(), hpet::REGISTERS_BYTES).expect("validated HPET extent")
    }
    pub(crate) fn table_sha256(self) -> [u8; 32] {
        self.0.table_sha256()
    }
    pub(crate) fn block_id(self) -> u32 {
        self.0.block_id()
    }
    pub(crate) fn number(self) -> u8 {
        self.0.number()
    }
    pub(super) fn geometry(self, id: u32, period_fs: u32) -> Result<hpet::Geometry, WorkError> {
        hpet::Geometry::qualify(self.0, id, period_fs).map_err(|_| WorkError::Unavailable)
    }
}
