//! Owned read-only Xe PF GSM probe. No GGTT/PAT/BO initialization or PTE writes.
use super::activation::{Device, Error, Facts};
use crate::bus::mmio::owned::{Mapping, MappingView};

/// Original immutable scalar geometry. It is not a mapping or allocation token.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct Geometry {
    pub gsm_offset: u64,
    pub gsm_bytes: u64,
    pub ggtt_start: u64,
    pub ggtt_bytes: u64,
}
const _: () = assert!(core::mem::size_of::<Geometry>() == 32);
const _: () = assert!(core::mem::offset_of!(Geometry, ggtt_start) == 16);
unsafe extern "C" {
    pub(super) fn stela_intel_gsm_config(graphics_verx100: u32, offset: &mut u16) -> i32;
    fn stela_intel_gsm_geometry(
        platform: u32,
        graphics_verx100: u32,
        discrete: bool,
        actual_bar_bytes: u64,
        config_present: bool,
        gmch: u16,
        output: &mut Geometry,
    ) -> i32;
    fn stela_intel_gsm_pte_offset(geometry: &Geometry, address: u64, offset: &mut usize) -> i32;
}
impl Geometry {
    pub(super) fn from_facts(
        facts: Facts,
        bar_bytes: u64,
        present: bool,
        gmch: u16,
    ) -> Result<Self, Error> {
        let mut result = Self::default();
        // SAFETY: CPU-only original policy and complete scalar ABI; actual live
        // device facts, whole BAR extent and same-function configuration input.
        let status = unsafe {
            stela_intel_gsm_geometry(
                facts.platform,
                facts.graphics_verx100,
                facts.discrete != 0,
                bar_bytes,
                present,
                gmch,
                &mut result,
            )
        };
        if status != 0 {
            return Err(Error::Native(status));
        }
        Ok(result)
    }
}
/// Exclusive live Device borrow retains forcewake/reset/power throughout reads
/// and canonical teardown. No raw pointer escapes. Explicit successful retire
/// releases this lease before the caller can sleep/finish the Device. Drop or
/// uncertain teardown permanently poisons that epoch and quarantines ownership;
/// retry can retire the SAME mapping but can never reopen device operations.
pub struct Probe<'device> {
    device: &'device mut Device,
    geometry: Geometry,
    mapping: Option<Mapping>,
    view: Option<MappingView>,
    closing: bool,
}
impl<'device> Probe<'device> {
    pub(super) fn from_native(
        device: &'device mut Device,
        geometry: Geometry,
        mapping: Mapping,
        view: MappingView,
    ) -> Self {
        Self {
            device,
            geometry,
            mapping: Some(mapping),
            view: Some(view),
            closing: false,
        }
    }
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }
    /// Raw original readq result; does not validate PTE contents or readiness.
    /// Address is an original GGTT page address, never an IOVA or CPU pointer.
    pub fn read_pte(&self, address: u64) -> Result<u64, Error> {
        if self.closing {
            return Err(Error::Closing);
        }
        let mut offset = 0;
        // SAFETY: immutable native-produced geometry, checked original index and
        // complete eight-byte span before pointer formation or owner access.
        let status = unsafe { stela_intel_gsm_pte_offset(&self.geometry, address, &mut offset) };
        if status != 0 {
            return Err(Error::Native(status));
        }
        self.device
            .gsm_read64(self.view.as_ref().ok_or(Error::Closing)?, offset)
    }
    pub fn retire(&mut self) -> Result<(), Error> {
        self.device.gsm_check_context()?; // pure context check, including retries.
        let mapping = self.mapping.as_mut().ok_or(Error::Closing)?;
        self.closing = true;
        drop(self.view.take());
        // SAFETY: no escaped pointers or firmware/DMA/IRQ users; exclusive actual
        // owner remains awake/pinned, no outstanding CPU accesses after &mut.
        if let Err(error) = unsafe { mapping.retire() } {
            self.device.gsm_poison();
            return Err(error.into());
        }
        self.mapping = None;
        Ok(())
    }
}
impl Drop for Probe<'_> {
    fn drop(&mut self) {
        if self.mapping.is_some() {
            self.device.gsm_poison();
            drop(self.view.take());
            drop(self.mapping.take()); // existing canonical quarantine.
        }
    }
}
