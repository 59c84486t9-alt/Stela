//! PTD publication geometry shared by the direct-memory and DCS frontends.
use {
    crate::platform::apple::ptd::transport::IRQ_STATUS,
    crate::platform::apple::ptd::transport::status, stela_soc_data::ptd::PTD_BYTES,
    stela_soc_data::ptd::UPDATE_OFFSET,
};

/// Placement and implemented capacity of a prepared publication bank.
/// Physical alias capacity can exceed the entries implemented by its backend.
pub(super) struct Layout {
    pub physical: u64,
    pub updates: (u64, u64),
    pub device_offset: u64,
    pub entries: usize,
}

impl Layout {
    pub fn binding(&self) -> (u64, u64, u64) {
        (self.physical, PTD_BYTES, self.device_offset)
    }

    pub fn display_view(&self, physical: u64, bytes: u64) -> Result<(u64, u64, u64), &'static str> {
        let end = physical
            .checked_add(bytes)
            .ok_or("display PTD view overflows")?;
        let bank_end = self
            .physical
            .checked_add(PTD_BYTES)
            .ok_or("prepared PTD bank overflows")?;
        if physical != self.updates.0 || bytes < self.updates.1 || end > bank_end {
            return Err("display PTD view must cover the complete update alias within its bank");
        }
        let offset = self
            .device_offset
            .checked_add(UPDATE_OFFSET)
            .ok_or("PTD device offset overflows")?;
        Ok((physical, bytes, offset))
    }

    pub fn entry(&self, offset: u64, bytes: u8) -> Option<u32> {
        let offset = offset.checked_sub(self.device_offset)?;
        (bytes == 8 && offset.is_multiple_of(16))
            .then_some(offset / 16)
            .filter(|&entry| entry < self.entries as u64)
            .and_then(|entry| u32::try_from(entry).ok())
    }

    pub fn status_pair(&self, offset: u64, bytes: u8) -> Option<(u64, status::Width)> {
        let offset = offset.checked_sub(self.device_offset)?;
        let width = match bytes {
            4 => status::Width::Double,
            8 => status::Width::Quad,
            _ => return None,
        };
        let words = self.entries.div_ceil(32) as u64;
        let end = IRQ_STATUS.checked_add(words.checked_mul(4)?)?;
        (offset >= IRQ_STATUS
            && offset.checked_add(width.bytes())? <= end
            && offset.is_multiple_of(width.bytes()))
        .then_some((offset, width))
    }

    pub fn supports_pair(&self, offset: u64, bytes: u8) -> bool {
        self.entry(offset, bytes).is_some() || self.status_pair(offset, bytes).is_some()
    }
}
