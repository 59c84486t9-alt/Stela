//! NVMe 1.4 section 4.3 PRPs. PRP1 may start inside a memory page; PRP2
//! names the second page for a two-page transfer, otherwise a PRP list.
//! The last entry of a full list page chains to the next list page. The
//! transfer limit bounds traversal even if a guest supplies a cyclic list.
use crate::platform::dma::{DmaError, Port};
use alloc::vec::Vec;

pub(super) const MAX_TRANSFER: usize = 1024 * 1024;

pub(super) fn dma_error(error: DmaError) -> &'static str {
    match error {
        DmaError::Unsupported(reason) => reason,
        DmaError::Fault(_) => "ANS DMA translation fault",
        DmaError::Memory => "ANS DMA target is not guest RAM",
    }
}

pub(super) struct Prps(Vec<(u64, usize)>);

impl Prps {
    pub fn new(
        port: &mut Port<'_, '_>,
        first: u64,
        second: u64,
        bytes: usize,
        page: u64,
    ) -> Result<Self, &'static str> {
        if bytes == 0 || bytes > MAX_TRANSFER || !matches!(page, 4096 | 16384) {
            return Err("ANS PRP transfer size or page size is not modeled");
        }
        if first == 0 || !first.is_multiple_of(4) {
            return Err("ANS PRP1 is null or not dword-aligned");
        }
        let mut ranges = Vec::new();
        let first_bytes = bytes.min((page - first % page) as usize);
        first
            .checked_add(first_bytes as u64 - 1)
            .ok_or("ANS PRP1 wraps")?;
        ranges.push((first, first_bytes));
        let mut remaining = bytes - first_bytes;
        if remaining == 0 {
            return Ok(Self(ranges));
        }
        if second == 0 || !second.is_multiple_of(page) {
            return Err("ANS PRP2 is null or not page-aligned");
        }
        if remaining <= page as usize {
            second
                .checked_add(remaining as u64 - 1)
                .ok_or("ANS PRP2 wraps")?;
            ranges.push((second, remaining));
            return Ok(Self(ranges));
        }
        let mut list = second;
        let mut index = 0;
        let entries = page / 8;
        while remaining != 0 {
            let at = list
                .checked_add(index * 8)
                .ok_or("ANS PRP list address wraps")?;
            let mut pointer = [0; 8];
            port.read(at, &mut pointer).map_err(dma_error)?;
            let pointer = u64::from_le_bytes(pointer);
            if pointer == 0 || !pointer.is_multiple_of(page) {
                return Err("ANS PRP list contains a null or unaligned page");
            }
            if index == entries - 1 && remaining > page as usize {
                list = pointer;
                index = 0;
                continue;
            }
            let chunk = remaining.min(page as usize);
            pointer
                .checked_add(chunk as u64 - 1)
                .ok_or("ANS PRP data address wraps")?;
            ranges.push((pointer, chunk));
            remaining -= chunk;
            index += 1;
        }
        Ok(Self(ranges))
    }

    pub fn read(&self, port: &mut Port<'_, '_>, buffer: &mut [u8]) -> Result<(), &'static str> {
        let mut at = 0;
        for &(address, bytes) in &self.0 {
            port.read(address, &mut buffer[at..at + bytes])
                .map_err(dma_error)?;
            at += bytes;
        }
        Ok(())
    }

    pub fn write(&self, port: &mut Port<'_, '_>, data: &[u8]) -> Result<(), &'static str> {
        let mut at = 0;
        for &(address, bytes) in &self.0 {
            port.write(address, &data[at..at + bytes])
                .map_err(dma_error)?;
            at += bytes;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        apple::{
            bus::{Access, MmioDevice, Width},
            interrupt::InterruptLatch,
            sart::Sart,
        },
        dma::tests::Ram,
    };

    #[test]
    fn prps_scatter_across_pages_and_sart_applies_to_lists_and_data() {
        let mut ram = Ram::new(0x8000_0000, 0x10000);
        let base = ram.base;
        let mut sart = Sart::default();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        for (offset, value) in [(0x40, base / 4096), (0x80, 16), (0, 0xff)] {
            sart.write(offset, Width::Word, value, &mut access).unwrap();
        }
        let mut port = Port {
            iommu: &mut sart,
            stream: 0,
            memory: &mut ram,
            access: &mut access,
        };
        port.write(base, &(base + 0x5000).to_le_bytes()).unwrap();
        port.write(base + 8, &(base + 0x7000).to_le_bytes())
            .unwrap();
        let prps = Prps::new(&mut port, base + 0x2ffc, base, 8192, 4096).unwrap();
        let data: Vec<_> = (0..8192).map(|i| (i % 251) as u8).collect();
        prps.write(&mut port, &data).unwrap();
        let mut read = alloc::vec![0;8192];
        prps.read(&mut port, &mut read).unwrap();
        assert_eq!(read, data);
        assert!(Prps::new(&mut port, base + 1, 0, 4, 4096).is_err());
        assert!(Prps::new(&mut port, base, base + 1, 8192, 4096).is_err());
        assert!(Prps::new(&mut port, base, base + 0x10000, 12288, 4096).is_err());
        assert!(Prps::new(&mut port, 0, 0, 4096, 4096).is_err());
    }
}
