//! NVMe 1.4 section 4.3 PRPs. PRP1 may start inside a memory page; PRP2
//! names the second page for a two-page transfer, otherwise a PRP list.
//! A list pointer needs only qword alignment, so the first list may start
//! inside its page (ANS2's CoastGuard TCBs place lists at 2 KiB offsets);
//! a list page ends at its page boundary, where its last entry chains to
//! the next, page-aligned list page while more than one data page remains.
//! Every list entry consumes data or chains to a whole list page, so the
//! transfer limit bounds traversal even if a guest supplies a cyclic list.
use crate::Result;
use alloc::vec::Vec;
use stela_contracts::Refusal;
use stela_contracts::refuse;
use {stela_contracts::dma::DmaError, stela_contracts::dma::Port};

pub(super) const MAX_TRANSFER: usize = 1024 * 1024;

pub(super) fn dma_error(error: DmaError) -> Refusal {
    match error {
        DmaError::Unsupported(reason) => reason,
        DmaError::Fault(code) => refuse!("ANS DMA translation fault", code),
        DmaError::Memory => refuse!("ANS DMA target is not guest RAM"),
    }
}

/// [`dma_error`] for a PRP access of `bytes` at `address`: the guest's list
/// names these addresses, which no register or command shows.
fn dma_error_at(address: u64, bytes: usize) -> impl FnOnce(DmaError) -> Refusal {
    move |error| match error {
        DmaError::Memory => refuse!("ANS DMA target is not guest RAM", address, bytes),
        error => dma_error(error)
            .with("address", &address)
            .with("bytes", &bytes),
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
    ) -> Result<Self> {
        if bytes == 0 || bytes > MAX_TRANSFER || !matches!(page, 4096 | 16384) {
            return Err(refuse!("ANS PRP transfer size or page size is not modeled"));
        }
        if first == 0 || !first.is_multiple_of(4) {
            return Err(refuse!("ANS PRP1 is null or not dword-aligned"));
        }
        let mut ranges = Vec::new();
        let first_bytes = bytes.min((page - first % page) as usize);
        first
            .checked_add(first_bytes as u64 - 1)
            .ok_or(refuse!("ANS PRP1 wraps"))?;
        ranges.push((first, first_bytes));
        let mut remaining = bytes - first_bytes;
        if remaining == 0 {
            return Ok(Self(ranges));
        }
        if remaining <= page as usize {
            if second == 0 || !second.is_multiple_of(page) {
                return Err(refuse!("ANS PRP2 is null or not page-aligned"));
            }
            second
                .checked_add(remaining as u64 - 1)
                .ok_or(refuse!("ANS PRP2 wraps"))?;
            ranges.push((second, remaining));
            return Ok(Self(ranges));
        }
        if second == 0 || !second.is_multiple_of(8) {
            return Err(refuse!("ANS PRP list pointer is null or not qword-aligned"));
        }
        let mut entry = second;
        while remaining != 0 {
            let mut pointer = [0; 8];
            port.read(entry, &mut pointer)
                .map_err(dma_error_at(entry, pointer.len()))?;
            let pointer = u64::from_le_bytes(pointer);
            if pointer == 0 || !pointer.is_multiple_of(page) {
                return Err(refuse!("ANS PRP list contains a null or unaligned page"));
            }
            let last_in_page = (entry + 8).is_multiple_of(page);
            if last_in_page && remaining > page as usize {
                entry = pointer;
                continue;
            }
            let chunk = remaining.min(page as usize);
            pointer
                .checked_add(chunk as u64 - 1)
                .ok_or(refuse!("ANS PRP data address wraps"))?;
            ranges.push((pointer, chunk));
            remaining -= chunk;
            entry = entry
                .checked_add(8)
                .ok_or(refuse!("ANS PRP list address wraps"))?;
        }
        Ok(Self(ranges))
    }

    pub fn read(&self, port: &mut Port<'_, '_>, buffer: &mut [u8]) -> Result<()> {
        let mut at = 0;
        for &(address, bytes) in &self.0 {
            port.read(address, &mut buffer[at..at + bytes])
                .map_err(dma_error_at(address, bytes))?;
            at += bytes;
        }
        Ok(())
    }

    pub fn write(&self, port: &mut Port<'_, '_>, data: &[u8]) -> Result<()> {
        let mut at = 0;
        for &(address, bytes) in &self.0 {
            port.write(address, &data[at..at + bytes])
                .map_err(dma_error_at(address, bytes))?;
            at += bytes;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use {
        stela_contracts::bus::Access, stela_contracts::dma::Physical,
        stela_contracts::dma::test_support::Ram, stela_contracts::interrupt::InterruptLatch,
    };

    #[test]
    fn prps_scatter_across_pages_at_physical_addresses() {
        let mut ram = Ram::new(0x8000_0000, 0x10000);
        let base = ram.base;
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut Physical,
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

    #[test]
    fn a_prp_list_may_start_inside_its_page_and_chains_at_the_page_end() {
        let mut ram = Ram::new(0x8000_0000, 0x20000);
        let base = ram.base;
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut Physical,
            stream: 0,
            memory: &mut ram,
            access: &mut access,
        };
        // A list at offset 0x800, as ANS2's BFH download of 21 pages has:
        // PRP1 is the first page and 20 list entries fit before 0x1000.
        let list = base + 0x800;
        for index in 0..20u64 {
            let page = base + 0x2000 + index * 0x1000 % 0x8000;
            port.write(list + index * 8, &page.to_le_bytes()).unwrap();
        }
        let prps = Prps::new(&mut port, base + 0x1000, list, 21 * 4096, 4096).unwrap();
        assert_eq!(prps.0.len(), 21);
        assert_eq!(prps.0[1], (base + 0x2000, 4096));
        // A list two entries from its page end: one data entry, then the
        // last slot chains to a page-aligned list page holding the rest.
        let near_end = base + 0xa000 - 16;
        port.write(near_end, &(base + 0xc000).to_le_bytes())
            .unwrap();
        port.write(near_end + 8, &(base + 0xb000).to_le_bytes())
            .unwrap();
        port.write(base + 0xb000, &(base + 0xd000).to_le_bytes())
            .unwrap();
        port.write(base + 0xb008, &(base + 0xe000).to_le_bytes())
            .unwrap();
        let prps = Prps::new(&mut port, base + 0x1000, near_end, 4 * 4096, 4096).unwrap();
        let pages: Vec<u64> = prps.0.iter().map(|&(address, _)| address).collect();
        assert_eq!(
            pages,
            [base + 0x1000, base + 0xc000, base + 0xd000, base + 0xe000]
        );
        // A list pointer must still be qword-aligned and nonzero.
        assert!(Prps::new(&mut port, base + 0x1000, list + 4, 3 * 4096, 4096).is_err());
        assert!(Prps::new(&mut port, base + 0x1000, 0, 3 * 4096, 4096).is_err());
    }
}
