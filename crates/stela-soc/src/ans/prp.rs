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
const ENTRY_BYTES: usize = size_of::<u64>();
const LIST_READ_ENTRIES: usize = 16;

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

/// Direct transfers keep their ranges inline. Indirect transfers reserve
/// space for every data page the validated byte count can reach.
pub(super) enum Prps {
    One([(u64, usize); 1]),
    Two([(u64, usize); 2]),
    List(Vec<(u64, usize)>),
}

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
        let first_bytes = bytes.min((page - first % page) as usize);
        first
            .checked_add(first_bytes as u64 - 1)
            .ok_or(refuse!("ANS PRP1 wraps"))?;
        let first = (first, first_bytes);
        let mut remaining = bytes - first_bytes;
        if remaining == 0 {
            return Ok(Self::One([first]));
        }
        if remaining <= page as usize {
            if second == 0 || !second.is_multiple_of(page) {
                return Err(refuse!("ANS PRP2 is null or not page-aligned"));
            }
            second
                .checked_add(remaining as u64 - 1)
                .ok_or(refuse!("ANS PRP2 wraps"))?;
            return Ok(Self::Two([first, (second, remaining)]));
        }
        if second == 0 || !second.is_multiple_of(8) {
            return Err(refuse!("ANS PRP list pointer is null or not qword-aligned"));
        }
        let mut ranges = Vec::with_capacity(1 + remaining.div_ceil(page as usize));
        ranges.push(first);
        let mut entry = second;
        let mut list = [0; ENTRY_BYTES * LIST_READ_ENTRIES];
        let mut read_entries = LIST_READ_ENTRIES;
        while remaining != 0 {
            let page_entries = (page - entry % page) as usize / ENTRY_BYTES;
            let entries = remaining
                .div_ceil(page as usize)
                .min(page_entries)
                .min(read_entries);
            let bytes = entries * ENTRY_BYTES;
            let loaded = port.read_progress(entry, &mut list[..bytes]);
            if entries > 1
                && matches!(&loaded, Err(fault) if fault.completed == 0 && fault.error == DmaError::Memory)
            {
                // Some RAM owners reject a span before reading its first
                // byte. Find the failing entry without replaying any prefix.
                read_entries = 1;
                continue;
            }
            // The first malformed entry in the readable prefix still takes
            // precedence over a fault on a later entry in this fetch.
            let readable = loaded
                .as_ref()
                .err()
                .map_or(bytes, |fault| fault.completed.min(bytes - 1));
            for (index, pointer) in list[..readable]
                .as_chunks::<ENTRY_BYTES>()
                .0
                .iter()
                .enumerate()
            {
                let pointer = u64::from_le_bytes(*pointer);
                if pointer == 0 || !pointer.is_multiple_of(page) {
                    return Err(refuse!("ANS PRP list contains a null or unaligned page"));
                }
                if index + 1 == page_entries && remaining > page as usize {
                    entry = pointer;
                    break;
                }
                let chunk = remaining.min(page as usize);
                pointer
                    .checked_add(chunk as u64 - 1)
                    .ok_or(refuse!("ANS PRP data address wraps"))?;
                ranges.push((pointer, chunk));
                remaining -= chunk;
                entry = entry
                    .checked_add(ENTRY_BYTES as u64)
                    .ok_or(refuse!("ANS PRP list address wraps"))?;
            }
            loaded.map_err(|fault| dma_error_at(entry, ENTRY_BYTES)(fault.error))?;
        }
        Ok(Self::List(ranges))
    }

    fn ranges(&self) -> &[(u64, usize)] {
        match self {
            Self::One(ranges) => ranges,
            Self::Two(ranges) => ranges,
            Self::List(ranges) => ranges,
        }
    }

    pub fn read(&self, port: &mut Port<'_, '_>, buffer: &mut [u8]) -> Result<()> {
        let mut at = 0;
        for &(address, bytes) in self.ranges() {
            port.read(address, &mut buffer[at..at + bytes])
                .map_err(dma_error_at(address, bytes))?;
            at += bytes;
        }
        Ok(())
    }

    pub fn write(&self, port: &mut Port<'_, '_>, data: &[u8]) -> Result<()> {
        let mut at = 0;
        for &(address, bytes) in self.ranges() {
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
        stela_contracts::bus::Access,
        stela_contracts::dma::test_support::Ram,
        stela_contracts::dma::{Memory, Physical, TransferFault},
        stela_contracts::interrupt::InterruptLatch,
        stela_contracts::refusal::Value,
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
    fn direct_prps_keep_an_offset_first_page_and_short_second_page() {
        let mut ram = Ram::new(0x8000_0000, 0x8000);
        let base = ram.base;
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut Physical,
            stream: 0,
            memory: &mut ram,
            access: &mut access,
        };
        let first = base + 0xff0;
        let prps = Prps::new(&mut port, first, 0, 16, 4096).unwrap();
        assert!(matches!(prps, Prps::One([(address, 16)]) if address == first));
        let second = base + 0x3000;
        let prps = Prps::new(&mut port, first, second, 24, 4096).unwrap();
        assert!(matches!(prps, Prps::Two([(a, 16), (b, 8)]) if (a, b) == (first, second)));
        let data: [u8; 24] = core::array::from_fn(|index| index as u8);
        prps.write(&mut port, &data).unwrap();
        let mut read = [0; 24];
        prps.read(&mut port, &mut read).unwrap();
        assert_eq!(read, data);
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
        assert_eq!(prps.ranges().len(), 21);
        assert_eq!(prps.ranges()[1], (base + 0x2000, 4096));
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
        let pages: Vec<u64> = prps.ranges().iter().map(|&(address, _)| address).collect();
        assert_eq!(
            pages,
            [base + 0x1000, base + 0xc000, base + 0xd000, base + 0xe000]
        );
        // A list pointer must still be qword-aligned and nonzero.
        assert!(Prps::new(&mut port, base + 0x1000, list + 4, 3 * 4096, 4096).is_err());
        assert!(Prps::new(&mut port, base + 0x1000, 0, 3 * 4096, 4096).is_err());
    }

    #[test]
    fn prp_list_validates_the_readable_prefix_before_reporting_a_later_fault() {
        struct ListPage {
            first: u64,
            partial: bool,
        }

        impl Memory for ListPage {
            fn read(&mut self, physical: u64, buffer: &mut [u8]) -> bool {
                self.read_progress(physical, buffer).is_ok()
            }

            fn write(&mut self, _: u64, _: &[u8]) -> bool {
                unreachable!()
            }

            fn read_progress(
                &mut self,
                physical: u64,
                buffer: &mut [u8],
            ) -> core::result::Result<(), TransferFault> {
                const LIST: u64 = 0x8000_1000;
                if physical == LIST && (buffer.len() == ENTRY_BYTES || self.partial) {
                    buffer[..ENTRY_BYTES].copy_from_slice(&self.first.to_le_bytes());
                    if buffer.len() == ENTRY_BYTES {
                        return Ok(());
                    }
                    return Err(TransferFault {
                        error: DmaError::Memory,
                        completed: ENTRY_BYTES,
                    });
                }
                Err(TransferFault {
                    error: DmaError::Memory,
                    completed: 0,
                })
            }
        }

        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        for partial in [false, true] {
            for (first, what) in [
                (0, "ANS PRP list contains a null or unaligned page"),
                (0x8000_4000, "ANS DMA target is not guest RAM"),
            ] {
                let mut page = ListPage { first, partial };
                let mut port = Port {
                    iommu: &mut Physical,
                    stream: 0,
                    memory: &mut page,
                    access: &mut access,
                };
                let error = Prps::new(&mut port, 0x8000_2000, 0x8000_1000, 3 * 4096, 4096)
                    .err()
                    .expect("the PRP list faults");
                assert_eq!(error.what(), what);
                if first != 0 {
                    assert_eq!(error.value("address"), Some(&Value::Hex(0x8000_1008)));
                    assert_eq!(error.value("bytes"), Some(&Value::Count(8)));
                }
            }
        }
    }
}
