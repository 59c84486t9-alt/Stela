//! The calling thread's address space for [`Devices::serve_call`]: virtual
//! addresses translated in the PE's current regime with EL0 permissions,
//! reaching RAM as device DMA does, outside the memory controllers' locks.
use super::{Controls, FETCH_PAGE, Host, RamTables, Translated, mmu};
use alloc::vec::Vec;
use stela_contracts::gate::{CallerFault, CallerMemory};

pub(super) struct CallerSpace<'a, H: Host> {
    pub host: &'a mut H,
    pub controls: Controls,
    pub requester: mmu::Requester,
    pub lock: mmu::MemoryLocks,
}

impl<H: Host> CallerSpace<'_, H> {
    /// The physical pieces of `bytes` at `address`, each within one page,
    /// once every one is accessible RAM.
    fn pieces(
        &mut self,
        address: u64,
        bytes: usize,
        access: mmu::Access,
    ) -> Result<Vec<(u64, usize)>, CallerFault> {
        let mut pieces = Vec::new();
        let mut done = 0;
        while done < bytes {
            let virtual_address = address
                .checked_add(done as u64)
                .ok_or(CallerFault::Denied { address })?;
            let length =
                ((FETCH_PAGE - (virtual_address & (FETCH_PAGE - 1))) as usize).min(bytes - done);
            let translation = match mmu::translate(
                &self.controls,
                virtual_address,
                access,
                self.requester,
                &mut RamTables(self.host),
            ) {
                Translated::Mapped(translation) => translation,
                Translated::Fault(_) => {
                    return Err(CallerFault::Denied {
                        address: virtual_address,
                    });
                }
                Translated::Unsupported(_) => {
                    return Err(CallerFault::Unsupported("the caller's translation"));
                }
            };
            let physical = translation.physical;
            let mut probe = [0];
            if !self.host.read_ram(physical, &mut probe)
                || !self.host.read_ram(physical + length as u64 - 1, &mut probe)
            {
                return Err(CallerFault::NotRam {
                    address: virtual_address,
                });
            }
            let last = physical + length as u64 - 1;
            if access == mmu::Access::Write
                && self
                    .lock
                    .into_iter()
                    .flatten()
                    .any(|(first, end)| physical <= end && first <= last)
            {
                return Err(CallerFault::Denied {
                    address: virtual_address,
                });
            }
            pieces.push((physical, length));
            done += length;
        }
        Ok(pieces)
    }
}

impl<H: Host> CallerMemory for CallerSpace<'_, H> {
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), CallerFault> {
        let mut offset = 0;
        for (physical, length) in self.pieces(address, buffer.len(), mmu::Access::Read)? {
            self.host
                .read_ram(physical, &mut buffer[offset..offset + length]);
            offset += length;
        }
        Ok(())
    }

    fn write(&mut self, address: u64, data: &[u8]) -> Result<(), CallerFault> {
        let mut offset = 0;
        for (physical, length) in self.pieces(address, data.len(), mmu::Access::Write)? {
            self.host
                .write_ram(physical, &data[offset..offset + length]);
            offset += length;
        }
        Ok(())
    }
}
