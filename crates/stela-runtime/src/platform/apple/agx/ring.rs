//! The shared-memory rings between the AGX kext and the GFX firmware, as the
//! 26A434 kext lays them out (docs/research/agx.md §2).
//!
//! Known (`AGXG14G`, kernel file offsets):
//! - Every ring has a 0x30-byte state block and 256 entries. The state holds
//!   the read index at +0x00, the "CFI" index at +0x10 and the write index at
//!   +0x20, each a 32-bit word on its own 16-byte line
//!   (`AGXAcceleratorRing<…>::get{Read,CFI,Write}Index` 0x1b41d78..0x1b42000,
//!   which panic on an index of 0x100 or more). The allocator sizes the state
//!   blocks 0x30 (`AGXFirmware::allocFirmwareData` 0x1b359f0, table at
//!   0x1b36530..0x1b36604).
//! - AP-to-firmware rings: the AP writes an entry at the write index and then
//!   advances it modulo 256; the ring is full when `write + 1 == read`
//!   (`AGXFirmware::submitDeviceControl` 0x1b32308). The firmware consumes by
//!   advancing the read index; `waitForDeviceControlCompletion` (0x1b2f794)
//!   waits until the read index reaches the write index.
//! - Entry sizes: a device-control entry is 0x40 bytes (the 0x4000-byte entry
//!   array, `getRingIndexForEntry` `>> 6`), a data-master (work) entry 0x18
//!   (0x1800-byte arrays) and a firmware event 0x48 (0x4800 bytes,
//!   `AGXFirmwareRingValidator::fetchNextEntry` 0x1b436ec).
//! - The firmware learns each AP-to-firmware ring from a 0x20-byte descriptor
//!   `AGXFirmware::initFirmwareData` (0x1b34214) writes into the ring directory:
//!   the firmware addresses of the read, CFI and write words, then the entry
//!   array's (vtable slots `getReadIndexFWPtr`, `getCFIIndexFWPtr`,
//!   `getWriteIndexFWPtr` and the ring's +0x20 field).
//!
//! The firmware side here reads descriptors and indices and retires entries;
//! what an entry means belongs to its consumer ([`super::firmware`]).

use super::uat;
use crate::platform::dma::{DmaError, Port};
use alloc::vec::Vec;

/// Entries in every ring.
pub const ENTRIES: u32 = 0x100;
/// Bytes of a ring's state block.
pub const STATE_BYTES: u64 = 0x30;
/// The read index's offset in the state block.
pub const READ: u64 = 0x00;
/// The CFI index's offset.
pub const CFI: u64 = 0x10;
/// The write index's offset.
pub const WRITE: u64 = 0x20;
/// Bytes of a ring descriptor in the ring directory.
pub const DESCRIPTOR_BYTES: usize = 0x20;

/// The firmware's view of shared memory: firmware virtual addresses reached
/// through the UAT. [`Port`] is the machine's; tests use flat memory.
pub trait Shared {
    fn read(&mut self, va: u64, buffer: &mut [u8]) -> Result<(), &'static str>;
    fn write(&mut self, va: u64, data: &[u8]) -> Result<(), &'static str>;

    fn read_u32(&mut self, va: u64) -> Result<u32, &'static str> {
        let mut word = [0; 4];
        self.read(va, &mut word)?;
        Ok(u32::from_le_bytes(word))
    }
    fn read_u64(&mut self, va: u64) -> Result<u64, &'static str> {
        let mut word = [0; 8];
        self.read(va, &mut word)?;
        Ok(u64::from_le_bytes(word))
    }

    /// A GPU-unit read in UAT `context`: the work the firmware runs reaches
    /// its address space with the GPU's permissions ([`uat::gpu_stream`]).
    fn gpu_read(&mut self, context: usize, va: u64, buffer: &mut [u8]) -> Result<(), DmaError>;
    /// A GPU-unit write in UAT `context`.
    fn gpu_write(&mut self, context: usize, va: u64, data: &[u8]) -> Result<(), DmaError>;
}

fn reason(error: DmaError) -> &'static str {
    match error {
        DmaError::Fault(_) => "GFX shared memory faults in the UAT",
        DmaError::Memory => "GFX shared memory is not RAM",
        DmaError::Unsupported(reason) => reason,
    }
}

impl Shared for Port<'_, '_> {
    fn read(&mut self, va: u64, buffer: &mut [u8]) -> Result<(), &'static str> {
        Port::read(self, va, buffer).map_err(reason)
    }
    fn write(&mut self, va: u64, data: &[u8]) -> Result<(), &'static str> {
        Port::write(self, va, data).map_err(reason)
    }
    fn gpu_read(&mut self, context: usize, va: u64, buffer: &mut [u8]) -> Result<(), DmaError> {
        gpu_port(self, context).read(va, buffer)
    }
    fn gpu_write(&mut self, context: usize, va: u64, data: &[u8]) -> Result<(), DmaError> {
        gpu_port(self, context).write(va, data)
    }
}

/// The same bus master's port for GPU-unit accesses in `context`.
fn gpu_port<'c, 'b>(port: &'c mut Port<'_, 'b>, context: usize) -> Port<'c, 'b> {
    Port {
        iommu: &mut *port.iommu,
        stream: uat::gpu_stream(context),
        memory: &mut *port.memory,
        access: &mut *port.access,
    }
}

/// What a ring carries, which fixes its entry size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `AGFIAcceleratorDeviceControlEntry`, AP to firmware.
    DeviceControl,
    /// `AGFIAcceleratorDataMasterEntry`, a channel's work, AP to firmware.
    DataMaster,
    /// `AGFIFirmwareEventRingEntry`, firmware to AP.
    FirmwareEvent,
}

impl Kind {
    pub const fn entry_bytes(self) -> usize {
        match self {
            Kind::DeviceControl => 0x40,
            Kind::DataMaster => 0x18,
            Kind::FirmwareEvent => 0x48,
        }
    }
}

/// An AP-to-firmware ring as its directory descriptor names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Descriptor {
    /// Firmware VA of the state block (its read word).
    pub state: u64,
    /// Firmware VA of entry 0.
    pub entries: u64,
}

impl Descriptor {
    /// Parse a descriptor. The three index pointers must name one state
    /// block, as `getReadIndexFWPtr`/`getCFIIndexFWPtr`/`getWriteIndexFWPtr`
    /// form them; anything else is a layout the model does not know.
    pub fn parse(bytes: &[u8; DESCRIPTOR_BYTES]) -> Result<Self, &'static str> {
        let word = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        let (read, cfi, write, entries) = (word(0), word(8), word(0x10), word(0x18));
        if read == 0 || entries == 0 {
            return Err("GFX ring descriptor is not populated");
        }
        if read.checked_add(CFI) != Some(cfi) || read.checked_add(WRITE) != Some(write) {
            return Err("GFX ring descriptor's index pointers do not name one state block");
        }
        Ok(Self {
            state: read,
            entries,
        })
    }

    /// Read the descriptor at `va`.
    pub fn read(memory: &mut dyn Shared, va: u64) -> Result<Self, &'static str> {
        let mut bytes = [0; DESCRIPTOR_BYTES];
        memory.read(va, &mut bytes)?;
        Self::parse(&bytes)
    }

    fn index(memory: &mut dyn Shared, va: u64, name: &'static str) -> Result<u32, &'static str> {
        let value = memory.read_u32(va)?;
        if value >= ENTRIES {
            return Err(name);
        }
        Ok(value)
    }

    /// The (read, write) indices, each checked as the kext checks them.
    pub fn indices(&self, memory: &mut dyn Shared) -> Result<(u32, u32), &'static str> {
        let read = Self::index(
            memory,
            self.state + READ,
            "GFX ring read_index out-of-bounds",
        )?;
        let write = Self::index(
            memory,
            self.state + WRITE,
            "GFX ring write_index out-of-bounds",
        )?;
        Ok((read, write))
    }

    /// The entry at `index`.
    pub fn entry(
        &self,
        memory: &mut dyn Shared,
        kind: Kind,
        index: u32,
    ) -> Result<Vec<u8>, &'static str> {
        if index >= ENTRIES {
            return Err("GFX ring entry index out-of-bounds");
        }
        let mut entry = alloc::vec![0; kind.entry_bytes()];
        memory.read(
            self.entries + u64::from(index) * kind.entry_bytes() as u64,
            &mut entry,
        )?;
        Ok(entry)
    }

    /// Retire entries up to (not including) `read`: the firmware's consume.
    pub fn retire(&self, memory: &mut dyn Shared, read: u32) -> Result<(), &'static str> {
        if read >= ENTRIES {
            return Err("GFX ring read_index out-of-bounds");
        }
        memory.write(self.state + READ, &read.to_le_bytes())
    }
}

/// The next index after `index`, modulo the ring.
pub const fn next(index: u32) -> u32 {
    (index + 1) % ENTRIES
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Flat shared memory: firmware VA `base + n` is byte `n`.
    pub(crate) struct Flat {
        pub base: u64,
        pub bytes: Vec<u8>,
    }

    impl Flat {
        pub fn new(base: u64, bytes: usize) -> Self {
            Self {
                base,
                bytes: alloc::vec![0; bytes],
            }
        }
        fn range(&self, va: u64, len: usize) -> Result<core::ops::Range<usize>, &'static str> {
            let start = va
                .checked_sub(self.base)
                .and_then(|n| usize::try_from(n).ok())
                .ok_or("outside the flat memory")?;
            let end = start.checked_add(len).ok_or("outside the flat memory")?;
            (end <= self.bytes.len())
                .then_some(start..end)
                .ok_or("outside the flat memory")
        }
        pub fn put(&mut self, va: u64, data: &[u8]) {
            let range = self.range(va, data.len()).unwrap();
            self.bytes[range].copy_from_slice(data);
        }
        pub fn put_u32(&mut self, va: u64, value: u32) {
            self.put(va, &value.to_le_bytes());
        }
        pub fn put_u64(&mut self, va: u64, value: u64) {
            self.put(va, &value.to_le_bytes());
        }
        /// Write a descriptor naming `state` and `entries` at `va`.
        pub fn put_descriptor(&mut self, va: u64, state: u64, entries: u64) {
            self.put_u64(va, state + READ);
            self.put_u64(va + 8, state + CFI);
            self.put_u64(va + 0x10, state + WRITE);
            self.put_u64(va + 0x18, entries);
        }
    }

    impl Shared for Flat {
        fn read(&mut self, va: u64, buffer: &mut [u8]) -> Result<(), &'static str> {
            let range = self.range(va, buffer.len())?;
            buffer.copy_from_slice(&self.bytes[range]);
            Ok(())
        }
        fn write(&mut self, va: u64, data: &[u8]) -> Result<(), &'static str> {
            let range = self.range(va, data.len())?;
            self.bytes[range].copy_from_slice(data);
            Ok(())
        }
        /// Every context sees the same flat memory; outside it is a fault.
        fn gpu_read(
            &mut self,
            _context: usize,
            va: u64,
            buffer: &mut [u8],
        ) -> Result<(), DmaError> {
            Shared::read(self, va, buffer).map_err(|_| DmaError::Fault(0))
        }
        fn gpu_write(&mut self, _context: usize, va: u64, data: &[u8]) -> Result<(), DmaError> {
            Shared::write(self, va, data).map_err(|_| DmaError::Fault(0))
        }
    }

    const BASE: u64 = 0xffff_ffa0_0000_0000;

    #[test]
    fn a_descriptor_names_one_state_block_and_an_entry_array() {
        let mut memory = Flat::new(BASE, 0x8000);
        memory.put_descriptor(BASE, BASE + 0x100, BASE + 0x1000);
        let ring = Descriptor::read(&mut memory, BASE).unwrap();
        assert_eq!(ring.state, BASE + 0x100);
        assert_eq!(ring.entries, BASE + 0x1000);
        // Index pointers into different blocks, or an empty slot, refuse.
        memory.put_u64(BASE + 0x10, BASE + 0x200);
        assert!(Descriptor::read(&mut memory, BASE).is_err());
        assert!(Descriptor::read(&mut memory, BASE + 0x20).is_err());
    }

    #[test]
    fn indices_entries_and_retirement_follow_the_kext_layout() {
        let mut memory = Flat::new(BASE, 0x8000);
        let ring = Descriptor {
            state: BASE + 0x100,
            entries: BASE + 0x1000,
        };
        memory.put_u32(BASE + 0x100 + WRITE, 2);
        memory.put(BASE + 0x1000 + 0x40, &[0xaa; 0x40]);
        assert_eq!(ring.indices(&mut memory).unwrap(), (0, 2));
        let entry = ring.entry(&mut memory, Kind::DeviceControl, 1).unwrap();
        assert_eq!(entry, [0xaa; 0x40]);
        ring.retire(&mut memory, 2).unwrap();
        assert_eq!(ring.indices(&mut memory).unwrap(), (2, 2));
        // The CFI word is never touched by a consume.
        assert_eq!(memory.read_u32(BASE + 0x100 + CFI).unwrap(), 0);
        assert_eq!(next(0xff), 0);
    }

    #[test]
    fn out_of_bounds_indices_refuse_as_the_kext_panics() {
        let mut memory = Flat::new(BASE, 0x8000);
        let ring = Descriptor {
            state: BASE + 0x100,
            entries: BASE + 0x1000,
        };
        memory.put_u32(BASE + 0x100 + WRITE, ENTRIES);
        assert_eq!(
            ring.indices(&mut memory),
            Err("GFX ring write_index out-of-bounds")
        );
        assert!(ring.retire(&mut memory, ENTRIES).is_err());
        assert!(ring.entry(&mut memory, Kind::DataMaster, ENTRIES).is_err());
    }
}
