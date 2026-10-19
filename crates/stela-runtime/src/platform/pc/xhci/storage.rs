//! USB mass storage disks: Bulk-Only Transport (BOT 1.0) with the SCSI
//! transparent command set, as host block devices.
//!
//! A disk is LUN 0 of an interface of class 8, subclass 6 (SCSI), protocol
//! 0x50 (Bulk-Only). Attach reads INQUIRY, waits out a unit attention with
//! TEST UNIT READY and REQUEST SENSE, takes the capacity from READ CAPACITY
//! (10), or (16) beyond 2^32 blocks, and the write protection from MODE
//! SENSE (6). Reads and writes use READ/WRITE (10), or (16) beyond the
//! 32-bit LBA range, in chunks of at most 64 KiB; `flush` is SYNCHRONIZE
//! CACHE (10). A STALL in the data stage clears the halt and reads the CSW
//! (BOT 5.3.3); a CSW that is not valid and meaningful, or a phase error,
//! runs reset recovery (5.3.4) and fails the command. A command that
//! fails reports its sense key and codes as the device status. Other
//! subclasses (RBC, UFI, ATAPI) and transports (CBI, UAS) are refused.
use super::{
    super::{
        block::{BlockDevice, BlockError, Identity, Transport},
        dma::{DmaAllocator, DmaBuffer},
    },
    Device, Endpoint, Interface, MAX_TD, Plan, Shared, setup,
};
use alloc::{format, string::String, vec, vec::Vec};

pub const CLASS: u8 = 8;
const SCSI: u8 = 6;
const BULK_ONLY: u8 = 0x50;
const RESET: u8 = 0xff;
const CBW_SIGNATURE: u32 = 0x4342_5355;
const CSW_SIGNATURE: u32 = 0x5342_5355;
const COMMAND_US: u64 = 30_000_000;
const READY_TRIES: usize = 20;
const READY_DELAY_US: u64 = 100_000;

pub(super) fn plan(interface: &Interface) -> Result<Plan, &'static str> {
    if interface.subclass != SCSI || interface.protocol != BULK_ONLY {
        return Err("mass storage other than SCSI over Bulk-Only");
    }
    let bulk = |is_in: bool| {
        interface
            .endpoints
            .iter()
            .copied()
            .find(|e| e.kind() == 2 && e.is_in() == is_in)
    };
    match (bulk(true), bulk(false)) {
        (Some(input), Some(output)) => Ok(Plan::Storage([input, output])),
        _ => Err("mass storage interface without two bulk endpoints"),
    }
}

/// Which way a command's data goes.
enum Data<'a> {
    None,
    In(usize),
    Out(&'a [u8]),
}

pub struct UsbDisk {
    controller: Shared,
    slot: u8,
    interface: u8,
    input: Endpoint,
    output: Endpoint,
    buffer: DmaBuffer,
    wrapper: DmaBuffer,
    tag: u32,
    identity: Identity,
}

impl UsbDisk {
    pub(super) fn new(
        controller: Shared,
        device: &Device,
        interface: &Interface,
        [input, output]: [Endpoint; 2],
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, BlockError> {
        let mut disk = Self {
            controller,
            slot: device.slot,
            interface: interface.number,
            input,
            output,
            buffer: dma.allocate(MAX_TD, MAX_TD)?,
            wrapper: dma.allocate(64, 64)?,
            tag: 0,
            identity: Identity {
                transport: Transport::Usb,
                location: device.location.clone(),
                model: String::new(),
                serial: device
                    .serial
                    .clone()
                    .unwrap_or_else(|| device.location.clone()),
                blocks: 0,
                block_size: 512,
                read_only: false,
            },
        };
        let inquiry = disk.command(&[0x12, 0, 0, 0, 36, 0], Data::In(36))?;
        if inquiry.len() < 36 {
            return Err(BlockError::Unsupported("short INQUIRY data"));
        }
        if inquiry[0] & 0x1f != 0 {
            return Err(BlockError::Unsupported(
                "USB storage that is not a direct-access block device",
            ));
        }
        let text = |bytes: &[u8]| String::from(String::from_utf8_lossy(bytes).trim());
        disk.identity.model = format!("{} {}", text(&inquiry[8..16]), text(&inquiry[16..32]))
            .trim()
            .into();
        let mut ready = false;
        for _ in 0..READY_TRIES {
            if disk.command(&[0; 6], Data::None).is_ok() {
                ready = true;
                break;
            }
            // REQUEST SENSE clears a unit attention.
            let _ = disk.command(&[0x03, 0, 0, 0, 18, 0], Data::In(18));
            let clock = disk.controller.borrow().clock;
            clock.delay(READY_DELAY_US);
        }
        if !ready {
            return Err(BlockError::Unsupported("USB storage never became ready"));
        }
        let capacity = disk.command(&[0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0], Data::In(8))?;
        if capacity.len() < 8 {
            return Err(BlockError::Unsupported("short READ CAPACITY data"));
        }
        let last = u32::from_be_bytes(capacity[..4].try_into().unwrap());
        let mut block_size = u32::from_be_bytes(capacity[4..8].try_into().unwrap());
        let blocks = if last == u32::MAX {
            let mut cdb = [0u8; 16];
            cdb[0] = 0x9e;
            cdb[1] = 0x10;
            cdb[13] = 32;
            let long = disk.command(&cdb, Data::In(32))?;
            if long.len() < 12 {
                return Err(BlockError::Unsupported("short READ CAPACITY (16) data"));
            }
            block_size = u32::from_be_bytes(long[8..12].try_into().unwrap());
            u64::from_be_bytes(long[..8].try_into().unwrap()) + 1
        } else {
            u64::from(last) + 1
        };
        if block_size < 512 || !block_size.is_power_of_two() || block_size as usize > MAX_TD {
            return Err(BlockError::Unsupported("USB storage block size"));
        }
        disk.identity.blocks = blocks;
        disk.identity.block_size = block_size;
        // Write protection, when the device reports a mode header.
        if let Ok(mode) = disk.command(&[0x1a, 0, 0x3f, 0, 4, 0], Data::In(4))
            && mode.len() >= 3
        {
            disk.identity.read_only = mode[2] & 0x80 != 0;
        }
        Ok(disk)
    }

    /// Reset recovery (BOT 5.3.4): the class reset, then both halts cleared.
    fn reset_recovery(&mut self) {
        let mut controller = self.controller.borrow_mut();
        let request = setup(0x21, RESET, 0, u16::from(self.interface), 0);
        let _ = controller.control(self.slot, request, &[]);
        let _ = controller.clear(self.slot, &self.input);
        let _ = controller.clear(self.slot, &self.output);
    }

    fn bulk(
        &mut self,
        endpoint: Endpoint,
        buffer: u64,
        length: usize,
    ) -> Result<usize, BlockError> {
        self.controller
            .borrow_mut()
            .transfer(self.slot, endpoint.dci(), buffer, length, COMMAND_US)
    }

    /// One command: its IN data, or nothing. A failed command's status is
    /// its sense key and ASC/ASCQ (`key << 16 | asc << 8 | ascq`).
    fn command(&mut self, cdb: &[u8], data: Data<'_>) -> Result<Vec<u8>, BlockError> {
        let (length, is_in) = match &data {
            Data::None => (0, false),
            Data::In(length) => (*length, true),
            Data::Out(bytes) => (bytes.len(), false),
        };
        if length > MAX_TD {
            return Err(BlockError::Unsupported("USB storage transfer above 64 KiB"));
        }
        self.tag = self.tag.wrapping_add(1);
        let mut wrapper = [0u8; 31];
        wrapper[..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
        wrapper[4..8].copy_from_slice(&self.tag.to_le_bytes());
        wrapper[8..12].copy_from_slice(&(length as u32).to_le_bytes());
        wrapper[12] = if is_in { 0x80 } else { 0 };
        wrapper[14] = cdb.len() as u8;
        wrapper[15..15 + cdb.len()].copy_from_slice(cdb);
        self.wrapper.bytes_mut()[..31].copy_from_slice(&wrapper);
        let physical = self.wrapper.physical();
        if let Err(error) = self.bulk(self.output, physical, 31) {
            self.reset_recovery();
            return Err(error);
        }
        let mut moved = 0;
        if let Data::Out(bytes) = &data {
            self.buffer.bytes_mut()[..bytes.len()].copy_from_slice(bytes);
        }
        if length > 0 {
            let endpoint = if is_in { self.input } else { self.output };
            match self.bulk(endpoint, self.buffer.physical(), length) {
                Ok(n) => moved = n,
                Err(BlockError::Device {
                    status: super::STALL,
                }) => {
                    self.controller.borrow_mut().clear(self.slot, &endpoint)?;
                }
                Err(error) => {
                    self.reset_recovery();
                    return Err(error);
                }
            }
        }
        // The CSW, once more after clearing a STALL (5.3.3).
        let status_buffer = self.wrapper.physical();
        let csw = match self.bulk(self.input, status_buffer, 13) {
            Err(BlockError::Device {
                status: super::STALL,
            }) => {
                self.controller.borrow_mut().clear(self.slot, &self.input)?;
                self.bulk(self.input, status_buffer, 13)
            }
            other => other,
        };
        let valid = matches!(csw, Ok(13)) && {
            let bytes = &self.wrapper.bytes()[..13];
            u32::from_le_bytes(bytes[..4].try_into().unwrap()) == CSW_SIGNATURE
                && u32::from_le_bytes(bytes[4..8].try_into().unwrap()) == self.tag
                && bytes[12] <= 1
        };
        if !valid {
            self.reset_recovery();
            return Err(BlockError::Device {
                status: 0x0200_0000,
            });
        }
        if self.wrapper.bytes()[12] == 1 {
            let sense = if cdb[0] == 0x03 { 0 } else { self.sense() };
            return Err(BlockError::Device { status: sense });
        }
        Ok(if is_in {
            self.buffer.bytes()[..moved].to_vec()
        } else {
            Vec::new()
        })
    }

    fn sense(&mut self) -> u32 {
        match self.command(&[0x03, 0, 0, 0, 18, 0], Data::In(18)) {
            Ok(sense) if sense.len() >= 14 => {
                u32::from(sense[2] & 0xf) << 16 | u32::from(sense[12]) << 8 | u32::from(sense[13])
            }
            _ => 0x0100_0000,
        }
    }

    /// READ or WRITE of `blocks` at `lba`, (10) when it fits, else (16).
    fn cdb(&self, write: bool, lba: u64, blocks: u32) -> Vec<u8> {
        if lba + u64::from(blocks) <= u64::from(u32::MAX) && blocks <= u32::from(u16::MAX) {
            let mut cdb = vec![if write { 0x2a } else { 0x28 }, 0];
            cdb.extend_from_slice(&(lba as u32).to_be_bytes());
            cdb.push(0);
            cdb.extend_from_slice(&(blocks as u16).to_be_bytes());
            cdb.push(0);
            cdb
        } else {
            let mut cdb = vec![if write { 0x8a } else { 0x88 }, 0];
            cdb.extend_from_slice(&lba.to_be_bytes());
            cdb.extend_from_slice(&blocks.to_be_bytes());
            cdb.extend_from_slice(&[0, 0]);
            cdb
        }
    }
}

impl BlockDevice for UsbDisk {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.identity.check(lba, buffer.len())?;
        let size = self.identity.block_size as usize;
        let mut lba = lba;
        for chunk in buffer.chunks_mut(MAX_TD / size * size) {
            let blocks = (chunk.len() / size) as u32;
            let cdb = self.cdb(false, lba, blocks);
            let data = self.command(&cdb, Data::In(chunk.len()))?;
            if data.len() != chunk.len() {
                return Err(BlockError::Device {
                    status: 0x0300_0000,
                });
            }
            chunk.copy_from_slice(&data);
            lba += u64::from(blocks);
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.identity.check_write(lba, data.len())?;
        let size = self.identity.block_size as usize;
        let mut lba = lba;
        for chunk in data.chunks(MAX_TD / size * size) {
            let blocks = (chunk.len() / size) as u32;
            let cdb = self.cdb(true, lba, blocks);
            self.command(&cdb, Data::Out(chunk))?;
            lba += u64::from(blocks);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        self.command(&[0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0], Data::None)
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{bench, run};
    use super::*;
    use crate::platform::{
        pc::block::tests::RamDisk,
        usb::{
            Function, Speed,
            hub::{Hub, Ports},
            storage::MassStorage,
        },
    };
    use alloc::{boxed::Box, vec};

    struct Disks(Vec<MassStorage>);
    impl Ports for Disks {
        fn count(&self) -> usize {
            self.0.len()
        }
        fn speed(&self, _: usize) -> Speed {
            Speed::High
        }
        fn function(&mut self, port: usize) -> &mut dyn Function {
            &mut self.0[port]
        }
        fn function_ref(&self, port: usize) -> &dyn Function {
            &self.0[port]
        }
    }

    fn disk(serial: &str, blocks: u64, read_only: bool) -> MassStorage {
        let mut ram = RamDisk::new(serial, blocks, 512);
        ram.identity.read_only = read_only;
        for (n, byte) in ram.bytes.iter_mut().enumerate() {
            *byte = (n / 512) as u8 ^ (n % 7) as u8;
        }
        MassStorage::new(Box::new(ram), "00000000000A", "Native Disk").unwrap()
    }

    #[test]
    fn a_disk_on_the_root_port_needs_no_hub() {
        let mut bench = bench(disk("c", 8, false));
        let mut found = run(&mut bench);
        assert!(found.failures.is_empty(), "{:?}", found.failures);
        let mut disk = found.disks.remove(0);
        assert!(
            disk.identity().location.ends_with("port 1"),
            "{}",
            disk.identity().location
        );
        let mut block = [0u8; 512];
        disk.read(7, &mut block).unwrap();
        assert_eq!(block[1], 7 ^ ((7 * 512 + 1) % 7) as u8);
    }

    #[test]
    fn disks_behind_a_hub_enumerate_read_write_and_flush() {
        let hub = Hub::new(
            Disks(vec![disk("a", 300, false), disk("b", 16, true)]),
            "HUB",
        )
        .unwrap();
        let mut bench = bench(hub);
        let mut found = run(&mut bench);
        assert!(found.failures.is_empty(), "{:?}", found.failures);
        assert_eq!(found.disks.len(), 2);
        let mut first = found.disks.remove(0);
        let identity = first.identity().clone();
        assert_eq!((identity.blocks, identity.block_size), (300, 512));
        assert_eq!(identity.model, "STELA Native Disk");
        assert_eq!(identity.serial, "00000000000A");
        assert!(
            identity.location.ends_with("port 1.1"),
            "{}",
            identity.location
        );
        assert!(!identity.read_only);
        // 200 blocks: two chunks of at most 64 KiB.
        let mut bytes = vec![0u8; 200 * 512];
        first.read(50, &mut bytes).unwrap();
        let expected = |at: usize| (at / 512) as u8 ^ (at % 7) as u8;
        assert_eq!(bytes[0], expected(50 * 512));
        assert_eq!(bytes[512 * 199 + 3], expected(249 * 512 + 3));
        let payload: Vec<u8> = (0..3 * 512).map(|n| (n % 253) as u8).collect();
        first.write(7, &payload).unwrap();
        let mut back = vec![0u8; 3 * 512];
        first.read(7, &mut back).unwrap();
        assert_eq!(back, payload);
        first.flush().unwrap();
        // Out of range fails before the bus; the device's own refusals
        // report their sense.
        assert!(first.read(300, &mut [0u8; 512]).is_err());
        let mut second = found.disks.remove(0);
        assert!(second.identity().read_only);
        assert!(matches!(
            second.write(0, &[0u8; 512]),
            Err(BlockError::ReadOnly)
        ));
        assert_eq!(
            second.command(&[0x04, 0, 0, 0, 0, 0], Data::None),
            Err(BlockError::Device { status: 0x05_2000 })
        );
        // The device still answers after the failed command.
        let mut block = [0u8; 512];
        second.read(15, &mut block).unwrap();
        assert_eq!(block[0], expected(15 * 512));
    }
}
