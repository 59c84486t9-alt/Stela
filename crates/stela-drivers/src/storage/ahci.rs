//! AHCI host bus adapters with SATA disks, one polled command slot per port.
use crate::{
    Clock, Handoff,
    block::{BlockDevice, BlockError, Identity, Transport, ascii},
    bus::{
        dma::{DmaAllocator, DmaBuffer},
        mmio::Mmio,
        pci::Function,
    },
    registers,
};
use alloc::{format, vec::Vec};
use core::sync::atomic::{Ordering, fence};

pub const CLASS: [u8; 3] = [0x01, 0x06, 0x01];

const CAPABILITIES: usize = 0x00;
const GLOBAL_CONTROL: usize = 0x04;
const PORTS_IMPLEMENTED: usize = 0x0c;
const CAPABILITIES_2: usize = 0x24;
const HANDOFF: usize = 0x28;

const CAP_64BIT: u32 = 1 << 31;
const CAP_STAGGERED_SPIN_UP: u32 = 1 << 27;
const CAP2_HANDOFF: u32 = 1 << 0;
const HANDOFF_BIOS_OWNED: u32 = 1 << 0;
const HANDOFF_OS_OWNED: u32 = 1 << 1;
const HANDOFF_BIOS_BUSY: u32 = 1 << 4;
const GLOBAL_RESET: u32 = 1 << 0;
const GLOBAL_AHCI_ENABLE: u32 = 1 << 31;

const PORT_LIST: usize = 0x00;
const PORT_FIS: usize = 0x08;
const PORT_INTERRUPTS: usize = 0x10;
const PORT_COMMAND: usize = 0x18;
const PORT_TASK_FILE: usize = 0x20;
const PORT_SIGNATURE: usize = 0x24;
const PORT_SATA_STATUS: usize = 0x28;
const PORT_SATA_CONTROL: usize = 0x2c;
const PORT_SATA_ERROR: usize = 0x30;
const PORT_ISSUE: usize = 0x38;

const COMMAND_START: u32 = 1 << 0;
const COMMAND_SPIN_UP: u32 = 1 << 1;
const COMMAND_FIS_RECEIVE: u32 = 1 << 4;
const COMMAND_FIS_RUNNING: u32 = 1 << 14;
const COMMAND_LIST_RUNNING: u32 = 1 << 15;
const TASK_FILE_ERROR: u32 = 1 << 0;
const TASK_FILE_BUSY: u32 = 0x88;
const INTERRUPT_TASK_FILE_ERROR: u32 = 1 << 30;
const DEVICE_PRESENT: u32 = 3;
const SATA_DISK: u32 = 0x0000_0101;

const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA_EXT: u8 = 0x35;
const ATA_FLUSH_CACHE_EXT: u8 = 0xea;
const ATA_IDENTIFY: u8 = 0xec;

const BOUNCE_BYTES: usize = 128 * 1024;
const RESET_TIMEOUT_US: u64 = 1_000_000;
const SPIN_UP_TIMEOUT_US: u64 = 10_000_000;
const COMMAND_TIMEOUT_US: u64 = 30_000_000;

/// Command register side effects, allowing hardware-like W1C and completion
/// tests against the actual table and DMA algorithm.
trait CommandPort {
    fn read32(&self, offset: usize) -> u32;
    fn write32(&self, offset: usize, value: u32);
}

impl CommandPort for Mmio {
    fn read32(&self, offset: usize) -> u32 {
        Mmio::read32(self, offset)
    }
    fn write32(&self, offset: usize, value: u32) {
        Mmio::write32(self, offset, value);
    }
}

pub struct AhciDisk {
    port: Mmio,
    commands: DmaBuffer,
    table: DmaBuffer,
    bounce: DmaBuffer,
    identity: Identity,
    clock: Clock,
    /// Failed commands require acknowledged reset and re-identification.
    /// The queue, FIS and bounce allocations remain reserved for this boot.
    fault: Option<BlockError>,
}

/// Take the HBA from the firmware, reset it and return one device per port
/// with an ATA disk behind it.
pub fn attach(
    function: &mut Function,
    handoff: &Handoff,
    dma: &mut dyn DmaAllocator,
) -> Result<Vec<AhciDisk>, BlockError> {
    function.power_up(&handoff.clock)?;
    let bars = function.bars();
    let hba = registers(handoff, bars[5], 0, 0x100)?;
    function.enable_polled();
    let clock = handoff.clock;
    if hba.read32(CAPABILITIES_2) & CAP2_HANDOFF != 0 {
        hba.write32(HANDOFF, hba.read32(HANDOFF) | HANDOFF_OS_OWNED);
        clock.wait(25_000, || hba.read32(HANDOFF) & HANDOFF_BIOS_OWNED == 0);
        if hba.read32(HANDOFF) & HANDOFF_BIOS_BUSY != 0 {
            clock.wait(2_000_000, || hba.read32(HANDOFF) & HANDOFF_BIOS_BUSY == 0);
        }
        if hba.read32(HANDOFF) & HANDOFF_BIOS_OWNED != 0 {
            return Err(BlockError::Unsupported(
                "firmware keeps the AHCI controller",
            ));
        }
    }
    hba.write32(GLOBAL_CONTROL, GLOBAL_AHCI_ENABLE);
    hba.write32(GLOBAL_CONTROL, GLOBAL_AHCI_ENABLE | GLOBAL_RESET);
    if !clock.wait(RESET_TIMEOUT_US, || {
        hba.read32(GLOBAL_CONTROL) & GLOBAL_RESET == 0
    }) {
        return Err(BlockError::Timeout);
    }
    // AHCI mode, interrupts off.
    hba.write32(GLOBAL_CONTROL, GLOBAL_AHCI_ENABLE);
    let capabilities = hba.read32(CAPABILITIES);
    let implemented = hba.read32(PORTS_IMPLEMENTED);
    let mut disks = Vec::new();
    for index in (0..32u64).filter(|index| implemented >> index & 1 == 1) {
        let port = registers(handoff, bars[5], 0x100 + 0x80 * index, 0x80)?;
        if let Some(mut disk) = AhciDisk::start(port, capabilities, clock, dma)? {
            disk.identity.location = format!("{} port {index}", function.address);
            disks.push(disk);
        }
    }
    Ok(disks)
}

impl AhciDisk {
    fn ready(&self) -> Result<(), BlockError> {
        self.fault.clone().map_or(Ok(()), Err)
    }

    /// Reset the link on one port and, when an ATA disk answers, start the
    /// port and identify the disk.
    fn start(
        port: Mmio,
        capabilities: u32,
        clock: Clock,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Option<Self>, BlockError> {
        let command = port.read32(PORT_COMMAND);
        port.write32(
            PORT_COMMAND,
            command & !(COMMAND_START | COMMAND_FIS_RECEIVE),
        );
        if !clock.wait(RESET_TIMEOUT_US, || {
            port.read32(PORT_COMMAND) & (COMMAND_LIST_RUNNING | COMMAND_FIS_RUNNING) == 0
        }) {
            return Err(BlockError::Timeout);
        }
        if capabilities & CAP_STAGGERED_SPIN_UP != 0 {
            port.write32(PORT_COMMAND, port.read32(PORT_COMMAND) | COMMAND_SPIN_UP);
        }
        let control = port.read32(PORT_SATA_CONTROL) & !0xf;
        port.write32(PORT_SATA_CONTROL, control | 1);
        clock.delay(1_000);
        port.write32(PORT_SATA_CONTROL, control);
        if !clock.wait(RESET_TIMEOUT_US, || {
            port.read32(PORT_SATA_STATUS) & 0xf == DEVICE_PRESENT
        }) {
            return Ok(None);
        }
        port.write32(PORT_SATA_ERROR, u32::MAX);
        let commands = dma.allocate(1024 + 256, 1024)?;
        let table = dma.allocate(4096, 128)?;
        let bounce = dma.allocate(BOUNCE_BYTES, 4096)?;
        if capabilities & CAP_64BIT == 0
            && [&commands, &table, &bounce]
                .iter()
                .any(|buffer| buffer.physical() + buffer.len() as u64 > 1 << 32)
        {
            return Err(BlockError::Unsupported("32-bit AHCI with DMA above 4 GiB"));
        }
        port.write64(PORT_LIST, commands.physical());
        port.write64(PORT_FIS, commands.physical() + 1024);
        port.write32(
            PORT_COMMAND,
            port.read32(PORT_COMMAND) | COMMAND_FIS_RECEIVE,
        );
        if !clock.wait(SPIN_UP_TIMEOUT_US, || {
            port.read32(PORT_TASK_FILE) & TASK_FILE_BUSY == 0
        }) {
            return Err(BlockError::Timeout);
        }
        if port.read32(PORT_SIGNATURE) != SATA_DISK {
            port.write32(
                PORT_COMMAND,
                port.read32(PORT_COMMAND) & !COMMAND_FIS_RECEIVE,
            );
            return Ok(None);
        }
        port.write32(PORT_INTERRUPTS, u32::MAX);
        port.write32(PORT_COMMAND, port.read32(PORT_COMMAND) | COMMAND_START);
        let mut disk = Self {
            port,
            commands,
            table,
            bounce,
            identity: Identity {
                transport: Transport::Ahci,
                location: alloc::string::String::new(),
                model: alloc::string::String::new(),
                serial: alloc::string::String::new(),
                blocks: 0,
                block_size: 512,
                read_only: false,
            },
            clock,
            fault: None,
        };
        disk.issue(ATA_IDENTIFY, 0, 0, 512, false)?;
        let data = disk.bounce.bytes();
        let word = |index: usize| u16::from_le_bytes([data[2 * index], data[2 * index + 1]]);
        // ATA strings hold two characters per word, high byte first.
        let string = |words: core::ops::Range<usize>| {
            let bytes: Vec<u8> = words.flat_map(|index| word(index).to_be_bytes()).collect();
            ascii(&bytes)
        };
        if word(83) & (1 << 10) == 0 {
            return Err(BlockError::Unsupported(
                "SATA disk without 48-bit addressing",
            ));
        }
        let blocks = (100..104)
            .rev()
            .fold(0u64, |value, index| value << 16 | u64::from(word(index)));
        let sector = word(106);
        let block_size = if sector & 0xc000 == 0x4000 && sector & (1 << 12) != 0 {
            (u32::from(word(117)) | u32::from(word(118)) << 16) * 2
        } else {
            512
        };
        if !(512..=BOUNCE_BYTES as u32).contains(&block_size) || !block_size.is_power_of_two() {
            return Err(BlockError::Unsupported("SATA logical sector size"));
        }
        disk.identity.serial = string(10..20);
        disk.identity.model = string(27..47);
        disk.identity.blocks = blocks;
        disk.identity.block_size = block_size;
        Ok(Some(disk))
    }

    /// Run one ATA command in slot 0 with `bytes` of data through the bounce
    /// buffer.
    fn issue(
        &mut self,
        command: u8,
        lba: u64,
        count: u16,
        bytes: usize,
        write: bool,
    ) -> Result<(), BlockError> {
        let port = self.port;
        self.issue_on(&port, command, lba, count, bytes, write)
    }

    fn issue_on(
        &mut self,
        port: &impl CommandPort,
        command: u8,
        lba: u64,
        count: u16,
        bytes: usize,
        write: bool,
    ) -> Result<(), BlockError> {
        self.ready()?;
        let table = self.table.physical();
        self.table.bytes_mut()[..0x90].fill(0);
        let fis = [
            0x27,
            0x80,
            command,
            0,
            lba as u8,
            (lba >> 8) as u8,
            (lba >> 16) as u8,
            if command == ATA_IDENTIFY { 0 } else { 0x40 },
            (lba >> 24) as u8,
            (lba >> 32) as u8,
            (lba >> 40) as u8,
            0,
            count as u8,
            (count >> 8) as u8,
        ];
        self.table.bytes_mut()[..fis.len()].copy_from_slice(&fis);
        let entries = u32::from(bytes > 0);
        if bytes > 0 {
            self.table.write(0x80, self.bounce.physical());
            self.table.write(0x8c, bytes as u32 - 1);
        }
        let flags = 5 | u32::from(write) << 6 | entries << 16;
        self.commands.write(0, flags);
        self.commands.write(4, 0u32);
        self.commands.write(8, table);
        fence(Ordering::SeqCst);
        port.write32(PORT_INTERRUPTS, u32::MAX);
        port.write32(PORT_ISSUE, 1);
        let mut failed = false;
        let done = self.clock.wait(COMMAND_TIMEOUT_US, || {
            failed = port.read32(PORT_INTERRUPTS) & INTERRUPT_TASK_FILE_ERROR != 0;
            failed || port.read32(PORT_ISSUE) & 1 == 0
        });
        fence(Ordering::SeqCst);
        let task_file = port.read32(PORT_TASK_FILE);
        if failed || task_file & TASK_FILE_ERROR != 0 {
            let error = BlockError::Device { status: task_file };
            self.fault = Some(error.clone());
            return Err(error);
        }
        if !done {
            self.fault = Some(BlockError::Timeout);
            return Err(BlockError::Timeout);
        }
        Ok(())
    }

    fn chunk_bytes(&self) -> usize {
        let block = self.identity.block_size as usize;
        BOUNCE_BYTES / block * block
    }

    fn sectors(&self, bytes: usize) -> u16 {
        (bytes / self.identity.block_size as usize) as u16
    }
}

impl BlockDevice for AhciDisk {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.identity.check(lba, buffer.len())?;
        self.ready()?;
        let block = self.identity.block_size as usize;
        let chunk = self.chunk_bytes();
        for (index, part) in buffer.chunks_mut(chunk).enumerate() {
            let first = lba + (index * chunk / block) as u64;
            let count = self.sectors(part.len());
            self.issue(ATA_READ_DMA_EXT, first, count, part.len(), false)?;
            part.copy_from_slice(&self.bounce.bytes()[..part.len()]);
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.identity.check_write(lba, data.len())?;
        self.ready()?;
        let block = self.identity.block_size as usize;
        let chunk = self.chunk_bytes();
        for (index, part) in data.chunks(chunk).enumerate() {
            let first = lba + (index * chunk / block) as u64;
            let count = self.sectors(part.len());
            self.bounce.bytes_mut()[..part.len()].copy_from_slice(part);
            self.issue(ATA_WRITE_DMA_EXT, first, count, part.len(), true)?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        self.issue(ATA_FLUSH_CACHE_EXT, 0, 0, 0, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::dma::RegionAllocator;
    use alloc::boxed::Box;
    use core::cell::{Cell, RefCell};

    #[derive(Clone, Copy)]
    enum Behavior {
        Complete,
        Timeout,
        TaskError,
    }

    struct PortModel {
        registers: RefCell<[u32; 32]>,
        behavior: Cell<Behavior>,
        writes: RefCell<Vec<(usize, u32)>>,
    }

    impl PortModel {
        fn new(behavior: Behavior) -> Self {
            let mut registers = [0u32; 32];
            registers[PORT_COMMAND / 4] = COMMAND_START | COMMAND_LIST_RUNNING;
            Self {
                registers: RefCell::new(registers),
                behavior: Cell::new(behavior),
                writes: RefCell::new(Vec::new()),
            }
        }
    }

    impl CommandPort for PortModel {
        fn read32(&self, offset: usize) -> u32 {
            let mut registers = self.registers.borrow_mut();
            if registers[PORT_ISSUE / 4] & 1 != 0 {
                match self.behavior.get() {
                    Behavior::Complete if offset == PORT_ISSUE => registers[PORT_ISSUE / 4] = 0,
                    Behavior::TaskError => {
                        registers[PORT_INTERRUPTS / 4] |= INTERRUPT_TASK_FILE_ERROR;
                        registers[PORT_TASK_FILE / 4] |= TASK_FILE_ERROR;
                    }
                    _ => {}
                }
            }
            registers[offset / 4]
        }
        fn write32(&self, offset: usize, value: u32) {
            self.writes.borrow_mut().push((offset, value));
            let mut registers = self.registers.borrow_mut();
            match offset {
                PORT_INTERRUPTS | PORT_SATA_ERROR => registers[offset / 4] &= !value,
                _ => registers[offset / 4] = value,
            }
        }
    }

    struct Fixture {
        disk: AhciDisk,
        _registers: Box<[u64]>,
        _memory: Vec<u64>,
    }

    impl Fixture {
        fn new() -> Self {
            let mut registers = vec![0u64; 16].into_boxed_slice();
            let mut memory = vec![0u64; 32768];
            let start = memory.as_mut_ptr() as u64;
            // SAFETY: stable fixture allocations outlive the disk and all
            // register/DMA operations; there is no physical device.
            let (port, mut dma) = unsafe {
                (
                    Mmio::new(registers.as_mut_ptr() as u64),
                    RegionAllocator::new(start..start + (memory.len() * 8) as u64),
                )
            };
            Self {
                disk: AhciDisk {
                    port,
                    commands: dma.allocate(1280, 1024).unwrap(),
                    table: dma.allocate(4096, 128).unwrap(),
                    bounce: dma.allocate(BOUNCE_BYTES, 4096).unwrap(),
                    identity: Identity {
                        transport: Transport::Ahci,
                        location: "fixture".into(),
                        model: "fixture".into(),
                        serial: "fixture".into(),
                        blocks: 1024,
                        block_size: 512,
                        read_only: false,
                    },
                    clock: Clock {
                        ticks_per_microsecond: 0,
                    },
                    fault: None,
                },
                _registers: registers,
                _memory: memory,
            }
        }
    }

    #[test]
    fn timeout_or_task_error_never_restarts_or_reuses_port_dma() {
        for behavior in [Behavior::Timeout, Behavior::TaskError] {
            let mut fixture = Fixture::new();
            let model = PortModel::new(behavior);
            let error = match behavior {
                Behavior::Timeout => BlockError::Timeout,
                _ => BlockError::Device {
                    status: TASK_FILE_ERROR,
                },
            };
            assert_eq!(
                fixture
                    .disk
                    .issue_on(&model, ATA_READ_DMA_EXT, 0, 1, 512, false),
                Err(error.clone())
            );
            // A still-running command engine never supplies an acknowledged
            // reset merely because the CPU's timeout elapsed.
            assert_eq!(
                model.registers.borrow()[PORT_COMMAND / 4],
                COMMAND_START | COMMAND_LIST_RUNNING
            );
            assert!(
                !model
                    .writes
                    .borrow()
                    .iter()
                    .any(|(offset, _)| *offset == PORT_COMMAND)
            );
            fixture.disk.bounce.bytes_mut().fill(0x9d); // Late device DMA.
            let commands = fixture.disk.commands.bytes().to_vec();
            let table = fixture.disk.table.bytes().to_vec();
            let writes = model.writes.borrow().len();
            model.behavior.set(Behavior::Complete);
            model.registers.borrow_mut()[PORT_ISSUE / 4] = 0;
            assert_eq!(
                fixture
                    .disk
                    .issue_on(&model, ATA_FLUSH_CACHE_EXT, 0, 0, 0, false),
                Err(error.clone())
            );
            assert_eq!(fixture.disk.write(0, &[0x44; 512]), Err(error.clone()));
            let mut output = [0x66; 512];
            assert_eq!(fixture.disk.read(0, &mut output), Err(error.clone()));
            assert_eq!(fixture.disk.flush(), Err(error));
            assert_eq!(output, [0x66; 512]);
            assert!(fixture.disk.bounce.bytes().iter().all(|byte| *byte == 0x9d));
            assert_eq!(fixture.disk.commands.bytes(), commands);
            assert_eq!(fixture.disk.table.bytes(), table);
            assert_eq!(model.writes.borrow().len(), writes);
            assert!(fixture.disk.port.read32(PORT_ISSUE) == 0);
        }
    }

    #[test]
    fn acknowledged_completions_keep_the_real_command_path_usable() {
        let mut fixture = Fixture::new();
        let model = PortModel::new(Behavior::Complete);
        fixture
            .disk
            .issue_on(&model, ATA_WRITE_DMA_EXT, 7, 1, 512, true)
            .unwrap();
        assert!(fixture.disk.fault.is_none());
        assert_eq!(fixture.disk.table.bytes()[2], ATA_WRITE_DMA_EXT);
        assert_eq!(fixture.disk.commands.read::<u32>(0), 5 | 1 << 6 | 1 << 16);
        fixture
            .disk
            .issue_on(&model, ATA_FLUSH_CACHE_EXT, 0, 0, 0, false)
            .unwrap();
        assert!(fixture.disk.fault.is_none());
        assert_eq!(fixture.disk.commands.read::<u32>(0), 5);
        assert_eq!(
            model
                .writes
                .borrow()
                .iter()
                .filter(|(offset, _)| *offset == PORT_ISSUE)
                .count(),
            2
        );
    }
}
