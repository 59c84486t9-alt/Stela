//! AHCI host bus adapters with SATA disks, one polled command slot per port.
//! Controller setup follows Linux `drivers/ata/ahci.c` and `libahci.c` at
//! a804c5742bff224d4cb4d25dd383554d598be32b: firmware-programmed capability
//! and port registers survive HBA reset, legacy Intel port enables are set,
//! and each port fails on its own.
use crate::{
    Clock, Handoff,
    block::{BlockDevice, BlockError, Identity, Transport, ascii},
    bus::{
        dma::{DmaAllocator, DmaBuffer},
        mmio::Mmio,
        pci::{ConfigSpace, Function},
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
/// CAP.NP: the number of ports, minus one.
const CAP_PORTS: u32 = 0x1f;
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

/// Intel Port Control and Status: one enable bit per port (Linux `PCS_6`).
const INTEL_PORT_CONTROL: u16 = 0x92;
const INTEL: u16 = 0x8086;
/// Linux `ahci_pci_tbl` Intel IDs whose board sets `AHCI_HFLAG_INTEL_PCS_QUIRK`.
const INTEL_PCS_QUIRK: &[u16] = &[
    0x02d3, 0x02d7, 0x06d6, 0x06d7, 0x0f22, 0x0f23, 0x1c02, 0x1c03, 0x1c04, 0x1c05, 0x1c06, 0x1c07,
    0x1d02, 0x1d04, 0x1d06, 0x1e02, 0x1e03, 0x1e04, 0x1e05, 0x1e06, 0x1e07, 0x1e0e, 0x1f22, 0x1f23,
    0x1f24, 0x1f25, 0x1f26, 0x1f27, 0x1f2e, 0x1f2f, 0x1f32, 0x1f33, 0x1f34, 0x1f35, 0x1f36, 0x1f37,
    0x1f3e, 0x1f3f, 0x22a3, 0x2323, 0x23a3, 0x2652, 0x2653, 0x2681, 0x2682, 0x2683, 0x27c1, 0x27c3,
    0x27c5, 0x27c6, 0x2821, 0x2822, 0x2823, 0x2824, 0x2826, 0x2827, 0x2829, 0x282a, 0x282f, 0x2922,
    0x2923, 0x2924, 0x2925, 0x2927, 0x2929, 0x292a, 0x292b, 0x292c, 0x292f, 0x294d, 0x294e, 0x34d3,
    0x3a05, 0x3a22, 0x3a25, 0x3b22, 0x3b23, 0x3b24, 0x3b25, 0x3b29, 0x3b2b, 0x3b2c, 0x3b2f, 0x43d4,
    0x43d5, 0x43d6, 0x43d7, 0x4b63, 0x502a, 0x502b, 0x5ae3, 0x8c02, 0x8c03, 0x8c04, 0x8c05, 0x8c06,
    0x8c07, 0x8c0e, 0x8c0f, 0x8c82, 0x8c83, 0x8c84, 0x8c85, 0x8c86, 0x8c87, 0x8c8e, 0x8c8f, 0x8d02,
    0x8d04, 0x8d06, 0x8d0e, 0x8d62, 0x8d64, 0x8d66, 0x8d6e, 0x9c02, 0x9c03, 0x9c04, 0x9c05, 0x9c06,
    0x9c07, 0x9c0e, 0x9c0f, 0x9c83, 0x9c85, 0x9c87, 0x9c8f, 0x9d03, 0x9d05, 0x9d07, 0x9dd3, 0xa102,
    0xa103, 0xa105, 0xa106, 0xa107, 0xa10f, 0xa182, 0xa186, 0xa1d2, 0xa1d6, 0xa202, 0xa206, 0xa252,
    0xa256, 0xa356, 0xa386,
];

const COMMAND_START: u32 = 1 << 0;
const COMMAND_SPIN_UP: u32 = 1 << 1;
const COMMAND_FIS_RECEIVE: u32 = 1 << 4;
const COMMAND_FIS_RUNNING: u32 = 1 << 14;
const COMMAND_LIST_RUNNING: u32 = 1 << 15;
const TASK_FILE_ERROR: u32 = 1 << 0;
const TASK_FILE_BUSY: u32 = 0x88;
/// Port interrupt status bits that end a command (Linux `PORT_IRQ_ERROR`).
const INTERRUPT_TASK_FILE_ERROR: u32 = 1 << 30;
const INTERRUPT_HOST_BUS_FATAL: u32 = 1 << 29;
const INTERRUPT_HOST_BUS_DATA: u32 = 1 << 28;
const INTERRUPT_INTERFACE_FATAL: u32 = 1 << 27;
const INTERRUPT_BAD_PORT_MULTIPLIER: u32 = 1 << 23;
const INTERRUPT_PHY_READY_CHANGE: u32 = 1 << 22;
const INTERRUPT_CONNECT_CHANGE: u32 = 1 << 6;
const INTERRUPT_UNKNOWN_FIS: u32 = 1 << 4;
const INTERRUPT_ERROR: u32 = INTERRUPT_TASK_FILE_ERROR
    | INTERRUPT_HOST_BUS_FATAL
    | INTERRUPT_HOST_BUS_DATA
    | INTERRUPT_INTERFACE_FATAL
    | INTERRUPT_BAD_PORT_MULTIPLIER
    | INTERRUPT_PHY_READY_CHANGE
    | INTERRUPT_CONNECT_CHANGE
    | INTERRUPT_UNKNOWN_FIS;
/// SStatus.DET: a device is present and Phy communication is established.
const DEVICE_PRESENT: u32 = 3;
const SATA_STATUS_DETECTION: u32 = 0xf;
/// SControl.DET: perform interface initialization (COMRESET).
const SATA_CONTROL_DETECTION: u32 = 0xf;
const SATA_CONTROL_RESET: u32 = 1;
/// Device signatures (AHCI 1.3.1 §3.3.9, Linux `SATA_SIGNATURE`s).
const SIGNATURE_ATA: u32 = 0x0000_0101;
const SIGNATURE_ATAPI: u32 = 0xeb14_0101;
const SIGNATURE_PORT_MULTIPLIER: u32 = 0x9669_0101;
const SIGNATURE_ENCLOSURE: u32 = 0xc33c_0101;
const PORT_REGISTERS: u64 = 0x80;
const PORT_BASE: u64 = 0x100;
const MAX_PORTS: u32 = 32;

/// Host-to-device Register FIS (SATA 3.x §10.5.6): type, the Command bit,
/// and the device register's LBA mode bit.
const FIS_REGISTER_HOST_TO_DEVICE: u8 = 0x27;
const FIS_COMMAND: u8 = 0x80;
const DEVICE_LBA: u8 = 0x40;
/// Command table: the FIS area, then the first PRDT entry's address and
/// byte count (AHCI 1.3.1 §4.2.3).
const TABLE_HEADER_BYTES: usize = 0x90;
const PRDT_ADDRESS: usize = 0x80;
const PRDT_BYTE_COUNT: usize = 0x8c;
/// IDENTIFY DEVICE words (ACS-3 §7.12.7).
const IDENTIFY_SERIAL: core::ops::Range<usize> = 10..20;
const IDENTIFY_MODEL: core::ops::Range<usize> = 27..47;
const IDENTIFY_COMMANDS_2: usize = 83;
const COMMANDS_2_LBA48: u16 = 1 << 10;
const COMMANDS_2_FLUSH_EXT: u16 = 1 << 13;
/// Words 83 and 87 are valid when bits 15:14 read 01b.
const WORD_VALID_MASK: u16 = 0xc000;
const WORD_VALID: u16 = 0x4000;
const IDENTIFY_ENABLED_1: usize = 85;
const ENABLED_1_WRITE_CACHE: u16 = 1 << 5;
const IDENTIFY_DEFAULTS: usize = 87;
const IDENTIFY_LBA48_SECTORS: core::ops::Range<usize> = 100..104;
const IDENTIFY_SECTOR_SIZE: usize = 106;
const SECTOR_SIZE_VALID_MASK: u16 = 0xc000;
const SECTOR_SIZE_VALID: u16 = 0x4000;
const SECTOR_SIZE_LOGICAL_LONG: u16 = 1 << 12;
const IDENTIFY_LOGICAL_WORDS: usize = 117;
const ATA_SECTOR_BYTES: u32 = 512;

/// The 32-slot command list (1 KiB aligned) followed by the received-FIS
/// area (256 bytes), and one command table (AHCI 1.3.1 §4.2).
const COMMAND_LIST_BYTES: usize = 1024;
const RECEIVED_FIS_BYTES: usize = 256;
const COMMAND_TABLE_BYTES: usize = 4096;
const COMMAND_TABLE_ALIGN: usize = 128;

/// Command header DW0: FIS length in dwords, direction, PRDT entries.
const COMMAND_FIS_DWORDS: u32 = 5;
const COMMAND_WRITE_SHIFT: u32 = 6;
const COMMAND_PRDT_SHIFT: u32 = 16;

const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA_EXT: u8 = 0x35;
const ATA_FLUSH_CACHE: u8 = 0xe7;
const ATA_FLUSH_CACHE_EXT: u8 = 0xea;
const ATA_STANDBY_IMMEDIATE: u8 = 0xe0;
const ATA_IDENTIFY: u8 = 0xec;

const BOUNCE_BYTES: usize = 128 * 1024;
const RESET_TIMEOUT_US: u64 = 1_000_000;
/// Linux `ahci_stop_engine` and `ahci_stop_fis_rx` waits.
const STOP_ENGINE_TIMEOUT_US: u64 = 500_000;
const STOP_FIS_TIMEOUT_US: u64 = 1_000_000;
const COMRESET_HOLD_US: u64 = 1_000;
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
    command_timeout_us: u64,
    /// Failed commands require acknowledged reset and re-identification.
    /// The queue, FIS and bounce allocations remain reserved for this boot.
    fault: Option<BlockError>,
    /// The cache flush command, or `None` when the write cache is off.
    flush: Option<u8>,
}

/// Linux's flush: none unless the write cache is enabled
/// (`ata_id_wcache_enabled`, which sd reads as WCE), then FLUSH CACHE EXT
/// when the disk has it (`ata_id_has_flush_ext`), else FLUSH CACHE.
fn flush_command(word: impl Fn(usize) -> u16) -> Option<u8> {
    if word(IDENTIFY_DEFAULTS) & WORD_VALID_MASK != WORD_VALID
        || word(IDENTIFY_ENABLED_1) & ENABLED_1_WRITE_CACHE == 0
    {
        return None;
    }
    let commands = word(IDENTIFY_COMMANDS_2);
    Some(
        if commands & WORD_VALID_MASK == WORD_VALID && commands & COMMANDS_2_FLUSH_EXT != 0 {
            ATA_FLUSH_CACHE_EXT
        } else {
            ATA_FLUSH_CACHE
        },
    )
}

/// The disks behind one controller, and the ports that failed on their own.
pub struct Attached {
    pub disks: Vec<AhciDisk>,
    pub failures: Vec<(u32, BlockError)>,
}

/// Take the HBA from the firmware, reset it and return one device per port
/// with an ATA disk behind it.
pub fn attach(
    function: &mut Function,
    handoff: &Handoff,
    dma: &mut dyn DmaAllocator,
) -> Result<Attached, BlockError> {
    validate_clock(handoff.clock)?;
    function.power_up(&handoff.clock)?;
    let bars = function.bars();
    let hba = registers(handoff, bars[5], 0, PORT_BASE)?;
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
    // Firmware programs CAP and PI, which may be write-once and which some
    // controllers clear on HBA reset (Linux `ahci_save_initial_config`).
    let capabilities = hba.read32(CAPABILITIES);
    let capabilities_2 = hba.read32(CAPABILITIES_2);
    let implemented = port_map(capabilities, hba.read32(PORTS_IMPLEMENTED));
    hba.write32(GLOBAL_CONTROL, GLOBAL_AHCI_ENABLE | GLOBAL_RESET);
    if !clock.wait(RESET_TIMEOUT_US, || {
        hba.read32(GLOBAL_CONTROL) & GLOBAL_RESET == 0
    }) {
        return Err(BlockError::Timeout);
    }
    // AHCI mode, interrupts off; then Linux `ahci_restore_initial_config`.
    hba.write32(GLOBAL_CONTROL, GLOBAL_AHCI_ENABLE);
    hba.write32(CAPABILITIES, capabilities);
    if capabilities_2 != 0 {
        hba.write32(CAPABILITIES_2, capabilities_2);
    }
    hba.write32(PORTS_IMPLEMENTED, implemented);
    hba.read32(PORTS_IMPLEMENTED);
    if function.vendor == INTEL && INTEL_PCS_QUIRK.contains(&function.device) {
        // Linux `ahci_intel_pcs_quirk`: enable ports firmware left off. Only
        // the low sixteen ports have PCS bits.
        let enables = implemented as u16;
        let control = function.config().read16(INTEL_PORT_CONTROL);
        if control & enables != enables {
            function
                .config()
                .write16(INTEL_PORT_CONTROL, control | enables);
        }
    }
    let mut attached = Attached {
        disks: Vec::new(),
        failures: Vec::new(),
    };
    for index in (0..MAX_PORTS).filter(|index| implemented >> index & 1 == 1) {
        let offset = PORT_BASE + PORT_REGISTERS * u64::from(index);
        let started = registers(handoff, bars[5], offset, PORT_REGISTERS)
            .and_then(|port| AhciDisk::start(port, capabilities, clock, dma));
        match started {
            Ok(Some(mut disk)) => {
                disk.identity.location = format!("{} port {index}", function.address);
                attached.disks.push(disk);
            }
            Ok(None) => {}
            Err(error) => attached.failures.push((index, error)),
        }
    }
    Ok(attached)
}

/// The implemented ports. An unprogrammed PI falls back to CAP.NP's count,
/// as Linux `ahci_save_initial_config` does.
fn port_map(capabilities: u32, implemented: u32) -> u32 {
    if implemented != 0 {
        return implemented;
    }
    let ports = (capabilities & CAP_PORTS) + 1;
    u32::MAX >> (MAX_PORTS - ports)
}

fn validate_clock(clock: Clock) -> Result<(), BlockError> {
    clock.check_duration(COMMAND_TIMEOUT_US).map_err(|_| {
        BlockError::Unsupported("AHCI requires a calibrated, representable operation clock")
    })
}

/// Stop the command list engine, then FIS reception, each waiting for the
/// port to report it stopped (AHCI 1.3.1 §10.1.2; Linux `ahci_stop_engine`,
/// `ahci_stop_fis_rx`).
fn stop_port(port: &impl CommandPort, clock: Clock) -> Result<(), BlockError> {
    validate_clock(clock)?;
    let command = port.read32(PORT_COMMAND);
    if command & (COMMAND_START | COMMAND_LIST_RUNNING) != 0 {
        port.write32(PORT_COMMAND, command & !COMMAND_START);
        if !clock.wait(STOP_ENGINE_TIMEOUT_US, || {
            port.read32(PORT_COMMAND) & COMMAND_LIST_RUNNING == 0
        }) {
            return Err(BlockError::Timeout);
        }
    }
    port.write32(
        PORT_COMMAND,
        port.read32(PORT_COMMAND) & !COMMAND_FIS_RECEIVE,
    );
    if !clock.wait(STOP_FIS_TIMEOUT_US, || {
        port.read32(PORT_COMMAND) & COMMAND_FIS_RUNNING == 0
    }) {
        return Err(BlockError::Timeout);
    }
    Ok(())
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
        stop_port(&port, clock)?;
        if capabilities & CAP_STAGGERED_SPIN_UP != 0 {
            port.write32(PORT_COMMAND, port.read32(PORT_COMMAND) | COMMAND_SPIN_UP);
        }
        let control = port.read32(PORT_SATA_CONTROL) & !SATA_CONTROL_DETECTION;
        port.write32(PORT_SATA_CONTROL, control | SATA_CONTROL_RESET);
        clock.delay(COMRESET_HOLD_US);
        port.write32(PORT_SATA_CONTROL, control);
        if !clock.wait(RESET_TIMEOUT_US, || {
            port.read32(PORT_SATA_STATUS) & SATA_STATUS_DETECTION == DEVICE_PRESENT
        }) {
            return Ok(None);
        }
        port.write32(PORT_SATA_ERROR, u32::MAX);
        let commands = dma.allocate(COMMAND_LIST_BYTES + RECEIVED_FIS_BYTES, COMMAND_LIST_BYTES)?;
        let table = dma.allocate(COMMAND_TABLE_BYTES, COMMAND_TABLE_ALIGN)?;
        let bounce = dma.allocate(BOUNCE_BYTES, 4096)?;
        if capabilities & CAP_64BIT == 0
            && [&commands, &table, &bounce]
                .iter()
                .any(|buffer| buffer.physical() + buffer.len() as u64 > 1 << 32)
        {
            return Err(BlockError::Unsupported("32-bit AHCI with DMA above 4 GiB"));
        }
        port.write64(PORT_LIST, commands.physical());
        port.write64(PORT_FIS, commands.physical() + COMMAND_LIST_BYTES as u64);
        port.write32(
            PORT_COMMAND,
            port.read32(PORT_COMMAND) | COMMAND_FIS_RECEIVE,
        );
        if !clock.wait(SPIN_UP_TIMEOUT_US, || {
            port.read32(PORT_TASK_FILE) & TASK_FILE_BUSY == 0
        }) {
            return Err(BlockError::Timeout);
        }
        let unsupported = match port.read32(PORT_SIGNATURE) {
            SIGNATURE_ATA => None,
            SIGNATURE_ATAPI => Some("ATAPI device"),
            SIGNATURE_PORT_MULTIPLIER => Some("SATA port multiplier"),
            SIGNATURE_ENCLOSURE => Some("SATA enclosure management bridge"),
            _ => Some("unknown SATA device signature"),
        };
        if let Some(device) = unsupported {
            stop_port(&port, clock)?;
            return Err(BlockError::Unsupported(device));
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
                block_size: ATA_SECTOR_BYTES,
                read_only: false,
            },
            clock,
            command_timeout_us: COMMAND_TIMEOUT_US,
            fault: None,
            flush: None,
        };
        disk.issue(ATA_IDENTIFY, 0, 0, ATA_SECTOR_BYTES as usize, false)?;
        let data = disk.bounce.bytes();
        let word = |index: usize| u16::from_le_bytes([data[2 * index], data[2 * index + 1]]);
        // ATA strings hold two characters per word, high byte first.
        let string = |words: core::ops::Range<usize>| {
            let bytes: Vec<u8> = words.flat_map(|index| word(index).to_be_bytes()).collect();
            ascii(&bytes)
        };
        if word(IDENTIFY_COMMANDS_2) & COMMANDS_2_LBA48 == 0 {
            return Err(BlockError::Unsupported(
                "SATA disk without 48-bit addressing",
            ));
        }
        let blocks = IDENTIFY_LBA48_SECTORS
            .rev()
            .fold(0u64, |value, index| value << 16 | u64::from(word(index)));
        let sector = word(IDENTIFY_SECTOR_SIZE);
        let block_size = if sector & SECTOR_SIZE_VALID_MASK == SECTOR_SIZE_VALID
            && sector & SECTOR_SIZE_LOGICAL_LONG != 0
        {
            // The logical sector size in 16-bit words.
            (u32::from(word(IDENTIFY_LOGICAL_WORDS))
                | u32::from(word(IDENTIFY_LOGICAL_WORDS + 1)) << 16)
                * 2
        } else {
            ATA_SECTOR_BYTES
        };
        if !(ATA_SECTOR_BYTES..=BOUNCE_BYTES as u32).contains(&block_size)
            || !block_size.is_power_of_two()
        {
            return Err(BlockError::Unsupported("SATA logical sector size"));
        }
        disk.flush = flush_command(word);
        disk.identity.serial = string(IDENTIFY_SERIAL);
        disk.identity.model = string(IDENTIFY_MODEL);
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
        self.table.bytes_mut()[..TABLE_HEADER_BYTES].fill(0);
        let fis = [
            FIS_REGISTER_HOST_TO_DEVICE,
            FIS_COMMAND,
            command,
            0,
            lba as u8,
            (lba >> 8) as u8,
            (lba >> 16) as u8,
            if command == ATA_IDENTIFY {
                0
            } else {
                DEVICE_LBA
            },
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
            self.table.write(PRDT_ADDRESS, self.bounce.physical());
            self.table.write(PRDT_BYTE_COUNT, bytes as u32 - 1);
        }
        let flags = COMMAND_FIS_DWORDS
            | u32::from(write) << COMMAND_WRITE_SHIFT
            | entries << COMMAND_PRDT_SHIFT;
        self.commands.write(0, flags);
        self.commands.write(4, 0u32);
        self.commands.write(8, table);
        fence(Ordering::SeqCst);
        port.write32(PORT_INTERRUPTS, u32::MAX);
        port.write32(PORT_ISSUE, 1);
        let mut interrupts = 0;
        let done = self.clock.wait(self.command_timeout_us, || {
            interrupts = port.read32(PORT_INTERRUPTS) & INTERRUPT_ERROR;
            interrupts != 0 || port.read32(PORT_ISSUE) & 1 == 0
        });
        fence(Ordering::SeqCst);
        let task_file = port.read32(PORT_TASK_FILE);
        if interrupts & !INTERRUPT_TASK_FILE_ERROR != 0 {
            // Host bus, interface or link errors leave the port frozen.
            let error = BlockError::Device { status: interrupts };
            self.fault = Some(error.clone());
            return Err(error);
        }
        if interrupts != 0 || task_file & TASK_FILE_ERROR != 0 {
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
        match self.flush {
            Some(command) => self.issue(command, 0, 0, 0, false),
            None => self.ready(),
        }
    }

    /// Flush, and before power-off spin the disk down, as Linux libata's
    /// `ata_dev_power_set_standby` does on `SYSTEM_POWER_OFF`.
    fn shutdown(&mut self, power_off: bool) -> Result<(), BlockError> {
        self.flush()?;
        if power_off {
            self.issue(ATA_STANDBY_IMMEDIATE, 0, 0, 0, false)?;
        }
        Ok(())
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
                    commands: dma
                        .allocate(COMMAND_LIST_BYTES + RECEIVED_FIS_BYTES, COMMAND_LIST_BYTES)
                        .unwrap(),
                    table: dma
                        .allocate(COMMAND_TABLE_BYTES, COMMAND_TABLE_ALIGN)
                        .unwrap(),
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
                        ticks_per_microsecond: 1000,
                    },
                    command_timeout_us: 1000,
                    fault: None,
                    flush: Some(ATA_FLUSH_CACHE_EXT),
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
            let started = fixture.disk.clock.try_start().unwrap();
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
            if matches!(behavior, Behavior::Timeout) {
                assert!(fixture.disk.clock.try_elapsed_us(started).unwrap() >= 1000);
            }
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

    /// Port command engines that stop only when their own enable clears.
    struct Engines {
        command: Cell<u32>,
        writes: RefCell<Vec<u32>>,
    }

    impl CommandPort for Engines {
        fn read32(&self, offset: usize) -> u32 {
            assert_eq!(offset, PORT_COMMAND);
            self.command.get()
        }
        fn write32(&self, offset: usize, value: u32) {
            assert_eq!(offset, PORT_COMMAND);
            self.writes.borrow_mut().push(value);
            let mut running = value;
            if value & COMMAND_START == 0 {
                running &= !COMMAND_LIST_RUNNING;
            }
            if value & COMMAND_FIS_RECEIVE == 0 {
                running &= !COMMAND_FIS_RUNNING;
            }
            self.command.set(running);
        }
    }

    #[test]
    fn ports_stop_the_command_list_before_fis_reception() {
        let port = Engines {
            command: Cell::new(
                COMMAND_START | COMMAND_LIST_RUNNING | COMMAND_FIS_RECEIVE | COMMAND_FIS_RUNNING,
            ),
            writes: RefCell::new(Vec::new()),
        };
        // This peer acknowledges both engine stops immediately; its finite
        // clock remains admitted even when no waiting is needed.
        let clock = Clock {
            ticks_per_microsecond: 1000,
        };
        stop_port(&port, clock).unwrap();
        let enables: Vec<u32> = port
            .writes
            .borrow()
            .iter()
            .map(|value| value & (COMMAND_START | COMMAND_FIS_RECEIVE))
            .collect();
        assert_eq!(enables, [COMMAND_FIS_RECEIVE, 0]);
        assert_eq!(port.command.get(), 0);
    }

    #[test]
    fn invalid_clock_never_attempts_an_engine_transition() {
        for ticks_per_microsecond in [0, u64::MAX, u64::MAX / (2 * COMMAND_TIMEOUT_US) + 1] {
            let command =
                COMMAND_START | COMMAND_LIST_RUNNING | COMMAND_FIS_RECEIVE | COMMAND_FIS_RUNNING;
            let port = Engines {
                command: Cell::new(command),
                writes: RefCell::new(Vec::new()),
            };
            assert!(
                stop_port(
                    &port,
                    Clock {
                        ticks_per_microsecond
                    }
                )
                .is_err()
            );
            assert!(port.writes.borrow().is_empty());
            assert_eq!(port.command.get(), command);
        }
    }

    #[test]
    fn an_unprogrammed_port_map_comes_from_the_port_count() {
        assert_eq!(port_map(0x4000_0005, 0), 0x3f);
        assert_eq!(port_map(CAP_PORTS, 0), u32::MAX);
        assert_eq!(port_map(0x5, 0x21), 0x21);
    }

    #[test]
    fn host_bus_and_interface_errors_fail_the_command_at_once() {
        let mut fixture = Fixture::new();
        let model = PortModel::new(Behavior::Timeout);
        model.registers.borrow_mut()[PORT_INTERRUPTS / 4] = 0;
        struct Fatal<'a>(&'a PortModel);
        impl CommandPort for Fatal<'_> {
            fn read32(&self, offset: usize) -> u32 {
                if offset == PORT_INTERRUPTS {
                    return INTERRUPT_INTERFACE_FATAL;
                }
                self.0.read32(offset)
            }
            fn write32(&self, offset: usize, value: u32) {
                self.0.write32(offset, value)
            }
        }
        assert_eq!(
            fixture
                .disk
                .issue_on(&Fatal(&model), ATA_READ_DMA_EXT, 0, 1, 512, false),
            Err(BlockError::Device {
                status: INTERRUPT_INTERFACE_FATAL
            })
        );
        assert!(fixture.disk.fault.is_some());
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

    #[test]
    fn flush_follows_the_write_cache_and_the_extended_command_like_linux() {
        let identify = |defaults: u16, enabled: u16, commands: u16| {
            move |index: usize| match index {
                IDENTIFY_DEFAULTS => defaults,
                IDENTIFY_ENABLED_1 => enabled,
                IDENTIFY_COMMANDS_2 => commands,
                _ => 0,
            }
        };
        let cache = ENABLED_1_WRITE_CACHE;
        let ext = WORD_VALID | COMMANDS_2_LBA48 | COMMANDS_2_FLUSH_EXT;
        assert_eq!(
            flush_command(identify(WORD_VALID, cache, ext)),
            Some(ATA_FLUSH_CACHE_EXT)
        );
        // Without the extended command, or with word 83 unsigned.
        assert_eq!(
            flush_command(identify(WORD_VALID, cache, ext & !COMMANDS_2_FLUSH_EXT)),
            Some(ATA_FLUSH_CACHE)
        );
        assert_eq!(
            flush_command(identify(WORD_VALID, cache, ext & !WORD_VALID)),
            Some(ATA_FLUSH_CACHE)
        );
        // A disabled or unreported write cache needs no flush.
        assert_eq!(flush_command(identify(WORD_VALID, 0, ext)), None);
        assert_eq!(flush_command(identify(0, cache, ext)), None);

        let mut fixture = Fixture::new();
        fixture.disk.flush = None;
        let issued = fixture.disk.port.read32(PORT_ISSUE);
        assert_eq!(fixture.disk.flush(), Ok(()));
        assert_eq!(fixture.disk.port.read32(PORT_ISSUE), issued);
        fixture.disk.fault = Some(BlockError::Timeout);
        assert_eq!(fixture.disk.flush(), Err(BlockError::Timeout));
    }
}
