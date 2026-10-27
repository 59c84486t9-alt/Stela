//! AHCI host bus adapters with SATA disks, one polled command slot per port.
//! Controller setup follows Linux `drivers/ata/ahci.c` and `libahci.c` at
//! a804c5742bff224d4cb4d25dd383554d598be32b: firmware-programmed capability
//! and port registers survive HBA reset, legacy Intel port enables are set,
//! and each port fails on its own. A failed command goes through libata's
//! error handler: the AHCI error interrupt and taskfile are classified as
//! `ahci_error_intr` and `ata_eh_link_autopsy` do, the engine restarts or the
//! link is hard reset and the disk revalidated, and sd's retries apply.
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
/// Linux `PORT_IRQ_FREEZE`: the errors that freeze the port.
const INTERRUPT_FREEZE: u32 = INTERRUPT_HOST_BUS_FATAL
    | INTERRUPT_INTERFACE_FATAL
    | INTERRUPT_CONNECT_CHANGE
    | INTERRUPT_PHY_READY_CHANGE
    | INTERRUPT_UNKNOWN_FIS
    | INTERRUPT_BAD_PORT_MULTIPLIER;
const INTERRUPT_ERROR: u32 = INTERRUPT_TASK_FILE_ERROR
    | INTERRUPT_HOST_BUS_FATAL
    | INTERRUPT_HOST_BUS_DATA
    | INTERRUPT_INTERFACE_FATAL
    | INTERRUPT_BAD_PORT_MULTIPLIER
    | INTERRUPT_PHY_READY_CHANGE
    | INTERRUPT_CONNECT_CHANGE
    | INTERRUPT_UNKNOWN_FIS;
/// ATA status and error register bits (Linux `include/linux/ata.h`).
const STATUS_BUSY: u8 = 1 << 7;
const STATUS_READY: u8 = 1 << 6;
const STATUS_FAULT: u8 = 1 << 5;
const STATUS_REQUEST: u8 = 1 << 3;
const STATUS_ERROR: u8 = 1 << 0;
const ERROR_INTERFACE_CRC: u8 = 1 << 7;
const ERROR_UNCORRECTABLE: u8 = 1 << 6;
const ERROR_ID_NOT_FOUND: u8 = 1 << 4;
const ERROR_ADDRESS_MARK: u8 = 1 << 0;
/// Device register obsolete bits (`ATA_DEVICE_OBS`).
const DEVICE_OBSOLETE: u8 = 0xa0;
/// SError bits (Linux `SERR_*`).
const SERROR_DATA: u32 = 1 << 8;
const SERROR_PERSISTENT: u32 = 1 << 9;
const SERROR_PROTOCOL: u32 = 1 << 10;
const SERROR_INTERNAL: u32 = 1 << 11;
const SERROR_PHY_READY_CHANGE: u32 = 1 << 16;
const SERROR_DEVICE_EXCHANGED: u32 = 1 << 26;
/// Linux `AC_ERR_*`: what a failed command is charged with.
const ERR_DEVICE: u32 = 1 << 0;
const ERR_HSM: u32 = 1 << 1;
const ERR_TIMEOUT: u32 = 1 << 2;
const ERR_MEDIA: u32 = 1 << 3;
const ERR_ATA_BUS: u32 = 1 << 4;
const ERR_HOST_BUS: u32 = 1 << 5;
const ERR_SYSTEM: u32 = 1 << 6;
const ERR_INVALID: u32 = 1 << 7;
/// SStatus.DET: a device is present and Phy communication is established.
const DEVICE_PRESENT: u32 = 3;
const SATA_STATUS_DETECTION: u32 = 0xf;
/// SControl.DET: perform interface initialization (COMRESET).
const SATA_CONTROL_DETECTION: u32 = 0xf;
const SATA_CONTROL_RESET: u32 = 1;
/// `sata_link_hardreset`: keep SPD, disable partial and slumber, then
/// COMRESET (DET 1) and release it (DET 0).
const SATA_CONTROL_SPEED: u32 = 0x0f0;
const SATA_CONTROL_COMRESET: u32 = 0x301;
const SATA_CONTROL_RESUMED: u32 = 0x300;
const SATA_CONTROL_RESUME_MASK: u32 = 0xf0f;
/// `sata_link_hardreset` turns the Phy off (DET 4) to change SPD.
const SATA_CONTROL_OFFLINE: u32 = 0x304;
const SPEED_SHIFT: u32 = 4;
/// Device signatures (AHCI 1.3.1 Â§3.3.9, Linux `SATA_SIGNATURE`s).
const SIGNATURE_ATA: u32 = 0x0000_0101;
const SIGNATURE_ATAPI: u32 = 0xeb14_0101;
const SIGNATURE_PORT_MULTIPLIER: u32 = 0x9669_0101;
const SIGNATURE_ENCLOSURE: u32 = 0xc33c_0101;
const PORT_REGISTERS: u64 = 0x80;
const PORT_BASE: u64 = 0x100;
const MAX_PORTS: u32 = 32;

/// Host-to-device Register FIS (SATA 3.x Â§10.5.6): type, the Command bit,
/// and the device register's LBA mode bit.
const FIS_REGISTER_HOST_TO_DEVICE: u8 = 0x27;
const FIS_COMMAND: u8 = 0x80;
const DEVICE_LBA: u8 = 0x40;
/// Command table: the FIS area, then the first PRDT entry's address and
/// byte count (AHCI 1.3.1 Â§4.2.3).
const TABLE_HEADER_BYTES: usize = 0x90;
const PRDT_ADDRESS: usize = 0x80;
const PRDT_BYTE_COUNT: usize = 0x8c;
/// IDENTIFY DEVICE words (ACS-3 Â§7.12.7).
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
/// area (256 bytes), and one command table (AHCI 1.3.1 Â§4.2).
const COMMAND_LIST_BYTES: usize = 1024;
const RECEIVED_FIS_BYTES: usize = 256;
/// The received D2H Register FIS, set to BSY before a hardreset.
const RECEIVED_D2H: usize = COMMAND_LIST_BYTES + 0x40;
const FIS_BYTES: usize = 20;
const COMMAND_TABLE_BYTES: usize = 4096;
const COMMAND_TABLE_ALIGN: usize = 128;
/// Revalidation IDENTIFY data, in the command table past its one PRDT entry,
/// so a failed write's data stays in the bounce buffer for its retry.
const IDENTIFY_DATA: usize = 0x200;

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
/// `ata_eh_reset_timeouts`: one hardreset per entry.
const RESET_TIMEOUTS_US: [u64; 4] = [10_000_000, 10_000_000, 35_000_000, 5_000_000];
/// `ATA_EH_DEV_TRIES`: revalidations before the disk is disabled.
const DEVICE_TRIES: usize = 3;
/// `SD_MAX_RETRIES`.
const COMMAND_RETRIES: u32 = 5;
/// `ATA_LINK_RESUME_TRIES`, each followed by a 200 ms settle.
const RESUME_TRIES: usize = 5;
const RESUME_SETTLE_US: u64 = 200_000;
/// `sata_deb_timing_normal` and `_hotplug`: interval, stable duration, limit.
const DEBOUNCE_NORMAL: [u64; 3] = [5_000, 100_000, 2_000_000];
const DEBOUNCE_HOTPLUG: [u64; 3] = [25_000, 500_000, 2_000_000];
/// Linux `ATA_EFLAG_*`: what `ata_eh_speed_down` records with an error.
const EFLAG_IO: u32 = 1 << 0;
const EFLAG_DUBIOUS: u32 = 1 << 1;
const EFLAG_OLD: u32 = 1 << 31;
/// Linux `ATA_ECAT_*`, each offset by `DUBIOUS` before the transfer is
/// verified.
const CATEGORY_ATA_BUS: usize = 1;
const CATEGORY_TIMEOUT_HSM: usize = 2;
const CATEGORY_UNKNOWN_DEVICE: usize = 3;
const CATEGORY_DUBIOUS: usize = 4;
const CATEGORIES: usize = 8;
/// Linux `ATA_EH_SPDN_*` verdicts.
const VERDICT_NCQ_OFF: u32 = 1 << 0;
const VERDICT_SPEED_DOWN: u32 = 1 << 1;
const VERDICT_FALLBACK_TO_PIO: u32 = 1 << 2;
const VERDICT_KEEP_ERRORS: u32 = 1 << 3;
/// `ATA_ERING_SIZE`, and the verdict's five- and ten-minute windows.
const ERROR_RING: usize = 32;
const VERDICT_SHORT_US: u64 = 5 * 60 * 1_000_000;
const VERDICT_LONG_US: u64 = 10 * 60 * 1_000_000;
/// The disk left the port or another device answered in its place.
const DETACHED: BlockError = BlockError::Protocol("the SATA disk detached or changed");

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
    /// Set when error handling cannot recover the disk, as libata disables
    /// it. The queue, FIS and bounce allocations remain reserved for this boot.
    fault: Option<BlockError>,
    /// The cache flush command, or `None` when the write cache is off.
    flush: Option<u8>,
    /// `dev->ering`, the history `ata_eh_speed_down` judges.
    errors: ErrorRing,
    /// `ATA_DFLAG_DUBIOUS_XFER`: no read or write has completed since the
    /// disk was configured.
    dubious: bool,
    /// `link->sata_spd_limit`, a mask of allowed SPD values less one, and
    /// `link->sata_spd`, the SStatus SPD after the last reset.
    speed_limit: u32,
    speed: u32,
}

/// One `ata_ering_entry`: its flags, `AC_ERR_*` mask and raw clock origin.
#[derive(Clone, Copy, Default)]
struct Recorded {
    eflags: u32,
    mask: u32,
    at: u64,
}

/// Linux `struct ata_ering`: the newest error at the cursor.
#[derive(Default)]
struct ErrorRing {
    entries: [Recorded; ERROR_RING],
    cursor: usize,
}

impl ErrorRing {
    /// `ata_ering_record`.
    fn record(&mut self, eflags: u32, mask: u32, at: u64) {
        self.cursor = (self.cursor + 1) % ERROR_RING;
        self.entries[self.cursor] = Recorded { eflags, mask, at };
    }

    /// `ata_ering_map`'s order: newest first, up to the first empty entry.
    fn newest(&mut self) -> impl Iterator<Item = &mut Recorded> {
        let (head, tail) = self.entries.split_at_mut(self.cursor + 1);
        head.iter_mut()
            .rev()
            .chain(tail.iter_mut().rev())
            .take_while(|entry| entry.mask != 0)
    }

    /// `ata_ering_clear`: entries stay but no longer count.
    fn clear(&mut self) {
        for entry in self.newest() {
            entry.eflags |= EFLAG_OLD;
        }
    }
}

/// Linux `ata_eh_categorize_error`. `verified` turns true at the first
/// error recorded after a verified transfer and stays so for older ones.
fn categorize(eflags: u32, mask: u32, verified: &mut bool) -> usize {
    if eflags & EFLAG_DUBIOUS == 0 {
        *verified = true;
    }
    let base = if *verified { 0 } else { CATEGORY_DUBIOUS };
    if mask & ERR_ATA_BUS != 0 {
        return base + CATEGORY_ATA_BUS;
    }
    if mask & ERR_TIMEOUT != 0 {
        return base + CATEGORY_TIMEOUT_HSM;
    }
    if eflags & EFLAG_IO != 0 {
        if mask & ERR_HSM != 0 {
            return base + CATEGORY_TIMEOUT_HSM;
        }
        if mask & (ERR_DEVICE | ERR_MEDIA | ERR_INVALID) == ERR_DEVICE {
            return base + CATEGORY_UNKNOWN_DEVICE;
        }
    }
    0
}

/// `fls`: the highest set bit, counting from one.
fn fls(value: u32) -> u32 {
    u32::BITS - value.leading_zeros()
}

/// `__sata_set_spd_needed`'s target SPD for a limit.
fn speed_target(limit: u32) -> u32 {
    if limit == u32::MAX {
        0
    } else {
        fls(limit) & 0xf
    }
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

/// What IDENTIFY DEVICE says about a disk.
struct Identified {
    model: alloc::string::String,
    serial: alloc::string::String,
    blocks: u64,
    block_size: u32,
    flush: Option<u8>,
}

fn identify(data: &[u8]) -> Result<Identified, BlockError> {
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
    Ok(Identified {
        model: string(IDENTIFY_MODEL),
        serial: string(IDENTIFY_SERIAL),
        blocks,
        block_size,
        flush: flush_command(word),
    })
}

/// A failed command as libata's error handler sees it.
#[derive(Debug)]
struct Failure {
    error: BlockError,
    /// The `AC_ERR_*` mask.
    mask: u32,
    /// The port froze: only a reset recovers it.
    frozen: bool,
    /// `ATA_EH_RESET` was requested.
    reset: bool,
    /// `ata_ehi_hotplugged`: debounce with the hotplug timing.
    hotplug: bool,
}

/// Linux `ahci_error_intr`, `ata_eh_analyze_serror` and `ata_eh_analyze_tf`
/// for a single non-NCQ command on a port without a multiplier.
fn classify(interrupts: u32, serror: u32, task_file: u32, timed_out: bool) -> Failure {
    let mut mask = 0;
    let mut reset = false;
    let mut hotplug = false;
    if interrupts & INTERRUPT_TASK_FILE_ERROR != 0 {
        mask |= ERR_DEVICE;
    }
    if interrupts & INTERRUPT_UNKNOWN_FIS != 0 {
        mask |= ERR_HSM;
        reset = true;
    }
    if interrupts & (INTERRUPT_HOST_BUS_FATAL | INTERRUPT_HOST_BUS_DATA) != 0 {
        mask |= ERR_HOST_BUS;
        reset = true;
    }
    if interrupts & INTERRUPT_INTERFACE_FATAL != 0 {
        mask |= ERR_ATA_BUS;
        reset = true;
    }
    if interrupts & (INTERRUPT_CONNECT_CHANGE | INTERRUPT_PHY_READY_CHANGE) != 0
        || serror & (SERROR_PHY_READY_CHANGE | SERROR_DEVICE_EXCHANGED) != 0
    {
        hotplug = true;
    }
    if serror & (SERROR_PERSISTENT | SERROR_DATA) != 0 {
        mask |= ERR_ATA_BUS;
        reset = true;
    }
    if serror & SERROR_PROTOCOL != 0 {
        mask |= ERR_HSM;
        reset = true;
    }
    if serror & SERROR_INTERNAL != 0 {
        mask |= ERR_SYSTEM;
        reset = true;
    }
    if hotplug {
        mask |= ERR_ATA_BUS;
        reset = true;
    }
    // A timed-out command freezes the port.
    let frozen = interrupts & INTERRUPT_FREEZE != 0 || timed_out;
    if timed_out {
        mask |= ERR_TIMEOUT;
    }
    let status = task_file as u8;
    let error = (task_file >> 8) as u8;
    if status & (STATUS_BUSY | STATUS_REQUEST | STATUS_READY) != STATUS_READY {
        mask |= ERR_HSM;
        reset = true;
    } else if status & (STATUS_ERROR | STATUS_FAULT) != 0 {
        mask |= ERR_DEVICE;
        if error & ERROR_INTERFACE_CRC != 0 {
            mask |= ERR_ATA_BUS;
        }
        if error & (ERROR_UNCORRECTABLE | ERROR_ADDRESS_MARK) != 0 {
            mask |= ERR_MEDIA;
        }
        if error & ERROR_ID_NOT_FOUND != 0 {
            mask |= ERR_INVALID;
        }
        if mask & (ERR_HSM | ERR_TIMEOUT | ERR_ATA_BUS) != 0 {
            reset = true;
        }
    }
    // Device errors are probably spurious beside an ATA bus error.
    if mask & ERR_ATA_BUS != 0 {
        mask &= !(ERR_DEVICE | ERR_MEDIA | ERR_INVALID);
    }
    let error = if timed_out {
        BlockError::Timeout
    } else if interrupts & !INTERRUPT_TASK_FILE_ERROR != 0 {
        BlockError::Device { status: interrupts }
    } else {
        BlockError::Device { status: task_file }
    };
    Failure {
        error,
        mask,
        frozen,
        reset,
        hotplug,
    }
}

/// Linux `ata_eh_worth_retry`.
fn worth_retry(mask: u32, io: bool) -> bool {
    if mask & ERR_MEDIA != 0 {
        return false;
    }
    if io {
        return true;
    }
    if mask & ERR_INVALID != 0 {
        return false;
    }
    mask != ERR_DEVICE
}

/// Linux `ahci_start_engine`.
fn start_engine(port: &impl CommandPort) {
    port.write32(PORT_COMMAND, port.read32(PORT_COMMAND) | COMMAND_START);
    port.read32(PORT_COMMAND);
}

/// Linux `ahci_stop_engine`: clear ST and wait for the command list to stop.
fn stop_engine(port: &impl CommandPort, clock: Clock) -> Result<(), BlockError> {
    let command = port.read32(PORT_COMMAND);
    if command & (COMMAND_START | COMMAND_LIST_RUNNING) == 0 {
        return Ok(());
    }
    if command == u32::MAX {
        return Err(BlockError::Unsupported(
            "the AHCI controller is unavailable",
        ));
    }
    port.write32(PORT_COMMAND, command & !COMMAND_START);
    if !clock.wait(STOP_ENGINE_TIMEOUT_US, || {
        port.read32(PORT_COMMAND) & COMMAND_LIST_RUNNING == 0
    }) {
        return Err(BlockError::Timeout);
    }
    Ok(())
}

/// Linux `sata_link_debounce`: wait until SStatus.DET holds still for the
/// stable duration, or a DET of 1 settles, before the limit.
fn debounce(
    port: &impl CommandPort,
    clock: Clock,
    timing: [u64; 3],
    limit_us: u64,
) -> Result<(), BlockError> {
    let [interval, duration, timeout] = timing;
    let limit = limit_us.min(timeout);
    let start = clock.try_start().map_err(|_| BlockError::Timeout)?;
    let elapsed = || clock.try_elapsed_us(start).map_err(|_| BlockError::Timeout);
    let mut last = port.read32(PORT_SATA_STATUS) & SATA_STATUS_DETECTION;
    let mut last_at = 0;
    loop {
        clock.delay(interval);
        let now = elapsed()?;
        let current = port.read32(PORT_SATA_STATUS) & SATA_STATUS_DETECTION;
        if current == last {
            if current == 1 && now < limit {
                continue;
            }
            if now > last_at + duration {
                return Ok(());
            }
            continue;
        }
        last = current;
        last_at = now;
        if now > limit {
            return Err(BlockError::Timeout);
        }
    }
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
/// port to report it stopped (AHCI 1.3.1 Â§10.1.2; Linux `ahci_stop_engine`,
/// `ahci_stop_fis_rx`).
fn stop_port(port: &impl CommandPort, clock: Clock) -> Result<(), BlockError> {
    validate_clock(clock)?;
    stop_engine(port, clock)?;
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
        // sata_link_init_spd: the firmware's SPD caps the limit.
        let initial = (port.read32(PORT_SATA_CONTROL) & SATA_CONTROL_SPEED) >> SPEED_SHIFT;
        let speed_limit = match initial {
            0 => u32::MAX,
            speed => (1 << speed) - 1,
        };
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
        let speed = (port.read32(PORT_SATA_STATUS) >> SPEED_SHIFT) & 0xf;
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
            errors: ErrorRing::default(),
            // ata_eh_set_mode configured the disk: the transfer is unverified.
            dubious: true,
            speed_limit,
            speed,
        };
        let port = disk.port;
        let buffer = disk.bounce.physical();
        disk.internal(&port, ATA_IDENTIFY, ATA_SECTOR_BYTES as usize, buffer)?;
        let found = identify(disk.bounce.bytes())?;
        disk.flush = found.flush;
        disk.identity.serial = found.serial;
        disk.identity.model = found.model;
        disk.identity.blocks = found.blocks;
        disk.identity.block_size = found.block_size;
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

    /// One command through libata's error handling: recover the port after a
    /// failure, then retry as sd does when `ata_eh_worth_retry` agrees.
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
        // Only reads and writes carry ATA_QCFLAG_IO.
        let io = matches!(command, ATA_READ_DMA_EXT | ATA_WRITE_DMA_EXT);
        let buffer = self.bounce.physical();
        let mut retries = 0;
        loop {
            let Err(failure) = self.attempt(port, command, lba, count, bytes, write, buffer) else {
                // ata_verify_xfer: a completed DMA transfer verifies it.
                if io {
                    self.dubious = false;
                }
                return Ok(());
            };
            if let Err(error) = self.recover(port, &failure, io) {
                self.fault = Some(error.clone());
                return Err(error);
            }
            if !worth_retry(failure.mask, io) || retries == COMMAND_RETRIES {
                return Err(failure.error);
            }
            retries += 1;
        }
    }

    /// An internal command (`ata_exec_internal`): a failure kicks the engine
    /// so it forgets the command, and is returned as is.
    fn internal(
        &mut self,
        port: &impl CommandPort,
        command: u8,
        bytes: usize,
        buffer: u64,
    ) -> Result<(), BlockError> {
        self.ready()?;
        self.attempt(port, command, 0, 0, bytes, false, buffer)
            .or_else(|failure| {
                stop_engine(port, self.clock)?;
                start_engine(port);
                Err(failure.error)
            })
    }

    /// Issue the command once and wait for its completion or error.
    #[allow(clippy::too_many_arguments)]
    fn attempt(
        &mut self,
        port: &impl CommandPort,
        command: u8,
        lba: u64,
        count: u16,
        bytes: usize,
        write: bool,
        buffer: u64,
    ) -> Result<(), Failure> {
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
            self.table.write(PRDT_ADDRESS, buffer);
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
        if done && interrupts == 0 {
            return Ok(());
        }
        // AHCI needs SError cleared; otherwise it might lock up.
        let serror = port.read32(PORT_SATA_ERROR);
        port.write32(PORT_SATA_ERROR, serror);
        port.write32(PORT_INTERRUPTS, port.read32(PORT_INTERRUPTS));
        Err(classify(
            interrupts,
            serror,
            port.read32(PORT_TASK_FILE),
            !done,
        ))
    }

    /// Linux `ahci_error_handler` and `ata_eh_recover`: restart an unfrozen
    /// engine and consider a speed-down; when a reset is due, hard reset the
    /// link (one try per `ata_eh_reset_timeouts` entry) and revalidate the
    /// disk, up to `ATA_EH_DEV_TRIES` times. An error disables the disk.
    fn recover(
        &mut self,
        port: &impl CommandPort,
        failure: &Failure,
        io: bool,
    ) -> Result<(), BlockError> {
        if !failure.frozen {
            stop_engine(port, self.clock)?;
            start_engine(port);
        }
        let slowed = self.speed_down(port, failure.mask, io)?;
        if !failure.reset && !slowed {
            return Ok(());
        }
        let mut hotplug = failure.hotplug;
        let mut last = failure.error.clone();
        for _ in 0..DEVICE_TRIES {
            let mut online = None;
            for timeout in RESET_TIMEOUTS_US {
                match self.hardreset(port, timeout, hotplug) {
                    Ok(present) => {
                        online = Some(present);
                        break;
                    }
                    Err(error) => last = error,
                }
            }
            match online {
                None => return Err(last),
                Some(false) => return Err(DETACHED),
                Some(true) => {}
            }
            match self.revalidate(port) {
                Ok(()) => return Ok(()),
                Err(error) if error == DETACHED => return Err(error),
                Err(error) => last = error,
            }
            hotplug = false;
        }
        Err(last)
    }

    /// Linux `ata_eh_speed_down`: record the error and, when the verdict
    /// calls for it, lower the SATA link speed limit; whether a reset must
    /// apply it. NCQ is never enabled, so NCQ_OFF has nothing to turn off;
    /// transfer modes are never programmed, so there is none to lower; and
    /// PIO fallback excludes SATA ATA disks.
    fn speed_down(
        &mut self,
        port: &impl CommandPort,
        mask: u32,
        io: bool,
    ) -> Result<bool, BlockError> {
        let mut eflags = if io { EFLAG_IO } else { 0 };
        if self.dubious {
            eflags |= EFLAG_DUBIOUS;
        }
        if categorize(eflags, mask, &mut false) == 0 {
            return Ok(false);
        }
        let at = self.clock.try_start().map_err(|_| BlockError::Timeout)?;
        self.errors.record(eflags, mask, at);
        let verdict = self.verdict()?;
        if verdict & VERDICT_SPEED_DOWN == 0 || !self.lower_speed_limit(port) {
            return Ok(false);
        }
        if verdict & VERDICT_KEEP_ERRORS == 0 {
            self.errors.clear();
        }
        Ok(true)
    }

    /// Linux `ata_eh_speed_down_verdict`.
    fn verdict(&mut self) -> Result<u32, BlockError> {
        let short = self.error_counts(VERDICT_SHORT_US)?;
        let long = self.error_counts(VERDICT_LONG_US)?;
        let dubious = |category| short[CATEGORY_DUBIOUS + category];
        let mut verdict = 0;
        if dubious(CATEGORY_ATA_BUS) + dubious(CATEGORY_TIMEOUT_HSM) > 1 {
            verdict |= VERDICT_SPEED_DOWN | VERDICT_FALLBACK_TO_PIO | VERDICT_KEEP_ERRORS;
        }
        if dubious(CATEGORY_TIMEOUT_HSM) + dubious(CATEGORY_UNKNOWN_DEVICE) > 1 {
            verdict |= VERDICT_NCQ_OFF | VERDICT_KEEP_ERRORS;
        }
        if short[CATEGORY_ATA_BUS] + short[CATEGORY_TIMEOUT_HSM] + short[CATEGORY_UNKNOWN_DEVICE]
            > 6
        {
            verdict |= VERDICT_FALLBACK_TO_PIO;
        }
        if long[CATEGORY_TIMEOUT_HSM] + long[CATEGORY_UNKNOWN_DEVICE] > 3 {
            verdict |= VERDICT_NCQ_OFF;
        }
        if long[CATEGORY_ATA_BUS] + long[CATEGORY_TIMEOUT_HSM] > 3
            || long[CATEGORY_UNKNOWN_DEVICE] > 6
        {
            verdict |= VERDICT_SPEED_DOWN;
        }
        Ok(verdict)
    }

    /// `speed_down_verdict_cb` over `ata_ering_map`: categorized errors
    /// within the window, newest first, up to the first cleared or older one.
    fn error_counts(&mut self, window_us: u64) -> Result<[u32; CATEGORIES], BlockError> {
        let clock = self.clock;
        let mut counts = [0; CATEGORIES];
        let mut verified = false;
        for entry in self.errors.newest() {
            let age = clock
                .try_elapsed_us(entry.at)
                .map_err(|_| BlockError::Timeout)?;
            if entry.eflags & EFLAG_OLD != 0 || age > window_us {
                break;
            }
            counts[categorize(entry.eflags, entry.mask, &mut verified)] += 1;
        }
        Ok(counts)
    }

    /// Linux `sata_down_spd_limit`: drop the highest allowed speed and every
    /// speed at or above the current one; false when already at the bottom.
    fn lower_speed_limit(&mut self, port: &impl CommandPort) -> bool {
        let status = port.read32(PORT_SATA_STATUS);
        let speed = if status & SATA_STATUS_DETECTION == DEVICE_PRESENT {
            (status >> SPEED_SHIFT) & 0xf
        } else {
            self.speed
        };
        let mut mask = self.speed_limit;
        if mask <= 1 {
            return false;
        }
        mask &= !(1 << (fls(mask) - 1));
        if speed > 1 {
            mask &= (1 << (speed - 1)) - 1;
        } else if self.speed != 0 {
            return false;
        }
        if mask == 0 {
            return false;
        }
        self.speed_limit = mask;
        true
    }

    /// Linux `ahci_do_hardreset` with `sata_link_hardreset`: whether an ATA
    /// disk is online afterwards.
    fn hardreset(
        &mut self,
        port: &impl CommandPort,
        timeout_us: u64,
        hotplug: bool,
    ) -> Result<bool, BlockError> {
        let clock = self.clock;
        let start = clock.try_start().map_err(|_| BlockError::Timeout)?;
        let elapsed = || clock.try_elapsed_us(start).map_err(|_| BlockError::Timeout);
        // Its failure is not fatal here, as in Linux.
        let _ = stop_engine(port, clock);
        // Clear the D2H reception area to BSY to wait for the new D2H FIS.
        let mut d2h = [0u8; FIS_BYTES];
        d2h[0] = FIS_REGISTER_HOST_TO_DEVICE;
        d2h[2] = STATUS_BUSY;
        d2h[7] = DEVICE_OBSOLETE;
        self.commands.bytes_mut()[RECEIVED_D2H..RECEIVED_D2H + FIS_BYTES].copy_from_slice(&d2h);
        port.write32(PORT_SATA_ERROR, port.read32(PORT_SATA_ERROR));
        port.write32(PORT_INTERRUPTS, port.read32(PORT_INTERRUPTS));
        // sata_set_spd_needed: with the Phy off, program the limit's speed.
        let target = speed_target(self.speed_limit);
        if (port.read32(PORT_SATA_CONTROL) & SATA_CONTROL_SPEED) >> SPEED_SHIFT != target {
            let control = port.read32(PORT_SATA_CONTROL) & SATA_CONTROL_SPEED;
            port.write32(PORT_SATA_CONTROL, control | SATA_CONTROL_OFFLINE);
            let control = port.read32(PORT_SATA_CONTROL) & !SATA_CONTROL_SPEED;
            port.write32(PORT_SATA_CONTROL, control | target << SPEED_SHIFT);
        }
        let speed = port.read32(PORT_SATA_CONTROL) & SATA_CONTROL_SPEED;
        port.write32(PORT_SATA_CONTROL, speed | SATA_CONTROL_COMRESET);
        port.read32(PORT_SATA_CONTROL);
        clock.delay(COMRESET_HOLD_US);
        // sata_link_resume
        let mut resumed = false;
        let mut control = port.read32(PORT_SATA_CONTROL);
        for _ in 0..RESUME_TRIES {
            port.write32(
                PORT_SATA_CONTROL,
                control & SATA_CONTROL_SPEED | SATA_CONTROL_RESUMED,
            );
            clock.delay(RESUME_SETTLE_US);
            control = port.read32(PORT_SATA_CONTROL);
            if control & SATA_CONTROL_RESUME_MASK == SATA_CONTROL_RESUMED {
                resumed = true;
                break;
            }
        }
        let result = (|| {
            if resumed {
                let timing = if hotplug {
                    DEBOUNCE_HOTPLUG
                } else {
                    DEBOUNCE_NORMAL
                };
                debounce(port, clock, timing, timeout_us.saturating_sub(elapsed()?))?;
                port.write32(PORT_SATA_ERROR, port.read32(PORT_SATA_ERROR));
            }
            if port.read32(PORT_SATA_STATUS) & SATA_STATUS_DETECTION != DEVICE_PRESENT {
                return Ok(false);
            }
            // ata_wait_ready with ahci_check_ready.
            let remaining = timeout_us.saturating_sub(elapsed()?);
            if !clock.wait(remaining, || {
                port.read32(PORT_TASK_FILE) as u8 & STATUS_BUSY == 0
            }) {
                return Err(BlockError::Timeout);
            }
            Ok(true)
        })();
        start_engine(port);
        let online = result?;
        // ata_eh_reset records the current link speed.
        self.speed = (port.read32(PORT_SATA_STATUS) >> SPEED_SHIFT) & 0xf;
        // ahci_dev_classify: only an ATA disk is the same device.
        Ok(online && port.read32(PORT_SIGNATURE) == SIGNATURE_ATA)
    }

    /// Linux `ata_dev_revalidate`: IDENTIFY again and require the same model,
    /// serial and capacity (`ata_dev_same_device`).
    fn revalidate(&mut self, port: &impl CommandPort) -> Result<(), BlockError> {
        let buffer = self.table.physical() + IDENTIFY_DATA as u64;
        self.internal(port, ATA_IDENTIFY, ATA_SECTOR_BYTES as usize, buffer)?;
        let data = &self.table.bytes()[IDENTIFY_DATA..IDENTIFY_DATA + ATA_SECTOR_BYTES as usize];
        let found = identify(data).map_err(|_| DETACHED)?;
        if found.model != self.identity.model
            || found.serial != self.identity.serial
            || found.blocks != self.identity.blocks
        {
            return Err(DETACHED);
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
            let port = self.port;
            let buffer = self.bounce.physical();
            self.internal(&port, ATA_STANDBY_IMMEDIATE, 0, buffer)?;
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

    /// How the disk answers the next issued command.
    #[derive(Clone, Copy)]
    enum Fault {
        /// TFES with this taskfile (status | error << 8).
        TaskFile(u32),
        /// The command never completes.
        Timeout,
        /// An interface fatal error with an unrecovered data SError.
        Interface,
        /// The disk leaves: PhyRdy changes and the link stays down.
        Gone,
    }

    /// A port and link that answer engine, COMRESET and command register
    /// writes like an AHCI port with one ATA disk.
    struct Link {
        registers: RefCell<[u32; 32]>,
        faults: RefCell<alloc::collections::VecDeque<Fault>>,
        writes: RefCell<Vec<(usize, u32)>>,
        issued: Cell<usize>,
        present: Cell<bool>,
        /// The disk's fastest SPD.
        fastest: Cell<u32>,
    }

    const READY: u32 = 0x50;

    impl Link {
        fn new(faults: &[Fault]) -> Self {
            let mut registers = [0u32; 32];
            registers[PORT_COMMAND / 4] =
                COMMAND_START | COMMAND_LIST_RUNNING | COMMAND_FIS_RECEIVE | COMMAND_FIS_RUNNING;
            registers[PORT_TASK_FILE / 4] = READY;
            registers[PORT_SATA_STATUS / 4] = 0x123;
            registers[PORT_SATA_CONTROL / 4] = 0x300;
            registers[PORT_SIGNATURE / 4] = SIGNATURE_ATA;
            Self {
                registers: RefCell::new(registers),
                faults: RefCell::new(faults.iter().copied().collect()),
                writes: RefCell::new(Vec::new()),
                issued: Cell::new(0),
                present: Cell::new(true),
                fastest: Cell::new(2),
            }
        }

        fn writes_to(&self, offset: usize) -> Vec<u32> {
            self.writes
                .borrow()
                .iter()
                .filter(|(at, _)| *at == offset)
                .map(|(_, value)| *value)
                .collect()
        }
    }

    impl CommandPort for Link {
        fn read32(&self, offset: usize) -> u32 {
            self.registers.borrow()[offset / 4]
        }
        fn write32(&self, offset: usize, value: u32) {
            self.writes.borrow_mut().push((offset, value));
            let mut registers = self.registers.borrow_mut();
            match offset {
                PORT_INTERRUPTS | PORT_SATA_ERROR => registers[offset / 4] &= !value,
                PORT_COMMAND => {
                    let mut command = value & !(COMMAND_LIST_RUNNING | COMMAND_FIS_RUNNING);
                    if value & COMMAND_START != 0 {
                        command |= COMMAND_LIST_RUNNING;
                    } else {
                        // Clearing ST clears PxCI.
                        registers[PORT_ISSUE / 4] = 0;
                    }
                    if value & COMMAND_FIS_RECEIVE != 0 {
                        command |= COMMAND_FIS_RUNNING;
                    }
                    registers[PORT_COMMAND / 4] = command;
                }
                PORT_SATA_CONTROL => {
                    registers[offset / 4] = value;
                    match value & SATA_CONTROL_DETECTION {
                        SATA_CONTROL_RESET => {
                            registers[PORT_SATA_STATUS / 4] = 0;
                            registers[PORT_TASK_FILE / 4] = 0x80;
                        }
                        // The link comes up at the fastest speed both allow.
                        0 if self.present.get() => {
                            let limit = (value >> SPEED_SHIFT) & 0xf;
                            let fastest = self.fastest.get();
                            let speed = if limit == 0 {
                                fastest
                            } else {
                                limit.min(fastest)
                            };
                            registers[PORT_SATA_STATUS / 4] = 0x103 | speed << SPEED_SHIFT;
                            registers[PORT_TASK_FILE / 4] = READY;
                        }
                        0 => {}
                        // Phy offline.
                        _ => registers[PORT_SATA_STATUS / 4] = 4,
                    }
                }
                PORT_ISSUE => {
                    assert_ne!(registers[PORT_COMMAND / 4] & COMMAND_LIST_RUNNING, 0);
                    self.issued.set(self.issued.get() + 1);
                    match self.faults.borrow_mut().pop_front() {
                        None => registers[PORT_TASK_FILE / 4] = READY,
                        Some(fault) => {
                            registers[PORT_ISSUE / 4] = value;
                            match fault {
                                Fault::TaskFile(task_file) => {
                                    registers[PORT_TASK_FILE / 4] = task_file;
                                    registers[PORT_INTERRUPTS / 4] |= INTERRUPT_TASK_FILE_ERROR;
                                }
                                Fault::Timeout => registers[PORT_TASK_FILE / 4] = 0xd0,
                                Fault::Interface => {
                                    registers[PORT_INTERRUPTS / 4] |= INTERRUPT_INTERFACE_FATAL;
                                    registers[PORT_SATA_ERROR / 4] |= SERROR_DATA;
                                }
                                Fault::Gone => {
                                    self.present.set(false);
                                    registers[PORT_INTERRUPTS / 4] |= INTERRUPT_PHY_READY_CHANGE;
                                    registers[PORT_SATA_ERROR / 4] |= SERROR_PHY_READY_CHANGE;
                                    registers[PORT_SATA_STATUS / 4] = 0;
                                }
                            }
                        }
                    }
                }
                _ => registers[offset / 4] = value,
            }
        }
    }

    /// IDENTIFY DEVICE data for an LBA48 disk.
    fn identify_page(serial: &str, blocks: u64) -> [u8; 512] {
        let mut page = [0u8; 512];
        let mut put = |index: usize, value: u16| {
            page[2 * index..2 * index + 2].copy_from_slice(&value.to_le_bytes())
        };
        for (words, text) in [(IDENTIFY_SERIAL, serial), (IDENTIFY_MODEL, "Fixture SSD")] {
            let mut bytes = text.as_bytes().to_vec();
            bytes.resize(2 * words.len(), b' ');
            for (index, pair) in words.zip(bytes.chunks(2)) {
                put(index, u16::from_be_bytes([pair[0], pair[1]]));
            }
        }
        put(IDENTIFY_COMMANDS_2, WORD_VALID | COMMANDS_2_LBA48);
        for (offset, index) in IDENTIFY_LBA48_SECTORS.enumerate() {
            put(index, (blocks >> (16 * offset)) as u16);
        }
        page
    }

    /// A disk identified from `identify_page`, answering revalidation with
    /// `page`, on a virtual one-tick-per-microsecond clock.
    fn recovering(page: [u8; 512]) -> (Fixture, crate::test_clock::Guard) {
        let clock = crate::test_clock::virtualize();
        let mut fixture = Fixture::new();
        let found = identify(&identify_page("S1", 1024)).unwrap();
        fixture.disk.identity.model = found.model;
        fixture.disk.identity.serial = found.serial;
        fixture.disk.identity.blocks = found.blocks;
        fixture.disk.clock = Clock {
            ticks_per_microsecond: 1,
        };
        fixture.disk.table.bytes_mut()[IDENTIFY_DATA..IDENTIFY_DATA + 512].copy_from_slice(&page);
        (fixture, clock)
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
                    errors: ErrorRing::default(),
                    dubious: false,
                    speed_limit: u32::MAX,
                    speed: 2,
                },
                _registers: registers,
                _memory: memory,
            }
        }
    }

    #[test]
    fn device_errors_restart_the_engine_and_follow_ata_eh_worth_retry() {
        // An aborted read is retried after the engine restarts.
        let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
        let link = Link::new(&[Fault::TaskFile(0x0451)]);
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
            Ok(())
        );
        assert_eq!(link.issued.get(), 2);
        let starts: Vec<u32> = link
            .writes_to(PORT_COMMAND)
            .iter()
            .map(|command| command & COMMAND_START)
            .collect();
        assert_eq!(starts, [0, COMMAND_START]);
        assert!(link.writes_to(PORT_SATA_CONTROL).is_empty());
        assert!(fixture.disk.fault.is_none());

        // A media error is not retried, and the disk stays usable.
        let link = Link::new(&[Fault::TaskFile(0x4051)]);
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
            Err(BlockError::Device { status: 0x4051 })
        );
        assert_eq!(link.issued.get(), 1);
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
            Ok(())
        );

        // Nor is a plain device error on a command that is not I/O.
        let link = Link::new(&[Fault::TaskFile(0x0451)]);
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_FLUSH_CACHE_EXT, 0, 0, 0, false),
            Err(BlockError::Device { status: 0x0451 })
        );
        assert_eq!(link.issued.get(), 1);

        // I/O is retried five times, as sd allows.
        drop(fixture);
        let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
        let link = Link::new(&[Fault::TaskFile(0x0451); 7]);
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_WRITE_DMA_EXT, 0, 1, 512, true),
            Err(BlockError::Device { status: 0x0451 })
        );
        assert_eq!(link.issued.get(), 6);
        assert!(fixture.disk.fault.is_none());
    }

    #[test]
    fn timeouts_and_link_errors_hard_reset_revalidate_and_retry() {
        for fault in [Fault::Timeout, Fault::Interface, Fault::TaskFile(0x8051)] {
            let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
            fixture.disk.bounce.bytes_mut()[..512].fill(0x44);
            let link = Link::new(&[fault]);
            assert_eq!(
                fixture
                    .disk
                    .issue_on(&link, ATA_WRITE_DMA_EXT, 9, 1, 512, true),
                Ok(())
            );
            // The write, the revalidating IDENTIFY, and the write again.
            assert_eq!(link.issued.get(), 3);
            let controls: Vec<u32> = link
                .writes_to(PORT_SATA_CONTROL)
                .iter()
                .map(|control| control & 0xf0f)
                .collect();
            assert_eq!(controls, [0x301, 0x300]);
            // The retried write still carries its data.
            assert!(
                fixture.disk.bounce.bytes()[..512]
                    .iter()
                    .all(|byte| *byte == 0x44)
            );
            assert_eq!(fixture.disk.table.bytes()[2], ATA_WRITE_DMA_EXT);
            assert_eq!(
                fixture.disk.commands.bytes()[RECEIVED_D2H..RECEIVED_D2H + 8],
                [0x27, 0, 0x80, 0, 0, 0, 0, 0xa0]
            );
            assert!(fixture.disk.fault.is_none());
        }
    }

    #[test]
    fn speed_down_verdicts_follow_ata_eh_speed_down_verdict() {
        let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
        let disk = &mut fixture.disk;
        // Errors `minutes` old, newest last.
        let mut judge = |errors: &[(u32, u32, u64)]| {
            disk.errors = ErrorRing::default();
            let now = disk.clock.try_start().unwrap();
            for &(eflags, mask, minutes) in errors {
                disk.errors.record(eflags, mask, now - minutes * 60_000_000);
            }
            disk.verdict().unwrap()
        };
        let io = EFLAG_IO;
        let dubious = EFLAG_IO | EFLAG_DUBIOUS;
        let spdn = VERDICT_SPEED_DOWN;
        // Two unverified bus errors or timeouts within five minutes.
        assert_eq!(
            judge(&[(dubious, ERR_ATA_BUS, 4), (dubious, ERR_TIMEOUT, 0)]),
            spdn | VERDICT_FALLBACK_TO_PIO | VERDICT_KEEP_ERRORS
        );
        assert_eq!(
            judge(&[(dubious, ERR_ATA_BUS, 6), (dubious, ERR_TIMEOUT, 0)]),
            0
        );
        // A newer verified error makes older errors verified too.
        assert_eq!(
            judge(&[
                (dubious, ERR_ATA_BUS, 2),
                (dubious, ERR_ATA_BUS, 1),
                (io, ERR_HSM, 0)
            ]),
            0
        );
        // Unverified timeouts or device errors turn NCQ off.
        assert_eq!(
            judge(&[(dubious, ERR_DEVICE, 1), (dubious, ERR_HSM, 0)]),
            VERDICT_NCQ_OFF | VERDICT_KEEP_ERRORS
        );
        // More than three bus errors or timeouts within ten minutes.
        let four = [
            (io, ERR_ATA_BUS, 9),
            (0, ERR_TIMEOUT, 7),
            (io, ERR_HSM, 3),
            (io, ERR_ATA_BUS | ERR_DEVICE, 0),
        ];
        assert_eq!(judge(&four), spdn);
        let mut expired = four;
        expired[0].2 = 11;
        assert_eq!(judge(&expired), 0);
        // More than six unknown device errors; HSM and media errors count only
        // for I/O and unknown device errors.
        let mut seven = [(io, ERR_DEVICE, 0); 7];
        assert_eq!(
            judge(&seven),
            spdn | VERDICT_NCQ_OFF | VERDICT_FALLBACK_TO_PIO
        );
        seven[0] = (io, ERR_DEVICE | ERR_MEDIA, 0);
        assert_eq!(judge(&seven), VERDICT_NCQ_OFF);
        seven[0] = (0, ERR_HSM, 0);
        assert_eq!(judge(&seven), VERDICT_NCQ_OFF);
        // A cleared history stops the scan.
        judge(&four[..3]);
        disk.errors.clear();
        let now = disk.clock.try_start().unwrap();
        disk.errors.record(io, ERR_ATA_BUS, now);
        assert_eq!(disk.verdict().unwrap(), 0);
        // The ring keeps the newest 32.
        for _ in 0..40 {
            disk.errors.record(io, ERR_DEVICE, now);
        }
        assert_eq!(disk.errors.newest().count(), ERROR_RING);
    }

    #[test]
    fn repeated_link_errors_lower_the_sata_speed_like_linux() {
        let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
        let link = Link::new(&[]);
        link.fastest.set(3);
        link.registers.borrow_mut()[PORT_SATA_STATUS / 4] = 0x133;
        fixture.disk.speed = 3;
        let controls = |link: &Link| -> Vec<u32> {
            link.writes_to(PORT_SATA_CONTROL)
                .iter()
                .map(|control| control & 0xfff)
                .collect()
        };
        // Three verified bus errors only reset the link.
        for _ in 0..3 {
            link.faults.borrow_mut().push_back(Fault::Interface);
            assert_eq!(
                fixture
                    .disk
                    .issue_on(&link, ATA_WRITE_DMA_EXT, 9, 1, 512, true),
                Ok(())
            );
        }
        assert_eq!(controls(&link), [0x301u32, 0x300].repeat(3));
        // The fourth lowers the limit below 6 Gbps, turning the Phy off to
        // program it, and clears the history.
        link.writes.borrow_mut().clear();
        link.faults.borrow_mut().push_back(Fault::Interface);
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_WRITE_DMA_EXT, 9, 1, 512, true),
            Ok(())
        );
        assert_eq!(fixture.disk.speed_limit, 0b11);
        assert_eq!(controls(&link), [0x304, 0x324, 0x321, 0x320]);
        assert_eq!(fixture.disk.speed, 2);
        assert_eq!(
            fixture
                .disk
                .errors
                .newest()
                .filter(|e| e.eflags & EFLAG_OLD == 0)
                .count(),
            0
        );
        // Four more reach 1.5 Gbps, the bottom.
        for _ in 0..4 {
            link.faults.borrow_mut().push_back(Fault::Interface);
            fixture
                .disk
                .issue_on(&link, ATA_WRITE_DMA_EXT, 9, 1, 512, true)
                .unwrap();
        }
        assert_eq!(fixture.disk.speed_limit, 0b1);
        assert_eq!(fixture.disk.speed, 1);
        for _ in 0..4 {
            link.faults.borrow_mut().push_back(Fault::Interface);
            fixture
                .disk
                .issue_on(&link, ATA_WRITE_DMA_EXT, 9, 1, 512, true)
                .unwrap();
        }
        assert_eq!(fixture.disk.speed_limit, 0b1);
        assert!(fixture.disk.fault.is_none());

        // Before a verified transfer, two bus errors suffice and the
        // history is kept. A flush transfers no data and verifies nothing.
        let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
        fixture.disk.dubious = true;
        let link = Link::new(&[]);
        for _ in 0..2 {
            link.faults.borrow_mut().push_back(Fault::Interface);
            assert_eq!(
                fixture
                    .disk
                    .issue_on(&link, ATA_FLUSH_CACHE_EXT, 0, 0, 0, false),
                Ok(())
            );
        }
        assert_eq!(fixture.disk.speed_limit, 0b1);
        assert_eq!(fixture.disk.errors.newest().count(), 2);
        assert!(fixture.disk.dubious);
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
            Ok(())
        );
        assert!(!fixture.disk.dubious);

        // Device errors that need no reset get one when they slow the link.
        let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
        let link = Link::new(&[Fault::TaskFile(0x0451); 6]);
        assert!(
            fixture
                .disk
                .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false)
                .is_err()
        );
        assert!(controls(&link).is_empty());
        link.faults.borrow_mut().push_back(Fault::TaskFile(0x0451));
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
            Ok(())
        );
        assert_eq!(fixture.disk.speed_limit, 0b1);
        assert_eq!(controls(&link), [0x304, 0x314, 0x311, 0x310]);
    }

    #[test]
    fn a_disk_that_leaves_or_changes_is_disabled() {
        let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
        let link = Link::new(&[Fault::Gone]);
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
            Err(DETACHED)
        );
        assert_eq!(fixture.disk.fault, Some(DETACHED));
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
            Err(DETACHED)
        );
        assert_eq!(link.issued.get(), 1);

        for page in [identify_page("S2", 1024), identify_page("S1", 2048)] {
            let (mut fixture, _clock) = recovering(page);
            let link = Link::new(&[Fault::Timeout]);
            assert_eq!(
                fixture
                    .disk
                    .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
                Err(DETACHED)
            );
            assert_eq!(link.issued.get(), 2);
            assert_eq!(fixture.disk.fault, Some(DETACHED));
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
    fn acknowledged_completions_keep_the_real_command_path_usable() {
        let mut fixture = Fixture::new();
        let model = Link::new(&[]);
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
