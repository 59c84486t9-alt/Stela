//! AHCI host bus adapters with SATA disks, one polled command slot per port.
//! Controller setup follows Linux `drivers/ata/ahci.c` and `libahci.c` at
//! a804c5742bff224d4cb4d25dd383554d598be32b: firmware-programmed capability
//! and port registers survive HBA reset, legacy Intel port enables are set,
//! and each port fails on its own. A failed command goes through libata's
//! error handler: the AHCI error interrupt and taskfile are classified as
//! `ahci_error_intr` and `ata_eh_link_autopsy` do, the engine restarts or the
//! link is hard reset and the disk revalidated, and sd's retries apply.
use crate::{
    Clock, Deadline, Handoff,
    block::{
        BlockDevice, BlockError, Command, Features, Finished, Identity, Sense, SenseCompletion,
        Transport, ascii,
    },
    bus::{
        dma::{DmaAllocator, DmaBuffer},
        mmio::Mmio,
        pci::{ConfigSpace, Function},
    },
    registers,
};
use alloc::{format, vec::Vec};
use core::sync::atomic::{Ordering, fence};

mod quirks;

pub const CLASS: [u8; 3] = [0x01, 0x06, 0x01];
/// `ahci_pci_tbl`: AMD uses the RAID class only for AHCI controllers.
const VENDOR_AMD: u16 = 0x1022;
const CLASS_RAID: [u8; 3] = [0x01, 0x04, 0x00];

/// Whether `ahci_pci_tbl` binds the function: the AHCI class, or an AMD
/// function of the RAID class.
pub fn matches<C>(function: &Function<C>) -> bool {
    matches_identity(&function.identity())
}

/// Candidate selection from copied identity DATA; owned attachment still
/// revalidates actual configuration and platform requirements.
pub fn matches_identity(function: &crate::bus::pci::Identity) -> bool {
    function.class == CLASS || function.vendor == VENDOR_AMD && function.class == CLASS_RAID
}

const CAPABILITIES: usize = 0x00;
const GLOBAL_CONTROL: usize = 0x04;
const PORTS_IMPLEMENTED: usize = 0x0c;
const CAPABILITIES_2: usize = 0x24;
const HANDOFF: usize = 0x28;

const CAP_64BIT: u32 = 1 << 31;
/// CAP.SNCQ: Linux sets `ATA_FLAG_NCQ` and `ATA_FLAG_FPDMA_AA` from it.
const CAP_NCQ: u32 = 1 << 30;
const CAP_STAGGERED_SPIN_UP: u32 = 1 << 27;
/// CAP.SALP, SSC, PSC and SXS; CAP2.SDS.
const CAP_AGGRESSIVE_LPM: u32 = 1 << 26;
const CAP_SLUMBER: u32 = 1 << 14;
const CAP_PARTIAL: u32 = 1 << 13;
const CAP_EXTERNAL: u32 = 1 << 5;
const CAP2_DEVICE_SLEEP: u32 = 1 << 3;
const CAP2_AGGRESSIVE_DEVICE_SLEEP: u32 = 1 << 4;
/// CAP.NP: the number of ports, minus one.
const CAP_PORTS: u32 = 0x1f;
/// CAP.NCS: the command slots per port, minus one.
const CAP_SLOTS_SHIFT: u32 = 8;
const CAP_SLOTS: u32 = 0x1f;
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
const PORT_SATA_ACTIVE: usize = 0x34;
const PORT_DEVICE_SLEEP: usize = 0x44;
/// PxDEVSLP: aggressive DevSleep enabled, and DevSleep present.
const DEVICE_SLEEP_AGGRESSIVE: u32 = 1 << 0;
const DEVICE_SLEEP_PRESENT: u32 = 1 << 1;
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
/// PxCMD.HPCP and ESP, ALPE and ASP, and ICC's Active request.
const COMMAND_HOTPLUG: u32 = 1 << 18;
const COMMAND_EXTERNAL: u32 = 1 << 21;
const COMMAND_AGGRESSIVE_LPM: u32 = 1 << 26;
const COMMAND_AGGRESSIVE_SLUMBER: u32 = 1 << 27;
const COMMAND_INTERFACE_ACTIVE: u32 = 1 << 28;
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
/// `ATA_SENSE`: sense data is available.
const STATUS_SENSE: u8 = 1 << 1;
/// `ATA_CORR`: corrected data error.
const STATUS_CORRECTED: u8 = 1 << 2;
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
/// SControl.IPM: transitions to Partial, Slumber and DevSleep disallowed.
const SATA_CONTROL_NO_PARTIAL: u32 = 0x100;
const SATA_CONTROL_NO_SLUMBER: u32 = 0x200;
const SATA_CONTROL_NO_DEVICE_SLEEP: u32 = 0x400;
const SATA_CONTROL_POWER: u32 = 0x700;
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
const IDENTIFY_CONFIG: usize = 0;
const IDENTIFY_SERIAL: core::ops::Range<usize> = 10..20;
const IDENTIFY_FIRMWARE: core::ops::Range<usize> = 23..27;
/// `ata_id_is_sata` reads the major version and hardware reset words.
const IDENTIFY_MAJOR_VERSION: usize = 80;
const IDENTIFY_HARDWARE_RESET: usize = 93;
/// Word 49 bit 11: IORDY supported; word 51 bits 15:8: the old PIO mode;
/// word 53 bits 1 and 2: words 64 and 88 valid; words 64 and 88: advanced
/// PIO and UDMA modes (`ata_id_xfermask`).
const IDENTIFY_CAPABILITY: usize = 49;
const CAPABILITY_IORDY: u16 = 1 << 11;
const IDENTIFY_OLD_PIO: usize = 51;
const IDENTIFY_FIELD_VALID: usize = 53;
const FIELD_VALID_PIO: u16 = 1 << 1;
const FIELD_VALID_UDMA: u16 = 1 << 2;
const IDENTIFY_PIO_MODES: usize = 64;
const IDENTIFY_UDMA_MODES: usize = 88;
/// Word 128 bits 2:0: security supported, enabled and locked.
const IDENTIFY_SECURITY: usize = 128;
/// SATA capabilities (word 76, HIPM in bit 9) and features supported (word
/// 78, DIPM in bit 3).
const IDENTIFY_SATA_CAPABILITY: usize = 76;
/// `ata_id_queue_depth`: the queued commands the disk takes, minus one.
const IDENTIFY_QUEUE_DEPTH: usize = 75;
const QUEUE_DEPTH_MASK: u16 = 0x1f;
const IDENTIFY_SATA_FEATURES: usize = 78;
const SATA_CAPABILITY_HIPM: u16 = 1 << 9;
const SATA_CAPABILITY_NCQ: u16 = 1 << 8;
const SATA_FEATURE_DIPM: u16 = 1 << 3;
const SATA_FEATURE_FPDMA_AA: u16 = 1 << 2;
const SATA_FEATURE_NCQ_AUTOSENSE: u16 = 1 << 7;
const SATA_FEATURE_DEVICE_SLEEP: u16 = 1 << 8;
const SECURITY_LOCKED: u16 = 0x7;
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
/// Word 169 bit 0: DATA SET MANAGEMENT with the TRIM bit.
const IDENTIFY_DATA_SET_MANAGEMENT: usize = 169;
const DATA_SET_MANAGEMENT_TRIM: u16 = 1;
/// Word 86 bit 15: words 119 and 120 are valid; their bit 6 is Sense Data
/// Reporting supported and enabled.
const IDENTIFY_ENABLED_2: usize = 86;
const ENABLED_2_WORDS_119_120: u16 = 1 << 15;
const IDENTIFY_COMMANDS_3: usize = 119;
const IDENTIFY_ENABLED_3: usize = 120;
const SENSE_DATA_REPORTING: u16 = 1 << 6;
/// Word 119: READ LOG DMA EXT.
const COMMANDS_3_READ_LOG_DMA: u16 = 1 << 3;
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
const COMMAND_HEADER_BYTES: usize = 32;
const RECEIVED_FIS_BYTES: usize = 256;
/// The received PIO Setup FIS a PIO data command ends with.
const RECEIVED_PIO: usize = COMMAND_LIST_BYTES + 0x20;
/// The received D2H Register FIS, set to BSY before a hardreset.
const RECEIVED_D2H: usize = COMMAND_LIST_BYTES + 0x40;
/// The Set Device Bits FIS a queued command completes with.
const RECEIVED_SDB: usize = COMMAND_LIST_BYTES + 0x58;
/// FIS types (SATA 3.5 §10.5): D2H Register, PIO Setup, Set Device Bits.
const FIS_REGISTER_DEVICE_TO_HOST: u8 = 0x34;
const FIS_PIO_SETUP: u8 = 0x5f;
const FIS_SET_DEVICE_BITS: u8 = 0xa1;
/// Polls of the received-FIS area between reads of PxIS and PxCI, which a
/// hypervisor traps, while a command runs: a failure may post no FIS.
const REGISTER_POLL_INTERVAL: u32 = 64;
const FIS_BYTES: usize = 20;
const COMMAND_TABLE_BYTES: usize = 4096;
const COMMAND_TABLE_ALIGN: usize = 128;
/// Revalidation IDENTIFY data, in the command table past its one PRDT entry,
/// so a failed write's data stays in the bounce buffer for its retry.
const IDENTIFY_DATA: usize = 0x200;
/// Where log pages are read, past the IDENTIFY data.
const LOG_DATA: usize = 0x400;

/// Command header DW0: FIS length in dwords, direction, PRDT entries.
const COMMAND_FIS_DWORDS: u32 = 5;
const COMMAND_WRITE_SHIFT: u32 = 6;
const COMMAND_PRDT_SHIFT: u32 = 16;

const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA_EXT: u8 = 0x35;
const ATA_READ_FPDMA_QUEUED: u8 = 0x60;
const ATA_WRITE_FPDMA_QUEUED: u8 = 0x61;
const ATA_READ_LOG_EXT: u8 = 0x2f;
const ATA_READ_LOG_DMA_EXT: u8 = 0x47;
/// The NCQ Command Error log (`ATA_LOG_SATA_NCQ`): byte 0 holds NQ, set
/// when no queued command failed, and the failed command's tag.
const LOG_SATA_NCQ: u8 = 0x10;
const LOG_NCQ_NQ: u8 = 0x80;
const LOG_NCQ_TAG: u8 = 0x1f;
/// The general purpose log directory, and the IDENTIFY DEVICE data log
/// with its SATA Settings page.
const LOG_DIRECTORY: u8 = 0x00;
const LOG_IDENTIFY_DEVICE: u8 = 0x30;
const LOG_SATA_SETTINGS: u8 = 0x08;
const ATA_FLUSH_CACHE: u8 = 0xe7;
const ATA_FLUSH_CACHE_EXT: u8 = 0xea;
const ATA_STANDBY_IMMEDIATE: u8 = 0xe0;
/// DATA SET MANAGEMENT, its TRIM feature, and the ranges one 512-byte block
/// of them holds, each at most 65535 sectors (Linux `ATA_MAX_TRIM_RNUM`).
const ATA_DATA_SET_MANAGEMENT: u8 = 0x06;
const TRIM: u16 = 1;
const TRIM_RANGES: u64 = 64;
const TRIM_RANGE_SECTORS: u64 = 0xffff;
const ATA_IDENTIFY: u8 = 0xec;
const ATA_SET_FEATURES: u8 = 0xef;
/// `SETFEATURES_XFER`, with the transfer mode in the count.
const FEATURE_TRANSFER_MODE: u8 = 0x03;
/// `XFER_PIO_0`, `XFER_PIO_2` and `XFER_UDMA_0`.
const MODE_PIO_0: u8 = 0x08;
const MODE_PIO_2: u8 = 0x0a;
const MODE_UDMA_0: u8 = 0x40;
/// `ahci_port_info`: PIO 0-4 and UDMA 0-6, no MWDMA.
const HOST_PIO_MASK: u32 = 0x1f;
const HOST_UDMA_MASK: u32 = 0x7f;
/// `ATA_UDMA_MASK_40C`: UDMA 0-2.
const UDMA_MASK_40_WIRE: u32 = 0x07;
const ATA_REQUEST_SENSE_DATA_EXT: u8 = 0x0b;
/// `SETFEATURE_SENSE_DATA`, enabled with a count of one.
const FEATURE_SENSE_DATA: u8 = 0xc3;
/// SET FEATURES enabling or disabling a SATA feature: DIPM.
const FEATURE_SATA_ENABLE: u8 = 0x10;
const FEATURE_SATA_DISABLE: u8 = 0x90;
const SATA_DIPM: u16 = 0x03;
/// First-party DMA auto-activation.
const SATA_FPDMA_AA: u16 = 0x02;
const SATA_DEVICE_SLEEP: u16 = 0x09;
/// Linux's `ATA_LPM_*` policies this driver uses: unknown before the first
/// configuration, maximum power, and CONFIG_SATA_MOBILE_LPM_POLICY's default.
const LPM_UNKNOWN: u8 = 0;
const LPM_MAX_POWER: u8 = 1;
const LPM_MED_POWER_WITH_DIPM: u8 = 3;
/// `ahci_set_lpm`'s wait for the interface to leave a low-power state.
const LPM_WAKE_US: u64 = 10_000;
/// The highest sense key REQUEST SENSE DATA EXT may report.
const SENSE_COMPLETED: u8 = 0x0f;

const BOUNCE_BYTES: usize = 128 * 1024;
/// The queued commands a port runs at once, each in its own slot with its
/// own command table and bounce buffer, as NVMe's tags bound them; Linux
/// queues up to `ATA_MAX_QUEUE` (32) without bounce memory.
const DEPTH: usize = 8;
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
/// `-EAGAIN` from configuration: another EH round without prejudice.
const AGAIN: BlockError = BlockError::Protocol("the SATA link needs another reset");

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
    /// `ata_id_sense_reporting_enabled` for the last IDENTIFY data read.
    sense_reporting: bool,
    /// The last IDENTIFY data's transfer modes, the device's own masks that
    /// speed-downs narrow, the configured mode and `spdn_cnt`.
    transfer: Transfer,
    pio_mask: u32,
    udma_mask: u32,
    mode: u8,
    step_downs: u8,
    /// `ata_id_is_locked` for the last IDENTIFY data read.
    locked: bool,
    lpm: Lpm,
    ncq: Ncq,
    /// `ata_id_has_read_log_dma_ext` for the last IDENTIFY data, and
    /// `ATA_QUIRK_NO_DMA_LOG`, set for good when READ LOG DMA EXT fails.
    log_dma: bool,
    no_dma_log: bool,
    /// `dev->quirks`: the table's, which configuration accumulates.
    quirks: u32,
    /// `ATA_DFLAG_DEVSLP`: the disk has DevSleep and its SATA Settings page.
    devslp: bool,
    /// Slots 1 and up's command tables and bounce buffers, for queued
    /// commands; slot 0's are `table` and `bounce`.
    slots: Vec<Slot>,
    /// The block commands started on the port, each in its own slot, and
    /// the next one's tag.
    running: Vec<Running>,
    next_tag: u32,
    /// Looks at the port since a command was last launched alone.
    looks: u32,
}

/// A slot's command table and bounce buffer.
struct Slot {
    table: DmaBuffer,
    bounce: DmaBuffer,
}

/// Task-file registers and the DMA region encoded for one command issue.
struct AtaRequest {
    command: u8,
    feature: u16,
    lba: u64,
    count: u16,
    bytes: usize,
    write: bool,
    buffer: u64,
}

/// A command issued in its slot, awaiting its ending FIS or an error.
struct Launched {
    slot: usize,
    queued: bool,
    deadline: Deadline,
}

/// One look at the port's launched commands ([`AhciDisk::look`]): the
/// slots that completed, and a failure with the slots it is charged to
/// unless the NCQ error log names one.
struct Seen {
    done: u32,
    failure: Option<Failure>,
    blamed: u32,
}

/// One command through libata's error handling ([`AhciDisk::issue_with`]),
/// a step at a time.
struct Issue {
    /// The slot whose command table and bounce buffer it uses.
    slot: usize,
    command: u8,
    feature: u16,
    lba: u64,
    count: u16,
    bytes: usize,
    write: bool,
    /// Only reads and writes carry ATA_QCFLAG_IO.
    io: bool,
    /// When the command was first prepared, for sd's runtime limit.
    prepared: u64,
    retries: u32,
    launched: Option<Launched>,
    /// The delay sense data asked for before the command runs again.
    resume: Option<Deadline>,
}

/// A started block command, run a bounce buffer's worth at a time in its
/// slot.
struct Running {
    tag: u32,
    slot: usize,
    command: Command,
    /// Bytes done; a flush counts one once complete.
    done: usize,
    data: Vec<u8>,
    issue: Option<Issue>,
    result: Option<Finished>,
}

/// The received FIS types a command ends with, and where they land: a
/// queued command's Set Device Bits, another's D2H Register, or for PIO
/// data a PIO Setup, which precedes the data, from when on the registers
/// are read every look.
fn ending(queued: bool) -> &'static [(usize, u8)] {
    if queued {
        &[(RECEIVED_SDB, FIS_SET_DEVICE_BITS)]
    } else {
        &[
            (RECEIVED_D2H, FIS_REGISTER_DEVICE_TO_HOST),
            (RECEIVED_PIO, FIS_PIO_SETUP),
        ]
    }
}

/// NCQ as Linux `ata_dev_config_ncq` configures it. A queued command's tag
/// is its slot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Ncq {
    /// CAP.SNCQ.
    host: bool,
    /// CAP.NCS + 1, and `ata_id_queue_depth` of the last IDENTIFY data.
    host_slots: usize,
    depth: usize,
    /// `ATA_DFLAG_NCQ`: the host and the last IDENTIFY data support it.
    device: bool,
    /// `ATA_DFLAG_NCQ_OFF`: a speed-down turned it off for good.
    off: bool,
    /// `ata_id_has_ncq_autosense`.
    autosense: bool,
    /// `ATA_QUIRK_BROKEN_FPDMA_AA`: enabling auto-activation failed.
    aa_broken: bool,
}

impl Ncq {
    /// `ata_ncq_enabled`.
    fn enabled(&self) -> bool {
        self.device && !self.off
    }
}

/// Linux link power management for one port.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Lpm {
    capabilities: u32,
    capabilities_2: u32,
    /// Not `ATA_LFLAG_NO_LPM`: an internal, LPM-capable port whose
    /// configuration has not failed with one try left.
    allowed: bool,
    /// `link->lpm_policy`.
    policy: u8,
    /// `ata_id_has_hipm` and `ata_id_has_dipm` for the last IDENTIFY data.
    hipm: bool,
    dipm: bool,
    /// `ATA_QUIRK_NOLPM`: the device's LPM is broken; max_power is forced.
    broken: bool,
}

impl Lpm {
    /// Linux `ahci_mark_external_port` and `ahci_update_initial_lpm_policy`:
    /// none on a hotplug-capable or eSATA port, where LPM hides removal, or
    /// on a host without Partial, Slumber and DevSleep.
    fn new(capabilities: u32, capabilities_2: u32, command: u32) -> Self {
        let external = command & COMMAND_EXTERNAL != 0 && capabilities & CAP_EXTERNAL != 0
            || command & COMMAND_HOTPLUG != 0;
        let states = capabilities & (CAP_PARTIAL | CAP_SLUMBER) != 0
            || capabilities_2 & CAP2_DEVICE_SLEEP != 0;
        Self {
            capabilities,
            capabilities_2,
            allowed: !external && states,
            policy: LPM_UNKNOWN,
            ..Self::default()
        }
    }

    /// `ap->target_lpm_policy`. The s2idle upgrade to the minimum-power
    /// policies needs the FADT low-power S0 flag, which the handoff does not
    /// carry; the S3 default stands.
    fn target(&self) -> u8 {
        if self.allowed && !self.broken {
            LPM_MED_POWER_WITH_DIPM
        } else {
            LPM_MAX_POWER
        }
    }

    /// Not `ATA_FLAG_NO_DIPM`: the host has both Partial and Slumber.
    fn host_dipm(&self) -> bool {
        self.capabilities & (CAP_PARTIAL | CAP_SLUMBER) == CAP_PARTIAL | CAP_SLUMBER
    }
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

    /// `ata_ering_top`: the newest entry, if any.
    fn top(&mut self) -> Option<&mut Recorded> {
        Some(&mut self.entries[self.cursor]).filter(|entry| entry.mask != 0)
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
    /// Sense Data Reporting supported, and enabled.
    sense_reporting: (bool, bool),
    transfer: Transfer,
    /// `ata_id_is_locked`.
    locked: bool,
    /// `ata_id_has_hipm` and `ata_id_has_dipm`.
    hipm: bool,
    dipm: bool,
    /// `ata_id_has_ncq`, `ata_id_has_fpdma_aa`, `ata_id_has_ncq_autosense`
    /// and `ata_id_has_read_log_dma_ext`.
    ncq: bool,
    fpdma_aa: bool,
    ncq_autosense: bool,
    read_log_dma: bool,
    /// `ata_id_queue_depth`.
    queue_depth: usize,
    /// `ata_dev_quirks` for the model number and firmware revision.
    quirks: u32,
    /// Word 76's supported SATA speeds.
    sata_speeds: u16,
    /// `ata_id_has_devslp`.
    devslp: bool,
    /// `ata_id_has_trim`.
    trim: bool,
}

/// What `ata_id_xfermask`, `ata_id_has_iordy` and `ata_id_is_cfa` read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Transfer {
    pio: u32,
    udma: u32,
    iordy: bool,
    compact_flash: bool,
    /// `ata_id_is_sata`.
    sata: bool,
}

impl Transfer {
    fn from_identify(word: impl Fn(usize) -> u16) -> Self {
        let pio = if word(IDENTIFY_FIELD_VALID) & FIELD_VALID_PIO != 0 {
            u32::from(word(IDENTIFY_PIO_MODES) & 0x03) << 3 | 0x07
        } else {
            match word(IDENTIFY_OLD_PIO) >> 8 {
                mode @ 0..5 => (2 << mode) - 1,
                _ => 1,
            }
        };
        let udma = if word(IDENTIFY_FIELD_VALID) & FIELD_VALID_UDMA != 0 {
            u32::from(word(IDENTIFY_UDMA_MODES) & 0xff)
        } else {
            0
        };
        let config = word(IDENTIFY_CONFIG);
        Self {
            pio,
            udma,
            iordy: word(IDENTIFY_CAPABILITY) & CAPABILITY_IORDY != 0,
            compact_flash: config == 0x848a
                || config == 0x844a
                || word(IDENTIFY_COMMANDS_2) & 0xc004 == 0x4004,
            sata: word(IDENTIFY_HARDWARE_RESET) == 0 && word(IDENTIFY_MAJOR_VERSION) as i16 >= 0x20,
        }
    }
}

/// `ata_xfer_mask2mode` for one mode class: its highest mode.
fn highest_mode(mask: u32, base: u8) -> Option<u8> {
    (mask != 0).then(|| base + (fls(mask) - 1) as u8)
}

/// Linux `ATA_DNXFER_*` steps.
#[derive(Clone, Copy)]
enum StepDown {
    Pio,
    Dma,
    FortyWire,
}

/// Linux `ata_id_has_sense_reporting` and `ata_id_sense_reporting_enabled`.
fn sense_reporting(word: impl Fn(usize) -> u16) -> (bool, bool) {
    let valid = |index| word(index) & WORD_VALID_MASK == WORD_VALID;
    let supported = word(IDENTIFY_ENABLED_2) & ENABLED_2_WORDS_119_120 != 0
        && valid(IDENTIFY_COMMANDS_3)
        && word(IDENTIFY_COMMANDS_3) & SENSE_DATA_REPORTING != 0;
    let enabled = supported
        && valid(IDENTIFY_ENABLED_3)
        && word(IDENTIFY_ENABLED_3) & SENSE_DATA_REPORTING != 0;
    (supported, enabled)
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
    // ata_id_c_string: up to a NUL, without trailing spaces.
    let c_string = |words: core::ops::Range<usize>| {
        let mut bytes: Vec<u8> = words.flat_map(|index| word(index).to_be_bytes()).collect();
        if let Some(end) = bytes.iter().position(|byte| *byte == 0) {
            bytes.truncate(end);
        }
        while bytes.last() == Some(&b' ') {
            bytes.pop();
        }
        bytes
    };
    let sata_valid = !matches!(word(IDENTIFY_SATA_CAPABILITY), 0 | 0xffff);
    Ok(Identified {
        model: string(IDENTIFY_MODEL),
        serial: string(IDENTIFY_SERIAL),
        blocks,
        block_size,
        flush: flush_command(word),
        sense_reporting: sense_reporting(word),
        transfer: Transfer::from_identify(word),
        locked: word(IDENTIFY_SECURITY) & SECURITY_LOCKED == SECURITY_LOCKED,
        hipm: sata_valid && word(IDENTIFY_SATA_CAPABILITY) & SATA_CAPABILITY_HIPM != 0,
        dipm: sata_valid && word(IDENTIFY_SATA_FEATURES) & SATA_FEATURE_DIPM != 0,
        ncq: word(IDENTIFY_SATA_CAPABILITY) & SATA_CAPABILITY_NCQ != 0,
        fpdma_aa: sata_valid && word(IDENTIFY_SATA_FEATURES) & SATA_FEATURE_FPDMA_AA != 0,
        ncq_autosense: word(IDENTIFY_SATA_FEATURES) & SATA_FEATURE_NCQ_AUTOSENSE != 0,
        read_log_dma: word(IDENTIFY_ENABLED_2) & ENABLED_2_WORDS_119_120 != 0
            && word(IDENTIFY_COMMANDS_3) & COMMANDS_3_READ_LOG_DMA != 0,
        queue_depth: usize::from(word(IDENTIFY_QUEUE_DEPTH) & QUEUE_DEPTH_MASK) + 1,
        quirks: quirks::quirks(&c_string(IDENTIFY_MODEL), &c_string(IDENTIFY_FIRMWARE)),
        sata_speeds: word(IDENTIFY_SATA_CAPABILITY) & 0xe,
        devslp: word(IDENTIFY_SATA_FEATURES) & SATA_FEATURE_DEVICE_SLEEP != 0,
        trim: word(IDENTIFY_DATA_SET_MANAGEMENT) & DATA_SET_MANAGEMENT_TRIM != 0,
    })
}

/// A failed command as libata's error handler sees it.
#[derive(Clone, Debug)]
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
    /// The status reported sense data, without a device fault.
    sense_reported: bool,
    /// `ATA_QCFLAG_SENSE_VALID`: the sense data fetched for it.
    sense: Option<Sense>,
    /// PxIS's error bits and SError.
    interrupts: u32,
    serror: u32,
    /// A queued command failed.
    queued: bool,
    /// The slots of the queued commands it reached (`link->sactive`), and
    /// the one the NCQ Command Error log named.
    slots: u32,
    named: Option<usize>,
    /// The result taskfile's status and error (`qc->result_tf`), captured
    /// from the FIS the command completed with.
    result: [u8; 2],
}

impl Failure {
    /// A failure no command analysis applies to.
    fn new(error: BlockError) -> Self {
        Self {
            error,
            mask: 0,
            frozen: false,
            reset: false,
            hotplug: false,
            sense_reported: false,
            sense: None,
            interrupts: 0,
            serror: 0,
            queued: false,
            slots: 0,
            named: None,
            result: [0; 2],
        }
    }

    /// `ata_exec_internal`'s minimal analysis gives exactly `AC_ERR_DEV`:
    /// the device refused the command, which did not time out.
    fn refused(&self) -> bool {
        self.mask & ERR_TIMEOUT == 0
            && (self.interrupts & INTERRUPT_TASK_FILE_ERROR != 0
                || self.result[0] & (STATUS_ERROR | STATUS_FAULT) != 0)
    }
}

/// Linux `ata_to_sense_error`, from the 3ware translation table: the error
/// register's best match first, then the status register.
fn translate_error(status: u8, error: u8) -> Sense {
    const ERRORS: [(u8, u8, u8, u8); 13] = [
        (0xd1, Sense::ABORTED_COMMAND, 0x00, 0x00),
        (0xd0, Sense::ABORTED_COMMAND, 0x00, 0x00),
        (0x61, Sense::HARDWARE_ERROR, 0x00, 0x00),
        (0x84, Sense::ABORTED_COMMAND, 0x47, 0x00),
        (0x37, Sense::NOT_READY, 0x04, 0x00),
        (0x09, Sense::NOT_READY, 0x04, 0x00),
        (0x01, Sense::MEDIUM_ERROR, 0x13, 0x00),
        (0x02, Sense::HARDWARE_ERROR, 0x00, 0x00),
        (0x08, Sense::NOT_READY, 0x04, 0x00),
        (0x10, Sense::ILLEGAL_REQUEST, 0x21, 0x00),
        (0x20, Sense::UNIT_ATTENTION, 0x28, 0x00),
        (0x40, Sense::MEDIUM_ERROR, 0x11, 0x04),
        (0x80, Sense::MEDIUM_ERROR, 0x11, 0x04),
    ];
    const STATUSES: [(u8, u8, u8, u8); 3] = [
        // Busy means no other bit is valid.
        (STATUS_BUSY, Sense::ABORTED_COMMAND, 0x00, 0x00),
        (STATUS_FAULT, Sense::HARDWARE_ERROR, 0x44, 0x00),
        (STATUS_CORRECTED, Sense::RECOVERED_ERROR, 0x00, 0x00),
    ];
    let sense = |(_, key, asc, ascq): (u8, u8, u8, u8)| Sense { key, asc, ascq };
    let error = if status & STATUS_BUSY != 0 { 0 } else { error };
    // ABRT alone is not descriptive enough: the status decides.
    ERRORS
        .iter()
        .find(|entry| error != 0 && entry.0 & error == entry.0)
        .or_else(|| STATUSES.iter().find(|entry| entry.0 & status != 0))
        .copied()
        .map_or(
            Sense {
                key: Sense::ABORTED_COMMAND,
                asc: 0,
                ascq: 0,
            },
            sense,
        )
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
    let mut sense_reported = false;
    if status & (STATUS_BUSY | STATUS_REQUEST | STATUS_READY) != STATUS_READY {
        mask |= ERR_HSM;
        reset = true;
    } else if status & (STATUS_ERROR | STATUS_FAULT) != 0 {
        mask |= ERR_DEVICE;
        // Sense data reporting does not work if the device fault bit is set.
        sense_reported = status & (STATUS_SENSE | STATUS_FAULT) == STATUS_SENSE;
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
        mask,
        frozen,
        reset,
        hotplug,
        sense_reported,
        interrupts,
        serror,
        ..Failure::new(error)
    }
}

/// Linux `ata_scsi_sense_is_valid`.
fn valid_sense(key: u8, asc: u8, ascq: u8) -> Option<Sense> {
    (key <= SENSE_COMPLETED && (key, asc, ascq) != (0, 0, 0)).then_some(Sense { key, asc, ascq })
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
            .and_then(|port| AhciDisk::start(port, capabilities, capabilities_2, clock, dma));
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
        capabilities_2: u32,
        clock: Clock,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Option<Self>, BlockError> {
        let lpm = Lpm::new(capabilities, capabilities_2, port.read32(PORT_COMMAND));
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
                .any(|buffer| buffer.bus_address() + buffer.len() as u64 > 1 << 32)
        {
            return Err(BlockError::Unsupported("32-bit AHCI with DMA above 4 GiB"));
        }
        port.write64(PORT_LIST, commands.bus_address());
        port.write64(PORT_FIS, commands.bus_address() + COMMAND_LIST_BYTES as u64);
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
                features: Features::default(),
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
            sense_reporting: false,
            transfer: Transfer::default(),
            pio_mask: u32::MAX,
            udma_mask: u32::MAX,
            mode: 0,
            step_downs: 0,
            locked: false,
            lpm,
            ncq: Ncq {
                host: capabilities & CAP_NCQ != 0,
                host_slots: (capabilities >> CAP_SLOTS_SHIFT & CAP_SLOTS) as usize + 1,
                ..Ncq::default()
            },
            log_dma: false,
            no_dma_log: false,
            quirks: 0,
            devslp: false,
            slots: Vec::new(),
            running: Vec::new(),
            next_tag: 0,
            looks: 0,
        };
        let port = disk.port;
        let buffer = disk.bounce.bus_address();
        disk.internal(&port, ATA_IDENTIFY, 0, 0, ATA_SECTOR_BYTES as usize, buffer)
            .map_err(|failure| failure.error)?;
        let found = identify(disk.bounce.bytes())?;
        if found.quirks & quirks::DISABLE != 0 {
            stop_port(&port, clock)?;
            return Err(BlockError::Unsupported("SATA device libata disables"));
        }
        disk.sense_reporting = found.sense_reporting.1;
        disk.flush = found.flush;
        disk.identity.serial = found.serial.clone();
        disk.identity.model = found.model.clone();
        disk.identity.blocks = found.blocks;
        disk.identity.block_size = found.block_size;
        // libata's `ata_dev_config_fua` uses FUA only with NCQ and its
        // quirk lists; this driver leaves it off: a durable write is
        // followed by a flush, which the write cache's state decides.
        disk.identity.features = Features {
            write_cache: found.flush.is_some(),
            fua: false,
            max_transfer: BOUNCE_BYTES,
            discard: found.trim.then_some(TRIM_RANGES * TRIM_RANGE_SECTORS),
            write_zeroes: None,
        };
        disk.transfer = found.transfer;
        disk.locked = found.locked;
        (disk.lpm.hipm, disk.lpm.dipm) = (found.hipm, found.dipm);
        // ata_dev_configure, then ATA_EHI_SETMODE and config_lpm; a failure
        // takes EH's next try.
        let mut configured = disk.configure(&port, &found);
        if configured.is_ok() {
            disk.set_mode(&port)?;
            configured = disk.configure_lpm(&port, DEVICE_TRIES);
        }
        if let Err(error) = configured {
            let tries = if error == AGAIN {
                DEVICE_TRIES
            } else {
                DEVICE_TRIES - 1
            };
            disk.reconfigure(&port, true, false, error, tries)?;
        }
        // Linux `__ata_change_queue_depth`: as many queued commands as the
        // host's slots and the disk take, here at most DEPTH. A slot the
        // DMA pool cannot hold leaves the queue shallower.
        if disk.ncq.device {
            let depth = DEPTH.min(disk.ncq.host_slots).min(disk.ncq.depth);
            for _ in 1..depth {
                let (Ok(table), Ok(bounce)) = (
                    dma.allocate(COMMAND_TABLE_BYTES, COMMAND_TABLE_ALIGN),
                    dma.allocate(BOUNCE_BYTES, 4096),
                ) else {
                    break;
                };
                let slot = Slot { table, bounce };
                if capabilities & CAP_64BIT == 0
                    && [&slot.table, &slot.bounce]
                        .iter()
                        .any(|buffer| buffer.bus_address() + buffer.len() as u64 > 1 << 32)
                {
                    break;
                }
                disk.slots.push(slot);
            }
        }
        Ok(Some(disk))
    }

    /// The commands the port runs at once: a slot each while NCQ is on.
    fn queue_depth(&self) -> usize {
        if self.ncq.enabled() {
            1 + self.slots.len()
        } else {
            1
        }
    }

    /// The lowest slot within the queue depth no started command holds.
    fn free_slot(&self) -> Option<usize> {
        (0..self.queue_depth()).find(|slot| self.running.iter().all(|run| run.slot != *slot))
    }

    fn table(&self, slot: usize) -> &DmaBuffer {
        match slot {
            0 => &self.table,
            slot => &self.slots[slot - 1].table,
        }
    }

    fn bounce(&self, slot: usize) -> &DmaBuffer {
        match slot {
            0 => &self.bounce,
            slot => &self.slots[slot - 1].bounce,
        }
    }

    fn bounce_mut(&mut self, slot: usize) -> &mut DmaBuffer {
        match slot {
            0 => &mut self.bounce,
            slot => &mut self.slots[slot - 1].bounce,
        }
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
    /// failure, then retry as `ata_eh_finish` decides, and complete a failed
    /// command by its fetched or generated sense data as sd does.
    fn issue_on(
        &mut self,
        port: &impl CommandPort,
        command: u8,
        lba: u64,
        count: u16,
        bytes: usize,
        write: bool,
    ) -> Result<(), BlockError> {
        self.issue_with(port, (command, 0), lba, count, bytes, write)
    }

    /// [`Self::issue_on`] with the command's FEATURE field.
    fn issue_with(
        &mut self,
        port: &impl CommandPort,
        command: (u8, u16),
        lba: u64,
        count: u16,
        bytes: usize,
        write: bool,
    ) -> Result<(), BlockError> {
        let issue = self.prepare(command, lba, count, bytes, write)?;
        self.complete(port, issue)
    }

    /// Run `issue` to its result in slot 0, after the started block
    /// commands'.
    fn complete(&mut self, port: &impl CommandPort, mut issue: Issue) -> Result<(), BlockError> {
        while self.running.iter().any(|running| running.result.is_none()) {
            self.run(port);
            crate::waiting();
            core::hint::spin_loop();
        }
        loop {
            if let Some(result) = self.step(port, &mut issue) {
                return result;
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }

    fn prepare(
        &self,
        (command, feature): (u8, u16),
        lba: u64,
        count: u16,
        bytes: usize,
        write: bool,
    ) -> Result<Issue, BlockError> {
        self.ready()?;
        Ok(Issue {
            slot: 0,
            command,
            feature,
            lba,
            count,
            bytes,
            write,
            io: matches!(
                command,
                ATA_READ_DMA_EXT
                    | ATA_WRITE_DMA_EXT
                    | ATA_READ_FPDMA_QUEUED
                    | ATA_WRITE_FPDMA_QUEUED
            ),
            prepared: self.clock.try_start().map_err(|_| BlockError::Timeout)?,
            retries: 0,
            launched: None,
            resume: None,
        })
    }

    /// Move `issue` on without waiting, the port running nothing else:
    /// [`Self::advance`] for one command.
    fn step(
        &mut self,
        port: &impl CommandPort,
        issue: &mut Issue,
    ) -> Option<Result<(), BlockError>> {
        self.advance(port, &mut [issue]).pop().flatten()
    }

    /// Move `issues`, each in its own slot, on without waiting: launch
    /// those that may run, take one look at the port, and recover it from a
    /// failure, after which each failed command is retried as
    /// `ata_eh_finish` decides and completes by its fetched or generated
    /// sense data, as sd does. Each issue's result once it has one.
    ///
    /// Linux `ata_std_qc_defer`: in turn, a queued command launches beside
    /// queued ones, any other alone. A failure reaches every launched
    /// command, as `ata_link_abort` does; one the NCQ Command Error log does
    /// not blame runs again uncharged (`ata_eh_qc_retry` without an error).
    fn advance(
        &mut self,
        port: &impl CommandPort,
        issues: &mut [&mut Issue],
    ) -> Vec<Option<Result<(), BlockError>>> {
        let mut results: Vec<_> = issues.iter().map(|_| None).collect();
        let mut launched = issues
            .iter()
            .filter(|issue| issue.launched.is_some())
            .count();
        let mut plain = issues.iter().any(|issue| {
            issue
                .launched
                .as_ref()
                .is_some_and(|launched| !launched.queued)
        });
        for (index, issue) in issues.iter_mut().enumerate() {
            if issue.launched.is_some() || issue.resume.is_some_and(|resume| !resume.passed()) {
                continue;
            }
            issue.resume = None;
            if let Err(error) = self.ready() {
                results[index] = Some(Err(error));
                continue;
            }
            let command = self.rw_command(issue.command);
            let queued = matches!(command, ATA_READ_FPDMA_QUEUED | ATA_WRITE_FPDMA_QUEUED);
            if plain || (!queued && launched > 0) {
                break;
            }
            let buffer = self.bounce(issue.slot).bus_address();
            match self.launch(
                port,
                issue.slot,
                launched == 0,
                AtaRequest {
                    command,
                    feature: issue.feature,
                    lba: issue.lba,
                    count: issue.count,
                    bytes: issue.bytes,
                    write: issue.write,
                    buffer,
                },
            ) {
                Ok(started) => {
                    issue.launched = Some(started);
                    launched += 1;
                    plain |= !queued;
                }
                Err(failure) => results[index] = Some(Err(failure.error)),
            }
        }
        let seen = {
            let launched: Vec<&Launched> = issues
                .iter()
                .filter_map(|issue| issue.launched.as_ref())
                .collect();
            if launched.is_empty() {
                return results;
            }
            match self.look(port, &launched) {
                Some(seen) => seen,
                None => return results,
            }
        };
        for (index, issue) in issues.iter_mut().enumerate() {
            if issue
                .launched
                .as_ref()
                .is_some_and(|launched| seen.done >> launched.slot & 1 != 0)
            {
                issue.launched = None;
                // ata_verify_xfer: a completed DMA transfer verifies it.
                if issue.io {
                    self.dubious = false;
                }
                results[index] = Some(Ok(()));
            }
        }
        let Some(mut failure) = seen.failure else {
            return results;
        };
        let io = issues
            .iter()
            .any(|issue| issue.launched.is_some() && issue.io);
        if let Err(error) = self.recover(port, &mut failure, io) {
            self.fault = Some(error.clone());
            for (index, issue) in issues.iter_mut().enumerate() {
                if issue.launched.take().is_some() {
                    results[index] = Some(Err(error.clone()));
                }
            }
            return results;
        }
        for (index, issue) in issues.iter_mut().enumerate() {
            let Some(launched) = issue.launched.take() else {
                continue;
            };
            let blamed = match failure.named {
                Some(slot) => slot == launched.slot,
                None => seen.blamed >> launched.slot & 1 != 0,
            };
            if blamed {
                results[index] = self.dispose(issue, failure.clone());
            }
        }
        results
    }

    /// `ata_eh_finish` and sd's completion for a command `failure` was
    /// charged to, after recovery: retry it, or complete it by its fetched
    /// or generated sense data.
    fn dispose(
        &mut self,
        issue: &mut Issue,
        mut failure: Failure,
    ) -> Option<Result<(), BlockError>> {
        // With valid sense, only a NEEDS_RETRY disposition with an error
        // left besides the device's is retried.
        let retry = match failure.sense {
            Some(sense) => failure.mask != 0 && sense.needs_retry(),
            None => worth_retry(failure.mask, issue.io),
        };
        if retry && issue.retries < COMMAND_RETRIES {
            issue.retries += 1;
            return None;
        }
        let sense = match failure.sense {
            Some(sense) => sense,
            None => self.generated_sense(&mut failure),
        };
        // A fixed disk: no media change.
        match sense.completion(false) {
            SenseCompletion::Done => Some(Ok(())),
            SenseCompletion::Fail | SenseCompletion::MediaChanged => Some(Err(failure.error)),
            SenseCompletion::Retry(delay_us) => {
                // scsi_cmd_runtime_exceeced: sd requeues end (allowed + 1)
                // timeouts after the command was first prepared.
                let runtime_us = (u64::from(COMMAND_RETRIES) + 1) * self.command_timeout_us;
                let Ok(elapsed) = self.clock.try_elapsed_us(issue.prepared) else {
                    return Some(Err(BlockError::Timeout));
                };
                if elapsed > runtime_us {
                    return Some(Err(failure.error));
                }
                match self.clock.try_deadline(delay_us) {
                    Ok(resume) => issue.resume = Some(resume),
                    Err(_) => return Some(Err(BlockError::Timeout)),
                }
                None
            }
        }
    }

    /// `ata_build_rw_tf`: reads and writes are queued while NCQ is enabled.
    fn rw_command(&self, command: u8) -> u8 {
        match command {
            ATA_READ_DMA_EXT if self.ncq.enabled() => ATA_READ_FPDMA_QUEUED,
            ATA_WRITE_DMA_EXT if self.ncq.enabled() => ATA_WRITE_FPDMA_QUEUED,
            _ => command,
        }
    }

    /// An internal command (`ata_exec_internal`): a failure kicks the engine
    /// so it forgets the command, and is returned as is.
    fn internal(
        &mut self,
        port: &impl CommandPort,
        command: u8,
        feature: u8,
        count: u16,
        bytes: usize,
        buffer: u64,
    ) -> Result<(), Failure> {
        self.ready().map_err(Failure::new)?;
        let Err(failure) = self.attempt(
            port,
            AtaRequest {
                command,
                feature: u16::from(feature),
                lba: 0,
                count,
                bytes,
                write: false,
                buffer,
            },
        ) else {
            return Ok(());
        };
        stop_engine(port, self.clock).map_err(Failure::new)?;
        start_engine(port);
        Err(failure)
    }

    /// Issue the command once in slot 0, the port running nothing else, and
    /// wait for its completion or error.
    fn attempt(&mut self, port: &impl CommandPort, request: AtaRequest) -> Result<(), Failure> {
        let launched = self.launch(port, 0, true, request)?;
        loop {
            if let Some(seen) = self.look(port, &[&launched]) {
                return seen.failure.map_or(Ok(()), Err);
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }

    /// Issue the command once in `slot`; `alone` when the port runs no
    /// other command, whose interrupts and ending FIS marks it may clear.
    fn launch(
        &mut self,
        port: &impl CommandPort,
        slot: usize,
        alone: bool,
        request: AtaRequest,
    ) -> Result<Launched, Failure> {
        let AtaRequest {
            command,
            feature,
            lba,
            count,
            bytes,
            write,
            buffer,
        } = request;
        let table = self.table(slot).bus_address();
        // A queued command's sector count moves to the features registers;
        // the count register carries its tag, its slot, in bits 7:3.
        let queued = matches!(command, ATA_READ_FPDMA_QUEUED | ATA_WRITE_FPDMA_QUEUED);
        let (feature, count) = if queued {
            (count, (slot as u16) << 3)
        } else {
            (feature, count)
        };
        let fis = [
            FIS_REGISTER_HOST_TO_DEVICE,
            FIS_COMMAND,
            command,
            feature as u8,
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
            (feature >> 8) as u8,
            count as u8,
            (count >> 8) as u8,
        ];
        let entries = u32::from(bytes > 0);
        let tables = match slot {
            0 => &mut self.table,
            slot => &mut self.slots[slot - 1].table,
        };
        tables.bytes_mut()[..TABLE_HEADER_BYTES].fill(0);
        tables.bytes_mut()[..fis.len()].copy_from_slice(&fis);
        if bytes > 0 {
            tables.write(PRDT_ADDRESS, buffer);
            tables.write(PRDT_BYTE_COUNT, bytes as u32 - 1);
        }
        let flags = COMMAND_FIS_DWORDS
            | u32::from(write) << COMMAND_WRITE_SHIFT
            | entries << COMMAND_PRDT_SHIFT;
        let header = slot * COMMAND_HEADER_BYTES;
        self.commands.write(header, flags);
        self.commands.write(header + 4, 0u32);
        self.commands.write(header + 8, table);
        fence(Ordering::SeqCst);
        // The FIS a command ends with lands in the received-FIS area in RAM.
        // Mark its types with the H2D Register type, as a hardreset does, to
        // see one arrive; a look marks a queued command's again.
        if alone {
            port.write32(PORT_INTERRUPTS, u32::MAX);
            for &(at, _) in ending(queued) {
                self.commands.write(at, FIS_REGISTER_HOST_TO_DEVICE);
            }
            // The first look reads the registers too: an emulated port may
            // finish at the PxCI write.
            self.looks = 0;
        }
        fence(Ordering::SeqCst);
        let deadline = self
            .clock
            .try_deadline(self.command_timeout_us)
            .map_err(|_| Failure::new(BlockError::Timeout))?;
        // ahci_qc_issue: a queued command is active in PxSACT until the
        // disk's Set Device Bits FIS clears it.
        if queued {
            port.write32(PORT_SATA_ACTIVE, 1 << slot);
        }
        port.write32(PORT_ISSUE, 1 << slot);
        Ok(Launched {
            slot,
            queued,
            deadline,
        })
    }

    /// One look at `launched`, all queued commands or one other; never
    /// waits. PxIS and PxSACT or PxCI, which a hypervisor traps, are read
    /// when an ending FIS arrived, every few looks since a failure may post
    /// none, and at a deadline. A queued command's Set Device Bits FIS is
    /// marked again before PxSACT is read, so a later one is seen. Nothing
    /// when no command completed or failed.
    fn look(&mut self, port: &impl CommandPort, launched: &[&Launched]) -> Option<Seen> {
        let queued = launched.iter().any(|launched| launched.queued);
        let active = if queued { PORT_SATA_ACTIVE } else { PORT_ISSUE };
        let due = self.looks.is_multiple_of(REGISTER_POLL_INTERVAL);
        self.looks = self.looks.wrapping_add(1);
        let posted = ending(queued)
            .iter()
            .any(|&(at, kind)| self.commands.read::<u8>(at) == kind);
        // The deadlines are read only when nothing else calls for a look.
        if !posted && !due && !launched.iter().any(|launched| launched.deadline.passed()) {
            return None;
        }
        if queued && posted {
            self.commands
                .write(RECEIVED_SDB, FIS_REGISTER_HOST_TO_DEVICE);
            fence(Ordering::SeqCst);
        }
        let interrupts = port.read32(PORT_INTERRUPTS) & INTERRUPT_ERROR;
        let running = port.read32(active);
        fence(Ordering::SeqCst);
        let slots = launched
            .iter()
            .fold(0, |slots, launched| slots | 1 << launched.slot);
        let done = slots & !running;
        let expired = launched
            .iter()
            .filter(|launched| running >> launched.slot & 1 != 0 && launched.deadline.passed())
            .fold(0, |slots, launched| slots | 1 << launched.slot);
        if interrupts == 0 && expired == 0 {
            return (done != 0).then_some(Seen {
                done,
                failure: None,
                blamed: 0,
            });
        }
        // AHCI needs SError cleared; otherwise it might lock up.
        let serror = port.read32(PORT_SATA_ERROR);
        port.write32(PORT_SATA_ERROR, serror);
        port.write32(PORT_INTERRUPTS, port.read32(PORT_INTERRUPTS));
        let timed_out = interrupts == 0;
        let mut failure = classify(interrupts, serror, port.read32(PORT_TASK_FILE), timed_out);
        // ahci_qc_fill_rtf, before error handling issues anything else: the
        // Set Device Bits FIS for a queued command, else the last D2H FIS.
        let fis = if queued { RECEIVED_SDB } else { RECEIVED_D2H };
        let fis = &self.commands.bytes()[fis..fis + FIS_BYTES];
        failure.result = [fis[2], fis[3]];
        failure.queued = queued;
        failure.slots = if queued { slots } else { 0 };
        // An error interrupt reaches every launched command, as
        // ata_link_abort does: those that completed run again. A timeout
        // charges the expired commands, after those that completed.
        Some(if timed_out {
            Seen {
                done,
                failure: Some(failure),
                blamed: expired,
            }
        } else {
            Seen {
                done: 0,
                failure: Some(failure),
                blamed: slots,
            }
        })
    }

    /// Take `command` as a started block command, in the lowest free slot.
    fn begin(&mut self, command: Command) -> Result<u32, BlockError> {
        self.ready()?;
        let command = command.within(&self.identity, 0)?;
        let Some(slot) = self.free_slot() else {
            return Err(BlockError::Protocol(
                "every AHCI command slot is running a command",
            ));
        };
        let tag = self.next_tag;
        self.next_tag = tag.wrapping_add(1);
        self.running.push(Running {
            tag,
            slot,
            command,
            done: 0,
            data: Vec::new(),
            issue: None,
            result: None,
        });
        Ok(tag)
    }

    /// Move the started block commands on as far as they go without
    /// waiting.
    fn run(&mut self, port: &impl CommandPort) {
        let mut running = core::mem::take(&mut self.running);
        loop {
            for command in running
                .iter_mut()
                .filter(|command| command.result.is_none() && command.issue.is_none())
            {
                match self.next_issue(command) {
                    Ok(Some(issue)) => command.issue = Some(issue),
                    Ok(None) => {
                        let data = core::mem::take(&mut command.data);
                        let read = matches!(command.command, Command::Read { .. });
                        command.result = Some(Ok(read.then_some(data)));
                    }
                    Err(error) => command.result = Some(Err(error)),
                }
            }
            let mut issues: Vec<&mut Issue> = running
                .iter_mut()
                .filter_map(|command| command.issue.as_mut())
                .collect();
            if issues.is_empty() {
                break;
            }
            let results = self.advance(port, &mut issues);
            let mut progressed = false;
            for (command, result) in running
                .iter_mut()
                .filter(|command| command.issue.is_some())
                .zip(results)
            {
                let Some(result) = result else {
                    continue;
                };
                progressed = true;
                let Some(issue) = command.issue.take() else {
                    continue;
                };
                match result {
                    Err(error) => command.result = Some(Err(error)),
                    Ok(()) => {
                        if let Command::Read { .. } = command.command {
                            command.data.extend_from_slice(
                                &self.bounce(command.slot).bytes()[..issue.bytes],
                            );
                        }
                        command.done += issue.bytes.max(1);
                    }
                }
            }
            if !progressed {
                break;
            }
        }
        self.running = running;
    }

    /// The next part of `running`'s command, its data staged in its slot's
    /// bounce buffer, or `None` once all of it is done.
    fn next_issue(&mut self, running: &Running) -> Result<Option<Issue>, BlockError> {
        let block = self.identity.block_size as usize;
        let done = running.done;
        let slot = running.slot;
        let issue = match &running.command {
            Command::Read { lba, bytes } if done < *bytes => {
                let part = (bytes - done).min(self.chunk_bytes());
                let first = lba + (done / block) as u64;
                let count = self.sectors(part);
                self.prepare((ATA_READ_DMA_EXT, 0), first, count, part, false)?
            }
            Command::Write {
                lba,
                data,
                fua: false,
            } if done < data.len() => {
                let part = (data.len() - done).min(self.chunk_bytes());
                self.bounce_mut(slot).bytes_mut()[..part].copy_from_slice(&data[done..done + part]);
                let first = lba + (done / block) as u64;
                let count = self.sectors(part);
                self.prepare((ATA_WRITE_DMA_EXT, 0), first, count, part, true)?
            }
            Command::Flush if done == 0 => match self.flush {
                Some(command) => self.prepare((command, 0), 0, 0, 0, false)?,
                None => return Ok(None),
            },
            Command::Discard { lba, blocks } if done == 0 => self.trim(*lba, *blocks, slot)?,
            Command::Write { fua: true, .. } => {
                return Err(BlockError::Unsupported(
                    "the device takes no Force Unit Access",
                ));
            }
            Command::WriteZeroes { .. } => {
                return Err(BlockError::Unsupported("the device takes no Write Zeroes"));
            }
            _ => return Ok(None),
        };
        Ok(Some(Issue { slot, ..issue }))
    }

    /// TRIM in one block of ranges, as libata's `ata_format_dsm_trim_descr`
    /// writes them: each the starting logical sector in bits 47:0 and the
    /// count in bits 63:48, staged in `slot`'s bounce buffer.
    fn trim(&mut self, lba: u64, blocks: u64, slot: usize) -> Result<Issue, BlockError> {
        let bytes = usize::try_from(blocks)
            .ok()
            .and_then(|blocks| blocks.checked_mul(self.identity.block_size as usize))
            .ok_or(BlockError::Unsupported("a TRIM past one block of ranges"))?;
        self.identity.check_write(lba, bytes)?;
        let (mut sector, mut sectors) = (lba, blocks);
        if sectors > TRIM_RANGES * TRIM_RANGE_SECTORS {
            return Err(BlockError::Unsupported("a TRIM past one block of ranges"));
        }
        self.ready()?;
        let ranges = &mut self.bounce_mut(slot).bytes_mut()[..ATA_SECTOR_BYTES as usize];
        ranges.fill(0);
        for range in ranges.chunks_mut(8) {
            if sectors == 0 {
                break;
            }
            let count = sectors.min(TRIM_RANGE_SECTORS);
            range.copy_from_slice(&(sector | count << 48).to_le_bytes());
            (sector, sectors) = (sector + count, sectors - count);
        }
        self.prepare(
            (ATA_DATA_SET_MANAGEMENT, TRIM),
            0,
            1,
            ATA_SECTOR_BYTES as usize,
            true,
        )
    }

    /// Linux `ahci_error_handler` and `ata_eh_recover`: restart an unfrozen
    /// engine, analyze an NCQ error, fetch sense data and consider a
    /// speed-down; when a reset is due, hard reset the
    /// link (one try per `ata_eh_reset_timeouts` entry) and revalidate the
    /// disk, up to `ATA_EH_DEV_TRIES` times. An error disables the disk.
    fn recover(
        &mut self,
        port: &impl CommandPort,
        failure: &mut Failure,
        io: bool,
    ) -> Result<(), BlockError> {
        if !failure.frozen {
            stop_engine(port, self.clock)?;
            start_engine(port);
        }
        // ahci_error_intr charges a queued command's device error to the
        // link, where valid sense does not clear it, unless the NCQ error log
        // names the command.
        let mut link_device = failure.queued && failure.interrupts & INTERRUPT_TASK_FILE_ERROR != 0;
        if link_device && !failure.frozen && self.analyze_ncq_error(port, failure)? {
            link_device = false;
        }
        // ata_eh_analyze_tf fetches reported sense data the log did not hold
        // unless the port is frozen or reporting is off; valid sense
        // supersedes the device error.
        if failure.sense.is_none()
            && failure.sense_reported
            && !failure.frozen
            && self.sense_reporting
        {
            failure.sense = self.request_sense(port)?;
        }
        if let Some(sense) = failure.sense {
            failure.error = BlockError::Sense(sense);
            failure.mask &= !ERR_DEVICE;
        }
        let all = failure.mask | if link_device { ERR_DEVICE } else { 0 };
        let slowed = self.speed_down(port, all, io)?;
        // ata_eh_link_autopsy's default actions: a frozen port, a timeout or
        // an HSM violation resets; any other error of an I/O command, and any
        // but a device error of another, revalidates.
        let reset = failure.reset || slowed || failure.frozen || all & (ERR_HSM | ERR_TIMEOUT) != 0;
        let revalidate = if io { all != 0 } else { all & !ERR_DEVICE != 0 };
        if !reset && !revalidate {
            return Ok(());
        }
        let last = failure.error.clone();
        self.reconfigure(port, reset, failure.hotplug, last, DEVICE_TRIES)
    }

    /// `ata_eh_recover`: a reset when one is due, then revalidation and
    /// configuration, `tries` times at most; each retry resets.
    fn reconfigure(
        &mut self,
        port: &impl CommandPort,
        mut reset: bool,
        mut hotplug: bool,
        mut last: BlockError,
        mut tries: usize,
    ) -> Result<(), BlockError> {
        loop {
            if reset {
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
            }
            reset = true;
            // ata_eh_revalidate_and_attach wakes a power-saving link first;
            // then ATA_EHI_SETMODE and config_lpm.
            let woken = if self.lpm.policy > LPM_MAX_POWER {
                self.set_lpm(port, LPM_MAX_POWER, tries)
            } else {
                Ok(())
            };
            let Err(error) = woken
                .and_then(|()| self.revalidate(port))
                .and_then(|()| self.set_mode(port))
                .and_then(|()| self.configure_lpm(port, tries))
            else {
                return Ok(());
            };
            // ata_eh_handle_dev_fail: another device gets one more chance,
            // and the last chance runs slower; -EAGAIN costs no try.
            if error != AGAIN {
                tries -= 1;
                if error == DETACHED {
                    tries = tries.min(1);
                }
                if tries == 1 {
                    self.lower_speed_limit(port);
                    self.lower_transfer_limit(StepDown::Pio);
                }
            }
            if tries == 0 {
                return Err(error);
            }
            last = error;
            hotplug = false;
        }
    }

    /// Linux `ata_eh_speed_down`: record the error and, when the verdict
    /// calls for it, lower the SATA link speed limit; whether a reset must
    /// apply it. NCQ_OFF turns NCQ off instead, and PIO fallback excludes
    /// SATA ATA disks.
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
        if verdict & VERDICT_NCQ_OFF != 0 && self.ncq.enabled() {
            self.ncq.off = true;
            if verdict & VERDICT_KEEP_ERRORS == 0 {
                self.errors.clear();
            }
            return Ok(false);
        }
        if verdict & VERDICT_SPEED_DOWN == 0 {
            return Ok(false);
        }
        // The link speed first, then the transfer mode, twice.
        if !self.lower_speed_limit(port) {
            if self.step_downs >= 2 {
                return Ok(false);
            }
            let step = [StepDown::Dma, StepDown::FortyWire][usize::from(self.step_downs)];
            self.step_downs += 1;
            if !self.lower_transfer_limit(step) {
                return Ok(false);
            }
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
        let buffer = self.table.bus_address() + IDENTIFY_DATA as u64;
        self.internal(port, ATA_IDENTIFY, 0, 0, ATA_SECTOR_BYTES as usize, buffer)
            .map_err(|failure| failure.error)?;
        let data = &self.table.bytes()[IDENTIFY_DATA..IDENTIFY_DATA + ATA_SECTOR_BYTES as usize];
        let found = identify(data).map_err(|_| DETACHED)?;
        if found.model != self.identity.model
            || found.serial != self.identity.serial
            || found.blocks != self.identity.blocks
        {
            return Err(DETACHED);
        }
        // ata_dev_reread_id keeps the new data.
        self.sense_reporting = found.sense_reporting.1;
        self.transfer = found.transfer;
        self.locked = found.locked;
        (self.lpm.hipm, self.lpm.dipm) = (found.hipm, found.dipm);
        self.configure(port, &found)
    }

    /// What Linux `ata_dev_configure`, which `ata_dev_revalidate` reruns,
    /// asks of the disk. The quirk table's entry accumulates; a 1.5 Gbps
    /// limit on a faster link asks for another reset. `ata_dev_config_ncq`
    /// enables first-party DMA auto-activation; a failure other than the
    /// device's refusal marks it broken and fails the configuration.
    /// `ata_dev_config_lpm` forces max_power for broken LPM and turns DIPM
    /// off on a host without it, as Software Settings Preservation may have
    /// kept it on. `ata_dev_config_devslp` reads the SATA Settings page for
    /// DevSleep. Then Sense Data Reporting, which
    /// a hard reset turns off again (`ata_dev_config_sense_reporting` only
    /// logs a refusal). The kept IDENTIFY data says it is enabled only once
    /// a revalidation rereads it.
    fn configure(&mut self, port: &impl CommandPort, found: &Identified) -> Result<(), BlockError> {
        let buffer = self.bounce.bus_address();
        self.quirks |= found.quirks;
        // ata_do_link_spd_quirk.
        if self.quirks & quirks::LINK_1_5_GBPS != 0 && self.speed_limit > 0b1 {
            self.speed_limit = 0b1;
            if self.speed > 1 {
                return Err(AGAIN);
            }
        }
        let ncq = found.ncq && self.quirks & quirks::NONCQ == 0;
        self.ncq.device = self.ncq.host && ncq;
        self.ncq.depth = found.queue_depth;
        self.ncq.autosense = found.ncq_autosense;
        self.ncq.aa_broken |= self.quirks & quirks::BROKEN_FPDMA_AA != 0;
        self.log_dma = found.read_log_dma;
        self.no_dma_log |= self.quirks & quirks::NO_DMA_LOG != 0;
        if ncq && self.ncq.host && found.fpdma_aa && !self.ncq.aa_broken {
            let enabled = self.internal(
                port,
                ATA_SET_FEATURES,
                FEATURE_SATA_ENABLE,
                SATA_FPDMA_AA,
                0,
                buffer,
            );
            if let Err(failure) = enabled
                && !failure.refused()
            {
                self.ncq.aa_broken = true;
                return Err(failure.error);
            }
        }
        // WD_BROKEN_LPM covers 1.5 Gbps-only disks; NO_LPM_ON_ATI needs an
        // ATI host, which an AMD one is not.
        if self.quirks & quirks::NOLPM != 0
            || self.quirks & quirks::WD_BROKEN_LPM != 0 && found.sata_speeds == 0x2
        {
            self.lpm.broken = true;
        }
        if !self.lpm.host_dipm() && found.dipm {
            let _ = self.internal(
                port,
                ATA_SET_FEATURES,
                FEATURE_SATA_DISABLE,
                SATA_DIPM,
                0,
                buffer,
            );
        }
        self.devslp = found.devslp
            && self.identify_page_supported(port, LOG_SATA_SETTINGS)?
            && self.read_log(port, LOG_IDENTIFY_DEVICE, LOG_SATA_SETTINGS)?;
        if found.sense_reporting == (true, false) {
            let _ = self.internal(port, ATA_SET_FEATURES, FEATURE_SENSE_DATA, 1, 0, buffer);
        }
        Ok(())
    }

    /// Linux `ata_read_log_page` for one page into the table's log area:
    /// READ LOG DMA EXT where IDENTIFY offers it, and once that fails READ
    /// LOG EXT for good (`ATA_QUIRK_NO_DMA_LOG`), at once unless the port
    /// froze. Whether the page was read.
    fn read_log(&mut self, port: &impl CommandPort, log: u8, page: u8) -> Result<bool, BlockError> {
        let buffer = self.table.bus_address() + LOG_DATA as u64;
        let lba = u64::from(log) | u64::from(page) << 8;
        loop {
            let dma = self.log_dma && !self.no_dma_log;
            let command = if dma {
                ATA_READ_LOG_DMA_EXT
            } else {
                ATA_READ_LOG_EXT
            };
            let bytes = ATA_SECTOR_BYTES as usize;
            let Err(failure) = self.attempt(
                port,
                AtaRequest {
                    command,
                    feature: 0,
                    lba,
                    count: 1,
                    bytes,
                    write: false,
                    buffer,
                },
            ) else {
                return Ok(true);
            };
            stop_engine(port, self.clock)?;
            start_engine(port);
            if !dma {
                return Ok(false);
            }
            self.no_dma_log = true;
            if failure.frozen {
                return Ok(false);
            }
        }
    }

    /// Linux `ata_identify_page_supported` with `ata_log_supported`: the
    /// general purpose log directory, reread at each configuration, lists
    /// the IDENTIFY DEVICE data log, whose page 0 lists `page`. Without that
    /// log the disk gets `ATA_QUIRK_NO_ID_DEV_LOG`.
    fn identify_page_supported(
        &mut self,
        port: &impl CommandPort,
        page: u8,
    ) -> Result<bool, BlockError> {
        if self.quirks & quirks::NO_ID_DEV_LOG != 0 {
            return Ok(false);
        }
        let entry = LOG_DATA + 2 * usize::from(LOG_IDENTIFY_DEVICE);
        let listed = self.quirks & quirks::NO_LOG_DIR == 0
            && self.read_log(port, LOG_DIRECTORY, 0)?
            && self.table.bytes()[entry..entry + 2] != [0, 0];
        if !listed {
            self.quirks |= quirks::NO_ID_DEV_LOG;
            return Ok(false);
        }
        if !self.read_log(port, LOG_IDENTIFY_DEVICE, 0)? {
            return Ok(false);
        }
        let pages = &self.table.bytes()[LOG_DATA..LOG_DATA + ATA_SECTOR_BYTES as usize];
        Ok(pages[9..9 + usize::from(pages[8])].contains(&page))
    }

    /// Linux `ata_eh_analyze_ncq_error`: the NCQ Command Error log names
    /// the failed command and holds its result taskfile and, with NCQ
    /// autosense, its sense data. Whether it named a launched command, whose
    /// slot `failure` then names.
    fn analyze_ncq_error(
        &mut self,
        port: &impl CommandPort,
        failure: &mut Failure,
    ) -> Result<bool, BlockError> {
        if !self.read_log(port, LOG_SATA_NCQ, 0)? {
            return Ok(false);
        }
        let log = &self.table.bytes()[LOG_DATA..LOG_DATA + ATA_SECTOR_BYTES as usize];
        // A tag no launched command holds names none, as Linux reports an
        // inactive tag.
        let tag = usize::from(log[0] & LOG_NCQ_TAG);
        if log[0] & LOG_NCQ_NQ != 0 || failure.slots >> tag & 1 == 0 {
            return Ok(false);
        }
        let [status, error] = [log[2], log[3]];
        let sense = if self.ncq.autosense && status & STATUS_SENSE != 0 {
            valid_sense(log[14], log[15], log[16])
        } else {
            None
        };
        let task_file = u32::from(status) | u32::from(error) << 8;
        *failure = Failure {
            queued: true,
            slots: failure.slots,
            named: Some(tag),
            result: [status, error],
            sense,
            ..classify(failure.interrupts, failure.serror, task_file, false)
        };
        Ok(true)
    }

    /// `ata_eh_recover`'s config_lpm: move to the target policy. A failure
    /// with at most two tries left disables LPM on the link, as
    /// `ata_eh_link_set_lpm` does.
    fn configure_lpm(&mut self, port: &impl CommandPort, tries: usize) -> Result<(), BlockError> {
        let target = self.lpm.target();
        if self.lpm.policy == target {
            return Ok(());
        }
        self.set_lpm(port, target, tries)
    }

    /// Linux `ata_eh_link_set_lpm` with `ahci_set_lpm`: DIPM off, the
    /// SControl IPM restrictions and PxCMD aggressive LPM the policy and HIPM
    /// allow, then DIPM on from MED_POWER_WITH_DIPM. A device's refusal is
    /// ignored; any other failure keeps the old policy.
    fn set_lpm(
        &mut self,
        port: &impl CommandPort,
        policy: u8,
        tries: usize,
    ) -> Result<(), BlockError> {
        if !self.lpm.allowed {
            return Ok(());
        }
        let result = self.apply_lpm(port, policy);
        if result.is_err() && tries <= 2 {
            self.lpm.allowed = false;
        }
        result
    }

    fn apply_lpm(&mut self, port: &impl CommandPort, policy: u8) -> Result<(), BlockError> {
        let lpm = self.lpm;
        let buffer = self.bounce.bus_address();
        let dipm = |disk: &mut Self, feature| match disk.internal(
            port,
            ATA_SET_FEATURES,
            feature,
            SATA_DIPM,
            0,
            buffer,
        ) {
            Err(failure) if !failure.refused() => Err(failure.error),
            _ => Ok(()),
        };
        if lpm.dipm {
            dipm(self, FEATURE_SATA_DISABLE)?;
        }
        // sata_link_scr_lpm; the port's PhyRdy interrupt is already masked.
        let scr_lpm = || {
            let mut control = port.read32(PORT_SATA_CONTROL);
            if policy == LPM_MAX_POWER {
                control |= SATA_CONTROL_POWER;
            } else {
                control &= !SATA_CONTROL_POWER;
                if lpm.capabilities & CAP_PARTIAL == 0 {
                    control |= SATA_CONTROL_NO_PARTIAL;
                }
                if lpm.capabilities & CAP_SLUMBER == 0 {
                    control |= SATA_CONTROL_NO_SLUMBER;
                }
                if lpm.capabilities_2 & CAP2_DEVICE_SLEEP == 0 {
                    control |= SATA_CONTROL_NO_DEVICE_SLEEP;
                }
            }
            port.write32(PORT_SATA_CONTROL, control);
            port.write32(PORT_SATA_ERROR, SERROR_PHY_READY_CHANGE);
        };
        // ahci_set_lpm restricts the link first when saving power, and
        // lifts the restrictions last at max_power.
        if policy != LPM_MAX_POWER {
            scr_lpm();
        }
        if lpm.capabilities & CAP_AGGRESSIVE_LPM != 0 {
            let mut command = port.read32(PORT_COMMAND);
            if policy == LPM_MAX_POWER || !lpm.hipm {
                command &= !(COMMAND_AGGRESSIVE_SLUMBER | COMMAND_AGGRESSIVE_LPM);
                port.write32(PORT_COMMAND, command | COMMAND_INTERFACE_ACTIVE);
                port.read32(PORT_COMMAND);
                self.clock.delay(LPM_WAKE_US);
            } else {
                port.write32(PORT_COMMAND, command | COMMAND_AGGRESSIVE_LPM);
            }
        }
        // ahci_set_aggressive_devslp: only the minimum-power policies,
        // which are never the target here, enable it; firmware's is undone.
        let sleep = CAP2_DEVICE_SLEEP | CAP2_AGGRESSIVE_DEVICE_SLEEP;
        let devslp = port.read32(PORT_DEVICE_SLEEP);
        if lpm.capabilities_2 & sleep == sleep
            && self.devslp
            && devslp & DEVICE_SLEEP_PRESENT != 0
            && devslp & DEVICE_SLEEP_AGGRESSIVE != 0
        {
            port.write32(PORT_DEVICE_SLEEP, devslp & !DEVICE_SLEEP_AGGRESSIVE);
            let _ = self.internal(
                port,
                ATA_SET_FEATURES,
                FEATURE_SATA_DISABLE,
                SATA_DEVICE_SLEEP,
                0,
                buffer,
            );
        }
        if policy == LPM_MAX_POWER {
            scr_lpm();
        }
        let old = self.lpm.policy;
        self.lpm.policy = policy;
        if policy >= LPM_MED_POWER_WITH_DIPM
            && lpm.host_dipm()
            && lpm.dipm
            && let Err(error) = dipm(self, FEATURE_SATA_ENABLE)
        {
            self.lpm.policy = old;
            return Err(error);
        }
        Ok(())
    }

    /// Linux `ata_gen_ata_sense` for a failed command without sense data,
    /// from its result taskfile. The error stays the transport's own when
    /// that reports no device error.
    fn generated_sense(&self, failure: &mut Failure) -> Sense {
        let [status, error] = failure.result;
        let sense = if self.locked {
            // Logical unit access not authorized.
            Sense {
                key: Sense::DATA_PROTECT,
                asc: 0x74,
                ascq: 0x71,
            }
        } else {
            translate_error(status, error)
        };
        if self.locked || status & (STATUS_BUSY | STATUS_FAULT | STATUS_ERROR | STATUS_REQUEST) != 0
        {
            failure.error = BlockError::Sense(sense);
        }
        sense
    }

    /// Linux `ata_eh_set_mode` with `ata_set_mode` and `ata_dev_set_mode`:
    /// choose the fastest PIO and UDMA modes the host, the IDENTIFY data and
    /// earlier speed-downs allow, program the UDMA mode with SET FEATURES and
    /// revalidate. A changed mode makes the transfer unverified again.
    fn set_mode(&mut self, port: &impl CommandPort) -> Result<(), BlockError> {
        // A verified transfer clears DUBIOUS on the newest error.
        if !self.dubious
            && let Some(top) = self.errors.top()
        {
            top.eflags &= !EFLAG_DUBIOUS;
        }
        // ata_dev_xfermask: no MWDMA on AHCI, no cable limit on SATA.
        self.pio_mask &= HOST_PIO_MASK & self.transfer.pio;
        self.udma_mask &= HOST_UDMA_MASK & self.transfer.udma;
        if self.quirks & quirks::NODMA != 0 {
            self.udma_mask = 0;
        }
        let pio = highest_mode(self.pio_mask, MODE_PIO_0)
            .ok_or(BlockError::Unsupported("SATA disk without PIO support"))?;
        // libata_dma_mask leaves CompactFlash in PIO, as without UDMA; these
        // drivers issue only DMA commands.
        let mode = highest_mode(self.udma_mask, MODE_UDMA_0)
            .filter(|_| !self.transfer.compact_flash)
            .ok_or(BlockError::Unsupported(
                "SATA disk that libata would run in PIO mode",
            ))?;
        if mode != self.mode {
            self.dubious = true;
        }
        self.mode = mode;
        // ata_dev_set_xfermode: with IORDY in use the mode is sent;
        // otherwise there is nothing to set.
        // NOSETXFER skips it between a SATA host and a SATA device.
        let mut refused = false;
        let skip = self.quirks & quirks::NOSETXFER != 0 && self.transfer.sata;
        if !skip && (pio > MODE_PIO_2 || self.transfer.iordy) {
            let buffer = self.bounce.bus_address();
            match self.internal(
                port,
                ATA_SET_FEATURES,
                FEATURE_TRANSFER_MODE,
                u16::from(mode),
                0,
                buffer,
            ) {
                Ok(()) => {}
                Err(failure) if failure.refused() => refused = true,
                Err(failure) => return Err(failure.error),
            }
        }
        self.revalidate(port)?;
        // A device error is ignored when the disk already runs its fastest
        // mode.
        if refused && highest_mode(self.transfer.udma, MODE_UDMA_0) != Some(mode) {
            return Err(BlockError::Protocol(
                "the SATA disk refused its transfer mode",
            ));
        }
        Ok(())
    }

    /// Linux `ata_down_xfermask_limit`: false when nothing changed or no PIO
    /// mode would remain.
    fn lower_transfer_limit(&mut self, step: StepDown) -> bool {
        let (mut pio, mut udma) = (self.pio_mask, self.udma_mask);
        match step {
            StepDown::Pio => pio &= !(1 << (fls(pio) - 1)),
            StepDown::Dma if udma != 0 => {
                udma &= !(1 << (fls(udma) - 1));
                if udma == 0 {
                    return false;
                }
            }
            StepDown::Dma => {}
            StepDown::FortyWire => udma &= UDMA_MASK_40_WIRE,
        }
        if pio == 0 || (pio, udma) == (self.pio_mask, self.udma_mask) {
            return false;
        }
        (self.pio_mask, self.udma_mask) = (pio, udma);
        true
    }

    /// Linux `ata_eh_request_sense`: REQUEST SENSE DATA EXT, whose D2H FIS
    /// carries the sense key, ASC and ASCQ in LBA bits 23:0. Its own error is
    /// ignored, as ERR might be set; a timeout leaves no result.
    fn request_sense(&mut self, port: &impl CommandPort) -> Result<Option<Sense>, BlockError> {
        let buffer = self.bounce.bus_address();
        if let Err(failure) = self.attempt(
            port,
            AtaRequest {
                command: ATA_REQUEST_SENSE_DATA_EXT,
                feature: 0,
                lba: 0,
                count: 0,
                bytes: 0,
                write: false,
                buffer,
            },
        ) {
            stop_engine(port, self.clock)?;
            start_engine(port);
            if failure.frozen {
                return Ok(None);
            }
        }
        let d2h = &self.commands.bytes()[RECEIVED_D2H..RECEIVED_D2H + FIS_BYTES];
        if d2h[2] & STATUS_SENSE == 0 {
            return Ok(None);
        }
        Ok(valid_sense(d2h[6], d2h[5], d2h[4]))
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

    fn flush_cache(&mut self) -> Result<(), BlockError> {
        match self.flush {
            Some(command) => self.issue(command, 0, 0, 0, false),
            None => self.ready(),
        }
    }

    fn discard(&mut self, lba: u64, blocks: u64) -> Result<(), BlockError> {
        let issue = self.trim(lba, blocks, 0)?;
        let port = self.port;
        self.complete(&port, issue)
    }

    /// Flush, and before power-off spin the disk down, as Linux libata's
    /// `ata_dev_power_set_standby` does on `SYSTEM_POWER_OFF`.
    fn shutdown(&mut self, power_off: bool) -> Result<(), BlockError> {
        self.flush_cache()?;
        if power_off {
            let port = self.port;
            let buffer = self.bounce.bus_address();
            self.internal(&port, ATA_STANDBY_IMMEDIATE, 0, 0, 0, buffer)
                .map_err(|failure| failure.error)?;
        }
        Ok(())
    }

    /// A command per slot while NCQ is on, else one in slot 0, started
    /// under the caller's lock and completed by a later look
    /// ([`Self::finish`]).
    fn depth(&self) -> usize {
        self.queue_depth()
    }

    fn room(&self) -> bool {
        self.free_slot().is_some()
    }

    fn start(&mut self, command: Command) -> Result<u32, BlockError> {
        let tag = self.begin(command)?;
        let port = self.port;
        self.run(&port);
        Ok(tag)
    }

    fn finish(&mut self, tag: u32) -> Option<Finished> {
        let index = self.running.iter().position(|running| running.tag == tag)?;
        if self.running[index].result.is_none() {
            let port = self.port;
            self.run(&port);
        }
        let index = self.running.iter().position(|running| running.tag == tag)?;
        let result = self.running[index].result.take()?;
        self.running.remove(index);
        Some(result)
    }

    /// A started command has a result, or a launched one's ending FIS has
    /// arrived: memory alone. A failure that posts none is seen at a later
    /// look.
    fn posted(&self) -> bool {
        self.running.iter().any(|running| {
            running.result.is_some()
                || running
                    .issue
                    .as_ref()
                    .and_then(|issue| issue.launched.as_ref())
                    .is_some_and(|launched| {
                        ending(launched.queued)
                            .iter()
                            .any(|&(at, kind)| self.commands.read::<u8>(at) == kind)
                    })
        })
    }
}

#[cfg(test)]
mod tests;
