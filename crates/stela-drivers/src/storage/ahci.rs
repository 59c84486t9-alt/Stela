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
    /// The block command started on the port, and the next one's tag.
    running: Option<Running>,
    next_tag: u32,
}

/// A command issued in slot 0, awaiting its ending FIS or an error.
struct Launched {
    queued: bool,
    deadline: Deadline,
    polls: u32,
}

/// One command through libata's error handling ([`AhciDisk::issue_with`]),
/// a step at a time.
struct Issue {
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

/// A started block command, run a bounce buffer's worth at a time.
struct Running {
    tag: u32,
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

/// NCQ as Linux `ata_dev_config_ncq` configures it. The block interface
/// submits one command at a time, so tag 0 is the only one in use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Ncq {
    /// CAP.SNCQ.
    host: bool,
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
        quirks: quirks::quirks(&c_string(IDENTIFY_MODEL), &c_string(IDENTIFY_FIRMWARE)),
        sata_speeds: word(IDENTIFY_SATA_CAPABILITY) & 0xe,
        devslp: word(IDENTIFY_SATA_FEATURES) & SATA_FEATURE_DEVICE_SLEEP != 0,
        trim: word(IDENTIFY_DATA_SET_MANAGEMENT) & DATA_SET_MANAGEMENT_TRIM != 0,
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
    /// The status reported sense data, without a device fault.
    sense_reported: bool,
    /// `ATA_QCFLAG_SENSE_VALID`: the sense data fetched for it.
    sense: Option<Sense>,
    /// PxIS's error bits and SError.
    interrupts: u32,
    serror: u32,
    /// A queued command failed.
    queued: bool,
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
                ..Ncq::default()
            },
            log_dma: false,
            no_dma_log: false,
            quirks: 0,
            devslp: false,
            running: None,
            next_tag: 0,
        };
        let port = disk.port;
        let buffer = disk.bounce.physical();
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

    /// Run `issue` to its result, after the started block command's.
    fn complete(&mut self, port: &impl CommandPort, mut issue: Issue) -> Result<(), BlockError> {
        while self
            .running
            .as_ref()
            .is_some_and(|running| running.result.is_none())
        {
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

    /// Move `issue` on without waiting: launch it, look for its completion,
    /// or recover the port from its failure and retry it as `ata_eh_finish`
    /// decides. A failed command completes by its fetched or generated
    /// sense data, as sd does. Its result once it has one.
    fn step(
        &mut self,
        port: &impl CommandPort,
        issue: &mut Issue,
    ) -> Option<Result<(), BlockError>> {
        if issue.resume.is_some_and(|resume| !resume.passed()) {
            return None;
        }
        issue.resume = None;
        if issue.launched.is_none() {
            if let Err(error) = self.ready() {
                return Some(Err(error));
            }
            let command = self.rw_command(issue.command);
            let buffer = self.bounce.physical();
            match self.launch(
                port,
                command,
                issue.feature,
                issue.lba,
                issue.count,
                issue.bytes,
                issue.write,
                buffer,
            ) {
                Ok(launched) => issue.launched = Some(launched),
                Err(failure) => return Some(Err(failure.error)),
            }
        }
        let result = self.check(port, issue.launched.as_mut()?)?;
        issue.launched = None;
        let mut failure = match result {
            Ok(()) => {
                // ata_verify_xfer: a completed DMA transfer verifies it.
                if issue.io {
                    self.dubious = false;
                }
                return Some(Ok(()));
            }
            Err(failure) => failure,
        };
        if let Err(error) = self.recover(port, &mut failure, issue.io) {
            self.fault = Some(error.clone());
            return Some(Err(error));
        }
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
            command,
            u16::from(feature),
            0,
            count,
            bytes,
            false,
            buffer,
        ) else {
            return Ok(());
        };
        stop_engine(port, self.clock).map_err(Failure::new)?;
        start_engine(port);
        Err(failure)
    }

    /// Issue the command once and wait for its completion or error.
    #[allow(clippy::too_many_arguments)]
    fn attempt(
        &mut self,
        port: &impl CommandPort,
        command: u8,
        feature: u16,
        lba: u64,
        count: u16,
        bytes: usize,
        write: bool,
        buffer: u64,
    ) -> Result<(), Failure> {
        let mut launched = self.launch(port, command, feature, lba, count, bytes, write, buffer)?;
        loop {
            if let Some(result) = self.check(port, &mut launched) {
                return result;
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }

    /// Issue the command once in slot 0.
    #[allow(clippy::too_many_arguments)]
    fn launch(
        &mut self,
        port: &impl CommandPort,
        command: u8,
        feature: u16,
        lba: u64,
        count: u16,
        bytes: usize,
        write: bool,
        buffer: u64,
    ) -> Result<Launched, Failure> {
        let table = self.table.physical();
        self.table.bytes_mut()[..TABLE_HEADER_BYTES].fill(0);
        // A queued command's sector count moves to the features registers;
        // the count register carries its tag, 0, in bits 7:3.
        let queued = matches!(command, ATA_READ_FPDMA_QUEUED | ATA_WRITE_FPDMA_QUEUED);
        let (feature, count) = if queued { (count, 0) } else { (feature, count) };
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
        // The FIS a command ends with lands in the received-FIS area in RAM.
        // Mark its types with the H2D Register type, as a hardreset does, to
        // see one arrive.
        for &(at, _) in ending(queued) {
            self.commands.write(at, FIS_REGISTER_HOST_TO_DEVICE);
        }
        fence(Ordering::SeqCst);
        let deadline = self
            .clock
            .try_deadline(self.command_timeout_us)
            .map_err(|_| Failure::new(BlockError::Timeout))?;
        // ahci_qc_issue: a queued command is active in PxSACT until the
        // disk's Set Device Bits FIS clears it.
        if queued {
            port.write32(PORT_SATA_ACTIVE, 1);
        }
        port.write32(PORT_ISSUE, 1);
        Ok(Launched {
            queued,
            deadline,
            polls: 0,
        })
    }

    /// The launched command's result once it completed, failed or timed
    /// out; never waits. PxIS and PxCI, which a hypervisor traps, are read
    /// when an ending FIS arrived, every few looks since a failure may post
    /// none, and at the deadline.
    fn check(
        &mut self,
        port: &impl CommandPort,
        launched: &mut Launched,
    ) -> Option<Result<(), Failure>> {
        let queued = launched.queued;
        let active = if queued { PORT_SATA_ACTIVE } else { PORT_ISSUE };
        let mut interrupts = 0;
        let mut finished = || {
            interrupts = port.read32(PORT_INTERRUPTS) & INTERRUPT_ERROR;
            interrupts != 0 || port.read32(active) & 1 == 0
        };
        // The first look reads the registers too: an emulated port may
        // finish at the PxCI write.
        let due = launched.polls.is_multiple_of(REGISTER_POLL_INTERVAL);
        launched.polls = launched.polls.wrapping_add(1);
        let posted = ending(queued)
            .iter()
            .any(|&(at, kind)| self.commands.read::<u8>(at) == kind);
        let done = if (posted || due) && finished() {
            true
        } else if launched.deadline.passed() {
            finished()
        } else {
            return None;
        };
        fence(Ordering::SeqCst);
        if done && interrupts == 0 {
            return Some(Ok(()));
        }
        // AHCI needs SError cleared; otherwise it might lock up.
        let serror = port.read32(PORT_SATA_ERROR);
        port.write32(PORT_SATA_ERROR, serror);
        port.write32(PORT_INTERRUPTS, port.read32(PORT_INTERRUPTS));
        let mut failure = classify(interrupts, serror, port.read32(PORT_TASK_FILE), !done);
        // ahci_qc_fill_rtf, before error handling issues anything else: the
        // Set Device Bits FIS for a queued command, else the last D2H FIS.
        let fis = if queued { RECEIVED_SDB } else { RECEIVED_D2H };
        let fis = &self.commands.bytes()[fis..fis + FIS_BYTES];
        failure.result = [fis[2], fis[3]];
        failure.queued = queued;
        Some(Err(failure))
    }

    /// Take `command` as the started block command.
    fn begin(&mut self, command: Command) -> Result<u32, BlockError> {
        self.ready()?;
        let command = command.within(&self.identity, 0)?;
        if self.running.is_some() {
            return Err(BlockError::Protocol(
                "an AHCI port runs one command at a time",
            ));
        }
        let tag = self.next_tag;
        self.next_tag = tag.wrapping_add(1);
        self.running = Some(Running {
            tag,
            command,
            done: 0,
            data: Vec::new(),
            issue: None,
            result: None,
        });
        Ok(tag)
    }

    /// Move the started block command on as far as it goes without waiting.
    fn run(&mut self, port: &impl CommandPort) {
        let Some(mut running) = self.running.take() else {
            return;
        };
        while running.result.is_none() {
            let Some(issue) = running.issue.as_mut() else {
                match self.next_issue(&running) {
                    Ok(Some(issue)) => running.issue = Some(issue),
                    Ok(None) => {
                        let data = core::mem::take(&mut running.data);
                        let read = matches!(running.command, Command::Read { .. });
                        running.result = Some(Ok(read.then_some(data)));
                    }
                    Err(error) => running.result = Some(Err(error)),
                }
                continue;
            };
            match self.step(port, issue) {
                None => break,
                Some(Err(error)) => running.result = Some(Err(error)),
                Some(Ok(())) => {
                    let bytes = issue.bytes;
                    if let Command::Read { .. } = running.command {
                        running
                            .data
                            .extend_from_slice(&self.bounce.bytes()[..bytes]);
                    }
                    running.done += bytes.max(1);
                    running.issue = None;
                }
            }
        }
        self.running = Some(running);
    }

    /// The next part of `running`'s command, its data staged in the bounce
    /// buffer, or `None` once all of it is done.
    fn next_issue(&mut self, running: &Running) -> Result<Option<Issue>, BlockError> {
        let block = self.identity.block_size as usize;
        let done = running.done;
        match &running.command {
            Command::Read { lba, bytes } if done < *bytes => {
                let part = (bytes - done).min(self.chunk_bytes());
                let first = lba + (done / block) as u64;
                let count = self.sectors(part);
                self.prepare((ATA_READ_DMA_EXT, 0), first, count, part, false)
                    .map(Some)
            }
            Command::Write {
                lba,
                data,
                fua: false,
            } if done < data.len() => {
                let part = (data.len() - done).min(self.chunk_bytes());
                self.bounce.bytes_mut()[..part].copy_from_slice(&data[done..done + part]);
                let first = lba + (done / block) as u64;
                let count = self.sectors(part);
                self.prepare((ATA_WRITE_DMA_EXT, 0), first, count, part, true)
                    .map(Some)
            }
            Command::Flush if done == 0 => match self.flush {
                Some(command) => self.prepare((command, 0), 0, 0, 0, false).map(Some),
                None => Ok(None),
            },
            Command::Discard { lba, blocks } if done == 0 => self.trim(*lba, *blocks).map(Some),
            Command::Write { fua: true, .. } => Err(BlockError::Unsupported(
                "the device takes no Force Unit Access",
            )),
            Command::WriteZeroes { .. } => {
                Err(BlockError::Unsupported("the device takes no Write Zeroes"))
            }
            _ => Ok(None),
        }
    }

    /// TRIM in one block of ranges, as libata's `ata_format_dsm_trim_descr`
    /// writes them: each the starting logical sector in bits 47:0 and the
    /// count in bits 63:48.
    fn trim(&mut self, lba: u64, blocks: u64) -> Result<Issue, BlockError> {
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
        let ranges = &mut self.bounce.bytes_mut()[..ATA_SECTOR_BYTES as usize];
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
        let buffer = self.table.physical() + IDENTIFY_DATA as u64;
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
        let buffer = self.bounce.physical();
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
        let buffer = self.table.physical() + LOG_DATA as u64;
        let lba = u64::from(log) | u64::from(page) << 8;
        loop {
            let dma = self.log_dma && !self.no_dma_log;
            let command = if dma {
                ATA_READ_LOG_DMA_EXT
            } else {
                ATA_READ_LOG_EXT
            };
            let bytes = ATA_SECTOR_BYTES as usize;
            let Err(failure) = self.attempt(port, command, 0, lba, 1, bytes, false, buffer) else {
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
    /// autosense, its sense data. Whether it named the active command.
    fn analyze_ncq_error(
        &mut self,
        port: &impl CommandPort,
        failure: &mut Failure,
    ) -> Result<bool, BlockError> {
        if !self.read_log(port, LOG_SATA_NCQ, 0)? {
            return Ok(false);
        }
        let log = &self.table.bytes()[LOG_DATA..LOG_DATA + ATA_SECTOR_BYTES as usize];
        if log[0] & LOG_NCQ_NQ != 0 || log[0] & LOG_NCQ_TAG != 0 {
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
        let buffer = self.bounce.physical();
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
            let buffer = self.bounce.physical();
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
        let buffer = self.bounce.physical();
        if let Err(failure) =
            self.attempt(port, ATA_REQUEST_SENSE_DATA_EXT, 0, 0, 0, 0, false, buffer)
        {
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
        let issue = self.trim(lba, blocks)?;
        let port = self.port;
        self.complete(&port, issue)
    }

    /// Flush, and before power-off spin the disk down, as Linux libata's
    /// `ata_dev_power_set_standby` does on `SYSTEM_POWER_OFF`.
    fn shutdown(&mut self, power_off: bool) -> Result<(), BlockError> {
        self.flush_cache()?;
        if power_off {
            let port = self.port;
            let buffer = self.bounce.physical();
            self.internal(&port, ATA_STANDBY_IMMEDIATE, 0, 0, 0, buffer)
                .map_err(|failure| failure.error)?;
        }
        Ok(())
    }

    /// One command at a time in slot 0, started under the caller's lock and
    /// completed by a later look ([`Self::finish`]).
    fn depth(&self) -> usize {
        1
    }

    fn room(&self) -> bool {
        self.running.is_none()
    }

    fn start(&mut self, command: Command) -> Result<u32, BlockError> {
        let tag = self.begin(command)?;
        let port = self.port;
        self.run(&port);
        Ok(tag)
    }

    fn finish(&mut self, tag: u32) -> Option<Finished> {
        if self.running.as_ref()?.tag != tag {
            return None;
        }
        let port = self.port;
        self.run(&port);
        let result = self.running.as_mut()?.result.take()?;
        self.running = None;
        Some(result)
    }

    /// The running command's ending FIS has arrived: memory alone. A
    /// failure that posts none is seen at a later look.
    fn posted(&self) -> bool {
        self.running.as_ref().is_some_and(|running| {
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
        /// The command completes.
        Complete,
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
                        // Clearing ST clears PxCI and PxSACT.
                        registers[PORT_ISSUE / 4] = 0;
                        registers[PORT_SATA_ACTIVE / 4] = 0;
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
                        None | Some(Fault::Complete) => {
                            registers[PORT_TASK_FILE / 4] = READY;
                            registers[PORT_SATA_ACTIVE / 4] = 0;
                        }
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
                                Fault::Complete => unreachable!(),
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
        put(IDENTIFY_CAPABILITY, CAPABILITY_IORDY);
        put(IDENTIFY_FIELD_VALID, FIELD_VALID_PIO | FIELD_VALID_UDMA);
        put(IDENTIFY_PIO_MODES, 0x03);
        put(IDENTIFY_UDMA_MODES, 0x7f);
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
        fixture.disk.transfer = found.transfer;
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
                        features: Features::default(),
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
                    sense_reporting: true,
                    transfer: Transfer::default(),
                    // As configured: PIO 0-4 and UDMA 0-6.
                    pio_mask: 0x1f,
                    udma_mask: 0x7f,
                    mode: 0x46,
                    step_downs: 0,
                    locked: false,
                    lpm: Lpm::default(),
                    ncq: Ncq::default(),
                    log_dma: false,
                    no_dma_log: false,
                    quirks: 0,
                    devslp: false,
                    running: None,
                    next_tag: 0,
                },
                _registers: registers,
                _memory: memory,
            }
        }
    }

    #[test]
    fn device_errors_restart_the_engine_and_follow_ata_eh_worth_retry() {
        // An aborted read revalidates the disk without a reset (IDENTIFY,
        // SET FEATURES with UDMA 6 and its IDENTIFY) and is retried after
        // the engine restarts.
        let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
        let link = Link::new(&[Fault::TaskFile(0x0451)]);
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
            Ok(())
        );
        assert_eq!(link.issued.get(), 5);
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
        assert_eq!(link.issued.get(), 4);
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
        let link = Link::new(&[]);
        for _ in 0..7 {
            link.faults.borrow_mut().extend([
                Fault::TaskFile(0x0451),
                Fault::Complete,
                Fault::Complete,
                Fault::Complete,
            ]);
        }
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_WRITE_DMA_EXT, 0, 1, 512, true),
            Err(BlockError::Device { status: 0x0451 })
        );
        assert_eq!(link.issued.get(), 6 * 4);
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
            // The write, the revalidating IDENTIFY, SET FEATURES with UDMA 6
            // and its IDENTIFY, and the write again.
            assert_eq!(link.issued.get(), 5);
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
            assert_eq!(fixture.disk.mode, 0x46);
            assert_eq!(
                fixture.disk.commands.bytes()[RECEIVED_D2H..RECEIVED_D2H + 8],
                [0x27, 0, 0x80, 0, 0, 0, 0, 0xa0]
            );
            assert!(fixture.disk.fault.is_none());
        }
    }

    #[test]
    fn started_commands_complete_at_a_later_look_without_waiting() {
        let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
        // A write is staged in the bounce buffer and completes at once.
        let link = Link::new(&[]);
        let data: Vec<u8> = (0..1024).map(|byte| byte as u8).collect();
        let disk = &mut fixture.disk;
        let tag = disk
            .begin(Command::Write {
                lba: 8,
                data: data.clone(),
                fua: false,
            })
            .unwrap();
        disk.run(&link);
        assert_eq!(disk.running.as_ref().unwrap().tag, tag);
        assert_eq!(disk.running.as_mut().unwrap().result.take(), Some(Ok(None)));
        assert_eq!(&disk.bounce.bytes()[..1024], &data[..]);
        assert_eq!(disk.table.bytes()[2], ATA_WRITE_DMA_EXT);
        disk.running = None;

        // A read the disk has not finished leaves the port running.
        let link = Link::new(&[Fault::Timeout]);
        let tag = disk.begin(Command::Read { lba: 0, bytes: 512 }).unwrap();
        assert!(!disk.room());
        assert_eq!(
            disk.begin(Command::Flush),
            Err(BlockError::Protocol(
                "an AHCI port runs one command at a time"
            ))
        );
        disk.run(&link);
        assert!(disk.running.as_ref().unwrap().result.is_none());
        assert_eq!(link.issued.get(), 1);
        // Its D2H Register FIS arrives with PxCI clear: the next look ends it.
        disk.bounce.bytes_mut()[..512].fill(0x5a);
        link.registers.borrow_mut()[PORT_ISSUE / 4] = 0;
        link.registers.borrow_mut()[PORT_TASK_FILE / 4] = READY;
        disk.commands
            .write(RECEIVED_D2H, FIS_REGISTER_DEVICE_TO_HOST);
        disk.run(&link);
        let running = disk.running.as_mut().unwrap();
        assert_eq!(running.tag, tag);
        assert_eq!(running.result.take(), Some(Ok(Some(vec![0x5a; 512]))));
        assert_eq!(link.issued.get(), 1);
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
        // Past the slowest link the UDMA mode steps down, to UDMA 5 and
        // then to the 40-wire UDMA 2, each reprogrammed with SET FEATURES.
        assert_eq!((fixture.disk.udma_mask, fixture.disk.mode), (0x3f, 0x45));
        for _ in 0..4 {
            link.faults.borrow_mut().push_back(Fault::Interface);
            fixture
                .disk
                .issue_on(&link, ATA_WRITE_DMA_EXT, 9, 1, 512, true)
                .unwrap();
        }
        assert_eq!((fixture.disk.udma_mask, fixture.disk.mode), (0x07, 0x42));
        for _ in 0..4 {
            link.faults.borrow_mut().push_back(Fault::Interface);
            fixture
                .disk
                .issue_on(&link, ATA_WRITE_DMA_EXT, 9, 1, 512, true)
                .unwrap();
        }
        assert_eq!((fixture.disk.udma_mask, fixture.disk.step_downs), (0x07, 2));

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

        // Device errors that only revalidate get a reset when they slow the
        // link.
        let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
        let link = Link::new(&[]);
        for _ in 0..6 {
            link.faults.borrow_mut().extend([
                Fault::TaskFile(0x0451),
                Fault::Complete,
                Fault::Complete,
                Fault::Complete,
            ]);
        }
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
    fn amd_raid_class_functions_bind_like_ahci_pci_tbl() {
        struct Config([u32; 4]);
        impl ConfigSpace for Config {
            fn read32(&self, offset: u16) -> u32 {
                self.0[usize::from(offset / 4)]
            }
            fn write32(&mut self, _: u16, _: u32) {}
        }
        let function = |vendor: u32, class: u32| {
            let address = crate::bus::pci::Address {
                segment: 0,
                bus: 0,
                device: 0,
                function: 0,
            };
            Function::new(address, Config([0x43f6 << 16 | vendor, 0, class << 8, 0])).unwrap()
        };
        assert!(matches(&function(0x1022, 0x01_06_01)));
        assert!(matches(&function(0x8086, 0x01_06_01)));
        assert!(matches(&function(0x1022, 0x01_04_00)));
        assert!(!matches(&function(0x8086, 0x01_04_00)));
        assert!(!matches(&function(0x1022, 0x01_04_01)));
        assert!(!matches(&function(0x1022, 0x01_06_00)));
    }

    #[test]
    fn transfer_modes_follow_ata_id_xfermask_and_ata_set_mode() {
        fn words(pairs: &[(usize, u16)]) -> impl Fn(usize) -> u16 + '_ {
            move |index| {
                pairs
                    .iter()
                    .find(|(at, _)| *at == index)
                    .map_or(0, |(_, value)| *value)
            }
        }
        let modern = Transfer::from_identify(words(&[(53, 0x06), (64, 0x03), (88, 0x7f)]));
        assert_eq!((modern.pio, modern.udma), (0x1f, 0x7f));
        // Without word 64, word 51 names the fastest PIO mode.
        let old = Transfer::from_identify(words(&[(51, 2 << 8)]));
        assert_eq!((old.pio, old.udma), (0x07, 0));
        assert_eq!(Transfer::from_identify(words(&[(51, 7 << 8)])).pio, 1);
        assert!(Transfer::from_identify(words(&[(0, 0x848a)])).compact_flash);
        assert!(Transfer::from_identify(words(&[(83, 0x4004)])).compact_flash);

        // SET FEATURES carries the mode, then IDENTIFY revalidates.
        let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
        fixture.disk.mode = 0;
        let link = Link::new(&[]);
        fixture.disk.set_mode(&link).unwrap();
        assert_eq!(fixture.disk.mode, 0x46);
        assert!(fixture.disk.dubious);
        assert_eq!(link.issued.get(), 2);
        // A refusal is ignored only at the disk's fastest mode.
        let link = Link::new(&[Fault::TaskFile(0x0451)]);
        assert_eq!(fixture.disk.set_mode(&link), Ok(()));
        fixture.disk.udma_mask = 0x1f;
        let link = Link::new(&[Fault::TaskFile(0x0451)]);
        assert!(fixture.disk.set_mode(&link).is_err());
        assert_eq!(fixture.disk.mode, 0x44);
        // No UDMA: libata would use PIO commands these drivers do not issue.
        fixture.disk.udma_mask = 0;
        assert!(matches!(
            fixture.disk.set_mode(&Link::new(&[])),
            Err(BlockError::Unsupported(_))
        ));

        // ata_down_xfermask_limit.
        fixture.disk.pio_mask = 0x1f;
        fixture.disk.udma_mask = 0x7f;
        assert!(fixture.disk.lower_transfer_limit(StepDown::Dma));
        assert_eq!(fixture.disk.udma_mask, 0x3f);
        assert!(fixture.disk.lower_transfer_limit(StepDown::FortyWire));
        assert_eq!(fixture.disk.udma_mask, 0x07);
        assert!(!fixture.disk.lower_transfer_limit(StepDown::FortyWire));
        fixture.disk.udma_mask = 0x01;
        assert!(!fixture.disk.lower_transfer_limit(StepDown::Dma));
        assert!(fixture.disk.lower_transfer_limit(StepDown::Pio));
        assert_eq!(fixture.disk.pio_mask, 0x0f);
        fixture.disk.pio_mask = 0x01;
        assert!(!fixture.disk.lower_transfer_limit(StepDown::Pio));
    }

    #[test]
    fn link_power_management_follows_ata_eh_link_set_lpm() {
        let host = CAP_AGGRESSIVE_LPM | CAP_SLUMBER | CAP_PARTIAL;
        // Hotplug-capable and eSATA ports, and hosts without LPM states,
        // stay at maximum power.
        assert!(!Lpm::new(host, 0, COMMAND_HOTPLUG).allowed);
        assert!(!Lpm::new(host | CAP_EXTERNAL, 0, COMMAND_EXTERNAL).allowed);
        assert!(Lpm::new(host, 0, COMMAND_EXTERNAL).allowed);
        assert!(!Lpm::new(CAP_AGGRESSIVE_LPM, 0, 0).allowed);
        assert!(Lpm::new(CAP_AGGRESSIVE_LPM, CAP2_DEVICE_SLEEP, 0).allowed);

        let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
        fixture.disk.lpm = Lpm {
            hipm: true,
            dipm: true,
            ..Lpm::new(host, 0, 0)
        };
        let link = Link::new(&[]);
        fixture.disk.configure_lpm(&link, DEVICE_TRIES).unwrap();
        // DIPM off and on around Partial and Slumber allowed with ALPE.
        assert_eq!(link.issued.get(), 2);
        assert_eq!(link.writes_to(PORT_SATA_CONTROL), [0x400]);
        assert_ne!(link.read32(PORT_COMMAND) & COMMAND_AGGRESSIVE_LPM, 0);
        assert_eq!(fixture.disk.lpm.policy, LPM_MED_POWER_WITH_DIPM);

        // A hard reset wakes the link to maximum power before revalidating,
        // then restores the policy; without HIPM, ALPE stays off.
        fixture.disk.lpm.hipm = false;
        let link = Link::new(&[Fault::Timeout]);
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_FLUSH_CACHE_EXT, 0, 0, 0, false),
            Ok(())
        );
        let controls = link.writes_to(PORT_SATA_CONTROL);
        assert!(controls.ends_with(&[0x700, 0x400]), "{controls:x?}");
        assert_eq!(link.read32(PORT_COMMAND) & COMMAND_AGGRESSIVE_LPM, 0);
        assert_eq!(fixture.disk.lpm.policy, LPM_MED_POWER_WITH_DIPM);

        // A failure with two tries left disables LPM; the old policy stays.
        // (The revalidation's IDENTIFY data reported no DIPM.)
        fixture.disk.lpm.dipm = true;
        let link = Link::new(&[Fault::Timeout]);
        assert_eq!(
            fixture.disk.set_lpm(&link, LPM_MAX_POWER, 2),
            Err(BlockError::Timeout)
        );
        assert!(!fixture.disk.lpm.allowed);
        assert_eq!(fixture.disk.lpm.policy, LPM_MED_POWER_WITH_DIPM);
    }

    #[test]
    fn generated_sense_follows_ata_to_sense_error() {
        let sense = |key, asc, ascq| Sense { key, asc, ascq };
        for (status, error, expected) in [
            (0x51, 0x40, sense(Sense::MEDIUM_ERROR, 0x11, 0x04)),
            (0x51, 0x84, sense(Sense::ABORTED_COMMAND, 0x47, 0x00)),
            (0x51, 0x10, sense(Sense::ILLEGAL_REQUEST, 0x21, 0x00)),
            (0x51, 0x20, sense(Sense::UNIT_ATTENTION, 0x28, 0x00)),
            (0x51, 0x37, sense(Sense::NOT_READY, 0x04, 0x00)),
            (0x51, 0x61, sense(Sense::HARDWARE_ERROR, 0x00, 0x00)),
            (0x51, 0xd1, sense(Sense::ABORTED_COMMAND, 0x00, 0x00)),
            // ABRT alone falls back to the status.
            (0x55, 0x04, sense(Sense::RECOVERED_ERROR, 0x00, 0x00)),
            (0x71, 0x04, sense(Sense::HARDWARE_ERROR, 0x44, 0x00)),
            (0x51, 0x04, sense(Sense::ABORTED_COMMAND, 0x00, 0x00)),
            // Busy invalidates the error register.
            (0xd0, 0x40, sense(Sense::ABORTED_COMMAND, 0x00, 0x00)),
        ] {
            assert_eq!(
                translate_error(status, error),
                expected,
                "{status:x} {error:x}"
            );
        }

        // The D2H FIS a failed flush completes with decides it.
        let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
        let mut complete_with = |status: u8, error: u8, locked| {
            fixture.disk.locked = locked;
            let d2h = &mut fixture.disk.commands.bytes_mut()[RECEIVED_D2H..];
            (d2h[2], d2h[3]) = (status, error);
            let link = Link::new(&[Fault::TaskFile(u32::from(error) << 8 | 0x51)]);
            let result = fixture
                .disk
                .issue_on(&link, ATA_FLUSH_CACHE_EXT, 0, 0, 0, false);
            (result, link.issued.get())
        };
        // A media change is requeued, a corrected error completes.
        assert_eq!(complete_with(0x51, 0x20, false), (Ok(()), 2));
        assert_eq!(complete_with(0x55, 0x04, false), (Ok(()), 1));
        assert_eq!(
            complete_with(0x51, 0x04, false),
            (
                Err(BlockError::Sense(sense(Sense::ABORTED_COMMAND, 0, 0))),
                1
            )
        );
        assert_eq!(
            complete_with(0x51, 0x04, true),
            (
                Err(BlockError::Sense(sense(Sense::DATA_PROTECT, 0x74, 0x71))),
                1
            )
        );
        // A FIS without a device error keeps the transport's error.
        assert_eq!(
            complete_with(0x50, 0x00, false),
            (Err(BlockError::Device { status: 0x51 }), 1)
        );
    }

    #[test]
    fn ncq_follows_ata_dev_config_ncq_and_ata_eh_analyze_ncq_error() {
        // NCQ with auto-activation, NCQ autosense and READ LOG DMA EXT.
        let mut page = identify_page("S1", 1024);
        for (word, value) in [(76u16, 1u16 << 8), (78, 0x84), (86, 1 << 15), (119, 0x4008)] {
            let at = 2 * usize::from(word);
            page[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        let found = identify(&page).unwrap();
        let (mut fixture, _clock) = recovering(page);
        fixture.disk.ncq.host = true;

        // ata_dev_config_ncq enables auto-activation; a refusal is ignored,
        // any other failure marks it broken.
        let link = Link::new(&[]);
        fixture.disk.configure(&link, &found).unwrap();
        assert_eq!(fixture.disk.table.bytes()[2..4], [ATA_SET_FEATURES, 0x10]);
        assert_eq!(fixture.disk.table.bytes()[12], 0x02);
        let link = Link::new(&[Fault::TaskFile(0x0451)]);
        fixture.disk.configure(&link, &found).unwrap();
        let link = Link::new(&[Fault::Interface]);
        assert!(fixture.disk.configure(&link, &found).is_err());
        assert!(fixture.disk.ncq.aa_broken);
        let link = Link::new(&[]);
        fixture.disk.configure(&link, &found).unwrap();
        assert_eq!(link.issued.get(), 0);
        assert!(fixture.disk.ncq.enabled());

        // A read is queued: the count in the features registers, tag 0.
        let link = Link::new(&[]);
        let read = |fixture: &mut Fixture, link: &Link| {
            fixture
                .disk
                .issue_on(link, ATA_READ_DMA_EXT, 0x1234, 8, 4096, false)
        };
        read(&mut fixture, &link).unwrap();
        let fis = &fixture.disk.table.bytes()[..14];
        assert_eq!(
            [fis[2], fis[3], fis[4], fis[7], fis[11], fis[12]],
            [ATA_READ_FPDMA_QUEUED, 8, 0x34, DEVICE_LBA, 0, 0]
        );
        assert_eq!(link.writes_to(PORT_SATA_ACTIVE), [1]);

        // An uncorrectable queued read: READ LOG DMA EXT fails and READ LOG
        // EXT names tag 0 with its autosense data. A medium error is not
        // retried; ERR_MEDIA revalidates without a reset.
        let log = &mut fixture.disk.table.bytes_mut()[LOG_DATA..LOG_DATA + 512];
        log[..4].copy_from_slice(&[0, 0, 0x43, 0x40]);
        log[14..17].copy_from_slice(&[Sense::MEDIUM_ERROR, 0x11, 0x04]);
        let link = Link::new(&[Fault::TaskFile(0x4041), Fault::TaskFile(0x0451)]);
        assert_eq!(
            read(&mut fixture, &link),
            Err(BlockError::Sense(Sense {
                key: Sense::MEDIUM_ERROR,
                asc: 0x11,
                ascq: 0x04,
            }))
        );
        assert!(fixture.disk.no_dma_log);
        // The read, both log reads, then IDENTIFY, SET FEATURES UDMA 6 and
        // IDENTIFY; auto-activation stays broken.
        assert_eq!(link.issued.get(), 6);
        assert!(link.writes_to(PORT_SATA_CONTROL).is_empty());

        // Four aborted reads in ten minutes turn NCQ off, without a reset.
        fixture.disk.table.bytes_mut()[LOG_DATA + 2..LOG_DATA + 4].copy_from_slice(&[0x51, 0x04]);
        for _ in 0..4 {
            assert!(fixture.disk.ncq.enabled());
            let link = Link::new(&[Fault::TaskFile(0x0451)]);
            read(&mut fixture, &link).unwrap();
            assert!(link.writes_to(PORT_SATA_CONTROL).is_empty());
        }
        assert!(fixture.disk.ncq.off);
        read(&mut fixture, &Link::new(&[])).unwrap();
        assert_eq!(fixture.disk.table.bytes()[2], ATA_READ_DMA_EXT);
    }

    #[test]
    fn quirks_configure_the_disk_like_ata_dev_configure() {
        // An NCQ disk with auto-activation, by model and firmware revision.
        let page = |model: &str, firmware: &str| {
            let mut page = identify_page("S1", 1024);
            for (words, text) in [(IDENTIFY_MODEL, model), (IDENTIFY_FIRMWARE, firmware)] {
                let mut bytes = text.as_bytes().to_vec();
                bytes.resize(2 * words.len(), b' ');
                page[2 * words.start..2 * words.end].copy_from_slice(&bytes);
                for pair in page[2 * words.start..2 * words.end].chunks_mut(2) {
                    pair.swap(0, 1);
                }
            }
            for (word, value) in [(76u16, 1u16 << 8 | 0x6), (78, 0x04)] {
                let at = 2 * usize::from(word);
                page[at..at + 2].copy_from_slice(&value.to_le_bytes());
            }
            identify(&page).unwrap()
        };
        let configure = |found: &Identified| {
            let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
            fixture.disk.ncq.host = true;
            (fixture.disk.configure(&Link::new(&[]), found), fixture)
        };

        // Without a quirk: NCQ and auto-activation.
        let (result, fixture) = configure(&page("Fixture SSD", "1.0"));
        assert_eq!(result, Ok(()));
        assert!(fixture.disk.ncq.enabled());
        assert_eq!(fixture.disk.quirks, 0);
        // Seagate's NCQ and FLUSH CACHE firmware bug: neither.
        let (result, fixture) = configure(&page("ST31500341AS", "SD17"));
        assert_eq!(result, Ok(()));
        assert!(!fixture.disk.ncq.enabled());
        assert_eq!(fixture.disk.table.bytes()[2], 0);
        // Broken LPM forces max_power.
        let (_, fixture) = configure(&page("ADATA SU680", "1.0"));
        assert_eq!(fixture.disk.lpm.target(), LPM_MAX_POWER);
        // A 1.5 Gbps limit on a 3 Gbps link takes another reset.
        let (result, fixture) = configure(&page("WD My Book", "1.0"));
        assert_eq!(result, Err(AGAIN));
        assert_eq!(fixture.disk.speed_limit, 0b1);
    }

    #[test]
    fn devslp_follows_ata_dev_config_devslp_and_ahci_set_aggressive_devslp() {
        let mut page = identify_page("S1", 1024);
        page[2 * 78..2 * 78 + 2].copy_from_slice(&(1u16 << 8).to_le_bytes());
        let found = identify(&page).unwrap();
        let (mut fixture, _clock) = recovering(page);
        // One buffer answers all three log reads: the directory lists the
        // IDENTIFY DEVICE data log, whose page 0 lists SATA Settings.
        let log = &mut fixture.disk.table.bytes_mut()[LOG_DATA..LOG_DATA + 512];
        (log[8], log[9], log[2 * 0x30]) = (1, LOG_SATA_SETTINGS, 1);
        let link = Link::new(&[]);
        fixture.disk.configure(&link, &found).unwrap();
        assert!(fixture.disk.devslp);
        assert_eq!(link.issued.get(), 3);

        // Firmware's aggressive DevSleep is turned off on the way to
        // max_power, before SControl lifts the restrictions.
        fixture.disk.lpm.capabilities_2 = CAP2_DEVICE_SLEEP | CAP2_AGGRESSIVE_DEVICE_SLEEP;
        link.registers.borrow_mut()[PORT_DEVICE_SLEEP / 4] = 0x3;
        fixture.disk.apply_lpm(&link, LPM_MAX_POWER).unwrap();
        assert_eq!(link.writes_to(PORT_DEVICE_SLEEP), [DEVICE_SLEEP_PRESENT]);
        let table = fixture.disk.table.bytes();
        assert_eq!(
            [table[2], table[3], table[12]],
            [ATA_SET_FEATURES, 0x90, 0x09]
        );
        let order: Vec<usize> = link
            .writes
            .borrow()
            .iter()
            .filter(|(at, _)| matches!(*at, PORT_DEVICE_SLEEP | PORT_SATA_CONTROL))
            .map(|(at, _)| *at)
            .collect();
        assert_eq!(order, [PORT_DEVICE_SLEEP, PORT_SATA_CONTROL]);

        // Without the IDENTIFY DEVICE data log the disk gets NO_ID_DEV_LOG.
        fixture.disk.table.bytes_mut()[LOG_DATA + 2 * 0x30] = 0;
        fixture.disk.configure(&link, &found).unwrap();
        assert!(!fixture.disk.devslp);
        assert_ne!(fixture.disk.quirks & quirks::NO_ID_DEV_LOG, 0);
    }

    #[test]
    fn revalidation_reenables_sense_reporting_like_ata_dev_configure() {
        // A disk whose reset left Sense Data Reporting supported but off.
        let mut page = identify_page("S1", 1024);
        for (word, value) in [(86u16, 1u16 << 15), (119, 0x4040), (120, 0x4000)] {
            let at = 2 * usize::from(word);
            page[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        let issued = |page| {
            let (mut fixture, _clock) = recovering(page);
            let link = Link::new(&[Fault::Timeout]);
            fixture
                .disk
                .issue_on(&link, ATA_FLUSH_CACHE_EXT, 0, 0, 0, false)
                .unwrap();
            link.issued.get()
        };
        // Each of the two revalidations turns it back on.
        assert_eq!(issued(page), issued(identify_page("S1", 1024)) + 2);
    }

    #[test]
    fn sense_reporting_follows_ata_id_sense_reporting_enabled() {
        fn words(pairs: &[(usize, u16)]) -> impl Fn(usize) -> u16 + '_ {
            move |index| {
                pairs
                    .iter()
                    .find(|(at, _)| *at == index)
                    .map_or(0, |(_, value)| *value)
            }
        }
        let supported = [(86, 1 << 15), (119, 0x4040)];
        assert_eq!(sense_reporting(words(&supported)), (true, false));
        let enabled = [(86, 1 << 15), (119, 0x4040), (120, 0x4040)];
        assert_eq!(sense_reporting(words(&enabled)), (true, true));
        // Words 119 and 120 need word 86 bit 15 and their own 01b signature.
        assert_eq!(
            sense_reporting(words(&[(119, 0x4040), (120, 0x4040)])),
            (false, false)
        );
        assert_eq!(
            sense_reporting(words(&[(86, 1 << 15), (119, 0xc040), (120, 0x4040)])),
            (false, false)
        );
        assert_eq!(
            sense_reporting(words(&[(86, 1 << 15), (119, 0x4040), (120, 0x0040)])),
            (true, false)
        );
    }

    #[test]
    fn sense_dispositions_follow_scsi_check_sense_and_sd_completion() {
        let sense = |key, asc, ascq| Sense { key, asc, ascq };
        for (key, asc, ascq, retry, done) in [
            (
                Sense::ABORTED_COMMAND,
                0x00,
                0x00,
                true,
                SenseCompletion::Fail,
            ),
            (
                Sense::ABORTED_COMMAND,
                0x10,
                0x01,
                false,
                SenseCompletion::Fail,
            ),
            (
                Sense::ABORTED_COMMAND,
                0x2e,
                0x02,
                false,
                SenseCompletion::Fail,
            ),
            (
                Sense::ABORTED_COMMAND,
                0x2e,
                0x04,
                true,
                SenseCompletion::Fail,
            ),
            (
                Sense::NOT_READY,
                0x04,
                0x01,
                true,
                SenseCompletion::Retry(9_000),
            ),
            (
                Sense::NOT_READY,
                0x04,
                0x0a,
                true,
                SenseCompletion::Retry(1_000_000),
            ),
            (
                Sense::NOT_READY,
                0x04,
                0x1b,
                false,
                SenseCompletion::Retry(9_000),
            ),
            (Sense::NOT_READY, 0x04, 0x02, false, SenseCompletion::Fail),
            (Sense::NOT_READY, 0x04, 0x24, false, SenseCompletion::Fail),
            (Sense::NOT_READY, 0x3a, 0x00, false, SenseCompletion::Fail),
            (
                Sense::UNIT_ATTENTION,
                0x29,
                0x00,
                false,
                SenseCompletion::Retry(0),
            ),
            (
                Sense::UNIT_ATTENTION,
                0x3f,
                0x0e,
                true,
                SenseCompletion::Retry(0),
            ),
            (
                Sense::MEDIUM_ERROR,
                0x11,
                0x04,
                false,
                SenseCompletion::Fail,
            ),
            (Sense::MEDIUM_ERROR, 0x0c, 0x00, true, SenseCompletion::Fail),
            (
                Sense::RECOVERED_ERROR,
                0x17,
                0x01,
                false,
                SenseCompletion::Done,
            ),
            (
                Sense::ILLEGAL_REQUEST,
                0x21,
                0x00,
                false,
                SenseCompletion::Fail,
            ),
            (0x04, 0x44, 0x00, false, SenseCompletion::Fail),
        ] {
            let sense = sense(key, asc, ascq);
            assert_eq!(sense.needs_retry(), retry, "{sense:?}");
            assert_eq!(sense.completion(false), done, "{sense:?}");
            // On a removable unit, UNIT ATTENTION reports a media change.
            if sense.key == Sense::UNIT_ATTENTION {
                assert_eq!(sense.completion(true), SenseCompletion::MediaChanged);
            }
        }
    }

    #[test]
    fn reported_sense_data_is_fetched_and_decides_completion_like_libata() {
        // The disk's D2H FIS for REQUEST SENSE DATA EXT.
        let reply = |fixture: &mut Fixture, status: u8, sense: [u8; 3]| {
            let d2h = &mut fixture.disk.commands.bytes_mut()[RECEIVED_D2H..];
            d2h[2] = status;
            d2h[4] = sense[2];
            d2h[5] = sense[1];
            d2h[6] = sense[0];
        };
        // Each failing command, then REQUEST SENSE DATA EXT.
        let failing = |task_file, times| {
            let link = Link::new(&[]);
            for _ in 0..times {
                link.faults
                    .borrow_mut()
                    .extend([Fault::TaskFile(task_file), Fault::Complete]);
            }
            link
        };
        // ERR | SENSE with ABRT: a medium error the disk could not recover
        // fails without a retry, carrying the sense.
        // Revalidation rereads Sense Data Reporting as enabled.
        let mut page = identify_page("S1", 1024);
        for (word, value) in [(86u16, 1u16 << 15), (119, 0x4040), (120, 0x4040)] {
            let at = 2 * usize::from(word);
            page[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        let (mut fixture, _clock) = recovering(page);
        reply(&mut fixture, 0x52, [Sense::MEDIUM_ERROR, 0x11, 0x04]);
        let link = Link::new(&[Fault::TaskFile(0x0453)]);
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
            Err(BlockError::Sense(Sense {
                key: Sense::MEDIUM_ERROR,
                asc: 0x11,
                ascq: 0x04
            }))
        );
        // The read, then REQUEST SENSE DATA EXT.
        assert_eq!(link.issued.get(), 2);
        assert_eq!(fixture.disk.table.bytes()[2], ATA_REQUEST_SENSE_DATA_EXT);
        // Without ERR_DEV the error is not charged to the device.
        assert_eq!(fixture.disk.errors.newest().count(), 0);

        // A recovered error is success.
        reply(&mut fixture, 0x52, [Sense::RECOVERED_ERROR, 0x17, 0x01]);
        let link = Link::new(&[Fault::TaskFile(0x0453)]);
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
            Ok(())
        );
        assert_eq!(link.issued.get(), 2);

        // A unit attention is requeued at once, outside the retry count.
        reply(&mut fixture, 0x52, [Sense::UNIT_ATTENTION, 0x29, 0x00]);
        let link = failing(0x0453, 7);
        assert_eq!(
            fixture
                .disk
                .issue_on(&link, ATA_WRITE_DMA_EXT, 0, 1, 512, true),
            Ok(())
        );
        assert_eq!(link.issued.get(), 15);

        // An uncorrectable error with sense needing a retry keeps
        // ERR_MEDIA, so EH revalidates the disk and retries it five times;
        // sd then fails it.
        reply(&mut fixture, 0x52, [Sense::MEDIUM_ERROR, 0x0c, 0x00]);
        let link = Link::new(&[]);
        for _ in 0..6 {
            link.faults
                .borrow_mut()
                .extend([Fault::TaskFile(0x4053), Fault::Complete]);
            link.faults.borrow_mut().extend([Fault::Complete; 3]);
        }
        assert!(matches!(
            fixture
                .disk
                .issue_on(&link, ATA_WRITE_DMA_EXT, 0, 1, 512, true),
            Err(BlockError::Sense(_))
        ));
        assert_eq!(link.issued.get(), 6 * 5);

        // A disk still becoming ready is requeued until sd's runtime ends.
        reply(&mut fixture, 0x52, [Sense::NOT_READY, 0x04, 0x01]);
        // At 1000 µs per command timeout the runtime is 6 ms: the 9 ms
        // requeue delay allows exactly one requeue.
        let link = failing(0x0453, 2);
        assert!(matches!(
            fixture
                .disk
                .issue_on(&link, ATA_READ_DMA_EXT, 0, 1, 512, false),
            Err(BlockError::Sense(_))
        ));
        assert_eq!(link.issued.get(), 4);

        // No sense without the SENSE status, with a device fault, with
        // reporting off, or with invalid sense.
        for (task_file, reporting, status, sense) in [
            (0x0451, true, 0x52, [Sense::UNIT_ATTENTION, 0x29, 0]),
            (0x0473, true, 0x52, [Sense::UNIT_ATTENTION, 0x29, 0]),
            (0x0453, false, 0x52, [Sense::UNIT_ATTENTION, 0x29, 0]),
            (0x0453, true, 0x50, [Sense::UNIT_ATTENTION, 0x29, 0]),
            (0x0453, true, 0x52, [0, 0, 0]),
            (0x0453, true, 0x52, [0x10, 0x29, 0]),
        ] {
            let (mut fixture, _clock) = recovering(identify_page("S1", 1024));
            fixture.disk.sense_reporting = reporting;
            reply(&mut fixture, status, sense);
            let link = Link::new(&[Fault::TaskFile(task_file)]);
            assert!(matches!(
                fixture
                    .disk
                    .issue_on(&link, ATA_FLUSH_CACHE_EXT, 0, 0, 0, false),
                Err(BlockError::Device { .. })
            ));
        }
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
            // One more chance, slower, as ata_eh_handle_dev_fail gives.
            assert_eq!(link.issued.get(), 3);
            assert_eq!(fixture.disk.speed_limit, 0b1);
            assert_eq!(fixture.disk.pio_mask, 0x0f);
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
        assert_eq!(fixture.disk.flush_cache(), Ok(()));
        assert_eq!(fixture.disk.port.read32(PORT_ISSUE), issued);
        fixture.disk.fault = Some(BlockError::Timeout);
        assert_eq!(fixture.disk.flush_cache(), Err(BlockError::Timeout));
    }
}
