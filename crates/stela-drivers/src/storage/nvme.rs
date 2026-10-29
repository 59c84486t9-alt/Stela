//! NVMe controllers with one admin and one I/O queue pair. Each active NVM
//! namespace with plain logical blocks becomes one device. The I/O queue
//! runs up to [`DEPTH`] commands at once, each through its own bounce buffer.
//! Errors are handled as Linux's `nvme_timeout` and `nvme_decide_disposition`
//! handle them: a command past its deadline is aborted and given another,
//! then the controller is reset with its DMA contained, and interrupted
//! commands, and those failing without Do Not Retry, run again up to
//! `nvme_max_retries`. Namespace discovery and rescans, asynchronous events,
//! the host memory buffer, shutdown and recovery follow Linux
//! `drivers/nvme/host/core.c` and `pci.c` at
//! a804c5742bff224d4cb4d25dd383554d598be32b.
use crate::bytes::le32;
use crate::{
    Clock, Handoff,
    block::{
        BlockDevice, BlockError, Command, Features, Finished, Identity, Transport, WriteZeroes,
        ascii,
    },
    bus::{dma::DmaAllocator, pci::Function},
    registers,
};
use alloc::{format, rc::Rc, vec::Vec};

pub mod owned;
use core::{
    cell::RefCell,
    sync::atomic::{Ordering, fence},
};
use owned::{Buffer, RegisterIo};

pub const CLASS: [u8; 3] = [0x01, 0x08, 0x02];

const CAPABILITIES: usize = 0x00;
const VERSION: usize = 0x08;
const INTERRUPT_MASK_SET: usize = 0x0c;
const CONFIGURATION: usize = 0x14;
const STATUS: usize = 0x1c;
const ADMIN_ATTRIBUTES: usize = 0x24;
const ADMIN_SUBMISSION: usize = 0x28;
const ADMIN_COMPLETION: usize = 0x30;
/// CRTO: CRWMT in its low half, in 500 ms units.
const READY_TIMEOUTS: usize = 0x68;
const DOORBELLS: usize = 0x1000;

const ENABLE: u32 = 1;
const READY: u32 = 1;
const FATAL: u32 = 1 << 1;
/// CSTS.PP: processing paused for a firmware activation.
const PROCESSING_PAUSED: u32 = 1 << 5;
/// A controller that is gone reads all ones (Linux `nvme_should_reset`
/// treats `~0` CSTS as removal).
const REMOVED: u32 = u32::MAX;
/// CC.SHN normal shutdown and CSTS.SHST (NVMe Base 2.1 §3.1.4.5–6).
const SHUTDOWN_NOTIFICATION: u32 = 3 << 14;
const SHUTDOWN_NORMAL: u32 = 1 << 14;
const SHUTDOWN_STATUS: u32 = 3 << 2;
const SHUTDOWN_COMPLETE: u32 = 2 << 2;
/// Linux bounds a shutdown by the controller's RTD3 entry latency, at least
/// five seconds (`shutdown_timeout`) and at most a minute.
const SHUTDOWN_MINIMUM_US: u64 = 5_000_000;
const SHUTDOWN_MAXIMUM_US: u64 = 60_000_000;
const MICROSECONDS_PER_SECOND: u64 = 1_000_000;
/// Completion polls between controller-fatal checks while a command runs.
const STATUS_POLL_INTERVAL: u32 = 1024;
/// The first version with the active namespace list (Linux `NVME_VS(1, 1, 0)`);
/// Identify Namespace reports an NGUID from 1.2 and the identification
/// descriptor list exists from 1.3.
const VERSION_1_1: u32 = 0x0001_0100;
const VERSION_1_2: u32 = 0x0001_0200;
const VERSION_1_3: u32 = 0x0001_0300;
const VERSION_2_0: u32 = 0x0002_0000;
/// 64-byte submission and 16-byte completion entries, 4 KiB pages, NVM set.
const CONFIGURATION_VALUE: u32 = ENABLE | 6 << 16 | 4 << 20;
/// CC.CSS: every I/O command set the controller supports.
const COMMAND_SETS_ALL: u32 = 6 << 4;
/// CAP.CSS's I/O command sets, and CAP.CRMS's CRWMS and CRIMS.
const CAPABILITY_COMMAND_SETS: u64 = 1 << 43;
const CAPABILITY_READY_WITH_MEDIA: u64 = 1 << 59;
const CAPABILITY_READY_INDEPENDENT: u64 = 1 << 60;

const ADMIN_DELETE_SUBMISSION: u8 = 0x00;
const ADMIN_CREATE_SUBMISSION: u8 = 0x01;
const ADMIN_GET_LOG_PAGE: u8 = 0x02;
const ADMIN_DELETE_COMPLETION: u8 = 0x04;
const ADMIN_CREATE_COMPLETION: u8 = 0x05;
const ADMIN_IDENTIFY: u8 = 0x06;
const ADMIN_ABORT: u8 = 0x08;
const ADMIN_SET_FEATURES: u8 = 0x09;
const ADMIN_ASYNC_EVENT: u8 = 0x0c;
/// One MSI-X table entry: message address, data and vector control.
const MSIX_ENTRY_BYTES: u64 = 16;
/// Autonomous Power State Transition (NVMe Base 2.1 5.27.1.6).
const FEATURE_APST: u32 = 0x0c;
/// Asynchronous Event Configuration, and the notices Linux enables from
/// OAES (`NVME_AEN_SUPPORTED`): namespace attributes, firmware activation,
/// ANA and discovery log changes.
const FEATURE_ASYNC_EVENTS: u32 = 0x0b;
const EVENTS_SUPPORTED: u32 = 1 << 8 | 1 << 9 | 1 << 11 | 1 << 31;
/// Asynchronous event types and the subtypes Linux acts on.
const EVENT_ERROR: u32 = 0;
const EVENT_NOTICE: u32 = 2;
const ERROR_PERSISTENT_INTERNAL: u32 = 0x03;
const NOTICE_NAMESPACES_CHANGED: u32 = 0x00;
const NOTICE_FIRMWARE_ACTIVATION: u32 = 0x01;
/// Firmware Slot Information and Changed Namespace List log pages.
const LOG_FIRMWARE_SLOT: u32 = 0x03;
const LOG_CHANGED_NAMESPACES: u32 = 0x04;
/// Host Behavior Support, with its ACRE and LBAFEE bytes.
const FEATURE_HOST_BEHAVIOR: u32 = 0x16;
const HOST_BEHAVIOR_ACRE: usize = 0;
const HOST_BEHAVIOR_LBAFEE: usize = 2;
const HOST_BEHAVIOR_BYTES: usize = 512;
/// Host Memory Buffer: CDW11 EHM and MR, CDW12 HSIZE in pages, CDW13-14
/// the descriptor list and CDW15 its entry count.
const FEATURE_HOST_MEMORY: u32 = 0x0d;
const HOST_MEMORY_ENABLE: u32 = 1 << 0;
const HOST_MEMORY_RETURN: u32 = 1 << 1;
/// `max_host_mem_size_mb`, and the largest chunk Linux tries first
/// (`PAGE_SIZE * MAX_ORDER_NR_PAGES` on x86-64).
const HOST_MEMORY_MAXIMUM: u64 = 128 << 20;
const HOST_MEMORY_CHUNK: u64 = 4 << 20;
/// One descriptor: address, size in pages, reserved.
const HOST_MEMORY_DESCRIPTOR: usize = 16;
const IO_FLUSH: u8 = 0x00;
const IO_WRITE: u8 = 0x01;
const IO_READ: u8 = 0x02;
const IO_WRITE_ZEROES: u8 = 0x08;
const IO_DATASET_MANAGEMENT: u8 = 0x09;

const IDENTIFY_NAMESPACE: u32 = 0;
const IDENTIFY_CONTROLLER: u32 = 1;
const IDENTIFY_ACTIVE_NAMESPACES: u32 = 2;
const IDENTIFY_DESCRIPTORS: u32 = 3;
/// The I/O command set's Identify Controller, here for CSI 0 (NVM).
const IDENTIFY_COMMAND_SET_CONTROLLER: u32 = 6;
/// Its WZSL and DMRSL (NVM Command Set 1.1 Figure 112).
const NVM_WRITE_ZEROES_LIMIT: usize = 1;
const NVM_DEALLOCATE_RANGE_LIMIT: usize = 4;
/// The command-set-independent Identify Namespace and its NSTAT.NRDY.
const IDENTIFY_INDEPENDENT_NAMESPACE: u32 = 8;
const INDEPENDENT_STATUS: usize = 14;
const NAMESPACE_READY: u8 = 1;

/// Identify Controller fields (NVMe Base 2.1 Figure 312).
const CONTROLLER_SERIAL: core::ops::Range<usize> = 4..24;
const CONTROLLER_MODEL: core::ops::Range<usize> = 24..64;
const CONTROLLER_MAXIMUM_TRANSFER: usize = 77;
const CONTROLLER_RTD3_ENTRY: core::ops::Range<usize> = 88..92;
/// OAES and CTRATT, whose ELBAS reports extended LBA formats.
const CONTROLLER_EVENTS: usize = 92;
const CONTROLLER_ATTRIBUTES: usize = 96;
const ATTRIBUTE_EXTENDED_LBA: u32 = 1 << 15;
/// CRDT1–3, in units of 100 ms.
const CONTROLLER_RETRY_DELAYS: usize = 128;
/// MTFA, in 100 ms units.
const CONTROLLER_ACTIVATION: usize = 258;
/// HMPRE and HMMIN in 4 KiB units, HMMINDS in 4 KiB units, HMMAXD.
const CONTROLLER_HOST_MEMORY_PREFERRED: usize = 272;
const CONTROLLER_HOST_MEMORY_MINIMUM: usize = 276;
const CONTROLLER_HOST_MEMORY_DESCRIPTOR_MINIMUM: usize = 332;
const CONTROLLER_HOST_MEMORY_DESCRIPTORS: usize = 336;
const CONTROLLER_NAMESPACES: core::ops::Range<usize> = 516..520;
/// ONCS: Dataset Management (bit 2) and Write Zeroes (bit 3).
const CONTROLLER_COMMANDS: usize = 520;
const COMMANDS_DATASET_MANAGEMENT: u16 = 1 << 2;
const COMMANDS_WRITE_ZEROES: u16 = 1 << 3;
/// VWC bit 0: a volatile write cache is present.
const CONTROLLER_VOLATILE_CACHE: usize = 525;
/// NPSS: the deepest power state's number.
const CONTROLLER_POWER_STATES: usize = 263;
/// APSTA bit 0: autonomous power state transitions are supported.
const CONTROLLER_APST: usize = 265;
/// The power state descriptors, 32 bytes each: flags at byte 3 (bit 1 a
/// non-operational state), entry and exit latencies in microseconds at
/// bytes 4 and 8.
const CONTROLLER_POWER_DESCRIPTORS: usize = 2048;
const POWER_NON_OPERATIONAL: u8 = 1 << 1;
/// Linux `nvme_core`'s defaults: states whose exit latency exceeds
/// `default_ps_max_latency_us` are never used; a state whose total latency is
/// within `apst_primary_latency_tol_us` is entered after
/// `apst_primary_timeout_ms` idle, one within `apst_secondary_latency_tol_us`
/// after `apst_secondary_timeout_ms`.
const APST_MAX_LATENCY_US: u64 = 100_000;
const APST_PRIMARY_TIMEOUT_MS: u64 = 100;
const APST_PRIMARY_TOLERANCE_US: u64 = 15_000;
const APST_SECONDARY_TIMEOUT_MS: u64 = 2_000;
const APST_SECONDARY_TOLERANCE_US: u64 = 100_000;
/// Identify Namespace fields (NVM Command Set 1.1 Figure 114).
const NAMESPACE_SIZE: core::ops::Range<usize> = 0..8;
const NAMESPACE_CAPACITY: core::ops::Range<usize> = 8..16;
const NAMESPACE_FORMAT: usize = 26;
/// DLFEAT: bits 2:0 what a deallocated block reads (001b zeros), bit 3
/// Write Zeroes may deallocate.
const NAMESPACE_DEALLOCATE: usize = 33;
const NAMESPACE_ATTRIBUTES: usize = 99;
const NAMESPACE_WRITE_PROTECTED: u8 = 1 << 0;
const NAMESPACE_NGUID: core::ops::Range<usize> = 104..120;
const NAMESPACE_EUI64: core::ops::Range<usize> = 120..128;
const NAMESPACE_FORMATS: usize = 128;
/// FLBAS: format index bits 3:0, and bits 6:5 for formats past sixteen.
const FORMAT_LOW: u8 = 0xf;
const FORMAT_HIGH: u8 = 3 << 5;
/// The most namespaces a sequential scan visits, one Identify each.
const SEQUENTIAL_SCAN_LIMIT: u32 = 1024;
/// Namespace Identification Descriptor types (NVMe Base 2.1 Figure 315).
const DESCRIPTOR_EUI64: u8 = 1;
const DESCRIPTOR_NGUID: u8 = 2;
const DESCRIPTOR_UUID: u8 = 3;
const DESCRIPTOR_CSI: u8 = 4;
/// Command set identifiers: NVM and zoned namespaces.
const CSI_NVM: u8 = 0;
const CSI_ZONED: u8 = 2;

const PAGE: usize = 4096;
const ADMIN_ENTRIES: u16 = 16;
/// The I/O queue's entries: one page of submissions.
const IO_ENTRIES: u16 = 64;
/// The commands the I/O queue runs at once, each holding a bounce buffer,
/// as Linux's tag set bounds them; one for a controller in an owned DMA
/// domain, whose buffers change hands whole.
const DEPTH: usize = 8;
const BOUNCE_BYTES: usize = 128 * 1024;
// Linux PCI NVME_MAX_BYTES bounds the logical command range independently of
// payload storage. Write Zeroes transfers no host data through the bounce pool.
const MAX_COMMAND_BYTES: usize = 8 * 1024 * 1024;
const COMMAND_TIMEOUT_US: u64 = 30_000_000;
/// Linux `NVME_ADMIN_TIMEOUT`.
const ADMIN_TIMEOUT_US: u64 = 60_000_000;
/// Linux `nvme_max_retries`: a command the controller's reset interrupted,
/// or that failed without Do Not Retry, runs again at most this often.
const RETRIES: u8 = 5;
/// The completion status field's Do Not Retry bit and Command Retry Delay
/// index.
const STATUS_DO_NOT_RETRY: u32 = 1 << 14;
const STATUS_RETRY_DELAY: u32 = 3 << 11;
const RETRY_DELAY_UNIT_US: u64 = 100_000;
/// Read/Write CDW12 bit 30: complete only once the data is durable.
const FORCE_UNIT_ACCESS: u32 = 1 << 30;
/// Write Zeroes CDW12 bit 25: the blocks may be deallocated.
const DEALLOCATE: u32 = 1 << 25;
/// Dataset Management CDW11 bit 2: deallocate the ranges.
const ATTRIBUTE_DEALLOCATE: u32 = 1 << 2;
/// I/O to a namespace Linux's rescan removed.
const NAMESPACE_REMOVED: BlockError =
    BlockError::Protocol("the NVMe namespace changed or was removed");

/// An I/O read or write of `blocks` blocks at `lba` through `pointers`.
fn transfer_command(
    opcode: u8,
    namespace: u32,
    lba: u64,
    blocks: u32,
    (prp1, prp2): (u64, u64),
    access: u32,
) -> [u32; 16] {
    let mut command = [0u32; 16];
    command[0] = u32::from(opcode);
    command[1] = namespace;
    command[6] = prp1 as u32;
    command[7] = (prp1 >> 32) as u32;
    command[8] = prp2 as u32;
    command[9] = (prp2 >> 32) as u32;
    command[10] = lba as u32;
    command[11] = (lba >> 32) as u32;
    command[12] = access | (blocks - 1);
    command
}

/// Linux `nvme_ns_ids`: what identifies a namespace across rescans.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Ids {
    eui64: [u8; 8],
    nguid: [u8; 16],
    uuid: [u8; 16],
    csi: u8,
}

impl Ids {
    /// Linux `nvme_identify_ns_descs` parsing: descriptors until a zero
    /// length, stopping at one whose length is wrong for its type.
    fn from_descriptors(data: &[u8]) -> Self {
        let mut ids = Self::default();
        let mut at = 0;
        while at + 4 <= data.len() {
            let (kind, length) = (data[at], usize::from(data[at + 1]));
            if length == 0 {
                break;
            }
            let Some(value) = data.get(at + 4..at + 4 + length) else {
                break;
            };
            let expected = match kind {
                DESCRIPTOR_EUI64 => 8,
                DESCRIPTOR_NGUID | DESCRIPTOR_UUID => 16,
                DESCRIPTOR_CSI => 1,
                // Unknown types are skipped.
                _ => length,
            };
            if length != expected {
                break;
            }
            match kind {
                DESCRIPTOR_EUI64 => ids.eui64.copy_from_slice(value),
                DESCRIPTOR_NGUID => ids.nguid.copy_from_slice(value),
                DESCRIPTOR_UUID => ids.uuid.copy_from_slice(value),
                DESCRIPTOR_CSI => ids.csi = value[0],
                _ => {}
            }
            at += 4 + length;
        }
        ids
    }

    /// Linux `nvme_ns_info_from_identify`: EUI64 and NGUID from Identify
    /// Namespace when the descriptors gave none.
    fn fill(&mut self, version: u32, data: &[u8]) {
        if version >= VERSION_1_1 && self.eui64 == [0; 8] {
            self.eui64.copy_from_slice(&data[NAMESPACE_EUI64]);
        }
        if version >= VERSION_1_2 && self.nguid == [0; 16] {
            self.nguid.copy_from_slice(&data[NAMESPACE_NGUID]);
        }
    }
}

/// How an admin command was lost, when it produced no completion to report.
enum Lost {
    /// Linux resets the controller: a timeout, or a fatal controller status.
    Reset(BlockError),
    /// The controller broke the protocol, is gone, or its registers failed.
    Fatal(BlockError),
}

struct Queue {
    submissions: Buffer,
    completions: Buffer,
    id: u16,
    entries: u16,
    tail: u16,
    head: u16,
    phase: bool,
    /// The submission head the controller last reported.
    consumed: u16,
}

impl Queue {
    fn new(id: u16, entries: u16, dma: &mut dyn DmaAllocator) -> Result<Self, BlockError> {
        Ok(Self {
            submissions: Buffer::Legacy(dma.allocate(PAGE, PAGE)?),
            completions: Buffer::Legacy(dma.allocate(PAGE, PAGE)?),
            id,
            entries,
            tail: 0,
            head: 0,
            phase: true,
            consumed: 0,
        })
    }

    /// Empty, as a controller reset leaves it.
    fn restart(&mut self) {
        self.tail = 0;
        self.head = 0;
        self.phase = true;
        self.consumed = 0;
    }

    /// Whether a reported submission head lies no earlier than the last
    /// one and no further than the tail, in ring order: commands fetched
    /// together may complete reporting the same head.
    fn consumes(&self, head: u16) -> bool {
        head < self.entries
            && self.ahead(self.consumed, head) <= self.ahead(self.consumed, self.tail)
    }

    /// Whether `head` shows the command at submission `slot` fetched: past
    /// it, and no further than the tail.
    fn fetched(&self, slot: u16, head: u16) -> bool {
        let past = self.ahead(slot, head);
        past != 0 && past <= self.ahead(slot, self.tail)
    }

    /// How many entries `to` lies after `from`, in ring order.
    fn ahead(&self, from: u16, to: u16) -> u16 {
        (to + self.entries - from) % self.entries
    }
}

/// A tag's bounce memory: its data and its PRP list.
struct Slot {
    bounce: Buffer,
    prp_list: Buffer,
}

/// A command of the I/O queue: under its tag until the controller completes
/// it, then its result until the namespace takes it.
#[derive(Default)]
enum Tag {
    #[default]
    Free,
    Running {
        id: u16,
        /// Its submission queue entry.
        slot: u16,
        /// An accepted submission head has passed this command.
        fetched: bool,
        namespace: u32,
        block: usize,
        command: Command,
        deadline: crate::Deadline,
        /// The runs before this one: retries and resets.
        retries: u8,
        /// An Abort for it was sent at its first deadline.
        aborted: bool,
    },
    /// Interrupted by a controller reset, to run again once it completes.
    Waiting {
        namespace: u32,
        block: usize,
        command: Command,
        retries: u8,
    },
    /// Failed without Do Not Retry, to run again after the delay its
    /// Command Retry Delay selects (`nvme_retry_req`).
    Delayed {
        namespace: u32,
        block: usize,
        command: Command,
        retries: u8,
        until: crate::Deadline,
    },
    Done(Finished),
}

/// The admin commands bringing a controller up, as Linux's
/// `nvme_reset_work` runs them after every reset and probe runs them once:
/// `nvme_init_ctrl_finish`'s Identify, host options and APST,
/// `nvme_setup_host_mem`, the I/O queues and `nvme_start_ctrl`'s events.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Step {
    Identify,
    /// `nvme_init_non_mdts_limits`'s NVM Identify Controller.
    Limits,
    HostOptions,
    Apst,
    HostMemory,
    CreateCompletion,
    CreateSubmission,
    Events,
}

const STEPS: [Step; 8] = [
    Step::Identify,
    Step::Limits,
    Step::HostOptions,
    Step::Apst,
    Step::HostMemory,
    Step::CreateCompletion,
    Step::CreateSubmission,
    Step::Events,
];

/// A controller reset in progress ([`Controller::recover`]), each step
/// looked for without waiting.
enum Recovery {
    /// Deleting the I/O submission, then completion, queue of a live
    /// controller (`nvme_delete_io_queues`), and the command's identifier.
    Deleting {
        submission: bool,
        id: u16,
        deadline: crate::Deadline,
    },
    /// CC.EN cleared; waiting for CSTS.RDY to clear.
    Disabling(crate::Deadline),
    /// CC.EN set; waiting for CSTS.RDY.
    Enabling(crate::Deadline),
    /// A bring-up command, its identifier, and the Identify Controller data
    /// once read.
    Admin {
        step: Step,
        id: u16,
        deadline: crate::Deadline,
        identify: Vec<u8>,
    },
}

/// Linux's asynchronous events: what Identify Controller enables, the
/// outstanding Asynchronous Event Request and a completion not yet acted on.
#[derive(Default)]
struct Events {
    supported: u32,
    /// MTFA, in microseconds.
    activation_us: u64,
    request: Option<u16>,
    completed: Option<(u32, u32)>,
}

impl Events {
    fn from_identify(identify: &[u8]) -> Self {
        Self {
            supported: le32(identify, CONTROLLER_EVENTS) & EVENTS_SUPPORTED,
            activation_us: u64::from(u16::from_le_bytes([
                identify[CONTROLLER_ACTIVATION],
                identify[CONTROLLER_ACTIVATION + 1],
            ])) * 100_000,
            ..Self::default()
        }
    }
}

/// Linux's host memory buffer: its descriptor list and chunks.
struct HostMemory {
    descriptors: Buffer,
    chunks: Vec<Buffer>,
    bytes: u64,
    /// The controller accepted it, so a re-enable may ask for its contents
    /// back (`host_mem_descs` retained).
    returnable: bool,
}

/// What Identify Controller asks of a host memory buffer, in bytes.
#[derive(Clone, Copy)]
struct HostMemoryRequest {
    preferred: u64,
    minimum: u64,
    descriptor_minimum: u64,
    descriptors: u32,
}

impl HostMemoryRequest {
    fn from_identify(identify: &[u8]) -> Self {
        let pages = |at| u64::from(le32(identify, at)) * PAGE as u64;
        Self {
            preferred: pages(CONTROLLER_HOST_MEMORY_PREFERRED),
            minimum: pages(CONTROLLER_HOST_MEMORY_MINIMUM),
            descriptor_minimum: pages(CONTROLLER_HOST_MEMORY_DESCRIPTOR_MINIMUM),
            descriptors: u32::from(u16::from_le_bytes([
                identify[CONTROLLER_HOST_MEMORY_DESCRIPTORS],
                identify[CONTROLLER_HOST_MEMORY_DESCRIPTORS + 1],
            ])),
        }
    }
}

/// Allocations for a host memory buffer: its descriptor list, then its
/// chunks.
trait HostMemorySource {
    fn allocate(&mut self, bytes: usize, chunk: bool) -> Result<Buffer, BlockError>;
}

impl HostMemorySource for &mut dyn DmaAllocator {
    fn allocate(&mut self, bytes: usize, _chunk: bool) -> Result<Buffer, BlockError> {
        DmaAllocator::allocate(*self, bytes, PAGE).map(Buffer::Legacy)
    }
}

/// One controller, shared by its namespaces.
struct Controller {
    registers: RegisterIo,
    doorbell_stride: usize,
    admin: Queue,
    io: Queue,
    /// Tag 0's bounce memory, which admin commands also use.
    bounce: Buffer,
    prp_list: Buffer,
    /// Tags 1 and up's bounce memory.
    slots: Vec<Slot>,
    tags: Vec<Tag>,
    recovery: Option<Recovery>,
    /// The I/O completion queue raises MSI-X vector 0, which the host
    /// gave the message of its completion signal.
    signalled: bool,
    /// Maximum data payload, bounded by the bounce allocation.
    max_transfer: usize,
    /// MDTS/host command bound used when no non-MDTS limit is supplied.
    max_command_bytes: usize,
    /// How long a normal shutdown may take.
    shutdown_timeout_us: u64,
    /// The controller acknowledged a shutdown; it takes no more commands.
    shut_down: bool,
    command_id: u16,
    clock: Clock,
    command_timeout_us: u64,
    admin_timeout_us: u64,
    /// An unresolved command may still own the queues, PRPs and bounce RAM,
    /// or the controller is gone. No buffer or queue may be reused until a
    /// new, acknowledged reset.
    fault: Option<BlockError>,
    owned: Option<owned::Owner>,
    teardown: owned::Teardown,
    ready_timeout_us: u64,
    /// CC without EN.
    configuration: u32,
    /// CAP.CRMS.CRIMS: namespaces report readiness of their own.
    independent_identify: bool,
    /// The VS register, read at discovery.
    version: u32,
    /// ONCS from Identify Controller.
    commands: u16,
    /// Queued namespace scans: one per reset and namespace-change notice.
    scans: u64,
    /// CRDT1–3 from Identify Controller, in 100 ms units.
    retry_delays: [u16; 3],
    /// The host memory buffer, kept across resets, and whether the
    /// controller uses it (`dev->hmb`).
    host_memory: Option<HostMemory>,
    host_memory_enabled: bool,
    events: Events,
    /// The Abort commands sent and not yet completed.
    aborts: Vec<u16>,
    limits: Limits,
}

/// `nvme_init_non_mdts_limits`: the NVM command set's Write Zeroes and
/// Deallocate limits, read again after each reset unless the controller
/// once refused the Identify (`NVME_CTRL_SKIP_ID_CNS_CS`).
#[derive(Clone, Copy, Debug, Default)]
struct Limits {
    /// WZSL: Write Zeroes up to 2^WZSL minimum pages; 0 for MDTS.
    write_zeroes: u8,
    /// DMRSL: the most blocks one Deallocate range takes; 0 for none.
    deallocate: u32,
    refused: bool,
}

impl Controller {
    fn ready(&mut self) -> Result<(), BlockError> {
        if let Some(error) = &self.fault {
            return Err(error.clone());
        }
        if self.shut_down {
            return Err(BlockError::Unsupported("NVMe controller is shut down"));
        }
        Ok(())
    }

    /// CSTS: a removed controller or CSTS.CFS, as an error.
    fn check_fatal(&self) -> Result<(), BlockError> {
        match self.registers.read32(STATUS)? {
            REMOVED => Err(removed()),
            status if status & FATAL != 0 => Err(BlockError::Device { status }),
            _ => Ok(()),
        }
    }

    fn poison(&mut self, error: BlockError) -> BlockError {
        self.fault = Some(error.clone());
        error
    }

    fn wait_status(&self, timeout: u64, condition: impl Fn(u32) -> bool) -> Result<(), BlockError> {
        let mut failure = None;
        let done = self
            .clock
            .wait(timeout, || match self.registers.read32(STATUS) {
                Ok(REMOVED) => {
                    failure = Some(removed());
                    true
                }
                Ok(status) => condition(status),
                Err(error) => {
                    failure = Some(error);
                    true
                }
            });
        if let Some(error) = failure {
            return Err(error);
        }
        if done {
            Ok(())
        } else {
            Err(BlockError::Timeout)
        }
    }

    /// Point the controller at the admin queue, empty, with every interrupt
    /// masked.
    fn configure_admin(&mut self) -> Result<(), BlockError> {
        self.admin.restart();
        self.admin.completions.give()?;
        self.io.completions.give()?;
        // Empty SQs are CPU-owned until their first command publication. The
        // controller cannot consume any SQE before the corresponding doorbell.
        let entries = u32::from(self.admin.entries - 1);
        self.registers
            .write32(ADMIN_ATTRIBUTES, entries << 16 | entries)?;
        self.registers
            .write64(ADMIN_SUBMISSION, self.admin.submissions.address()?)?;
        self.admin.submissions.publish();
        self.registers
            .write64(ADMIN_COMPLETION, self.admin.completions.address()?)?;
        self.registers.write32(INTERRUPT_MASK_SET, u32::MAX)
    }

    /// Linux `nvme_enable_ctrl`: set CC.EN, returning how long CSTS.RDY may
    /// take, CAP.TO or a longer CRTO.CRWMT. CRIME stays clear, as in Linux.
    fn enable(&mut self) -> Result<u64, BlockError> {
        let capabilities = self.registers.read64(CAPABILITIES)?;
        let mut timeout = capabilities >> 24 & 0xff;
        if capabilities & CAPABILITY_READY_WITH_MEDIA != 0 {
            let media = self.registers.read32(READY_TIMEOUTS)? & 0xffff;
            timeout = timeout.max(u64::from(media));
        }
        self.independent_identify = capabilities & CAPABILITY_READY_INDEPENDENT != 0;
        self.registers
            .write32(CONFIGURATION, self.configuration | ENABLE)?;
        Ok(ready_wait_us(timeout))
    }

    fn initialize(&mut self) -> Result<(), BlockError> {
        if let Some(owner) = self.owned.as_mut() {
            // An attempted prepare may have effects without establishing D0.
            // Only success authorizes NVMe MMIO; uncertain failure quarantines.
            self.teardown = owned::Teardown::Preparing;
            owner.lifecycle.prepare()?;
            self.teardown = owned::Teardown::Active;
        }
        let capabilities = self.registers.read64(CAPABILITIES)?;
        self.doorbell_stride = 4usize << (capabilities >> 32 & 0xf);
        self.ready_timeout_us = ready_wait_us(capabilities >> 24 & 0xff);
        if capabilities >> 37 & 1 == 0 {
            return Err(BlockError::Unsupported(
                "NVMe controller without the NVM command set",
            ));
        }
        if capabilities >> 48 & 0xf != 0 {
            return Err(BlockError::Unsupported(
                "NVMe controller without 4 KiB pages",
            ));
        }
        // CAP.MQES is zero-based; both queues must fit.
        let longest = (capabilities & 0xffff) + 1;
        if longest < u64::from(ADMIN_ENTRIES) {
            return Err(BlockError::Unsupported(
                "NVMe queues shorter than 16 entries",
            ));
        }
        self.io.entries = self
            .io
            .entries
            .min(u16::try_from(longest).unwrap_or(u16::MAX));
        let depth = self.tags.len().min(usize::from(self.io.entries) - 1);
        self.tags.truncate(depth);
        if 4 * self.doorbell_stride + DOORBELLS > 0x2000 {
            return Err(BlockError::Unsupported("NVMe doorbell stride"));
        }
        self.configuration = CONFIGURATION_VALUE & !ENABLE;
        if capabilities & CAPABILITY_COMMAND_SETS != 0 {
            self.configuration |= COMMAND_SETS_ALL;
        }
        self.registers.write32(CONFIGURATION, 0)?;
        self.wait_status(self.ready_timeout_us, |status| status & READY == 0)?;
        self.configure_admin()?;
        if let Some(owner) = self.owned.as_mut() {
            owner.lifecycle.enable_dma()?;
        }
        let timeout = self.enable()?;
        self.wait_status(timeout, |status| status & (READY | FATAL) != 0)?;
        self.check_fatal()
    }

    /// The admin command creating the I/O completion queue, or with
    /// `submission` the submission queue, polled.
    fn create_queue(&self, submission: bool) -> Result<[u32; 16], BlockError> {
        let entries = u32::from(self.io.entries - 1);
        let mut command = [0u32; 16];
        let address = if submission {
            command[0] = u32::from(ADMIN_CREATE_SUBMISSION);
            command[11] = 1 << 16 | 1; // completion queue 1, contiguous
            self.io.submissions.address()?
        } else {
            command[0] = u32::from(ADMIN_CREATE_COMPLETION);
            // Physically contiguous; with interrupts enabled, vector 0.
            command[11] = 1 | u32::from(self.signalled) << 1;
            self.io.completions.address()?
        };
        command[6] = address as u32;
        command[7] = (address >> 32) as u32;
        command[10] = entries << 16 | 1;
        Ok(command)
    }

    fn identify_command(&self, cns: u32, namespace: u32) -> Result<[u32; 16], BlockError> {
        let mut command = [0u32; 16];
        command[0] = u32::from(ADMIN_IDENTIFY);
        command[1] = namespace;
        let page = self.bounce.address()?;
        command[6] = page as u32;
        command[7] = (page >> 32) as u32;
        command[10] = cns;
        Ok(command)
    }

    /// Run admin `command` through tag 0's memory once every queued command
    /// ended, as Linux runs its own admin commands: never retried. One past
    /// its deadline, or a fatal controller, resets the controller, as
    /// `nvme_timeout` does for the admin queue; a failed reset poisons every
    /// sibling. Only a positively identified CQE or an acknowledged reset
    /// authorizes SQ/PRP/data CPU reuse.
    fn admin(&mut self, command: [u32; 16]) -> Result<u32, BlockError> {
        self.ready()?;
        self.settle()?;
        match self.admin_wait(command, Some(0)) {
            Ok((result, 0)) => Ok(result),
            Ok((_, status)) => Err(BlockError::Device { status }),
            Err(Lost::Reset(error)) => {
                // The lost command leaves no admin queue to delete with.
                self.reset_with(false);
                self.settle()?;
                Err(error)
            }
            Err(Lost::Fatal(error)) => Err(self.poison(error)),
        }
    }

    /// Publish admin `command` with tag `tag`'s memory and wait for its
    /// completion, taking the others posted before it.
    fn admin_wait(&mut self, command: [u32; 16], tag: Option<usize>) -> Result<(u32, u32), Lost> {
        match self.registers.read32(STATUS).map_err(Lost::Fatal)? {
            REMOVED => return Err(Lost::Fatal(removed())),
            status if status & FATAL != 0 => {
                return Err(Lost::Reset(BlockError::Device { status }));
            }
            _ => {}
        }
        let id = self.publish(false, command, tag).map_err(Lost::Fatal)?;
        let (clock, timeout) = (self.clock, self.admin_timeout_us);
        let data = tag.is_some();
        let mut observed = None;
        let mut polls = 0u32;
        clock.wait(timeout, || {
            // The CQE lives in RAM; CSTS is an MMIO read, which a hypervisor
            // traps. Check for a fatal controller only every few polls.
            polls = polls.wrapping_add(1);
            if polls.is_multiple_of(STATUS_POLL_INTERVAL) {
                let lost = match self.registers.read32(STATUS) {
                    Ok(REMOVED) => Some(Lost::Fatal(removed())),
                    Ok(status) if status & FATAL != 0 => {
                        Some(Lost::Reset(BlockError::Device { status }))
                    }
                    Ok(_) => None,
                    Err(error) => Some(Lost::Fatal(error)),
                };
                if let Some(lost) = lost {
                    observed = Some(Err(lost));
                    return true;
                }
            }
            match self.admin_completion(Some((id, data))) {
                Ok(None) => false,
                Ok(Some(completion)) => {
                    observed = Some(Ok(completion));
                    true
                }
                Err(error) => {
                    observed = Some(Err(Lost::Fatal(error)));
                    true
                }
            }
        });
        observed.unwrap_or(Err(Lost::Reset(BlockError::Timeout)))
    }

    /// Take the admin completions the controller has posted, one doorbell
    /// each: an Asynchronous Event Request's is kept for
    /// [`Self::service_events`] and an Abort's ends it. Command `id`'s result
    /// and status once posted, giving tag 0's memory back to the CPU when
    /// it holds `data`; any other completion breaks the protocol.
    fn admin_completion(
        &mut self,
        expected: Option<(u16, bool)>,
    ) -> Result<Option<(u32, u32)>, BlockError> {
        while let Some((id, result, status, _)) = self.posted(false)? {
            self.release(false)?;
            if self.events.request == Some(id) {
                self.events.request = None;
                self.events.completed = Some((result, status));
            } else if let Some(at) = self.aborts.iter().position(|abort| *abort == id) {
                self.aborts.swap_remove(at);
            } else if let Some((_, data)) = expected.filter(|(expected, _)| *expected == id) {
                if data {
                    self.trust_completion()?;
                    // SAFETY: the controller completed this exact command;
                    // no other command reaches tag 0's memory meanwhile.
                    unsafe {
                        self.bounce.take()?;
                        self.prp_list.take()?;
                    }
                }
                return Ok(Some((result, status)));
            } else {
                return Err(BlockError::Device { status: 0xffff });
            }
        }
        Ok(None)
    }

    /// Before the CPU takes back memory a completion released: an owned
    /// controller's completion counts only while its registers answer
    /// without a fatal status, which a removed hierarchy or a failed engine
    /// would not.
    fn trust_completion(&self) -> Result<(), BlockError> {
        match self.owned {
            Some(_) => self.check_fatal(),
            None => Ok(()),
        }
    }

    /// Tag `tag`'s bounce memory: its data and its PRP list.
    fn slot(&mut self, tag: usize) -> (&mut Buffer, &mut Buffer) {
        match tag {
            0 => (&mut self.bounce, &mut self.prp_list),
            _ => {
                let slot = &mut self.slots[tag - 1];
                (&mut slot.bounce, &mut slot.prp_list)
            }
        }
    }

    /// Whether command identifier `id` names a command still outstanding.
    fn outstanding(&self, id: u16) -> bool {
        self.events.request == Some(id)
            || self.aborts.contains(&id)
            || self
                .tags
                .iter()
                .any(|tag| matches!(tag, Tag::Running { id: running, .. } if *running == id))
            || matches!(
                self.recovery,
                Some(Recovery::Deleting { id: step, .. } | Recovery::Admin { id: step, .. })
                    if step == id
            )
    }

    /// Publish `command` on queue `io`, giving the controller tag `tag`'s
    /// memory when it moves data, and ring its doorbell; its identifier,
    /// one no outstanding command holds.
    fn publish(
        &mut self,
        io: bool,
        command: [u32; 16],
        tag: Option<usize>,
    ) -> Result<u16, BlockError> {
        let stride = self.doorbell_stride;
        loop {
            self.command_id = self.command_id.wrapping_add(1);
            if !self.outstanding(self.command_id) {
                break;
            }
        }
        let id = self.command_id;
        if let Some(tag) = tag {
            let (bounce, prp_list) = self.slot(tag);
            bounce.give()?;
            prp_list.give()?;
        }
        let registers = &self.registers;
        let queue = if io { &mut self.io } else { &mut self.admin };
        // SAFETY: the controller only reads submission entries, and the tail
        // entry is none it has yet to fetch: fewer commands are outstanding
        // than the queue holds.
        unsafe { queue.submissions.resume_writes() };
        let base = usize::from(queue.tail) * 64;
        for (index, word) in command.iter().enumerate() {
            queue.submissions.write(
                base + 4 * index,
                if index == 0 {
                    word | u32::from(id) << 16
                } else {
                    *word
                },
            );
        }
        queue.submissions.give()?;
        queue.tail = (queue.tail + 1) % queue.entries;
        fence(Ordering::SeqCst);
        registers.write32(
            DOORBELLS + 2 * usize::from(queue.id) * stride,
            u32::from(queue.tail),
        )?;
        Ok(id)
    }

    /// The completion at queue `io`'s head, once the controller has posted
    /// it: its identifier, result, status and submission head, which must
    /// not have moved back nor past the tail.
    fn posted(&mut self, io: bool) -> Result<Option<(u16, u32, u32, u16)>, BlockError> {
        let queue = if io { &mut self.io } else { &mut self.admin };
        let entry = usize::from(queue.head) * 16;
        if (queue.completions.coherent(entry + 12)? >> 16 & 1 == 1) != queue.phase {
            return Ok(None);
        }
        // The domain qualifies the coherent observation; this barrier orders
        // later CQ words after the device's final phase/status publication.
        fence(Ordering::SeqCst);
        let result = queue.completions.coherent(entry)?;
        let submission = queue.completions.coherent(entry + 8)?;
        let tail_word = queue.completions.coherent(entry + 12)?;
        let head = submission as u16;
        if ((tail_word >> 16 & 1) == 1) != queue.phase
            || submission >> 16 != u32::from(queue.id)
            || !queue.consumes(head)
        {
            return Err(BlockError::Device { status: 0xffff });
        }
        queue.consumed = head;
        queue.head = (queue.head + 1) % queue.entries;
        if queue.head == 0 {
            queue.phase = !queue.phase;
        }
        Ok(Some((
            tail_word as u16,
            result,
            tail_word >> 17 & 0x7fff,
            head,
        )))
    }

    /// Whether a running command's completion is posted at the I/O
    /// queue's head, or one is done and not yet taken: memory alone.
    fn posted_completion(&self) -> bool {
        let mut running = false;
        for tag in &self.tags {
            match tag {
                Tag::Done(_) => return true,
                Tag::Running { .. } => running = true,
                _ => {}
            }
        }
        let entry = usize::from(self.io.head) * 16;
        running
            && self
                .io
                .completions
                .coherent(entry + 12)
                .is_ok_and(|word| (word >> 16 & 1 == 1) == self.io.phase)
    }

    /// Ring queue `io`'s completion doorbell at its head.
    fn release(&mut self, io: bool) -> Result<(), BlockError> {
        let stride = self.doorbell_stride;
        let queue = if io { &self.io } else { &self.admin };
        self.registers.write32(
            DOORBELLS + (2 * usize::from(queue.id) + 1) * stride,
            u32::from(queue.head),
        )
    }

    /// Whether a command runs, waits to run again or the controller resets.
    fn busy(&self) -> bool {
        self.recovery.is_some()
            || self.tags.iter().any(|tag| {
                matches!(
                    tag,
                    Tag::Running { .. } | Tag::Waiting { .. } | Tag::Delayed { .. }
                )
            })
    }

    /// Wait for every queued command, keeping each result for its tag, and
    /// for a reset to end: a command of a waiting caller's own follows.
    /// Every running command and reset step has a deadline, and retries are
    /// bounded, so this ends.
    fn settle(&mut self) -> Result<(), BlockError> {
        loop {
            self.advance();
            if let Some(error) = &self.fault {
                return Err(error.clone());
            }
            if !self.busy() {
                return Ok(());
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }

    /// The I/O command for `command` with tag `tag`'s memory, its data
    /// copied in.
    fn io_command(
        &mut self,
        tag: usize,
        namespace: u32,
        block: usize,
        command: &Command,
    ) -> Result<[u32; 16], BlockError> {
        let mut words = [0u32; 16];
        words[1] = namespace;
        match command {
            Command::Read { lba, bytes } => {
                let pointers = self.data_pointers(tag, *bytes)?;
                Ok(transfer_command(
                    IO_READ,
                    namespace,
                    *lba,
                    (bytes / block) as u32,
                    pointers,
                    0,
                ))
            }
            Command::Write { lba, data, fua } => {
                self.slot(tag).0.bytes_mut()[..data.len()].copy_from_slice(data);
                let pointers = self.data_pointers(tag, data.len())?;
                let access = if *fua { FORCE_UNIT_ACCESS } else { 0 };
                let blocks = (data.len() / block) as u32;
                Ok(transfer_command(
                    IO_WRITE, namespace, *lba, blocks, pointers, access,
                ))
            }
            Command::Flush => {
                words[0] = u32::from(IO_FLUSH);
                Ok(words)
            }
            Command::Discard { lba, blocks } => {
                // One range: context attributes, length, starting LBA.
                let count = u32::try_from(*blocks)
                    .map_err(|_| BlockError::Unsupported("an NVMe range past 2^32 blocks"))?;
                let (bounce, _) = self.slot(tag);
                bounce.write(0, 0u32);
                bounce.write(4, count);
                bounce.write(8, *lba);
                let address = bounce.address()?;
                words[0] = u32::from(IO_DATASET_MANAGEMENT);
                words[6] = address as u32;
                words[7] = (address >> 32) as u32;
                words[11] = ATTRIBUTE_DEALLOCATE;
                Ok(words)
            }
            Command::WriteZeroes { lba, blocks, unmap } => {
                let count = u16::try_from(blocks.wrapping_sub(1))
                    .map_err(|_| BlockError::Unsupported("Write Zeroes past 65536 blocks"))?;
                words[0] = u32::from(IO_WRITE_ZEROES);
                words[10] = *lba as u32;
                words[11] = (*lba >> 32) as u32;
                words[12] = u32::from(count) | if *unmap { DEALLOCATE } else { 0 };
                Ok(words)
            }
        }
    }

    /// Whether [`Self::start`] answers now: a tag is free and no reset runs,
    /// or the controller failed or shut down, which it refuses at once
    /// rather than leaving the command waiting for room it never gets.
    fn room(&self) -> bool {
        self.fault.is_some()
            || self.shut_down
            || (self.recovery.is_none() && self.tags.iter().any(|tag| matches!(tag, Tag::Free)))
    }

    /// Run `command` of `namespace` under a free tag; the tag.
    fn start(&mut self, namespace: u32, block: usize, command: Command) -> Result<u32, BlockError> {
        self.ready()?;
        let tag = self
            .tags
            .iter()
            .position(|tag| matches!(tag, Tag::Free))
            .filter(|_| self.recovery.is_none())
            .ok_or(BlockError::Protocol("every NVMe tag is in use"))?;
        self.submit(tag, namespace, block, command, 0);
        Ok(tag as u32)
    }

    /// Run `command` of `namespace` once every queued command ended, and
    /// wait for it. A fatal controller is reset before it is sent, as
    /// Linux's timeout handling would reset it.
    fn run(&mut self, namespace: u32, block: usize, command: Command) -> Finished {
        self.ready()?;
        self.settle()?;
        match self.registers.read32(STATUS)? {
            REMOVED => return Err(self.poison(removed())),
            status if status & FATAL != 0 => {
                self.reset();
                self.settle()?;
            }
            _ => {}
        }
        let tag = self.start(namespace, block, command)? as usize;
        loop {
            if let Some(result) = self.finish(tag) {
                return result;
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }

    /// Publish `command` under `tag`, which holds no other.
    fn submit(&mut self, tag: usize, namespace: u32, block: usize, command: Command, retries: u8) {
        let slot = self.io.tail;
        // A command whose deadline cannot be kept is not sent; the deadline
        // runs from its doorbell.
        let published = self.deadline(self.command_timeout_us).and_then(|_| {
            let words = self.io_command(tag, namespace, block, &command)?;
            let id = self.publish(true, words, Some(tag))?;
            Ok((id, self.deadline(self.command_timeout_us)?))
        });
        self.tags[tag] = match published {
            Ok((id, deadline)) => Tag::Running {
                id,
                slot,
                fetched: false,
                namespace,
                block,
                command,
                deadline,
                retries,
                aborted: false,
            },
            Err(error) => Tag::Done(Err(self.poison(error))),
        };
    }

    /// Collect every completion the controller has posted, run delayed
    /// retries, check the running commands' deadlines and move a reset on;
    /// never waits.
    fn advance(&mut self) {
        if self.fault.is_some() {
            self.fail_all();
            return;
        }
        if self.recovery.is_some() {
            if let Err(error) = self.recover() {
                self.poison(error);
                self.fail_all();
            }
            return;
        }
        // Abort and event completions, which the I/O commands do not wait for.
        if (self.events.request.is_some() || !self.aborts.is_empty())
            && let Err(error) = self.admin_completion(None)
        {
            self.poison(error);
            self.fail_all();
            return;
        }
        // A controller posts completions only for running commands.
        let running = self
            .tags
            .iter()
            .any(|tag| matches!(tag, Tag::Running { .. }));
        let mut reaped = false;
        loop {
            if !running {
                break;
            }
            let (head, phase, consumed) = (self.io.head, self.io.phase, self.io.consumed);
            match self.posted(true) {
                Ok(None) => break,
                Ok(Some((id, _, status, sq_head))) => {
                    if !reaped && let Err(error) = self.trust_completion() {
                        (self.io.head, self.io.phase, self.io.consumed) = (head, phase, consumed);
                        self.poison(error);
                        self.fail_all();
                        return;
                    }
                    if !self.complete(id, status, sq_head) {
                        // A completion for no running command, or for one the
                        // controller had not fetched: the queue is corrupt.
                        // It stays unretired.
                        (self.io.head, self.io.phase, self.io.consumed) = (head, phase, consumed);
                        self.poison(BlockError::Device { status: 0xffff });
                        self.fail_all();
                        return;
                    }
                    reaped = true;
                }
                Err(error) => {
                    self.poison(error);
                    self.fail_all();
                    return;
                }
            }
        }
        if reaped && let Err(error) = self.release(true) {
            self.poison(error);
            self.fail_all();
            return;
        }
        for tag in 0..self.tags.len() {
            if matches!(&self.tags[tag], Tag::Delayed { until, .. } if until.passed()) {
                let Tag::Delayed {
                    namespace,
                    block,
                    command,
                    retries,
                    ..
                } = core::mem::take(&mut self.tags[tag])
                else {
                    unreachable!();
                };
                self.submit(tag, namespace, block, command, retries);
            }
        }
        for tag in 0..self.tags.len() {
            let Tag::Running {
                id,
                deadline,
                aborted,
                ..
            } = &self.tags[tag]
            else {
                continue;
            };
            if !deadline.passed() {
                continue;
            }
            if *aborted {
                self.reset();
                return;
            }
            let id = *id;
            match self.abort(tag, id) {
                Ok(true) => {}
                Ok(false) => {
                    self.reset();
                    return;
                }
                Err(error) => {
                    self.poison(error);
                    self.fail_all();
                    return;
                }
            }
        }
    }

    /// Linux `nvme_timeout` for an I/O command's first deadline: abort it
    /// and give it another, unless the controller is fatally failed, which
    /// is reset at once (`false`).
    fn abort(&mut self, tag: usize, id: u16) -> Result<bool, BlockError> {
        match self.registers.read32(STATUS)? {
            REMOVED => return Err(removed()),
            status if status & FATAL != 0 => return Ok(false),
            _ => {}
        }
        let mut command = [0u32; 16];
        command[0] = u32::from(ADMIN_ABORT);
        command[10] = u32::from(id) << 16 | u32::from(self.io.id);
        let abort = self.publish(false, command, None)?;
        self.aborts.push(abort);
        let renewed = self.deadline(self.command_timeout_us)?;
        if let Tag::Running {
            deadline, aborted, ..
        } = &mut self.tags[tag]
        {
            (*deadline, *aborted) = (renewed, true);
        }
        Ok(true)
    }

    /// Command `id` completed with `status`, the controller reporting
    /// submission head `head`: its tag takes the result, or, for an error
    /// without Do Not Retry and retries left, runs it again after the delay
    /// its Command Retry Delay selects (`nvme_decide_disposition`). Whether
    /// a running command matched.
    fn complete(&mut self, id: u16, status: u32, head: u16) -> bool {
        let io = &self.io;
        // NVMe SQHD is a snapshot when the CQE is created, not the completed
        // command's slot (Base 1.1, section 4.6). A fetched command may remain
        // in flight while later commands carry the ring through another turn.
        for tag in &mut self.tags {
            if let Tag::Running { slot, fetched, .. } = tag {
                *fetched |= io.fetched(*slot, head);
            }
        }
        let Some(tag) = self.tags.iter().position(|tag| {
            matches!(tag, Tag::Running { id: running, fetched: true, .. }
                if *running == id)
        }) else {
            return false;
        };
        let Tag::Running {
            namespace,
            block,
            command,
            retries,
            ..
        } = core::mem::take(&mut self.tags[tag])
        else {
            unreachable!();
        };
        // SAFETY: the controller completed this exact command; its memory
        // is the CPU's again.
        let taken = unsafe {
            let (bounce, prp_list) = self.slot(tag);
            bounce.take().and_then(|()| prp_list.take())
        };
        let retry = status != 0 && status & STATUS_DO_NOT_RETRY == 0 && retries < RETRIES;
        self.tags[tag] = match (taken, status, command) {
            (Err(error), ..) => Tag::Done(Err(self.poison(error))),
            (Ok(()), _, command) if retry => {
                let delay = match (status & STATUS_RETRY_DELAY) >> 11 {
                    0 => 0,
                    index => u64::from(self.retry_delays[index as usize - 1]) * RETRY_DELAY_UNIT_US,
                };
                match self.deadline(delay) {
                    Ok(until) => Tag::Delayed {
                        namespace,
                        block,
                        command,
                        retries: retries + 1,
                        until,
                    },
                    Err(error) => Tag::Done(Err(error)),
                }
            }
            (Ok(()), 0, Command::Read { bytes, .. }) => {
                Tag::Done(Ok(Some(self.slot(tag).0.bytes()[..bytes].to_vec())))
            }
            (Ok(()), 0, _) => Tag::Done(Ok(None)),
            (Ok(()), status, _) => Tag::Done(Err(BlockError::Device { status })),
        };
        true
    }

    /// End every command with the controller's fault.
    fn fail_all(&mut self) {
        let error = self.fault.clone().unwrap_or(BlockError::Timeout);
        for tag in &mut self.tags {
            if matches!(
                tag,
                Tag::Running { .. } | Tag::Waiting { .. } | Tag::Delayed { .. }
            ) {
                *tag = Tag::Done(Err(error.clone()));
            }
        }
        self.recovery = None;
    }

    /// Reset the controller, as Linux's `nvme_timeout` does once a
    /// controller is not gone: every running command waits to run again
    /// once the reset completes, while it has retries left.
    fn reset(&mut self) {
        self.reset_with(true);
    }

    /// [`Self::reset`]: `nvme_dev_disable` deletes the I/O queues of a live
    /// controller, unless `delete` is clear or an Abort went unanswered,
    /// either leaving no admin queue to delete with. A removed controller
    /// stays failed.
    fn reset_with(&mut self, delete: bool) {
        let status = match self.registers.read32(STATUS) {
            Ok(REMOVED) => Err(removed()),
            other => other,
        };
        let status = match status {
            Ok(status) => status,
            Err(error) => {
                self.poison(error);
                self.fail_all();
                return;
            }
        };
        for tag in &mut self.tags {
            *tag = match core::mem::take(tag) {
                Tag::Running {
                    namespace,
                    block,
                    command,
                    retries,
                    ..
                } => Tag::Waiting {
                    namespace,
                    block,
                    command,
                    retries: retries + 1,
                },
                other => other,
            };
        }
        let dead = status & FATAL != 0 || status & READY == 0;
        let started = if !dead && delete && self.aborts.is_empty() {
            self.delete_next(true)
        } else {
            self.disable()
        };
        if let Err(error) = started {
            self.poison(error);
            self.fail_all();
        }
    }

    fn deadline(&self, us: u64) -> Result<crate::Deadline, BlockError> {
        self.clock
            .try_deadline(us)
            .map_err(|_| BlockError::Unsupported("NVMe requires a representable deadline"))
    }

    /// Delete the I/O submission queue, or then the completion queue.
    fn delete_next(&mut self, submission: bool) -> Result<(), BlockError> {
        let mut command = [0u32; 16];
        command[0] = u32::from(if submission {
            ADMIN_DELETE_SUBMISSION
        } else {
            ADMIN_DELETE_COMPLETION
        });
        command[10] = u32::from(self.io.id);
        let id = self.publish(false, command, None)?;
        let deadline = self.deadline(self.admin_timeout_us)?;
        self.recovery = Some(Recovery::Deleting {
            submission,
            id,
            deadline,
        });
        Ok(())
    }

    /// Clear CC.EN (and any shutdown notification).
    fn disable(&mut self) -> Result<(), BlockError> {
        let configuration = self.registers.read32(CONFIGURATION)?;
        self.registers.write32(
            CONFIGURATION,
            configuration & !(ENABLE | SHUTDOWN_NOTIFICATION),
        )?;
        let deadline = self.deadline(self.ready_timeout_us)?;
        self.recovery = Some(Recovery::Disabling(deadline));
        Ok(())
    }

    /// The disabled controller no longer reaches any queue or buffer:
    /// contain its DMA (`pci_disable_device`), take every one back, end the
    /// commands out of retries (`nvme_cancel_tagset`), empty the queues and
    /// point the controller at the admin queue again.
    fn restart_queues(&mut self) -> Result<(), BlockError> {
        if let Some(owner) = self.owned.as_mut() {
            owner.lifecycle.disable_dma()?;
            // SAFETY: the engine acknowledged its reset and BME is off.
            unsafe { owner.domain.drain_posted_writes() }.map_err(owned::map_dma_error)?;
        }
        for tag in 0..self.tags.len() {
            // SAFETY: CSTS.RDY clear acknowledges the stopped engine.
            unsafe {
                let (bounce, prp_list) = self.slot(tag);
                bounce.take()?;
                prp_list.take()?;
            }
        }
        // SAFETY: as above.
        unsafe {
            self.admin.submissions.take()?;
            self.io.submissions.take()?;
            for queue in [&mut self.admin, &mut self.io] {
                queue.completions.take()?;
                queue.completions.bytes_mut().fill(0);
            }
        }
        for tag in &mut self.tags {
            if matches!(tag, Tag::Waiting { retries, .. } if *retries > RETRIES) {
                *tag = Tag::Done(Err(BlockError::Timeout));
            }
        }
        self.io.restart();
        self.aborts.clear();
        // The disable ended the Asynchronous Event Request; the host memory
        // buffer is offered back with the bring-up.
        self.events.request = None;
        self.host_memory_enabled = false;
        self.configure_admin()?;
        if let Some(owner) = self.owned.as_mut() {
            owner.lifecycle.enable_dma()?;
        }
        Ok(())
    }

    /// Move the controller reset on, never waiting: the I/O queues deleted,
    /// disabled, enabled with the admin queue, brought up again, then the
    /// interrupted commands run again under their tags.
    fn recover(&mut self) -> Result<(), BlockError> {
        let status = self.registers.read32(STATUS)?;
        if status == REMOVED {
            return Err(removed());
        }
        match self.recovery.take() {
            None => Ok(()),
            Some(Recovery::Deleting {
                submission,
                id,
                deadline,
            }) => match self.admin_completion(Some((id, false)))? {
                None if !deadline.passed() => {
                    self.recovery = Some(Recovery::Deleting {
                        submission,
                        id,
                        deadline,
                    });
                    Ok(())
                }
                // A refused deletion is ignored and a timed-out one ends
                // the deletions, as in Linux.
                Some(_) if submission => self.delete_next(false),
                _ => self.disable(),
            },
            Some(Recovery::Disabling(deadline)) => {
                if status & READY != 0 {
                    if deadline.passed() {
                        return Err(BlockError::Timeout);
                    }
                    self.recovery = Some(Recovery::Disabling(deadline));
                    return Ok(());
                }
                self.restart_queues()?;
                let timeout = self.enable()?;
                let deadline = self.deadline(timeout)?;
                self.recovery = Some(Recovery::Enabling(deadline));
                Ok(())
            }
            Some(Recovery::Enabling(deadline)) => {
                if status & FATAL != 0 {
                    return Err(BlockError::Device { status });
                }
                if status & READY == 0 {
                    if deadline.passed() {
                        return Err(BlockError::Timeout);
                    }
                    self.recovery = Some(Recovery::Enabling(deadline));
                    return Ok(());
                }
                self.bring_up(Step::Identify, Vec::new())
            }
            Some(Recovery::Admin {
                step,
                id,
                deadline,
                mut identify,
            }) => {
                let Some((_, code)) = self.admin_completion(Some((id, true)))? else {
                    if deadline.passed() {
                        return Err(BlockError::Timeout);
                    }
                    self.recovery = Some(Recovery::Admin {
                        step,
                        id,
                        deadline,
                        identify,
                    });
                    return Ok(());
                };
                match (step, code) {
                    (Step::Identify, 0) => {
                        identify = self.bounce.bytes()[..PAGE].to_vec();
                        self.identified(&identify);
                    }
                    (Step::Limits, code) => self.limits_answered(code),
                    (Step::HostMemory, code) => self.host_memory_answered(code == 0),
                    // A refused feature is only logged.
                    (Step::HostOptions | Step::Apst | Step::Events, _) => {}
                    (Step::CreateCompletion | Step::CreateSubmission, 0) => {}
                    (_, status) => return Err(BlockError::Device { status }),
                }
                let next = STEPS.iter().position(|each| *each == step).unwrap() + 1;
                match STEPS.get(next) {
                    Some(&next) => self.bring_up(next, identify),
                    None => self.restarted(),
                }
            }
        }
    }

    /// Submit the bring-up command of the first step from `from` on that
    /// has one; with none left, the controller is up.
    fn bring_up(&mut self, from: Step, identify: Vec<u8>) -> Result<(), BlockError> {
        let first = STEPS.iter().position(|each| *each == from).unwrap();
        for &step in &STEPS[first..] {
            let command = match step {
                Step::Identify => Some(self.identify_command(IDENTIFY_CONTROLLER, 0)?),
                Step::Limits => self.limits_command()?,
                Step::HostOptions => self.host_options(&identify)?,
                Step::Apst => match apst_table(&identify) {
                    Some(table) => Some(self.apst_command(&table)?),
                    None => None,
                },
                Step::HostMemory => self.host_memory_command()?,
                Step::CreateCompletion => Some(self.create_queue(false)?),
                Step::CreateSubmission => {
                    self.io.submissions.publish();
                    Some(self.create_queue(true)?)
                }
                Step::Events => self.events_command(),
            };
            let Some(command) = command else {
                continue;
            };
            let id = self.publish(false, command, Some(0))?;
            let deadline = self.deadline(self.admin_timeout_us)?;
            self.recovery = Some(Recovery::Admin {
                step,
                id,
                deadline,
                identify,
            });
            return Ok(());
        }
        self.restarted()
    }

    /// `nvme_start_ctrl`: leave an Asynchronous Event Request outstanding,
    /// queue a namespace scan and run the interrupted commands again.
    fn restarted(&mut self) -> Result<(), BlockError> {
        if self.events.supported != 0 {
            self.request_event()?;
        }
        self.scans += 1;
        for tag in 0..self.tags.len() {
            match core::mem::take(&mut self.tags[tag]) {
                Tag::Waiting {
                    namespace,
                    block,
                    command,
                    retries,
                } => self.submit(tag, namespace, block, command, retries),
                other => self.tags[tag] = other,
            }
        }
        Ok(())
    }

    /// What `nvme_init_ctrl_finish` keeps from Identify Controller: the
    /// retry delays, transfer limits and the events to enable. A reset's fresh
    /// Identify updates both limits before namespace features are rescanned.
    fn identified(&mut self, identify: &[u8]) {
        let mdts = identify[CONTROLLER_MAXIMUM_TRANSFER];
        let bytes = if mdts == 0 {
            usize::MAX
        } else {
            1usize
                .checked_shl(u32::from(mdts))
                .unwrap_or(usize::MAX)
                .saturating_mul(PAGE)
        };
        self.max_transfer = BOUNCE_BYTES.min(bytes);
        self.max_command_bytes = MAX_COMMAND_BYTES.min(bytes);
        for (index, delay) in self.retry_delays.iter_mut().enumerate() {
            let at = CONTROLLER_RETRY_DELAYS + 2 * index;
            *delay = u16::from_le_bytes([identify[at], identify[at + 1]]);
        }
        self.events = Events::from_identify(identify);
    }

    /// The NVM Identify Controller of `nvme_init_non_mdts_limits`, which
    /// `nvme_id_cns_ok` sends only from NVMe 1.2. WZSL starts over each
    /// time; a refused command is not sent again.
    fn limits_command(&mut self) -> Result<Option<[u32; 16]>, BlockError> {
        self.limits.write_zeroes = 0;
        if self.version < VERSION_1_2 || self.limits.refused {
            return Ok(None);
        }
        // CDW11's CSI stays 0, the NVM command set.
        self.identify_command(IDENTIFY_COMMAND_SET_CONTROLLER, 0)
            .map(Some)
    }

    fn limits_answered(&mut self, status: u32) {
        if status != 0 {
            self.limits.refused = true;
            return;
        }
        let page = self.bounce.bytes();
        self.limits.write_zeroes = page[NVM_WRITE_ZEROES_LIMIT];
        self.limits.deallocate = le32(page, NVM_DEALLOCATE_RANGE_LIMIT);
    }

    /// Linux `nvme_configure_host_options` from `identify`: a Set Features
    /// for Host Behavior Support enabling ACRE when a retry delay is
    /// reported and LBAFEE for extended LBA formats, its data in tag 0's
    /// bounce page.
    fn host_options(&mut self, identify: &[u8]) -> Result<Option<[u32; 16]>, BlockError> {
        let acre = self.retry_delays[0] != 0;
        let lbafee = le32(identify, CONTROLLER_ATTRIBUTES) & ATTRIBUTE_EXTENDED_LBA != 0;
        if !acre && !lbafee {
            return Ok(None);
        }
        let page = &mut self.bounce.bytes_mut()[..HOST_BEHAVIOR_BYTES];
        page.fill(0);
        page[HOST_BEHAVIOR_ACRE] = u8::from(acre);
        page[HOST_BEHAVIOR_LBAFEE] = u8::from(lbafee);
        let data = self.bounce.address()?;
        let mut command = [0u32; 16];
        command[0] = u32::from(ADMIN_SET_FEATURES);
        command[6] = data as u32;
        command[7] = (data >> 32) as u32;
        command[10] = FEATURE_HOST_BEHAVIOR;
        Ok(Some(command))
    }

    /// The Set Features enabling autonomous power state transitions with
    /// `table`, written to tag 0's bounce page.
    fn apst_command(&mut self, table: &[u64; 32]) -> Result<[u32; 16], BlockError> {
        for (index, entry) in table.iter().enumerate() {
            self.bounce.write(8 * index, *entry);
        }
        let page = self.bounce.address()?;
        let mut command = [0u32; 16];
        command[0] = u32::from(ADMIN_SET_FEATURES);
        command[6] = page as u32;
        command[7] = (page >> 32) as u32;
        command[10] = FEATURE_APST;
        command[11] = 1;
        Ok(command)
    }

    /// Linux `nvme_alloc_host_mem_multi`: chunks of `chunk` bytes up to the
    /// preferred size and descriptor limit; `None` when not one chunk fits.
    fn host_memory_chunks(
        request: HostMemoryRequest,
        preferred: u64,
        chunk: u64,
        source: &mut dyn HostMemorySource,
    ) -> Option<HostMemory> {
        let mut entries = preferred.div_ceil(chunk);
        if request.descriptors != 0 {
            entries = entries.min(u64::from(request.descriptors));
        }
        let mut descriptors = source
            .allocate(entries as usize * HOST_MEMORY_DESCRIPTOR, false)
            .ok()?;
        let mut chunks = Vec::new();
        let mut bytes = 0u64;
        while bytes < preferred && (chunks.len() as u64) < entries {
            let length = chunk.min(preferred - bytes);
            let Ok(buffer) = source.allocate(length as usize, true) else {
                break;
            };
            let at = chunks.len() * HOST_MEMORY_DESCRIPTOR;
            descriptors.write(at, buffer.address().ok()?);
            descriptors.write(at + 8, (length / PAGE as u64) as u32);
            chunks.push(buffer);
            bytes += length;
        }
        if bytes == 0 {
            return None;
        }
        descriptors.give().ok()?;
        for chunk in &mut chunks {
            chunk.give().ok()?;
        }
        Some(HostMemory {
            descriptors,
            chunks,
            bytes,
            returnable: false,
        })
    }

    /// Linux `nvme_setup_host_mem` at discovery: the preferred size, capped
    /// at `max_host_mem_size_mb`, from the largest chunks down to the
    /// minimum descriptor size. A controller works without one when it
    /// cannot be had; the bring-up hands it over.
    fn allocate_host_memory(
        &mut self,
        request: HostMemoryRequest,
        source: &mut dyn HostMemorySource,
    ) {
        if request.preferred == 0 || request.minimum > HOST_MEMORY_MAXIMUM {
            return;
        }
        let preferred = request.preferred.min(HOST_MEMORY_MAXIMUM);
        let smallest = request.descriptor_minimum.max(2 * PAGE as u64);
        let mut chunk = preferred.min(HOST_MEMORY_CHUNK);
        while chunk >= smallest {
            if let Some(memory) = Self::host_memory_chunks(request, preferred, chunk, source) {
                if request.minimum == 0 || memory.bytes >= request.minimum {
                    self.host_memory = Some(memory);
                    return;
                }
                // nvme_free_host_mem: the controller never saw it.
                drop(memory);
            }
            chunk /= 2;
        }
    }

    /// Linux `nvme_set_host_mem` with EHM, and MR for a buffer the
    /// controller already filled.
    fn host_memory_command(&self) -> Result<Option<[u32; 16]>, BlockError> {
        let Some(memory) = self.host_memory.as_ref() else {
            return Ok(None);
        };
        let mut bits = HOST_MEMORY_ENABLE;
        if memory.returnable {
            bits |= HOST_MEMORY_RETURN;
        }
        let list = memory.descriptors.address()?;
        let mut command = [0u32; 16];
        command[0] = u32::from(ADMIN_SET_FEATURES);
        command[10] = FEATURE_HOST_MEMORY;
        command[11] = bits;
        command[12] = (memory.bytes / PAGE as u64) as u32;
        command[13] = list as u32;
        command[14] = (list >> 32) as u32;
        command[15] = memory.chunks.len() as u32;
        Ok(Some(command))
    }

    /// The controller took the host memory buffer or refused it, which
    /// leaves it without one: the next bring-up offers it afresh
    /// (`nvme_free_host_mem`). Its pages stay reserved, never reused for
    /// anything else.
    fn host_memory_answered(&mut self, accepted: bool) {
        self.host_memory_enabled = accepted;
        if let Some(memory) = self.host_memory.as_mut() {
            memory.returnable = accepted;
        }
    }

    /// Linux `nvme_enable_aen`: enable the notices Linux handles.
    fn events_command(&self) -> Option<[u32; 16]> {
        if self.events.supported == 0 {
            return None;
        }
        let mut command = [0u32; 16];
        command[0] = u32::from(ADMIN_SET_FEATURES);
        command[10] = FEATURE_ASYNC_EVENTS;
        command[11] = self.events.supported;
        Some(command)
    }

    /// Linux `nvme_pci_submit_async_event`.
    fn request_event(&mut self) -> Result<(), BlockError> {
        let mut command = [0u32; 16];
        command[0] = u32::from(ADMIN_ASYNC_EVENT);
        let id = self.publish(false, command, None)?;
        self.events.request = Some(id);
        Ok(())
    }

    /// Linux's interrupt-time `nvme_complete_async_event` and its work,
    /// between commands: act on a completed Asynchronous Event Request and
    /// request the next event. A failed request is not repeated; a
    /// persistent internal error resets the controller, which requests
    /// events again.
    fn service_events(&mut self) -> Result<(), BlockError> {
        if self.events.request.is_some()
            && !self.busy()
            && let Err(error) = self.admin_completion(None)
        {
            return Err(self.poison(error));
        }
        let Some((result, status)) = self.events.completed.take() else {
            return Ok(());
        };
        if status != 0 {
            return Ok(());
        }
        match (result & 0x7, result >> 8 & 0xff) {
            (EVENT_NOTICE, NOTICE_NAMESPACES_CHANGED) => {
                // nvme_scan_work clears the Changed Namespace List first.
                self.read_log(LOG_CHANGED_NAMESPACES, PAGE)?;
                self.scans += 1;
            }
            (EVENT_NOTICE, NOTICE_FIRMWARE_ACTIVATION) => {
                // nvme_fw_act_work: commands wait while processing is paused,
                // up to MTFA or the admin timeout, then the Firmware Slot
                // Information log clears the event.
                let timeout = match self.events.activation_us {
                    0 => self.admin_timeout_us,
                    activation => activation,
                };
                match self.wait_status(timeout, |status| status & PROCESSING_PAUSED == 0) {
                    Ok(()) => self.read_log(LOG_FIRMWARE_SLOT, 512)?,
                    Err(BlockError::Timeout) => return self.reset_and_settle(),
                    Err(error) => return Err(self.poison(error)),
                }
            }
            (EVENT_ERROR, ERROR_PERSISTENT_INTERNAL) => return self.reset_and_settle(),
            _ => {}
        }
        self.request_event()
    }

    fn reset_and_settle(&mut self) -> Result<(), BlockError> {
        self.reset();
        self.settle()
    }

    /// Linux `nvme_get_log` for every namespace into tag 0's bounce page. A
    /// failure is only logged.
    fn read_log(&mut self, log: u32, bytes: usize) -> Result<(), BlockError> {
        let page = self.bounce.address()?;
        let mut command = [0u32; 16];
        command[0] = u32::from(ADMIN_GET_LOG_PAGE);
        command[1] = u32::MAX;
        command[6] = page as u32;
        command[7] = (page >> 32) as u32;
        command[10] = ((bytes / 4 - 1) as u32) << 16 | log;
        let _ = self.admin(command);
        self.ready()
    }

    /// Linux `nvme_scan_ns` before it adds or validates a namespace: its
    /// identifiers and whether the command-set-independent Identify
    /// Namespace described it, or `None` when Linux passes it over for
    /// refused descriptors, a command set the controller does not run, or a
    /// namespace that is not ready.
    fn namespace_ids(&mut self, namespace: u32) -> Result<Option<(Ids, bool)>, BlockError> {
        let Some(ids) = self.descriptors(namespace)? else {
            return Ok(None);
        };
        if ids.csi != CSI_NVM && self.configuration & COMMAND_SETS_ALL == 0 {
            return Ok(None);
        }
        if self.independent_identify
            || (ids.csi != CSI_NVM && ids.csi != CSI_ZONED)
            || self.version >= VERSION_2_0
        {
            match self.identify(IDENTIFY_INDEPENDENT_NAMESPACE, namespace) {
                Ok(data) => {
                    let ready = data[INDEPENDENT_STATUS] & NAMESPACE_READY != 0;
                    return Ok(ready.then_some((ids, true)));
                }
                Err(BlockError::Device { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(Some((ids, false)))
    }

    /// Linux `nvme_identify_ns_descs`: none before NVMe 1.3. `None` when the
    /// controller refused the list; the scan then skips the namespace.
    fn descriptors(&mut self, namespace: u32) -> Result<Option<Ids>, BlockError> {
        if self.version < VERSION_1_3 {
            return Ok(Some(Ids::default()));
        }
        match self.identify(IDENTIFY_DESCRIPTORS, namespace) {
            Ok(data) => Ok(Some(Ids::from_descriptors(data))),
            Err(BlockError::Device { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Tag `tag`'s result once its command completed; never waits.
    fn finish(&mut self, tag: usize) -> Option<Finished> {
        self.advance();
        if !matches!(self.tags.get(tag)?, Tag::Done(_)) {
            return None;
        }
        match core::mem::take(&mut self.tags[tag]) {
            Tag::Done(result) => Some(result),
            _ => unreachable!(),
        }
    }

    /// Flush callers before this method; acknowledged SHST prevents further
    /// commands, while owned resource retirement separately requires RDY0.
    fn shutdown(&mut self) -> Result<(), BlockError> {
        if self.shut_down {
            return Ok(());
        }
        self.ready()?;
        if let Err(error) = self.check_fatal() {
            return Err(self.poison(error));
        }
        self.settle()?;
        self.delete_io_queues()?;
        let result = (|| {
            let configuration = self.registers.read32(CONFIGURATION)?;
            self.registers.write32(
                CONFIGURATION,
                configuration & !SHUTDOWN_NOTIFICATION | SHUTDOWN_NORMAL,
            )?;
            self.wait_status(self.shutdown_timeout_us, |status| {
                status & SHUTDOWN_STATUS == SHUTDOWN_COMPLETE
            })
        })();
        if let Err(error) = result {
            return Err(self.poison(error));
        }
        self.shut_down = true;
        Ok(())
    }

    /// Linux `nvme_dev_disable` deletes the I/O queues, submission queue
    /// first, before the shutdown notification. A refused deletion is
    /// ignored and a timed-out one ends the deletions, as in Linux; a
    /// broken protocol poisons.
    fn delete_io_queues(&mut self) -> Result<(), BlockError> {
        for opcode in [ADMIN_DELETE_SUBMISSION, ADMIN_DELETE_COMPLETION] {
            let mut command = [0u32; 16];
            command[0] = u32::from(opcode);
            command[10] = u32::from(self.io.id);
            match self.admin_wait(command, None) {
                Ok(_) => {}
                Err(Lost::Reset(_)) => break,
                Err(Lost::Fatal(error)) => return Err(self.poison(error)),
            }
        }
        Ok(())
    }

    /// An admin Identify into tag 0's bounce page.
    fn identify(&mut self, cns: u32, namespace: u32) -> Result<&[u8], BlockError> {
        let command = self.identify_command(cns, namespace)?;
        self.admin(command)?;
        Ok(&self.bounce.bytes()[..PAGE])
    }

    /// The PRP entries for the first `bytes` of tag `tag`'s bounce buffer.
    fn data_pointers(&mut self, tag: usize, bytes: usize) -> Result<(u64, u64), BlockError> {
        let (bounce, prp_list) = self.slot(tag);
        let first = bounce.address()?;
        match bytes.div_ceil(PAGE) {
            0 | 1 => Ok((first, 0)),
            2 => Ok((first, first + PAGE as u64)),
            pages => {
                for page in 1..pages {
                    prp_list.write(8 * (page - 1), first + (page * PAGE) as u64);
                }
                Ok((first, prp_list.address()?))
            }
        }
    }
}

fn removed() -> BlockError {
    BlockError::Unsupported("the NVMe controller is gone")
}

/// One namespace of a controller.
pub struct Namespace {
    controller: Rc<RefCell<Controller>>,
    namespace: u32,
    identity: Identity,
    ids: Ids,
    /// The controller scan count this namespace was last scanned at.
    scanned: u64,
    /// Set once a rescan removed the namespace.
    removed: Option<BlockError>,
}

/// Reset `function`'s controller, bring up its queues and return its usable
/// namespaces.
pub fn attach(
    function: &mut Function,
    handoff: &Handoff,
    dma: &mut dyn DmaAllocator,
) -> Result<Attached, BlockError> {
    validate_clock(handoff.clock)?;
    function.power_up(&handoff.clock)?;
    let bars = function.bars();
    let registers = RegisterIo::Legacy(registers(handoff, bars[0], 0, 0x2000)?);
    function.enable_polled();
    let signalled = match (handoff.completion, function.interrupts().msix) {
        (Some(message), Some(msix)) => {
            let table = crate::registers(
                handoff,
                bars[usize::from(msix.table_bar)],
                u64::from(msix.table_offset),
                MSIX_ENTRY_BYTES,
            )?;
            function.enable_msix(msix, || {
                table.write32(0, message.address as u32);
                table.write32(4, (message.address >> 32) as u32);
                table.write32(8, message.data);
                table.write32(12, 0);
                Ok(())
            })?;
            true
        }
        _ => false,
    };
    let mut slots = Vec::new();
    for _ in 1..DEPTH {
        slots.push(Slot {
            bounce: Buffer::Legacy(dma.allocate(BOUNCE_BYTES, PAGE)?),
            prp_list: Buffer::Legacy(dma.allocate(PAGE, PAGE)?),
        });
    }
    let mut controller = Controller {
        registers,
        doorbell_stride: 0,
        admin: Queue::new(0, ADMIN_ENTRIES, dma)?,
        io: Queue::new(1, IO_ENTRIES, dma)?,
        bounce: Buffer::Legacy(dma.allocate(BOUNCE_BYTES, PAGE)?),
        prp_list: Buffer::Legacy(dma.allocate(PAGE, PAGE)?),
        slots,
        tags: (0..DEPTH).map(|_| Tag::Free).collect(),
        recovery: None,
        signalled,
        max_transfer: BOUNCE_BYTES,
        max_command_bytes: MAX_COMMAND_BYTES,
        shutdown_timeout_us: SHUTDOWN_MINIMUM_US,
        shut_down: false,
        command_id: 0,
        clock: handoff.clock,
        command_timeout_us: COMMAND_TIMEOUT_US,
        admin_timeout_us: ADMIN_TIMEOUT_US,
        fault: None,
        owned: None,
        teardown: owned::Teardown::Unprepared,
        ready_timeout_us: 500_000,
        configuration: CONFIGURATION_VALUE & !ENABLE,
        independent_identify: false,
        version: 0,
        commands: 0,
        scans: 0,
        retry_delays: [0; 3],
        host_memory: None,
        host_memory_enabled: false,
        events: Events::default(),
        aborts: Vec::new(),
        limits: Limits::default(),
    };
    controller.initialize()?;
    discover(controller, format!("{}", function.address), &mut { dma })
}

/// Linux `nvme_wait_ready`'s bound for a ready timeout in 500 ms units:
/// whole seconds, rounded up.
fn ready_wait_us(units: u64) -> u64 {
    units.div_ceil(2) * MICROSECONDS_PER_SECOND
}

pub(crate) fn validate_clock(clock: Clock) -> Result<(), BlockError> {
    // CRTO.CRWMT permits 65535 half-second intervals, beyond CAP.TO's 255.
    // The fixed command and maximum shutdown policies are shorter; admit
    // every later native wait upfront.
    clock.check_duration(ready_wait_us(0xffff)).map_err(|_| {
        BlockError::Unsupported("NVMe requires a calibrated, representable operation clock")
    })
}

fn discover(
    mut controller: Controller,
    location: alloc::string::String,
    host_memory: &mut dyn HostMemorySource,
) -> Result<Attached, BlockError> {
    let identify = controller.identify(IDENTIFY_CONTROLLER, 0)?.to_vec();
    let request = HostMemoryRequest::from_identify(&identify);
    let serial = ascii(&identify[CONTROLLER_SERIAL]);
    let model = ascii(&identify[CONTROLLER_MODEL]);
    let rtd3_entry_us = u64::from(le32(&identify[CONTROLLER_RTD3_ENTRY], 0));
    let namespaces = le32(&identify[CONTROLLER_NAMESPACES], 0);
    controller.commands = u16::from_le_bytes([
        identify[CONTROLLER_COMMANDS],
        identify[CONTROLLER_COMMANDS + 1],
    ]);
    // Linux `nvme_init_identify` takes a present cache as one to flush and
    // leaves the controller's Volatile Write Cache feature as it is.
    let write_cache = identify[CONTROLLER_VOLATILE_CACHE] & 1 != 0;
    controller.shutdown_timeout_us = shutdown_timeout_us(rtd3_entry_us);
    controller.identified(&identify);
    controller.allocate_host_memory(request, host_memory);
    let version = controller.registers.read32(VERSION)?;
    controller.version = version;
    // The rest of the bring-up, as a reset repeats it: the NVM limits, host
    // options, APST, the host memory buffer, the I/O queues and events.
    controller.bring_up(Step::Limits, identify)?;
    controller.settle()?;

    // Linux `nvme_scan_work`: the active list from NVMe 1.1, otherwise (or
    // when the controller refuses it) every namespace ID in turn.
    let listed = if version >= VERSION_1_1 {
        controller
            .identify(IDENTIFY_ACTIVE_NAMESPACES, 0)
            .map(|list| {
                list.as_chunks::<4>()
                    .0
                    .iter()
                    .map(|word| u32::from_le_bytes(*word))
                    .take_while(|namespace| *namespace != 0)
                    .collect::<Vec<u32>>()
            })
            .ok()
    } else {
        None
    };
    controller.ready()?;
    let (candidates, sequential) = match listed {
        Some(active) => (active, false),
        None => ((1..=namespaces.min(SEQUENTIAL_SCAN_LIMIT)).collect(), true),
    };
    let mut attached = Attached {
        namespaces: Vec::new(),
        failures: Vec::new(),
    };
    let mut found = Vec::new();
    let (max_transfer, max_command_bytes, commands, scans, limits) = (
        controller.max_transfer,
        controller.max_command_bytes,
        controller.commands,
        controller.scans,
        controller.limits,
    );
    for namespace in candidates {
        let Some((mut ids, independent)) = controller.namespace_ids(namespace)? else {
            continue;
        };
        // Zoned and other command sets need drivers Stela does not have.
        if ids.csi != CSI_NVM {
            attached
                .failures
                .push((namespace, BlockError::Unsupported("NVMe I/O command set")));
            continue;
        }
        let data = controller.identify(IDENTIFY_NAMESPACE, namespace)?;
        if !independent {
            ids.fill(version, data);
        }
        match plain_format(data, max_transfer) {
            // An inactive namespace reads as all zeros in a sequential scan.
            Ok(None) if sequential => {}
            Ok(None) => attached
                .failures
                .push((namespace, BlockError::Unsupported("empty NVMe namespace"))),
            Ok(Some(format)) => found.push((namespace, format, ids)),
            Err(error) => attached.failures.push((namespace, error)),
        }
    }
    let controller = Rc::new(RefCell::new(controller));
    attached.namespaces = found
        .into_iter()
        .map(|(namespace, format, ids)| Namespace {
            controller: controller.clone(),
            namespace,
            ids,
            scanned: scans,
            removed: None,
            identity: Identity {
                transport: Transport::Nvme,
                location: format!("{location} namespace {namespace}"),
                model: model.clone(),
                serial: serial.clone(),
                blocks: format.blocks,
                block_size: format.block_size,
                read_only: format.read_only,
                features: features(
                    write_cache,
                    commands,
                    limits,
                    &format,
                    TransferLimits {
                        data: max_transfer,
                        command: max_command_bytes,
                    },
                ),
            },
        })
        .collect();
    Ok(attached)
}

/// The APST table Linux `nvme_configure_apst` gives a controller that
/// supports it, or `None`: from the deepest power state up, each state goes
/// to the deepest usable non-operational state below it once idle for its
/// timeout, at most one state per latency tolerance.
fn apst_table(identify: &[u8]) -> Option<[u64; 32]> {
    let deepest = usize::from(identify[CONTROLLER_POWER_STATES]);
    if identify[CONTROLLER_APST] & 1 == 0 || deepest > 31 {
        return None;
    }
    let mut table = [0; 32];
    let mut target = 0;
    let mut tolerance = u32::MAX;
    for state in (0..=deepest).rev() {
        table[state] = target;
        let descriptor = &identify[CONTROLLER_POWER_DESCRIPTORS + 32 * state..][..32];
        if descriptor[3] & POWER_NON_OPERATIONAL == 0 {
            continue;
        }
        let exit = u64::from(le32(descriptor, 8));
        if exit > APST_MAX_LATENCY_US {
            continue;
        }
        let total = exit + u64::from(le32(descriptor, 4));
        let idle = if total <= APST_PRIMARY_TOLERANCE_US && tolerance != 1 {
            tolerance = 1;
            APST_PRIMARY_TIMEOUT_MS
        } else if total > APST_PRIMARY_TOLERANCE_US
            && total <= APST_SECONDARY_TOLERANCE_US
            && tolerance > 2
        {
            tolerance = 2;
            APST_SECONDARY_TIMEOUT_MS
        } else {
            continue;
        };
        target = (state as u64) << 3 | idle << 8;
    }
    Some(table)
}

/// Payload storage and logical command-range limits are separate: a no-data
/// command does not consume the smaller DMA bounce-buffer allowance.
#[derive(Clone, Copy)]
struct TransferLimits {
    data: usize,
    command: usize,
}

/// A namespace's features, as Linux `nvme_update_disk_info` sets them:
/// FUA with a volatile write cache; Deallocate as discard with Dataset
/// Management, one range of up to DMRSL blocks, or else `UINT_MAX` sectors;
/// and Write Zeroes up to WZSL, or else the controller's command range
/// (`nvme_init_non_mdts_limits`), which may deallocate where the namespace
/// reads deallocated blocks as zeros and says Write Zeroes deallocates
/// (`NVME_NS_DEAC`). A Write Zeroes command takes at most 2^16 blocks.
fn features(
    write_cache: bool,
    commands: u16,
    limits: Limits,
    format: &Format,
    transfer: TransferLimits,
) -> Features {
    let block_shift = format.block_size.trailing_zeros();
    let sectors = u64::from(u32::MAX) >> (block_shift - 9);
    let deallocate = u64::from(limits.deallocate);
    let zeroes = match limits.write_zeroes {
        0 => transfer.command as u64,
        // 2^WZSL minimum pages of 4 KiB, saturating as nvme_mps_to_sectors.
        units => 1u64
            .checked_shl(u32::from(units) + 12)
            .filter(|bytes| *bytes >> 9 <= u64::from(u32::MAX))
            .unwrap_or(u64::from(u32::MAX) << 9),
    };
    Features {
        write_cache,
        fua: write_cache,
        max_transfer: transfer.data,
        discard: (commands & COMMANDS_DATASET_MANAGEMENT != 0).then_some(
            if deallocate != 0 && deallocate <= sectors {
                deallocate
            } else {
                sectors
            },
        ),
        write_zeroes: (commands & COMMANDS_WRITE_ZEROES != 0).then_some(WriteZeroes {
            blocks: (zeroes >> block_shift).min(1 << 16),
            unmap: format.deallocate & 0x7 == 1 && format.deallocate & 1 << 3 != 0,
        }),
    }
}

/// The namespaces of one controller, and those it cannot serve.
pub struct Attached {
    pub namespaces: Vec<Namespace>,
    pub failures: Vec<(u32, BlockError)>,
}

/// A namespace's size and its in-use LBA format.
struct Format {
    blocks: u64,
    block_size: u32,
    read_only: bool,
    /// DLFEAT.
    deallocate: u8,
}

/// The format of an Identify Namespace page: none for an empty namespace,
/// and a refusal for formats this driver cannot transfer.
fn plain_format(data: &[u8], max_transfer: usize) -> Result<Option<Format>, BlockError> {
    let blocks = u64::from_le_bytes(data[NAMESPACE_SIZE].try_into().unwrap());
    if blocks == 0 {
        return Ok(None);
    }
    let flbas = data[NAMESPACE_FORMAT];
    let index = usize::from(flbas & FORMAT_LOW | (flbas & FORMAT_HIGH) >> 1);
    let descriptor = le32(data, NAMESPACE_FORMATS + 4 * index);
    let metadata = descriptor & 0xffff;
    let shift = descriptor >> 16 & 0xff;
    if metadata != 0 {
        return Err(BlockError::Unsupported("NVMe format with metadata"));
    }
    if !(9..=16).contains(&shift) || 1usize << shift > max_transfer {
        return Err(BlockError::Unsupported("NVMe logical block size"));
    }
    Ok(Some(Format {
        blocks,
        block_size: 1 << shift,
        read_only: data[NAMESPACE_ATTRIBUTES] & NAMESPACE_WRITE_PROTECTED != 0,
        deallocate: data[NAMESPACE_DEALLOCATE],
    }))
}

/// Linux's shutdown bound: the RTD3 entry latency in whole seconds, between
/// five seconds and a minute.
fn shutdown_timeout_us(rtd3_entry_us: u64) -> u64 {
    rtd3_entry_us
        .div_ceil(MICROSECONDS_PER_SECOND)
        .saturating_mul(MICROSECONDS_PER_SECOND)
        .clamp(SHUTDOWN_MINIMUM_US, SHUTDOWN_MAXIMUM_US)
}

impl Namespace {
    fn chunk_bytes(&self, controller: &Controller) -> usize {
        let block = self.identity.block_size as usize;
        controller.max_transfer / block * block
    }

    /// Linux `nvme_scan_ns` and `nvme_validate_ns` after a controller reset
    /// or namespace-change notice, once asynchronous events are acted on:
    /// a namespace no longer allocated, or whose identifiers changed, is
    /// removed; otherwise its size and format are updated. A refused
    /// Identify leaves the namespace as it was. Admin commands of its own:
    /// only while no command runs.
    fn rescan(&mut self, controller: &mut Controller) -> Result<(), BlockError> {
        controller.ready()?;
        if let Some(error) = &self.removed {
            return Err(error.clone());
        }
        controller.service_events()?;
        if self.scanned == controller.scans {
            return Ok(());
        }
        let scans = controller.scans;
        let Some((mut ids, independent)) = controller.namespace_ids(self.namespace)? else {
            self.scanned = scans;
            return Ok(());
        };
        let (version, max_transfer, max_command_bytes) = (
            controller.version,
            controller.max_transfer,
            controller.max_command_bytes,
        );
        let (commands, limits) = (controller.commands, controller.limits);
        let data = match controller.identify(IDENTIFY_NAMESPACE, self.namespace) {
            Ok(data) => data,
            Err(BlockError::Device { .. }) => {
                self.scanned = scans;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if !independent {
            ids.fill(version, data);
        }
        let allocated = data[NAMESPACE_CAPACITY] != [0; 8];
        let format = plain_format(data, max_transfer);
        self.scanned = scans;
        match format {
            Ok(Some(format)) if allocated && ids == self.ids => {
                self.identity.blocks = format.blocks;
                self.identity.block_size = format.block_size;
                self.identity.read_only = format.read_only;
                let write_cache = self.identity.features.write_cache;
                self.identity.features = features(
                    write_cache,
                    commands,
                    limits,
                    &format,
                    TransferLimits {
                        data: max_transfer,
                        command: max_command_bytes,
                    },
                );
                Ok(())
            }
            Err(error) if allocated && ids == self.ids => {
                // nvme_update_ns_info hides a namespace it cannot use.
                self.removed = Some(error.clone());
                Err(error)
            }
            _ => {
                self.removed = Some(NAMESPACE_REMOVED);
                Err(NAMESPACE_REMOVED)
            }
        }
    }

    /// Run `command` alone once rescanned, waiting for it.
    fn command(&mut self, command: Command) -> Finished {
        let controller = self.controller.clone();
        let mut controller = controller.borrow_mut();
        self.rescan(&mut controller)?;
        let command = command.within(&self.identity, 0)?;
        let block = self.identity.block_size as usize;
        controller.run(self.namespace, block, command)
    }

    fn write_with(&mut self, lba: u64, data: &[u8], fua: bool) -> Result<(), BlockError> {
        let block = self.identity.block_size as usize;
        let chunk = self.chunk_bytes(&self.controller.borrow());
        for (index, part) in data.chunks(chunk).enumerate() {
            let lba = lba + (index * chunk / block) as u64;
            let data = part.to_vec();
            self.command(Command::Write { lba, data, fua })?;
        }
        Ok(())
    }
}

impl BlockDevice for Namespace {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        let block = self.identity.block_size as usize;
        let chunk = self.chunk_bytes(&self.controller.borrow());
        for (index, part) in buffer.chunks_mut(chunk).enumerate() {
            let lba = lba + (index * chunk / block) as u64;
            let bytes = part.len();
            let data = self.command(Command::Read { lba, bytes })?;
            part.copy_from_slice(&data.unwrap_or_default()[..bytes]);
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.write_with(lba, data, false)
    }

    fn write_fua(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.write_with(lba, data, true)
    }

    fn flush_cache(&mut self) -> Result<(), BlockError> {
        self.command(Command::Flush).map(drop)
    }

    fn discard(&mut self, lba: u64, blocks: u64) -> Result<(), BlockError> {
        self.command(Command::Discard { lba, blocks }).map(drop)
    }

    fn write_zeroes(&mut self, lba: u64, blocks: u64, unmap: bool) -> Result<(), BlockError> {
        self.command(Command::WriteZeroes { lba, blocks, unmap })
            .map(drop)
    }

    /// One transfer runs as it is, a read handing back its bounce copy.
    fn execute(&mut self, command: Command) -> Finished {
        let chunk = self.chunk_bytes(&self.controller.borrow());
        match command {
            Command::Read { lba, bytes } if bytes > chunk => {
                let mut data = alloc::vec![0; bytes];
                self.read(lba, &mut data).map(|()| Some(data))
            }
            Command::Write { lba, data, fua } if data.len() > chunk => {
                self.write_with(lba, &data, fua).map(|()| None)
            }
            command => self.command(command),
        }
    }

    /// The controller's tags, shared by its namespaces: [`Self::finish`]
    /// looks for completions in memory, never at a register, until a
    /// command's timeout.
    fn depth(&self) -> usize {
        self.controller.borrow().tags.len()
    }

    fn room(&self) -> bool {
        self.removed.is_some() || self.controller.borrow().room()
    }

    /// Asynchronous events and rescans run admin commands, which wait: only
    /// while no command runs, as Linux's work items run between requests.
    fn start(&mut self, command: Command) -> Result<u32, BlockError> {
        let controller = self.controller.clone();
        let mut controller = controller.borrow_mut();
        if !controller.busy() {
            self.rescan(&mut controller)?;
        } else if let Some(error) = &self.removed {
            return Err(error.clone());
        }
        let command = command.within(&self.identity, 0)?;
        let block = self.identity.block_size as usize;
        controller.start(self.namespace, block, command)
    }

    fn finish(&mut self, tag: u32) -> Option<Finished> {
        self.controller.borrow_mut().finish(tag as usize)
    }

    fn posted(&self) -> bool {
        self.controller.borrow().posted_completion()
    }

    fn signals(&self) -> bool {
        self.controller.borrow().signalled
    }

    /// Flush, then shut the controller down once for all its namespaces.
    fn shutdown(&mut self, _power_off: bool) -> Result<(), BlockError> {
        if !self.controller.borrow().shut_down {
            self.flush()?;
        }
        self.controller.borrow_mut().shutdown()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::{dma::RegionAllocator, mmio::Mmio};
    use alloc::boxed::Box;

    struct Fixture {
        disk: Namespace,
        // The real driver uses volatile MMIO/DMA accesses to these owned,
        // stable allocations. This fixture advances completions explicitly;
        // it is not a physical NVMe model or a reset qualification.
        _registers: Box<[u64]>,
        _memory: Vec<u64>,
    }

    impl Fixture {
        fn new() -> Self {
            let mut registers = vec![0u64; 1024].into_boxed_slice();
            let mut memory = vec![0u64; 65536];
            let start = memory.as_mut_ptr() as u64;
            // SAFETY: this fixture owns both stable allocations until after
            // all controller operations; no actual device accesses them.
            let (mmio, mut dma) = unsafe {
                (
                    Mmio::new(registers.as_mut_ptr() as u64),
                    RegionAllocator::new(start..start + (memory.len() * 8) as u64),
                )
            };
            let slots = (1..DEPTH)
                .map(|_| Slot {
                    bounce: Buffer::Legacy(dma.allocate(PAGE, PAGE).unwrap()),
                    prp_list: Buffer::Legacy(dma.allocate(PAGE, PAGE).unwrap()),
                })
                .collect();
            let controller = Controller {
                registers: RegisterIo::Legacy(mmio),
                doorbell_stride: 4,
                admin: Queue::new(0, ADMIN_ENTRIES, &mut dma).unwrap(),
                io: Queue::new(1, IO_ENTRIES, &mut dma).unwrap(),
                bounce: Buffer::Legacy(dma.allocate(BOUNCE_BYTES, PAGE).unwrap()),
                prp_list: Buffer::Legacy(dma.allocate(PAGE, PAGE).unwrap()),
                slots,
                tags: (0..DEPTH).map(|_| Tag::Free).collect(),
                recovery: None,
                signalled: false,
                max_transfer: BOUNCE_BYTES,
                max_command_bytes: MAX_COMMAND_BYTES,
                shutdown_timeout_us: 1000,
                shut_down: false,
                command_id: 0,
                // Exercise a real finite deadline with a short captured test
                // policy; native attachment retains its thirty-second policy.
                clock: Clock {
                    ticks_per_microsecond: 1000,
                },
                command_timeout_us: 1000,
                admin_timeout_us: 1000,
                fault: None,
                owned: None,
                teardown: owned::Teardown::Unprepared,
                ready_timeout_us: 500_000,
                configuration: CONFIGURATION_VALUE & !ENABLE,
                independent_identify: false,
                version: 0,
                commands: 0,
                scans: 0,
                retry_delays: [0; 3],
                host_memory: None,
                host_memory_enabled: false,
                events: Events::default(),
                aborts: Vec::new(),
                limits: Limits::default(),
            };
            Self {
                _registers: registers,
                _memory: memory,
                disk: Namespace {
                    controller: Rc::new(RefCell::new(controller)),
                    namespace: 1,
                    ids: Ids::default(),
                    scanned: 0,
                    removed: None,
                    identity: Identity {
                        transport: Transport::Nvme,
                        location: "fixture".into(),
                        model: "fixture".into(),
                        serial: "fixture".into(),
                        blocks: 1024,
                        block_size: 512,
                        read_only: false,
                        features: Features {
                            write_cache: true,
                            fua: true,
                            max_transfer: BOUNCE_BYTES,
                            ..Features::default()
                        },
                    },
                },
            }
        }
    }

    #[test]
    fn a_timeout_aborts_then_a_controller_that_stays_down_poisons_its_siblings() {
        let _clock = crate::test_clock::virtualize();
        let mut fixture = Fixture::new();
        fixture.disk.controller.borrow_mut().clock = Clock {
            ticks_per_microsecond: 1,
        };
        // Nothing answers: the write times out, its abort goes unanswered,
        // and the controller never reports ready again after its reset.
        assert_eq!(
            fixture.disk.write(0, &[0x31; 512]),
            Err(BlockError::Timeout)
        );
        let mut sibling = Namespace {
            controller: fixture.disk.controller.clone(),
            namespace: 2,
            identity: fixture.disk.identity.clone(),
            ids: Ids::default(),
            scanned: 0,
            removed: None,
        };
        {
            let c = fixture.disk.controller.borrow();
            // The abort names the write's command and queue.
            let abort = &c.admin.submissions.bytes()[..64];
            assert_eq!(abort[0], ADMIN_ABORT);
            assert_eq!(
                u32::from_le_bytes(abort[40..44].try_into().unwrap()),
                1 << 16 | 1
            );
            // The reset re-enabled the controller with the admin queue.
            assert_eq!(
                c.registers.read32(CONFIGURATION).unwrap(),
                CONFIGURATION_VALUE
            );
            assert_eq!(c.fault, Some(BlockError::Timeout));
            assert_eq!(c.command_id, 2);
        }
        let mut output = vec![0x55; 512];
        assert_eq!(sibling.read(0, &mut output), Err(BlockError::Timeout));
        assert!(output.iter().all(|byte| *byte == 0x55));
        assert_eq!(sibling.flush(), Err(BlockError::Timeout));
        assert_eq!(fixture.disk.controller.borrow().command_id, 2);
    }

    #[test]
    fn unrelated_or_malformed_completions_do_not_retire_our_command() {
        for (cid, sqid, head) in [
            (2u32, 1u32, 1u32),
            (1, 2, 1),
            (1, 1, 16),
            (1, 1, 0),
            (1, 1, 2),
        ] {
            let mut fixture = Fixture::new();
            {
                let mut c = fixture.disk.controller.borrow_mut();
                c.io.completions.write(8, sqid << 16 | head);
                c.io.completions.write(12, 1u32 << 16 | cid);
            }
            let error = BlockError::Device { status: 0xffff };
            assert_eq!(fixture.disk.flush(), Err(error.clone()));
            assert_eq!(fixture.disk.write(0, &[0x71; 512]), Err(error));
            let c = fixture.disk.controller.borrow();
            assert_eq!(c.io.head, 0);
            assert_eq!(c.registers.read32(DOORBELLS + 12).unwrap(), 0);
            assert!(c.bounce.bytes().iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn sq_head_validation_preserves_wrap_and_rejects_stale_or_ahead_heads() {
        let stale = u32::from(IO_ENTRIES - 1);
        for invalid_head in [None, Some(stale), Some(1)] {
            let mut fixture = Fixture::new();
            for next in 1..IO_ENTRIES {
                {
                    let mut c = fixture.disk.controller.borrow_mut();
                    let offset = usize::from(next - 1) * 16;
                    c.io.completions
                        .write(offset + 8, 1u32 << 16 | u32::from(next));
                    c.io.completions
                        .write(offset + 12, 1u32 << 16 | u32::from(next));
                }
                fixture.disk.flush().unwrap();
            }
            {
                let mut c = fixture.disk.controller.borrow_mut();
                let last = usize::from(IO_ENTRIES - 1) * 16;
                c.io.completions
                    .write(last + 8, 1u32 << 16 | invalid_head.unwrap_or(0));
                c.io.completions
                    .write(last + 12, 1u32 << 16 | u32::from(IO_ENTRIES));
            }
            let result = fixture.disk.flush();
            let mut c = fixture.disk.controller.borrow_mut();
            assert_eq!(c.io.tail, 0);
            match invalid_head {
                Some(_) => {
                    assert_eq!(result, Err(BlockError::Device { status: 0xffff }));
                    assert_eq!(c.io.head, IO_ENTRIES - 1);
                    assert!(c.io.phase);
                }
                None => {
                    assert_eq!(result, Ok(()));
                    assert_eq!(c.io.head, 0);
                    assert!(!c.io.phase);
                    c.io.completions.write(8, 1u32 << 16 | 1);
                    c.io.completions.write(12, u32::from(IO_ENTRIES) + 1); // New phase is zero.
                    drop(c);
                    fixture.disk.flush().unwrap();
                }
            }
        }
    }

    #[test]
    fn completed_command_error_is_distinct_from_unresolved_dma() {
        let mut fixture = Fixture::new();
        {
            let mut c = fixture.disk.controller.borrow_mut();
            c.io.completions.write(8, 1u32 << 16 | 1);
            // Invalid Field, with Do Not Retry.
            c.io.completions
                .write(12, (STATUS_DO_NOT_RETRY | 2) << 17 | 1 << 16 | 1);
        }
        assert_eq!(
            fixture.disk.flush(),
            Err(BlockError::Device {
                status: STATUS_DO_NOT_RETRY | 2
            })
        );
        {
            let mut c = fixture.disk.controller.borrow_mut();
            assert!(c.fault.is_none());
            assert_eq!(c.io.head, 1);
            c.io.completions.write(16 + 8, 1u32 << 16 | 2);
            c.io.completions.write(16 + 12, 1u32 << 16 | 2);
        }
        assert_eq!(fixture.disk.flush(), Ok(()));
        assert_eq!(fixture.disk.controller.borrow().io.head, 2);
    }

    #[test]
    fn a_fatal_controller_is_reset_first_and_poisons_when_it_stays_fatal() {
        let mut fixture = Fixture::new();
        fixture
            .disk
            .controller
            .borrow()
            .registers
            .write32(STATUS, FATAL)
            .unwrap();
        let error = BlockError::Device { status: FATAL };
        assert_eq!(fixture.disk.write(0, &[0xa9; 512]), Err(error.clone()));
        fixture
            .disk
            .controller
            .borrow()
            .registers
            .write32(STATUS, 0)
            .unwrap();
        assert_eq!(fixture.disk.flush(), Err(error));
        let c = fixture.disk.controller.borrow();
        // Nothing was submitted to the fatal controller, whose reset found
        // it fatal again.
        assert_eq!(
            c.registers.read32(CONFIGURATION).unwrap(),
            CONFIGURATION_VALUE
        );
        assert_eq!((c.command_id, c.io.tail, c.io.head), (0, 0, 0));
        assert!(c.io.submissions.bytes().iter().all(|byte| *byte == 0));
        assert!(c.bounce.bytes().iter().all(|byte| *byte == 0));
        assert_eq!(c.registers.read32(DOORBELLS + 8).unwrap(), 0);
    }

    fn namespace(blocks: u64, flbas: u8, formats: &[(usize, u32)], attributes: u8) -> Vec<u8> {
        let mut page = vec![0u8; PAGE];
        page[NAMESPACE_SIZE].copy_from_slice(&blocks.to_le_bytes());
        page[NAMESPACE_FORMAT] = flbas;
        page[NAMESPACE_ATTRIBUTES] = attributes;
        for &(index, descriptor) in formats {
            page[NAMESPACE_FORMATS + 4 * index..][..4].copy_from_slice(&descriptor.to_le_bytes());
        }
        page
    }

    #[test]
    fn namespace_formats_use_both_flbas_index_fields_and_write_protection() {
        // Format 17 (index bits 0001 and 01) holds 4 KiB blocks.
        let page = namespace(64, 1 | 1 << 5, &[(17, 12 << 16)], NAMESPACE_WRITE_PROTECTED);
        let format = plain_format(&page, BOUNCE_BYTES).unwrap().unwrap();
        assert_eq!((format.blocks, format.block_size), (64, 4096));
        assert!(format.read_only);
        assert!(
            plain_format(&namespace(0, 0, &[], 0), BOUNCE_BYTES)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            plain_format(&namespace(8, 0, &[(0, 8 | 9 << 16)], 0), BOUNCE_BYTES).err(),
            Some(BlockError::Unsupported("NVMe format with metadata"))
        );
        // A 64 KiB block cannot fit an 8 KiB maximum transfer.
        assert_eq!(
            plain_format(&namespace(8, 0, &[(0, 16 << 16)], 0), 2 * PAGE).err(),
            Some(BlockError::Unsupported("NVMe logical block size"))
        );
    }

    #[test]
    fn shutdown_waits_follow_the_rtd3_entry_latency_within_linux_bounds() {
        assert_eq!(shutdown_timeout_us(0), SHUTDOWN_MINIMUM_US);
        assert_eq!(shutdown_timeout_us(8_000_001), 9 * MICROSECONDS_PER_SECOND);
        assert_eq!(shutdown_timeout_us(u64::MAX), SHUTDOWN_MAXIMUM_US);
    }

    /// Post, at the I/O queue's head, the completion of the command `id`,
    /// with every submission up to the tail consumed.
    fn post(controller: &mut Controller, id: u16, status: u32) {
        let entry = usize::from(controller.io.head) * 16;
        let tail = u32::from(controller.io.tail);
        let phase = u32::from(controller.io.phase) << 16;
        controller
            .io
            .completions
            .write(entry + 8, 1u32 << 16 | tail);
        controller
            .io
            .completions
            .write(entry + 12, status << 17 | phase | u32::from(id));
    }

    /// Post, at the admin queue's head, the completion of the command `id`.
    fn post_admin(controller: &mut Controller, id: u16, status: u32) {
        let entry = usize::from(controller.admin.head) * 16;
        let tail = u32::from(controller.admin.tail);
        let phase = u32::from(controller.admin.phase) << 16;
        controller.admin.completions.write(entry + 8, tail);
        controller
            .admin
            .completions
            .write(entry + 12, status << 17 | phase | u32::from(id));
    }

    fn running_id(controller: &Controller, tag: u32) -> u16 {
        match controller.tags[tag as usize] {
            Tag::Running { id, .. } => id,
            _ => panic!("tag {tag} runs nothing"),
        }
    }

    #[test]
    fn queued_commands_run_together_and_complete_in_any_order() {
        let mut fixture = Fixture::new();
        let disk = &mut fixture.disk;
        assert_eq!(disk.depth(), DEPTH);
        let read = disk.start(Command::Read { lba: 0, bytes: 512 }).unwrap();
        let write = disk
            .start(Command::Write {
                lba: 1,
                data: vec![7; 512],
                fua: true,
            })
            .unwrap();
        assert_ne!(read, write);
        assert_eq!(
            disk.controller.borrow().io.tail,
            2,
            "both submitted at once"
        );
        assert_eq!(disk.finish(read), None, "not complete yet");
        {
            let mut controller = disk.controller.borrow_mut();
            // The write carries Force Unit Access.
            let words = controller.io.submissions.bytes()[64 + 48..64 + 52].to_vec();
            assert_eq!(
                u32::from_le_bytes(words.try_into().unwrap()),
                FORCE_UNIT_ACCESS
            );
            // The write completes first.
            let id = running_id(&controller, write);
            post(&mut controller, id, 0);
        }
        assert_eq!(disk.finish(write), Some(Ok(None)));
        assert_eq!(disk.finish(read), None);
        {
            let mut controller = disk.controller.borrow_mut();
            let tag = read as usize;
            controller.slot(tag).0.bytes_mut()[..512].fill(0x42);
            let id = running_id(&controller, read);
            post(&mut controller, id, 0);
        }
        assert_eq!(disk.finish(read), Some(Ok(Some(vec![0x42; 512]))));
        assert_eq!(disk.controller.borrow().io.head, 2);
        // Every tag in use leaves no room.
        for _ in 0..DEPTH {
            disk.start(Command::Flush).unwrap();
        }
        assert!(!disk.room());
        assert!(disk.start(Command::Flush).is_err());
    }

    #[test]
    fn delayed_read_completes_after_submission_ring_wraps() {
        let _clock = crate::test_clock::virtualize();
        for turns in [1, 2] {
            let mut fixture = Fixture::new();
            let disk = &mut fixture.disk;
            let delayed = disk.start(Command::Read { lba: 0, bytes: 512 }).unwrap();
            let delayed_id = running_id(&disk.controller.borrow(), delayed);
            for _ in 1..usize::from(IO_ENTRIES) * turns {
                let read = disk.start(Command::Read { lba: 1, bytes: 512 }).unwrap();
                {
                    let mut controller = disk.controller.borrow_mut();
                    controller.slot(read as usize).0.bytes_mut()[..512].fill(0x71);
                    let id = running_id(&controller, read);
                    post(&mut controller, id, 0);
                }
                assert_eq!(disk.finish(read), Some(Ok(Some(vec![0x71; 512]))));
                assert_eq!(disk.finish(delayed), None);
            }
            {
                let mut controller = disk.controller.borrow_mut();
                assert_eq!(controller.io.tail, 0);
                assert_eq!(controller.io.consumed, 0);
                controller.slot(delayed as usize).0.bytes_mut()[..512].fill(0x42);
                post(&mut controller, delayed_id, 0);
            }
            assert_eq!(disk.finish(delayed), Some(Ok(Some(vec![0x42; 512]))));
            assert!(disk.controller.borrow().fault.is_none());
        }
    }

    #[test]
    fn reused_tag_requires_its_new_submission_to_be_fetched() {
        let _clock = crate::test_clock::virtualize();
        let mut fixture = Fixture::new();
        let disk = &mut fixture.disk;
        let first = disk.start(Command::Read { lba: 0, bytes: 512 }).unwrap();
        {
            let mut controller = disk.controller.borrow_mut();
            let id = running_id(&controller, first);
            post(&mut controller, id, 0);
        }
        assert!(disk.finish(first).unwrap().is_ok());
        let second = disk.start(Command::Read { lba: 1, bytes: 512 }).unwrap();
        assert_eq!(first, second);
        {
            let mut controller = disk.controller.borrow_mut();
            let id = running_id(&controller, second);
            let entry = usize::from(controller.io.head) * 16;
            let consumed = u32::from(controller.io.consumed);
            let phase = u32::from(controller.io.phase) << 16;
            controller
                .io
                .completions
                .write(entry + 8, 1u32 << 16 | consumed);
            controller
                .io
                .completions
                .write(entry + 12, phase | u32::from(id));
        }
        assert_eq!(
            disk.finish(second),
            Some(Err(BlockError::Device { status: 0xffff }))
        );
        assert_eq!(disk.controller.borrow().io.head, 1);
    }

    #[test]
    fn deallocate_and_write_zeroes_carry_their_ranges() {
        let mut fixture = Fixture::new();
        let disk = &mut fixture.disk;
        let discard = disk.start(Command::Discard { lba: 9, blocks: 3 }).unwrap();
        let zeroes = disk
            .start(Command::WriteZeroes {
                lba: 20,
                blocks: 4,
                unmap: true,
            })
            .unwrap();
        let mut controller = disk.controller.borrow_mut();
        let word = |controller: &Controller, entry: usize, index: usize| {
            let bytes = &controller.io.submissions.bytes()[entry * 64 + 4 * index..][..4];
            u32::from_le_bytes(bytes.try_into().unwrap())
        };
        assert_eq!(
            word(&controller, 0, 0) & 0xff,
            u32::from(IO_DATASET_MANAGEMENT)
        );
        assert_eq!(word(&controller, 0, 11), ATTRIBUTE_DEALLOCATE);
        let range = controller.slot(discard as usize).0.bytes()[..16].to_vec();
        assert_eq!(range[4..8], 3u32.to_le_bytes());
        assert_eq!(range[8..16], 9u64.to_le_bytes());
        assert_eq!(word(&controller, 1, 0) & 0xff, u32::from(IO_WRITE_ZEROES));
        assert_eq!(word(&controller, 1, 10), 20);
        assert_eq!(word(&controller, 1, 12), 3 | DEALLOCATE);
        let _ = zeroes;
    }

    #[test]
    fn a_command_past_its_deadline_is_aborted_then_resets_the_controller_and_runs_again() {
        let _clock = crate::test_clock::virtualize();
        let mut fixture = Fixture::new();
        let disk = &mut fixture.disk;
        let read = disk.start(Command::Read { lba: 0, bytes: 512 }).unwrap();
        let read_id = running_id(&disk.controller.borrow(), read);
        let wait = |disk: &mut Namespace| {
            let clock = disk.controller.borrow().clock;
            let started = clock.try_start().unwrap();
            while clock.try_elapsed_us(started).unwrap() < 1000 {
                core::hint::spin_loop();
            }
        };
        // The deadline passes: the read is aborted and given another.
        wait(disk);
        assert_eq!(disk.finish(read), None);
        {
            let mut controller = disk.controller.borrow_mut();
            let abort = &controller.admin.submissions.bytes()[..64];
            assert_eq!(abort[0], ADMIN_ABORT);
            assert_eq!(abort[40..44], (u32::from(read_id) << 16 | 1).to_le_bytes());
            // The controller reports it not aborted.
            let id = controller.aborts[0];
            post_admin(&mut controller, id, 0);
        }
        assert_eq!(disk.finish(read), None);
        assert!(disk.controller.borrow().aborts.is_empty());
        // The second deadline passes: the controller, not ready, is disabled.
        wait(disk);
        assert_eq!(disk.finish(read), None);
        {
            let controller = disk.controller.borrow();
            assert!(matches!(controller.recovery, Some(Recovery::Disabling(_))));
            assert_eq!(controller.registers.read32(CONFIGURATION).unwrap(), 0);
            assert!(!disk.room());
        }
        // CSTS.RDY is clear: it is enabled again.
        assert_eq!(disk.finish(read), None);
        {
            let controller = disk.controller.borrow();
            assert!(matches!(controller.recovery, Some(Recovery::Enabling(_))));
            controller.registers.write32(STATUS, READY).unwrap();
        }
        // Ready: identified, then the I/O queues created again, completion
        // queue first.
        for opcode in [
            ADMIN_IDENTIFY,
            ADMIN_CREATE_COMPLETION,
            ADMIN_CREATE_SUBMISSION,
        ] {
            assert_eq!(disk.finish(read), None);
            let mut controller = disk.controller.borrow_mut();
            let Some(Recovery::Admin { id, .. }) = controller.recovery else {
                panic!("no bring-up command");
            };
            let offset = usize::from(controller.admin.tail - 1) * 64;
            assert_eq!(controller.admin.submissions.bytes()[offset], opcode);
            post_admin(&mut controller, id, 0);
        }
        // The interrupted read runs again on the empty queue.
        assert_eq!(disk.finish(read), None);
        let mut controller = disk.controller.borrow_mut();
        assert!(controller.recovery.is_none());
        assert_eq!(controller.scans, 1);
        assert_eq!((controller.io.tail, controller.io.head), (1, 0));
        let id = running_id(&controller, read);
        controller.bounce.bytes_mut()[..512].fill(0x5a);
        post(&mut controller, id, 0);
        drop(controller);
        assert_eq!(disk.finish(read), Some(Ok(Some(vec![0x5a; 512]))));
    }

    #[test]
    fn errors_without_do_not_retry_run_again_after_their_retry_delay() {
        let _clock = crate::test_clock::virtualize();
        let mut fixture = Fixture::new();
        let disk = &mut fixture.disk;
        disk.controller.borrow_mut().clock = Clock {
            ticks_per_microsecond: 1,
        };
        disk.controller.borrow_mut().retry_delays = [1, 0, 0];
        let flush = disk.start(Command::Flush).unwrap();
        {
            let mut controller = disk.controller.borrow_mut();
            let id = running_id(&controller, flush);
            // Namespace Not Ready with CRD 1: 100 ms.
            post(&mut controller, id, 0x82 | 1 << 11);
        }
        assert_eq!(disk.finish(flush), None);
        assert!(matches!(
            disk.controller.borrow().tags[flush as usize],
            Tag::Delayed { retries: 1, .. }
        ));
        let clock = disk.controller.borrow().clock;
        let started = clock.try_start().unwrap();
        while disk.controller.borrow().io.tail == 1 {
            assert_eq!(disk.finish(flush), None);
        }
        assert!(clock.try_elapsed_us(started).unwrap() >= 100_000);
        {
            let mut controller = disk.controller.borrow_mut();
            let id = running_id(&controller, flush);
            post(&mut controller, id, 0);
        }
        assert_eq!(disk.finish(flush), Some(Ok(None)));
    }

    /// Each state idles into the deepest usable non-operational state below
    /// it, one per latency tolerance, as Linux `nvme_configure_apst`.
    #[test]
    fn apst_follows_linux_tolerances_from_the_deepest_state_up() {
        let mut identify = vec![0u8; PAGE];
        assert_eq!(apst_table(&identify), None, "no APST support");
        identify[CONTROLLER_APST] = 1;
        identify[CONTROLLER_POWER_STATES] = 5;
        // (state, entry us, exit us): PS5's exit is past the latency limit.
        for (state, entry, exit) in [
            (2, 500, 500),
            (3, 2_000, 2_000),
            (4, 4_000, 30_000),
            (5, 0, 200_000),
        ] {
            let descriptor = &mut identify[CONTROLLER_POWER_DESCRIPTORS + 32 * state..][..32];
            descriptor[3] = POWER_NON_OPERATIONAL;
            descriptor[4..8].copy_from_slice(&u32::to_le_bytes(entry));
            descriptor[8..12].copy_from_slice(&u32::to_le_bytes(exit));
        }
        let table = apst_table(&identify).unwrap();
        let primary = 3 << 3 | APST_PRIMARY_TIMEOUT_MS << 8;
        let secondary = 4 << 3 | APST_SECONDARY_TIMEOUT_MS << 8;
        assert_eq!(table[..6], [primary, primary, primary, secondary, 0, 0]);
        assert!(table[6..].iter().all(|&entry| entry == 0));
    }

    /// A signalled controller's I/O completion queue raises vector 0, and
    /// a posted completion shows in memory before the namespace takes it.
    #[test]
    fn completions_are_signalled_and_posted_in_memory() {
        let mut fixture = Fixture::new();
        let disk = &mut fixture.disk;
        assert_eq!(disk.controller.borrow().create_queue(false).unwrap()[11], 1);
        disk.controller.borrow_mut().signalled = true;
        assert!(disk.signals());
        assert_eq!(
            disk.controller.borrow().create_queue(false).unwrap()[11],
            0b11
        );
        assert!(!disk.posted(), "nothing runs");
        let read = disk.start(Command::Read { lba: 0, bytes: 512 }).unwrap();
        assert!(!disk.posted());
        {
            let mut controller = disk.controller.borrow_mut();
            let id = running_id(&controller, read);
            post(&mut controller, id, 0);
        }
        assert!(disk.posted());
        assert!(disk.finish(read).is_some());
        assert!(!disk.posted());
    }

    #[test]
    fn a_removed_controller_fails_its_commands_without_a_reset() {
        let mut fixture = Fixture::new();
        let disk = &mut fixture.disk;
        let read = disk.start(Command::Read { lba: 0, bytes: 512 }).unwrap();
        disk.controller
            .borrow()
            .registers
            .write32(STATUS, REMOVED)
            .unwrap();
        disk.controller.borrow_mut().reset();
        assert_eq!(disk.finish(read), Some(Err(removed())));
        assert!(disk.controller.borrow().recovery.is_none());
        assert_eq!(disk.read(0, &mut [0; 512]), Err(removed()));
    }

    #[test]
    fn only_a_controller_with_a_volatile_write_cache_is_sent_flushes() {
        let mut fixture = Fixture::new();
        fixture.disk.identity.features.write_cache = false;
        assert_eq!(fixture.disk.flush(), Ok(()));
        assert_eq!(fixture.disk.controller.borrow().io.tail, 0);
        // With a cache the flush is submitted; this fixture never completes
        // it, nor its abort.
        fixture.disk.identity.features.write_cache = true;
        assert_eq!(fixture.disk.flush(), Err(BlockError::Timeout));
        let controller = fixture.disk.controller.borrow();
        assert_eq!(controller.io.submissions.bytes()[0], IO_FLUSH);
        assert_eq!(controller.admin.submissions.bytes()[0], ADMIN_ABORT);
    }

    #[test]
    fn identification_descriptors_parse_like_nvme_identify_ns_descs() {
        let mut page = vec![0u8; PAGE];
        let mut at = 0;
        for (kind, value) in [
            (DESCRIPTOR_EUI64, &[1u8; 8][..]),
            (9, &[7; 5][..]),
            (DESCRIPTOR_UUID, &[3; 16][..]),
            (DESCRIPTOR_CSI, &[2][..]),
        ] {
            page[at] = kind;
            page[at + 1] = value.len() as u8;
            page[at + 4..at + 4 + value.len()].copy_from_slice(value);
            at += 4 + value.len();
        }
        let ids = Ids::from_descriptors(&page);
        assert_eq!(
            ids,
            Ids {
                eui64: [1; 8],
                nguid: [0; 16],
                uuid: [3; 16],
                csi: 2
            }
        );
        // A wrong length ends the list; Identify Namespace then fills EUI64
        // from 1.1 and NGUID from 1.2.
        page[1] = 9;
        let mut ids = Ids::from_descriptors(&page);
        assert_eq!(ids, Ids::default());
        let mut data = vec![0u8; PAGE];
        data[NAMESPACE_EUI64].fill(5);
        data[NAMESPACE_NGUID].fill(6);
        ids.fill(VERSION_1_1, &data);
        assert_eq!((ids.eui64, ids.nguid), ([5; 8], [0; 16]));
        ids.fill(VERSION_1_2, &data);
        assert_eq!(ids.nguid, [6; 16]);
    }

    #[test]
    fn a_controller_shuts_down_once_and_then_refuses_commands() {
        let fixture = Fixture::new();
        let mut controller = fixture.disk.controller.borrow_mut();
        controller
            .registers
            .write32(CONFIGURATION, CONFIGURATION_VALUE)
            .unwrap();
        controller
            .registers
            .write32(STATUS, READY | SHUTDOWN_COMPLETE)
            .unwrap();
        // The I/O submission queue's deletion is refused (Invalid Queue
        // Identifier); its completion queue's succeeds.
        let completion = |c: &mut Controller, slot: usize, id: u32, status: u32| {
            c.admin.completions.write(16 * slot + 8, id);
            c.admin
                .completions
                .write(16 * slot + 12, status << 17 | 1 << 16 | id);
        };
        completion(&mut controller, 0, 1, 1);
        completion(&mut controller, 1, 2, 0);
        controller.shutdown().unwrap();
        let submitted = controller.admin.submissions.bytes();
        for (slot, opcode) in [(0, ADMIN_DELETE_SUBMISSION), (1, ADMIN_DELETE_COMPLETION)] {
            let entry = &submitted[64 * slot..64 * slot + 64];
            assert_eq!(entry[0], opcode);
            assert_eq!(u32::from_le_bytes(entry[40..44].try_into().unwrap()), 1);
        }
        assert_eq!(
            controller.registers.read32(CONFIGURATION).unwrap(),
            CONFIGURATION_VALUE | SHUTDOWN_NORMAL
        );
        controller.registers.write32(CONFIGURATION, 0).unwrap();
        controller.shutdown().unwrap();
        assert_eq!(controller.registers.read32(CONFIGURATION).unwrap(), 0);
        assert_eq!(
            controller.ready(),
            Err(BlockError::Unsupported("NVMe controller is shut down"))
        );
    }
}
