//! ANS2's AP-facing NVMe controller; no coprocessor firmware is executed.
//!
//! Evidence: Linux `drivers/nvme/host/apple.c` documents linear SQ doorbells
//! (0x2490c/0x24910), 64 shared tags, 128-byte NVMMU TCBs at bases
//! 0x28108/0x28110, invalidation/status 0x28118/0x28120, and BOOT_STATUS
//! 0x1300 = 0xde71ce55. NVMe 1.4 sections 3, 4, 5 and 6 define the base
//! registers, PRPs, admin commands, completions and NVM read/write/flush.
//! The 26A434 J473AP kernel drives an ANS2 with `nvme-linear-sq` through
//! `AppleANS3CGv2Controller` (`probe` 0x3dfa2f4), a subclass of
//! `AppleANS2CGv2Controller` (file 0x3de4954) whose `GetIOSQES`
//! (0x3de51d0) returns 6. The register accessors at 0x3ddee24..64 use ANS
//! `reg[3]`; its `nvme-interrupt-idx` selects the completion interrupt.
//! docs/research/ans2.md owns the SPTM NVMe validation matrix this
//! controller's values must satisfy, and the matrix of every register the
//! drivers reach through restore, boot, sleep, wake and shutdown.
//!
//! Stela's die choices: NVMe 1.3, one I/O queue, 64 tags, 4/16 KiB memory
//! pages, 4 KiB LBAs, 1 MiB maximum transfer, no volatile write cache, no
//! optional encryption/SHA/firmware-slot updates or asynchronous events.
//! The restore mode's boot-from-host image download is recorded, not run. Identity
//! strings identify Stela rather than impersonating a physical Apple SSD.
//! The boot stage starts RTKit before handoff. NVMe itself uses MMIO; the
//! RTKit coprocessor lists one application endpoint, [`RTKIT_ENDPOINT`],
//! which carries no messages but must exist for the driver to start.
//! Undescribed registers, commands, fields and cryptographic effects refuse.
mod bfh;
mod commands;
mod die;
mod namespace;
mod prp;

use super::{
    bus::{Access, Direction, MmioDevice, MmioError, Width, refuse},
    interrupt::{AicInput, Wire},
};
use crate::platform::{apple::sart::Sart, dma::Port, pc::block::BlockDevice};
use alloc::{boxed::Box, collections::VecDeque};
pub use bfh::BootImage;
pub use namespace::Description;
use namespace::Medium;
use prp::dma_error;

const NAME: &str = "ans2";
pub const TAGS: u16 = 64;
/// Entries one queue may hold, CAP.MQES + 1. SPTM `INIT` (0x270c79d0)
/// requires the kernel's queue entries to equal `nvme-queue-entries` (64),
/// and `AppleANS3CGv2Controller::GetNVMeSPTMQueueEntries` (0x3db9270)
/// passes `min(MQES + 1, 257) - 1` (0x3de4aa8..ae0 with its 256 pending
/// commands, 0x3db9264), so MQES is exactly 64. The kernel sizes every
/// ring with that minimum (`SetNVMeProperties` 0x3db3850, read by
/// `CreateSubmissionQueue` 0x3ddd1dc and `CreateCompletionQueue`
/// 0x3ddd648): 65-entry admin and I/O rings, while tags stay below
/// [`TAGS`] (SPTM `MAP_PAGES` 0x270c8178).
pub const QUEUE_ENTRIES: u16 = 65;
pub const REGISTER_BYTES: u64 = 0x28134;
/// Where SPTM finds the VDMA translation cache in ANS2 `reg[13]` when the
/// node carries `nvme-vdma-wa` (`nvme_bootstrap` 0x270c8cac..cdc maps the
/// bank and keeps it + 0x20000), and the cache's span: one 32-byte entry
/// per tag (`UNMAP_PAGES` 0x270c7c20..30 reads tag << 5).
pub const VDMA_CACHE_OFFSET: u64 = 0x2_0000;
pub const VDMA_CACHE_BYTES: u64 = TAGS as u64 * VDMA_ENTRY_BYTES;
/// The device offset the board maps the VDMA cache window at, past the
/// NVMe registers.
pub const VDMA_CACHE: u64 = 0x10_0000;
const VDMA_ENTRY_BYTES: u64 = 32;
const CAP: u64 = 0;
const VS: u64 = 8;
const INTMS: u64 = 0xc;
const INTMC: u64 = 0x10;
const CC: u64 = 0x14;
const CSTS: u64 = 0x1c;
const AQA: u64 = 0x24;
const ASQ: u64 = 0x28;
const ACQ: u64 = 0x30;
const ADMIN_HEAD: u64 = 0x1004;
const IO_HEAD: u64 = 0x100c;
const IO_SQ: u64 = 0x1200;
const IO_CQ: u64 = 0x1208;
const TAG_STATUS: u64 = 0x28000;
const MAX_PENDING: u64 = 0x1210;
const BOOT_STATUS: u64 = 0x1300;
const MODESEL: u64 = 0x1304;
const BASE_CID: u64 = 0x1308;
const SLEEP_NOTIFY: u64 = 0x1314;
const AUTO_QUEUE: u64 = 0x13c8;
const LINEAR: u64 = 0x24908;
const ADMIN_SUBMIT: u64 = 0x2490c;
const IO_SUBMIT: u64 = 0x24910;
const TCB_COUNT: u64 = 0x28100;
const ADMIN_TCB: u64 = 0x28108;
const IO_TCB: u64 = 0x28110;
const TCB_INVALIDATE: u64 = 0x28118;
const TCB_STATUS: u64 = 0x28120;
const ENABLE: u32 = 1;
const SHUTDOWN: u32 = 3 << 14;
/// MODESEL values `PreCCEnableHook` writes before enabling: 0 regular, 4
/// in the restore environment (`AppleANS2NVMeController::PreCCEnableHook`
/// 0x3dbdfb8: 4 when `-restore` set its boot-from-host flag, 0x3dbb6b8).
const MODE_REGULAR: u32 = 0;
const MODE_RESTORE: u32 = 4;
const CONFIG_MASK: u32 = ENABLE | (0xf << 7) | SHUTDOWN | (0xf << 16) | (0xf << 20);
const ENTRY_SIZES: u32 = (6 << 16) | (4 << 20);
const READY: u32 = 1;
const SHUTDOWN_COMPLETE: u32 = 2 << 2;
const CAPABILITIES: u64 =
    (QUEUE_ENTRIES as u64 - 1) | (1 << 16) | (1 << 24) | (1 << 37) | (2 << 52);
const VERSION: u64 = 0x0001_0300;
const BOOT_OK: u64 = 0xde71_ce55;
const COMMAND_BYTES: u64 = 64;
const COMPLETION_BYTES: u64 = 16;
const TCB_BYTES: u64 = 128;

/// ANS2's RTKit application endpoint. RTBuddy publishes it at roll call as
/// the service `ANS2Endpoint1` (`RTBuddyEndpointService::createName`
/// 0x4665818: role + "Endpoint" + endpoint - 0x1f).
/// `AppleANS2NVMeController::start` blocks until that service matches
/// (`waitForMatchingService` 0x3dbb308, before `WaitDeviceActive`), binds
/// it with no message handler (`initForOwner` 0x3dbb344) and only attaches
/// its own power-state action to it (`InitializePowerManagement`
/// 0x3dbf668), so no message crosses it in either direction.
pub const RTKIT_ENDPOINT: u8 = 0x20;

/// The coprocessor side of [`RTKIT_ENDPOINT`]: enabling it is accepted and
/// any message on it refuses.
#[derive(Debug, Default)]
pub struct Endpoint;

impl super::rtkit::Endpoint for Endpoint {
    fn start(&mut self, _outbox: &mut alloc::vec::Vec<u64>) -> Result<(), &'static str> {
        Ok(())
    }
    fn receive(
        &mut self,
        _payload: u64,
        _outbox: &mut alloc::vec::Vec<u64>,
    ) -> Result<(), &'static str> {
        Err("ANS2 RTKit endpoint 0x20 has no AP message protocol")
    }
}

#[derive(Clone, Copy, Default)]
struct Queue {
    sq: u64,
    cq: u64,
    sq_entries: u16,
    cq_entries: u16,
    head: u16,
    tail: u16,
    pending: u16,
    phase: bool,
    sq_enabled: bool,
    cq_enabled: bool,
    interrupt: bool,
}

impl Queue {
    fn acknowledge(&mut self, head: u16) -> Result<(), &'static str> {
        if !self.cq_enabled || head >= self.cq_entries {
            return Err("ANS CQ head outside an enabled queue");
        }
        let consumed = (head + self.cq_entries - self.head) % self.cq_entries;
        let consumed = if consumed == 0 && self.pending == self.cq_entries {
            self.cq_entries
        } else {
            consumed
        };
        if consumed > self.pending {
            return Err("ANS CQ head consumes completions not produced");
        }
        self.pending -= consumed;
        self.head = head;
        Ok(())
    }
}

/// Last DMA submission, retained for an explicit refusal diagnostic. This
/// never grants keys or substitutes a successful completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    pub queue: usize,
    pub tag: u16,
    pub command: [u8; 64],
    pub tcb: [u8; 128],
    /// The tunnel request the command named, once it was read.
    pub tunnel: Option<[u8; 80]>,
}

pub struct Ans {
    medium: Medium,
    config: u32,
    status: u32,
    interrupt_mask: u32,
    irq: Option<AicInput>,
    irq_level: bool,
    aqa: u32,
    queues: [Queue; 2],
    tcb_bases: [u64; 2],
    tcb_count: u16,
    valid: [bool; TAGS as usize],
    pending: VecDeque<(usize, u16)>,
    linear: bool,
    /// I/O queue attributes at 0x1210: 0's-based SQ entries in bits 15:0
    /// and CQ entries in bits 31:16, as AQA. Both writers size their rings
    /// one larger than the field: `AppleANS2CGv2Controller::SetupIOQARegister`
    /// (0x3de5a6c) passes ring entries - 1 through SPTM `IOQA` (0x270c7470),
    /// and `AppleANS2NVMeController::SetupIOQARegister` (0x3dc15d4) writes
    /// 64 for its 65-entry rings. None until programmed.
    queue_attributes: Option<u32>,
    modesel: u32,
    auto_queue: bool,
    shutdown: bool,
    /// NVMe feature state, indexed by the small standard feature IDs.
    features: [u32; 12],
    timestamp: u64,
    os_build: [u8; 16],
    /// The uncommitted boot-from-host download and the last image it
    /// committed, which survives controller resets.
    download: bfh::Download,
    boot_image: Option<BootImage>,
    last_submission: Option<Submission>,
}

impl Ans {
    pub fn new(
        backing: Box<dyn BlockDevice>,
        namespaces: &[Description],
        irq: Option<AicInput>,
    ) -> Result<Self, &'static str> {
        let medium = Medium::new(backing, namespaces)?;
        Ok(Self {
            medium,
            config: 0,
            status: 0,
            interrupt_mask: 0,
            irq,
            irq_level: false,
            aqa: 0,
            queues: [Queue::default(); 2],
            tcb_bases: [0; 2],
            tcb_count: TAGS - 1,
            valid: [false; TAGS as usize],
            pending: VecDeque::new(),
            linear: false,
            queue_attributes: None,
            modesel: 0,
            auto_queue: false,
            shutdown: false,
            features: [0; 12],
            timestamp: 0,
            os_build: [0; 16],
            download: bfh::Download::default(),
            boot_image: None,
            last_submission: None,
        })
    }

    /// The identity of the last committed boot-from-host image.
    pub fn boot_image(&self) -> Option<&BootImage> {
        self.boot_image.as_ref()
    }

    pub fn last_submission(&self) -> Option<&Submission> {
        self.last_submission.as_ref()
    }

    pub fn pending(&self) -> bool {
        self.shutdown || !self.pending.is_empty()
    }

    fn page(&self) -> u64 {
        4096 << ((self.config >> 7) & 0xf)
    }

    fn base(&self, offset: u64) -> Option<u64> {
        Some(match offset {
            ASQ => self.queues[0].sq,
            ACQ => self.queues[0].cq,
            IO_SQ => self.queues[1].sq,
            IO_CQ => self.queues[1].cq,
            ADMIN_TCB => self.tcb_bases[0],
            IO_TCB => self.tcb_bases[1],
            _ => return None,
        })
    }

    /// SPTM 26A434 VA 0xfffffff0270c7250/0x270c6fd0 programs the
    /// linear I/O queue bases; 0x270c7470 supplies the SQ/CQ entry counts.
    /// Auto management (CGv2 0x3de5ad8) activates that single queue without
    /// Create SQ/CQ commands. Existing manually created queues use the same
    /// submission, completion, bounds and interrupt machinery.
    fn refresh_auto_queue(&mut self) {
        if !self.auto_queue || self.config & ENABLE == 0 {
            return;
        }
        let Some(attributes) = self.queue_attributes else {
            return;
        };
        let sq_entries = (attributes & 0xffff) as u16 + 1;
        let cq_entries = (attributes >> 16) as u16 + 1;
        let q = &mut self.queues[1];
        if q.sq != 0 && q.cq != 0 && !q.sq_enabled && !q.cq_enabled {
            q.sq_entries = sq_entries;
            q.cq_entries = cq_entries;
            q.sq_enabled = true;
            q.cq_enabled = true;
            q.interrupt = true;
            q.phase = true;
        }
    }

    fn update_irq(&mut self, access: &mut Access<'_>) {
        let level = self.interrupt_mask & 1 == 0
            && self.queues.iter().any(|q| q.interrupt && q.pending != 0);
        if self.irq_level != level {
            self.irq_level = level;
            if let Some(irq) = self.irq {
                access.interrupts.set_level(Wire::Aic(irq), level);
            }
        }
    }

    /// The boot chain's hand-off under `/defaults nvme-iboot-sptm-security`:
    /// the boot stage has put the controller in linear submission mode, so
    /// the kernel never writes LINEAR (`AppleANS3CGv2Controller::EnableLinearSQ`
    /// 0x3db9064 returns at once with that flag) and SPTM, which also reads
    /// it, writes no linear register either.
    pub fn handed_off_linear(mut self) -> Self {
        self.linear = true;
        self
    }

    fn configure(&mut self, value: u32) -> Result<(), &'static str> {
        if value & !CONFIG_MASK != 0 {
            return Err("ANS CC fields without a model");
        }
        if value & ENABLE != 0 {
            if value & (0xff << 16) != ENTRY_SIZES || !matches!((value >> 7) & 0xf, 0 | 2) {
                return Err("ANS CC requires 64-byte SQEs, 16-byte CQEs and 4/16 KiB pages");
            }
            if self.config & ENABLE != 0 && (value ^ self.config) & !SHUTDOWN != 0 {
                return Err("ANS CC changed while enabled");
            }
            if self.config & ENABLE == 0 {
                let sq_entries = ((self.aqa & 0xfff) + 1) as u16;
                let cq_entries = (((self.aqa >> 16) & 0xfff) + 1) as u16;
                let page = 4096 << ((value >> 7) & 0xf);
                let queue = self.queues[0];
                if sq_entries > QUEUE_ENTRIES
                    || cq_entries > QUEUE_ENTRIES
                    || queue.sq == 0
                    || queue.cq == 0
                    || !queue.sq.is_multiple_of(page)
                    || !queue.cq.is_multiple_of(page)
                {
                    return Err("ANS admin queues are missing, unaligned or too deep");
                }
                self.queues[0] = Queue {
                    sq_entries,
                    cq_entries,
                    phase: true,
                    sq_enabled: true,
                    cq_enabled: true,
                    interrupt: true,
                    ..queue
                };
                self.status = READY;
            }
            // Normal (01b), abrupt (10b, `HandleAbruptShutdown` 0x3ddbb14)
            // and suspend (11b) notifications all complete once every
            // accepted command has and the backing has flushed: the die
            // keeps no volatile state that one would lose and another not.
            if value & SHUTDOWN != 0 && self.config & SHUTDOWN == 0 {
                self.shutdown = true;
            }
        } else {
            if !self.pending.is_empty() {
                return Err("ANS disable with unprocessed submissions");
            }
            self.status = 0;
            self.queues = [Queue::default(); 2];
            self.valid.fill(false);
            self.shutdown = false;
            // NVMe 1.4 section 5.11: a controller-level reset discards an
            // uncommitted image download.
            self.download = bfh::Download::default();
        }
        self.config = value;
        self.refresh_auto_queue();
        Ok(())
    }

    fn submit(&mut self, queue: usize, tag: u16) -> Result<(), &'static str> {
        if self.status != READY || self.shutdown || !self.linear || !self.queues[queue].sq_enabled {
            return Err("ANS submission requires a ready controller and an enabled linear SQ");
        }
        if tag > self.tcb_count || tag >= TAGS || self.valid[tag as usize] {
            return Err("ANS tag outside NVMMU capacity or still in use");
        }
        if self.tcb_bases[queue] == 0 {
            return Err("ANS submission without an NVMMU TCB array");
        }
        let limit = self
            .queue_attributes
            .map(|attributes| ((attributes >> (queue * 16)) & 0xffff) as usize + 1);
        if limit
            .is_some_and(|limit| self.pending.iter().filter(|&&(q, _)| q == queue).count() >= limit)
        {
            return Err("ANS pending commands exceed the programmed queue limit");
        }
        self.valid[tag as usize] = true;
        self.pending.push_back((queue, tag));
        Ok(())
    }

    /// Complete submitted commands before the next guest access. The NVMe
    /// engine reaches queues, TCBs, PRPs and data at physical addresses
    /// through `port`: the driver gives them no SART entries
    /// (`AllocateNVMeQueue` 0x3dbe804 and the request pool create their
    /// buffers without a mapper; `GetIOMappers` 0x3dbceb4). Only tunnel
    /// buffers, which the coprocessor reaches at raw addresses carried in the
    /// command (`AllocateTunnelBuffer` 0x3dbe83c), are checked against `sart`.
    /// NVMMU TCB PRPs are authoritative; their encryption and hash fields
    /// must be zero until those engines are modeled, apart from the
    /// CDW14/CDW15 copy the CG v2 driver places at TCB 0x38.
    pub fn run(&mut self, port: &mut Port<'_, '_>, sart: &mut Sart) -> Result<(), MmioError> {
        while let Some(&(queue, tag)) = self.pending.front() {
            self.last_submission = None;
            let error = |reason| {
                refuse(
                    NAME,
                    if queue == 0 { ADMIN_SUBMIT } else { IO_SUBMIT },
                    Width::Word,
                    Direction::Write,
                    reason,
                )
            };
            let q = self.queues[queue];
            if !q.cq_enabled || q.pending == q.cq_entries {
                return Err(error("ANS completion queue is full or disabled"));
            }
            let address = |base: u64, bytes| base.checked_add(bytes).ok_or("ANS DMA address wraps");
            let mut raw = [0; 64];
            port.read(
                address(q.sq, u64::from(tag) * COMMAND_BYTES).map_err(error)?,
                &mut raw,
            )
            .map_err(dma_error)
            .map_err(error)?;
            let mut command = commands::Command(raw);
            if command.cid() != tag {
                return Err(error("ANS SQ command ID differs from its linear tag"));
            }
            let mut tcb = [0; 128];
            port.read(
                address(self.tcb_bases[queue], u64::from(tag) * TCB_BYTES).map_err(error)?,
                &mut tcb,
            )
            .map_err(dma_error)
            .map_err(error)?;
            self.last_submission = Some(Submission {
                queue,
                tag,
                command: command.0,
                tcb,
                tunnel: None,
            });
            // `NVMeCoastGuardSetTCBEntry` (CG v2, 0x3de4bd8..0x3de4be4)
            // copies CDW14 and CDW15 to TCB 0x38 and 0x3c; earlier
            // submissions leave them zero. The key area from 0x40 on must
            // stay empty.
            let mirror = &tcb[56..64];
            if tcb[0] != 0 && tcb[0] != command.opcode()
                || u16::from(tcb[2]) != tag
                || tcb[3] != 0
                || mirror != [0; 8] && mirror != &command.0[56..64]
                || tcb[6..24]
                    .iter()
                    .chain(&tcb[40..56])
                    .chain(&tcb[64..])
                    .any(|&b| b != 0)
            {
                return Err(error(
                    "ANS NVMMU TCB opcode, tag, encryption or hash fields are not modeled",
                ));
            }
            let flags = tcb[1];
            command.validate().map_err(error)?;
            let direction = command.direction(queue).map_err(error)?;
            if flags & !3 != 0 || flags != direction {
                return Err(error(
                    "ANS NVMMU TCB DMA permissions disagree with the command",
                ));
            }
            if queue != 0 && matches!(command.opcode(), 1 | 2 | 5) && tcb[4..6] != command.0[48..50]
            {
                return Err(error("ANS NVMMU length differs from the command"));
            }
            command.0[24..40].copy_from_slice(&tcb[24..40]);
            let outcome = self.execute(queue, &command, port, sart).map_err(error)?;
            let mut completion = [0; 16];
            completion[..4].copy_from_slice(&outcome.result.to_le_bytes());
            // Linear SQs have no advancing head; the consumed slot is tag.
            completion[8..10].copy_from_slice(&tag.to_le_bytes());
            completion[10..12].copy_from_slice(&(queue as u16).to_le_bytes());
            completion[12..14].copy_from_slice(&command.cid().to_le_bytes());
            completion[14..]
                .copy_from_slice(&((outcome.status << 1) | u16::from(q.phase)).to_le_bytes());
            port.write(
                address(q.cq, u64::from(q.tail) * COMPLETION_BYTES).map_err(error)?,
                &completion,
            )
            .map_err(dma_error)
            .map_err(error)?;
            let q = &mut self.queues[queue];
            q.pending += 1;
            q.tail += 1;
            if q.tail == q.cq_entries {
                q.tail = 0;
                q.phase = !q.phase;
            }
            self.pending.pop_front();
            self.update_irq(port.access);
        }
        if self.shutdown {
            self.medium.device.flush().map_err(|_| {
                refuse(
                    NAME,
                    CC,
                    Width::Word,
                    Direction::Write,
                    "ANS backing flush failed during shutdown",
                )
            })?;
            self.shutdown = false;
            self.status = READY | SHUTDOWN_COMPLETE;
        }
        Ok(())
    }
}

impl MmioDevice for Ans {
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        if let Some(base) = self.base(offset & !7) {
            return match (offset % 8, width) {
                (0, Width::Double) => Ok(base),
                (0 | 4, Width::Word) => Ok((base >> ((offset % 8) * 8)) & 0xffff_ffff),
                _ => Err(refuse(
                    NAME,
                    offset,
                    width,
                    Direction::Read,
                    "ANS base register width or alignment",
                )),
            };
        }
        // Before invalidating a tag, SPTM's UNMAP_PAGES (0x270c7c18..30,
        // with nvme-vdma-wa) requires the tag's VDMA cache entry to hold no
        // DMA permissions (bits 9:8 of its first word, the TCB's direction
        // bits). The controller caches no translation once a command
        // completes, so that entry reads 0; every other word, and the entry
        // of a tag whose command is still pending, has no model.
        if (VDMA_CACHE..VDMA_CACHE + VDMA_CACHE_BYTES).contains(&offset) {
            let tag = (offset - VDMA_CACHE) / VDMA_ENTRY_BYTES;
            let pending = self.pending.iter().any(|&(_, t)| u64::from(t) == tag);
            if width != Width::Word || !offset.is_multiple_of(VDMA_ENTRY_BYTES) || pending {
                return Err(refuse(
                    NAME,
                    offset,
                    width,
                    Direction::Read,
                    "ANS VDMA cache word or pending entry without a model",
                ));
            }
            return Ok(0);
        }
        // SPTM 0x270c7c40 invalidates a tag then checks its three-bit
        // status in a four-bit lane (eight tags per word). The controller
        // has no cached translations after a synchronous DMA completes.
        if (TAG_STATUS..TAG_STATUS + 32).contains(&offset)
            && offset.is_multiple_of(4)
            && width == Width::Word
        {
            let first = ((offset - TAG_STATUS) * 2) as u16;
            return Ok(self
                .pending
                .iter()
                .filter(|(_, tag)| (first..first + 8).contains(tag))
                .fold(0, |bits, (_, tag)| bits | (1 << ((tag - first) * 4))));
        }
        let value = match (offset, width) {
            (CAP, Width::Double) => CAPABILITIES,
            (CAP, Width::Word) => CAPABILITIES & u64::from(u32::MAX),
            (4, Width::Word) => CAPABILITIES >> 32,
            (VS, Width::Word) => VERSION,
            (INTMS | INTMC, Width::Word) => u64::from(self.interrupt_mask),
            (CC, Width::Word) => u64::from(self.config),
            (CSTS, Width::Word) => u64::from(self.status),
            (AQA, Width::Word) => u64::from(self.aqa),
            (ASQ, Width::Double) => self.queues[0].sq,
            (ACQ, Width::Double) => self.queues[0].cq,
            (ADMIN_TCB, Width::Double) => self.tcb_bases[0],
            (IO_TCB, Width::Double) => self.tcb_bases[1],
            (BOOT_STATUS, Width::Word) => BOOT_OK,
            (BASE_CID, Width::Word) => 0, // Stela assigns tags starting at zero.
            // `SetupANS2SleepNotifier` (0x3dbc540) subscribes to system power
            // changes and tunnels sleep notices to the controller only when
            // bits 1:0 read 1. Stela's die takes no such notices.
            (SLEEP_NOTIFY, Width::Word) => 0,
            (MODESEL, Width::Word) => u64::from(self.modesel),
            (AUTO_QUEUE, Width::Word) => u64::from(self.auto_queue),
            (MAX_PENDING, Width::Word) => u64::from(self.queue_attributes.unwrap_or(0)),
            (LINEAR, Width::Word) => u64::from(self.linear),
            (TCB_COUNT, Width::Word) => u64::from(self.tcb_count),
            (TCB_STATUS, Width::Word) => 0, // No cached translations: invalidation completes synchronously.
            _ => {
                return Err(refuse(
                    NAME,
                    offset,
                    width,
                    Direction::Read,
                    "ANS register or width without a model",
                ));
            }
        };
        Ok(value)
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let error = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        if let Some(old) = self.base(offset & !7) {
            let base = offset & !7;
            if self.config & ENABLE != 0 && !matches!(base, IO_SQ | IO_CQ) {
                return Err(error("ANS queue/TCB base changed while enabled"));
            }
            if !self.pending.is_empty() || self.queues[1].pending != 0 {
                return Err(error("ANS base changed with outstanding commands"));
            }
            // SPTM 0x270c88c4..0x270c88e8 and 0x270c76cc..0x270c7750
            // issue low/high 32-bit stores to TCB and queue addresses.
            let value = match (offset % 8, width) {
                (0, Width::Double) => value,
                (0 | 4, Width::Word) if value <= u64::from(u32::MAX) => {
                    let shift = (offset % 8) * 8;
                    (old & !(0xffff_ffff << shift)) | (value << shift)
                }
                _ => return Err(error("ANS base register width or alignment")),
            };
            if !value.is_multiple_of(4096) {
                return Err(error("ANS queue/TCB base is not page-aligned"));
            }
            match base {
                ASQ => self.queues[0].sq = value,
                ACQ => self.queues[0].cq = value,
                IO_SQ => self.queues[1].sq = value,
                IO_CQ => self.queues[1].cq = value,
                ADMIN_TCB => self.tcb_bases[0] = value,
                IO_TCB => self.tcb_bases[1] = value,
                _ => unreachable!(),
            }
            self.refresh_auto_queue();
            return Ok(());
        }
        if width != Width::Word || value > u64::from(u32::MAX) {
            return Err(error("ANS register requires a 32-bit word"));
        }
        let value = value as u32;
        match offset {
            CC => self.configure(value).map_err(error)?,
            INTMS | INTMC => {
                // NVMe's full 32-bit interrupt mask: W1S/W1C. Only
                // vector zero has a source in this single-vector die.
                if offset == INTMS {
                    self.interrupt_mask |= value;
                } else {
                    self.interrupt_mask &= !value;
                }
            }
            AQA if self.config & ENABLE == 0 && value & 0xf000_f000 == 0 => self.aqa = value,
            ADMIN_HEAD | IO_HEAD => {
                let head =
                    u16::try_from(value).map_err(|_| error("ANS CQ head exceeds 16 bits"))?;
                self.queues[usize::from(offset == IO_HEAD)]
                    .acknowledge(head)
                    .map_err(error)?;
            }
            LINEAR if value <= 1 && self.pending.is_empty() => self.linear = value != 0,
            MAX_PENDING
                if value & 0xffff < u32::from(QUEUE_ENTRIES)
                    && value >> 16 < u32::from(QUEUE_ENTRIES) =>
            {
                self.queue_attributes = Some(value)
            }
            MODESEL
                if matches!(value, MODE_REGULAR | MODE_RESTORE) && self.config & ENABLE == 0 =>
            {
                // A die choice: Stela's controller runs no host-loaded
                // firmware, so the restore mode serves the same commands;
                // its boot-from-host image download stays an unmodeled
                // admin command.
                self.modesel = value
            }
            AUTO_QUEUE if value <= 1 => self.auto_queue = value != 0,
            TCB_COUNT if value < u32::from(TAGS) && self.config & ENABLE == 0 => {
                self.tcb_count = value as u16
            }
            ADMIN_SUBMIT | IO_SUBMIT => self
                .submit(
                    usize::from(offset == IO_SUBMIT),
                    u16::try_from(value).map_err(|_| error("ANS tag exceeds 16 bits"))?,
                )
                .map_err(error)?,
            TCB_INVALIDATE if value < u32::from(TAGS) => {
                if self.pending.iter().any(|&(_, tag)| u32::from(tag) == value) {
                    return Err(error("ANS invalidation of a pending command"));
                }
                self.valid[value as usize] = false;
            }
            _ => return Err(error("ANS register, field or state without a model")),
        }
        self.refresh_auto_queue();
        self.update_irq(access);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        apple::{
            interrupt::InterruptLatch,
            sart::{Bounds, Sart},
        },
        dma::{Memory, Physical, tests::Ram},
        pc::block::tests::RamDisk,
    };
    use alloc::{vec, vec::Vec};
    const RAM: u64 = 0x8_0000_0000;
    const SQ: u64 = RAM;
    const CQ: u64 = RAM + 0x1000;
    const TCB: u64 = RAM + 0x2000;
    const IOSQ: u64 = RAM + 0x4000;
    const IOCQ: u64 = RAM + 0x5000;
    const IOTCB: u64 = RAM + 0x6000;
    const DATA: u64 = RAM + 0x9000;
    const IRQ: AicInput = AicInput::new(0, 724);
    /// CC.SHN for a suspend: `IONVMeController::ShutdownNVMe(inSuspend)`
    /// (0x3ddbb48) passes `inSuspend` to `SendShutdownNotification`
    /// (0x3ddb908), which writes 11b (0x3ddb9dc) for it and 01b otherwise.
    /// NVMe reserves 11b; Apple's controllers take it as the suspend notice.
    const SUSPEND: u32 = 3 << 14;

    struct Rig {
        ans: Ans,
        sart: Sart,
        ram: Ram,
        latch: InterruptLatch,
    }
    impl Rig {
        fn new() -> Self {
            let disk = Box::new(RamDisk::new("partition-id", 32, 4096));
            let mut rig = Self {
                ans: Ans::new(
                    disk,
                    &[Description {
                        id: 1,
                        kind: 1,
                        blocks: 0,
                    }],
                    Some(IRQ),
                )
                .unwrap(),
                sart: Sart::new(Bounds::Exclusive),
                ram: Ram::new(RAM, 0x20000),
                latch: InterruptLatch::new(),
            };
            let mut access = Access::new(0, 0, &mut rig.latch);
            for (offset, value) in [(0x40, RAM / 4096), (0x80, 0x20), (0, 0xff)] {
                rig.sart
                    .write(offset, Width::Word, value, &mut access)
                    .unwrap();
            }
            for (offset, width, value) in [
                (AQA, Width::Word, 0x0001_0001),
                (ASQ, Width::Double, SQ),
                (ACQ, Width::Double, CQ),
                (ADMIN_TCB, Width::Double, TCB),
                (IO_TCB, Width::Double, IOTCB),
                (LINEAR, Width::Word, 1),
                (CC, Width::Word, u64::from(ENTRY_SIZES | ENABLE)),
            ] {
                rig.ans.write(offset, width, value, &mut access).unwrap();
            }
            rig
        }
        fn read(&mut self, offset: u64) -> u64 {
            self.ans
                .read(offset, Width::Word, &mut Access::new(0, 0, &mut self.latch))
                .unwrap()
        }
        fn write(&mut self, offset: u64, value: u64) -> Result<(), MmioError> {
            self.ans.write(
                offset,
                Width::Word,
                value,
                &mut Access::new(0, 0, &mut self.latch),
            )
        }
        fn run(&mut self) -> Result<(), MmioError> {
            let mut access = Access::new(0, 0, &mut self.latch);
            self.ans.run(
                &mut Port {
                    iommu: &mut Physical,
                    stream: 0,
                    memory: &mut self.ram,
                    access: &mut access,
                },
                &mut self.sart,
            )
        }
        fn submit(
            &mut self,
            queue: usize,
            tag: u16,
            opcode: u8,
            nsid: u32,
            prp: u64,
            words: [u32; 6],
        ) -> Result<(), MmioError> {
            let mut cmd = [0u8; 64];
            cmd[0] = opcode;
            cmd[2..4].copy_from_slice(&tag.to_le_bytes());
            cmd[4..8].copy_from_slice(&nsid.to_le_bytes());
            cmd[24..32].copy_from_slice(&prp.to_le_bytes());
            for (i, word) in words.iter().enumerate() {
                cmd[40 + 4 * i..44 + 4 * i].copy_from_slice(&word.to_le_bytes());
            }
            let mut tcb = [0u8; 128];
            tcb[2] = tag as u8;
            tcb[4..6].copy_from_slice(&(words[2] as u16).to_le_bytes());
            tcb[24..32].copy_from_slice(&prp.to_le_bytes());
            tcb[1] = commands::Command(cmd).direction(queue).unwrap_or(0);
            tcb[56..64].copy_from_slice(&cmd[56..64]);
            let (sq, tcbs, doorbell) = if queue == 0 {
                (SQ, TCB, ADMIN_SUBMIT)
            } else {
                (IOSQ, IOTCB, IO_SUBMIT)
            };
            assert!(self.ram.write(sq + u64::from(tag) * 64, &cmd));
            assert!(self.ram.write(tcbs + u64::from(tag) * 128, &tcb));
            self.write(doorbell, u64::from(tag))?;
            self.run()
        }
        fn retire(&mut self, queue: usize, tag: u16) {
            let head = (self.ans.queues[queue].head + 1) % self.ans.queues[queue].cq_entries;
            self.write(TCB_INVALIDATE, u64::from(tag)).unwrap();
            self.write(
                if queue == 0 { ADMIN_HEAD } else { IO_HEAD },
                u64::from(head),
            )
            .unwrap();
        }
        fn io_queues(&mut self) {
            self.submit(0, 0, 5, 0, IOCQ, [1 | (3 << 16), 3, 0, 0, 0, 0])
                .unwrap();
            self.retire(0, 0);
            self.submit(0, 1, 1, 0, IOSQ, [1 | (3 << 16), 1 | (1 << 16), 0, 0, 0, 0])
                .unwrap();
            self.retire(0, 1);
        }
        fn bytes(&mut self, address: u64, len: usize) -> alloc::vec::Vec<u8> {
            let mut data = vec![0; len];
            assert!(self.ram.read(address, &mut data));
            data
        }
    }

    #[test]
    fn sptm_split_bases_auto_queue_and_packed_invalidation_status() {
        let mut rig = Rig::new();
        rig.write(CC, 0).unwrap();
        for (register, address) in [
            (ASQ, SQ),
            (ACQ, CQ),
            (ADMIN_TCB, TCB),
            (IO_TCB, IOTCB),
            (IO_SQ, IOSQ),
            (IO_CQ, IOCQ),
        ] {
            rig.write(register, address & 0xffff_ffff).unwrap();
            rig.write(register + 4, address >> 32).unwrap();
            assert_eq!(
                rig.ans.read(
                    register,
                    Width::Double,
                    &mut Access::new(0, 0, &mut rig.latch)
                ),
                Ok(address)
            );
            assert_eq!(
                rig.ans.read(
                    register + 4,
                    Width::Word,
                    &mut Access::new(0, 0, &mut rig.latch)
                ),
                Ok(address >> 32)
            );
        }
        rig.write(MAX_PENDING, 3 | (3 << 16)).unwrap();
        rig.write(AUTO_QUEUE, 1).unwrap();
        rig.write(CC, u64::from(ENTRY_SIZES | ENABLE)).unwrap();
        assert!(rig.ans.queues[1].sq_enabled && rig.ans.queues[1].cq_enabled);
        rig.submit(1, 2, 2, 1, DATA, [0; 6]).unwrap();
        assert_eq!(rig.bytes(IOCQ + 14, 2), [1, 0]);
        rig.retire(1, 2);
        rig.write(IO_SUBMIT, 2).unwrap();
        assert_eq!(
            rig.ans.read(
                TAG_STATUS,
                Width::Word,
                &mut Access::new(0, 0, &mut rig.latch)
            ),
            Ok(1 << 8)
        );
        assert!(rig.write(TCB_INVALIDATE, 2).is_err());
        rig.run().unwrap();
        rig.retire(1, 2);
        assert_eq!(
            rig.ans.read(
                TAG_STATUS,
                Width::Word,
                &mut Access::new(0, 0, &mut rig.latch)
            ),
            Ok(0)
        );
    }

    #[test]
    fn private_identify_matches_features_and_partition_capacity() {
        let mut rig = Rig::new();
        rig.submit(0, 0, 6, 0, DATA, [0; 6]).unwrap();
        assert_eq!(rig.bytes(DATA + 0x204, 4), 1u32.to_le_bytes());
        assert_eq!(&rig.bytes(DATA + 0xc00, 16)[..14], b"Stela ANS2 1.0");
        assert_eq!(rig.bytes(DATA + 0xe06, 2), 1u16.to_le_bytes());
        let descriptor = u64::from_le_bytes(rig.bytes(DATA + 0xd00, 8).try_into().unwrap());
        rig.retire(0, 0);
        rig.submit(0, 1, 0xa, 0, 0, [0xc0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(rig.bytes(CQ + 16, 4), (descriptor as u32).to_le_bytes());
        rig.retire(0, 1);
        rig.submit(0, 0, 0xa, 0, 0, [0xc1, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(rig.bytes(CQ, 4), ((descriptor >> 32) as u32).to_le_bytes());
        rig.retire(0, 0);
        rig.submit(0, 1, 0xa, 0, 0, [0xc2, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(rig.bytes(CQ + 16, 4), [0; 4]);
        rig.retire(0, 1);
        assert!(rig.submit(0, 0, 9, 0, 0, [0xc0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn identify_completions_wrap_phase_and_interrupt_is_level_masked() {
        let mut rig = Rig::new();
        rig.submit(0, 0, 6, 0, DATA, [1, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(&rig.bytes(DATA + 24, 10), b"Stela ANS2");
        assert_eq!(rig.bytes(DATA, 4), vec![0x6b, 0x10, 0x6b, 0x10]);
        assert_eq!(rig.bytes(DATA + 260, 1), vec![3]);
        let cqe = rig.bytes(CQ, 16);
        assert_eq!(cqe[14], 1);
        assert_eq!(&cqe[8..14], &[0; 6]);
        assert!(rig.latch.is_asserted(Wire::Aic(IRQ)));
        rig.write(INTMS, u64::from(u32::MAX)).unwrap();
        assert_eq!(rig.ans.interrupt_mask, u32::MAX);
        assert!(!rig.latch.is_asserted(Wire::Aic(IRQ)));
        rig.write(INTMC, 1).unwrap();
        assert_eq!(rig.ans.interrupt_mask, u32::MAX - 1);
        assert!(rig.latch.is_asserted(Wire::Aic(IRQ)));
        assert!(rig.write(ADMIN_SUBMIT, 0).is_err());
        rig.retire(0, 0);
        assert!(!rig.latch.is_asserted(Wire::Aic(IRQ)));
        rig.submit(0, 1, 6, 1, DATA, [0; 6]).unwrap();
        assert_eq!(rig.bytes(DATA + 130, 1), vec![12]);
        rig.retire(0, 1);
        rig.submit(0, 0, 6, 0, DATA, [1, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            rig.bytes(CQ + 14, 2),
            vec![0, 0],
            "phase flips after wrapping CQ"
        );
        assert!(rig.write(ADMIN_HEAD, 2).is_err());
    }

    #[test]
    fn writes_reads_compare_fua_flush_and_namespace_range() {
        let mut rig = Rig::new();
        rig.io_queues();
        let pattern = vec![0xa5; 4096];
        assert!(rig.ram.write(DATA, &pattern));
        rig.submit(1, 2, 1, 1, DATA, [3, 0, 1 << 30, 0, 0, 0])
            .unwrap();
        rig.retire(1, 2);
        assert!(rig.ram.write(DATA, &[0; 4096]));
        rig.submit(1, 3, 2, 1, DATA, [3, 0, 0, 0, 0, 0]).unwrap();
        rig.retire(1, 3);
        assert_eq!(rig.bytes(DATA, 4096), pattern);
        rig.submit(1, 4, 5, 1, DATA, [3, 0, 0, 0, 0, 0]).unwrap();
        rig.retire(1, 4);
        assert!(rig.ram.write(DATA, &[1; 4096]));
        rig.submit(1, 5, 5, 1, DATA, [3, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            u16::from_le_bytes(rig.bytes(IOCQ + 3 * 16 + 14, 2).try_into().unwrap()) >> 1,
            0x285
        );
        rig.retire(1, 5);
        rig.submit(1, 6, 0, 1, 0, [0; 6]).unwrap();
        rig.retire(1, 6);
        rig.submit(1, 7, 2, 1, DATA, [32, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            u16::from_le_bytes(rig.bytes(IOCQ + 16 + 14, 2).try_into().unwrap()) >> 1,
            0x80
        );
    }

    #[test]
    fn encryption_and_unknown_commands_never_complete_and_queues_bypass_the_sart() {
        let mut rig = Rig::new();
        assert!(rig.submit(0, 0, 0xff, 0, 0, [0; 6]).is_err());
        assert_eq!(rig.bytes(CQ, 16), vec![0; 16]);
        let mut rig = Rig::new();
        assert!(rig.ram.write(TCB + 64, &[1]));
        // Install an ordinary identify first, then change its protected TCB
        // before the deferred DMA service runs.
        let mut cmd = [0; 64];
        cmd[0] = 6;
        cmd[24..32].copy_from_slice(&DATA.to_le_bytes());
        cmd[40] = 1;
        assert!(rig.ram.write(SQ, &cmd));
        assert!(rig.ram.write(TCB + 1, &[1]));
        assert!(rig.ram.write(TCB + 24, &DATA.to_le_bytes()));
        rig.write(ADMIN_SUBMIT, 0).unwrap();
        assert!(rig.run().is_err());
        let rejected = rig.ans.last_submission().unwrap();
        assert_eq!((rejected.queue, rejected.tag), (0, 0));
        assert_eq!(rejected.command[0], 6);
        assert_eq!(rejected.tcb[64], 1);
        assert_eq!(rig.bytes(CQ, 16), vec![0; 16]);
        // TCB 0x38..0x40 holds zero or a copy of CDW14 and CDW15.
        let mut rig = Rig::new();
        assert!(rig.ram.write(SQ, &cmd));
        assert!(rig.ram.write(TCB + 1, &[1]));
        assert!(rig.ram.write(TCB + 24, &DATA.to_le_bytes()));
        assert!(rig.ram.write(TCB + 60, &[1]));
        rig.write(ADMIN_SUBMIT, 0).unwrap();
        assert!(rig.run().is_err());
        assert_eq!(rig.bytes(CQ, 16), vec![0; 16]);
        // Queues, TCBs and PRP data are physical: an Identify completes
        // with every SART entry disabled.
        let mut rig = Rig::new();
        rig.sart
            .write(0, Width::Word, 0, &mut Access::new(0, 0, &mut rig.latch))
            .unwrap();
        rig.submit(0, 0, 6, 0, DATA, [1, 0, 0, 0, 0, 0]).unwrap();
        assert_ne!(rig.bytes(CQ, 16), vec![0; 16]);
        assert!(rig.latch.is_asserted(Wire::Aic(IRQ)));
    }

    #[test]
    fn queue_depth_satisfies_the_sptm_queue_entries_contract() {
        // ANS3CGv2 hands SPTM INIT min(MQES + 1, 256 + 1) - 1, which must
        // equal the tree's nvme-queue-entries.
        const NVME_QUEUE_ENTRIES: u64 = 64;
        let mut rig = Rig::new();
        let cap = rig
            .ans
            .read(CAP, Width::Double, &mut Access::new(0, 0, &mut rig.latch))
            .unwrap();
        assert_eq!((cap & 0xffff) + 1, u64::from(QUEUE_ENTRIES));
        assert_eq!(((cap & 0xffff) + 1).min(256 + 1) - 1, NVME_QUEUE_ENTRIES);
        // The kernel's 65-entry admin rings fit; a deeper ring does not.
        rig.write(CC, 0).unwrap();
        for (base, address) in [(ASQ, SQ), (ACQ, CQ)] {
            rig.ans
                .write(
                    base,
                    Width::Double,
                    address,
                    &mut Access::new(0, 0, &mut rig.latch),
                )
                .unwrap();
        }
        rig.write(AQA, 65 | 65 << 16).unwrap();
        assert!(rig.write(CC, u64::from(ENTRY_SIZES | ENABLE)).is_err());
        rig.write(AQA, 64 | 64 << 16).unwrap();
        rig.write(CC, u64::from(ENTRY_SIZES | ENABLE)).unwrap();
        assert_eq!(rig.ans.queues[0].sq_entries, QUEUE_ENTRIES);
        assert_eq!(rig.ans.queues[0].cq_entries, QUEUE_ENTRIES);
        // Create I/O CQ: QSIZE 65 (66 entries) fails, QSIZE 64 succeeds.
        rig.submit(0, 0, 5, 0, IOCQ, [1 | (65 << 16), 3, 0, 0, 0, 0])
            .unwrap();
        assert_ne!(rig.bytes(CQ + 14, 2), [1, 0]);
        rig.retire(0, 0);
        rig.submit(0, 1, 5, 0, IOCQ, [1 | (64 << 16), 3, 0, 0, 0, 0])
            .unwrap();
        assert_eq!(rig.bytes(CQ + 16 + 14, 2), [1, 0]);
        assert_eq!(rig.ans.queues[1].cq_entries, QUEUE_ENTRIES);
        // Tags stay below 64 whatever the ring depth.
        assert!(rig.write(ADMIN_SUBMIT, u64::from(TAGS)).is_err());
        // I/O queue attributes are 0's based like AQA.
        assert!(rig.write(MAX_PENDING, 65).is_err());
        rig.write(MAX_PENDING, 64 | 64 << 16).unwrap();
    }

    #[test]
    fn restore_mode_suspend_shutdown_and_the_sleep_notice_capability() {
        let mut rig = Rig::new();
        // The restore boot's MODESEL 4 before enabling, then CC.EN.
        rig.write(CC, 0).unwrap();
        for (base, address) in [(ASQ, SQ), (ACQ, CQ)] {
            rig.ans
                .write(
                    base,
                    Width::Double,
                    address,
                    &mut Access::new(0, 0, &mut rig.latch),
                )
                .unwrap();
        }
        rig.write(MODESEL, u64::from(MODE_RESTORE)).unwrap();
        rig.write(CC, u64::from(ENTRY_SIZES | ENABLE)).unwrap();
        assert_eq!(rig.read(CSTS), u64::from(READY));
        assert_eq!(rig.read(MODESEL), u64::from(MODE_RESTORE));
        assert_eq!(rig.read(SLEEP_NOTIFY), 0);
        // A suspend notification completes like a normal one.
        rig.write(CC, u64::from(ENTRY_SIZES | ENABLE | SUSPEND))
            .unwrap();
        rig.run().unwrap();
        assert_eq!(rig.read(CSTS), u64::from(READY | SHUTDOWN_COMPLETE));
        // Clearing SHN keeps the completed status (`HandleAbruptShutdown`
        // 0x3dc0fc8 clears it and polls SHST for 2).
        rig.write(CC, u64::from(ENTRY_SIZES | ENABLE)).unwrap();
        rig.run().unwrap();
        assert_eq!(rig.read(CSTS), u64::from(READY | SHUTDOWN_COMPLETE));
        // The abrupt notification after it completes again.
        rig.write(CC, u64::from(ENTRY_SIZES | ENABLE | 2 << 14))
            .unwrap();
        rig.run().unwrap();
        assert_eq!(rig.read(CSTS), u64::from(READY | SHUTDOWN_COMPLETE));
        // The hand-off leaves a fresh controller in linear mode.
        let disk = Box::new(RamDisk::new("partition-id", 32, 4096));
        let namespaces = [Description {
            id: 1,
            kind: 1,
            blocks: 0,
        }];
        assert!(!Ans::new(disk, &namespaces, None).unwrap().linear);
        let disk = Box::new(RamDisk::new("partition-id", 32, 4096));
        let ans = Ans::new(disk, &namespaces, None)
            .unwrap()
            .handed_off_linear();
        assert!(ans.linear);
    }

    /// Disable, select MODESEL 4 and re-enable, as the restore boot does.
    fn restore_mode(rig: &mut Rig) {
        rig.write(CC, 0).unwrap();
        for (base, address) in [(ASQ, SQ), (ACQ, CQ)] {
            rig.ans
                .write(
                    base,
                    Width::Double,
                    address,
                    &mut Access::new(0, 0, &mut rig.latch),
                )
                .unwrap();
        }
        rig.write(MODESEL, u64::from(MODE_RESTORE)).unwrap();
        rig.write(CC, u64::from(ENTRY_SIZES | ENABLE)).unwrap();
    }

    #[test]
    fn boot_from_host_download_is_ordered_crc_checked_and_recorded() {
        let image: Vec<u8> = (0..0x1800u32).map(|i| (i * 7 + 3) as u8).collect();
        let chunk = |rig: &mut Rig, tag, offset: usize, len: usize, crc: u32| {
            assert!(rig.ram.write(DATA, &image[offset..offset + len]));
            let words = [len as u32 / 4 - 1, offset as u32 / 4, 0, 0, 0, crc];
            rig.submit(0, tag, 0x11, 0, DATA, words)
        };
        let crc = |offset: usize, len: usize| bfh::crc32c(&image[offset..offset + len]);
        // Outside the restore mode the commands refuse.
        let mut rig = Rig::new();
        assert!(chunk(&mut rig, 0, 0, 0x1000, crc(0, 0x1000)).is_err());
        let mut rig = Rig::new();
        restore_mode(&mut rig);
        // The parameter block, then the loader in two chunks.
        assert!(rig.ram.write(DATA + 0x2000, b"FWUP"));
        rig.submit(0, 0, 0xd1, 0, DATA + 0x2000, [0, 0, 0, 0, 0, 0])
            .unwrap();
        assert_eq!(rig.bytes(CQ + 14, 2), [1, 0]);
        rig.retire(0, 0);
        chunk(&mut rig, 1, 0, 0x1000, crc(0, 0x1000)).unwrap();
        assert_eq!(rig.bytes(CQ + 16 + 14, 2), [1, 0]);
        rig.retire(0, 1);
        // The two-entry ring wraps: success with the inverted phase.
        chunk(&mut rig, 2, 0x1000, 0x800, crc(0x1000, 0x800)).unwrap();
        assert_eq!(rig.bytes(CQ + 14, 2), [0, 0]);
        rig.retire(0, 2);
        // Slot 0, commit action 1 records the identity and succeeds.
        rig.submit(0, 3, 0x10, 0, 0, [1 << 3, 0, 0, 0, 0, 0])
            .unwrap();
        assert_eq!(rig.bytes(CQ + 16 + 14, 2), [0, 0]);
        rig.retire(0, 3);
        let recorded = rig.ans.boot_image().unwrap();
        assert_eq!(recorded.sections.len(), 1);
        assert_eq!(recorded.sections[0].0, 0);
        assert_eq!(recorded.sections[0].1.bytes, 0x1800);
        assert_eq!(recorded.sections[0].1.crc32c, crc(0, 0x1800));
        assert_eq!(recorded.params.as_ref().unwrap().bytes, 4);
        // The identity survives a controller reset.
        restore_mode(&mut rig);
        assert!(rig.ans.boot_image().is_some());

        // A CRC mismatch, a gap, an out-of-order section and an
        // unsupported commit action each stop without completing.
        let refused = |words: [u32; 6], opcode| {
            let mut rig = Rig::new();
            restore_mode(&mut rig);
            assert!(rig.ram.write(DATA, &image[..0x1000]));
            rig.submit(0, 0, opcode, 0, DATA, words).is_err()
        };
        assert!(refused([0x3ff, 0, 0, 0, 0, crc(0, 0x1000) ^ 1], 0x11));
        assert!(refused([0x3ff, 4, 0, 0, 0, crc(0, 0x1000)], 0x11));
        assert!(refused([0x3ff, 0, 0, 0, 1, crc(0, 0x1000)], 0x11));
        assert!(refused([0x3ff, 0, 0, 0, 3, crc(0, 0x1000)], 0x11));
        assert!(refused([0x3ff, 0, 1, 0, 0, crc(0, 0x1000)], 0x11));
        assert!(refused([2 << 3, 0, 0, 0, 0, 0], 0x10));
        assert!(refused([1 << 3, 0, 0, 0, 0, 0], 0x10));
        // A controller reset discards an uncommitted download.
        let mut rig = Rig::new();
        restore_mode(&mut rig);
        chunk(&mut rig, 0, 0, 0x1000, crc(0, 0x1000)).unwrap();
        rig.retire(0, 0);
        restore_mode(&mut rig);
        assert!(
            rig.submit(0, 0, 0x10, 0, 0, [1 << 3, 0, 0, 0, 0, 0])
                .is_err()
        );
    }

    #[test]
    fn shutdown_deletes_the_io_sq_before_its_cq() {
        let mut rig = Rig::new();
        rig.io_queues();
        // The status of admin command `tag`, retired after it completes.
        let delete = |rig: &mut Rig, tag: u16, opcode: u8, id: u32| {
            let slot = rig.ans.queues[0].tail;
            rig.submit(0, tag, opcode, 0, 0, [id, 0, 0, 0, 0, 0])
                .unwrap();
            let status = rig.bytes(CQ + u64::from(slot) * 16 + 14, 2);
            rig.retire(0, tag);
            u16::from_le_bytes([status[0], status[1]]) >> 1
        };
        // The CQ cannot go while its SQ exists; queue 2 does not exist.
        assert_eq!(delete(&mut rig, 2, 4, 1), 0x10c);
        assert_eq!(delete(&mut rig, 3, 0, 2), 0x101);
        assert_eq!(delete(&mut rig, 4, 0, 1), 0);
        assert!(!rig.ans.queues[1].sq_enabled);
        assert_eq!(delete(&mut rig, 5, 0, 1), 0x101);
        assert_eq!(delete(&mut rig, 6, 4, 1), 0);
        assert!(!rig.ans.queues[1].cq_enabled);
        // A deletion carrying a data pointer is outside the contract.
        assert!(rig.submit(0, 7, 4, 0, DATA, [1, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn full_queues_do_not_overwrite_and_invalid_config_has_no_effect() {
        let mut rig = Rig::new();
        rig.submit(0, 0, 6, 0, DATA, [1, 0, 0, 0, 0, 0]).unwrap();
        rig.submit(0, 1, 6, 0, DATA, [1, 0, 0, 0, 0, 0]).unwrap();
        let before = rig.bytes(CQ, 32);
        assert!(rig.submit(0, 2, 6, 0, DATA, [1, 0, 0, 0, 0, 0]).is_err());
        assert_eq!(rig.bytes(CQ, 32), before);
        assert!(
            rig.write(CC, u64::from(ENTRY_SIZES | ENABLE | 1 << 12))
                .is_err()
        );
        assert_eq!(rig.ans.config, ENTRY_SIZES | ENABLE);
        assert!(rig.write(MODESEL, 1).is_err());
        // MODESEL applies at enable.
        assert!(rig.write(MODESEL, u64::from(MODE_RESTORE)).is_err());
        assert!(rig.write(AUTO_QUEUE, 2).is_err());
        assert!(rig.write(ADMIN_HEAD, 3).is_err());
    }
}
