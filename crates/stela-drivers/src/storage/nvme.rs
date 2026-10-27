//! NVMe controllers with one admin and one I/O queue pair. Each active NVM
//! namespace with plain logical blocks becomes one device. The I/O queue
//! runs up to [`DEPTH`] commands at once, each through its own bounce buffer,
//! and a command that times out resets the controller and runs again, as
//! Linux's `nvme_timeout` and `nvme_reset_work` recover one. Namespace
//! discovery, shutdown and recovery follow Linux `drivers/nvme/host/core.c`
//! and `pci.c` at a804c5742bff224d4cb4d25dd383554d598be32b.
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
const DOORBELLS: usize = 0x1000;

const ENABLE: u32 = 1;
const READY: u32 = 1;
const FATAL: u32 = 1 << 1;
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
/// The first version with the active namespace list (Linux `NVME_VS(1, 1, 0)`).
const VERSION_1_1: u32 = 0x0001_0100;
/// 64-byte submission and 16-byte completion entries, 4 KiB pages, NVM set.
const CONFIGURATION_VALUE: u32 = ENABLE | 6 << 16 | 4 << 20;

const ADMIN_CREATE_SUBMISSION: u8 = 0x01;
const ADMIN_CREATE_COMPLETION: u8 = 0x05;
const ADMIN_IDENTIFY: u8 = 0x06;
const ADMIN_SET_FEATURES: u8 = 0x09;
/// One MSI-X table entry: message address, data and vector control.
const MSIX_ENTRY_BYTES: u64 = 16;
/// Autonomous Power State Transition (NVMe Base 2.1 5.27.1.6).
const FEATURE_APST: u32 = 0x0c;
const IO_FLUSH: u8 = 0x00;
const IO_WRITE: u8 = 0x01;
const IO_READ: u8 = 0x02;
const IO_WRITE_ZEROES: u8 = 0x08;
const IO_DATASET_MANAGEMENT: u8 = 0x09;

const IDENTIFY_NAMESPACE: u32 = 0;
const IDENTIFY_CONTROLLER: u32 = 1;
const IDENTIFY_ACTIVE_NAMESPACES: u32 = 2;

/// Identify Controller fields (NVMe Base 2.1 Figure 312).
const CONTROLLER_SERIAL: core::ops::Range<usize> = 4..24;
const CONTROLLER_MODEL: core::ops::Range<usize> = 24..64;
const CONTROLLER_MAXIMUM_TRANSFER: usize = 77;
const CONTROLLER_RTD3_ENTRY: core::ops::Range<usize> = 88..92;
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
const NAMESPACE_FORMAT: usize = 26;
/// DLFEAT: bits 2:0 what a deallocated block reads (001b zeros), bit 3
/// Write Zeroes may deallocate.
const NAMESPACE_DEALLOCATE: usize = 33;
const NAMESPACE_ATTRIBUTES: usize = 99;
const NAMESPACE_WRITE_PROTECTED: u8 = 1 << 0;
const NAMESPACE_FORMATS: usize = 128;
/// FLBAS: format index bits 3:0, and bits 6:5 for formats past sixteen.
const FORMAT_LOW: u8 = 0xf;
const FORMAT_HIGH: u8 = 3 << 5;
/// The most namespaces a sequential scan visits, one Identify each.
const SEQUENTIAL_SCAN_LIMIT: u32 = 1024;

const PAGE: usize = 4096;
const ADMIN_ENTRIES: u16 = 16;
/// The I/O queue's entries: one page of submissions.
const IO_ENTRIES: u16 = 64;
/// The commands the I/O queue runs at once, each holding a bounce buffer,
/// as Linux's tag set bounds them; one for a controller in an owned DMA
/// domain, whose buffers change hands whole.
const DEPTH: usize = 8;
const BOUNCE_BYTES: usize = 128 * 1024;
const COMMAND_TIMEOUT_US: u64 = 30_000_000;
/// Linux `nvme_max_retries`: a command the controller's reset interrupted
/// runs again at most this often.
const RETRIES: u8 = 5;
/// Read/Write CDW12 bit 30: complete only once the data is durable.
const FORCE_UNIT_ACCESS: u32 = 1 << 30;
/// Write Zeroes CDW12 bit 25: the blocks may be deallocated.
const DEALLOCATE: u32 = 1 << 25;
/// Dataset Management CDW11 bit 2: deallocate the ranges.
const ATTRIBUTE_DEALLOCATE: u32 = 1 << 2;

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
        namespace: u32,
        block: usize,
        command: Command,
        deadline: Option<crate::Deadline>,
        retries: u8,
    },
    /// Interrupted by a controller reset, to run again once it completes.
    Waiting {
        namespace: u32,
        block: usize,
        command: Command,
        retries: u8,
    },
    Done(Finished),
}

/// A controller reset in progress ([`Controller::recover`]), each step
/// looked for without waiting.
enum Recovery {
    /// CC.EN cleared; waiting for CSTS.RDY to clear.
    Disabling(crate::Deadline),
    /// CC.EN set; waiting for CSTS.RDY.
    Enabling(crate::Deadline),
    /// The admin command creating the I/O completion, then submission,
    /// queue, and its identifier.
    Creating {
        submission: bool,
        id: u16,
        deadline: crate::Deadline,
    },
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
    max_transfer: usize,
    /// How long a normal shutdown may take.
    shutdown_timeout_us: u64,
    /// The controller acknowledged a shutdown; it takes no more commands.
    shut_down: bool,
    command_id: u16,
    clock: Clock,
    command_timeout_us: u64,
    /// An unresolved command may still own the queues, PRPs and bounce RAM,
    /// or the controller is gone. No buffer or queue may be reused until a
    /// new, acknowledged reset.
    fault: Option<BlockError>,
    owned: Option<owned::Owner>,
    teardown: owned::Teardown,
    ready_timeout_us: u64,
}

impl Controller {
    fn ready(&mut self) -> Result<(), BlockError> {
        if let Some(error) = &self.fault {
            return Err(error.clone());
        }
        if self.shut_down {
            return Err(BlockError::Unsupported("NVMe controller is shut down"));
        }
        let status = self.registers.read32(STATUS)?;
        if status == REMOVED {
            return Err(self.poison(removed()));
        }
        if status & FATAL != 0 {
            return Err(self.poison(BlockError::Device { status }));
        }
        Ok(())
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
        self.ready_timeout_us = ((capabilities >> 24 & 0xff).max(1)) * 500_000;
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
        self.registers.write32(CONFIGURATION, 0)?;
        self.wait_status(self.ready_timeout_us, |status| status & READY == 0)?;
        self.configure_admin()?;
        if let Some(owner) = self.owned.as_mut() {
            owner.lifecycle.enable_dma()?;
        }
        self.registers.write32(CONFIGURATION, CONFIGURATION_VALUE)?;
        self.wait_status(self.ready_timeout_us, |status| {
            status & (READY | FATAL) != 0
        })?;
        self.ready()
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

    /// A failure after publication poisons every sibling. Only a positively
    /// identified CQE can authorize SQ/PRP/data CPU reuse.
    fn execute(&mut self, io: bool, command: [u32; 16]) -> Result<u32, BlockError> {
        self.ready()?;
        match self.execute_inner(io, command) {
            Ok((result, 0)) => Ok(result),
            Ok((_, status)) => Err(BlockError::Device { status }),
            Err(error) => Err(self.poison(error)),
        }
    }
    fn execute_inner(&mut self, io: bool, command: [u32; 16]) -> Result<(u32, u32), BlockError> {
        // Queued commands go first: a waiting caller's command runs alone.
        self.settle()?;
        let id = self.publish(io, command, 0)?;
        self.wait_completion(io, id)
    }

    /// Wait for command `id`'s completion on queue `io`.
    fn wait_completion(&mut self, io: bool, id: u16) -> Result<(u32, u32), BlockError> {
        let (clock, timeout) = (self.clock, self.command_timeout_us);
        let mut observed = None;
        let mut polls = 0u32;
        clock.wait(timeout, || {
            // The CQE lives in RAM; CSTS is an MMIO read, which a hypervisor
            // traps. Check for a fatal controller only every few polls.
            polls = polls.wrapping_add(1);
            match self.completion(io, id, polls.is_multiple_of(STATUS_POLL_INTERVAL)) {
                Ok(None) => false,
                done => {
                    observed = Some(done);
                    true
                }
            }
        });
        match observed {
            Some(Ok(Some(completion))) => Ok(completion),
            Some(Err(error)) => Err(error),
            Some(Ok(None)) | None => Err(BlockError::Timeout),
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

    /// Publish `command` on queue `io` with tag `tag`'s memory and ring its
    /// doorbell; its identifier.
    fn publish(&mut self, io: bool, command: [u32; 16], tag: usize) -> Result<u16, BlockError> {
        let stride = self.doorbell_stride;
        self.command_id = self.command_id.wrapping_add(1);
        let id = self.command_id;
        {
            let (bounce, prp_list) = self.slot(tag);
            bounce.give()?;
            prp_list.give()?;
        }
        let registers = &self.registers;
        let queue = if io { &mut self.io } else { &mut self.admin };
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
    /// not have moved back nor past the tail. `check_status` reads CSTS
    /// first.
    fn posted(
        &mut self,
        io: bool,
        check_status: bool,
    ) -> Result<Option<(u16, u32, u32, u16)>, BlockError> {
        let registers = &self.registers;
        let queue = if io { &mut self.io } else { &mut self.admin };
        let entry = usize::from(queue.head) * 16;
        if check_status {
            let status = registers.read32(STATUS)?;
            if status == REMOVED {
                return Err(removed());
            }
            if status & FATAL != 0 {
                return Err(BlockError::Device { status });
            }
        }
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

    /// Command `id`'s result and status once the controller has posted its
    /// completion at queue `io`'s head, the only command outstanding there;
    /// never waits. `check_status` also reads CSTS for a fatal controller
    /// first.
    fn completion(
        &mut self,
        io: bool,
        id: u16,
        check_status: bool,
    ) -> Result<Option<(u32, u32)>, BlockError> {
        let queue = if io { &self.io } else { &self.admin };
        let (head, phase, consumed) = (queue.head, queue.phase, queue.consumed);
        let Some((posted, result, status, _)) = self.posted(io, check_status)? else {
            return Ok(None);
        };
        let queue = if io { &mut self.io } else { &mut self.admin };
        if posted != id || queue.consumed != queue.tail {
            (queue.head, queue.phase, queue.consumed) = (head, phase, consumed);
            return Err(BlockError::Device { status: 0xffff });
        }
        let csts = self.registers.read32(STATUS)?;
        if csts == REMOVED {
            return Err(removed());
        }
        if csts & FATAL != 0 {
            return Err(BlockError::Device { status: csts });
        }
        // SAFETY: exact outstanding command completed; no other command can
        // access these ranges until this one's owner permits another.
        unsafe {
            let queue = if io { &mut self.io } else { &mut self.admin };
            queue.submissions.take()?;
            self.bounce.take()?;
            self.prp_list.take()?;
        }
        self.release(io)?;
        Ok(Some((result, status)))
    }

    /// Wait for every queued command, keeping each result for its tag: a
    /// command of a waiting caller's own follows.
    fn settle(&mut self) -> Result<(), BlockError> {
        let started = self.clock.try_start().ok();
        loop {
            self.advance();
            if let Some(error) = &self.fault {
                return Err(error.clone());
            }
            let busy = self.recovery.is_some()
                || self
                    .tags
                    .iter()
                    .any(|tag| matches!(tag, Tag::Running { .. } | Tag::Waiting { .. }));
            if !busy {
                return Ok(());
            }
            // Each running command has its own deadline; recovery steps too.
            if started
                .and_then(|started| self.clock.try_elapsed_us(started).ok())
                .is_some_and(|elapsed| elapsed > 4 * self.command_timeout_us)
            {
                return Err(self.poison(BlockError::Timeout));
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

    /// Whether a tag is free for a command, and none waits to run again.
    fn room(&self) -> bool {
        self.fault.is_none()
            && !self.shut_down
            && self.recovery.is_none()
            && self.tags.iter().any(|tag| matches!(tag, Tag::Free))
    }

    /// Run `command` of `namespace` under a free tag; the tag.
    fn start(&mut self, namespace: u32, block: usize, command: Command) -> Result<u32, BlockError> {
        if let Some(error) = &self.fault {
            return Err(error.clone());
        }
        if self.shut_down {
            return Err(BlockError::Unsupported("NVMe controller is shut down"));
        }
        let tag = self
            .tags
            .iter()
            .position(|tag| matches!(tag, Tag::Free))
            .filter(|_| self.recovery.is_none())
            .ok_or(BlockError::Protocol("every NVMe tag is in use"))?;
        self.submit(tag, namespace, block, command, 0);
        Ok(tag as u32)
    }

    /// Publish `command` under `tag`, which holds no other.
    fn submit(&mut self, tag: usize, namespace: u32, block: usize, command: Command, retries: u8) {
        let slot = self.io.tail;
        let published = self
            .io_command(tag, namespace, block, &command)
            .and_then(|words| self.publish(true, words, tag));
        self.tags[tag] = match published {
            Ok(id) => Tag::Running {
                id,
                slot,
                namespace,
                block,
                command,
                deadline: self.clock.try_deadline(self.command_timeout_us).ok(),
                retries,
            },
            Err(error) => Tag::Done(Err(self.poison(error))),
        };
    }

    /// Collect every completion the controller has posted, check the
    /// running commands' deadlines and move a reset on; never waits.
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
            match self.posted(true, false) {
                Ok(None) => break,
                Ok(Some((id, _, status, head))) => {
                    reaped = true;
                    self.complete(id, status, head);
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
        let expired = self.tags.iter().any(
            |tag| matches!(tag, Tag::Running { deadline: Some(deadline), .. } if deadline.passed()),
        );
        if expired {
            self.reset();
        }
    }

    /// Command `id` completed with `status`, the controller reporting
    /// submission head `head`: its tag takes the result.
    fn complete(&mut self, id: u16, status: u32, head: u16) {
        let io = &self.io;
        let Some(tag) = self.tags.iter().position(|tag| {
            matches!(tag, Tag::Running { id: running, slot, .. }
                if *running == id && io.fetched(*slot, head))
        }) else {
            // A completion for no running command, or for one the
            // controller had not fetched: the queue is corrupt.
            self.poison(BlockError::Device { status: 0xffff });
            return;
        };
        let Tag::Running { command, .. } = core::mem::take(&mut self.tags[tag]) else {
            unreachable!();
        };
        // SAFETY: the controller completed this exact command; its memory
        // is the CPU's again.
        let taken = unsafe {
            let (bounce, prp_list) = self.slot(tag);
            bounce.take().and_then(|()| prp_list.take())
        };
        self.tags[tag] = Tag::Done(match (taken, status, command) {
            (Err(error), ..) => Err(self.poison(error)),
            (Ok(()), 0, Command::Read { bytes, .. }) => {
                Ok(Some(self.slot(tag).0.bytes()[..bytes].to_vec()))
            }
            (Ok(()), 0, _) => Ok(None),
            (Ok(()), status, _) => Err(BlockError::Device { status }),
        });
    }

    /// End every command with the controller's fault.
    fn fail_all(&mut self) {
        let error = self.fault.clone().unwrap_or(BlockError::Timeout);
        for tag in &mut self.tags {
            if matches!(tag, Tag::Running { .. } | Tag::Waiting { .. }) {
                *tag = Tag::Done(Err(error.clone()));
            }
        }
        self.recovery = None;
    }

    /// Reset the controller for a command past its deadline, as Linux's
    /// `nvme_timeout` does once a controller is not fatally failed: every
    /// running command waits to run again once the reset completes. A
    /// fatal or removed controller, or one whose DMA domain changes hands
    /// whole, stays failed.
    fn reset(&mut self) {
        let status = self.registers.read32(STATUS);
        let error = match status {
            Ok(REMOVED) => Some(removed()),
            Ok(_) if self.owned.is_some() => Some(BlockError::Timeout),
            Ok(_) => None,
            Err(error) => Some(error),
        };
        if let Some(error) = error {
            self.poison(error);
            self.fail_all();
            return;
        }
        for tag in &mut self.tags {
            *tag = match core::mem::take(tag) {
                Tag::Running {
                    namespace,
                    block,
                    command,
                    retries,
                    ..
                } if retries < RETRIES => Tag::Waiting {
                    namespace,
                    block,
                    command,
                    retries: retries + 1,
                },
                Tag::Running { .. } => Tag::Done(Err(BlockError::Timeout)),
                other => other,
            };
        }
        let disabled = self
            .registers
            .write32(CONFIGURATION, 0)
            .and_then(|()| self.deadline(self.ready_timeout_us));
        match disabled {
            Ok(deadline) => self.recovery = Some(Recovery::Disabling(deadline)),
            Err(error) => {
                self.poison(error);
                self.fail_all();
            }
        }
    }

    fn deadline(&self, us: u64) -> Result<crate::Deadline, BlockError> {
        self.clock
            .try_deadline(us)
            .map_err(|_| BlockError::Unsupported("NVMe requires a representable deadline"))
    }

    /// Move the controller reset on, never waiting: disabled, enabled with
    /// the admin queue, the I/O queues created again, then the interrupted
    /// commands run again under their tags.
    fn recover(&mut self) -> Result<(), BlockError> {
        let status = self.registers.read32(STATUS)?;
        if status == REMOVED {
            return Err(removed());
        }
        match self.recovery.take() {
            None => Ok(()),
            Some(Recovery::Disabling(deadline)) => {
                if status & READY != 0 {
                    if deadline.passed() {
                        return Err(BlockError::Timeout);
                    }
                    self.recovery = Some(Recovery::Disabling(deadline));
                    return Ok(());
                }
                // The disabled controller no longer reaches any queue or
                // buffer: every one is the CPU's again.
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
                }
                self.io.restart();
                self.io.completions.bytes_mut().fill(0);
                self.admin.completions.bytes_mut().fill(0);
                self.configure_admin()?;
                self.registers.write32(CONFIGURATION, CONFIGURATION_VALUE)?;
                let deadline = self.deadline(self.ready_timeout_us)?;
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
                self.create_next(false)
            }
            Some(Recovery::Creating {
                submission,
                id,
                deadline,
            }) => match self.completion(false, id, false)? {
                None if deadline.passed() => Err(BlockError::Timeout),
                None => {
                    self.recovery = Some(Recovery::Creating {
                        submission,
                        id,
                        deadline,
                    });
                    Ok(())
                }
                Some((_, 0)) if !submission => {
                    self.io.submissions.publish();
                    self.create_next(true)
                }
                Some((_, 0)) => {
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
                Some((_, status)) => Err(BlockError::Device { status }),
            },
        }
    }

    /// Submit the admin command creating the next I/O queue of a reset.
    fn create_next(&mut self, submission: bool) -> Result<(), BlockError> {
        let command = self.create_queue(submission)?;
        let id = self.publish(false, command, 0)?;
        let deadline = self.deadline(self.command_timeout_us)?;
        self.recovery = Some(Recovery::Creating {
            submission,
            id,
            deadline,
        });
        Ok(())
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
        self.settle()?;
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

    /// An admin Identify into the first bounce page.
    fn identify(&mut self, cns: u32, namespace: u32) -> Result<&[u8], BlockError> {
        let mut command = [0u32; 16];
        command[0] = u32::from(ADMIN_IDENTIFY);
        command[1] = namespace;
        let page = self.bounce.address()?;
        command[6] = page as u32;
        command[7] = (page >> 32) as u32;
        command[10] = cns;
        self.execute(false, command)?;
        Ok(&self.bounce.bytes()[..PAGE])
    }

    /// Enable autonomous power state transitions with `table`.
    fn set_apst(&mut self, table: &[u64; 32]) -> Result<(), BlockError> {
        for (index, entry) in table.iter().enumerate() {
            self.bounce.write(8 * index, *entry);
        }
        let mut command = [0u32; 16];
        command[0] = u32::from(ADMIN_SET_FEATURES);
        let page = self.bounce.address()?;
        command[6] = page as u32;
        command[7] = (page >> 32) as u32;
        command[10] = FEATURE_APST;
        command[11] = 1;
        self.execute(false, command).map(drop)
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

    fn transfer(
        &mut self,
        opcode: u8,
        namespace: u32,
        lba: u64,
        blocks: u32,
        bytes: usize,
        access: u32,
    ) -> Result<(), BlockError> {
        self.ready()?;
        self.settle()?;
        let pointers = self.data_pointers(0, bytes)?;
        let command = transfer_command(opcode, namespace, lba, blocks, pointers, access);
        self.execute(true, command).map(|_| ())
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
        shutdown_timeout_us: SHUTDOWN_MINIMUM_US,
        shut_down: false,
        command_id: 0,
        clock: handoff.clock,
        command_timeout_us: COMMAND_TIMEOUT_US,
        fault: None,
        owned: None,
        teardown: owned::Teardown::Unprepared,
        ready_timeout_us: 500_000,
    };
    controller.initialize()?;
    discover(controller, format!("{}", function.address))
}

pub(crate) fn validate_clock(clock: Clock) -> Result<(), BlockError> {
    // CAP.TO permits 255 half-second intervals. The fixed command and maximum
    // shutdown policies are shorter; admit every later native wait upfront.
    clock.check_duration(255 * 500_000).map_err(|_| {
        BlockError::Unsupported("NVMe requires a calibrated, representable operation clock")
    })
}

fn discover(
    mut controller: Controller,
    location: alloc::string::String,
) -> Result<Attached, BlockError> {
    let identify = controller.identify(IDENTIFY_CONTROLLER, 0)?;
    let serial = ascii(&identify[CONTROLLER_SERIAL]);
    let model = ascii(&identify[CONTROLLER_MODEL]);
    // The maximum transfer, in minimum pages as a power of two; 0 is none.
    let maximum = identify[CONTROLLER_MAXIMUM_TRANSFER];
    let rtd3_entry_us = u64::from(le32(&identify[CONTROLLER_RTD3_ENTRY], 0));
    let namespaces = le32(&identify[CONTROLLER_NAMESPACES], 0);
    let commands = u16::from_le_bytes([
        identify[CONTROLLER_COMMANDS],
        identify[CONTROLLER_COMMANDS + 1],
    ]);
    // Linux `nvme_init_identify` takes a present cache as one to flush and
    // leaves the controller's Volatile Write Cache feature as it is.
    let write_cache = identify[CONTROLLER_VOLATILE_CACHE] & 1 != 0;
    let apst = apst_table(identify);
    if maximum != 0 {
        let limit = 1usize.checked_shl(u32::from(maximum)).unwrap_or(usize::MAX);
        controller.max_transfer = controller.max_transfer.min(limit.saturating_mul(PAGE));
    }
    controller.shutdown_timeout_us = shutdown_timeout_us(rtd3_entry_us);

    let command = controller.create_queue(false)?;
    controller.execute(false, command)?;
    let command = controller.create_queue(true)?;
    controller.io.submissions.publish();
    controller.execute(false, command)?;
    if let Some(table) = apst {
        controller.set_apst(&table)?;
    }

    // Linux `nvme_scan_work`: the active list from NVMe 1.1, otherwise (or
    // when the controller refuses it) every namespace ID in turn.
    let version = controller.registers.read32(VERSION)?;
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
    let max_transfer = controller.max_transfer;
    for namespace in candidates {
        let data = controller.identify(IDENTIFY_NAMESPACE, namespace)?;
        match plain_format(data, max_transfer) {
            // An inactive namespace reads as all zeros in a sequential scan.
            Ok(None) if sequential => {}
            Ok(None) => attached
                .failures
                .push((namespace, BlockError::Unsupported("empty NVMe namespace"))),
            Ok(Some(format)) => found.push((namespace, format)),
            Err(error) => attached.failures.push((namespace, error)),
        }
    }
    let controller = Rc::new(RefCell::new(controller));
    attached.namespaces = found
        .into_iter()
        .map(|(namespace, format)| Namespace {
            controller: controller.clone(),
            namespace,
            identity: Identity {
                transport: Transport::Nvme,
                location: format!("{location} namespace {namespace}"),
                model: model.clone(),
                serial: serial.clone(),
                blocks: format.blocks,
                block_size: format.block_size,
                read_only: format.read_only,
                features: features(write_cache, commands, &format, max_transfer),
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

/// A namespace's features, as Linux `nvme_update_disk_info` and
/// `nvme_config_discard` set them: FUA with a volatile write cache,
/// Deallocate as discard with Dataset Management, and Write Zeroes, which
/// may deallocate where the namespace reads deallocated blocks as zeros
/// and says Write Zeroes deallocates (`NVME_NS_DEAC`), each up to the
/// largest transfer.
fn features(write_cache: bool, commands: u16, format: &Format, max_transfer: usize) -> Features {
    let blocks = (max_transfer / format.block_size as usize) as u64;
    Features {
        write_cache,
        fua: write_cache,
        max_transfer,
        discard: (commands & COMMANDS_DATASET_MANAGEMENT != 0).then_some(u64::from(u32::MAX)),
        write_zeroes: (commands & COMMANDS_WRITE_ZEROES != 0).then_some(WriteZeroes {
            blocks: blocks.min(1 << 16),
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

    fn write_with(&mut self, lba: u64, data: &[u8], access: u32) -> Result<(), BlockError> {
        self.identity.check_write(lba, data.len())?;
        let mut controller = self.controller.borrow_mut();
        controller.ready()?;
        controller.settle()?;
        let block = self.identity.block_size as usize;
        let chunk = self.chunk_bytes(&controller);
        for (index, part) in data.chunks(chunk).enumerate() {
            let first = lba + (index * chunk / block) as u64;
            let blocks = (part.len() / block) as u32;
            controller.bounce.bytes_mut()[..part.len()].copy_from_slice(part);
            controller.transfer(IO_WRITE, self.namespace, first, blocks, part.len(), access)?;
        }
        Ok(())
    }

    /// Run `command` alone, waiting for it.
    fn run(&mut self, command: Command) -> Result<(), BlockError> {
        let command = command.within(&self.identity, 0)?;
        let mut controller = self.controller.borrow_mut();
        controller.ready()?;
        controller.settle()?;
        let block = self.identity.block_size as usize;
        let words = controller.io_command(0, self.namespace, block, &command)?;
        controller.execute(true, words).map(drop)
    }
}

impl BlockDevice for Namespace {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.identity.check(lba, buffer.len())?;
        let mut controller = self.controller.borrow_mut();
        controller.ready()?;
        controller.settle()?;
        let block = self.identity.block_size as usize;
        let chunk = self.chunk_bytes(&controller);
        for (index, part) in buffer.chunks_mut(chunk).enumerate() {
            let first = lba + (index * chunk / block) as u64;
            let blocks = (part.len() / block) as u32;
            controller.transfer(IO_READ, self.namespace, first, blocks, part.len(), 0)?;
            part.copy_from_slice(&controller.bounce.bytes()[..part.len()]);
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.write_with(lba, data, 0)
    }

    fn write_fua(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.write_with(lba, data, FORCE_UNIT_ACCESS)
    }

    fn flush_cache(&mut self) -> Result<(), BlockError> {
        self.run(Command::Flush)
    }

    fn discard(&mut self, lba: u64, blocks: u64) -> Result<(), BlockError> {
        self.run(Command::Discard { lba, blocks })
    }

    fn write_zeroes(&mut self, lba: u64, blocks: u64, unmap: bool) -> Result<(), BlockError> {
        self.run(Command::WriteZeroes { lba, blocks, unmap })
    }

    /// The controller's tags, shared by its namespaces: [`Self::finish`]
    /// looks for completions in memory, never at a register, until a
    /// command's timeout.
    fn depth(&self) -> usize {
        self.controller.borrow().tags.len()
    }

    fn room(&self) -> bool {
        self.controller.borrow().room()
    }

    fn start(&mut self, command: Command) -> Result<u32, BlockError> {
        let command = command.within(&self.identity, 0)?;
        let block = self.identity.block_size as usize;
        self.controller
            .borrow_mut()
            .start(self.namespace, block, command)
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
                shutdown_timeout_us: 1000,
                shut_down: false,
                command_id: 0,
                // Exercise a real finite deadline with a short captured test
                // policy; native attachment retains its thirty-second policy.
                clock: Clock {
                    ticks_per_microsecond: 1000,
                },
                command_timeout_us: 1000,
                fault: None,
                owned: None,
                teardown: owned::Teardown::Unprepared,
                ready_timeout_us: 500_000,
            };
            Self {
                _registers: registers,
                _memory: memory,
                disk: Namespace {
                    controller: Rc::new(RefCell::new(controller)),
                    namespace: 1,
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
    fn timeout_and_late_completion_cannot_reuse_any_namespace_dma() {
        let mut fixture = Fixture::new();
        let clock = fixture.disk.controller.borrow().clock;
        let started = clock.try_start().unwrap();
        assert_eq!(
            fixture.disk.write(0, &[0x31; 512]),
            Err(BlockError::Timeout)
        );
        assert!(clock.try_elapsed_us(started).unwrap() >= 1000);
        let mut sibling = Namespace {
            controller: fixture.disk.controller.clone(),
            namespace: 2,
            identity: fixture.disk.identity.clone(),
        };
        let (submission, prps, doorbell) = {
            let mut c = fixture.disk.controller.borrow_mut();
            // The timed-out device now delivers its late completion and DMA.
            c.io.completions.write(8, 1u32 << 16 | 1);
            c.io.completions.write(12, 1u32 << 16 | 1);
            c.bounce.bytes_mut().fill(0x9d);
            (
                c.io.submissions.bytes().to_vec(),
                c.prp_list.bytes().to_vec(),
                c.registers.read32(DOORBELLS + 8).unwrap(),
            )
        };
        let mut output = vec![0x55; BOUNCE_BYTES];
        assert_eq!(sibling.read(0, &mut output), Err(BlockError::Timeout));
        assert!(output.iter().all(|byte| *byte == 0x55));
        assert_eq!(
            fixture.disk.write(1, &[0xe6; 512]),
            Err(BlockError::Timeout)
        );
        assert_eq!(sibling.flush(), Err(BlockError::Timeout));
        let mut c = fixture.disk.controller.borrow_mut();
        assert_eq!(
            c.transfer(IO_READ, 1, 0, 256, BOUNCE_BYTES, 0),
            Err(BlockError::Timeout)
        );
        assert!(c.bounce.bytes().iter().all(|byte| *byte == 0x9d));
        assert_eq!(c.io.submissions.bytes(), submission);
        assert_eq!(c.prp_list.bytes(), prps);
        assert_eq!(c.registers.read32(DOORBELLS + 8).unwrap(), doorbell);
        assert_eq!((c.command_id, c.io.tail, c.io.head), (1, 1, 0));
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
            c.io.completions.write(12, 2u32 << 17 | 1 << 16 | 1);
        }
        assert_eq!(fixture.disk.flush(), Err(BlockError::Device { status: 2 }));
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
    fn fatal_status_poison_precedes_cpu_dma_access_and_does_not_reopen() {
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
    fn a_command_past_its_deadline_resets_the_controller_and_runs_again() {
        let mut fixture = Fixture::new();
        let disk = &mut fixture.disk;
        let read = disk.start(Command::Read { lba: 0, bytes: 512 }).unwrap();
        let clock = disk.controller.borrow().clock;
        let started = clock.try_start().unwrap();
        while clock.try_elapsed_us(started).unwrap() < 1000 {
            core::hint::spin_loop();
        }
        // The deadline passes: the controller is disabled.
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
        // Ready: the I/O queues are created again, completion queue first.
        for submission in [false, true] {
            assert_eq!(disk.finish(read), None);
            let mut controller = disk.controller.borrow_mut();
            let Some(Recovery::Creating { id, .. }) = controller.recovery else {
                panic!("no queue creation");
            };
            let entry = usize::from(controller.admin.head) * 16;
            let tail = u32::from(controller.admin.tail);
            let phase = u32::from(controller.admin.phase) << 16;
            controller.admin.completions.write(entry + 8, tail);
            controller
                .admin
                .completions
                .write(entry + 12, phase | u32::from(id));
            let opcode = if submission {
                ADMIN_CREATE_SUBMISSION
            } else {
                ADMIN_CREATE_COMPLETION
            };
            let offset = usize::from(controller.admin.tail - 1) * 64;
            assert_eq!(controller.admin.submissions.bytes()[offset], opcode);
        }
        // The interrupted read runs again on the empty queue.
        assert_eq!(disk.finish(read), None);
        let mut controller = disk.controller.borrow_mut();
        assert!(controller.recovery.is_none());
        assert_eq!((controller.io.tail, controller.io.head), (1, 0));
        let id = running_id(&controller, read);
        controller.bounce.bytes_mut()[..512].fill(0x5a);
        post(&mut controller, id, 0);
        drop(controller);
        assert_eq!(disk.finish(read), Some(Ok(Some(vec![0x5a; 512]))));
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
        // With a cache the flush is submitted; this fixture never completes it.
        fixture.disk.identity.features.write_cache = true;
        assert_eq!(fixture.disk.flush(), Err(BlockError::Timeout));
        assert_eq!(fixture.disk.controller.borrow().io.tail, 1);
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
        controller.shutdown().unwrap();
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
