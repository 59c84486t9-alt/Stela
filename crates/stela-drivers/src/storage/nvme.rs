//! NVMe controllers with one admin and one I/O queue pair, polled. Each
//! active NVM namespace with plain logical blocks becomes one device.
//! Namespace discovery and shutdown follow Linux `drivers/nvme/host/core.c`
//! and `pci.c` at a804c5742bff224d4cb4d25dd383554d598be32b.
use crate::bytes::le32;
use crate::{
    Clock, Handoff,
    block::{BlockDevice, BlockError, Identity, Transport, ascii},
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
/// The first version with the active namespace list (Linux `NVME_VS(1, 1, 0)`).
const VERSION_1_1: u32 = 0x0001_0100;
/// 64-byte submission and 16-byte completion entries, 4 KiB pages, NVM set.
const CONFIGURATION_VALUE: u32 = ENABLE | 6 << 16 | 4 << 20;

const ADMIN_DELETE_SUBMISSION: u8 = 0x00;
const ADMIN_CREATE_SUBMISSION: u8 = 0x01;
const ADMIN_DELETE_COMPLETION: u8 = 0x04;
const ADMIN_CREATE_COMPLETION: u8 = 0x05;
const ADMIN_IDENTIFY: u8 = 0x06;
const ADMIN_ABORT: u8 = 0x08;
const IO_FLUSH: u8 = 0x00;
const IO_WRITE: u8 = 0x01;
const IO_READ: u8 = 0x02;

const IDENTIFY_NAMESPACE: u32 = 0;
const IDENTIFY_CONTROLLER: u32 = 1;
const IDENTIFY_ACTIVE_NAMESPACES: u32 = 2;

/// Identify Controller fields (NVMe Base 2.1 Figure 312).
const CONTROLLER_SERIAL: core::ops::Range<usize> = 4..24;
const CONTROLLER_MODEL: core::ops::Range<usize> = 24..64;
const CONTROLLER_MAXIMUM_TRANSFER: usize = 77;
const CONTROLLER_RTD3_ENTRY: core::ops::Range<usize> = 88..92;
const CONTROLLER_NAMESPACES: core::ops::Range<usize> = 516..520;
/// Identify Namespace fields (NVM Command Set 1.1 Figure 114).
const NAMESPACE_SIZE: core::ops::Range<usize> = 0..8;
const NAMESPACE_FORMAT: usize = 26;
const NAMESPACE_ATTRIBUTES: usize = 99;
const NAMESPACE_WRITE_PROTECTED: u8 = 1 << 0;
const NAMESPACE_FORMATS: usize = 128;
/// FLBAS: format index bits 3:0, and bits 6:5 for formats past sixteen.
const FORMAT_LOW: u8 = 0xf;
const FORMAT_HIGH: u8 = 3 << 5;
/// The most namespaces a sequential scan visits, one Identify each.
const SEQUENTIAL_SCAN_LIMIT: u32 = 1024;

const PAGE: usize = 4096;
const ENTRIES: u16 = 16;
const BOUNCE_BYTES: usize = 128 * 1024;
const COMMAND_TIMEOUT_US: u64 = 30_000_000;
/// Linux `NVME_ADMIN_TIMEOUT`.
const ADMIN_TIMEOUT_US: u64 = 60_000_000;
/// Linux `nvme_max_retries`.
const COMMAND_RETRIES: u32 = 5;
/// The completion status field's Do Not Retry bit.
const STATUS_DO_NOT_RETRY: u32 = 1 << 14;

/// How a command was lost, when it produced no completion to report.
enum Lost {
    /// Linux resets the controller: a timeout, or a fatal controller status.
    Reset(BlockError),
    /// The controller broke the protocol or its registers failed.
    Fatal(BlockError),
}

/// One wait for a completion queue entry.
enum Reaped {
    Done(u32, u32),
    TimedOut,
    /// CSTS.CFS: the controller reported a fatal status.
    Fatal(u32),
}

struct Queue {
    submissions: Buffer,
    completions: Buffer,
    id: u16,
    tail: u16,
    head: u16,
    phase: bool,
}

impl Queue {
    fn new(id: u16, dma: &mut dyn DmaAllocator) -> Result<Self, BlockError> {
        Ok(Self {
            submissions: Buffer::Legacy(dma.allocate(PAGE, PAGE)?),
            completions: Buffer::Legacy(dma.allocate(PAGE, PAGE)?),
            id,
            tail: 0,
            head: 0,
            phase: true,
        })
    }
}

/// One controller, shared by its namespaces.
struct Controller {
    registers: RegisterIo,
    doorbell_stride: usize,
    admin: Queue,
    io: Queue,
    bounce: Buffer,
    prp_list: Buffer,
    max_transfer: usize,
    /// How long a normal shutdown may take.
    shutdown_timeout_us: u64,
    /// The controller acknowledged a shutdown; it takes no more commands.
    shut_down: bool,
    command_id: u16,
    clock: Clock,
    command_timeout_us: u64,
    admin_timeout_us: u64,
    /// An unresolved command may still own the queues, PRPs and bounce RAM.
    /// Set when a reset cannot recover the controller; no buffer or queue is
    /// reused afterwards.
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
        Ok(())
    }

    /// CSTS.CFS, as an error.
    fn check_fatal(&self) -> Result<(), BlockError> {
        let status = self.registers.read32(STATUS)?;
        if status & FATAL != 0 {
            return Err(BlockError::Device { status });
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
        if (capabilities & 0xffff) + 1 < u64::from(ENTRIES) {
            return Err(BlockError::Unsupported(
                "NVMe queues shorter than 16 entries",
            ));
        }
        if 4 * self.doorbell_stride + DOORBELLS > 0x2000 {
            return Err(BlockError::Unsupported("NVMe doorbell stride"));
        }
        self.registers.write32(CONFIGURATION, 0)?;
        self.wait_status(self.ready_timeout_us, |status| status & READY == 0)?;
        self.admin.completions.give()?;
        self.io.completions.give()?;
        self.configure_admin_queue()
    }

    /// Linux `nvme_pci_configure_admin_queue` after the controller is
    /// disabled: program the admin queue and enable the controller.
    fn configure_admin_queue(&mut self) -> Result<(), BlockError> {
        // Empty SQs are CPU-owned until their first command publication. The
        // controller cannot consume any SQE before the corresponding doorbell.
        let entries = u32::from(ENTRIES - 1);
        self.registers
            .write32(ADMIN_ATTRIBUTES, entries << 16 | entries)?;
        self.registers
            .write64(ADMIN_SUBMISSION, self.admin.submissions.address()?)?;
        self.admin.submissions.publish();
        self.registers
            .write64(ADMIN_COMPLETION, self.admin.completions.address()?)?;
        self.registers.write32(INTERRUPT_MASK_SET, u32::MAX)?;
        if let Some(owner) = self.owned.as_mut() {
            owner.lifecycle.enable_dma()?;
        }
        self.registers.write32(CONFIGURATION, CONFIGURATION_VALUE)?;
        self.wait_status(self.ready_timeout_us, |status| {
            status & (READY | FATAL) != 0
        })?;
        self.check_fatal()
    }

    /// The Create I/O Completion Queue and Create I/O Submission Queue
    /// commands for the single polled I/O queue pair.
    fn create_queue_commands(&self) -> Result<[[u32; 16]; 2], BlockError> {
        let entries = u32::from(ENTRIES - 1);
        let completion = self.io.completions.address()?;
        let submission = self.io.submissions.address()?;
        let mut create_completion = [0u32; 16];
        create_completion[0] = u32::from(ADMIN_CREATE_COMPLETION);
        create_completion[6] = completion as u32;
        create_completion[7] = (completion >> 32) as u32;
        create_completion[10] = entries << 16 | 1;
        create_completion[11] = 1; // physically contiguous, no interrupt
        let mut create_submission = create_completion;
        create_submission[0] = u32::from(ADMIN_CREATE_SUBMISSION);
        create_submission[6] = submission as u32;
        create_submission[7] = (submission >> 32) as u32;
        create_submission[11] = 1 << 16 | 1; // completion queue 1, contiguous
        Ok([create_completion, create_submission])
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

    /// Linux's command error handling. A timed-out I/O command is aborted and
    /// given another timeout; then, or at once for an admin command or a
    /// fatal controller, the controller is reset. I/O is retried after a
    /// reset or an error status without DNR, up to `nvme_max_retries`; admin
    /// commands fail fast. A failed reset poisons every sibling. Only a
    /// positively identified CQE or an acknowledged reset authorizes
    /// SQ/PRP/data CPU reuse.
    fn execute(&mut self, io: bool, command: [u32; 16]) -> Result<u32, BlockError> {
        self.ready()?;
        let mut retries = 0;
        loop {
            match self.run(io, command) {
                Ok((result, 0)) => return Ok(result),
                Ok((_, status)) => {
                    if !io || status & STATUS_DO_NOT_RETRY != 0 || retries == COMMAND_RETRIES {
                        return Err(BlockError::Device { status });
                    }
                }
                Err(Lost::Reset(error)) => {
                    if let Err(failure) = self.reset() {
                        return Err(self.poison(failure));
                    }
                    if !io || retries == COMMAND_RETRIES {
                        return Err(error);
                    }
                }
                Err(Lost::Fatal(error)) => return Err(self.poison(error)),
            }
            retries += 1;
        }
    }

    /// One command to its completion, with `nvme_timeout`'s abort.
    fn run(&mut self, io: bool, command: [u32; 16]) -> Result<(u32, u32), Lost> {
        let status = self.registers.read32(STATUS).map_err(Lost::Fatal)?;
        if status & FATAL != 0 {
            return Err(Lost::Reset(BlockError::Device { status }));
        }
        let id = self.submit(io, command).map_err(Lost::Fatal)?;
        let timeout = if io {
            self.command_timeout_us
        } else {
            self.admin_timeout_us
        };
        match self.reap(io, id, timeout).map_err(Lost::Fatal)? {
            Reaped::Done(result, status) => {
                // SAFETY: the only outstanding command completed.
                unsafe { self.reclaim() }.map_err(Lost::Fatal)?;
                return Ok((result, status));
            }
            Reaped::Fatal(status) => return Err(Lost::Reset(BlockError::Device { status })),
            Reaped::TimedOut if !io => return Err(Lost::Reset(BlockError::Timeout)),
            Reaped::TimedOut => {}
        }
        let mut abort = [0u32; 16];
        abort[0] = u32::from(ADMIN_ABORT);
        abort[10] = u32::from(id) << 16 | u32::from(self.io.id);
        let abort_id = self.submit(false, abort).map_err(Lost::Fatal)?;
        let completed = match self
            .reap(true, id, self.command_timeout_us)
            .map_err(Lost::Fatal)?
        {
            Reaped::Done(result, status) => (result, status),
            Reaped::Fatal(status) => return Err(Lost::Reset(BlockError::Device { status })),
            Reaped::TimedOut => return Err(Lost::Reset(BlockError::Timeout)),
        };
        match self
            .reap(false, abort_id, self.admin_timeout_us)
            .map_err(Lost::Fatal)?
        {
            Reaped::Done(..) => {
                // SAFETY: the command and its abort both completed.
                unsafe { self.reclaim() }.map_err(Lost::Fatal)?;
            }
            // The abort itself timed out: Linux resets for it, and the
            // command's own completion stands.
            _ => self.reset().map_err(Lost::Fatal)?,
        }
        Ok(completed)
    }

    /// Write `command` at the queue tail and ring its doorbell.
    fn submit(&mut self, io: bool, command: [u32; 16]) -> Result<u16, BlockError> {
        let stride = self.doorbell_stride;
        self.command_id = self.command_id.wrapping_add(1);
        let id = self.command_id;
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
        self.bounce.give()?;
        self.prp_list.give()?;
        queue.submissions.give()?;
        queue.tail = (queue.tail + 1) % ENTRIES;
        fence(Ordering::SeqCst);
        self.registers.write32(
            DOORBELLS + 2 * usize::from(queue.id) * stride,
            u32::from(queue.tail),
        )?;
        Ok(id)
    }

    /// Wait for command `id`'s entry at the completion queue head and retire
    /// it. Only an entry naming exactly this command and queue is accepted.
    fn reap(&mut self, io: bool, id: u16, timeout: u64) -> Result<Reaped, BlockError> {
        let stride = self.doorbell_stride;
        let registers = &self.registers;
        let queue = if io { &mut self.io } else { &mut self.admin };
        let entry = usize::from(queue.head) * 16;
        let mut failure = None;
        let mut fatal = None;
        let done = self.clock.wait(timeout, || {
            let observed = (|| {
                let status = registers.read32(STATUS)?;
                if status & FATAL != 0 {
                    fatal = Some(status);
                    return Ok(true);
                }
                Ok((queue.completions.coherent(entry + 12)? >> 16 & 1 == 1) == queue.phase)
            })();
            match observed {
                Ok(ready) => ready,
                Err(error) => {
                    failure = Some(error);
                    true
                }
            }
        });
        if let Some(error) = failure {
            return Err(error);
        }
        if let Some(status) = fatal {
            return Ok(Reaped::Fatal(status));
        }
        if !done {
            return Ok(Reaped::TimedOut);
        }
        let status = registers.read32(STATUS)?;
        if status & FATAL != 0 {
            return Ok(Reaped::Fatal(status));
        }
        // The domain qualifies the coherent observation; this barrier orders
        // later CQ words after the device's final phase/status publication.
        fence(Ordering::SeqCst);
        let result = queue.completions.coherent(entry)?;
        let submission = queue.completions.coherent(entry + 8)?;
        let tail_word = queue.completions.coherent(entry + 12)?;
        if ((tail_word >> 16 & 1) == 1) != queue.phase
            || tail_word as u16 != id
            || submission >> 16 != u32::from(queue.id)
            || submission as u16 != queue.tail
        {
            return Err(BlockError::Device { status: 0xffff });
        }
        queue.head = (queue.head + 1) % ENTRIES;
        if queue.head == 0 {
            queue.phase = !queue.phase;
        }
        registers.write32(
            DOORBELLS + (2 * usize::from(queue.id) + 1) * stride,
            u32::from(queue.head),
        )?;
        Ok(Reaped::Done(result, tail_word >> 17 & 0x7fff))
    }

    /// Return the submission queues, PRP list and bounce buffer to the CPU.
    ///
    /// # Safety
    /// Every published command completed, or the controller acknowledged a
    /// reset and its DMA was contained.
    unsafe fn reclaim(&mut self) -> Result<(), BlockError> {
        // SAFETY: forwarded from the caller.
        unsafe {
            self.admin.submissions.take()?;
            self.io.submissions.take()?;
            self.bounce.take()?;
            self.prp_list.take()?;
        }
        Ok(())
    }

    /// One admin command inside error handling, which never recurses.
    fn admin_command(&mut self, command: [u32; 16]) -> Result<u32, BlockError> {
        match self.run(false, command) {
            Ok((result, 0)) => Ok(result),
            Ok((_, status)) => Err(BlockError::Device { status }),
            Err(Lost::Reset(error) | Lost::Fatal(error)) => Err(error),
        }
    }

    /// Linux `nvme_dev_disable` and `nvme_reset_work`: delete the I/O queues
    /// of a live controller, disable it and contain its DMA, then configure
    /// the admin queue again, identify the controller and recreate the I/O
    /// queues.
    fn reset(&mut self) -> Result<(), BlockError> {
        let status = self.registers.read32(STATUS)?;
        let dead = status & FATAL != 0 || status & READY == 0;
        // A still-outstanding admin command (an unanswered abort) leaves no
        // admin queue to delete with.
        if !dead && self.admin.head == self.admin.tail {
            self.delete_io_queues()?;
        }
        let configuration = self.registers.read32(CONFIGURATION)?;
        self.registers.write32(
            CONFIGURATION,
            configuration & !(ENABLE | SHUTDOWN_NOTIFICATION),
        )?;
        self.wait_status(self.ready_timeout_us, |status| status & READY == 0)?;
        if let Some(owner) = self.owned.as_mut() {
            // pci_disable_device: bus mastering off and posted writes drained.
            owner.lifecycle.disable_dma()?;
            // SAFETY: the engine acknowledged its reset and BME is off.
            unsafe { owner.domain.drain_posted_writes() }.map_err(owned::map_dma_error)?;
        }
        // SAFETY: the controller acknowledged its reset and its DMA is
        // contained; no command owns any queue or buffer.
        unsafe {
            self.reclaim()?;
            for queue in [&mut self.admin, &mut self.io] {
                queue.completions.take()?;
                queue.completions.bytes_mut()[..usize::from(ENTRIES) * 16].fill(0);
                queue.completions.give()?;
                queue.head = 0;
                queue.tail = 0;
                queue.phase = true;
            }
        }
        self.configure_admin_queue()?;
        // Identify through the bounce buffer's first page, keeping the data a
        // retried write still needs there.
        let kept = self.bounce.bytes()[..PAGE].to_vec();
        let identify = self.identify_command(IDENTIFY_CONTROLLER, 0)?;
        self.admin_command(identify)?;
        self.bounce.bytes_mut()[..PAGE].copy_from_slice(&kept);
        for command in self.create_queue_commands()? {
            self.io.submissions.publish();
            self.admin_command(command)?;
        }
        Ok(())
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

    /// Linux `nvme_delete_io_queues`, submission queue first. A refused
    /// deletion is ignored and a timed-out one ends the deletions, as in
    /// Linux; a broken protocol poisons.
    fn delete_io_queues(&mut self) -> Result<(), BlockError> {
        for opcode in [ADMIN_DELETE_SUBMISSION, ADMIN_DELETE_COMPLETION] {
            let mut command = [0u32; 16];
            command[0] = u32::from(opcode);
            command[10] = u32::from(self.io.id);
            match self.run(false, command) {
                Ok(_) => {}
                Err(Lost::Reset(_)) => break,
                Err(Lost::Fatal(error)) => return Err(self.poison(error)),
            }
        }
        Ok(())
    }

    /// An admin Identify into the first bounce page.
    fn identify(&mut self, cns: u32, namespace: u32) -> Result<&[u8], BlockError> {
        let command = self.identify_command(cns, namespace)?;
        self.execute(false, command)?;
        Ok(&self.bounce.bytes()[..PAGE])
    }

    /// The PRP entries for the first `bytes` of the bounce buffer.
    fn data_pointers(&mut self, bytes: usize) -> Result<(u64, u64), BlockError> {
        let first = self.bounce.address()?;
        match bytes.div_ceil(PAGE) {
            0 | 1 => Ok((first, 0)),
            2 => Ok((first, first + PAGE as u64)),
            pages => {
                for page in 1..pages {
                    self.prp_list
                        .write(8 * (page - 1), first + (page * PAGE) as u64);
                }
                Ok((first, self.prp_list.address()?))
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
    ) -> Result<(), BlockError> {
        self.ready()?;
        let (prp1, prp2) = self.data_pointers(bytes)?;
        let mut command = [0u32; 16];
        command[0] = u32::from(opcode);
        command[1] = namespace;
        command[6] = prp1 as u32;
        command[7] = (prp1 >> 32) as u32;
        command[8] = prp2 as u32;
        command[9] = (prp2 >> 32) as u32;
        command[10] = lba as u32;
        command[11] = (lba >> 32) as u32;
        command[12] = blocks - 1;
        self.execute(true, command).map(|_| ())
    }
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
    let mut controller = Controller {
        registers,
        doorbell_stride: 0,
        admin: Queue::new(0, dma)?,
        io: Queue::new(1, dma)?,
        bounce: Buffer::Legacy(dma.allocate(BOUNCE_BYTES, PAGE)?),
        prp_list: Buffer::Legacy(dma.allocate(PAGE, PAGE)?),
        max_transfer: BOUNCE_BYTES,
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
    if maximum != 0 {
        let limit = 1usize.checked_shl(u32::from(maximum)).unwrap_or(usize::MAX);
        controller.max_transfer = controller.max_transfer.min(limit.saturating_mul(PAGE));
    }
    controller.shutdown_timeout_us = shutdown_timeout_us(rtd3_entry_us);

    for command in controller.create_queue_commands()? {
        controller.io.submissions.publish();
        controller.execute(false, command)?;
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
            },
        })
        .collect();
    Ok(attached)
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
}

impl BlockDevice for Namespace {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.identity.check(lba, buffer.len())?;
        let mut controller = self.controller.borrow_mut();
        controller.ready()?;
        let block = self.identity.block_size as usize;
        let chunk = self.chunk_bytes(&controller);
        for (index, part) in buffer.chunks_mut(chunk).enumerate() {
            let first = lba + (index * chunk / block) as u64;
            let blocks = (part.len() / block) as u32;
            controller.transfer(IO_READ, self.namespace, first, blocks, part.len())?;
            part.copy_from_slice(&controller.bounce.bytes()[..part.len()]);
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.identity.check_write(lba, data.len())?;
        let mut controller = self.controller.borrow_mut();
        controller.ready()?;
        let block = self.identity.block_size as usize;
        let chunk = self.chunk_bytes(&controller);
        for (index, part) in data.chunks(chunk).enumerate() {
            let first = lba + (index * chunk / block) as u64;
            let blocks = (part.len() / block) as u32;
            controller.bounce.bytes_mut()[..part.len()].copy_from_slice(part);
            controller.transfer(IO_WRITE, self.namespace, first, blocks, part.len())?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        let mut command = [0u32; 16];
        command[0] = u32::from(IO_FLUSH);
        command[1] = self.namespace;
        self.controller
            .borrow_mut()
            .execute(true, command)
            .map(|_| ())
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
            let controller = Controller {
                registers: RegisterIo::Legacy(mmio),
                doorbell_stride: 4,
                admin: Queue::new(0, &mut dma).unwrap(),
                io: Queue::new(1, &mut dma).unwrap(),
                bounce: Buffer::Legacy(dma.allocate(BOUNCE_BYTES, PAGE).unwrap()),
                prp_list: Buffer::Legacy(dma.allocate(PAGE, PAGE).unwrap()),
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
                admin_timeout_us: 1000,
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
        for invalid_head in [None, Some(15u32), Some(1)] {
            let mut fixture = Fixture::new();
            for next in 1..ENTRIES {
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
                c.io.completions
                    .write(15 * 16 + 8, 1u32 << 16 | invalid_head.unwrap_or(0));
                c.io.completions.write(15 * 16 + 12, 1u32 << 16 | 16);
            }
            let result = fixture.disk.flush();
            let mut c = fixture.disk.controller.borrow_mut();
            assert_eq!(c.io.tail, 0);
            match invalid_head {
                Some(_) => {
                    assert_eq!(result, Err(BlockError::Device { status: 0xffff }));
                    assert_eq!(c.io.head, 15);
                    assert!(c.io.phase);
                }
                None => {
                    assert_eq!(result, Ok(()));
                    assert_eq!(c.io.head, 0);
                    assert!(!c.io.phase);
                    c.io.completions.write(8, 1u32 << 16 | 1);
                    c.io.completions.write(12, 17u32); // New phase is zero.
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
        // Nothing was submitted to the fatal controller.
        assert_eq!((c.command_id, c.io.tail, c.io.head), (0, 0, 0));
        assert!(c.io.submissions.bytes().iter().all(|byte| *byte == 0));
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
