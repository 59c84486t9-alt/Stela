//! NVMe controllers with one admin and one I/O queue pair, polled. Each
//! active NVM namespace with plain logical blocks becomes one device.
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
use alloc::{format, rc::Rc, vec::Vec};
use core::{
    cell::RefCell,
    sync::atomic::{Ordering, fence},
};

pub const CLASS: [u8; 3] = [0x01, 0x08, 0x02];

const CAPABILITIES: usize = 0x00;
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
/// 64-byte submission and 16-byte completion entries, 4 KiB pages, NVM set.
const CONFIGURATION_VALUE: u32 = ENABLE | 6 << 16 | 4 << 20;

const ADMIN_CREATE_SUBMISSION: u8 = 0x01;
const ADMIN_CREATE_COMPLETION: u8 = 0x05;
const ADMIN_IDENTIFY: u8 = 0x06;
const IO_FLUSH: u8 = 0x00;
const IO_WRITE: u8 = 0x01;
const IO_READ: u8 = 0x02;

const IDENTIFY_NAMESPACE: u32 = 0;
const IDENTIFY_CONTROLLER: u32 = 1;
const IDENTIFY_ACTIVE_NAMESPACES: u32 = 2;

const PAGE: usize = 4096;
const ENTRIES: u16 = 16;
const BOUNCE_BYTES: usize = 128 * 1024;
const COMMAND_TIMEOUT_US: u64 = 30_000_000;

struct Queue {
    submissions: DmaBuffer,
    completions: DmaBuffer,
    id: u16,
    tail: u16,
    head: u16,
    phase: bool,
}

impl Queue {
    fn new(id: u16, dma: &mut dyn DmaAllocator) -> Result<Self, BlockError> {
        Ok(Self {
            submissions: dma.allocate(PAGE, PAGE)?,
            completions: dma.allocate(PAGE, PAGE)?,
            id,
            tail: 0,
            head: 0,
            phase: true,
        })
    }
}

/// One controller, shared by its namespaces.
struct Controller {
    registers: Mmio,
    doorbell_stride: usize,
    admin: Queue,
    io: Queue,
    bounce: DmaBuffer,
    prp_list: DmaBuffer,
    max_transfer: usize,
    command_id: u16,
    clock: Clock,
    /// An unresolved command may still own the queues, PRPs and bounce RAM.
    /// No buffer or queue may be reused until a new, acknowledged reset.
    fault: Option<BlockError>,
}

impl Controller {
    fn ready(&mut self) -> Result<(), BlockError> {
        if let Some(error) = &self.fault {
            return Err(error.clone());
        }
        let status = self.registers.read32(STATUS);
        if status & FATAL != 0 {
            return Err(self.poison(BlockError::Device { status }));
        }
        Ok(())
    }

    fn poison(&mut self, error: BlockError) -> BlockError {
        self.fault = Some(error.clone());
        error
    }

    /// Submit one command on `queue` (admin when false) and poll for its
    /// completion; return completion dword 0.
    fn execute(&mut self, io: bool, command: [u32; 16]) -> Result<u32, BlockError> {
        self.ready()?;
        let stride = self.doorbell_stride;
        let registers = self.registers;
        self.command_id = self.command_id.wrapping_add(1);
        let id = self.command_id;
        let queue = if io { &mut self.io } else { &mut self.admin };
        let base = usize::from(queue.tail) * 64;
        for (index, word) in command.iter().enumerate() {
            let value = if index == 0 {
                word | u32::from(id) << 16
            } else {
                *word
            };
            queue.submissions.write(base + 4 * index, value);
        }
        queue.tail = (queue.tail + 1) % ENTRIES;
        fence(Ordering::SeqCst);
        registers.write32(
            DOORBELLS + 2 * usize::from(queue.id) * stride,
            u32::from(queue.tail),
        );
        let entry = usize::from(queue.head) * 16;
        let phase = queue.phase;
        let completions = &queue.completions;
        let done = self.clock.wait(COMMAND_TIMEOUT_US, || {
            registers.read32(STATUS) & FATAL != 0
                || (completions.read::<u32>(entry + 12) >> 16 & 1 == 1) == phase
        });
        let status = registers.read32(STATUS);
        if status & FATAL != 0 {
            return Err(self.poison(BlockError::Device { status }));
        }
        if !done {
            return Err(self.poison(BlockError::Timeout));
        }
        fence(Ordering::SeqCst);
        let result = queue.completions.read::<u32>(entry);
        let tail_word = queue.completions.read::<u32>(entry + 12);
        let submission = queue.completions.read::<u32>(entry + 8);
        // A phase bit alone does not retire our command. A stale/malformed
        // completion must not authorize reuse or acknowledge an unknown CQE.
        if tail_word as u16 != id
            || submission >> 16 != u32::from(queue.id)
            // With exactly one outstanding command, consuming its SQE must
            // advance SQHD to our tail, including the modulo-ENTRIES wrap.
            // NVMe Base 2.1: SQHD reports the head when this CQE was created.
            || submission as u16 != queue.tail
        {
            return Err(self.poison(BlockError::Device { status: 0xffff }));
        }
        queue.head = (queue.head + 1) % ENTRIES;
        if queue.head == 0 {
            queue.phase = !queue.phase;
        }
        registers.write32(
            DOORBELLS + (2 * usize::from(queue.id) + 1) * stride,
            u32::from(queue.head),
        );
        match tail_word >> 17 & 0x7fff {
            0 => Ok(result),
            status => Err(BlockError::Device { status }),
        }
    }

    /// An admin Identify into the first bounce page.
    fn identify(&mut self, cns: u32, namespace: u32) -> Result<&[u8], BlockError> {
        let mut command = [0u32; 16];
        command[0] = u32::from(ADMIN_IDENTIFY);
        command[1] = namespace;
        let page = self.bounce.physical();
        command[6] = page as u32;
        command[7] = (page >> 32) as u32;
        command[10] = cns;
        self.execute(false, command)?;
        Ok(&self.bounce.bytes()[..PAGE])
    }

    /// The PRP entries for the first `bytes` of the bounce buffer.
    fn data_pointers(&mut self, bytes: usize) -> (u64, u64) {
        let first = self.bounce.physical();
        match bytes.div_ceil(PAGE) {
            0 | 1 => (first, 0),
            2 => (first, first + PAGE as u64),
            pages => {
                for page in 1..pages {
                    self.prp_list
                        .write(8 * (page - 1), first + (page * PAGE) as u64);
                }
                (first, self.prp_list.physical())
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
        let (prp1, prp2) = self.data_pointers(bytes);
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
) -> Result<Vec<Namespace>, BlockError> {
    function.power_up(&handoff.clock)?;
    let bars = function.bars();
    let registers = registers(handoff, bars[0], 0, 0x2000)?;
    function.enable_polled();
    let capabilities = registers.read64(CAPABILITIES);
    let entries_supported = (capabilities & 0xffff) + 1;
    let doorbell_stride = 4usize << (capabilities >> 32 & 0xf);
    let ready_timeout = ((capabilities >> 24 & 0xff).max(1)) * 500_000;
    let page_minimum = capabilities >> 48 & 0xf;
    if capabilities >> 37 & 1 == 0 {
        return Err(BlockError::Unsupported(
            "NVMe controller without the NVM command set",
        ));
    }
    if page_minimum != 0 {
        return Err(BlockError::Unsupported(
            "NVMe controller without 4 KiB pages",
        ));
    }
    if entries_supported < u64::from(ENTRIES) {
        return Err(BlockError::Unsupported(
            "NVMe queues shorter than 16 entries",
        ));
    }
    if 2 * 2 * doorbell_stride + DOORBELLS > 0x2000 {
        return Err(BlockError::Unsupported("NVMe doorbell stride"));
    }
    let clock = handoff.clock;
    if registers.read32(CONFIGURATION) & ENABLE != 0 {
        registers.write32(CONFIGURATION, 0);
    }
    if !clock.wait(ready_timeout, || registers.read32(STATUS) & READY == 0) {
        return Err(BlockError::Timeout);
    }
    let admin = Queue::new(0, dma)?;
    let io = Queue::new(1, dma)?;
    let entries = u32::from(ENTRIES - 1);
    registers.write32(ADMIN_ATTRIBUTES, entries << 16 | entries);
    registers.write64(ADMIN_SUBMISSION, admin.submissions.physical());
    registers.write64(ADMIN_COMPLETION, admin.completions.physical());
    registers.write32(CONFIGURATION, CONFIGURATION_VALUE);
    if !clock.wait(ready_timeout, || {
        registers.read32(STATUS) & (READY | FATAL) != 0
    }) {
        return Err(BlockError::Timeout);
    }
    let status = registers.read32(STATUS);
    if status & FATAL != 0 {
        return Err(BlockError::Device { status });
    }
    registers.write32(INTERRUPT_MASK_SET, u32::MAX);
    let mut controller = Controller {
        registers,
        doorbell_stride,
        admin,
        io,
        bounce: dma.allocate(BOUNCE_BYTES, PAGE)?,
        prp_list: dma.allocate(PAGE, PAGE)?,
        max_transfer: BOUNCE_BYTES,
        command_id: 0,
        clock,
        fault: None,
    };

    let identify = controller.identify(IDENTIFY_CONTROLLER, 0)?;
    let serial = ascii(&identify[4..24]);
    let model = ascii(&identify[24..64]);
    // The maximum transfer, in minimum pages as a power of two; 0 is none.
    let maximum = identify[77];
    if maximum != 0 {
        let limit = 1usize.checked_shl(u32::from(maximum)).unwrap_or(usize::MAX);
        controller.max_transfer = controller.max_transfer.min(limit.saturating_mul(PAGE));
    }

    let completion = controller.io.completions.physical();
    let submission = controller.io.submissions.physical();
    let mut command = [0u32; 16];
    command[0] = u32::from(ADMIN_CREATE_COMPLETION);
    command[6] = completion as u32;
    command[7] = (completion >> 32) as u32;
    command[10] = entries << 16 | 1;
    command[11] = 1; // physically contiguous, no interrupt
    controller.execute(false, command)?;
    command[0] = u32::from(ADMIN_CREATE_SUBMISSION);
    command[6] = submission as u32;
    command[7] = (submission >> 32) as u32;
    command[11] = 1 << 16 | 1; // completion queue 1, contiguous
    controller.execute(false, command)?;

    let active: Vec<u32> = controller
        .identify(IDENTIFY_ACTIVE_NAMESPACES, 0)?
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| u32::from_le_bytes(*word))
        .take_while(|namespace| *namespace != 0)
        .collect();
    let mut found = Vec::new();
    for namespace in active {
        let data = controller.identify(IDENTIFY_NAMESPACE, namespace)?;
        let blocks = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let format = usize::from(data[26] & 0xf);
        let descriptor =
            u32::from_le_bytes(data[128 + 4 * format..132 + 4 * format].try_into().unwrap());
        let metadata = descriptor & 0xffff;
        let shift = descriptor >> 16 & 0xff;
        if metadata != 0 || !(9..=16).contains(&shift) || blocks == 0 {
            // Formats with metadata or odd block sizes are not served.
            continue;
        }
        found.push((namespace, blocks, 1u32 << shift));
    }
    let location = format!("{}", function.address);
    let controller = Rc::new(RefCell::new(controller));
    Ok(found
        .into_iter()
        .map(|(namespace, blocks, block_size)| Namespace {
            controller: controller.clone(),
            namespace,
            identity: Identity {
                transport: Transport::Nvme,
                location: format!("{location} namespace {namespace}"),
                model: model.clone(),
                serial: serial.clone(),
                blocks,
                block_size,
                read_only: false,
            },
        })
        .collect())
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::dma::RegionAllocator;
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
                registers: mmio,
                doorbell_stride: 4,
                admin: Queue::new(0, &mut dma).unwrap(),
                io: Queue::new(1, &mut dma).unwrap(),
                bounce: dma.allocate(BOUNCE_BYTES, PAGE).unwrap(),
                prp_list: dma.allocate(PAGE, PAGE).unwrap(),
                max_transfer: BOUNCE_BYTES,
                command_id: 0,
                // Force the actual polling path to expire immediately.
                clock: Clock {
                    ticks_per_microsecond: 0,
                },
                fault: None,
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
    fn timeout_and_late_completion_cannot_reuse_any_namespace_dma() {
        let mut fixture = Fixture::new();
        assert_eq!(
            fixture.disk.write(0, &[0x31; 512]),
            Err(BlockError::Timeout)
        );
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
                c.registers.read32(DOORBELLS + 8),
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
            c.transfer(IO_READ, 1, 0, 256, BOUNCE_BYTES),
            Err(BlockError::Timeout)
        );
        assert!(c.bounce.bytes().iter().all(|byte| *byte == 0x9d));
        assert_eq!(c.io.submissions.bytes(), submission);
        assert_eq!(c.prp_list.bytes(), prps);
        assert_eq!(c.registers.read32(DOORBELLS + 8), doorbell);
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
            assert_eq!(c.registers.read32(DOORBELLS + 12), 0);
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
            .write32(STATUS, FATAL);
        let error = BlockError::Device { status: FATAL };
        assert_eq!(fixture.disk.write(0, &[0xa9; 512]), Err(error.clone()));
        fixture
            .disk
            .controller
            .borrow()
            .registers
            .write32(STATUS, 0);
        assert_eq!(fixture.disk.flush(), Err(error));
        let c = fixture.disk.controller.borrow();
        assert_eq!((c.command_id, c.io.tail, c.io.head), (0, 0, 0));
        assert!(c.io.submissions.bytes().iter().all(|byte| *byte == 0));
        assert!(c.bounce.bytes().iter().all(|byte| *byte == 0));
        assert_eq!(c.registers.read32(DOORBELLS + 8), 0);
    }
}
