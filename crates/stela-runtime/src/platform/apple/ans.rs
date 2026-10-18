//! ANS2's AP-facing NVMe controller; no coprocessor firmware is executed.
//!
//! Evidence: Linux `drivers/nvme/host/apple.c` documents linear SQ doorbells
//! (0x2490c/0x24910), 64 shared tags, 128-byte NVMMU TCBs at bases
//! 0x28108/0x28110, invalidation/status 0x28118/0x28120, and BOOT_STATUS
//! 0x1300 = 0xde71ce55. NVMe 1.4 sections 3, 4, 5 and 6 define the base
//! registers, PRPs, admin commands, completions and NVM read/write/flush.
//! The 26A434 J473AP kernel uses `AppleANS2CGv2Controller` (file 0x3de4954):
//! `GetIOSQES` (0x3de51d0) returns 6; `SetupAdminQueue` (0x3de502c) and
//! `Enable{Completion,Submission}Queue` (0x3de54a4/0x3de5608) ask SPTM to
//! program the NVMe registers. The register accessors at 0x3ddee24..64 use
//! ANS `reg[3]`; its `nvme-interrupt-idx` selects the completion interrupt.
//!
//! Stela's die choices: NVMe 1.3, one I/O queue, 64 tags, 4/16 KiB memory
//! pages, 4 KiB LBAs, 1 MiB maximum transfer, no volatile write cache, no
//! optional encryption/SHA/firmware download or asynchronous events. Identity
//! strings identify Stela rather than impersonating a physical Apple SSD.
//! The boot stage starts RTKit before handoff; the ASC uses the existing
//! management protocol with no application endpoints (ANS NVMe uses MMIO).
//! Undescribed registers, commands, fields and cryptographic effects refuse.
mod commands;
mod die;
mod namespace;
mod prp;

use super::{
    bus::{Access, Direction, MmioDevice, MmioError, Width, refuse},
    interrupt::{AicInput, Wire},
};
use crate::platform::{dma::Port, pc::block::BlockDevice};
use alloc::{boxed::Box, collections::VecDeque};
pub use namespace::Description;
use namespace::Medium;
use prp::dma_error;

const NAME: &str = "ans2";
pub const TAGS: u16 = 64;
pub const REGISTER_BYTES: u64 = 0x28134;
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
const MAX_PENDING: u64 = 0x1210;
const BOOT_STATUS: u64 = 0x1300;
const MODESEL: u64 = 0x1304;
const BASE_CID: u64 = 0x1308;
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
const CONFIG_MASK: u32 = ENABLE | (0xf << 7) | SHUTDOWN | (0xf << 16) | (0xf << 20);
const ENTRY_SIZES: u32 = (6 << 16) | (4 << 20);
const READY: u32 = 1;
const SHUTDOWN_COMPLETE: u32 = 2 << 2;
const CAPABILITIES: u64 = (TAGS as u64 - 1) | (1 << 16) | (1 << 24) | (1 << 37) | (2 << 52);
const VERSION: u64 = 0x0001_0300;
const BOOT_OK: u64 = 0xde71_ce55;
const COMMAND_BYTES: u64 = 64;
const COMPLETION_BYTES: u64 = 16;
const TCB_BYTES: u64 = 128;

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

pub struct Ans {
    medium: Medium,
    config: u32,
    status: u32,
    interrupt_mask: bool,
    irq: Option<AicInput>,
    irq_level: bool,
    aqa: u32,
    queues: [Queue; 2],
    tcb_bases: [u64; 2],
    tcb_count: u16,
    valid: [bool; TAGS as usize],
    pending: VecDeque<(usize, u16)>,
    linear: bool,
    max_pending: u32,
    modesel: u32,
    auto_queue: bool,
    shutdown: bool,
    /// NVMe feature state, indexed by the small standard feature IDs.
    features: [u32; 12],
    timestamp: u64,
    os_build: [u8; 16],
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
            interrupt_mask: false,
            irq,
            irq_level: false,
            aqa: 0,
            queues: [Queue::default(); 2],
            tcb_bases: [0; 2],
            tcb_count: TAGS - 1,
            valid: [false; TAGS as usize],
            pending: VecDeque::new(),
            linear: false,
            max_pending: 0,
            modesel: 0,
            auto_queue: false,
            shutdown: false,
            features: [0; 12],
            timestamp: 0,
            os_build: [0; 16],
        })
    }

    pub fn pending(&self) -> bool {
        self.shutdown || !self.pending.is_empty()
    }

    fn page(&self) -> u64 {
        4096 << ((self.config >> 7) & 0xf)
    }

    fn update_irq(&mut self, access: &mut Access<'_>) {
        let level =
            !self.interrupt_mask && self.queues.iter().any(|q| q.interrupt && q.pending != 0);
        if self.irq_level != level {
            self.irq_level = level;
            if let Some(irq) = self.irq {
                access.interrupts.set_level(Wire::Aic(irq), level);
            }
        }
    }

    fn configure(&mut self, value: u32) -> Result<(), &'static str> {
        if value & SHUTDOWN == SHUTDOWN {
            return Err("ANS reserved shutdown notification");
        }
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
                if sq_entries > TAGS
                    || cq_entries > TAGS
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
            if value & SHUTDOWN == SHUTDOWN {
                return Err("ANS reserved shutdown notification");
            }
            if value & SHUTDOWN != 0 {
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
        }
        self.config = value;
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
        let limit = (self.max_pending >> (queue * 16)) & 0xffff;
        if limit != 0 && self.pending.iter().filter(|&&(q, _)| q == queue).count() >= limit as usize
        {
            return Err("ANS pending commands exceed the programmed queue limit");
        }
        self.valid[tag as usize] = true;
        self.pending.push_back((queue, tag));
        Ok(())
    }

    /// Complete submitted commands through the board's SART port before the
    /// next guest access. NVMMU TCB PRPs are authoritative; their encryption
    /// and hash fields must be zero until those engines are modeled.
    pub fn run(&mut self, port: &mut Port<'_, '_>) -> Result<(), MmioError> {
        while let Some(&(queue, tag)) = self.pending.front() {
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
            if tcb[0] != 0 && tcb[0] != command.opcode()
                || u16::from(tcb[2]) != tag
                || tcb[3] != 0
                || tcb[6..24].iter().chain(tcb[40..].iter()).any(|&b| b != 0)
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
            let outcome = self.execute(queue, &command, port).map_err(error)?;
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
            (MODESEL, Width::Word) => u64::from(self.modesel),
            (AUTO_QUEUE, Width::Word) => u64::from(self.auto_queue),
            (MAX_PENDING, Width::Word) => u64::from(self.max_pending),
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
        if width == Width::Double {
            if self.config & ENABLE != 0 {
                return Err(error("ANS queue/TCB base changed while enabled"));
            }
            if !value.is_multiple_of(4096) {
                return Err(error("ANS queue/TCB base is not page-aligned"));
            }
            match offset {
                ASQ => self.queues[0].sq = value,
                ACQ => self.queues[0].cq = value,
                ADMIN_TCB => self.tcb_bases[0] = value,
                IO_TCB => self.tcb_bases[1] = value,
                _ => return Err(error("ANS 64-bit register without a model")),
            }
            return Ok(());
        }
        if width != Width::Word || value > u64::from(u32::MAX) {
            return Err(error("ANS register requires a 32-bit word"));
        }
        let value = value as u32;
        match offset {
            CC => self.configure(value).map_err(error)?,
            INTMS | INTMC if value & !1 == 0 => {
                self.interrupt_mask = if offset == INTMS {
                    self.interrupt_mask || value != 0
                } else {
                    self.interrupt_mask && value == 0
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
            MAX_PENDING if value & 0xffff <= u32::from(TAGS) && value >> 16 <= u32::from(TAGS) => {
                self.max_pending = value
            }
            MODESEL if value == 0 => self.modesel = value,
            AUTO_QUEUE if value == 0 => self.auto_queue = false,
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
        self.update_irq(access);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        apple::{interrupt::InterruptLatch, sart::Sart},
        dma::{Memory, tests::Ram},
        pc::block::tests::RamDisk,
    };
    use alloc::vec;
    const RAM: u64 = 0x8_0000_0000;
    const SQ: u64 = RAM;
    const CQ: u64 = RAM + 0x1000;
    const TCB: u64 = RAM + 0x2000;
    const IOSQ: u64 = RAM + 0x4000;
    const IOCQ: u64 = RAM + 0x5000;
    const IOTCB: u64 = RAM + 0x6000;
    const DATA: u64 = RAM + 0x9000;
    const IRQ: AicInput = AicInput::new(0, 724);

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
                sart: Sart::default(),
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
            self.ans.run(&mut Port {
                iommu: &mut self.sart,
                stream: 0,
                memory: &mut self.ram,
                access: &mut access,
            })
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
        rig.write(INTMS, 1).unwrap();
        assert!(!rig.latch.is_asserted(Wire::Aic(IRQ)));
        rig.write(INTMC, 1).unwrap();
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
    fn sart_faults_encryption_and_unknown_commands_never_complete() {
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
        assert_eq!(rig.bytes(CQ, 16), vec![0; 16]);
        let mut rig = Rig::new();
        rig.sart
            .write(0, Width::Word, 0, &mut Access::new(0, 0, &mut rig.latch))
            .unwrap();
        assert!(rig.submit(0, 0, 6, 0, DATA, [1, 0, 0, 0, 0, 0]).is_err());
        assert_eq!(rig.bytes(CQ, 16), vec![0; 16]);
        assert!(!rig.latch.is_asserted(Wire::Aic(IRQ)));
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
            rig.write(CC, u64::from(ENTRY_SIZES | ENABLE | 3 << 14))
                .is_err()
        );
        assert_eq!(rig.ans.config, ENTRY_SIZES | ENABLE);
        assert!(rig.write(MODESEL, 1).is_err());
        assert!(rig.write(AUTO_QUEUE, 1).is_err());
        assert!(rig.write(ADMIN_HEAD, 3).is_err());
    }
}
