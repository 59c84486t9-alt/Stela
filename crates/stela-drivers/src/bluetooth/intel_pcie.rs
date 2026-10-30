// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2024 Intel Corporation
//! Intel PCIe Bluetooth DMA/MMIO transport. No USB binding, H4 wrapper or
//! synthetic HCI completion is used. A ROM transport is not initialized radio
//! firmware: image selection/authentication and the guest frontend are separate.
pub mod firmware;
mod memory;
pub mod native;
mod packet;
mod registers;
#[cfg(test)]
mod tests;
use crate::{
    block::BlockError,
    bus::{dma::DmaAllocator, pci::Address},
};
use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use core::{
    mem::ManuallyDrop,
    sync::atomic::{Ordering, fence},
};
use memory::*;
pub use packet::{Kind, Packet};
use registers::*;
pub type Result<T> = core::result::Result<T, Error>;
pub const DEVICE_IDS: &[u16] = &[0x4d76, 0xa876, 0xe376, 0xe476, 0xd346, 0x6e74];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub address: Address,
    pub vendor: u16,
    pub device: u16,
    pub subsystem_vendor: u16,
    pub subsystem_device: u16,
}
/// The native PCI/config/MMIO/IRQ/requester lifetime, or an explicit
/// independent hardware model. Implementations must not synthesize MMIO/DMA
/// completions or turn a masked interrupt into a stopped-device observation.
///
/// # Safety
/// The identity is the exclusively owned Function. BAR0's required byte
/// accesses through offset0x28a5 are UC mapped and kept. One real MSI-X
/// entry0 and its registered callback/message belong to this same PCI/reset
/// epoch; there is no MSI/INTx fallback. All old callbacks and firmware owners
/// are drained, all callbacks only schedule this serialized process/deferred
/// service, and shared hardware reset is authorized by the platform coordinator.
/// Supplied DMA pages are boot-lifetime reserved, coherent and identity-addressed
/// for this requester. Native owners cannot be revoked while kept.
/// `retire_vector_zero` must mask and drain the real route/callback/work lifetime;
/// it does not certify that device DMA has stopped. Drop must keep any failed
/// physical ownership rather than releasing a still-active route/mapping.
pub unsafe trait Platform: 'static {
    fn identity(&self) -> Identity;
    fn read32(&mut self, offset: usize) -> Result<u32>;
    fn write32(&mut self, offset: usize, value: u32) -> Result<()>;
    fn write8(&mut self, offset: usize, value: u8) -> Result<()>;
    fn now_us(&self) -> u64;
    fn arm_vector_zero(&mut self) -> Result<()>;
    fn retire_vector_zero(&mut self) -> Result<()>;
    /// Consume the work flag before reading causes. A callback during service
    /// must remain pending for the next serialized service pass.
    fn service_begin(&mut self) -> Result<()> {
        Ok(())
    }
    /// Restore a source masked by the hard-IRQ callback after this
    /// serialized completion/cause service. Pure polling/model owners need no
    /// extra operation beyond the device's automask acknowledgment.
    fn service_complete(&mut self) -> Result<()> {
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Allocated,
    Rom,
    Iml,
    Operational,
    Closed,
    Failed,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub function: u32,
    pub boot_stage: u32,
    pub image_response: u32,
    pub fh_cause: u32,
    pub hw_cause: u32,
    pub mailbox_status: u32,
    pub mailboxes: [Option<u32>; 4],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported(&'static str),
    State(State),
    Dma(BlockError),
    Mmio(&'static str),
    Native(native::Error),
    Timeout(&'static str),
    Protocol {
        requirement: &'static str,
        observed: u64,
    },
    Controller(Box<Snapshot>),
    Packet {
        requirement: &'static str,
        raw: Vec<u8>,
    },
    Cleanup {
        cause: Box<Error>,
        cleanup: Box<Error>,
    },
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Intel PCIe Bluetooth {self:?}")
    }
}
impl core::error::Error for Error {}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResetKind {
    Intel,
    Hci,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Pending {
    descriptor: u16,
    next: u16,
    complete: bool,
    reset: Option<ResetKind>,
    alive_at_start: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxReceipt {
    pub descriptor: u16,
    pub next_index: u16,
    pub alive: Option<Snapshot>,
}
/// DMA storage stays reserved for the boot. On failed physical retirement
/// the platform/IRQ/MMIO lifetime is leaked too. Safe APIs never
/// reopen or rewrite that uncertain owner.
pub struct Transport<P: Platform> {
    platform: ManuallyDrop<P>,
    identity: Identity,
    memory: Memory,
    state: State,
    snapshot: Snapshot,
    hardware_revision: Option<u32>,
    radio_id: Option<u32>,
    rx_owned: [bool; RX_COUNT],
    pending: Option<Pending>,
    received: VecDeque<Packet>,
    alive: u64,
    boot_notification: bool,
    awaiting_d0: bool,
    retirement_attempted: bool,
    retired: bool,
    retirement_error: Option<Box<Error>>,
    fault: Option<Box<Error>>,
    fault_snapshot: Option<Box<Snapshot>>,
}
impl<P: Platform> Transport<P> {
    pub fn new(platform: P, dma: &mut dyn DmaAllocator) -> Result<Self> {
        let identity = platform.identity();
        if identity.vendor != 0x8086 || !DEVICE_IDS.contains(&identity.device) {
            return Err(Error::Unsupported("source Intel PCIe Bluetooth identity"));
        }
        let memory = Memory::new(dma)?;
        Ok(Self {
            platform: ManuallyDrop::new(platform),
            identity,
            memory,
            state: State::Allocated,
            snapshot: Snapshot::default(),
            hardware_revision: None,
            radio_id: None,
            rx_owned: [false; RX_COUNT],
            pending: None,
            received: VecDeque::new(),
            alive: 0,
            boot_notification: false,
            awaiting_d0: false,
            retirement_attempted: false,
            retired: false,
            retirement_error: None,
            fault: None,
            fault_snapshot: None,
        })
    }
    pub fn identity(&self) -> Identity {
        self.identity
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn fault_snapshot(&self) -> Option<&Snapshot> {
        self.fault_snapshot.as_deref()
    }
    pub fn fault(&self) -> Option<&Error> {
        self.fault.as_deref()
    }
    pub fn hardware_revision(&self) -> Option<u32> {
        self.hardware_revision
    }
    pub fn radio_id(&self) -> Option<u32> {
        self.radio_id
    }
    fn read(&mut self, offset: usize) -> Result<u32> {
        self.platform.read32(offset)
    }
    fn write(&mut self, offset: usize, value: u32) -> Result<()> {
        self.platform.write32(offset, value)
    }
    fn delay(&self, us: u64) {
        let start = self.platform.now_us();
        while self.platform.now_us().wrapping_sub(start) < us {
            crate::waiting();
            core::hint::spin_loop();
        }
    }
    fn update_function(&mut self, clear: u32, set: u32) -> Result<u32> {
        let value = self.read(FUNC)?;
        self.snapshot.function = value;
        if value == u32::MAX {
            return Err(Error::Mmio("unreadable function control"));
        }
        let value = (value & !clear) | set;
        self.write(FUNC, value)?;
        Ok(value)
    }
    fn reset_device(&mut self) -> Result<()> {
        self.update_function(ENABLE | MAC_INIT | FUNC_INIT, MASTER_DISCONNECT)?;
        let mut stopped = false;
        for _ in 0..3 {
            let value = self.read(FUNC)?;
            self.snapshot.function = value;
            if value != u32::MAX && value & MASTER_STOPPED != 0 {
                stopped = true;
                break;
            }
            self.delay(10_000);
        }
        if !stopped {
            return Err(Error::Timeout(
                "actual bus-master disconnect acknowledgment",
            ));
        }
        self.delay(10_000);
        self.update_function(ENABLE | MAC_INIT | FUNC_INIT, RESET)?;
        self.delay(10_000);
        self.snapshot.function = self.read(FUNC)?;
        self.snapshot.boot_stage = self.read(BOOT)?;
        if self.snapshot.boot_stage != 0 {
            return Err(Error::Protocol {
                requirement: "actual reset boot stage zero",
                observed: u64::from(self.snapshot.boot_stage),
            });
        }
        Ok(())
    }
    pub fn start(&mut self) -> Result<()> {
        if self.state != State::Allocated {
            return Err(Error::State(self.state));
        }
        match self.start_inner() {
            Ok(()) => Ok(()),
            Err(e) => Err(self.fail(e)),
        }
    }
    fn start_inner(&mut self) -> Result<()> {
        self.reset_device()?;
        for cause in [0, 1, 0x20, 0x23, 0x25] {
            self.platform.write8(IVAR + cause, 0x80)?;
        }
        let fh = self.read(FH_MASK)?;
        let hw = self.read(HW_MASK)?;
        self.write(FH_MASK, fh & !FH_ENABLED)?;
        self.write(HW_MASK, hw & !HW_ENABLED)?;
        self.platform.arm_vector_zero()?;
        fence(Ordering::Release);
        let ci = self.memory.pool.physical() + CI as u64;
        self.write(CI_LOW, ci as u32)?;
        self.write(CI_HIGH, (ci >> 32) as u32)?;
        if self.identity.device == 0x4d76 {
            self.delay(50_000);
        }
        self.update_function(FUNC_INIT | MASTER_DISCONNECT | RESET, ENABLE | MAC_INIT)?;
        self.update_function(0, FUNC_INIT)?;
        self.snapshot.function = self.read(FUNC)?;
        let start = self.platform.now_us();
        while self.alive == 0 {
            self.service()?;
            if self.platform.now_us().wrapping_sub(start) >= 3_000_000 {
                return Err(Error::Timeout("actual ROM GP0 alive cause"));
            }
            crate::waiting();
            core::hint::spin_loop();
        }
        if self.snapshot.boot_stage & ROM == 0 {
            return Err(Error::Protocol {
                requirement: "ROM boot stage after actual GP0",
                observed: u64::from(self.snapshot.boot_stage),
            });
        }
        self.hardware_revision = Some(self.read(HW_REV)?);
        self.radio_id = Some(self.read(RF_ID)?);
        if self.hardware_revision == Some(u32::MAX) || self.radio_id == Some(u32::MAX) {
            return Err(Error::Mmio("unreadable CNVI/CNVR identity"));
        }
        self.state = State::Rom;
        self.post_initial_rx()
    }
    fn post_rx(&mut self) -> Result<()> {
        let index = usize::from(self.memory.index(TR_HEAD, 1));
        if index >= RX_COUNT || self.rx_owned[index] {
            return Err(Error::Protocol {
                requirement: "free actual RX descriptor and buffer",
                observed: index as u64,
            });
        }
        let mut d = [0; 16];
        d[..4].copy_from_slice(&(index as u32).to_le_bytes());
        d[8..]
            .copy_from_slice(&(self.memory.rx.physical() + (index * BUFFER) as u64).to_le_bytes());
        self.memory.descriptor(FRBD + index * 16, &d);
        self.rx_owned[index] = true;
        let next = ((index + 1) % RX_COUNT) as u16;
        self.memory.set_index(TR_HEAD, 1, next);
        fence(Ordering::Release);
        self.write(DOORBELL, RX_DB | u32::from(next))
    }
    fn post_initial_rx(&mut self) -> Result<()> {
        for _ in 0..RX_COUNT - 3 {
            self.post_rx()?;
        }
        Ok(())
    }
    fn read_snapshot(&mut self) -> Result<()> {
        self.snapshot.boot_stage = self.read(BOOT)?;
        self.snapshot.image_response = self.read(IMAGE)?;
        self.snapshot.mailbox_status = self.read(MAILBOX_STATUS)?;
        for (i, &offset) in MAILBOX.iter().enumerate() {
            if self.snapshot.mailbox_status & (1 << i) != 0 {
                self.snapshot.mailboxes[i] = Some(self.read(offset)?);
            }
        }
        if self.snapshot.boot_stage & (LOCKDOWN | ABORT | HALTED) != 0 {
            return Err(Error::Controller(Box::new(self.snapshot.clone())));
        }
        // WARNING is held in the snapshot; the source does not stop solely
        // for its warning bit. Abort/lockdown/halt are terminal.
        let _warning = self.snapshot.boot_stage & WARNING;
        Ok(())
    }
    fn tx_completions(&mut self) -> Result<()> {
        let head = usize::from(self.memory.index(CR_HEAD, 0));
        let mut tail = usize::from(self.memory.index(CR_TAIL, 0));
        if head >= TX_COUNT || tail >= TX_COUNT {
            return Err(Error::Protocol {
                requirement: "bounded TX completion indices",
                observed: ((head as u64) << 32) | tail as u64,
            });
        }
        fence(Ordering::Acquire);
        while tail != head {
            let d = self.memory.pool.read::<u32>(URBD0 + tail * 4);
            let pending = self.pending.as_mut().ok_or(Error::Protocol {
                requirement: "actual in-flight TX for completion",
                observed: u64::from(d),
            })?;
            // Donor URBD0 says TFD index+1; send_sync publishes that modulo32
            // head, and its reader rejects indices>=32. Require this wrapped
            // next index, including0 for descriptor31, to reject stale tickets.
            if pending.complete
                || d & 0xffff != u32::from(pending.next)
                || (d >> 16) & 0xff != 0
                || (d >> 24) & 0xf != 1
                || d >> 31 != 1
            {
                return Err(Error::Protocol {
                    requirement: "matching source URBD0 index/queue/count/immediate",
                    observed: u64::from(d),
                });
            }
            pending.complete = true;
            tail = (tail + 1) % TX_COUNT;
            self.memory.set_index(CR_TAIL, 0, tail as u16);
        }
        Ok(())
    }
    fn rx_completions(&mut self) -> Result<()> {
        let head = usize::from(self.memory.index(CR_HEAD, 1));
        let mut tail = usize::from(self.memory.index(CR_TAIL, 1));
        if head >= RX_COUNT || tail >= RX_COUNT {
            return Err(Error::Protocol {
                requirement: "bounded RX completion indices",
                observed: ((head as u64) << 32) | tail as u64,
            });
        }
        fence(Ordering::Acquire);
        while tail != head {
            let d = self.memory.pool.read::<u32>(URBD1 + tail * 4);
            let tag = (d & 0xffff) as usize;
            if tag >= RX_COUNT || !self.rx_owned[tag] {
                return Err(Error::Protocol {
                    requirement: "completion for an actually posted RX tag",
                    observed: u64::from(d),
                });
            }
            self.rx_owned[tag] = false;
            let packet =
                packet::receive(&self.memory.rx.bytes()[tag * BUFFER..(tag + 1) * BUFFER], d)?;
            if self.received.len() >= 128 {
                return Err(Error::Packet {
                    requirement: "bounded retained PCIe RX queue",
                    raw: packet.bytes,
                });
            }
            if packet.kind == Kind::Event
                // intel_bootup has six payload bytes after vendor subtype 02.
                // A matching subtype alone cannot authorize the D0 transition.
                && packet.bytes.len() == 9
                && packet.bytes[0] == 0xff
                && packet.bytes[1] == 7
                && packet.bytes[2] == 2
            {
                self.boot_notification = true;
            }
            self.received.push_back(packet);
            tail = (tail + 1) % RX_COUNT;
            self.memory.set_index(CR_TAIL, 1, tail as u16);
            self.post_rx()?;
        }
        Ok(())
    }
    fn service(&mut self) -> Result<()> {
        self.platform.service_begin()?;
        let fh = self.read(FH_CAUSE)?;
        let hw = self.read(HW_CAUSE)?;
        self.snapshot.fh_cause = fh;
        self.snapshot.hw_cause = hw;
        if fh == u32::MAX || hw == u32::MAX {
            return Err(Error::Mmio("unreadable interrupt cause registers"));
        }
        self.write(FH_CAUSE, fh)?;
        self.write(HW_CAUSE, hw)?;
        if fh | hw == 0 {
            self.write(AUTOMASK, 1)?;
            return self.platform.service_complete();
        }
        if hw & ((1 << 3) | (1 << 5)) != 0 {
            self.read_snapshot()?;
            return Err(Error::Controller(Box::new(self.snapshot.clone())));
        }
        if hw & (1 << 1) != 0 {
            self.read_snapshot()?;
            return Err(Error::Unsupported("GP1 diagnostic mailbox service"));
        }
        self.tx_completions()?;
        self.rx_completions()?;
        if hw & 1 != 0 {
            self.read_snapshot()?;
            self.alive = self.alive.wrapping_add(1);
            if let Some(pending) = self.pending
                && pending.reset.is_some()
            {
                if !pending.complete {
                    return Err(Error::Protocol {
                        requirement: "actual TX completion before queue-reset GP0",
                        observed: self.alive,
                    });
                }
                let expected = match pending.reset.unwrap() {
                    ResetKind::Intel => self.snapshot.boot_stage & (IML | OP) != 0,
                    ResetKind::Hci => {
                        self.snapshot.boot_stage & OP != 0 && self.snapshot.boot_stage & D3 == 0
                    }
                };
                if !expected {
                    return Err(Error::Protocol {
                        requirement: "reset-specific actual GP0 boot stage",
                        observed: u64::from(self.snapshot.boot_stage),
                    });
                }
                self.memory.reset_indices();
                self.rx_owned.fill(false);
                self.post_initial_rx()?;
                if self.snapshot.boot_stage & OP != 0 {
                    self.state = State::Operational;
                    self.awaiting_d0 = pending.reset == Some(ResetKind::Intel);
                } else {
                    self.state = State::Iml;
                }
            }
        }
        self.write(AUTOMASK, 1)?;
        self.platform.service_complete()
    }
    fn active(&self) -> Result<()> {
        if matches!(self.state, State::Rom | State::Iml | State::Operational) {
            Ok(())
        } else {
            Err(Error::State(self.state))
        }
    }
    /// Drain real completion/cause state in serialized deferred context. Empty
    /// means no traffic, not an invented command event or readiness indication.
    pub fn poll(&mut self) -> Result<Vec<Packet>> {
        self.active()?;
        if let Err(e) = self.service() {
            return Err(self.fail(e));
        }
        Ok(self.received.drain(..).collect())
    }
    pub fn send(&mut self, kind: Kind, bytes: &[u8]) -> Result<TxReceipt> {
        self.active()?;
        if kind == Kind::Event
            || bytes.len() > BUFFER - 4
            || packet::length(kind, bytes)? != bytes.len()
        {
            return Err(Error::Packet {
                requirement: "one bounded complete outbound HCI packet",
                raw: bytes.to_vec(),
            });
        }
        if self.pending.is_some() {
            return Err(Error::Unsupported("one actual TX owner at a time"));
        }
        match self.send_inner(kind, bytes) {
            Ok(r) => Ok(r),
            Err(e) => Err(self.fail(e)),
        }
    }
    fn send_inner(&mut self, kind: Kind, bytes: &[u8]) -> Result<TxReceipt> {
        self.service()?;
        let start = self.platform.now_us();
        let index = usize::from(self.memory.index(TR_HEAD, 0));
        if index >= TX_COUNT {
            return Err(Error::Protocol {
                requirement: "bounded TX descriptor index",
                observed: index as u64,
            });
        }
        let offset = index * BUFFER;
        self.memory.tx.bytes_mut()[offset..offset + 4]
            .copy_from_slice(&(kind as u32).to_le_bytes());
        self.memory.tx.bytes_mut()[offset + 4..offset + 4 + bytes.len()].copy_from_slice(bytes);
        let mut d = [0; 16];
        d[1..3].copy_from_slice(&((bytes.len() + 4) as u16).to_le_bytes());
        d[4..12].copy_from_slice(&(self.memory.tx.physical() + offset as u64).to_le_bytes());
        self.memory.descriptor(TFD + index * 16, &d);
        let next = ((index + 1) % TX_COUNT) as u16;
        let opcode = if kind == Kind::Command {
            Some(u16::from_le_bytes([bytes[0], bytes[1]]))
        } else {
            None
        };
        let reset = match opcode {
            Some(0xfc01) => Some(ResetKind::Intel),
            Some(0x0c03) => Some(ResetKind::Hci),
            _ => None,
        };
        if self.platform.now_us().wrapping_sub(start) >= 500_000 {
            return Err(Error::Timeout("TX publication deadline"));
        }
        self.pending = Some(Pending {
            descriptor: index as u16,
            next,
            complete: false,
            reset,
            alive_at_start: self.alive,
        });
        if reset.is_some() {
            self.boot_notification = false;
        }
        self.memory.set_index(TR_HEAD, 0, next);
        fence(Ordering::Release);
        if self.platform.now_us().wrapping_sub(start) >= 500_000 {
            return Err(Error::Timeout("TX publication deadline"));
        }
        self.write(DOORBELL, u32::from(next))?;
        while !self.pending.unwrap().complete {
            self.service()?;
            if self.platform.now_us().wrapping_sub(start) >= 500_000 {
                return Err(Error::Timeout("actual TX URBD0 completion"));
            }
            crate::waiting();
            core::hint::spin_loop();
        }
        let pending = self.pending.unwrap();
        let alive = if reset.is_some() {
            let start = self.platform.now_us();
            while self.alive == pending.alive_at_start {
                self.service()?;
                if self.platform.now_us().wrapping_sub(start) >= 3_000_000 {
                    return Err(Error::Timeout("actual reset GP0 alive cause"));
                }
                crate::waiting();
                core::hint::spin_loop();
            }
            Some(self.snapshot.clone())
        } else {
            None
        };
        self.pending = None;
        Ok(TxReceipt {
            descriptor: index as u16,
            next_index: next,
            alive,
        })
    }
    /// After the real OP boot notification, request D0 and observe a
    /// subsequent GP0. IML has no D0 handshake and cannot call this method.
    pub fn enter_d0(&mut self) -> Result<Snapshot> {
        self.active()?;
        if self.state != State::Operational || !self.awaiting_d0 || !self.boot_notification {
            return Err(Error::Unsupported("actual OP boot notification before D0"));
        }
        match self.enter_d0_inner() {
            Ok(s) => Ok(s),
            Err(e) => Err(self.fail(e)),
        }
    }
    fn enter_d0_inner(&mut self) -> Result<Snapshot> {
        // Consume preexisting GP0 causes before recording the request baseline;
        // an older OP notification cannot acknowledge the new SLEEP write.
        self.service()?;
        if self.state != State::Operational
            || !self.awaiting_d0
            || !self.boot_notification
            || self.snapshot.boot_stage & OP == 0
        {
            return Err(Error::Protocol {
                requirement: "current OP boot context before D0 request",
                observed: u64::from(self.snapshot.boot_stage),
            });
        }
        let alive = self.alive;
        let start = self.platform.now_us();
        self.write(SLEEP, 0)?;
        while self.alive == alive {
            self.service()?;
            if self.platform.now_us().wrapping_sub(start) >= 3_000_000 {
                return Err(Error::Timeout("actual D0 GP0 alive cause"));
            }
            crate::waiting();
            core::hint::spin_loop();
        }
        if self.snapshot.boot_stage & OP == 0 || self.snapshot.boot_stage & D3 != 0 {
            return Err(Error::Controller(Box::new(self.snapshot.clone())));
        }
        self.awaiting_d0 = false;
        Ok(self.snapshot.clone())
    }
    fn retire(&mut self) -> Result<()> {
        if self.retirement_attempted {
            return self
                .retirement_error
                .as_deref()
                .cloned()
                .map_or(Ok(()), Err);
        }
        self.retirement_attempted = true;
        let result: Result<()> = (|| {
            self.write(FH_MASK, u32::MAX)?;
            self.write(HW_MASK, u32::MAX)?;
            // The IRQ registry's source quiescence requires device DMA
            // stop, not just masked MSI-X. Stop/reset first; its source rereads
            // those acknowledgments before callback/CPU/work retirement. Even
            // a failed stop still attempts the real route mask/drain, whose
            // source must refuse quiescence if the acknowledgments are absent.
            let stopped = self.reset_device();
            let interrupts = self.platform.retire_vector_zero();
            match (stopped, interrupts) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
                (Err(cause), Err(cleanup)) => Err(Error::Cleanup {
                    cause: Box::new(cause),
                    cleanup: Box::new(cleanup),
                }),
            }
        })();
        match result {
            Ok(()) => {
                self.retired = true;
                Ok(())
            }
            Err(e) => {
                self.retirement_error = Some(Box::new(e.clone()));
                Err(e)
            }
        }
    }
    fn fail(&mut self, cause: Error) -> Error {
        self.state = State::Failed;
        if self.fault_snapshot.is_none() {
            self.fault_snapshot = Some(Box::new(self.snapshot.clone()));
        }
        let error = match self.retire() {
            Ok(()) => cause,
            Err(cleanup) => Error::Cleanup {
                cause: Box::new(cause),
                cleanup: Box::new(cleanup),
            },
        };
        if self.fault.is_none() {
            self.fault = Some(Box::new(error.clone()));
        }
        error
    }
    pub fn close(&mut self) -> Result<()> {
        if self.state == State::Closed {
            return Ok(());
        }
        match self.retire() {
            Ok(()) => {
                if self.state != State::Failed {
                    self.state = State::Closed;
                }
                Ok(())
            }
            Err(e) => {
                self.state = State::Failed;
                if self.fault.is_none() {
                    self.fault = Some(Box::new(e.clone()));
                }
                if self.fault_snapshot.is_none() {
                    self.fault_snapshot = Some(Box::new(self.snapshot.clone()));
                }
                Err(e)
            }
        }
    }
}
impl<P: Platform> Drop for Transport<P> {
    fn drop(&mut self) {
        let _ = self.close();
        if self.retired {
            // SAFETY: route/callback drain plus bus-master disconnect
            // acknowledgment and reset boot-stage0 proved physical retirement.
            unsafe {
                ManuallyDrop::drop(&mut self.platform);
            }
        }
        // Otherwise keep the platform owner forever. DMA pages are
        // permanently reserved independently; no destructor can recycle them.
    }
}
