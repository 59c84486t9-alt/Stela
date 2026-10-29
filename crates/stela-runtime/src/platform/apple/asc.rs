//! The ASC coprocessor wrapper (`iop,ascwrap-v4`; ADT `/arm-io/<iop>` `reg[0]`):
//! the CPU control of an RTKit coprocessor and its AP mailbox.
//!
//! The coprocessor's own software is emulated natively behind [`Firmware`]
//! (docs/target.md: RTKit coprocessors are emulated at their AP-facing
//! protocols); the wrapper only carries 128-bit messages and starts it.
//!
//! Documented by Linux `drivers/soc/apple/rtkit-helper.c` (`APPLE_ASC_CPU_CONTROL`
//! 0x44, `RUN` bit 4) and `drivers/mailbox/apple-mailbox.c` (the `asc` variant,
//! 0x8000 into the wrapper): A2I (AP to coprocessor) control 0x110, send
//! 0x800 and 0x808; I2A control 0x114, receive 0x830 and 0x838; control bit 16
//! FULL and bit 17 EMPTY; a message is two 64-bit words, the payload and the
//! endpoint in the low byte of the second, sent by the store of 0x808 and
//! consumed by the load of 0x838. The 26A434 J473AP `AppleASCWrapV4` accesses
//! exactly these registers (`_inbox` stores 0x8800 and 0x8808, `_outbox` loads
//! 0x8830 and 0x8838, `_getInboxEmpty`/`_getInboxFull` read 0x8110 bits 17/16,
//! `_runCPU` sets or clears 0x44 bit 4 and on stop also clears bit 5).
//! `getMailboxBulk` takes the number of waiting messages from I2A control
//! bits 23:20. Each received second word also snapshots the pre-pop count in
//! bits 55:52 (`getMailboxBulk`, kernel file 0x1badaa8); the driver uses
//! that snapshot to stop a bulk read after its last message. The full and
//! empty queries treat bits 19:18 as errors,
//! which the model never raises.
//!
//! The ADT lists four interrupts in the order of their AIC numbers rotated by
//! one pair (J473AP PMP: 0x275, 0x274, 0x277, 0x276); `AppleA7IOP` takes
//! index 1 as inbox empty and index 2 as outbox not empty. With Linux's order
//! of a wrapper's four consecutive lines (send empty, send not empty, receive
//! empty, receive not empty), index 0 is inbox not empty and index 3 outbox
//! empty. Every line is a level.
//!
//! Inferred, not documented:
//! - the native firmware takes each message as it is sent, so the inbox is
//!   always empty, which is the fastest permitted completion; a message sent
//!   while the coprocessor is stopped is refused, since nothing would drain it;
//! - `AppleASCWrapV4::_enableOutbox` sets 0x8114 bit 0 and leaves interrupt
//!   enables to its no-op `_enableOutboxInterrupt`, so bit 0 enables the
//!   outbox itself: the coprocessor's messages wait in it, invisible, until
//!   the AP enables it. 0x8110 bit 0 (`_getKICInboxEnabled`) is held;
//! - a load of an empty outbox is refused (the hardware underflows, which
//!   `AppleA7IOP::_outboxUnderflowCheck` treats as an error);
//! - clearing RUN halts native firmware rather than resetting it. A firmware
//!   must admit kept stop/resume explicitly; unsupported reset and
//!   power-loss flows still refuse. Mailbox controls, staged payload and
//!   queued responses survive a halt.
use alloc::boxed::Box;
use alloc::collections::{BTreeSet, VecDeque};
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::any::Any;
use stela_contracts::dma::Port;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction, stela_contracts::bus::Lifecycle,
    stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::bus::Transition, stela_contracts::bus::Width,
    stela_contracts::bus::refuse,
};
use {stela_contracts::interrupt::AicInput, stela_contracts::interrupt::Wire};

pub mod entry;
pub use entry::{Auxiliary, EntryFetch, EntryHandoff};

const NAME: &str = "asc";

const CPU_CONTROL: u64 = 0x44;
const RUN: u64 = 1 << 4;
/// Cleared with RUN on stop; its meaning is not documented, so it is held.
const CPU_CONTROL_HELD: u64 = 1 << 5;
const IDLE_STATUS: u64 = 0x8000;
const A2I_CONTROL: u64 = 0x8110;
const I2A_CONTROL: u64 = 0x8114;
const A2I_SEND0: u64 = 0x8800;
const A2I_SEND1: u64 = 0x8808;
const I2A_RECV0: u64 = 0x8830;
const I2A_RECV1: u64 = 0x8838;
const CONTROL_ENABLE: u64 = 1;
const CONTROL_FULL: u64 = 1 << 16;
const CONTROL_EMPTY: u64 = 1 << 17;
/// The I2A control's count of waiting messages, bits 23:20.
const OCCUPANCY_SHIFT: u32 = 20;
const OCCUPANCY_MAX: usize = 0xf;
const CONTROL_STATUS: u64 = CONTROL_FULL | CONTROL_EMPTY | (0xf << OCCUPANCY_SHIFT);
/// The second message word holds the endpoint in its low byte.
const ENDPOINT: u64 = 0xff;

/// The wrapper's register span, through the mailbox.
pub const WRAPPER_BYTES: u64 = 0x8840;

/// One mailbox message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message {
    pub endpoint: u8,
    pub payload: u64,
}

/// A machine transition a coprocessor carries out for the AP, such as the
/// SMC's restart and standby commands: the device and its reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionRequest {
    pub device: &'static str,
    pub transition: Transition,
    pub reason: &'static str,
}

/// The coprocessor's software, emulated natively.
pub trait Firmware: Any {
    /// Fetch through this backend's live allocation and selected IOP mapping
    /// owners. Success requires known instruction bytes, resolved PA,
    /// current mapping/ownership and applicable fetch access. A source hash,
    /// numerical address relation or native protocol peer is not that proof.
    /// ASC checks the result at handoff and before every start/resume; the
    /// same backend must keep the owners through its execution/use boundary.
    fn fetch_entry(&mut self, _iop: u64) -> Result<EntryFetch, &'static str> {
        Err("original coprocessor instruction fetch ownership is not modeled")
    }

    /// Validate loss of native volatile firmware state. Physical reset is
    /// distinct from an RTKit sleep request: no mailbox ACK is generated.
    fn check_reset(&self) -> Result<(), &'static str> {
        Err("coprocessor volatile-state reset is not modeled")
    }
    /// Cold reset after `check_reset` succeeded, without starting execution.
    fn reset(&mut self) -> Result<(), &'static str> {
        Err("coprocessor volatile-state reset is not modeled")
    }
    /// The coprocessor starts running; messages it sends go to `outbox`.
    /// Start/resume/receive output is provisional until Ok; a refusal must
    /// keep retryable native state and must not commit its success ACK.
    fn start(&mut self, outbox: &mut Vec<Message>) -> Result<(), &'static str>;
    /// Halt CPU execution while keeping firmware state. Validate before
    /// changing state: a refusal leaves RUN and the mailbox untouched.
    /// Autonomous hardware work must be settled or kept by its owner.
    fn stop(&mut self) -> Result<(), &'static str> {
        Err("firmware retained CPU stop is not modeled")
    }
    /// Resume after an accepted halt, preserving protocol state.
    /// This is distinct from cold `start`; refusal leaves the CPU halted.
    fn resume(&mut self, _outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        Err("firmware retained CPU resume is not modeled")
    }
    /// The AP sent `message`.
    fn receive(&mut self, message: Message, outbox: &mut Vec<Message>) -> Result<(), &'static str>;
    /// The coprocessor has bus-master work queued (DMA it began when it
    /// received a message), to run before the AP's next mailbox access. The
    /// default coprocessor masters no memory.
    fn dma_pending(&self) -> bool {
        false
    }
    /// Perform that queued DMA through `port`, pushing committed mailbox
    /// messages to `outbox`. Earlier output remains committed if a later
    /// transfer fails; keep unfinished native work for retry.
    fn dma(
        &mut self,
        _port: &mut Port<'_, '_>,
        _outbox: &mut Vec<Message>,
    ) -> Result<(), &'static str> {
        Ok(())
    }
    /// Committed asynchronous messages, collected at each device advance.
    /// Output appended before a later error remains visible; keep only
    /// unfinished native work so retry never duplicates an earlier event.
    fn poll(&mut self, _outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        Ok(())
    }
    /// A machine transition the AP's last message asked for, once.
    fn take_transition(&mut self) -> Option<TransitionRequest> {
        None
    }
    /// The coprocessor's own error reply to `message`, a request it does
    /// not implement (`reason`; docs/design/runtime.md "Unsupported
    /// operations"). `None`, the default, when its protocol has no error reply for that request: the request is then left
    /// unanswered, so the client's own timeout path runs.
    fn error_reply(&mut self, _message: Message, _reason: &'static str) -> Option<Vec<Message>> {
        None
    }
}

/// The wrapper's interrupt lines, in ADT `interrupts` order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Lines {
    pub inbox_not_empty: Option<AicInput>,
    pub inbox_empty: Option<AicInput>,
    pub outbox_not_empty: Option<AicInput>,
    pub outbox_empty: Option<AicInput>,
}

impl Lines {
    /// The lines of an ADT `interrupts` list of four AIC inputs.
    pub fn from_interrupts(irqs: [AicInput; 4]) -> Self {
        Self {
            inbox_not_empty: Some(irqs[0]),
            inbox_empty: Some(irqs[1]),
            outbox_not_empty: Some(irqs[2]),
            outbox_empty: Some(irqs[3]),
        }
    }
}

pub struct Asc {
    auxiliary: Auxiliary,
    firmware: Box<dyn Firmware>,
    lifecycle: LifecycleState,
    running: bool,
    /// RUN was cleared after firmware admitted a CPU halt.
    halted: bool,
    cpu_control: u64,
    a2i_control: u64,
    outbox_enabled: bool,
    send0: Option<u64>,
    /// The coprocessor's messages; the head is visible while the outbox is
    /// enabled.
    outbox: VecDeque<Message>,
    lines: Lines,
    /// Levels last reported, in [`Lines`] order.
    levels: [Option<bool>; 4],
    /// The endpoints and refusals answered degraded so far.
    reported: BTreeSet<(u8, &'static str)>,
    /// Reports not yet taken ([`Self::take_unmodeled`]).
    unmodeled: Vec<String>,
}

impl Asc {
    /// A wrapper whose coprocessor `running` already (started by the boot
    /// firmware) or waits for the AP to set RUN.
    pub fn new(
        mut firmware: Box<dyn Firmware>,
        running: bool,
        lines: Lines,
    ) -> Result<Self, &'static str> {
        let mut outbox = Vec::new();
        if running {
            firmware.start(&mut outbox)?;
        }
        Ok(Self {
            auxiliary: Auxiliary::unknown(running),
            firmware,
            lifecycle: LifecycleState {
                powered: true,
                clocked: true,
                quiesced: false,
                reset: false,
                retention: false,
            },
            running,
            halted: false,
            cpu_control: if running { RUN } else { 0 },
            a2i_control: 0,
            outbox_enabled: false,
            send0: None,
            outbox: outbox.into(),
            lines,
            levels: [None; 4],
            reported: BTreeSet::new(),
            unmodeled: Vec::new(),
        })
    }

    /// The requests answered degraded for the first time since the last
    /// call.
    pub fn take_unmodeled(&mut self) -> Vec<String> {
        core::mem::take(&mut self.unmodeled)
    }

    /// Emulated boot-chain handoff: native firmware is running and both
    /// mailboxes are enabled before the AP attaches. RTBuddy's preloaded
    /// path waits for HELLO without reinitializing those controls.
    pub fn booted(firmware: Box<dyn Firmware>, lines: Lines) -> Result<Self, &'static str> {
        let mut asc = Self::new(firmware, true, lines)?;
        asc.a2i_control = CONTROL_ENABLE;
        asc.outbox_enabled = true;
        Ok(asc)
    }

    /// The ASCv4 provider's second register aperture. It shares this owner's
    /// lifecycle; do not bind a second PMGR lifecycle owner to the handle.
    /// Native protocol firmware does not imply an ARM entry-register value.
    #[cfg(test)]
    pub fn auxiliary(&self) -> Auxiliary {
        self.auxiliary.clone()
    }

    /// Check the backend's current owned entry fetch, then establish
    /// the independent register handoff. The supplied mapping describes all
    /// three address domains and the expected original instruction.
    /// This never loads or executes ARM firmware, or derives an entry from a
    /// native Rust implementation address.
    #[cfg(test)]
    pub fn establish_entry(&mut self, handoff: EntryHandoff) -> Result<(), &'static str> {
        self.check_entry_fetch(handoff)?;
        self.auxiliary.establish(handoff)
    }

    fn check_entry_fetch(&mut self, handoff: EntryHandoff) -> Result<(), &'static str> {
        let fetched = self.firmware.fetch_entry(handoff.iop_entry())?;
        if fetched.physical != handoff.physical_entry() {
            return Err("ASC actual entry translation disagrees with owned physical backing");
        }
        if fetched.instruction != handoff.instruction() {
            return Err("ASC fetched entry instruction disagrees with original source");
        }
        Ok(())
    }

    /// Read-only mailbox state for boot diagnostics.
    pub fn diagnostic(&self) -> alloc::string::String {
        alloc::format!(
            "run={} a2i={:#x} i2a_enabled={} send={:x?} outbox={:x?} levels={:?}",
            self.running,
            self.a2i_control,
            self.outbox_enabled,
            self.send0,
            self.outbox,
            self.levels
        )
    }

    /// A native coprocessor's typed state, for its DMA boundary. The wrapper
    /// still owns all mailbox and interrupt effects; firmware cannot replace it.
    pub fn firmware<F: Firmware>(&self) -> Option<&F> {
        (&*self.firmware as &dyn Any).downcast_ref()
    }

    /// Whether the coprocessor has bus-master work to run this step.
    pub fn dma_pending(&self) -> bool {
        self.execution_enabled() && self.firmware.dma_pending()
    }

    /// Run the coprocessor's queued DMA through `port`; any messages it
    /// produces enter the outbox and raise the mailbox interrupt, exactly as
    /// a received message's replies do.
    pub fn service_dma(&mut self, port: &mut Port<'_, '_>) -> Result<(), &'static str> {
        if !self.execution_enabled() {
            return Err("mailbox DMA on a stopped coprocessor");
        }
        let mut produced = Vec::new();
        let result = self.firmware.dma(port, &mut produced);
        // Firmware may have committed earlier DMA writes before a later
        // transfer faults. Its already-produced notifications are equally
        // committed and must remain visible even when this step fails.
        self.outbox.extend(produced);
        self.update_lines(port.access);
        result
    }

    /// The native coprocessor, for board events it reports; what it sends
    /// in response leaves through the mailbox at the next device advance.
    pub fn firmware_mut<F: Firmware>(&mut self) -> Option<&mut F> {
        (&mut *self.firmware as &mut dyn Any).downcast_mut()
    }

    fn visible(&self) -> bool {
        self.outbox_enabled && !self.outbox.is_empty()
    }

    /// CPU-driven work, including display scanout outside mailbox DMA,
    /// may run only while every physical execution gate is released.
    pub fn execution_enabled(&self) -> bool {
        self.running
            && self.lifecycle.powered
            && self.lifecycle.clocked
            && !self.lifecycle.quiesced
            && !self.lifecycle.reset
    }

    fn accessible(&self) -> Result<(), &'static str> {
        if !self.lifecycle.powered {
            return Err("ASC power is gated");
        }
        if !self.lifecycle.clocked {
            return Err("ASC clock is gated");
        }
        if self.lifecycle.reset {
            return Err("ASC reset is asserted");
        }
        Ok(())
    }

    fn update_lines(&mut self, access: &mut Access<'_>) {
        let visible = self.visible();
        let wanted = [
            (self.lines.inbox_not_empty, false),
            (self.lines.inbox_empty, true),
            (self.lines.outbox_not_empty, visible),
            (self.lines.outbox_empty, !visible),
        ];
        for (index, (line, level)) in wanted.into_iter().enumerate() {
            if self.levels[index] != Some(level) {
                self.levels[index] = Some(level);
                if let Some(irq) = line {
                    access.interrupts.set_level(Wire::Aic(irq), level);
                }
            }
        }
    }

    fn deliver(&mut self, result: Result<Vec<Message>, &'static str>) -> Result<(), &'static str> {
        self.outbox.extend(result?);
        Ok(())
    }

    fn send(&mut self, endpoint_word: u64) -> Result<(), &'static str> {
        if self.lifecycle.quiesced {
            return Err("ASC inbox submission while PMGR quiesced");
        }
        if !self.running {
            return Err("mailbox send to a stopped coprocessor");
        }
        if endpoint_word & !ENDPOINT != 0 {
            return Err("mailbox message bits above the endpoint are not modeled");
        }
        let payload = self.send0.ok_or("mailbox send without its payload word")?;
        let message = Message {
            endpoint: endpoint_word as u8,
            payload,
        };
        let mut replies = Vec::new();
        let result = match self.firmware.receive(message, &mut replies) {
            Ok(()) => Ok(replies),
            // A request the firmware does not implement gets the firmware's
            // own error reply where its protocol has one, else none, and is
            // reported once per endpoint and refusal.
            Err(reason) => {
                let error = self.firmware.error_reply(message, reason);
                if self.reported.insert((message.endpoint, reason)) {
                    self.unmodeled.push(alloc::format!(
                        "endpoint {:#x} payload {:#018x}: {reason}; {}",
                        message.endpoint,
                        message.payload,
                        if error.is_some() {
                            "answered with the firmware's error reply"
                        } else {
                            "left unanswered for the client's timeout"
                        }
                    ));
                }
                Ok(error.unwrap_or_default())
            }
        };
        self.deliver(result)?;
        self.send0 = None;
        Ok(())
    }

    fn write_cpu_control(&mut self, value: u64) -> Result<(), &'static str> {
        if value & !(RUN | CPU_CONTROL_HELD) != 0 {
            return Err("ASC CPU control bit is not modeled");
        }
        let run = value & RUN != 0;
        if run && !self.running && self.lifecycle.quiesced {
            return Err("ASC CPU start while PMGR quiesced");
        }
        if self.running && !run {
            self.firmware.stop()?;
            self.running = false;
            self.halted = true;
        }
        if run && !self.running {
            if let Some(handoff) = self.auxiliary.check_start()? {
                self.check_entry_fetch(handoff)?;
            }
            let mut started = Vec::new();
            let result = if self.halted {
                self.firmware.resume(&mut started)
            } else {
                self.firmware.start(&mut started)
            }
            .map(|()| started);
            self.deliver(result)?;
            self.running = true;
            self.halted = false;
        }
        self.cpu_control = value;
        self.auxiliary.set_running(self.running);
        Ok(())
    }
}

impl Lifecycle for Asc {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
        let destructive = proposed.reset && !self.lifecycle.reset
            || !proposed.powered && self.lifecycle.powered && !proposed.retention;
        if destructive {
            // A posted word or committed notification still belongs to its
            // sender. Do not erase it or complete the PMGR request first.
            if self.send0.is_some() || !self.outbox.is_empty() {
                return Err("ASC reset or power loss with owned mailbox messages");
            }
            self.firmware.check_reset()?;
        }
        Ok(())
    }

    fn set_lifecycle(&mut self, proposed: LifecycleState, access: &mut Access<'_>) {
        let destructive = proposed.reset && !self.lifecycle.reset
            || !proposed.powered && self.lifecycle.powered && !proposed.retention;
        if destructive {
            self.firmware.reset().expect("ASC reset was preflighted");
            self.running = false;
            self.halted = false;
            self.cpu_control = 0;
            self.a2i_control = 0;
            self.outbox_enabled = false;
        }
        self.lifecycle = proposed;
        self.auxiliary.set_lifecycle(proposed);
        // Gates freeze execution; neither they nor gate release
        // synthesize a firmware sleep/wake message or alter FIFO ownership.
        self.update_lines(access);
    }
}

impl MmioDevice for Asc {
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        Some(self)
    }
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(
        &mut self,
        offset: u64,
        width: Width,
        access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        self.accessible().map_err(fail)?;
        let value = match (offset, width) {
            (CPU_CONTROL, Width::Word) => self.cpu_control,
            // AppleASCWrapV4::_isIdle (kernel file 0x1bad724) consumes
            // (IDLE_STATUS & 3) != 0. Emulated die choice: bit 0 denotes
            // quiescent native mailboxes, with no partially posted message
            // or pending response. Unknown writes remain refused.
            (IDLE_STATUS, Width::Word) => u64::from(self.send0.is_none() && self.outbox.is_empty()),
            (A2I_CONTROL, Width::Word) => self.a2i_control | CONTROL_EMPTY,
            (I2A_CONTROL, Width::Word) => {
                let waiting = if self.visible() { self.outbox.len() } else { 0 };
                u64::from(self.outbox_enabled)
                    | (waiting.min(OCCUPANCY_MAX) as u64) << OCCUPANCY_SHIFT
                    | if waiting == 0 { CONTROL_EMPTY } else { 0 }
            }
            (I2A_RECV0, Width::Double) => self
                .visible()
                .then(|| self.outbox[0].payload)
                .ok_or_else(|| fail("load of an empty outbox"))?,
            (I2A_RECV1, Width::Double) => {
                if !self.visible() {
                    return Err(fail("load of an empty outbox"));
                }
                let waiting = self.outbox.len().min(OCCUPANCY_MAX) as u64;
                let message = self.outbox.pop_front().expect("visible outbox has a head");
                self.update_lines(access);
                u64::from(message.endpoint) | waiting << (32 + OCCUPANCY_SHIFT)
            }
            _ => return Err(fail("ASC register without a model")),
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
        let fail = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        self.accessible().map_err(fail)?;
        match (offset, width) {
            (CPU_CONTROL, Width::Word) => self.write_cpu_control(value).map_err(fail)?,
            (A2I_CONTROL, Width::Word) if value & !(CONTROL_ENABLE | CONTROL_STATUS) == 0 => {
                self.a2i_control = value & CONTROL_ENABLE
            }
            (I2A_CONTROL, Width::Word) if value & !(CONTROL_ENABLE | CONTROL_STATUS) == 0 => {
                // _enableOutbox (kernel file 0x1badc28..0x1badc94)
                // preserves read-only FIFO status in its RMW store.
                self.outbox_enabled = value & CONTROL_ENABLE != 0;
            }
            (A2I_CONTROL | I2A_CONTROL, Width::Word) => {
                return Err(fail("mailbox control field without a model"));
            }
            (A2I_SEND0, Width::Double) => self.send0 = Some(value),
            (A2I_SEND1, Width::Double) => {
                self.send(value).map_err(fail)?;
                if let Some(request) = self.firmware.take_transition() {
                    access.request_transition(request.device, request.transition, request.reason);
                }
            }
            _ => return Err(fail("ASC register without a model")),
        }
        self.update_lines(access);
        Ok(())
    }
    fn advance(&mut self, access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        if self.execution_enabled() {
            let mut sent = Vec::new();
            let result = self.firmware.poll(&mut sent);
            self.outbox.extend(sent);
            self.update_lines(access);
            result.map_err(|reason| refuse(NAME, 0, Width::Double, Direction::Read, reason))?;
        }
        self.update_lines(access);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_contracts::interrupt::InterruptLatch;

    #[test]
    fn physical_retention_freezes_work_and_preserves_mailbox_irq_ownership() {
        struct Active {
            polls: u32,
            resets: u32,
        }
        impl Firmware for Active {
            fn check_reset(&self) -> Result<(), &'static str> {
                Ok(())
            }
            fn reset(&mut self) -> Result<(), &'static str> {
                self.resets += 1;
                Ok(())
            }
            fn start(&mut self, _: &mut Vec<Message>) -> Result<(), &'static str> {
                Ok(())
            }
            fn receive(&mut self, _: Message, _: &mut Vec<Message>) -> Result<(), &'static str> {
                Ok(())
            }
            fn dma_pending(&self) -> bool {
                true
            }
            fn poll(&mut self, out: &mut Vec<Message>) -> Result<(), &'static str> {
                self.polls += 1;
                out.push(Message {
                    endpoint: 0x20,
                    payload: u64::from(self.polls),
                });
                Ok(())
            }
        }
        let mut asc = Asc::booted(
            Box::new(Active {
                polls: 0,
                resets: 0,
            }),
            Lines::from_interrupts(LINES),
        )
        .unwrap();
        let active = asc.lifecycle;
        let mut latch = InterruptLatch::new();
        {
            let mut access = Access::new(0, 0, &mut latch);
            asc.advance(&mut access).unwrap();
            asc.write(A2I_SEND0, Width::Double, 0x123, &mut access)
                .unwrap();
        }
        assert!(latch.is_asserted(Wire::Aic(LINES[2])));
        for gated in [
            LifecycleState {
                clocked: false,
                ..active
            },
            LifecycleState {
                quiesced: true,
                ..active
            },
            LifecycleState {
                powered: false,
                clocked: false,
                retention: true,
                ..active
            },
        ] {
            let mut access = Access::new(0, 1, &mut latch);
            asc.check_lifecycle(gated).unwrap();
            asc.set_lifecycle(gated, &mut access);
            asc.advance(&mut access).unwrap();
            assert!(!asc.dma_pending());
            assert_eq!(asc.send0, Some(0x123));
            assert_eq!(asc.outbox.len(), 1);
            assert_eq!(asc.firmware::<Active>().unwrap().polls, 1);
            assert!(
                asc.check_lifecycle(LifecycleState {
                    reset: true,
                    ..active
                })
                .is_err()
            );
            asc.set_lifecycle(active, &mut access);
            assert!(asc.dma_pending());
        }
        assert!(latch.is_asserted(Wire::Aic(LINES[2])));
        let mut access = Access::new(0, 2, &mut latch);
        assert_eq!(receive(&mut asc, &mut access).0, 1);
        asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
            .unwrap();
        let reset = LifecycleState {
            reset: true,
            ..active
        };
        asc.check_lifecycle(reset).unwrap();
        asc.set_lifecycle(reset, &mut access);
        assert!(!asc.running && !asc.halted && asc.outbox.is_empty());
        assert_eq!(asc.firmware::<Active>().unwrap().resets, 1);
        assert!(asc.read(CPU_CONTROL, Width::Word, &mut access).is_err());
        asc.set_lifecycle(active, &mut access);
        assert_eq!(asc.read(CPU_CONTROL, Width::Word, &mut access), Ok(0));
        assert!(!asc.execution_enabled());
        asc.write(CPU_CONTROL, Width::Word, RUN, &mut access)
            .unwrap();
        assert!(asc.execution_enabled());
        assert_eq!(asc.firmware::<Active>().unwrap().resets, 1);
    }

    /// Echoes every message back on endpoint + 1 and says hello at start.
    struct Echo;
    impl Firmware for Echo {
        fn start(&mut self, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
            outbox.push(Message {
                endpoint: 0,
                payload: 0x11,
            });
            Ok(())
        }
        fn receive(
            &mut self,
            message: Message,
            outbox: &mut Vec<Message>,
        ) -> Result<(), &'static str> {
            if message.endpoint == 0xff {
                return Err(if message.payload == 0 {
                    "refused without a reply"
                } else {
                    "refused"
                });
            }
            outbox.push(Message {
                endpoint: message.endpoint + 1,
                payload: message.payload,
            });
            Ok(())
        }
        /// A refused request with a nonzero payload has an error reply.
        fn error_reply(&mut self, message: Message, _: &'static str) -> Option<Vec<Message>> {
            (message.payload != 0).then(|| {
                alloc::vec![Message {
                    endpoint: message.endpoint,
                    payload: !message.payload,
                }]
            })
        }
    }

    #[test]
    fn unimplemented_requests_get_the_error_reply_or_none_and_report_once() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut asc = Asc::booted(Box::new(Echo), Lines::from_interrupts(LINES)).unwrap();
        asc.write(I2A_CONTROL, Width::Word, 1, &mut access).unwrap();
        assert_eq!(receive(&mut asc, &mut access).0, 0x11);
        let send = |asc: &mut Asc, payload, access: &mut Access<'_>| {
            asc.write(A2I_SEND0, Width::Double, payload, access)
                .unwrap();
            asc.write(A2I_SEND1, Width::Double, 0xff, access)
        };
        for _ in 0..2 {
            send(&mut asc, 5, &mut access).unwrap();
            assert_eq!(receive(&mut asc, &mut access).0, !5);
        }
        let reports = asc.take_unmodeled();
        assert_eq!(reports.len(), 1);
        assert!(reports[0].contains("refused"), "{}", reports[0]);
        // Without an error reply in its protocol the request is left
        // unanswered, so the client's timeout runs.
        for _ in 0..2 {
            send(&mut asc, 0, &mut access).unwrap();
            assert!(asc.outbox.is_empty());
        }
        let reports = asc.take_unmodeled();
        assert_eq!(reports.len(), 1);
        assert!(reports[0].contains("left unanswered"), "{}", reports[0]);
    }

    const LINES: [AicInput; 4] = [
        AicInput::new(0, 0x275),
        AicInput::new(0, 0x274),
        AicInput::new(0, 0x277),
        AicInput::new(0, 0x276),
    ];

    fn receive(asc: &mut Asc, access: &mut Access<'_>) -> (u64, u64) {
        let payload = asc.read(I2A_RECV0, Width::Double, access).unwrap();
        (payload, asc.read(I2A_RECV1, Width::Double, access).unwrap())
    }

    #[test]
    fn boot_handoff_delivers_hello_without_an_ap_mailbox_enable() {
        let mut latch = InterruptLatch::new();
        let mut asc = Asc::booted(Box::new(Echo), Lines::from_interrupts(LINES)).unwrap();
        {
            let mut access = Access::new(0, 0, &mut latch);
            asc.advance(&mut access).unwrap();
        }
        assert!(latch.is_asserted(Wire::Aic(LINES[2])));
        let mut access = Access::new(0, 0, &mut latch);
        assert_eq!(asc.read(IDLE_STATUS, Width::Word, &mut access), Ok(0));
        assert_eq!(
            asc.read(A2I_CONTROL, Width::Word, &mut access),
            Ok(CONTROL_ENABLE | CONTROL_EMPTY)
        );
        let control = asc.read(I2A_CONTROL, Width::Word, &mut access).unwrap();
        asc.write(I2A_CONTROL, Width::Word, control, &mut access)
            .unwrap();
        assert_eq!(receive(&mut asc, &mut access), (0x11, 1 << 52));
        assert_eq!(asc.read(IDLE_STATUS, Width::Word, &mut access), Ok(1));
        assert!(!latch.is_asserted(Wire::Aic(LINES[2])));
        let mut access = Access::new(0, 0, &mut latch);
        asc.write(A2I_SEND0, Width::Double, 0x123, &mut access)
            .unwrap();
        assert_eq!(asc.read(IDLE_STATUS, Width::Word, &mut access), Ok(0));
        asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
            .unwrap();
        asc.write(A2I_SEND0, Width::Double, 0x456, &mut access)
            .unwrap();
        asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
            .unwrap();
        assert_eq!(receive(&mut asc, &mut access), (0x123, 0x21 | 2 << 52));
        assert_eq!(receive(&mut asc, &mut access), (0x456, 0x21 | 1 << 52));
        assert!(asc.read(I2A_RECV0, Width::Double, &mut access).is_err());
    }

    #[test]
    fn a_started_coprocessor_answers_through_the_enabled_outbox() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let lines = Lines::from_interrupts(LINES);
        let mut asc = Asc::new(Box::new(Echo), false, lines).unwrap();
        assert_eq!(asc.read(CPU_CONTROL, Width::Word, &mut access), Ok(0));
        // A stopped coprocessor cannot take a message.
        asc.write(A2I_SEND0, Width::Double, 1, &mut access).unwrap();
        assert!(
            asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
                .is_err()
        );
        asc.write(CPU_CONTROL, Width::Word, RUN, &mut access)
            .unwrap();
        // Its hello waits in the disabled outbox.
        assert_eq!(
            asc.read(I2A_CONTROL, Width::Word, &mut access),
            Ok(CONTROL_EMPTY)
        );
        assert!(asc.read(I2A_RECV0, Width::Double, &mut access).is_err());
        asc.write(I2A_CONTROL, Width::Word, 1, &mut access).unwrap();
        assert!(latch.is_asserted(Wire::Aic(LINES[2])));
        assert!(!latch.is_asserted(Wire::Aic(LINES[3])));
        assert!(latch.is_asserted(Wire::Aic(LINES[1])));
        let mut access = Access::new(0, 0, &mut latch);
        assert_eq!(
            asc.read(I2A_CONTROL, Width::Word, &mut access),
            Ok(1 | 1 << OCCUPANCY_SHIFT)
        );
        assert_eq!(receive(&mut asc, &mut access), (0x11, 1 << 52));
        assert_eq!(
            asc.read(I2A_CONTROL, Width::Word, &mut access),
            Ok(1 | CONTROL_EMPTY)
        );
        // A message is sent by its second word and answered at once.
        asc.write(A2I_SEND0, Width::Double, 0xabc, &mut access)
            .unwrap();
        asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
            .unwrap();
        assert_eq!(
            asc.read(A2I_CONTROL, Width::Word, &mut access),
            Ok(CONTROL_EMPTY)
        );
        assert_eq!(receive(&mut asc, &mut access), (0xabc, 0x21 | 1 << 52));
        assert!(!latch.is_asserted(Wire::Aic(LINES[2])));
        assert!(latch.is_asserted(Wire::Aic(LINES[3])));
    }

    #[test]
    fn refusals_stay_explicit() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut asc = Asc::new(Box::new(Echo), true, Lines::default()).unwrap();
        assert_eq!(asc.read(CPU_CONTROL, Width::Word, &mut access), Ok(RUN));
        assert!(asc.write(CPU_CONTROL, Width::Word, 0, &mut access).is_err());
        asc.write(
            CPU_CONTROL,
            Width::Word,
            RUN | CPU_CONTROL_HELD,
            &mut access,
        )
        .unwrap();
        assert!(
            asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
                .is_err()
        );
        asc.write(A2I_SEND0, Width::Double, 1, &mut access).unwrap();
        assert!(
            asc.write(A2I_SEND1, Width::Double, 0x120, &mut access)
                .is_err()
        );
        // A request the firmware refuses is answered degraded, reported once.
        asc.write(A2I_SEND0, Width::Double, 1, &mut access).unwrap();
        asc.write(A2I_SEND1, Width::Double, 0xff, &mut access)
            .unwrap();
        assert_eq!(asc.take_unmodeled().len(), 1);
        assert!(
            asc.write(I2A_CONTROL, Width::Word, 1 << 7, &mut access)
                .is_err()
        );
        assert!(asc.read(0x8004, Width::Word, &mut access).is_err());
        assert!(asc.read(I2A_RECV0, Width::Word, &mut access).is_err());
    }

    #[derive(Default)]
    struct Retained {
        starts: u32,
        stops: u32,
        resumes: u32,
        polls: u32,
        value: u64,
        refuse_stop: bool,
        refuse_resume: bool,
    }

    impl Firmware for Retained {
        fn start(&mut self, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
            self.starts += 1;
            outbox.push(Message {
                endpoint: 0,
                payload: 0x1234,
            });
            Ok(())
        }
        fn stop(&mut self) -> Result<(), &'static str> {
            if self.refuse_stop {
                return Err("stop refused");
            }
            self.stops += 1;
            Ok(())
        }
        fn resume(&mut self, _: &mut Vec<Message>) -> Result<(), &'static str> {
            if self.refuse_resume {
                return Err("resume refused");
            }
            self.resumes += 1;
            Ok(())
        }
        fn receive(
            &mut self,
            message: Message,
            outbox: &mut Vec<Message>,
        ) -> Result<(), &'static str> {
            self.value += message.payload;
            outbox.push(Message {
                endpoint: message.endpoint,
                payload: self.value,
            });
            Ok(())
        }
        fn poll(&mut self, _: &mut Vec<Message>) -> Result<(), &'static str> {
            self.polls += 1;
            Ok(())
        }
        fn dma_pending(&self) -> bool {
            true
        }
    }

    #[test]
    fn retained_halt_keeps_mailboxes_state_and_cpu_work_until_resume() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut asc = Asc::new(
            Box::new(Retained::default()),
            false,
            Lines::from_interrupts(LINES),
        )
        .unwrap();
        asc.write(CPU_CONTROL, Width::Word, 0, &mut access).unwrap();
        assert_eq!(asc.firmware::<Retained>().unwrap().stops, 0);
        asc.write(CPU_CONTROL, Width::Word, RUN, &mut access)
            .unwrap();
        asc.write(
            CPU_CONTROL,
            Width::Word,
            RUN | CPU_CONTROL_HELD,
            &mut access,
        )
        .unwrap();
        asc.write(A2I_CONTROL, Width::Word, 1, &mut access).unwrap();
        asc.write(I2A_CONTROL, Width::Word, 1, &mut access).unwrap();
        asc.write(A2I_SEND0, Width::Double, 5, &mut access).unwrap();
        asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
            .unwrap();
        asc.write(A2I_SEND0, Width::Double, 7, &mut access).unwrap();
        asc.advance(&mut access).unwrap();
        assert!(asc.dma_pending());
        // Clearing RUN and the held bit are separate AP stores. Neither
        // flushes a response or the first word of an AP message.
        asc.write(CPU_CONTROL, Width::Word, CPU_CONTROL_HELD, &mut access)
            .unwrap();
        asc.write(CPU_CONTROL, Width::Word, 0, &mut access).unwrap();
        asc.advance(&mut access).unwrap();
        assert!(!asc.dma_pending());
        assert_eq!(asc.levels[2], Some(true)); // Outbox IRQ survives CPU halt.
        assert_eq!(asc.firmware::<Retained>().unwrap().polls, 1);
        assert_eq!(
            asc.read(A2I_CONTROL, Width::Word, &mut access),
            Ok(CONTROL_ENABLE | CONTROL_EMPTY)
        );
        assert_eq!(receive(&mut asc, &mut access), (0x1234, 2 << 52));
        assert_eq!(asc.levels[2], Some(true));
        assert_eq!(receive(&mut asc, &mut access), (5, 0x20 | 1 << 52));
        assert_eq!(asc.levels[2], Some(false));
        assert_eq!(asc.levels[3], Some(true));
        assert!(
            asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
                .is_err()
        );
        assert_eq!(asc.send0, Some(7));
        asc.write(CPU_CONTROL, Width::Word, RUN, &mut access)
            .unwrap();
        asc.write(CPU_CONTROL, Width::Word, RUN, &mut access)
            .unwrap();
        assert!(asc.dma_pending());
        assert!(asc.outbox.is_empty()); // Resume did not emit another cold Hello.
        asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
            .unwrap();
        assert_eq!(receive(&mut asc, &mut access), (12, 0x20 | 1 << 52));
        let firmware = asc.firmware::<Retained>().unwrap();
        assert_eq!(
            (firmware.starts, firmware.stops, firmware.resumes),
            (1, 1, 1)
        );
        assert_eq!(firmware.value, 12);
    }

    #[test]
    fn refused_halt_and_resume_leave_control_and_mailboxes_unchanged() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut asc = Asc::new(
            Box::new(Retained {
                refuse_stop: true,
                ..Retained::default()
            }),
            true,
            Lines::default(),
        )
        .unwrap();
        asc.write(A2I_SEND0, Width::Double, 9, &mut access).unwrap();
        assert!(asc.write(CPU_CONTROL, Width::Word, 0, &mut access).is_err());
        assert!(asc.running && !asc.halted);
        assert_eq!(asc.cpu_control, RUN);
        assert_eq!(asc.send0, Some(9));
        assert_eq!(asc.outbox.len(), 1);
        asc.firmware_mut::<Retained>().unwrap().refuse_stop = false;
        asc.write(CPU_CONTROL, Width::Word, 0, &mut access).unwrap();
        asc.firmware_mut::<Retained>().unwrap().refuse_resume = true;
        assert!(
            asc.write(CPU_CONTROL, Width::Word, RUN, &mut access)
                .is_err()
        );
        assert!(!asc.running && asc.halted);
        assert_eq!(asc.cpu_control, 0);
        assert_eq!(asc.send0, Some(9));
        assert_eq!(asc.outbox.len(), 1);
        assert!(
            asc.write(CPU_CONTROL, Width::Word, RUN | 1, &mut access)
                .is_err()
        );
        assert!(
            asc.write(CPU_CONTROL, Width::Double, RUN, &mut access)
                .is_err()
        );
        assert_eq!(asc.firmware::<Retained>().unwrap().resumes, 0);
    }

    struct AtomicCommand {
        refuse_start: bool,
        refuse_resume: bool,
        refuse_receive: bool,
        value: u64,
    }
    impl Firmware for AtomicCommand {
        fn start(&mut self, out: &mut Vec<Message>) -> Result<(), &'static str> {
            out.push(Message {
                endpoint: 0,
                payload: 0x11,
            });
            if self.refuse_start {
                return Err("start refused");
            }
            Ok(())
        }
        fn stop(&mut self) -> Result<(), &'static str> {
            Ok(())
        }
        fn resume(&mut self, out: &mut Vec<Message>) -> Result<(), &'static str> {
            out.push(Message {
                endpoint: 0,
                payload: 7 << 52 | 0x20,
            });
            if self.refuse_resume {
                return Err("resume refused");
            }
            Ok(())
        }
        fn receive(
            &mut self,
            message: Message,
            out: &mut Vec<Message>,
        ) -> Result<(), &'static str> {
            out.push(Message {
                endpoint: message.endpoint,
                payload: self.value + message.payload,
            });
            if self.refuse_receive {
                return Err("command refused");
            }
            self.value += message.payload;
            Ok(())
        }
    }

    #[test]
    fn atomic_refusals_discard_tentative_acks() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut asc = Asc::new(
            Box::new(AtomicCommand {
                refuse_start: true,
                refuse_resume: true,
                refuse_receive: true,
                value: 0,
            }),
            false,
            Lines::from_interrupts(LINES),
        )
        .unwrap();
        asc.write(I2A_CONTROL, Width::Word, 1, &mut access).unwrap();
        assert!(
            asc.write(CPU_CONTROL, Width::Word, RUN, &mut access)
                .is_err()
        );
        assert!(!asc.running && !asc.halted && asc.cpu_control == 0);
        assert!(asc.outbox.is_empty());
        assert_eq!(asc.levels[2], Some(false));
        asc.firmware_mut::<AtomicCommand>().unwrap().refuse_start = false;
        asc.write(CPU_CONTROL, Width::Word, RUN, &mut access)
            .unwrap();
        assert_eq!(receive(&mut asc, &mut access).0, 0x11);
        // A refused command publishes no tentative ack: it is left
        // unanswered and reported once.
        asc.write(A2I_SEND0, Width::Double, 5, &mut access).unwrap();
        asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
            .unwrap();
        assert_eq!(asc.send0, None);
        assert_eq!(asc.firmware::<AtomicCommand>().unwrap().value, 0);
        assert!(asc.outbox.is_empty());
        assert_eq!(asc.levels[2], Some(false));
        assert_eq!(asc.take_unmodeled().len(), 1);
        asc.firmware_mut::<AtomicCommand>().unwrap().refuse_receive = false;
        asc.write(A2I_SEND0, Width::Double, 5, &mut access).unwrap();
        asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
            .unwrap();
        assert_eq!(asc.send0, None);
        assert_eq!(asc.firmware::<AtomicCommand>().unwrap().value, 5);
        assert_eq!(receive(&mut asc, &mut access).0, 5);
        asc.write(CPU_CONTROL, Width::Word, 0, &mut access).unwrap();
        assert!(
            asc.write(CPU_CONTROL, Width::Word, RUN, &mut access)
                .is_err()
        );
        assert!(!asc.running && asc.halted && asc.cpu_control == 0);
        assert!(asc.outbox.is_empty());
        asc.firmware_mut::<AtomicCommand>().unwrap().refuse_resume = false;
        asc.write(CPU_CONTROL, Width::Word, RUN, &mut access)
            .unwrap();
        assert_eq!(receive(&mut asc, &mut access).0, 7 << 52 | 0x20);
        assert!(asc.outbox.is_empty());
    }

    struct AsyncEndpoint {
        value: u64,
        issued: bool,
        fail: bool,
        polls: u32,
    }
    impl super::super::rtkit::Endpoint for AsyncEndpoint {
        fn start(&mut self, _: &mut Vec<u64>) -> Result<(), &'static str> {
            Ok(())
        }
        fn receive(&mut self, _: u64, _: &mut Vec<u64>) -> Result<(), &'static str> {
            Err("no command contract")
        }
        fn poll(&mut self, out: &mut Vec<u64>) -> Result<(), &'static str> {
            self.polls += 1;
            if !self.issued {
                self.issued = true;
                out.push(self.value);
            }
            if self.fail {
                return Err("later async operation failed");
            }
            Ok(())
        }
    }

    #[test]
    fn rtkit_poll_preserves_both_prior_and_failing_endpoint_events_and_irqs() {
        use super::super::rtkit::{Endpoint, RtKit};
        let endpoints = (0x20..=0x22)
            .map(|number| {
                (
                    number,
                    Box::new(AsyncEndpoint {
                        value: u64::from(number) + 100,
                        issued: false,
                        fail: number == 0x21,
                        polls: 0,
                    }) as Box<dyn Endpoint>,
                )
            })
            .collect();
        let rtkit = RtKit::new(endpoints, stela_formats::builds::DEFAULT.rtkit_version).unwrap();
        let mut asc = Asc::booted(Box::new(rtkit), Lines::from_interrupts(LINES)).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let send = |asc: &mut Asc, payload, access: &mut Access<'_>| {
            asc.write(A2I_SEND0, Width::Double, payload, access)
                .unwrap();
            asc.write(A2I_SEND1, Width::Double, 0, access).unwrap();
        };
        receive(&mut asc, &mut access); // Hello.
        send(&mut asc, 2 << 52 | 12 | 12 << 16, &mut access);
        receive(&mut asc, &mut access); // Roll call0.
        send(&mut asc, 8 << 52 | 1, &mut access);
        receive(&mut asc, &mut access); // Roll call1.
        send(&mut asc, 8 << 52 | 1 << 51 | 1 << 32, &mut access);
        assert_eq!(receive(&mut asc, &mut access).0, 7 << 52 | 0x20);
        for number in 0x20..=0x22 {
            send(&mut asc, 5 << 52 | number << 32 | 2, &mut access);
        }
        asc.write(I2A_CONTROL, Width::Word, 0, &mut access).unwrap();
        assert!(asc.advance(&mut access).is_err());
        assert_eq!(asc.outbox.len(), 2);
        assert_eq!(asc.levels[2], Some(false)); // Delivery gated, events kept.
        assert!(asc.read(I2A_RECV0, Width::Double, &mut access).is_err());
        asc.write(I2A_CONTROL, Width::Word, 1, &mut access).unwrap();
        assert_eq!(asc.levels[2], Some(true));
        assert_eq!(receive(&mut asc, &mut access).0, 132);
        assert_eq!(asc.levels[2], Some(true));
        assert_eq!(receive(&mut asc, &mut access).0, 133);
        assert_eq!(asc.levels[2], Some(false));
        let rtkit = asc.firmware_mut::<RtKit>().unwrap();
        assert_eq!(rtkit.endpoint_mut::<AsyncEndpoint>(0x22).unwrap().polls, 0);
        rtkit.endpoint_mut::<AsyncEndpoint>(0x21).unwrap().fail = false;
        asc.advance(&mut access).unwrap();
        assert_eq!(asc.outbox.len(), 1); // Committed events were not replayed.
        assert_eq!(receive(&mut asc, &mut access).0, 134);
        let rtkit = asc.firmware_mut::<RtKit>().unwrap();
        assert_eq!(rtkit.endpoint_mut::<AsyncEndpoint>(0x20).unwrap().polls, 2);
        assert_eq!(rtkit.endpoint_mut::<AsyncEndpoint>(0x21).unwrap().polls, 2);
        assert_eq!(rtkit.endpoint_mut::<AsyncEndpoint>(0x22).unwrap().polls, 1);
        assert!(asc.outbox.is_empty());
    }

    struct PartialDma(bool);
    impl Firmware for PartialDma {
        fn start(&mut self, _: &mut Vec<Message>) -> Result<(), &'static str> {
            Ok(())
        }
        fn receive(&mut self, _: Message, _: &mut Vec<Message>) -> Result<(), &'static str> {
            Ok(())
        }
        fn dma(
            &mut self,
            port: &mut Port<'_, '_>,
            out: &mut Vec<Message>,
        ) -> Result<(), &'static str> {
            if !self.0 {
                port.write(0, b"done").map_err(|_| "first DMA failed")?;
                out.push(Message {
                    endpoint: 0x24,
                    payload: 0x85 << 48,
                });
                self.0 = true;
            }
            port.read(0x1000, &mut [0]).map_err(|_| "later DMA failed")
        }
    }

    #[test]
    fn an_earlier_dma_notification_survives_a_later_transfer_fault() {
        use {stela_contracts::dma::Physical, stela_contracts::dma::test_support::Ram};
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut memory = Ram::new(0, 8);
        let mut asc =
            Asc::booted(Box::new(PartialDma(false)), Lines::from_interrupts(LINES)).unwrap();
        asc.write(I2A_CONTROL, Width::Word, CONTROL_ENABLE, &mut access)
            .unwrap();
        for _ in 0..2 {
            let mut port = Port {
                iommu: &mut Physical,
                stream: 0,
                memory: &mut memory,
                access: &mut access,
            };
            assert_eq!(asc.service_dma(&mut port), Err("later DMA failed"));
        }
        assert_eq!(&memory.bytes[..4], b"done");
        assert_eq!(asc.outbox.len(), 1);
        assert_eq!(asc.levels[2], Some(true));
        assert_eq!(receive(&mut asc, &mut access), (0x85 << 48, 0x24 | 1 << 52));
        assert_eq!(asc.levels[2], Some(false));
    }

    /// Powers the machine off for any message and reports one event of
    /// its own per poll.
    struct Standby {
        events: u64,
        requested: bool,
    }
    impl Firmware for Standby {
        fn start(&mut self, _outbox: &mut Vec<Message>) -> Result<(), &'static str> {
            Ok(())
        }
        fn receive(
            &mut self,
            _message: Message,
            _outbox: &mut Vec<Message>,
        ) -> Result<(), &'static str> {
            self.requested = true;
            Ok(())
        }
        fn poll(&mut self, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
            self.events += 1;
            outbox.push(Message {
                endpoint: 0x20,
                payload: self.events,
            });
            Ok(())
        }
        fn take_transition(&mut self) -> Option<TransitionRequest> {
            core::mem::take(&mut self.requested).then_some(TransitionRequest {
                device: "standby",
                transition: Transition::PowerOff,
                reason: "test",
            })
        }
    }

    #[test]
    fn firmware_events_leave_at_advance_and_transitions_reach_the_machine() {
        let mut latch = InterruptLatch::new();
        let firmware = Standby {
            events: 0,
            requested: false,
        };
        let mut asc = Asc::booted(Box::new(firmware), Lines::from_interrupts(LINES)).unwrap();
        let mut access = Access::new(0, 7, &mut latch);
        asc.advance(&mut access).unwrap();
        assert!(latch.is_asserted(Wire::Aic(LINES[2])));
        let mut access = Access::new(0, 7, &mut latch);
        assert_eq!(receive(&mut asc, &mut access), (1, 0x20 | 1 << 52));
        assert_eq!(asc.firmware_mut::<Standby>().unwrap().events, 1);
        assert!(asc.firmware_mut::<Echo>().is_none());
        asc.write(A2I_SEND0, Width::Double, 0, &mut access).unwrap();
        assert!(access.reset_request().is_none());
        asc.write(A2I_SEND1, Width::Double, 0x20, &mut access)
            .unwrap();
        let request = access.reset_request().unwrap();
        assert_eq!(
            (request.device, request.transition, request.at),
            ("standby", Transition::PowerOff, 7)
        );
    }
}
