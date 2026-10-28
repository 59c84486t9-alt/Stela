//! An RTKit coprocessor's operating system, emulated natively behind an ASC
//! mailbox ([`super::asc::Firmware`]): the management endpoint and the
//! application endpoints a coprocessor model provides ([`Endpoint`]).
//!
//! The management protocol is the 26A434 J473AP kernel's
//! `RTBuddyManagementEndpoint` (cited by kernel file offset), which extends
//! Linux `drivers/soc/apple/rtkit.c`. Endpoint 0 carries messages whose type
//! is bits 55:52 of the payload (the dispatcher at 0x466f81c takes four bits):
//!
//! - HELLO (1, coprocessor to AP) offers versions `[15:0]` to `[31:16]`; the
//!   AP accepts a range holding 12 and answers HELLO_REPLY (2) with 12 in both
//!   fields, debugger permission in bit 32 and tracing in bit 33 (0x4670494).
//! - EPMAP (8, both ways) is a roll call: the coprocessor lists group
//!   `[37:32]`'s endpoints `32 × group + bit` as the bitmap `[31:0]`, the last
//!   group marked by bit 51; the AP creates each listed endpoint and answers
//!   with the request's group and last bits and its own bitmap of enabled
//!   endpoints in that group (0x46706e8, `_buildRollCall` 0x4670b68). The last
//!   answer completes enumeration.
//! - Endpoint control (5, AP to coprocessor) enables (2) or disables (1)
//!   endpoint `[47:32]`; nothing acknowledges it (0x467020c).
//! - IOP power (6, AP to coprocessor) requests 0x201, 0x220, 0x202 or 0;
//!   the coprocessor acknowledges with type 7 and the state reached, of which
//!   the AP checks the low byte (0x467017c, table 0xcd4620, 0x4670930).
//! - AP power (0xb, both ways) announces 0x201, 0x20 or 0; the coprocessor
//!   echoes the full 32-bit state (0x466fe2c).
//! - Watchdog ping (3, AP to coprocessor) carries a sequence number in
//!   `[31:0]`; the coprocessor answers type 4 with it (0x4670cbc, 0x4670830).
//! - Ready for power nap (0xa, AP to coprocessor) is a Boolean nothing
//!   acknowledges (0x46700dc).
//!
//! Starting a coprocessor, `RTBuddy::_performPowerStateChangeGated`
//! (0x465d140) sets status 4 (0x465d7b0), starts its CPU and blocks in
//! `_iopValidate` (0x465dfd8) for 20 s until the status reaches its target,
//! or panics "No response received" (0x465d900). The last roll-call answer
//! sets VersionOk (6, `_handleEPRollCall` 0x46707ec), which is the target
//! only for a nub marked `remote-only` or `automatic-rail-gating-enabled`
//! (`_initConfigEDT` 0x4660f08 keeps them at +0x100 and +0x108). Every
//! other nub, `user-power-managed` ones such as the PMP's included (that
//! flag is +0x107 and only hands power policy to a client driver), waits
//! for running (8): the coprocessor announces power-on with an unsolicited
//! type 7 0x20 once enumeration completes, which `_handlePowerAck`
//! (0x4670930) takes. The roll call already published each listed
//! application endpoint as an `RTBuddyEndpointService` named after the
//! role (`createEndpoint` 0x465dca8, `createName` 0x4665818: "ANS2" +
//! "Endpoint" + endpoint - 0x1f), so client drivers start and enable
//! endpoints while the AP still waits. This coprocessor always sends that
//! power-on announcement.
//!
//! A nub marked `quiesced` was used and quiesced by the boot chain:
//! `RTBuddy::_initConfigEDT` (0xfffffe000b665158) starts it in power state
//! 3, and `_performPowerStateChangeGated` (0xfffffe000b66187c) wakes it
//! with `wakeQuiesced` (0xfffffe000b674db8): IOP power 0x220, or AP power
//! 0x20 when `automatic-rail-gating-enabled` is set. A quiesced coprocessor
//! sends no HELLO until that wake. It then says HELLO and rolls call, and it
//! acknowledges 0x220 once enumeration completes. That ack's low byte 0x20
//! moves the AP to running (`_handlePowerAck` 0xfffffe000b674930), as Linux
//! `apple_rtkit_wake` also expects. An ack sent during enumeration would
//! change the AP's status before the last roll-call group, which
//! `_handleEPRollCall` (0xfffffe000b6746e8) requires at VersionOk. The
//! rail-gated AP-power wake is not modeled and refuses.
//!
//! Retained CPU stop follows a completed IOP sleep request: the AP's power
//! table at VA `0xfffffe0007cd8620` maps RTBuddy states 0/1/2/3 to wire
//! 0x201/0x220/0x202/0, while `powerStatePreservesMemory` at
//! `0xfffffe000b669488` admits only states below 3. RTBuddy waits for the
//! sleep ACK, disables outbox delivery, then calls `stopCPU(false, ...)`
//! (`0xfffffe000b661328..0xfffffe000b6615f4`). The ASC RUN edge retains
//! protocol and endpoint state. On retained CPU resume, ordinary management
//! announces running (type7/0x20) without a new HELLO or roll call. The AP
//! sets status4 before RUN and invokes wakeQuiesced only for prior status3
//! (`0xfffffe000b6617a0..0xfffffe000b661884`); sleep ACKs set status2,
//! so a retained CPU wake does not depend on another IOP power request.
//! Original DCP transition `0x230c0` runs its low-power helper `0x235bc`,
//! announces sleep through `0x236ec`, and blocks in `0xf824`. After hardware
//! return, `0x232fc..0x23330` invokes callbacks back to the saved running
//! state0x21 and announces it through the same notifier: `0x25704` and
//! `0x2fbb28` map it to wire0x20, `0x2374c` adds type7. Unenumerated, awake,
//! memory-loss and rail-gated CPU-stop paths refuse.
//!
//! The roll call lists exactly the endpoints the model provides. Of RTKit's
//! system endpoints (crashlog 1, syslog 2, kdebug 3, IOReporting 4, OSLog 8,
//! ...) the default constructor lists only crashlog: the kernel assumes it. On a
//! panic, `RTBuddy::callPlatformFunction` (0x4659480) hands every nub marked
//! `crashlog-non-fatal` (J473's ANS2; `_initCoreDump` 0x4663514) to
//! `RTBuddyCrashlogEndpoint::forceNonFatalCrashlog` without checking that the
//! endpoint exists, so a coprocessor without it turns any panic into a
//! nested one that loses the first panic's message. A native coprocessor
//! never crashes, so its crashlog endpoint requests no buffer (the AP
//! allocates one only on that request, `_messageHandler` 0x4669c74) and
//! takes no AP message; with no buffer, `_checkForCrashGated` (0x466b214)
//! returns before reading or forcing anything. The other system endpoints
//! are services of Apple's firmware this coprocessor does not have, so they
//! are listed only when their actual endpoint owners are supplied through
//! [`SystemEndpoints`]. Every other management message refuses.
//!
//! Application endpoints also send on their own (the SMC's board
//! notifications): an enabled endpoint's pending messages leave at each
//! device advance once enumeration is complete. An endpoint whose message
//! restarts or powers off the machine hands the wrapper that transition.
use super::asc::{Firmware, Message, TransitionRequest};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::any::Any;

pub mod channel;

const MANAGEMENT: u8 = 0;
/// The crashlog system endpoint (see the module comment).
const CRASHLOG: u8 = 1;
const KDEBUG: u8 = 3;
const IOREPORTING: u8 = 4;
const TYPE_SHIFT: u32 = 52;
const TYPE: u64 = 0xf << TYPE_SHIFT;
const HELLO: u64 = 1;
const HELLO_REPLY: u64 = 2;
const PING: u64 = 3;
const PING_ACK: u64 = 4;
const ENDPOINT_CONTROL: u64 = 5;
const IOP_POWER: u64 = 6;
const IOP_POWER_ACK: u64 = 7;
const ROLL_CALL: u64 = 8;
const POWER_NAP: u64 = 0xa;
const AP_POWER: u64 = 0xb;

const HELLO_FLAGS: u64 = 0x3 << 32;
const LOW: u64 = 0xffff_ffff;
const ROLL_CALL_LAST: u64 = 1 << 51;
const ROLL_CALL_GROUP_SHIFT: u32 = 32;
/// The bits the AP's roll-call answer keeps from the request.
const ROLL_CALL_ECHO: u64 = 0x0008_003f_0000_0000;
const CONTROL_ENDPOINT_SHIFT: u32 = 32;
const CONTROL_ENDPOINT: u64 = 0xffff << CONTROL_ENDPOINT_SHIFT;
const ENABLE: u64 = 2;
const DISABLE: u64 = 1;

/// The IOP power state of a running coprocessor.
pub const POWER_ON: u64 = 0x20;
const IOP_STATES: [u64; 4] = [0x201, WAKE, 0x202, 0];
/// The IOP power state that wakes a quiesced coprocessor.
const WAKE: u64 = 0x220;
const AP_STATES: [u64; 3] = [0x201, POWER_ON, 0];

/// The first application endpoint.
pub const FIRST_APPLICATION: u8 = 0x20;

/// An application endpoint of the coprocessor.
pub trait Endpoint: Any {
    /// A physical reset loses the endpoint session without replying to the
    /// AP. Every endpoint must qualify its own native ownership first.
    fn check_reset(&self) -> Result<(), &'static str> {
        Err("RTKit endpoint volatile-state reset is not modeled")
    }
    fn reset(&mut self) -> Result<(), &'static str> {
        Err("RTKit endpoint volatile-state reset is not modeled")
    }
    /// The AP enabled the endpoint; messages it sends go to `outbox` as
    /// payloads on this endpoint.
    fn start(&mut self, outbox: &mut Vec<u64>) -> Result<(), &'static str>;
    /// The AP sent `payload` to the enabled endpoint.
    fn receive(&mut self, payload: u64, outbox: &mut Vec<u64>) -> Result<(), &'static str>;
    /// Messages the enabled endpoint sends on its own, such as events
    /// from the board, collected at each device advance. Output already
    /// appended is committed even if a later asynchronous operation fails;
    /// the endpoint must retain only unfinished work for retry.
    fn poll(&mut self, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        Ok(())
    }
    /// A machine transition the endpoint carries out for the AP's last
    /// message, once.
    fn take_transition(&mut self) -> Option<TransitionRequest> {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Quiesced by the boot chain, waiting for the AP's wake.
    Quiesced,
    /// HELLO sent, waiting for the AP's choice.
    Hello,
    /// Roll call of `group` sent, waiting for the AP's answer.
    RollCall { group: u8, last: bool },
    /// Enumerated; the AP enables endpoints.
    Ready,
}

/// Optional native system services with independent endpoint ownership. The
/// caller must supply actual protocol/resource implementations; these slots
/// never create a successful empty service or borrow application endpoint0x20.
#[derive(Default)]
pub struct SystemEndpoints {
    pub trace: Option<Box<dyn Endpoint>>,
    pub reporting: Option<Box<dyn Endpoint>>,
}

/// The RTKit operating system of one coprocessor.
pub struct RtKit {
    endpoints: BTreeMap<u8, (Box<dyn Endpoint>, bool)>,
    /// Whether the AP enabled the crashlog endpoint.
    crashlog: bool,
    stage: Stage,
    quiesced: bool,
    /// The wake state acknowledged when enumeration completes.
    wake: Option<u64>,
    iop_power: u64,
    /// The wrapper halted this CPU after a retained-sleep handshake.
    cpu_stopped: bool,
    ap_power: u64,
    power_nap: bool,
    /// The management protocol version it offers and accepts (the build's
    /// `rtkit_version`).
    version: u64,
}

fn management(kind: u64, fields: u64) -> Message {
    Message {
        endpoint: MANAGEMENT,
        payload: kind << TYPE_SHIFT | fields,
    }
}

impl RtKit {
    /// A coprocessor providing `endpoints`, each numbered from
    /// [`FIRST_APPLICATION`] up to 255.
    pub fn new(
        endpoints: Vec<(u8, Box<dyn Endpoint>)>,
        version: u64,
    ) -> Result<Self, &'static str> {
        Self::with_system_endpoints(endpoints, SystemEndpoints::default(), version)
    }

    /// Original RTBuddy consumes trace and IOReporting on system endpoints3/4.
    /// Enumerate only moved-in owners and route their control, input, polling
    /// and reset through the same actual endpoint session as application work.
    /// AP allocation, clock, mapping and queue resources remain their owners'
    /// responsibility; attaching an endpoint supplies no such authority.
    pub fn with_system_endpoints(
        endpoints: Vec<(u8, Box<dyn Endpoint>)>,
        system: SystemEndpoints,
        version: u64,
    ) -> Result<Self, &'static str> {
        let mut map = BTreeMap::new();
        for (number, endpoint) in endpoints {
            if number < FIRST_APPLICATION {
                return Err("RTKit application endpoints start at 0x20");
            }
            if map.insert(number, (endpoint, false)).is_some() {
                return Err("RTKit endpoint provided twice");
            }
        }
        for (number, endpoint) in [(KDEBUG, system.trace), (IOREPORTING, system.reporting)] {
            if let Some(endpoint) = endpoint {
                map.insert(number, (endpoint, false));
            }
        }
        Ok(Self {
            endpoints: map,
            crashlog: false,
            stage: Stage::Hello,
            quiesced: false,
            wake: None,
            iop_power: POWER_ON,
            cpu_stopped: false,
            ap_power: 0,
            power_nap: false,
            version,
        })
    }

    /// Join actual native resources after the cold ASC and DART have both
    /// been placed, before the AP begins enumeration. A previously queued
    /// HELLO remains the same message; the session is never restarted/replaced.
    pub fn attach_cold_system_endpoints(
        &mut self,
        system: SystemEndpoints,
    ) -> Result<(), &'static str> {
        if !matches!(self.stage, Stage::Hello | Stage::Quiesced)
            || self.cpu_stopped
            || self.crashlog
            || self.endpoints.values().any(|(_, enabled)| *enabled)
            || self.endpoints.contains_key(&KDEBUG)
            || self.endpoints.contains_key(&IOREPORTING)
        {
            return Err("RTKit native system owners must join once before enumeration");
        }
        for (number, endpoint) in [(KDEBUG, system.trace), (IOREPORTING, system.reporting)] {
            if let Some(endpoint) = endpoint {
                self.endpoints.insert(number, (endpoint, false));
            }
        }
        Ok(())
    }

    /// The boot chain hands the coprocessor off quiesced (DT `quiesced`).
    pub fn quiesced(mut self) -> Self {
        self.quiesced = true;
        self
    }

    /// The reached IOP power state, for retained device-state hooks.
    /// A rejected management message does not change this value.
    pub fn iop_power(&self) -> u64 {
        self.iop_power
    }

    /// Application endpoint `number`'s model, for board events it reports.
    pub fn endpoint_mut<E: Endpoint>(&mut self, number: u8) -> Option<&mut E> {
        let (endpoint, _) = self.endpoints.get_mut(&number)?;
        (&mut **endpoint as &mut dyn Any).downcast_mut()
    }

    fn hello(&mut self, outbox: &mut Vec<Message>) {
        self.stage = Stage::Hello;
        outbox.push(management(HELLO, self.version | self.version << 16));
    }

    /// Group `group`'s bitmap: the management and crashlog endpoints and the
    /// endpoints the model provides.
    fn bitmap(&self, group: u8) -> u32 {
        let provided = self
            .endpoints
            .keys()
            .filter(|&&n| n / 32 == group)
            .fold(0u32, |bits, &n| bits | 1 << (n % 32));
        let system = 1 << MANAGEMENT | 1 << CRASHLOG;
        provided | if group == 0 { system } else { 0 }
    }

    /// Groups 0 and every later one with endpoints, in order.
    fn next_group(&self, after: Option<u8>) -> Option<u8> {
        let first = after.map_or(0, |group| group + 1);
        (first..8).find(|&group| group == 0 || self.bitmap(group) != 0)
    }

    fn roll_call(&mut self, group: u8, outbox: &mut Vec<Message>) {
        let last = self.next_group(Some(group)).is_none();
        outbox.push(management(
            ROLL_CALL,
            u64::from(group) << ROLL_CALL_GROUP_SHIFT
                | u64::from(self.bitmap(group))
                | if last { ROLL_CALL_LAST } else { 0 },
        ));
        self.stage = Stage::RollCall { group, last };
    }

    fn control(&mut self, fields: u64, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        if fields & !(CONTROL_ENDPOINT | LOW) != 0 {
            return Err("RTKit endpoint control field is not modeled");
        }
        let number = u8::try_from((fields & CONTROL_ENDPOINT) >> CONTROL_ENDPOINT_SHIFT)
            .map_err(|_| "RTKit endpoint control of an endpoint above 255")?;
        if number == CRASHLOG {
            // The crashlog endpoint sends nothing when started: a native
            // coprocessor requests no crashlog buffer.
            self.crashlog = match fields & LOW {
                ENABLE => true,
                DISABLE => false,
                _ => return Err("RTKit endpoint control other than enable and disable"),
            };
            return Ok(());
        }
        let (endpoint, enabled) = self
            .endpoints
            .get_mut(&number)
            .ok_or("RTKit endpoint control of an endpoint the coprocessor does not have")?;
        match fields & LOW {
            ENABLE => {
                let mut sent = Vec::new();
                endpoint.start(&mut sent)?;
                *enabled = true;
                outbox.extend(sent.into_iter().map(|payload| Message {
                    endpoint: number,
                    payload,
                }));
                Ok(())
            }
            DISABLE => {
                *enabled = false;
                Ok(())
            }
            _ => Err("RTKit endpoint control other than enable and disable"),
        }
    }

    fn manage(&mut self, payload: u64, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        let kind = (payload & TYPE) >> TYPE_SHIFT;
        let fields = payload & !TYPE;
        match (kind, self.stage) {
            (HELLO_REPLY, Stage::Hello) => {
                if fields & !HELLO_FLAGS != self.version | self.version << 16 {
                    return Err("RTKit HELLO_REPLY did not choose the offered version");
                }
                self.roll_call(0, outbox);
                Ok(())
            }
            (ROLL_CALL, Stage::RollCall { group, last }) => {
                if fields & !(ROLL_CALL_ECHO | LOW) != 0
                    || fields & ROLL_CALL_ECHO
                        != u64::from(group) << ROLL_CALL_GROUP_SHIFT
                            | if last { ROLL_CALL_LAST } else { 0 }
                {
                    return Err("RTKit roll-call answer does not answer the last group");
                }
                match self.next_group(Some(group)) {
                    Some(next) => self.roll_call(next, outbox),
                    None => {
                        self.stage = Stage::Ready;
                        if let Some(state) = self.wake.take() {
                            outbox.push(management(IOP_POWER_ACK, state));
                        } else {
                            outbox.push(management(IOP_POWER_ACK, POWER_ON));
                        }
                    }
                }
                Ok(())
            }
            (IOP_POWER, Stage::Quiesced) if fields == WAKE => {
                self.iop_power = fields;
                self.wake = Some(fields);
                self.hello(outbox);
                Ok(())
            }
            (_, Stage::Quiesced) => Err("RTKit quiesced coprocessor takes only the IOP power wake"),
            // The AP starts each system endpoint as its roll-call group
            // creates it, before answering the group (restore study ru-s58:
            // the crashlog endpoint's start arrived mid-enumeration).
            (ENDPOINT_CONTROL, Stage::RollCall { .. } | Stage::Ready) => {
                self.control(fields, outbox)
            }
            (IOP_POWER, _) if IOP_STATES.contains(&fields) => {
                self.iop_power = fields;
                outbox.push(management(IOP_POWER_ACK, fields));
                Ok(())
            }
            (AP_POWER, _) if AP_STATES.contains(&fields) => {
                self.ap_power = fields;
                outbox.push(management(AP_POWER, fields));
                Ok(())
            }
            (PING, _) => {
                outbox.push(management(PING_ACK, fields & LOW));
                Ok(())
            }
            (POWER_NAP, _) if fields <= 1 => {
                self.power_nap = fields == 1;
                Ok(())
            }
            _ => Err("RTKit management message is not modeled in this stage"),
        }
    }
}

impl Firmware for RtKit {
    fn check_reset(&self) -> Result<(), &'static str> {
        for (endpoint, _) in self.endpoints.values() {
            endpoint.check_reset()?;
        }
        Ok(())
    }

    fn reset(&mut self) -> Result<(), &'static str> {
        self.check_reset()?;
        for (endpoint, enabled) in self.endpoints.values_mut() {
            endpoint
                .reset()
                .expect("RTKit endpoint reset was preflighted");
            *enabled = false;
        }
        self.crashlog = false;
        self.stage = Stage::Hello;
        // `quiesced` describes a boot-chain handoff, not subsequent cold
        // reset. A new RUN must begin a fresh HELLO and enumeration.
        self.quiesced = false;
        self.wake = None;
        self.iop_power = POWER_ON;
        self.cpu_stopped = false;
        self.ap_power = 0;
        self.power_nap = false;
        Ok(())
    }
    fn start(&mut self, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        if self.cpu_stopped {
            return Err("RTKit cold start cannot replace a retained CPU resume");
        }
        if self.quiesced {
            self.stage = Stage::Quiesced;
        } else {
            self.hello(outbox);
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), &'static str> {
        if self.stage != Stage::Ready || !matches!(self.iop_power, 0x201 | 0x202) {
            return Err("RTKit CPU stop requires a completed retained-sleep handshake");
        }
        self.cpu_stopped = true;
        Ok(())
    }

    fn resume(&mut self, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        if !self.cpu_stopped {
            return Err("RTKit CPU resume without a retained halt");
        }
        self.cpu_stopped = false;
        self.iop_power = POWER_ON;
        outbox.push(management(IOP_POWER_ACK, POWER_ON));
        Ok(())
    }

    fn receive(&mut self, message: Message, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        if self.cpu_stopped {
            return Err("RTKit message while its CPU is halted");
        }
        if message.endpoint == MANAGEMENT {
            return self.manage(message.payload, outbox);
        }
        if message.endpoint == CRASHLOG {
            return Err(if self.crashlog {
                "RTKit crashlog endpoint takes no AP message: the coprocessor requested no buffer"
            } else {
                "RTKit message to an endpoint the AP has not enabled"
            });
        }
        let (endpoint, enabled) = self
            .endpoints
            .get_mut(&message.endpoint)
            .ok_or("RTKit message to an endpoint the coprocessor does not have")?;
        if !*enabled {
            return Err("RTKit message to an endpoint the AP has not enabled");
        }
        let mut sent = Vec::new();
        endpoint.receive(message.payload, &mut sent)?;
        outbox.extend(sent.into_iter().map(|payload| Message {
            endpoint: message.endpoint,
            payload,
        }));
        Ok(())
    }

    /// Unsolicited messages of the enabled endpoints, once the AP has
    /// enumerated them.
    fn poll(&mut self, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        if self.cpu_stopped || self.stage != Stage::Ready {
            return Ok(());
        }
        for (&number, (endpoint, enabled)) in &mut self.endpoints {
            if !*enabled {
                continue;
            }
            let mut sent = Vec::new();
            let result = endpoint.poll(&mut sent);
            outbox.extend(sent.into_iter().map(|payload| Message {
                endpoint: number,
                payload,
            }));
            result?;
        }
        Ok(())
    }

    fn take_transition(&mut self) -> Option<TransitionRequest> {
        self.endpoints
            .values_mut()
            .find_map(|(endpoint, _)| endpoint.take_transition())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const VERSION: u64 = stela_formats::builds::DEFAULT.rtkit_version;

    #[test]
    fn a_physical_reset_clears_enumeration_without_reusing_boot_quiescence() {
        let mut kit = RtKit::new(
            vec![(0x20, Box::new(super::super::pmp::Pmp::default()))],
            stela_formats::builds::DEFAULT.rtkit_version,
        )
        .unwrap()
        .quiesced();
        let mut output = Vec::new();
        kit.start(&mut output).unwrap();
        assert!(output.is_empty());
        kit.check_reset().unwrap();
        kit.reset().unwrap();
        assert!(output.is_empty());
        kit.start(&mut output).unwrap();
        assert_eq!(output, [management(HELLO, VERSION | VERSION << 16)]);
        assert!(step(&mut kit, 0x20, 2 << 52).is_err());
        mgmt(&mut kit, HELLO_REPLY, VERSION | VERSION << 16).unwrap();
        mgmt(&mut kit, ROLL_CALL, 1).unwrap();
        mgmt(&mut kit, ROLL_CALL, ROLL_CALL_LAST | 1 << 32).unwrap();
        mgmt(&mut kit, ENDPOINT_CONTROL, 0x20 << 32 | ENABLE).unwrap();
        assert_eq!(
            step(&mut kit, 0x20, 2 << 52 | 123).unwrap()[0].payload,
            0x21 << 48 | 123
        );
    }

    /// Answers every payload with its complement.
    struct Complement;
    impl Endpoint for Complement {
        fn start(&mut self, outbox: &mut Vec<u64>) -> Result<(), &'static str> {
            outbox.push(0x5);
            Ok(())
        }
        fn receive(&mut self, payload: u64, outbox: &mut Vec<u64>) -> Result<(), &'static str> {
            outbox.push(!payload);
            Ok(())
        }
    }

    fn step(rtkit: &mut RtKit, endpoint: u8, payload: u64) -> Result<Vec<Message>, &'static str> {
        let mut outbox = Vec::new();
        rtkit.receive(Message { endpoint, payload }, &mut outbox)?;
        Ok(outbox)
    }

    fn mgmt(rtkit: &mut RtKit, kind: u64, fields: u64) -> Result<Vec<Message>, &'static str> {
        step(rtkit, 0, management(kind, fields).payload)
    }

    fn booted() -> RtKit {
        let mut rtkit = RtKit::new(
            vec![
                (0x20, Box::new(Complement) as Box<dyn Endpoint>),
                (0x41, Box::new(Complement)),
            ],
            stela_formats::builds::DEFAULT.rtkit_version,
        )
        .unwrap();
        let mut outbox = Vec::new();
        rtkit.start(&mut outbox).unwrap();
        assert_eq!(outbox, vec![management(HELLO, 12 | 12 << 16)]);
        rtkit
    }

    #[test]
    fn cold_system_binding_keeps_the_started_session_and_precedes_roll_call() {
        let mut kit = RtKit::new(Vec::new(), stela_formats::builds::DEFAULT.rtkit_version).unwrap();
        let mut initial = Vec::new();
        kit.start(&mut initial).unwrap();
        kit.attach_cold_system_endpoints(SystemEndpoints {
            trace: Some(Box::new(Complement)),
            reporting: Some(Box::new(Complement)),
        })
        .unwrap();
        assert_eq!(initial, vec![management(HELLO, VERSION | VERSION << 16)]);
        assert_eq!(
            mgmt(&mut kit, HELLO_REPLY, VERSION | VERSION << 16).unwrap(),
            vec![management(
                ROLL_CALL,
                ROLL_CALL_LAST | 3 | 1 << KDEBUG | 1 << IOREPORTING,
            )]
        );
        mgmt(&mut kit, ROLL_CALL, ROLL_CALL_LAST).unwrap();
        assert!(
            kit.attach_cold_system_endpoints(SystemEndpoints::default())
                .is_err()
        );
        assert!(step(&mut kit, IOREPORTING, 7).is_err());
    }

    #[test]
    fn late_or_duplicate_native_binding_refuses_before_changing_the_endpoint_map() {
        let mut kit = RtKit::new(Vec::new(), stela_formats::builds::DEFAULT.rtkit_version).unwrap();
        let mut initial = Vec::new();
        kit.start(&mut initial).unwrap();
        mgmt(&mut kit, HELLO_REPLY, VERSION | VERSION << 16).unwrap();
        assert!(
            kit.attach_cold_system_endpoints(SystemEndpoints {
                trace: Some(Box::new(Complement)),
                reporting: Some(Box::new(Complement)),
            })
            .is_err()
        );
        assert_eq!(kit.bitmap(0), 3);
        let mut kit = RtKit::with_system_endpoints(
            Vec::new(),
            SystemEndpoints {
                trace: Some(Box::new(Complement)),
                reporting: None,
            },
            stela_formats::builds::DEFAULT.rtkit_version,
        )
        .unwrap();
        assert!(
            kit.attach_cold_system_endpoints(SystemEndpoints {
                trace: None,
                reporting: Some(Box::new(Complement)),
            })
            .is_err()
        );
        assert_eq!(kit.bitmap(0), 3 | 1 << KDEBUG);
    }

    #[test]
    fn explicit_system_owners_enumerate_and_receive_on_their_own_session() {
        let mut kit = RtKit::with_system_endpoints(
            Vec::new(),
            SystemEndpoints {
                trace: Some(Box::new(Complement)),
                reporting: Some(Box::new(Complement)),
            },
            stela_formats::builds::DEFAULT.rtkit_version,
        )
        .unwrap();
        let mut output = Vec::new();
        kit.start(&mut output).unwrap();
        assert_eq!(
            mgmt(&mut kit, HELLO_REPLY, VERSION | VERSION << 16).unwrap(),
            vec![management(
                ROLL_CALL,
                ROLL_CALL_LAST | 3 | 1 << KDEBUG | 1 << IOREPORTING
            )]
        );
        mgmt(&mut kit, ROLL_CALL, ROLL_CALL_LAST).unwrap();
        assert!(step(&mut kit, KDEBUG, 7).is_err());
        assert!(step(&mut kit, IOREPORTING, 7).is_err());
        for number in [KDEBUG, IOREPORTING] {
            assert_eq!(
                mgmt(&mut kit, ENDPOINT_CONTROL, u64::from(number) << 32 | ENABLE).unwrap(),
                vec![Message {
                    endpoint: number,
                    payload: 5
                }]
            );
            assert_eq!(
                step(&mut kit, number, 7).unwrap(),
                vec![Message {
                    endpoint: number,
                    payload: !7
                }]
            );
        }
        mgmt(
            &mut kit,
            ENDPOINT_CONTROL,
            u64::from(KDEBUG) << 32 | DISABLE,
        )
        .unwrap();
        assert!(step(&mut kit, KDEBUG, 7).is_err());
        assert!(step(&mut kit, IOREPORTING, 7).is_ok());
        assert!(step(&mut kit, FIRST_APPLICATION, 7).is_err());
        // Existing callers cannot smuggle a system service into the ordinary
        // application constructor or replace the reserved crashlog owner.
        assert!(
            RtKit::new(
                vec![(IOREPORTING, Box::new(Complement))],
                stela_formats::builds::DEFAULT.rtkit_version
            )
            .is_err()
        );
    }

    #[test]
    fn the_coprocessor_says_hello_rolls_call_and_serves_its_endpoints() {
        let mut rtkit = booted();
        assert!(mgmt(&mut rtkit, HELLO_REPLY, 11 | 11 << 16).is_err());
        // Group 0 holds the management and crashlog endpoints.
        let call = mgmt(&mut rtkit, HELLO_REPLY, 1 << 32 | 12 | 12 << 16).unwrap();
        assert_eq!(call, vec![management(ROLL_CALL, 3)]);
        assert!(mgmt(&mut rtkit, ROLL_CALL, 1 << 32 | 1).is_err());
        // 0x20 is bit 0 of group 1, 0x41 bit 1 of group 2, the last.
        let call = mgmt(&mut rtkit, ROLL_CALL, 1).unwrap();
        assert_eq!(call, vec![management(ROLL_CALL, 1 << 32 | 1)]);
        let call = mgmt(&mut rtkit, ROLL_CALL, 1 << 32).unwrap();
        assert_eq!(
            call,
            vec![management(ROLL_CALL, ROLL_CALL_LAST | 2 << 32 | 2)]
        );
        assert!(step(&mut rtkit, 0x20, 1).is_err());
        assert_eq!(
            mgmt(&mut rtkit, ROLL_CALL, ROLL_CALL_LAST | 2 << 32).unwrap(),
            vec![management(IOP_POWER_ACK, POWER_ON)]
        );
        let started = mgmt(&mut rtkit, ENDPOINT_CONTROL, 0x20 << 32 | ENABLE).unwrap();
        assert_eq!(
            started,
            vec![Message {
                endpoint: 0x20,
                payload: 5
            }]
        );
        assert_eq!(
            step(&mut rtkit, 0x20, 0xf0).unwrap(),
            vec![Message {
                endpoint: 0x20,
                payload: !0xf0
            }]
        );
        assert!(step(&mut rtkit, 0x41, 1).is_err());
        assert!(
            mgmt(&mut rtkit, ENDPOINT_CONTROL, 0x20 << 32 | DISABLE)
                .unwrap()
                .is_empty()
        );
        assert!(step(&mut rtkit, 0x20, 1).is_err());
        assert!(mgmt(&mut rtkit, ENDPOINT_CONTROL, 0x21 << 32 | ENABLE).is_err());
        assert!(mgmt(&mut rtkit, ENDPOINT_CONTROL, 0x20 << 32 | 3).is_err());
    }

    #[test]
    fn the_crashlog_endpoint_starts_silently_and_takes_no_ap_message() {
        let mut rtkit = booted();
        // Endpoint control before the roll call names anything refuses.
        assert!(mgmt(&mut rtkit, ENDPOINT_CONTROL, 1 << 32 | ENABLE).is_err());
        mgmt(&mut rtkit, HELLO_REPLY, 12 | 12 << 16).unwrap();
        // The AP starts the crashlog endpoint while answering group 0.
        assert!(
            mgmt(&mut rtkit, ENDPOINT_CONTROL, 1 << 32 | ENABLE)
                .unwrap()
                .is_empty()
        );
        mgmt(&mut rtkit, ROLL_CALL, 3).unwrap();
        mgmt(&mut rtkit, ROLL_CALL, 1 << 32).unwrap();
        mgmt(&mut rtkit, ROLL_CALL, ROLL_CALL_LAST | 2 << 32).unwrap();
        assert!(step(&mut rtkit, CRASHLOG, 1).is_err());
        // Enabling it requests no buffer; a buffer answer or any other AP
        // message refuses, enabled or not.
        let started = mgmt(&mut rtkit, ENDPOINT_CONTROL, 1 << 32 | ENABLE).unwrap();
        assert!(started.is_empty());
        let refusal = step(&mut rtkit, CRASHLOG, 0x1 << 52 | 0x8000).unwrap_err();
        assert!(refusal.contains("no buffer"), "{refusal}");
        assert!(mgmt(&mut rtkit, ENDPOINT_CONTROL, 1 << 32 | 3).is_err());
        assert!(
            mgmt(&mut rtkit, ENDPOINT_CONTROL, 1 << 32 | DISABLE)
                .unwrap()
                .is_empty()
        );
        // Other system endpoints stay absent.
        assert!(mgmt(&mut rtkit, ENDPOINT_CONTROL, 2 << 32 | ENABLE).is_err());
    }

    #[test]
    fn power_pings_and_naps_are_answered_as_the_ap_expects() {
        let mut rtkit = booted();
        mgmt(&mut rtkit, HELLO_REPLY, 12 | 12 << 16).unwrap();
        mgmt(&mut rtkit, ROLL_CALL, 1).unwrap();
        mgmt(&mut rtkit, ROLL_CALL, 1 << 32).unwrap();
        // An ordinarily managed IOP announces power-on.
        assert_eq!(
            mgmt(&mut rtkit, ROLL_CALL, ROLL_CALL_LAST | 2 << 32 | 1).unwrap(),
            vec![management(IOP_POWER_ACK, POWER_ON)]
        );
        assert_eq!(
            mgmt(&mut rtkit, IOP_POWER, 0x220).unwrap(),
            vec![management(IOP_POWER_ACK, 0x220)]
        );
        assert_eq!(
            mgmt(&mut rtkit, AP_POWER, 0x201).unwrap(),
            vec![management(AP_POWER, 0x201)]
        );
        assert_eq!(
            mgmt(&mut rtkit, PING, 0x1234 << 32 | 21).unwrap(),
            vec![management(PING_ACK, 21)]
        );
        assert!(mgmt(&mut rtkit, POWER_NAP, 1).unwrap().is_empty());
        assert!(mgmt(&mut rtkit, IOP_POWER, 0x10).is_err());
        assert!(mgmt(&mut rtkit, AP_POWER, 0x202).is_err());
        assert!(mgmt(&mut rtkit, POWER_NAP, 2).is_err());
        assert!(mgmt(&mut rtkit, 0xf, 0).is_err());
    }

    #[test]
    fn retained_cpu_halt_requires_sleep_and_resumes_without_enumeration() {
        for sleep in [0x201, 0x202] {
            let mut rtkit = booted();
            assert!(rtkit.stop().is_err()); // Incomplete protocol start.
            mgmt(&mut rtkit, HELLO_REPLY, 12 | 12 << 16).unwrap();
            mgmt(&mut rtkit, ROLL_CALL, 1).unwrap();
            mgmt(&mut rtkit, ROLL_CALL, 1 << 32).unwrap();
            mgmt(&mut rtkit, ROLL_CALL, ROLL_CALL_LAST | 2 << 32).unwrap();
            mgmt(&mut rtkit, ENDPOINT_CONTROL, 0x20 << 32 | ENABLE).unwrap();
            assert!(rtkit.stop().is_err()); // Awake, not retained sleep.
            mgmt(&mut rtkit, IOP_POWER, 0).unwrap();
            assert!(rtkit.stop().is_err()); // Memory-loss power state.
            mgmt(&mut rtkit, IOP_POWER, sleep).unwrap();
            rtkit.stop().unwrap();
            assert_eq!(rtkit.iop_power(), sleep);
            assert!(step(&mut rtkit, 0x20, 7).is_err());
            assert!(mgmt(&mut rtkit, IOP_POWER, WAKE).is_err());
            assert!(rtkit.start(&mut Vec::new()).is_err());
            let mut out = Vec::new();
            rtkit.resume(&mut out).unwrap();
            assert_eq!(out, [management(IOP_POWER_ACK, POWER_ON)]);
            assert_eq!(rtkit.iop_power(), POWER_ON);
            assert_eq!(rtkit.stage, Stage::Ready);
            assert!(rtkit.resume(&mut out).is_err());
            assert_eq!(out, [management(IOP_POWER_ACK, POWER_ON)]);
            assert_eq!(
                mgmt(&mut rtkit, IOP_POWER, WAKE).unwrap(),
                vec![management(IOP_POWER_ACK, WAKE)]
            );
            // The endpoint remains enabled and its existing native state serves
            // another request without a new endpoint control or roll call.
            assert_eq!(step(&mut rtkit, 0x20, 7).unwrap()[0].payload, !7u64);
        }
    }

    #[test]
    fn the_restore_boot_pmp_handshake_ends_with_the_power_on_announcement() {
        // The AP's side of restore boot s25's PMP mailbox log, word for
        // word: the AP waited 20 s for running after its last answer.
        let mut rtkit = RtKit::new(
            vec![(0x20, Box::new(Complement) as Box<dyn Endpoint>)],
            stela_formats::builds::DEFAULT.rtkit_version,
        )
        .unwrap();
        let raw = |rtkit: &mut RtKit, payload| step(rtkit, 0, payload).unwrap();
        let mut outbox = Vec::new();
        rtkit.start(&mut outbox).unwrap();
        let payloads = |messages: Vec<Message>| -> Vec<u64> {
            messages
                .iter()
                .inspect(|message| assert_eq!(message.endpoint, 0))
                .map(|message| message.payload)
                .collect()
        };
        assert_eq!(payloads(outbox), [0x0010_0000_000c_000c]);
        // Group 0 now also lists the crashlog endpoint (bit 1), which s25's
        // coprocessor did not; the AP's answers are unchanged.
        assert_eq!(
            payloads(raw(&mut rtkit, 0x0020_0000_000c_000c)),
            [0x0080_0000_0000_0003]
        );
        assert_eq!(
            payloads(raw(&mut rtkit, 0x0080_0000_0000_0001)),
            [0x0088_0001_0000_0001]
        );
        assert_eq!(
            payloads(raw(&mut rtkit, 0x0088_0001_0000_0000)),
            [0x0070_0000_0000_0020]
        );
        // The client driver's STARTEP of 0x20 starts the endpoint.
        assert_eq!(
            raw(&mut rtkit, 0x0050_0020_0000_0002),
            [Message {
                endpoint: 0x20,
                payload: 5
            }]
        );
    }

    #[test]
    fn a_quiesced_coprocessor_waits_for_its_wake_and_acks_it_after_enumeration() {
        let mut rtkit = RtKit::new(
            vec![(0x20, Box::new(Complement) as Box<dyn Endpoint>)],
            stela_formats::builds::DEFAULT.rtkit_version,
        )
        .unwrap()
        .quiesced();
        let mut outbox = Vec::new();
        rtkit.start(&mut outbox).unwrap();
        assert!(outbox.is_empty());
        assert!(mgmt(&mut rtkit, AP_POWER, POWER_ON).is_err());
        assert!(mgmt(&mut rtkit, HELLO_REPLY, 12 | 12 << 16).is_err());
        assert_eq!(
            mgmt(&mut rtkit, IOP_POWER, WAKE).unwrap(),
            vec![management(HELLO, 12 | 12 << 16)]
        );
        mgmt(&mut rtkit, HELLO_REPLY, 12 | 12 << 16).unwrap();
        // No ack before the last group is answered.
        assert_eq!(
            mgmt(&mut rtkit, ROLL_CALL, 1).unwrap(),
            vec![management(ROLL_CALL, ROLL_CALL_LAST | 1 << 32 | 1)]
        );
        assert_eq!(
            mgmt(&mut rtkit, ROLL_CALL, ROLL_CALL_LAST | 1 << 32).unwrap(),
            vec![management(IOP_POWER_ACK, WAKE)]
        );
    }

    /// Sends `pending` on its own and restarts the machine on any message.
    #[derive(Default)]
    struct Board {
        pending: Vec<u64>,
        restart: bool,
    }
    impl Endpoint for Board {
        fn start(&mut self, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
            Ok(())
        }
        fn receive(&mut self, _payload: u64, _outbox: &mut Vec<u64>) -> Result<(), &'static str> {
            self.restart = true;
            Ok(())
        }
        fn poll(&mut self, outbox: &mut Vec<u64>) -> Result<(), &'static str> {
            outbox.append(&mut self.pending);
            Ok(())
        }
        fn take_transition(&mut self) -> Option<TransitionRequest> {
            core::mem::take(&mut self.restart).then_some(TransitionRequest {
                device: "board",
                transition: super::super::bus::Transition::Restart,
                reason: "test",
            })
        }
    }

    #[test]
    fn enabled_endpoints_send_board_events_and_carry_transitions() {
        let mut rtkit = RtKit::new(
            vec![(0x20, Box::new(Board::default()) as Box<dyn Endpoint>)],
            stela_formats::builds::DEFAULT.rtkit_version,
        )
        .unwrap();
        rtkit.start(&mut Vec::new()).unwrap();
        rtkit.endpoint_mut::<Board>(0x20).unwrap().pending.push(9);
        assert!(rtkit.endpoint_mut::<Complement>(0x20).is_none());
        assert!(rtkit.endpoint_mut::<Board>(0x21).is_none());
        // Nothing leaves before enumeration and the endpoint's enable.
        let mut outbox = Vec::new();
        Firmware::poll(&mut rtkit, &mut outbox).unwrap();
        assert!(outbox.is_empty());
        mgmt(&mut rtkit, HELLO_REPLY, 12 | 12 << 16).unwrap();
        mgmt(&mut rtkit, ROLL_CALL, 0).unwrap();
        mgmt(&mut rtkit, ROLL_CALL, ROLL_CALL_LAST | 1 << 32).unwrap();
        Firmware::poll(&mut rtkit, &mut outbox).unwrap();
        assert!(outbox.is_empty());
        mgmt(&mut rtkit, ENDPOINT_CONTROL, 0x20 << 32 | ENABLE).unwrap();
        Firmware::poll(&mut rtkit, &mut outbox).unwrap();
        assert_eq!(
            outbox,
            vec![Message {
                endpoint: 0x20,
                payload: 9
            }]
        );
        assert!(Firmware::take_transition(&mut rtkit).is_none());
        step(&mut rtkit, 0x20, 1).unwrap();
        let request = Firmware::take_transition(&mut rtkit).unwrap();
        assert_eq!(request.device, "board");
        assert!(Firmware::take_transition(&mut rtkit).is_none());
    }

    #[test]
    fn endpoints_are_application_endpoints_once_each() {
        let one = || Box::new(Complement) as Box<dyn Endpoint>;
        assert!(
            RtKit::new(
                vec![(0x2, one())],
                stela_formats::builds::DEFAULT.rtkit_version
            )
            .is_err()
        );
        assert!(
            RtKit::new(
                vec![(0x20, one()), (0x20, one())],
                stela_formats::builds::DEFAULT.rtkit_version
            )
            .is_err()
        );
    }
}
