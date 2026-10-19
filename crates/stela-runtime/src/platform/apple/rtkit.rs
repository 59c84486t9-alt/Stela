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
//! endpoints while the AP still waits.
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
//! The roll call lists exactly the endpoints the model provides. RTKit's
//! system endpoints (crashlog 1, syslog 2, kdebug 3, IOReporting 4, OSLog 8,
//! ...) are services of Apple's firmware this coprocessor does not have, so
//! they are not listed rather than advertised with nothing behind them.
//! Every other management message refuses.
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

const MANAGEMENT: u8 = 0;
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

/// The protocol version the coprocessor offers.
pub const VERSION: u64 = 12;
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
    /// The AP enabled the endpoint; messages it sends go to `outbox` as
    /// payloads on this endpoint.
    fn start(&mut self, outbox: &mut Vec<u64>) -> Result<(), &'static str>;
    /// The AP sent `payload` to the enabled endpoint.
    fn receive(&mut self, payload: u64, outbox: &mut Vec<u64>) -> Result<(), &'static str>;
    /// Messages the enabled endpoint sends on its own, such as events
    /// from the board, collected at each device advance.
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

/// What completes the coprocessor's start-up for the AP (see the module
/// comment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Management {
    /// `remote-only` or `automatic-rail-gating-enabled`: enumeration does,
    /// and the coprocessor announces nothing.
    Enumeration,
    /// Every other nub: the coprocessor announces power-on after
    /// enumeration.
    Ordinary,
}

/// The RTKit operating system of one coprocessor.
pub struct RtKit {
    endpoints: BTreeMap<u8, (Box<dyn Endpoint>, bool)>,
    management: Management,
    stage: Stage,
    quiesced: bool,
    /// The wake state acknowledged when enumeration completes.
    wake: Option<u64>,
    iop_power: u64,
    ap_power: u64,
    power_nap: bool,
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
        management: Management,
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
        Ok(Self {
            endpoints: map,
            management,
            stage: Stage::Hello,
            quiesced: false,
            wake: None,
            iop_power: POWER_ON,
            ap_power: 0,
            power_nap: false,
        })
    }

    /// The boot chain hands the coprocessor off quiesced (DT `quiesced`).
    pub fn quiesced(mut self) -> Self {
        self.quiesced = true;
        self
    }

    /// Application endpoint `number`'s model, for board events it reports.
    pub fn endpoint_mut<E: Endpoint>(&mut self, number: u8) -> Option<&mut E> {
        let (endpoint, _) = self.endpoints.get_mut(&number)?;
        (&mut **endpoint as &mut dyn Any).downcast_mut()
    }

    fn hello(&mut self, outbox: &mut Vec<Message>) {
        self.stage = Stage::Hello;
        outbox.push(management(HELLO, VERSION | VERSION << 16));
    }

    /// Group `group`'s bitmap: the management endpoint and the endpoints the
    /// model provides.
    fn bitmap(&self, group: u8) -> u32 {
        let provided = self
            .endpoints
            .keys()
            .filter(|&&n| n / 32 == group)
            .fold(0u32, |bits, &n| bits | 1 << (n % 32));
        provided | u32::from(group == 0)
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
                if fields & !HELLO_FLAGS != VERSION | VERSION << 16 {
                    return Err("RTKit HELLO_REPLY did not choose version 12");
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
                        } else if self.management == Management::Ordinary {
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
            (ENDPOINT_CONTROL, Stage::Ready) => self.control(fields, outbox),
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
    fn start(&mut self, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        if self.quiesced {
            self.stage = Stage::Quiesced;
        } else {
            self.hello(outbox);
        }
        Ok(())
    }

    fn receive(&mut self, message: Message, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        if message.endpoint == MANAGEMENT {
            return self.manage(message.payload, outbox);
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
        if self.stage != Stage::Ready {
            return Ok(());
        }
        for (&number, (endpoint, enabled)) in &mut self.endpoints {
            if !*enabled {
                continue;
            }
            let mut sent = Vec::new();
            endpoint.poll(&mut sent)?;
            outbox.extend(sent.into_iter().map(|payload| Message {
                endpoint: number,
                payload,
            }));
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

    fn booted(management_kind: Management) -> RtKit {
        let mut rtkit = RtKit::new(
            vec![
                (0x20, Box::new(Complement) as Box<dyn Endpoint>),
                (0x41, Box::new(Complement)),
            ],
            management_kind,
        )
        .unwrap();
        let mut outbox = Vec::new();
        rtkit.start(&mut outbox).unwrap();
        assert_eq!(outbox, vec![management(HELLO, 12 | 12 << 16)]);
        rtkit
    }

    #[test]
    fn the_coprocessor_says_hello_rolls_call_and_serves_its_endpoints() {
        let mut rtkit = booted(Management::Enumeration);
        assert!(mgmt(&mut rtkit, HELLO_REPLY, 11 | 11 << 16).is_err());
        // Group 0 holds the management endpoint alone.
        let call = mgmt(&mut rtkit, HELLO_REPLY, 1 << 32 | 12 | 12 << 16).unwrap();
        assert_eq!(call, vec![management(ROLL_CALL, 1)]);
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
        // An IOP the AP does not wait for announces nothing at the end of
        // enumeration.
        assert!(
            mgmt(&mut rtkit, ROLL_CALL, ROLL_CALL_LAST | 2 << 32)
                .unwrap()
                .is_empty()
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
    fn power_pings_and_naps_are_answered_as_the_ap_expects() {
        let mut rtkit = booted(Management::Ordinary);
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
    fn the_restore_boot_pmp_handshake_ends_with_the_power_on_announcement() {
        // The AP's side of restore boot s25's PMP mailbox log, word for
        // word: the AP waited 20 s for running after its last answer.
        let mut rtkit = RtKit::new(
            vec![(0x20, Box::new(Complement) as Box<dyn Endpoint>)],
            Management::Ordinary,
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
        assert_eq!(
            payloads(raw(&mut rtkit, 0x0020_0000_000c_000c)),
            [0x0080_0000_0000_0001]
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
            Management::Ordinary,
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
            Management::Ordinary,
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
        assert!(RtKit::new(vec![(0x2, one())], Management::Ordinary).is_err());
        assert!(RtKit::new(vec![(0x20, one()), (0x20, one())], Management::Ordinary).is_err());
    }
}
