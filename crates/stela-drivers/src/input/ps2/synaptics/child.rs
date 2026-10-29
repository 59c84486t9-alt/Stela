// SPDX-License-Identifier: GPL-2.0-only
// Original Synaptics/libps2/psmouse notices: ../synaptics.rs and input/THIRD_PARTY.md.
//! One negotiated standard/IntelliMouse/Explorer passthrough mouse.
//! Input remains separate from the parent touchpad, under its i8042
//! owner. Vendor child protocols and guest/frontend attachment are separate.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub native_sequence: u64,
    /// Microseconds from the native controller's clock origin.
    pub received_us: u64,
    pub byte: u8,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    pub opcode: u8,
    pub argument: Option<u8>,
    pub acknowledged: u8,
    pub observations: Vec<Observation>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    /// False for the source's ID-without-ACK workaround.
    pub acknowledged: bool,
    pub observation: Observation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScrollMode {
    Ordinary,
    Explorer4,
}
#[derive(Default)]
pub(super) struct Mouse {
    pub(super) protocol: Option<MouseProtocol>,
    pub(super) active: bool,
    pub(super) waiting: bool,
    replies: VecDeque<Observation>,
    pub(super) command: Option<Command>,
    identities: Vec<Identity>,
    enhanced_scroll: bool,
    decoder: mouse::Mouse,
    events: Vec<Input>,
    horizontal: Vec<i8>,
}
impl Mouse {
    pub(super) fn backpressured(&self) -> bool {
        self.events.len() + self.horizontal.len() >= QUEUE_LIMIT
    }
    pub(super) fn receive(
        &mut self,
        record: passthrough::Record,
        now: u64,
        timeout: u64,
    ) -> Result<(), ErrorKind> {
        if self.waiting {
            let observation = Observation {
                native_sequence: record.native_sequence,
                received_us: now,
                byte: record.first(),
            };
            if self.replies.len() >= QUEUE_LIMIT
                || self.command.as_ref().unwrap().observations.len() >= QUEUE_LIMIT
            {
                return Err(ErrorKind::QueueFull);
            }
            self.command
                .as_mut()
                .unwrap()
                .observations
                .push(observation);
            self.replies.push_back(observation);
        } else if self.active {
            if self.backpressured() {
                return Err(ErrorKind::QueueFull);
            }
            let count = if self.protocol == Some(MouseProtocol::Standard) {
                3
            } else {
                4
            };
            for byte in &record.fields()[..count] {
                if self.enhanced_scroll {
                    self.decoder.feed_with_scroll(
                        *byte,
                        now,
                        timeout,
                        &mut self.events,
                        Some(&mut self.horizontal),
                    )?;
                } else {
                    self.decoder.feed(*byte, now, timeout, &mut self.events)?;
                }
            }
        }
        Ok(())
    }
    pub(super) fn release(&mut self) {
        self.decoder.release(&mut self.events);
    }
    pub(super) fn external_buttons(&mut self, buttons: u8) -> Result<(), ErrorKind> {
        if self.backpressured() {
            return Err(ErrorKind::QueueFull);
        }
        self.decoder.external_buttons(buttons, &mut self.events);
        Ok(())
    }
    pub(super) fn activate(&mut self, protocol: MouseProtocol) {
        self.decoder.set_protocol(protocol);
        self.protocol = Some(protocol);
        self.waiting = false;
        self.active = true;
    }
}

impl<R: Registers, T: Timer> Controller<R, T> {
    pub fn synaptics_child_protocol(&self) -> Option<MouseProtocol> {
        self.is_ready().then_some(())?;
        let child = self.synaptics.as_ref()?.child.as_ref()?;
        child.active.then_some(child.protocol).flatten()
    }
    pub fn synaptics_child_command(&self) -> Option<&Command> {
        self.synaptics.as_ref()?.child.as_ref()?.command.as_ref()
    }
    pub fn synaptics_child_identities(&self) -> Option<&[Identity]> {
        Some(&self.synaptics.as_ref()?.child.as_ref()?.identities)
    }
    /// Last accepted source scroll programming, separately from Ready permission.
    pub fn synaptics_child_scroll_mode(&self) -> Option<ScrollMode> {
        let child = self.synaptics.as_ref()?.child.as_ref()?;
        child.protocol?;
        Some(if child.enhanced_scroll {
            ScrollMode::Explorer4
        } else {
            ScrollMode::Ordinary
        })
    }
    /// Horizontal detents are separate from the shared vertical-only
    /// compatibility Input ABI. A guest frontend must expose the matching axis.
    pub fn drain_synaptics_child_horizontal(&mut self) -> Vec<i8> {
        self.synaptics
            .as_mut()
            .and_then(|e| e.child.as_mut())
            .map_or_else(Vec::new, |c| core::mem::take(&mut c.horizontal))
    }
    /// Acknowledge the source Explorer4.0 magic 200/80/40 rate sequence and
    /// restore the child's configured 100pps rate. Requires a
    /// negotiated ID4 child. No hardware-generation identity is inferred.
    pub fn enable_synaptics_explorer_scroll(&mut self) -> Result<(), super::super::Error> {
        self.ready()?;
        if self.synaptics_child_protocol() != Some(MouseProtocol::Explorer) {
            return Err(ErrorKind::Synaptics(Error::ChildScrollUnsupported).into());
        }
        if self
            .synaptics
            .as_ref()
            .unwrap()
            .child
            .as_ref()
            .unwrap()
            .enhanced_scroll
        {
            return Ok(());
        }
        let result = (|| {
            self.device_command(Port::Mouse, DISABLE_REPORTING, &[])?;
            let timeout = self.config.command_timeout_us;
            self.synaptics_child_transaction(DISABLE_REPORTING, None, 0, timeout)?;
            self.synaptics
                .as_mut()
                .unwrap()
                .child
                .as_mut()
                .unwrap()
                .active = false;
            for rate in [200, 80, 40] {
                self.synaptics_child_transaction(SET_RATE, Some(rate), 0, timeout)?;
            }
            self.synaptics
                .as_mut()
                .unwrap()
                .child
                .as_mut()
                .unwrap()
                .enhanced_scroll = true;
            self.synaptics_child_transaction(SET_RATE, Some(100), 0, timeout)?;
            self.synaptics_child_transaction(ENABLE_REPORTING, None, 0, timeout)?;
            self.synaptics
                .as_mut()
                .unwrap()
                .child
                .as_mut()
                .unwrap()
                .activate(MouseProtocol::Explorer);
            self.device_command(Port::Mouse, ENABLE_REPORTING, &[])
        })();
        result.map_err(|kind| self.fail(kind))
    }
    /// Child input has a separate device destination from the parent.
    /// This also keeps already decoded input and explicit releases on error.
    pub fn drain_synaptics_child_inputs(&mut self) -> Vec<Input> {
        self.synaptics
            .as_mut()
            .and_then(|e| e.child.as_mut())
            .map_or_else(Vec::new, |c| core::mem::take(&mut c.events))
    }
    fn synaptics_child_response(
        &mut self,
        start: u64,
        timeout: u64,
    ) -> Result<Observation, ErrorKind> {
        loop {
            let observation = self
                .synaptics
                .as_mut()
                .unwrap()
                .child
                .as_mut()
                .unwrap()
                .replies
                .pop_front();
            if let Some(observation) = observation {
                // Responses may already have arrived while the parent's outer
                // command was acknowledging. Current time covers late reads;
                // subtracting this later wait start from an earlier receipt
                // would incorrectly reject already queued responses.
                if self.expired(start, timeout) {
                    return Err(ErrorKind::Timeout(Phase::Response));
                }
                return Ok(observation);
            }
            if self.expired(start, timeout) {
                return Err(ErrorKind::Timeout(Phase::Response));
            }
            let byte = if let Some(byte) = self.pending.pop_front() {
                Some(byte)
            } else {
                self.read_byte()?
            };
            if let Some(byte) = byte {
                self.decode(byte)?;
            } else {
                self.timer.relax();
            }
        }
    }
    fn synaptics_child_byte(
        &mut self,
        byte: u8,
        timeout: u64,
        id_without_ack: bool,
    ) -> Result<Option<Observation>, ErrorKind> {
        let start = self.timer.start();
        for _ in 0..MAX_ATTEMPTS {
            // Waiting is installed before the write: a wrapped
            // child ACK can arrive before the parent's outer ACK.
            self.synaptics_sliced(byte)?;
            self.device_command(Port::Mouse, SET_RATE, &[0x28])?;
            self.observed_response = None;
            let observation = self.synaptics_child_response(start, timeout)?;
            match observation.byte {
                ACK => {
                    self.synaptics
                        .as_mut()
                        .unwrap()
                        .child
                        .as_mut()
                        .unwrap()
                        .command
                        .as_mut()
                        .unwrap()
                        .acknowledged += 1;
                    return Ok(None);
                }
                RESEND => (),
                0 | 3 | 4 if id_without_ack => return Ok(Some(observation)),
                other => return Err(ErrorKind::Synaptics(Error::ChildReply(other))),
            }
        }
        Err(ErrorKind::ResendLimit {
            port: Port::Mouse,
            byte,
        })
    }
    pub(super) fn synaptics_child_transaction(
        &mut self,
        opcode: u8,
        argument: Option<u8>,
        count: usize,
        timeout: u64,
    ) -> Result<Vec<Observation>, ErrorKind> {
        let child = self.synaptics.as_mut().unwrap().child.as_mut().unwrap();
        if !child.replies.is_empty() {
            return Err(ErrorKind::Synaptics(Error::ChildUnsolicited));
        }
        child.waiting = true;
        child.command = Some(Command {
            opcode,
            argument,
            acknowledged: 0,
            observations: Vec::new(),
        });
        let first = self.synaptics_child_byte(opcode, timeout, opcode == GET_ID)?;
        if let Some(argument) = argument {
            self.synaptics_child_byte(argument, timeout, false)?;
        }
        let start = self.timer.start();
        let mut result = Vec::new();
        if let Some(id) = first {
            result.push(id);
        }
        for _ in result.len()..count {
            result.push(self.synaptics_child_response(start, timeout)?);
        }
        if opcode == GET_ID {
            let child = self.synaptics.as_mut().unwrap().child.as_mut().unwrap();
            let command = child.command.as_ref().unwrap();
            child.identities.push(Identity {
                acknowledged: command.acknowledged != 0,
                observation: result[0],
            });
        }
        self.synaptics
            .as_mut()
            .unwrap()
            .child
            .as_mut()
            .unwrap()
            .waiting = false;
        Ok(result)
    }
    pub(in crate::input::ps2) fn stop_synaptics_mouse_inner(&mut self) -> Result<bool, ErrorKind> {
        if !self
            .synaptics
            .as_ref()
            .and_then(|e| e.child.as_ref())
            .is_some_and(|c| c.active)
        {
            return Ok(false);
        }
        self.device_command(Port::Mouse, DISABLE_REPORTING, &[])?;
        self.synaptics_child_transaction(
            DISABLE_REPORTING,
            None,
            0,
            self.config.command_timeout_us,
        )?;
        self.synaptics
            .as_mut()
            .unwrap()
            .child
            .as_mut()
            .unwrap()
            .active = false;
        Ok(true)
    }
    /// Probe exactly one ordinary PS/2 mouse behind an observed passthrough
    /// port. Reset/BAT/ID, defaults, resolution, wheel/Explorer negotiation and
    /// activation require wrapped child replies. GET_ID alone permits
    /// the source's ID-without-ACK case, kept as acknowledged=false.
    /// Vendor protocols are not inferred. Parent ownership survives failure.
    pub fn initialize_synaptics_mouse(&mut self) -> Result<MouseProtocol, super::super::Error> {
        self.require_synaptics_passthrough()?;
        if self
            .synaptics
            .as_ref()
            .unwrap()
            .child
            .as_ref()
            .is_some_and(|c| c.active)
        {
            return Err(ErrorKind::AlreadyInitialized.into());
        }
        let result = (|| {
            self.device_command(Port::Mouse, DISABLE_REPORTING, &[])?;
            if self.synaptics.as_ref().unwrap().child.is_none() {
                self.synaptics.as_mut().unwrap().child = Some(Mouse::default());
            }
            self.synaptics
                .as_mut()
                .unwrap()
                .child
                .as_mut()
                .unwrap()
                .identities
                .clear();
            // Source PT connection settles for at least10ms before probing.
            let start = self.timer.start();
            while !self.expired(start, 10_000) {
                self.timer.relax();
            }
            let reset =
                self.synaptics_child_transaction(RESET, None, 2, self.config.reset_timeout_us)?;
            if reset[0].byte != BAT_OK || !matches!(reset[1].byte, 0 | 3 | 4) {
                return Err(ErrorKind::Synaptics(Error::ChildReset([
                    reset[0].byte,
                    reset[1].byte,
                ])));
            }
            self.synaptics
                .as_mut()
                .unwrap()
                .child
                .as_mut()
                .unwrap()
                .enhanced_scroll = false;
            let timeout = self.config.command_timeout_us;
            for command in [DEFAULTS, DISABLE_REPORTING] {
                self.synaptics_child_transaction(command, None, 0, timeout)?;
            }
            self.synaptics_child_transaction(SET_RESOLUTION, Some(2), 0, timeout)?;
            let mut id = 0;
            for rates in [[200, 100, 80], [200, 200, 80]] {
                for rate in rates {
                    self.synaptics_child_transaction(SET_RATE, Some(rate), 0, timeout)?;
                }
                id = self.synaptics_child_transaction(GET_ID, None, 1, timeout)?[0].byte;
                if !matches!(id, 0 | 3 | 4) {
                    return Err(ErrorKind::UnsupportedMouseId(id));
                }
            }
            let protocol = match id {
                0 => MouseProtocol::Standard,
                3 => MouseProtocol::IntelliMouse,
                4 => MouseProtocol::Explorer,
                _ => unreachable!(),
            };
            if self
                .synaptics
                .as_ref()
                .unwrap()
                .child
                .as_ref()
                .unwrap()
                .protocol
                .is_some_and(|old| old != protocol)
            {
                return Err(ErrorKind::Synaptics(Error::ChildIdentityChanged));
            }
            self.synaptics_child_transaction(SET_RATE, Some(100), 0, timeout)?;
            self.synaptics_child_transaction(SCALE_ONE_TO_ONE, None, 0, timeout)?;
            let mode = self.synaptics_capabilities().unwrap().mode.unwrap();
            let mode = if protocol == MouseProtocol::Standard {
                mode & !2
            } else {
                mode | 2
            };
            self.synaptics.as_mut().unwrap().format_transition = true;
            self.synaptics_sliced(mode)?;
            self.device_command(Port::Mouse, SET_RATE, &[0x14])?;
            let engine = self.synaptics.as_mut().unwrap();
            engine.capabilities.as_mut().unwrap().mode = Some(mode);
            engine.format_transition = false;
            self.synaptics_child_transaction(ENABLE_REPORTING, None, 0, timeout)?;
            self.synaptics
                .as_mut()
                .unwrap()
                .child
                .as_mut()
                .unwrap()
                .activate(protocol);
            self.device_command(Port::Mouse, ENABLE_REPORTING, &[])?;
            Ok(protocol)
        })();
        result.map_err(|kind| self.fail(kind))
    }
}
