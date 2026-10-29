// SPDX-License-Identifier: GPL-2.0-only
//! Standard analog jack unsolicited enable, RIRB delivery and teardown.
//! Adapted from Linux sound/hda/{core/{bus,controller},common/jack}.c.
//! Copyright (c) 2011-2012 Takashi Iwai <tiwai@suse.de>.
//! Raw notifications invalidate measurements; use pin sense for state.
use super::{CodecGraph, Controller, ControllerToken, Registers, Verb, WidgetKind};
use crate::{audio::Error, bus::i2c::Timer};
use alloc::{collections::VecDeque, vec::Vec};

const QUEUE: usize = 64;
const SET_UNSOL: u16 = 0x708;
const GET_UNSOL: u16 = 0xf08;
const ENABLE: u8 = 0x80;

/// A tag reservation bound to one controller/reset epoch. Tags are never
/// recycled in that epoch, even after disable; a late event cannot name a new pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JackNotificationId {
    token: ControllerToken,
    index: usize,
}
/// Original hardware response. An optional subscription is historical mapping,
/// not a current pin state or permission to change a route/amp/codec power.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsolicitedResponse {
    pub codec: u8,
    pub tag: u8,
    pub response: u32,
    pub extra: u32,
    pub subscription: Option<JackNotificationId>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnsolicitedEvent {
    Response(UnsolicitedResponse),
    /// Software queue loss, after all earlier kept responses. While loss
    /// is pending, later events join this count so no event overtakes the gap.
    Overflow {
        at_least: u64,
    },
}
struct Subscription {
    codec: u8,
    pin: u8,
    tag: u8,
    previous: u8,
    active: bool,
}
pub(super) struct State {
    subscriptions: Vec<Subscription>,
    next: [u8; 15],
    capturing: bool,
    events: VecDeque<UnsolicitedResponse>,
    lost: u64,
}
impl State {
    /// Whether the controller gate passes unsolicited responses.
    pub(super) fn capturing(&self) -> bool {
        self.capturing
    }
    pub(super) fn new() -> Self {
        Self {
            subscriptions: Vec::new(),
            next: [1; 15],
            capturing: false,
            events: VecDeque::new(),
            lost: 0,
        }
    }
    pub(super) fn receive(&mut self, token: ControllerToken, response: u32, extra: u32) {
        if !self.capturing {
            return;
        }
        if self.events.len() == QUEUE || self.lost != 0 {
            self.lost = self.lost.saturating_add(1);
            return;
        }
        let codec = (extra & 15) as u8;
        let tag = (response >> 26) as u8;
        let subscription = self
            .subscriptions
            .iter()
            .position(|s| s.codec == codec && s.tag == tag)
            .map(|index| JackNotificationId { token, index });
        self.events.push_back(UnsolicitedResponse {
            codec,
            tag,
            response,
            extra,
            subscription,
        });
    }
}

impl<R: Registers, T: Timer> Controller<R, T> {
    fn jack_ready(&self) -> Result<(), Error> {
        if self.lifecycle_failed || self.command_poisoned {
            return Err(Error::NeedsReset);
        }
        if self.stopped {
            return Err(Error::Shutdown);
        }
        Ok(())
    }
    fn jack_index(&self, id: JackNotificationId) -> Result<usize, Error> {
        if id.token != self.token || id.index >= self.unsolicited.subscriptions.len() {
            return Err(Error::InvalidJackNotification);
        }
        Ok(id.index)
    }
    pub(super) fn jack_gate(&mut self, enable: bool) -> Result<(), Error> {
        use super::registers::{GCTL, GCTL_RESET, GCTL_UNSOL};
        let value = self.registers.read32(GCTL);
        if value == u32::MAX || value & GCTL_RESET == 0 {
            return Err(Error::RegisterUnavailable { offset: GCTL });
        }
        let wanted = if enable {
            value | GCTL_UNSOL
        } else {
            value & !GCTL_UNSOL
        };
        self.registers.write32(GCTL, wanted);
        let actual = self.registers.read32(GCTL);
        if actual == u32::MAX
            || actual & (GCTL_RESET | GCTL_UNSOL) != wanted & (GCTL_RESET | GCTL_UNSOL)
        {
            return Err(Error::RouteRejected);
        }
        Ok(())
    }
    fn jack_control(&mut self, codec: u8, pin: u8, value: u8) -> Result<(), Error> {
        self.verb(Verb::short(codec, pin, SET_UNSOL, value)?)?;
        let actual = self.verb(Verb::short(codec, pin, GET_UNSOL, 0)?)?;
        if actual == u32::MAX || actual & 255 != u32::from(value) {
            return Err(Error::RouteRejected);
        }
        Ok(())
    }
    /// Enable standard analog pin notifications on an already powered, owned
    /// codec. No OEM sense inversion, debounce or automatic speaker policy is
    /// inferred. Physical live widget capabilities/defaults are re-enumerated;
    /// caller-edited graph fields cannot authorize a write. Digital/MST is separate.
    pub fn enable_jack_notifications(
        &mut self,
        graph: &CodecGraph,
        pin: u8,
    ) -> Result<JackNotificationId, Error> {
        if graph.token != self.token {
            return Err(Error::InvalidCodecGraph);
        }
        self.jack_ready()?;
        if self
            .unsolicited
            .subscriptions
            .iter()
            .any(|s| s.codec == graph.address && s.pin == pin && s.active)
        {
            return Err(Error::RouteInUse);
        }
        let actual = self.enumerate_codec(graph.address)?;
        if actual.vendor_id != graph.vendor_id || actual.revision_id != graph.revision_id {
            return Err(Error::InvalidCodecGraph);
        }
        let widget = actual.widget(pin).ok_or(Error::InvalidCodecGraph)?;
        let config = widget
            .pin_configuration()
            .ok_or(Error::UnsupportedTopology)?;
        if widget.kind != WidgetKind::Pin
            || widget.capabilities & (1 << 9) != 0
            || widget.capabilities & (1 << 7) == 0
            || widget
                .pin_capabilities
                .is_none_or(|caps| caps == u32::MAX || caps & (1 << 2) == 0)
            || config.raw == u32::MAX
            || config.no_presence_detection()
            || !matches!(
                config.connection(),
                super::PinConnection::Jack | super::PinConnection::JackAndFixed
            )
        {
            return Err(Error::UnsupportedTopology);
        }
        let tag = self.unsolicited.next[usize::from(graph.address)];
        if tag > 63 {
            return Err(Error::JackNotificationTagsExhausted);
        }
        let previous = self.verb(Verb::short(graph.address, pin, GET_UNSOL, 0)?)?;
        if previous == u32::MAX || previous & 0xc0 != 0 {
            return Err(Error::RouteInUse);
        }
        let id = JackNotificationId {
            token: self.token,
            index: self.unsolicited.subscriptions.len(),
        };
        // Reserve before any publication, including an uncertain SET/readback.
        self.unsolicited.next[usize::from(graph.address)] += 1;
        self.unsolicited.subscriptions.push(Subscription {
            codec: graph.address,
            pin,
            tag,
            previous: previous as u8,
            active: true,
        });
        self.unsolicited.capturing = true;
        let result = self
            .jack_gate(true)
            .and_then(|()| self.jack_control(graph.address, pin, ENABLE | tag));
        if let Err(error) = result {
            self.lifecycle_failed = true;
            return Err(error);
        }
        Ok(id)
    }
    /// Acknowledged codec disable precedes tag retirement and last global gate
    /// disable. The original tag reservation survives until a real full reset.
    pub fn disable_jack_notifications(&mut self, id: JackNotificationId) -> Result<(), Error> {
        let index = self.jack_index(id)?; // stale handles never reach MMIO
        self.jack_ready()?;
        let subscription = &self.unsolicited.subscriptions[index];
        if !subscription.active {
            return Ok(());
        }
        let (codec, pin, previous) = (subscription.codec, subscription.pin, subscription.previous);
        if let Err(error) = self.jack_control(codec, pin, previous) {
            self.lifecycle_failed = true;
            return Err(error);
        }
        self.unsolicited.subscriptions[index].active = false;
        if !self.unsolicited.subscriptions.iter().any(|s| s.active)
            && let Err(error) = self.jack_gate(false)
        {
            self.lifecycle_failed = true;
            return Err(error);
        }
        Ok(())
    }
    /// Explicit polled delivery. Responses arriving between solicited verbs are
    /// by that same real RIRB drain. Even cached events require a live
    /// command/ownership epoch. Raw event bits never replace fresh pin sense.
    pub fn next_unsolicited(&mut self) -> Result<Option<UnsolicitedEvent>, Error> {
        self.jack_ready()?;
        if let Err(error) = self.update_rirb() {
            self.command_poisoned = true;
            let _ = self.stop_commands();
            return Err(error);
        }
        if let Some(event) = self.unsolicited.events.pop_front() {
            return Ok(Some(UnsolicitedEvent::Response(event)));
        }
        if self.unsolicited.lost != 0 {
            let at_least = core::mem::take(&mut self.unsolicited.lost);
            return Ok(Some(UnsolicitedEvent::Overflow { at_least }));
        }
        Ok(None)
    }
    pub(super) fn shutdown_jack_notifications(&mut self) -> Result<(), Error> {
        let mut error = None;
        for index in 0..self.unsolicited.subscriptions.len() {
            let subscription = &self.unsolicited.subscriptions[index];
            if subscription.active {
                let (codec, pin, previous) =
                    (subscription.codec, subscription.pin, subscription.previous);
                match self.jack_control(codec, pin, previous) {
                    Ok(()) => self.unsolicited.subscriptions[index].active = false,
                    Err(fault) => {
                        error.get_or_insert(fault);
                    }
                }
            }
        }
        if self.unsolicited.capturing
            && let Err(fault) = self.jack_gate(false)
        {
            error.get_or_insert(fault);
        }
        error.map_or(Ok(()), Err)
    }
}
