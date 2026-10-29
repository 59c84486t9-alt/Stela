// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Native owned encapsulation EEPROM exchange through the mailbox.
use super::{
    Cause, Event, Mailbox, Operation, PCI_TIMEOUT_US, Packet, PortState, QueueIo, TransportFailure,
};
use crate::net::wifi::mediatek::{identity::Identity, mcu::eeprom as codec, ring::rx::Frame};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reply {
    pub sequence: u8,
    pub dma_released: bool,
    pub frame: Frame,
}
/// Completed read, with immutable full raw observations. The private
/// owner binds historical native command context, not current power/reset/
/// firmware policy or authentication of source-opaque validity fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Report {
    identity: Identity,
    owner: u64,
    reply: Reply,
    observed: codec::Observation,
}
impl Report {
    pub fn identity(&self) -> Identity {
        self.identity
    }
    pub fn reply(&self) -> &Reply {
        &self.reply
    }
    pub fn observed(&self) -> &codec::Observation {
        &self.observed
    }
    pub fn belongs_to<W: QueueIo, F: QueueIo, R: QueueIo>(
        &self,
        mailbox: &Mailbox<W, F, R>,
    ) -> bool {
        self.owner == mailbox.owner
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Failure {
    Transport(TransportFailure),
    /// Response and TX DMA completed, but the reply did not contain
    /// this complete echoed EEPROM block. Keep its real owned raw frame.
    Malformed {
        error: codec::Error,
        reply: Reply,
    },
}
impl Failure {
    pub fn port(&self) -> PortState {
        match self {
            Self::Transport(e) => e.port,
            Self::Malformed { .. } => PortState::Usable,
        }
    }
}
impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek native EEPROM query: {self:?}")
    }
}
impl core::error::Error for Failure {}
impl<W: QueueIo, F: QueueIo, R: QueueIo> Mailbox<W, F, R> {
    pub fn interrupted_encapsulation_reply(&self) -> Option<&Reply> {
        self.interrupted_encapsulation_reply.as_ref()
    }
    /// Execute the source-defined encapsulation read; no missing/invalid read
    /// can supply a default board byte or satisfy an applied regulatory policy.
    pub fn query_encapsulation(&mut self) -> Result<Report, Failure> {
        self.query_encapsulation_timed(PCI_TIMEOUT_US)
    }
    pub(super) fn query_encapsulation_timed(&mut self, timeout_us: u64) -> Result<Report, Failure> {
        if self.poisoned {
            return Err(Failure::Transport(self.failure(
                Operation::Encapsulation,
                0,
                false,
                Cause::Poisoned,
            )));
        }
        let packet = self.encoder.encode_encapsulation_query(self.identity.chip);
        self.execute(&Packet::Encapsulation(packet), timeout_us)
            .map_err(Failure::Transport)?;
        let reply = self
            .interrupted_encapsulation_reply
            .take()
            .expect("actual completed EEPROM reply");
        let event =
            Event::parse(self.identity.chip, &reply.frame.bytes).expect("matched EEPROM event");
        let observed = match codec::Observation::parse(self.identity.chip, event.payload) {
            Ok(observed) => observed,
            Err(error) => return Err(Failure::Malformed { error, reply }),
        };
        Ok(Report {
            identity: self.identity,
            owner: self.owner,
            reply,
            observed,
        })
    }
}
