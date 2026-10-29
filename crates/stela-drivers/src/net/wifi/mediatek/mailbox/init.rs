// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Initial commands share the real serialized mailbox; only the owning
//! lifecycle may publish them. Raw generic replies are not invented ACKs.
use super::{Cause, Mailbox, Operation, PCI_TIMEOUT_US, Packet, QueueIo, TransportFailure};
use crate::net::wifi::mediatek::{mcu::init as codec, ring::rx::Frame};
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reply {
    pub kind: codec::Kind,
    pub sequence: u8,
    pub dma_released: bool,
    pub frame: Frame,
}
#[derive(Debug)]
pub enum Fact {
    OneWayDmaCompleted { kind: codec::Kind, sequence: u8 },
    GenericResponse(Reply),
    StationResult { reply: Reply, status: u32 },
}
impl Fact {
    pub fn kind(&self) -> codec::Kind {
        match self {
            Self::OneWayDmaCompleted { kind, .. } => *kind,
            Self::GenericResponse(r) | Self::StationResult { reply: r, .. } => r.kind,
        }
    }
}
impl<W: QueueIo, F: QueueIo, R: QueueIo> Mailbox<W, F, R> {
    /// Vendor-local: the caller is the lifecycle with the
    /// controller/firmware/policy/WCID resources, not an arbitrary integer.
    pub(in crate::net::wifi::mediatek) fn initial(
        &mut self,
        request: &codec::Request,
    ) -> Result<Fact, TransportFailure> {
        let kind = request.kind();
        if self.poisoned || request.chip() != self.identity.chip {
            return Err(self.failure(Operation::Initial(kind), 0, false, Cause::Poisoned));
        }
        if kind == codec::Kind::Restart {
            self.download_binding = None;
            if self.cookie != 0 {
                return Err(self.failure(
                    Operation::Initial(kind),
                    0,
                    false,
                    Cause::PendingTransmit,
                ));
            }
        }
        let packet = self.encoder.encode_bootstrap(request);
        let sequence = packet.sequence();
        self.execute(&Packet::Initial(packet), PCI_TIMEOUT_US)?;
        if kind == codec::Kind::Restart {
            self.source_restart_cookie = Some(self.cookie);
        }
        if !request.expects_response() {
            return Ok(Fact::OneWayDmaCompleted { kind, sequence });
        }
        let reply = self
            .interrupted_initial_reply
            .take()
            .expect("actual initial RX and TX completed");
        if matches!(kind, codec::Kind::RawTranslation { .. })
            && self.identity.chip != crate::net::wifi::mediatek::identity::Chip::Mt7925
        {
            let event = super::Event::parse(self.identity.chip, &reply.frame.bytes)
                .expect("matched initial response");
            // The source station status was matched by execute. Decode
            // against this same immutable request/sequence without advancing it.
            let payload = event.payload;
            let status =
                u32::from_le_bytes(payload[4..8].try_into().expect("source station result"));
            Ok(Fact::StationResult { reply, status })
        } else {
            Ok(Fact::GenericResponse(reply))
        }
    }
    pub fn interrupted_initial_reply(&self) -> Option<&Reply> {
        self.interrupted_initial_reply.as_ref()
    }
}
