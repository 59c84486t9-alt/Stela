// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
//! Actual source-queue split-parent ownership before canonical replay. This
//! deliberately refuses partial flushes rather than promoting loss to a full
//! authenticated parent. Raw AMPDU does not create a negotiated BA session.
use super::*;
use wifi::security::aggregate::{OrderedGroup, Shape};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Queue {
    Event,
    Data,
}
impl Queue {
    const fn index(self) -> usize {
        match self {
            Self::Event => 0,
            Self::Data => 1,
        }
    }
}
pub(super) struct ReceivedFrame {
    pub(super) queue: Queue,
    pub(super) frame: crate::net::wifi::mediatek::ring::rx::Frame,
}
// This is created only from this Client's actual completed native queue and
// retained installed peer. It is never minted by a public copied-RX API.
struct SourceOwner<C: 'static> {
    _resource: Arc<C>,
    context: Arc<station::AssociationContext>,
    association: u64,
    peer_generation: u64,
    queue: Queue,
    key: Option<KeyIdentity>,
}
pub(super) struct Parent<C: 'static> {
    owner: SourceOwner<C>,
    members: Vec<Mpdu>,
    bytes: usize,
    shape: Shape,
}
impl<C> Parent<C> {
    pub(super) fn head(&self) -> &Mpdu {
        &self.members[0]
    }
    pub(super) fn context(&self) -> &Arc<station::AssociationContext> {
        &self.owner.context
    }
    fn matches(&self, next: &Self) -> bool {
        let a = &self.members[0];
        let b = &next.members[0];
        let x = a.header();
        let y = b.header();
        Arc::ptr_eq(&self.owner.context, &next.owner.context)
            && self.owner.association == next.owner.association
            && self.owner.peer_generation == next.owner.peer_generation
            && self.owner.queue == next.owner.queue
            && self.owner.key == next.owner.key
            && x.control == y.control
            && x.receiver == y.receiver
            && x.transmitter == y.transmitter
            && x.sequence == y.sequence
            && x.tid == y.tid
            && x.amsdu == y.amsdu
            && a.radio.band == b.radio.band
            && a.radio.channel == b.radio.channel
            && a.radio.frequency_mhz == b.radio.frequency_mhz
            && b.security.pn.is_none_or(|pn| a.security.pn == Some(pn))
    }
    // Actual completion and optional BA release are established by this
    // private native caller, not by a public first/last or numeric epoch input.
    unsafe fn ordered(self) -> OrderedGroup<SourceOwner<C>> {
        // SAFETY: covered by this function's own safety contract.
        unsafe {
            OrderedGroup::new(
                self.owner.context.clone(),
                self.members,
                self.shape,
                self.owner,
            )
        }
    }
}
pub(super) struct Groups<C: 'static> {
    pending: [Option<Parent<C>>; 2],
}
impl<C> Groups<C> {
    pub(super) fn new() -> Self {
        Self {
            pending: [None, None],
        }
    }
    pub(super) fn is_idle(&self) -> bool {
        self.pending.iter().all(Option::is_none)
    }
    pub(super) fn clear(&mut self) {
        self.pending = [None, None];
    }
    pub(super) fn discard(&mut self, queue: Queue) {
        self.pending[queue.index()] = None;
    }
    pub(super) fn discard_tid(&mut self, tid: u8) {
        for parent in &mut self.pending {
            if parent
                .as_ref()
                .is_some_and(|p| p.head().header().tid == Some(tid))
            {
                *parent = None;
            }
        }
    }
    fn push(&mut self, mut next: Parent<C>) -> Result<Option<Parent<C>>, Error> {
        let index = next.owner.queue.index();
        let Some(observed) = next.members[0].aggregation.amsdu else {
            if self.pending[index].take().is_some() {
                return Err(Error::IncompleteParent);
            }
            return Ok(Some(next));
        };
        if !next.members[0].header().amsdu {
            self.pending[index] = None;
            return Err(Error::IncompleteParent);
        }
        if observed.first {
            let lost = self.pending[index].take().is_some();
            if observed.last {
                return Err(Error::IncompleteParent);
            }
            next.shape = Shape::HardwareSplitAmsdu;
            self.pending[index] = Some(next);
            return if lost {
                Err(Error::IncompleteParent)
            } else {
                Ok(None)
            };
        }
        let Some(parent) = self.pending[index].as_mut() else {
            // Source format LAST can describe one genuinely whole one-subframe
            // A-MSDU. Canonical framing still checks actual QoS/payload/key/PN.
            return if observed.last {
                Ok(Some(next))
            } else {
                Err(Error::IncompleteParent)
            };
        };
        if !parent.matches(&next)
            || parent.members.len() >= wifi::frame::MAX_MPDU / 14
            || parent
                .bytes
                .checked_add(next.bytes)
                .is_none_or(|n| n > wifi::frame::MAX_MPDU)
        {
            self.pending[index] = None;
            return Err(Error::IncompleteParent);
        }
        parent.members.try_reserve(1).map_err(|_| Error::NoMemory)?;
        next.members[0].aggregation.amsdu.as_mut().unwrap().index = parent.members.len() as u16;
        parent.bytes += next.bytes;
        parent.members.push(next.members.pop().unwrap());
        if observed.last {
            Ok(self.pending[index].take())
        } else {
            Ok(None)
        }
    }
}

impl<I: BarIo, Q: QueueIo, C: 'static> Client<I, Q, C> {
    pub(super) fn receive_parent(
        s: &mut Owned<I, Q, C>,
        queue: Queue,
        frame: Mpdu,
        now: u64,
    ) -> Result<Vec<Ingress>, Error> {
        let context = s
            .modern
            .as_ref()
            .ok_or(Error::WrongPhase)?
            .context()
            .clone();
        s.station
            .validate_association_context(&context)
            .map_err(Error::Station)?;
        // Split records repeat their MAC header. Bound the actual parent
        // payload, never count repeated headers against its source byte cap.
        let bytes = frame.bytes().len() - frame.header().length;
        let key = frame.security.key;
        let owner = SourceOwner {
            _resource: s.controller.state().resource.clone(),
            context,
            association: s.station.association_epoch().ok_or(Error::WrongPhase)?,
            peer_generation: s.peer_generation,
            queue,
            key,
        };
        let mut members = Vec::new();
        members.try_reserve_exact(1).map_err(|_| Error::NoMemory)?;
        members.push(frame);
        let Some(parent) = s.receive_groups.push(Parent {
            owner,
            members,
            bytes,
            shape: Shape::WholeMpdu,
        })?
        else {
            return Ok(Vec::new());
        };
        Self::order_parent(s, parent, now)
    }
    pub(super) fn deliver_parent(
        s: &mut Owned<I, Q, C>,
        parent: Parent<C>,
    ) -> Result<Vec<Ingress>, Error> {
        Self::validate_pmf_data(s)?;
        s.station
            .validate_association_context(parent.context())
            .map_err(Error::Station)?;
        let key = parent.head().security.key;
        // SAFETY: This private entry is reached only by the native source bypass or
        // the exact currently installed BA queue's actual ordered release.
        let group = unsafe { parent.ordered() };
        let slot = if key.is_some() {
            let owner = if group.members()[0].header().receiver.is_multicast() {
                s.gtk.as_mut()
            } else {
                s.ptk.as_mut()
            }
            .ok_or(Error::NoKey)?;
            Some(owner.slot_mut())
        } else {
            None
        };
        let received = s
            .station
            .receive_ordered_group(&group, slot)
            .map_err(Error::Aggregate)?;
        let ptk = s.ptk.as_ref().ok_or(Error::NoKey)?.slot();
        let gtk = s.gtk.as_ref().ok_or(Error::NoKey)?.slot();
        s.station
            .receive_group_refs(&received, &[ptk, gtk])
            .map_err(Error::Data)
    }
}
