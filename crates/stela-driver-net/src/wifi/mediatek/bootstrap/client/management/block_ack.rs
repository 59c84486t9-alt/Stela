// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! Explicit OS-selected protected BA MLME, using original authenticated RX.
//! Transport/key installation alone never selects negotiated management policy.
use super::*;
use wifi::regulatory::{AssociationAdmission, HardwarePolicy, OsPolicy, Owner};

// Bound authenticated deferred actions independently of firmware TX-ring capacity.
const MAX_PENDING_ACTIONS: usize = 32;

pub(in crate::wifi::mediatek::bootstrap::client) struct BaSubmission<C: 'static> {
    pub(in crate::wifi::mediatek::bootstrap::client) bytes: Vec<u8>,
    pub(in crate::wifi::mediatek::bootstrap::client) config: txwi::Config,
    pub(in crate::wifi::mediatek::bootstrap::client) owner: PacketOwner<C>,
    pub(in crate::wifi::mediatek::bootstrap::client) grant: Option<u64>,
}

impl<I: BarIo, Q: QueueIo, C: 'static> Client<I, Q, C> {
    /// Consume this original authenticated unicast BA action for the real OS's
    /// negotiated management service. Ordinary RX only reports the observation.
    /// Refusal keeps the original envelope in `received`; successful accepted
    /// consumption takes it. A full bounded action queue never discards RX.
    /// Native queue programming and responses still await separate guarded
    /// progress and firmware ACKs; no callback return invents completion.
    ///
    /// # Safety
    /// Inherit configure_modern's requester/permission/revocation contract.
    /// The real OS explicitly authorizes this original action and subsequent
    /// deferred BA responses, timers and teardown under its negotiated protected
    /// management policy. Session installation alone supplies no such policy.
    pub unsafe fn receive_management_block_ack<H: HardwarePolicy, O: OsPolicy>(
        &mut self,
        authority: &mut Owner<H, O>,
        admission: AssociationAdmission,
        received: &mut Option<Received>,
        now: u64,
    ) -> Result<(), Error> {
        let s = self.state_mut();
        let original = received.as_ref().ok_or(Error::WrongPhase)?;
        Self::validate_received_management(s, original)?;
        if original.group {
            return Err(Error::Unsupported);
        }
        let context = original.session.context.as_ref().ok_or(Error::WrongPhase)?;
        Self::validate_ba_management(s)?;
        if s.ba_management_pn
            .is_some_and(|old| original.pn.value() <= old.value())
        {
            return Err(Error::Key(mailbox::key::Error::Security(
                wifi::security::Error::Replay,
            )));
        }
        if s.ba_actions.len() >= MAX_PENDING_ACTIONS {
            return Err(Error::Busy);
        }
        s.ba_actions.try_reserve(1).map_err(|_| Error::NoMemory)?;
        // SAFETY: authenticated original envelope, exact Station, both
        // current providers and explicitly supplied negotiated OS policy.
        let action = unsafe {
            authority.consume_association(admission, &mut s.station, |station, _| {
                station.receive_authenticated_block_ack(
                    context,
                    &original.frame,
                    &original.body,
                    now,
                )
            })
        }
        .map_err(Error::Regulatory)?
        .map_err(Error::BlockAck)?;
        s.ba_management_pn = Some(original.pn);
        s.ba_management = Some(original.session.clone());
        Self::queue_block_ack(s, action, now)?;
        drop(received.take());
        Ok(())
    }

    /// Begin an explicitly OS-selected protected BA exchange. The legacy raw
    /// begin remains refused when a management transport is attached.
    ///
    /// # Safety
    /// Same kept requester/current policy and negotiated OS authorization
    /// as receive_management_block_ack, including deferred automatic responses
    /// and local DELBA. No PMF, SAE or 6GHz negotiation is inferred here.
    pub unsafe fn begin_management_block_ack<H: HardwarePolicy, O: OsPolicy>(
        &mut self,
        authority: &mut Owner<H, O>,
        admission: AssociationAdmission,
        session: &Arc<Session>,
        tid: u8,
        timeout_tu: u16,
        now: u64,
    ) -> Result<(), Error> {
        let s = self.state_mut();
        Self::validate_management(s, session)?;
        if s.modern.is_none() {
            return Err(Error::WrongPhase);
        }
        if s.transmit_ba
            .get(usize::from(tid))
            .is_some_and(Option::is_some)
        {
            return Err(Error::Busy);
        }
        Self::validate_ba_management(s)?;
        if s.ba_actions.len() >= MAX_PENDING_ACTIONS {
            return Err(Error::Busy);
        }
        s.ba_actions.try_reserve(1).map_err(|_| Error::NoMemory)?;
        // SAFETY: same original Station and both current policy guards.
        let action = unsafe {
            authority.consume_association(admission, &mut s.station, |station, _| {
                station.begin_authenticated_tx_block_ack(tid, timeout_tu, now)
            })
        }
        .map_err(Error::Regulatory)?
        .map_err(Error::BlockAck)?;
        s.ba_management = Some(session.clone());
        Self::queue_tx_ba(s, action, now)
    }

    // A binding exists for the complete canonical/native BA lifetime. Rotation
    // can replace it only after management_drained proves every BA user idle.
    pub(in crate::wifi::mediatek::bootstrap::client) fn validate_ba_management(
        s: &Owned<I, Q, C>,
    ) -> Result<(), Error> {
        if let Some(session) = &s.ba_management {
            Self::validate_management(s, session)?;
        } else if !s.station.block_ack_idle() && s.management.is_some() {
            return Err(Error::WrongPhase);
        }
        Ok(())
    }

    pub(in crate::wifi::mediatek::bootstrap::client) fn prepare_ba_submission(
        s: &Owned<I, Q, C>,
        original: &[u8],
    ) -> Result<BaSubmission<C>, Error> {
        Self::validate_ba_management(s)?;
        if s.station.requires_protected_management() && s.ba_management.is_none() {
            return Err(Error::WrongPhase);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(original.len())
            .map_err(|_| Error::NoMemory)?;
        bytes.extend_from_slice(original);
        let session = match (&s.management, &s.ba_management) {
            (Some(_), Some(session)) => Some(session),
            (None, None) => None,
            _ => return Err(Error::WrongPhase),
        };
        if session.is_some() {
            let fc = u16::from_le_bytes(bytes[..2].try_into().unwrap());
            bytes[..2].copy_from_slice(&(fc | wifi::frame::PROTECTED).to_le_bytes());
        }
        let mut prepared =
            Self::prepare_submission(s, &bytes, session.map(|session| session.ptk), true, true)?;
        prepared.1.management = session.cloned();
        Ok(BaSubmission {
            bytes,
            config: prepared.0,
            owner: prepared.1,
            grant: prepared.2,
        })
    }
}
