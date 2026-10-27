// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
// Copyright (C) 2020-2023 MediaTek Inc.
// Count comparison and queue updates follow pinned Linux mac80211/mlme.c.
//! Associated WMM observations from this owner's completed native RX, followed
//! by an independently guarded real EDCA command. Negotiated identity is immutable.
use super::*;
use station::phy::{AccessCategory, Role, Wmm};

const OBSERVATION_LIFETIME_US: u64 = 30_000_000;

/// Last complete actual EDCA ACK plus descriptor/mapping retirement. This is
/// local queue configuration, not new association or authentication evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppliedEdca {
    pub parameter_set_count: u8,
    pub access_categories: [AccessCategory; 4],
}

pub(super) struct Observed<C: 'static> {
    resource: Arc<C>,
    context: Arc<station::AssociationContext>,
    profile: Profile,
    association: u64,
    peer_generation: u64,
    ptk: Option<KeyIdentity>,
    gtk: Option<KeyIdentity>,
    seen: u64,
    count: u8,
    parameters: [AccessCategory; 4],
    // Retain the actual normalized completed DMA observation, never caller bytes.
    _frame: Mpdu,
}

impl<I: BarIo, Q: QueueIo, C: 'static> Client<I, Q, C> {
    pub fn applied_edca(&self) -> Option<&AppliedEdca> {
        self.state().modern.as_ref()?.applied_edca.as_ref()
    }
    pub fn pending_edca(&self) -> bool {
        self.state().edca.is_some()
    }

    pub(super) fn observe_edca(s: &mut Owned<I, Q, C>, frame: Mpdu) -> Result<(), Error> {
        let p = s.profile.ok_or(Error::WrongProfile)?;
        let modern = s.modern.as_ref().ok_or(Error::WrongPhase)?;
        s.station
            .validate_association_context(modern.context())
            .map_err(Error::Station)?;
        let h = frame.header();
        let subtype = h.control & 0x00fc;
        if h.transmitter != Some(p.peer)
            || frame.bytes().get(16..22) != Some(p.peer.0.as_slice())
            || (
                frame.radio.band,
                frame.radio.channel,
                frame.radio.frequency_mhz,
            ) != (p.channel.band, p.channel.number, p.channel.frequency_mhz)
            || modern.context().bssid() != p.peer
            || modern.context().channel() != p.channel
        {
            return Err(Error::WrongProfile);
        }
        // Contradictory current-peer evidence cannot leave an older pending
        // relaxation eligible. This drops only an unsubmitted CPU observation.
        s.edca = None;
        if s.phase != Phase::Associated
            || frame.fcs_error
            || frame.monitor_only
            || h.protected()
            || h.fragmented()
            || h.control & 0x0300 != 0
            || h.length != 24
            || frame.aggregation != wifi::Aggregation::default()
            || !matches!(subtype, 0x0080 | 0x0050)
            || (subtype == 0x0080 && h.receiver != crate::net::Mac::BROADCAST)
            || (subtype == 0x0050 && h.receiver != p.interface.address)
        {
            return Err(Error::WrongProfile);
        }
        let mut elements = frame.bytes().get(36..).ok_or(Error::WrongProfile)?;
        if elements.len() > 2300 {
            return Err(Error::WrongProfile);
        }
        let mut observed = None;
        while !elements.is_empty() {
            let n = usize::from(*elements.get(1).ok_or(Error::WrongProfile)?);
            let data = elements.get(2..2 + n).ok_or(Error::WrongProfile)?;
            // MU-EDCA requires its own current count and firmware semantics.
            if elements[0] == 255 && data.first() == Some(&38) {
                return Err(Error::Unsupported);
            }
            if elements[0] == 221 && data.get(..4) == Some(&[0, 0x50, 0xf2, 2]) {
                if observed.is_some() {
                    return Err(Error::WrongProfile);
                }
                observed =
                    Some(Wmm::parse(data, Role::AccessPoint).map_err(|_| Error::WrongProfile)?);
            }
            elements = &elements[2 + n..];
        }
        let Some(observed) = observed else {
            return Ok(());
        };
        let parameters = observed.parameters.ok_or(Error::Unsupported)?;
        let negotiated = modern.context().negotiated();
        negotiated.wmm.as_ref().ok_or(Error::Unsupported)?;
        let original_ap = negotiated.peer().wmm().ok_or(Error::Unsupported)?;
        // U-APSD continues to use the immutable association. Admission
        // control is host-side: data TIDs follow the applied flags, as
        // `ieee80211_sta_wmm_params` updates `wmm_acm`.
        if observed.qos_info & 0x80 != original_ap.qos_info & 0x80
            || parameters.iter().any(|ac| ac.ecw_min == 0)
        {
            return Err(Error::Unsupported);
        }
        let count = observed.qos_info & 15;
        let applied = modern.applied_edca.as_ref().ok_or(Error::WrongPhase)?;
        // Pinned source uses equality, not ordering:15 ->0 is a real update.
        if count == applied.parameter_set_count {
            return Ok(());
        }
        s.edca = Some(Observed {
            resource: s.controller.state().resource.clone(),
            context: modern.context().clone(),
            profile: p,
            association: s.station.association_epoch().ok_or(Error::WrongPhase)?,
            peer_generation: s.peer_generation,
            ptk: s.ptk.as_ref().and_then(|key| key.slot().installed()),
            gtk: s.gtk.as_ref().and_then(|key| key.slot().installed()),
            seen: s.controller.state().control.clock.now_us(),
            count,
            parameters,
            _frame: frame,
        });
        Ok(())
    }

    fn validate_edca(s: &Owned<I, Q, C>, observed: &Observed<C>) -> Result<(), Error> {
        if s.phase != Phase::Associated {
            return Err(Error::WrongPhase);
        }
        if s.modern
            .as_ref()
            .is_none_or(|m| !Arc::ptr_eq(m.context(), &observed.context))
            || !Arc::ptr_eq(&observed.resource, &s.controller.state().resource)
            || s.profile != Some(observed.profile)
            || s.station.association_epoch() != Some(observed.association)
            || s.peer_generation != observed.peer_generation
            || s.ptk.as_ref().and_then(|key| key.slot().installed()) != observed.ptk
            || s.gtk.as_ref().and_then(|key| key.slot().installed()) != observed.gtk
        {
            return Err(Error::Station(station::Error::Stale));
        }
        s.station
            .validate_association_context(&observed.context)
            .map_err(Error::Station)?;
        if s.controller
            .state()
            .control
            .clock
            .now_us()
            .checked_sub(observed.seen)
            .is_none_or(|age| age > OBSERVATION_LIFETIME_US)
        {
            return Err(Error::GrantTimeout);
        }
        Ok(())
    }

    /// Install the latest genuine completed current-peer WMM observation.
    /// `limit` is the current immutable control-channel regulatory WMM rule;
    /// clamping and request encoding happen inside actual publication guards.
    ///
    /// # Safety
    /// The exact-controller, applied-policy, revocation and retained autonomous
    /// user contracts of `configure_modern` apply. `limit` must belong to that
    /// same current OS country/control-channel rule, not an invented relaxation.
    /// Active/pending BA sessions, partial aggregation, pending native RX and
    /// outstanding TX/DMA owners must drain first; this conservative cut does
    /// not reconfigure an operational BA session. External publication/reset/IRQ
    /// paths serialize through this owner and authority; no raw user may publish new work during the checked drain and
    /// actual command. This function preserves keys/context and grants no new
    /// PHY, ACM, U-APSD, PMF or 6 GHz admission.
    pub unsafe fn update_edca_modern<
        H: wifi::regulatory::HardwarePolicy,
        O: wifi::regulatory::OsPolicy,
    >(
        &mut self,
        authority: &mut wifi::regulatory::Owner<H, O>,
        admission: wifi::regulatory::AssociationAdmission,
        limit: Option<&wifi::regulatory::database::Wmm>,
    ) -> Result<(), Error> {
        let s = self.state_mut();
        let observed = s.edca.as_ref().ok_or(Error::WrongPhase)?;
        Self::validate_edca(s, observed)?;
        Self::management_drained(s)?;
        s.replies.try_reserve(1).map_err(|_| Error::NoMemory)?;
        let clock = s.controller.state().control.clock;
        let observed = s.edca.as_ref().unwrap();
        let phase = &mut s.phase;
        let controller = &mut s.controller;
        let replies = &mut s.replies;
        // SAFETY: covered by this function's exact-controller/policy contract.
        let result = unsafe {
            authority.publish_edca(
                admission,
                &s.station,
                observed.count,
                &observed.parameters,
                limit,
                |operation| {
                    if clock
                        .now_us()
                        .checked_sub(observed.seen)
                        .is_none_or(|age| age > OBSERVATION_LIFETIME_US)
                    {
                        return Err(Error::GrantTimeout);
                    }
                    let effective = *operation.effective();
                    let body = wire::modern::Configuration::observed_edca_request(
                        observed.profile,
                        operation.observed(),
                        &effective,
                    )
                    .map_err(Error::Codec)?;
                    *phase = Phase::Quarantined;
                    Self::command_parts(controller, replies, Command::Edca, &body)?;
                    if clock
                        .now_us()
                        .checked_sub(observed.seen)
                        .is_none_or(|age| age > OBSERVATION_LIFETIME_US)
                    {
                        return Err(Error::GrantTimeout);
                    }
                    Ok(AppliedEdca {
                        parameter_set_count: observed.count,
                        access_categories: effective,
                    })
                },
            )
        }
        .map_err(Error::Regulatory)??;
        s.modern.as_mut().unwrap().applied_edca = Some(result);
        s.edca = None;
        s.phase = Phase::Associated;
        Ok(())
    }
}
