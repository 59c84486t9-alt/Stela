// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
// Native key/TX ownership follows the existing MediaTek client. Robust frame,
// SA Query and firmware CCMP rules follow the pinned Linux mac80211/mt7925
// sources and original notices kept in mediatek/THIRD_PARTY.md.
//! Key-bound protected-management transport for a real OS management service.
//! This is not PMF negotiation or a station management policy:
//! authenticated observations never disconnect, open a port or admit 6GHz.

use super::*;
use core::any::Any;
use mailbox::key::bip;
use wifi::security::NonceOwner;

mod block_ack;
mod modern;
mod rotation;

/// Transport namespace. No public constructor, Clone or mutable
/// fields. Its existence proves key installation, not negotiated PMF policy.
/// The real OS service must own SA Query transactions, timers and departure/
/// action decisions; this backend never infers those from authenticated bytes.
pub struct Session {
    _resource: Arc<dyn Any + Send + Sync>,
    association: u64,
    peer_generation: u64,
    profile: Profile,
    context: Option<Arc<station::AssociationContext>>,
    ptk: KeyIdentity,
    gtk: KeyIdentity,
    igtk: bip::Identity,
    igtks: [Option<bip::Identity>; 2],
}
impl Session {
    pub const fn association_epoch(&self) -> u64 {
        self.association
    }
    pub const fn pairwise_key(&self) -> KeyIdentity {
        self.ptk
    }
    pub const fn group_key(&self) -> KeyIdentity {
        self.gtk
    }
    pub const fn management_key(&self) -> bip::Identity {
        self.igtk
    }
    /// Kept MMIE 4/5 receive identities; firmware delivery/air overlap
    /// remains unchecked and no hardware integrity error is ignored.
    pub const fn receive_management_keys(&self) -> [Option<bip::Identity>; 2] {
        self.igtks
    }
    pub fn association_context(&self) -> Option<&station::AssociationContext> {
        self.context.as_deref()
    }
}

/// Original completed RX and authenticated plaintext. Keeps the original
/// requester/association/key namespace, including while queued by the OS. The
/// transport keeps its original association epoch and, for modern links, the
/// AssociationContext. Body access is a historical observation; acting
/// on it requires with_management or guarded with_management_modern
/// to recheck the original namespace under the serialized current Client.
pub struct Received {
    session: Arc<Session>,
    frame: Mpdu,
    body: Vec<u8>,
    pn: PacketNumber,
    group: bool,
}
impl Received {
    pub fn session(&self) -> &Arc<Session> {
        &self.session
    }
    pub fn frame(&self) -> &Mpdu {
        &self.frame
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub const fn packet_number(&self) -> PacketNumber {
        self.pn
    }
    pub const fn group(&self) -> bool {
        self.group
    }
}

/// Bounded OS-generated robust management messages. SA Query transaction IDs
/// remain opaque OS bytes; this does not invent randomness, retries, timers
/// or successful transaction matching. Departure publication does not itself
/// remove the local peer: the OS must call the ordinary disconnect/drain path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transmit {
    Deauthenticate(u16),
    Disassociate(u16),
    SaQueryRequest([u8; 2]),
    SaQueryResponse([u8; 2]),
}
impl Transmit {
    fn encode(self, profile: Profile) -> Vec<u8> {
        let (subtype, body): (u16, Vec<u8>) = match self {
            Self::Deauthenticate(reason) => (0xc0, reason.to_le_bytes().to_vec()),
            Self::Disassociate(reason) => (0xa0, reason.to_le_bytes().to_vec()),
            Self::SaQueryRequest(id) => (0xd0, alloc::vec![8, 0, id[0], id[1]]),
            Self::SaQueryResponse(id) => (0xd0, alloc::vec![8, 1, id[0], id[1]]),
        };
        let mut bytes = alloc::vec![0; 24];
        bytes[..2].copy_from_slice(&(subtype | 0x4000).to_le_bytes());
        bytes[4..10].copy_from_slice(&profile.peer.0);
        bytes[10..16].copy_from_slice(&profile.interface.address.0);
        bytes[16..22].copy_from_slice(&profile.peer.0);
        bytes.extend_from_slice(&body);
        bytes
    }
}

impl<I: BarIo, Q: QueueIo, C: 'static> Client<I, Q, C> {
    fn management_keys(s: &Owned<I, Q, C>) -> Result<(KeyIdentity, KeyIdentity), Error> {
        if s.phase != Phase::Associated
            || s.station.phase() != station::Phase::Associated
            || s.format_generation != Some(s.peer_generation)
            || s.controller
                .state()
                .data_tx
                .as_ref()
                .is_none_or(|q| q.is_poisoned())
        {
            return Err(Error::WrongPhase);
        }
        let p = s.profile.ok_or(Error::WrongProfile)?;
        let ptk = s
            .ptk
            .as_ref()
            .and_then(|k| k.slot().installed())
            .ok_or(Error::NoKey)?;
        let gtk = s
            .gtk
            .as_ref()
            .and_then(|k| k.slot().installed())
            .ok_or(Error::NoKey)?;
        let peer = s.station.pairwise_peer().ok_or(Error::WrongProfile)?;
        if ptk.scope() != KeyScope::Pairwise(peer)
            || gtk.scope() != KeyScope::Group(p.peer)
            || ptk.slot() != p.wcid
            || gtk.slot() != p.interface.broadcast_wcid
            || ptk.index() != 0
            || ptk.nonce_owner() != NonceOwner::Firmware
        {
            return Err(Error::WrongProfile);
        }
        Ok((ptk, gtk))
    }

    pub(super) fn validate_management(s: &Owned<I, Q, C>, session: &Session) -> Result<(), Error> {
        // Kept object first: copied numbers or an equal peer/profile
        // from another Client cannot create permission or trigger MMIO.
        if s.management
            .as_ref()
            .is_none_or(|current| !core::ptr::eq(current.as_ref(), session))
        {
            return Err(Error::Station(station::Error::Stale));
        }
        let (ptk, gtk) = Self::management_keys(s)?;
        if s.station.association_epoch() != Some(session.association)
            || s.profile.map(|p| p.association_identity())
                != Some(session.profile.association_identity())
            || s.peer_generation != session.peer_generation
            || ptk != session.ptk
            || gtk != session.gtk
            || s.gtk.as_ref().and_then(HardwareKey::installed_igtk) != Some(session.igtk)
            || s.gtk.as_ref().map(HardwareKey::installed_igtks) != Some(session.igtks)
        {
            return Err(Error::Station(station::Error::Stale));
        }
        match (&session.context, &s.modern) {
            (Some(context), Some(modern)) if Arc::ptr_eq(context, modern.context()) => {
                s.station
                    .validate_association_context(context)
                    .map_err(Error::Station)?;
                if context.bssid() != session.profile.peer
                    || s.station.operating_definition().map(|d| d.control)
                        != s.profile.map(|p| p.channel)
                {
                    return Err(Error::WrongProfile);
                }
            }
            (None, None) => {}
            _ => return Err(Error::Station(station::Error::Stale)),
        }
        Ok(())
    }

    // Check every native user, including canonical pending/quarantined
    // BA records whose native queue may not yet exist. The independent unsafe
    // hardware/RX/IRQ/external-deferred-user fence remains required as well.
    pub(super) fn management_drained(s: &Owned<I, Q, C>) -> Result<(), Error> {
        let controller = s.controller.state();
        let queue = controller.data_tx.as_ref().ok_or(Error::WrongPhase)?;
        if queue.outstanding_tokens() != 0
            || queue.pending_descriptors() != 0
            || !s.pending_rx.is_empty()
            || !s.asynchronous.is_empty()
            || !s.receive_groups.is_idle()
            || s.receive_ba.iter().any(Option::is_some)
            || s.transmit_ba.iter().any(Option::is_some)
            || !s.ba_actions.is_empty()
            || !s.station.block_ack_idle()
            || !controller.data_assembly.is_idle()
            || !controller.mailbox.as_ref().unwrap().receive_idle()
        {
            return Err(Error::NeedsDrain);
        }
        Ok(())
    }

    unsafe fn install_management_parts(
        controller: &mut Controller<I, Q, C>,
        phase: &mut Phase,
        key: &mut HardwareKey<Arc<C>>,
        cipher: Option<ManagementCipher>,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<bip::Identity, Error> {
        // BIP-CMAC-128 is the suite an RSNE without one selects.
        let cipher = cipher.unwrap_or(ManagementCipher::Cmac128);
        // SAFETY: caller checked all native users and supplies the independent
        // old hardware/RX/IRQ/deferred-key-user drain and authentic input.
        let outcome = unsafe {
            key.install_igtk(
                controller.state_mut().mailbox.as_mut().unwrap(),
                cipher,
                index,
                material,
                receive,
            )
        };
        if key.is_quarantined() {
            *phase = Phase::Quarantined;
        }
        outcome.map_err(Error::Key)
    }

    fn management_session(
        s: &mut Owned<I, Q, C>,
        epoch: u64,
        ptk: KeyIdentity,
        gtk: KeyIdentity,
        igtk: bip::Identity,
    ) -> Result<Arc<Session>, Error>
    where
        C: Send + Sync,
    {
        if let Some(session) = &s.management {
            Self::validate_management(s, session)?;
            return Ok(session.clone());
        }
        // Initial attachment and rotation require all old BA users drained.
        s.ba_management = None;
        s.ba_management_pn = None;
        let session = Arc::new(Session {
            _resource: s.controller.state().resource.clone(),
            association: epoch,
            peer_generation: s.peer_generation,
            profile: s.profile.ok_or(Error::WrongProfile)?,
            context: s.modern.as_ref().map(|m| m.context().clone()),
            ptk,
            gtk,
            igtk,
            igtks: s.gtk.as_ref().ok_or(Error::NoKey)?.installed_igtks(),
        });
        s.management = Some(session.clone());
        Ok(session)
    }

    /// Attach an initial GTK/IGTK batch and keep a protected-management
    /// transport for the real OS service. Does not authorize a controlled port,
    /// negotiate PMF, process a departure or override association admission.
    /// Exact retries keep the original advanced IPN and transport object.
    ///
    /// # Safety
    /// The real OS authenticated exchange supplied this IGTK/IPN for this exact
    /// association. Independently stop and drain all old GTK hardware RX/TX,
    /// DMA/IRQ/work and delayed key users before the initial combined key batch;
    /// the checked empty CPU/TX queues below alone cannot establish that fence.
    /// Serialize this with every other key/publication/reset/policy operation.
    /// Modern associations use install_management_key_modern instead, enclosing
    /// the key command in Owner::publish_association Management guards.
    /// This API does not implement live IGTK rekey. The OS management policy must
    /// separately establish negotiated protection before publishing or applying
    /// management effects; a returned Session grants transport only.
    pub unsafe fn install_management_key(
        &mut self,
        epoch: u64,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Arc<Session>, Error>
    where
        C: Send + Sync,
    {
        let s = self.state_mut();
        let (ptk, gtk) = Self::management_keys(s)?;
        if s.station.association_epoch() != Some(epoch) {
            return Err(Error::Station(station::Error::Stale));
        }
        if s.modern.is_some() {
            return Err(Error::ModernAdmissionRequired);
        }
        Self::management_drained(s)?;
        // SAFETY: inherited authenticated-input and independent drain contract.
        let igtk = unsafe {
            Self::install_management_parts(
                &mut s.controller,
                &mut s.phase,
                s.gtk.as_mut().ok_or(Error::NoKey)?,
                s.management_cipher,
                index,
                material,
                receive,
            )
        }?;
        Self::management_session(s, epoch, ptk, gtk, igtk)
    }

    /// Consume one native authenticated observation only while its
    /// original peer, PTK, GTK and IGTK remain current. The synchronous callback
    /// runs with exclusive Client access; an OS deferring work again must keep
    /// its own association-scoped policy and revalidate at its effects.
    pub fn with_management<T>(
        &mut self,
        received: Received,
        consume: impl FnOnce(&Mpdu, &[u8], PacketNumber) -> T,
    ) -> Result<T, Error> {
        Self::validate_management(self.state(), &received.session)?;
        if self.state().modern.is_some() {
            return Err(Error::ModernAdmissionRequired);
        }
        Ok(consume(&received.frame, &received.body, received.pn))
    }

    /// Publish exact OS-selected protected unicast departure/SA Query bytes.
    /// The real OS owns negotiated management policy and all transaction/state
    /// semantics. Firmware owns the acknowledged PTK's CCMP PN/IV/MIC;
    /// no caller-supplied counter or raw data/control frame is accepted. Actual
    /// descriptor+TX-free+unmap retirement keeps the original Session/keys.
    pub fn transmit_management(
        &mut self,
        session: &Session,
        message: Transmit,
        source: &dyn PageSource,
        policy: &mut impl station::RegulatoryPolicy,
    ) -> Result<Receipt, Error> {
        let s = self.state_mut();
        Self::validate_management(s, session)?;
        if s.modern.is_some() {
            return Err(Error::ModernAdmissionRequired);
        }
        let channel = s.profile.ok_or(Error::WrongProfile)?.channel;
        if !policy.allow_management_tx(channel) {
            return Err(Error::Station(station::Error::Regulatory));
        }
        let bytes = message.encode(session.profile);
        let (config, mut owner, grant) =
            Self::prepare_submission(s, &bytes, Some(session.ptk), true, true)?;
        owner.management = s.management.clone();
        let result =
            Self::publish_submission(&mut s.controller, source, &bytes, (config, owner, grant));
        if s.controller.state().data_tx.as_ref().unwrap().is_poisoned() {
            s.phase = Phase::Quarantined;
        }
        result
    }

    pub(super) fn receive_management(
        s: &mut Owned<I, Q, C>,
        frame: Mpdu,
        raw: &[u8],
    ) -> Result<Received, Error> {
        let session = s.management.as_ref().ok_or(Error::WrongPhase)?.clone();
        Self::validate_management(s, &session)?;
        let p = s.profile.ok_or(Error::WrongProfile)?;
        let d = rx::decode(Chip::Mt7925, raw).map_err(Error::Rx)?;
        let h = frame.header();
        let group = h.receiver.is_multicast();
        if (
            frame.radio.band,
            frame.radio.channel,
            frame.radio.frequency_mhz,
        ) != (p.channel.band, p.channel.number, p.channel.frequency_mhz)
            || d.wcid != p.wcid
            || d.unicast_to_me == group
            || h.control & 12 != 0
            || d.security.icv_error
            || d.security.tkip_mic_error
        {
            return Err(Error::WrongProfile);
        }
        // An MLD association's unicast frame names the MLDs before its PTK,
        // the MLDs', checks it.
        let frame = Self::translated(s, &frame).into_owned();
        let (local, _) = Self::association_addresses(s, p);
        let mut body = Vec::new();
        body.try_reserve_exact(frame.bytes().len())
            .map_err(|_| Error::NoMemory)?;
        let pn = if group {
            let proof = s
                .gtk
                .as_mut()
                .ok_or(Error::NoKey)?
                .authenticate_bip(&frame)
                .map_err(Error::Key)?;
            body.extend_from_slice(proof.body());
            proof.packet_number()
        } else {
            let proof = s
                .ptk
                .as_mut()
                .ok_or(Error::NoKey)?
                .authorize_unicast_management(&frame, local)
                .map_err(|e| Error::Key(mailbox::key::Error::Security(e)))?;
            body.extend_from_slice(proof.body());
            proof.packet_number()
        };
        if body.len() < 2 {
            return Err(Error::Frame(wifi::frame::Error::Truncated));
        }
        Ok(Received {
            session,
            frame,
            body,
            pn,
            group,
        })
    }
}

#[cfg(test)]
mod tests;
