// SPDX-License-Identifier: GPL-2.0-only
// 802.11/802.3 and controlled-port rules adapt Linux net/wireless/util.c
// and net/mac80211/{rx.c,tx.c,wpa.c}. Original notices in THIRD_PARTY.md.
//! Single-MSDU data/control-port framing. TX output is an explicit hardware
//! work plan: its MPDU is plaintext, and required hardware cipher/MIC work must
//! be completed by the selected vendor path before successful TX.

use super::{
    AssociationContext, Phase, PortPolicy, RegulatoryPolicy, Station, phy::AccessCategory,
};
use crate::{
    MAX_FRAME, Mac,
    wifi::{
        Aggregation, Channel,
        frame::Mpdu,
        security::{self, KeyIdentity, KeyScope, KeySlot, NonceOwner, PacketNumber},
    },
};
use alloc::{sync::Arc, vec, vec::Vec};
use core::borrow::{Borrow, BorrowMut};

pub mod amsdu;

const EAPOL: u16 = 0x888e;
const PAE_GROUP: Mac = Mac([1, 0x80, 0xc2, 0, 0, 3]);
const RFC1042: [u8; 6] = [0xaa, 0xaa, 3, 0, 0, 0];
const BRIDGE_TUNNEL: [u8; 6] = [0xaa, 0xaa, 3, 0, 0, 0xf8];
const AARP: u16 = 0x80f3;
const IPX: u16 = 0x8137;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    NotAssociated,
    Stale,
    WrongChannel,
    WrongPeer,
    Integrity,
    Unsupported(&'static str),
    ClosedPort,
    Unencrypted,
    WrongKey,
    Regulatory,
    InvalidEthernet,
    NoMemory,
    Busy,
    Crypto(security::Error),
}

impl From<security::Error> for Error {
    fn from(error: security::Error) -> Self {
        Self::Crypto(error)
    }
}

#[derive(Debug)]
pub enum Ingress {
    Data(Vec<u8>),
    /// Route to the real OS authentication service, not the ordinary data
    /// stack. Classifying EAPOL does not validate its handshake/MIC/replay.
    ControlPort {
        ethernet: Vec<u8>,
        encrypted: bool,
        key: Option<KeyIdentity>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxClass {
    Data,
    ControlPortPlaintext,
    ControlPortProtected(KeyIdentity),
}

/// The acknowledged association context whose WMM parameters a QoS MSDU
/// uses, and the TID it is sent with.
#[derive(Clone, Copy)]
pub struct Qos<'a> {
    pub context: &'a Arc<AssociationContext>,
    pub tid: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SequenceOwner {
    /// Preserve the shared host-prepared sequence in the vendor's MAC header/
    /// descriptor input. This does not prove the on-air sequence.
    Host,
    /// The source-backed vendor path explicitly assigns sequence in the device.
    Device,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SequenceAssignment {
    /// Prepared host input, never an observed on-air sequence.
    Host(u16),
    /// Device owns air assignment. QoS may still carry the canonical
    /// source software sequence input for ADDBA bookkeeping; that input is
    /// never an on-air observation. Descriptor must request device mode.
    Device,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    None,
    /// MPDU contains no IV/PN or MIC space. Hardware owns all three.
    Firmware {
        key: KeyIdentity,
    },
    /// MPDU contains the reserved eight-byte IV/PN header; hardware still
    /// computes the cipher and appends its MIC. Never treat it as ciphertext.
    HostIv {
        key: KeyIdentity,
        pn: PacketNumber,
    },
}

/// Not Clone: a host PN reservation belongs to this MPDU alone.
#[derive(Debug)]
pub struct TxPlan {
    epoch: u64,
    channel: Channel,
    plaintext: Vec<u8>,
    protection: Protection,
    sequence: SequenceAssignment,
    control_port: bool,
    qos: Option<(u8, Arc<AssociationContext>)>,
}

impl TxPlan {
    pub const fn association_epoch(&self) -> u64 {
        self.epoch
    }
    pub const fn channel(&self) -> Channel {
        self.channel
    }
    pub fn plaintext_mpdu(&self) -> &[u8] {
        &self.plaintext
    }
    pub const fn protection(&self) -> Protection {
        self.protection
    }
    pub const fn control_port(&self) -> bool {
        self.control_port
    }
    pub const fn sequence(&self) -> SequenceAssignment {
        self.sequence
    }
    pub fn qos_tid(&self) -> Option<u8> {
        self.qos.as_ref().map(|(tid, _)| *tid)
    }
    pub fn association_context(&self) -> Option<&Arc<AssociationContext>> {
        self.qos.as_ref().map(|(_, context)| context)
    }
    /// Vendor queue must revalidate epoch/full key identity before publishing
    /// DMA, implement every requested protection/sequence effect or return unsupported,
    /// and keep key/counter resources until hardware/work retirement.
    pub fn into_parts(self) -> (u64, Channel, Vec<u8>, Protection, SequenceAssignment, bool) {
        (
            self.epoch,
            self.channel,
            self.plaintext,
            self.protection,
            self.sequence,
            self.control_port,
        )
    }
}

fn ethernet(destination: Mac, source: Mac, payload: &[u8]) -> Result<Vec<u8>, Error> {
    let snap = payload.get(..8).and_then(|header| {
        let protocol = u16::from_be_bytes([header[6], header[7]]);
        if (header[..6] == RFC1042 && !matches!(protocol, AARP | IPX))
            || header[..6] == BRIDGE_TUNNEL
        {
            Some(protocol)
        } else {
            None
        }
    });
    let (protocol, body) = if let Some(protocol) = snap {
        (protocol, &payload[8..])
    } else {
        (
            u16::try_from(payload.len()).map_err(|_| Error::InvalidEthernet)?,
            payload,
        )
    };
    if body.len() > MAX_FRAME - 14 {
        return Err(Error::InvalidEthernet);
    }
    let mut output = Vec::with_capacity(14 + body.len());
    output.extend_from_slice(&destination.0);
    output.extend_from_slice(&source.0);
    output.extend_from_slice(&protocol.to_be_bytes());
    output.extend_from_slice(body);
    Ok(output)
}

fn msdu(ethernet: &[u8]) -> Result<(Mac, Mac, u16, Vec<u8>), Error> {
    if !(14..=MAX_FRAME).contains(&ethernet.len()) {
        return Err(Error::InvalidEthernet);
    }
    let destination = Mac(ethernet[..6].try_into().unwrap());
    let source = Mac(ethernet[6..12].try_into().unwrap());
    let protocol = u16::from_be_bytes(ethernet[12..14].try_into().unwrap());
    let mut body = Vec::with_capacity(ethernet.len() - 6);
    if matches!(protocol, AARP | IPX) {
        body.extend_from_slice(&BRIDGE_TUNNEL);
    } else if protocol >= 0x0600 {
        body.extend_from_slice(&RFC1042);
    }
    if protocol >= 0x0600 {
        body.extend_from_slice(&ethernet[12..]);
    } else {
        if usize::from(protocol) > ethernet.len() - 14 {
            return Err(Error::InvalidEthernet);
        }
        body.extend_from_slice(&ethernet[14..]);
    }
    Ok((destination, source, protocol, body))
}

impl Station {
    /// The authorized PTK and GTK of the link whose keys `keys` holds.
    fn authorized_link<K: Borrow<KeySlot>>(
        &self,
        keys: &[K],
    ) -> Option<(KeyIdentity, KeyIdentity)> {
        let present = |key| {
            keys.iter()
                .any(|slot| slot.borrow().installed() == Some(key))
        };
        self.authorization
            .as_ref()?
            .iter()
            .copied()
            .find(|&(ptk, gtk)| present(ptk) && present(gtk))
    }

    /// Recheck immediately before queue publication, serialized with
    /// station/key retirement and policy changes. This is permission to submit
    /// the plan, never evidence of DMA ownership, cipher execution or air ACK.
    /// A caller holding a plan must keep its key epoch alive until the plan is
    /// discarded or the real hardware/deferred users have drained.
    pub fn validate_tx_plan(
        &self,
        plan: &TxPlan,
        keys: &[KeySlot],
        policy: &mut impl RegulatoryPolicy,
    ) -> Result<(), Error> {
        self.validate_tx_plan_refs(plan, keys, policy)
    }

    /// The same publication check for separately kept key owners. Borrowed
    /// entries refer to the original slots; no key or nonce state is recreated.
    pub fn validate_tx_plan_refs<K: Borrow<KeySlot>>(
        &self,
        plan: &TxPlan,
        keys: &[K],
        policy: &mut impl RegulatoryPolicy,
    ) -> Result<(), Error> {
        if self.phase != Phase::Associated {
            return Err(Error::NotAssociated);
        }
        if plan.epoch != self.epoch {
            return Err(Error::Stale);
        }
        let join = self.join.as_ref().ok_or(Error::NotAssociated)?;
        let channel = self.current_channel().ok_or(Error::NotAssociated)?;
        if plan.channel != channel {
            return Err(Error::WrongChannel);
        }
        if let Some((tid, context)) = &plan.qos {
            self.validate_association_context(context)
                .map_err(|_| Error::Stale)?;
            let header = crate::wifi::frame::Header::parse(&plan.plaintext)
                .map_err(|_| Error::InvalidEthernet)?;
            if header.tid != Some(*tid)
                || header.amsdu
                || plan.plaintext.get(24..26) != Some(&[*tid, 0])
            {
                return Err(Error::Stale);
            }
            qos_access(context, *tid)?;
        }
        if !policy.allow_data_tx(channel) {
            return Err(Error::Regulatory);
        }
        let key = match plan.protection {
            Protection::None => None,
            Protection::Firmware { key } | Protection::HostIv { key, .. } => Some(key),
        };
        // Frames leave with the setup link's PTK; the device puts them on a
        // link.
        if !plan.control_port && join.policy == PortPolicy::Controlled {
            let setup = self.authorization.as_ref().and_then(|links| links.first());
            if self.authorized_link(keys).is_none() || setup.is_none() {
                return Err(Error::ClosedPort);
            }
            if key != setup.map(|pair| pair.0) {
                return Err(Error::WrongKey);
            }
        }
        if let Some(key) = key
            && !keys
                .iter()
                .any(|slot| slot.borrow().installed() == Some(key))
        {
            return Err(Error::WrongKey);
        }
        Ok(())
    }

    /// RX epoch must come from the firmware/RX context, not a
    /// current-epoch lookup that retags old deferred frames.
    pub fn receive_msdu(
        &self,
        epoch: u64,
        frame: &Mpdu,
        keys: &mut [KeySlot],
    ) -> Result<Ingress, Error> {
        self.receive_msdu_refs(epoch, frame, keys)
    }

    /// Borrow separately owned slots exclusively for this RX operation. Replay
    /// mutation occurs in the selected slot. Safe Rust forbids aliasing
    /// mutable entries; the implementation never manufactures references.
    pub fn receive_msdu_refs<K: BorrowMut<KeySlot>>(
        &self,
        epoch: u64,
        frame: &Mpdu,
        keys: &mut [K],
    ) -> Result<Ingress, Error> {
        if self.phase != Phase::Associated {
            return Err(Error::NotAssociated);
        }
        if epoch != self.epoch {
            return Err(Error::Stale);
        }
        let join = self.join.as_ref().ok_or(Error::NotAssociated)?;
        let (view, link) = self.mld_view(frame).map_err(|_| Error::WrongChannel)?;
        let frame = view.as_ref();
        let (local, peer) = self.addresses().map_err(|_| Error::NotAssociated)?;
        // Group-addressed frames keep the address of the link they arrive on.
        let transmitter = if frame.header().receiver.is_multicast() {
            link.ap
        } else {
            peer
        };
        let header = frame.header();
        if !header.data_present() || header.control & 0x0300 != 0x0200 {
            return Err(Error::Unsupported("nonstation FromDS data"));
        }
        if header.fragmented() || header.amsdu || frame.aggregation != Aggregation::default() {
            return Err(Error::Unsupported("fragment/aggregate data"));
        }
        if header.transmitter != Some(transmitter)
            || (header.receiver != local && !header.receiver.is_multicast())
        {
            return Err(Error::WrongPeer);
        }
        let source = Mac(frame.bytes()[16..22].try_into().unwrap());
        if header.receiver.is_multicast() && source == local {
            return Err(Error::WrongPeer);
        }
        if frame.fcs_error || frame.monitor_only {
            return Err(Error::Integrity);
        }
        let mut selected_key = None;
        let payload = if header.protected() {
            if join.policy != PortPolicy::Controlled {
                return Err(Error::WrongKey);
            }
            let key = frame.security.key.ok_or(Error::WrongKey)?;
            let expected = if header.receiver.is_multicast() {
                KeyScope::Group(transmitter)
            } else {
                KeyScope::Pairwise(transmitter)
            };
            if key.scope() != expected {
                return Err(Error::WrongKey);
            }
            if matches!(expected, KeyScope::Pairwise(_))
                && key.index() != 0
                && !key.cipher().is_wep()
            {
                return Err(Error::Unsupported("extended pairwise key ID"));
            }
            let (pairwise, group) = join.request.key_ciphers().ok_or(Error::WrongKey)?;
            if key.cipher()
                != if header.receiver.is_multicast() {
                    group
                } else {
                    pairwise
                }
            {
                return Err(Error::WrongKey);
            }
            let slot = keys
                .iter_mut()
                .find(|slot| K::borrow(&**slot).installed() == Some(key))
                .ok_or(Error::WrongKey)?;
            let authenticated = slot.borrow_mut().authorize(frame)?;
            selected_key = Some(authenticated.key());
            authenticated.payload()
        } else {
            &frame.bytes()[header.length..]
        };
        let ethernet = ethernet(header.receiver, source, payload)?;
        if u16::from_be_bytes([ethernet[12], ethernet[13]]) == EAPOL {
            if header.receiver != local && header.receiver != PAE_GROUP {
                return Err(Error::WrongPeer);
            }
            return Ok(Ingress::ControlPort {
                ethernet,
                encrypted: header.protected(),
                key: selected_key,
            });
        }
        if join.policy == PortPolicy::Controlled {
            let (ptk, gtk) = self.authorized_link(keys).ok_or(Error::ClosedPort)?;
            if !header.protected() {
                return Err(Error::Unencrypted);
            }
            // A newly installed key cannot bypass explicit frontend activation.
            if selected_key != Some(ptk) && selected_key != Some(gtk) {
                return Err(Error::WrongKey);
            }
        }
        Ok(Ingress::Data(ethernet))
    }

    /// Deliver a complete post-order parent already checked by the
    /// canonical aggregate gate. This never authorizes a raw same-PN member or
    /// repeats the parent's replay update. Current context, original installed
    /// keys and controlled-port activation are rechecked before any output.
    pub fn receive_group_refs<C, K: Borrow<KeySlot>>(
        &self,
        received: &security::aggregate::ReceivedGroup<'_, C>,
        keys: &[K],
    ) -> Result<Vec<Ingress>, Error> {
        use security::aggregate::{GroupSecurity, Shape};
        if self.phase != Phase::Associated {
            return Err(Error::NotAssociated);
        }
        self.validate_association_context(received.group().context())
            .map_err(|_| Error::Stale)?;
        let join = self.join.as_ref().ok_or(Error::NotAssociated)?;
        let selected = match received.security() {
            GroupSecurity::Open => {
                if join.policy != PortPolicy::Open {
                    return Err(Error::Unencrypted);
                }
                None
            }
            GroupSecurity::Protected { key, .. } => {
                if join.policy != PortPolicy::Controlled
                    || !keys
                        .iter()
                        .any(|slot| slot.borrow().installed() == Some(key))
                {
                    return Err(Error::WrongKey);
                }
                Some(key)
            }
        };
        let mut out = Vec::new();
        for member in received.members() {
            let header = member.mpdu().header();
            let mut frames = if header.amsdu {
                subframes(
                    member.payload(),
                    header.receiver,
                    received.group().shape() == Shape::HardwareSplitAmsdu,
                )?
            } else {
                let source = Mac(member.mpdu().bytes()[16..22].try_into().unwrap());
                vec![ethernet(header.receiver, source, member.payload())?]
            };
            out.try_reserve(frames.len()).map_err(|_| Error::NoMemory)?;
            for ethernet in frames.drain(..) {
                if u16::from_be_bytes([ethernet[12], ethernet[13]]) == EAPOL {
                    let destination = Mac(ethernet[..6].try_into().unwrap());
                    if destination != self.local && destination != PAE_GROUP {
                        return Err(Error::WrongPeer);
                    }
                    out.push(Ingress::ControlPort {
                        ethernet,
                        encrypted: selected.is_some(),
                        key: selected,
                    });
                } else {
                    if join.policy == PortPolicy::Controlled {
                        let (ptk, gtk) = self.authorized_link(keys).ok_or(Error::ClosedPort)?;
                        if selected != Some(ptk) && selected != Some(gtk) {
                            return Err(Error::WrongKey);
                        }
                    }
                    out.push(Ingress::Data(ethernet));
                }
            }
        }
        Ok(out)
    }

    /// Single-MSDU QoS with source-backed device sequence assignment. The
    /// current acknowledged context supplies WMM; a copied capability or
    /// TID cannot bypass it. The TID is sent as given: `data_tid` chooses it
    /// as `ieee80211_select_queue` does. No BA/A-MSDU permission is implied.
    pub fn prepare_qos_msdu_refs<K: BorrowMut<KeySlot>>(
        &mut self,
        epoch: u64,
        ethernet: &[u8],
        class: TxClass,
        qos: Qos<'_>,
        keys: &mut [K],
        policy: &mut impl RegulatoryPolicy,
    ) -> Result<TxPlan, Error> {
        let mut plan = self.prepare_qos_subframe_refs(epoch, ethernet, class, qos, keys, policy)?;
        let Qos { context, tid } = qos;
        let sequence = self.allocate_qos_sequence(context, tid).map_err(|e| {
            if e == super::Error::Busy {
                Error::Busy
            } else {
                Error::Stale
            }
        })?;
        plan.plaintext[22..24].copy_from_slice(&(sequence << 4).to_le_bytes());
        Ok(plan)
    }

    /// [`Self::prepare_qos_msdu_refs`] without a sequence number: an MSDU that
    /// joins an A-MSDU travels under the number of the frame it joins.
    pub fn prepare_qos_subframe_refs<K: BorrowMut<KeySlot>>(
        &mut self,
        epoch: u64,
        ethernet: &[u8],
        class: TxClass,
        qos: Qos<'_>,
        keys: &mut [K],
        policy: &mut impl RegulatoryPolicy,
    ) -> Result<TxPlan, Error> {
        let Qos { context, tid } = qos;
        self.validate_association_context(context)
            .map_err(|_| Error::Stale)?;
        qos_access(context, tid)?;
        let mut plan =
            self.prepare_msdu_refs(epoch, ethernet, class, SequenceOwner::Device, keys, policy)?;
        plan.plaintext
            .try_reserve_exact(2)
            .map_err(|_| Error::NoMemory)?;
        plan.plaintext[0] |= 0x80;
        // Insert before the IV/PN reserve, if any. The body remains
        // plaintext and the existing selected original key owns cipher work.
        plan.plaintext.splice(24..24, [tid, 0]);
        plan.qos = Some((tid, context.clone()));
        Ok(plan)
    }

    /// Prepare one non-QoS MPDU. The physical backend selects its source-backed
    /// sequence owner independently of nonce ownership. Returns a hardware work
    /// plan, not successful queueing, on-air transmission or a ciphertext buffer.
    pub fn prepare_msdu(
        &mut self,
        epoch: u64,
        ethernet: &[u8],
        class: TxClass,
        sequence_owner: SequenceOwner,
        keys: &mut [KeySlot],
        policy: &mut impl RegulatoryPolicy,
    ) -> Result<TxPlan, Error> {
        self.prepare_msdu_refs(epoch, ethernet, class, sequence_owner, keys, policy)
    }

    /// Prepare against borrowed original slots from independently kept
    /// hardware owners, using exactly the same admission and nonce algorithm.
    pub fn prepare_msdu_refs<K: BorrowMut<KeySlot>>(
        &mut self,
        epoch: u64,
        ethernet: &[u8],
        class: TxClass,
        sequence_owner: SequenceOwner,
        keys: &mut [K],
        policy: &mut impl RegulatoryPolicy,
    ) -> Result<TxPlan, Error> {
        if self.phase != Phase::Associated {
            return Err(Error::NotAssociated);
        }
        if epoch != self.epoch {
            return Err(Error::Stale);
        }
        let join = self.join.as_ref().ok_or(Error::NotAssociated)?;
        let channel = self.current_channel().ok_or(Error::NotAssociated)?;
        if !policy.allow_data_tx(channel) {
            return Err(Error::Regulatory);
        }
        let (destination, source, protocol, payload) = msdu(ethernet)?;
        // An MLD association's frames address the MLDs; the device puts them
        // on a link, as mt792x_tx does.
        let (local, peer) = self.addresses().map_err(|_| Error::NotAssociated)?;
        if source != local {
            return Err(Error::WrongPeer);
        }
        let control_port = protocol == EAPOL;
        let selected = match class {
            TxClass::Data => {
                if control_port {
                    return Err(Error::Unsupported(
                        "EAPOL requires explicit control-port command",
                    ));
                }
                if join.policy == PortPolicy::Controlled {
                    let setup = self.authorization.as_ref().and_then(|links| links.first());
                    if self.authorized_link(keys).is_none() {
                        return Err(Error::ClosedPort);
                    }
                    Some(setup.ok_or(Error::ClosedPort)?.0)
                } else {
                    None
                }
            }
            TxClass::ControlPortPlaintext | TxClass::ControlPortProtected(_) => {
                if !control_port || (destination != peer && destination != PAE_GROUP) {
                    return Err(Error::WrongPeer);
                }
                if let TxClass::ControlPortProtected(key) = class {
                    Some(key)
                } else {
                    None
                }
            }
        };
        let (protection, crypto_header) = if let Some(key) = selected {
            if key.index() != 0 && !key.cipher().is_wep() {
                return Err(Error::Unsupported("extended pairwise key ID"));
            }
            if key.scope() != KeyScope::Pairwise(peer)
                || join.request.key_ciphers().map(|pair| pair.0) != Some(key.cipher())
            {
                return Err(Error::WrongKey);
            }
            let slot = keys
                .iter_mut()
                .find(|slot| K::borrow(&**slot).installed() == Some(key))
                .ok_or(Error::WrongKey)?;
            match key.nonce_owner() {
                NonceOwner::Host => {
                    let nonce = slot.borrow_mut().reserve_host_tx_nonce(key)?;
                    let pn = nonce.packet_number();
                    (Protection::HostIv { key, pn }, Some(nonce.into_header()))
                }
                NonceOwner::Firmware => (Protection::Firmware { key }, None),
                NonceOwner::ReceiveOnly => return Err(Error::WrongKey),
            }
        } else {
            (Protection::None, None)
        };
        let mut plaintext = vec![0; 24];
        let control = if selected.is_some() {
            0x4108_u16
        } else {
            0x0108_u16
        };
        plaintext[..2].copy_from_slice(&control.to_le_bytes());
        plaintext[4..10].copy_from_slice(&peer.0);
        plaintext[10..16].copy_from_slice(&local.0);
        plaintext[16..22].copy_from_slice(&destination.0);
        let sequence = match sequence_owner {
            SequenceOwner::Host => {
                let assigned = self.sequence;
                plaintext[22..24].copy_from_slice(&(assigned << 4).to_le_bytes());
                self.sequence = (self.sequence + 1) & 0xfff;
                SequenceAssignment::Host(assigned)
            }
            SequenceOwner::Device => SequenceAssignment::Device,
        };
        if let Some(header) = crypto_header {
            plaintext.extend_from_slice(&header);
        }
        plaintext.extend_from_slice(&payload);
        Ok(TxPlan {
            epoch,
            channel,
            plaintext,
            protection,
            sequence,
            control_port,
            qos: None,
        })
    }
}

// Source ieee80211_amsdu_to_8023s station profile: Ethernet-length subheaders,
// four-byte inter-subframe padding, first-DA RFC1042 injection rejection and
// local unicast-DA matching. Station FromDS permits independent inner SAs.
// A malformed later subframe refuses the whole output, never a partial prefix.
fn subframes(mut bytes: &[u8], receiver: Mac, split_member: bool) -> Result<Vec<Vec<u8>>, Error> {
    let mut out = Vec::new();
    let mut index = 0;
    loop {
        let header = bytes.get(..14).ok_or(Error::InvalidEthernet)?;
        if index == 0 && header[..6] == RFC1042 {
            return Err(Error::InvalidEthernet);
        }
        let length = usize::from(u16::from_be_bytes([header[12], header[13]]));
        let end = 14usize.checked_add(length).ok_or(Error::InvalidEthernet)?;
        bytes.get(14..end).ok_or(Error::InvalidEthernet)?;
        let padding = (4 - end % 4) % 4;
        let last = bytes.len() <= end + padding;
        if split_member && !last {
            return Err(Error::InvalidEthernet);
        }
        let destination = Mac(header[..6].try_into().unwrap());
        let source = Mac(header[6..12].try_into().unwrap());
        if destination.is_multicast() || destination == receiver {
            out.try_reserve(1).map_err(|_| Error::NoMemory)?;
            // Source reuses the final linear skb without trimming up to three
            // trailing bytes. Preserve those bytes and the original
            // length field for non-SNAP frames, rather than inventing a new
            // length or silently discarding observed trailing padding.
            let payload = if last { &bytes[14..] } else { &bytes[14..end] };
            let mut frame = ethernet(destination, source, payload)?;
            let tunnel = payload.get(..8).is_some_and(|p| {
                let protocol = u16::from_be_bytes([p[6], p[7]]);
                (p[..6] == RFC1042 && !matches!(protocol, AARP | IPX)) || p[..6] == BRIDGE_TUNNEL
            });
            if !tunnel {
                frame[12..14].copy_from_slice(&header[12..14]);
            }
            out.push(frame);
        }
        if last {
            return Ok(out);
        }
        bytes = bytes.get(end + padding..).ok_or(Error::InvalidEthernet)?;
        index += 1;
    }
}

/// The WMM access category of each 802.1D priority, `ieee802_1d_to_ac`.
const ACI: [u8; 8] = [0, 1, 1, 0, 2, 2, 3, 3];

fn qos_access(context: &AssociationContext, tid: u8) -> Result<(), Error> {
    let aci = *ACI
        .get(usize::from(tid))
        .ok_or(Error::Unsupported("QoS TID above7"))?;
    let wmm = context
        .negotiated()
        .wmm
        .as_ref()
        .ok_or(Error::Unsupported("missing actual WMM"))?;
    wmm.access_categories
        .iter()
        .find(|ac| ac.aci == aci)
        .ok_or(Error::Unsupported("missing WMM access category"))?;
    Ok(())
}

/// Linux `ieee80211_downgrade_queue` without an admitted TSPEC: a priority
/// whose access category requires admission control moves to the next
/// lower category until one does not; background is used regardless.
fn downgrade(categories: &[AccessCategory], mut priority: u8) -> u8 {
    let acm = |priority: u8| {
        categories
            .iter()
            .any(|ac| ac.aci == ACI[usize::from(priority)] && ac.admission_control)
    };
    while acm(priority) {
        // `wme_downgrade_ac`: voice to video, video to best effort, best
        // effort to background.
        priority = match priority {
            6 | 7 => 5,
            4 | 5 => 3,
            0 | 3 => 2,
            _ => break,
        };
    }
    priority
}

/// Linux `ieee80211_select_queue` for a station: the QoS TID of an outgoing
/// Ethernet frame, or `None` when the association has no WMM and data goes
/// without QoS. EAPOL takes priority 7; other frames are classified by
/// `cfg80211_classify8021d`. A QoS Map comes from the OS's interworking
/// configuration, and none reaches the station, so the RFC 8325 default
/// applies. `current` holds the AP's latest access categories, whose
/// admission-control flags it may change in later beacons.
pub fn data_tid(
    context: &AssociationContext,
    current: Option<&[AccessCategory; 4]>,
    qos_map: Option<&QosMap>,
    ethernet: &[u8],
) -> Option<u8> {
    let wmm = context.negotiated().wmm.as_ref()?;
    let categories = current.unwrap_or(&wmm.access_categories);
    let ethertype = |at: usize| {
        ethernet
            .get(at..at + 2)
            .map_or(0, |b| u16::from_be_bytes([b[0], b[1]]))
    };
    let priority = if ethertype(12) == EAPOL {
        7
    } else {
        classify8021d(ethernet, qos_map)
    };
    Some(downgrade(categories, priority))
}

/// An interworking QoS Map the OS sets for the association, as
/// `cfg80211_qos_map`: DSCP exceptions, then each priority's DSCP range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QosMap {
    exceptions: [(u8, u8); 21],
    count: u8,
    ranges: [(u8, u8); 8],
}

impl QosMap {
    /// `nl80211_set_qos_map`'s QoS Map Set field: up to 21 (DSCP, priority)
    /// exceptions, then eight (low, high) DSCP ranges.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if !bytes.len().is_multiple_of(2) || !(16..=16 + 2 * 21).contains(&bytes.len()) {
            return Err(Error::Unsupported("QoS Map length"));
        }
        let (exceptions, ranges) = bytes.split_at(bytes.len() - 16);
        let mut map = Self {
            exceptions: [(0, 0); 21],
            count: 0,
            ranges: [(0, 0); 8],
        };
        for (slot, e) in map.exceptions.iter_mut().zip(exceptions.as_chunks::<2>().0) {
            if e[1] > 7 {
                return Err(Error::Unsupported("QoS Map priority"));
            }
            *slot = (e[0], e[1]);
            map.count += 1;
        }
        for (slot, r) in map.ranges.iter_mut().zip(ranges.as_chunks::<2>().0) {
            *slot = (r[0], r[1]);
        }
        Ok(map)
    }

    /// The priority the map gives `dscp`: an exception, else the first
    /// priority whose range holds it.
    fn priority(&self, dscp: u8) -> Option<u8> {
        self.exceptions[..usize::from(self.count)]
            .iter()
            .find(|&&(exception, _)| exception == dscp)
            .map(|&(_, priority)| priority)
            .or_else(|| {
                (0..8u8).find(|&up| {
                    let (low, high) = self.ranges[usize::from(up)];
                    (low..=high).contains(&dscp)
                })
            })
    }
}

/// Linux `cfg80211_classify8021d`. A VLAN tag's nonzero priority stands, as
/// for a tag the stack carries beside the frame; otherwise the encapsulated
/// protocol is classified, through the QoS Map when one is set.
fn classify8021d(ethernet: &[u8], qos_map: Option<&QosMap>) -> u8 {
    const VLAN: u16 = 0x8100;
    let mut at = 12;
    let field = |at: usize| ethernet.get(at..at + 2).map(|b| [b[0], b[1]]);
    if field(at).map(u16::from_be_bytes) == Some(VLAN) {
        let priority = field(at + 2).map_or(0, |tci| tci[0] >> 5);
        if priority > 0 {
            return priority;
        }
        at += 4;
    }
    let body = ethernet.get(at + 2..).unwrap_or_default();
    let dscp = match field(at).map(u16::from_be_bytes) {
        // IPv4 and IPv6 DSCP from a whole header.
        Some(0x0800) if body.len() >= 20 => body[1] & 0xfc,
        Some(0x86dd) if body.len() >= 40 => (body[0] << 4 | body[1] >> 4) & 0xfc,
        // MPLS unicast and multicast: the label's traffic class.
        Some(0x8847 | 0x8848) if body.len() >= 4 => return (body[2] >> 1) & 7,
        // 802.21 is network control.
        Some(0x8917) => return 7,
        _ => return 0,
    };
    if let Some(priority) = qos_map.and_then(|map| map.priority(dscp >> 2)) {
        return priority;
    }
    // RFC 8325: the DSCP's three high bits, except the service classes
    // section 4 maps elsewhere.
    match dscp >> 2 {
        // AF11-13 high-throughput data and CS2 OAM.
        10 | 12 | 14 | 16 => 0,
        // AF21-23 low-latency data.
        18 | 20 | 22 => 3,
        // CS3 broadcast video and AF31-33 multimedia streaming.
        24 | 26 | 28 | 30 => 4,
        // VA voice admit and EF telephony.
        44 | 46 => 6,
        // CS6 network control.
        48 => 7,
        _ => dscp >> 5,
    }
}

#[cfg(test)]
mod tests;
