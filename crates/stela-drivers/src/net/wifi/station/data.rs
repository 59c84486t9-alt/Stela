// SPDX-License-Identifier: GPL-2.0-only
// 802.11/802.3 and controlled-port rules adapt Linux net/wireless/util.c
// and net/mac80211/{rx.c,tx.c,wpa.c}. Original notices in THIRD_PARTY.md.
//! Single-MSDU data/control-port framing. TX output is an explicit hardware
//! work plan: its MPDU is plaintext, and required hardware cipher/MIC work must
//! be completed by the selected actual vendor path before successful TX.

use super::{
    AssociationContext, Phase, PortPolicy, RegulatoryPolicy, Station, phy::AccessCategory,
};
use crate::net::{
    MAX_FRAME, Mac,
    wifi::{
        Aggregation, Channel,
        frame::Mpdu,
        security::{self, KeyIdentity, KeyScope, KeySlot, NonceOwner, PacketNumber},
    },
};
use alloc::{sync::Arc, vec, vec::Vec};
use core::borrow::{Borrow, BorrowMut};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SequenceOwner {
    /// Preserve the shared host-prepared sequence in the vendor's MAC header/
    /// descriptor input. This does not prove the actual on-air sequence.
    Host,
    /// The source-backed vendor path explicitly assigns sequence in the device.
    Device,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SequenceAssignment {
    /// Prepared host input, never an observed on-air sequence.
    Host(u16),
    /// Device owns actual air assignment. QoS may still carry the canonical
    /// source software sequence input for ADDBA bookkeeping; that input is
    /// never an on-air observation. Actual descriptor must request device mode.
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
    /// and retain key/counter resources until actual hardware/work retirement.
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
    fn authorized_keys_present<K: Borrow<KeySlot>>(&self, keys: &[K]) -> bool {
        self.authorization.is_some_and(|(ptk, gtk)| {
            keys.iter()
                .any(|slot| slot.borrow().installed() == Some(ptk))
                && keys
                    .iter()
                    .any(|slot| slot.borrow().installed() == Some(gtk))
        })
    }

    /// Recheck immediately before actual queue publication, serialized with
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

    /// The same publication check for separately retained key owners. Borrowed
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
            let header = crate::net::wifi::frame::Header::parse(&plan.plaintext)
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
        if !plan.control_port && join.policy == PortPolicy::Controlled {
            if !self.authorized_keys_present(keys) {
                return Err(Error::ClosedPort);
            }
            if key != self.authorization.map(|pair| pair.0) {
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

    /// RX epoch must come from the actual retained firmware/RX context, not a
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
    /// mutation occurs in the actual selected slot. Safe Rust forbids aliasing
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
        let channel = self.current_channel().ok_or(Error::NotAssociated)?;
        if (
            frame.radio.band,
            frame.radio.channel,
            frame.radio.frequency_mhz,
        ) != (channel.band, channel.number, channel.frequency_mhz)
        {
            return Err(Error::WrongChannel);
        }
        let header = frame.header();
        if !header.data_present() || header.control & 0x0300 != 0x0200 {
            return Err(Error::Unsupported("nonstation FromDS data"));
        }
        if header.fragmented() || header.amsdu || frame.aggregation != Aggregation::default() {
            return Err(Error::Unsupported("fragment/aggregate data"));
        }
        if header.transmitter != Some(join.bssid)
            || (header.receiver != self.local && !header.receiver.is_multicast())
        {
            return Err(Error::WrongPeer);
        }
        let source = Mac(frame.bytes()[16..22].try_into().unwrap());
        if header.receiver.is_multicast() && source == self.local {
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
                KeyScope::Group(join.bssid)
            } else {
                KeyScope::Pairwise(join.bssid)
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
            if header.receiver != self.local && header.receiver != PAE_GROUP {
                return Err(Error::WrongPeer);
            }
            return Ok(Ingress::ControlPort {
                ethernet,
                encrypted: header.protected(),
                key: selected_key,
            });
        }
        if join.policy == PortPolicy::Controlled {
            if !self.authorized_keys_present(keys) {
                return Err(Error::ClosedPort);
            }
            if !header.protected() {
                return Err(Error::Unencrypted);
            }
            // A newly installed key cannot bypass explicit frontend activation.
            if !self
                .authorization
                .is_some_and(|(ptk, gtk)| selected_key == Some(ptk) || selected_key == Some(gtk))
            {
                return Err(Error::WrongKey);
            }
        }
        Ok(Ingress::Data(ethernet))
    }

    /// Deliver a genuinely complete post-order parent already checked by the
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
                        if !self.authorized_keys_present(keys) {
                            return Err(Error::ClosedPort);
                        }
                        if !self.authorization.is_some_and(|(ptk, gtk)| {
                            selected == Some(ptk) || selected == Some(gtk)
                        }) {
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
    /// exact current acknowledged context supplies WMM; a copied capability or
    /// TID cannot bypass it. The TID is sent as given: `data_tid` chooses it
    /// as `ieee80211_select_queue` does. No BA/A-MSDU permission is implied.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_qos_msdu_refs<K: BorrowMut<KeySlot>>(
        &mut self,
        epoch: u64,
        ethernet: &[u8],
        class: TxClass,
        context: &Arc<AssociationContext>,
        tid: u8,
        keys: &mut [K],
        policy: &mut impl RegulatoryPolicy,
    ) -> Result<TxPlan, Error> {
        self.validate_association_context(context)
            .map_err(|_| Error::Stale)?;
        qos_access(context, tid)?;
        let mut plan =
            self.prepare_msdu_refs(epoch, ethernet, class, SequenceOwner::Device, keys, policy)?;
        plan.plaintext
            .try_reserve_exact(2)
            .map_err(|_| Error::NoMemory)?;
        plan.plaintext[0] |= 0x80;
        // Insert before the actual IV/PN reserve, if any. The body remains
        // plaintext and the existing selected original key owns cipher work.
        plan.plaintext.splice(24..24, [tid, 0]);
        let sequence = self.allocate_qos_sequence(context, tid).map_err(|e| {
            if e == super::Error::Busy {
                Error::Busy
            } else {
                Error::Stale
            }
        })?;
        plan.plaintext[22..24].copy_from_slice(&(sequence << 4).to_le_bytes());
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

    /// Prepare against borrowed original slots from independently retained
    /// hardware owners, using exactly the same admission and nonce algorithm.
    #[allow(clippy::too_many_arguments)]
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
        if source != self.local {
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
                    if !self.authorized_keys_present(keys) {
                        return Err(Error::ClosedPort);
                    }
                    Some(self.authorization.ok_or(Error::ClosedPort)?.0)
                } else {
                    None
                }
            }
            TxClass::ControlPortPlaintext | TxClass::ControlPortProtected(_) => {
                if !control_port || (destination != join.bssid && destination != PAE_GROUP) {
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
            if key.scope() != KeyScope::Pairwise(join.bssid)
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
        plaintext[4..10].copy_from_slice(&join.bssid.0);
        plaintext[10..16].copy_from_slice(&self.local.0);
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
            // trailing bytes. Preserve those actual bytes and the original
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
mod tests {
    use super::*;

    #[test]
    fn data_frames_classify_like_cfg80211_classify8021d() {
        let frame = |ethertype: u16, body: &[u8]| {
            let mut frame = vec![0; 12];
            frame.extend_from_slice(&ethertype.to_be_bytes());
            frame.extend_from_slice(body);
            frame
        };
        let mut ipv4 = [0u8; 20];
        ipv4[1] = 46 << 2; // EF, which RFC 8325 maps to 6.
        assert_eq!(classify8021d(&frame(0x0800, &ipv4), None), 6);
        assert_eq!(classify8021d(&frame(0x0800, &ipv4[..19]), None), 0);
        let mut ipv6 = [0u8; 40];
        ipv6[0] = 0x60 | (56 << 2) >> 4; // CS7
        assert_eq!(classify8021d(&frame(0x86dd, &ipv6), None), 7);
        assert_eq!(classify8021d(&frame(0x8847, &[0, 0, 0b1010, 0]), None), 5);
        assert_eq!(classify8021d(&frame(0x8917, &[]), None), 7);
        assert_eq!(classify8021d(&frame(0x0806, &[0; 28]), None), 0);
        let dscp = |value: u8| {
            let mut ipv4 = [0u8; 20];
            ipv4[1] = value << 2;
            frame(0x0800, &ipv4)
        };
        let rfc8325 = [10, 16, 18, 24, 30, 40, 44, 48].map(|d| classify8021d(&dscp(d), None));
        assert_eq!(rfc8325, [0, 0, 3, 4, 4, 5, 6, 7]);
        // A tagged frame's PCP, or its inner protocol when the PCP is zero.
        let mut tagged = frame(0x8100, &[0x60, 0, 0x08, 0]);
        tagged.extend_from_slice(&ipv4);
        assert_eq!(classify8021d(&tagged, None), 3);
        tagged[14] = 0;
        assert_eq!(classify8021d(&tagged, None), 6);
        // A QoS Map's exception, then its ranges, then RFC 8325.
        let mut set = vec![46, 5];
        for up in 0..8u8 {
            set.extend_from_slice(&[up * 8, up * 8 + 3]);
        }
        let map = QosMap::parse(&set).unwrap();
        let mapped = [46, 18, 7].map(|d| classify8021d(&dscp(d), Some(&map)));
        assert_eq!(mapped, [5, 2, 0]);
        assert!(QosMap::parse(&set[1..]).is_err());
        set[1] = 8;
        assert!(QosMap::parse(&set).is_err());
    }

    #[test]
    #[ignore = "requires fresh pinned full A-MSDU helper trace via STELA_WIFI_AMSDU_ORACLE"]
    fn full_source_amsdu_station_conversion_matches_all_bytes() {
        extern crate std;
        let path =
            std::env::var_os("STELA_WIFI_AMSDU_ORACLE").expect("fresh unchanged Linux trace");
        let trace = std::fs::read(path).unwrap();
        let mut bytes = trace.as_slice();
        fn take_u32(bytes: &mut &[u8]) -> usize {
            let value = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
            *bytes = &bytes[4..];
            value
        }
        for case in 0..512 {
            let length = take_u32(&mut bytes);
            let input = &bytes[..length];
            bytes = &bytes[length..];
            let count = take_u32(&mut bytes);
            let mut expected = Vec::new();
            for _ in 0..count {
                let length = take_u32(&mut bytes);
                expected.push(bytes[..length].to_vec());
                bytes = &bytes[length..];
            }
            match subframes(input, Mac([2, 1, 2, 3, 4, 5]), false) {
                Ok(actual) => assert_eq!(actual, expected, "full source case{case}"),
                Err(_) => assert!(expected.is_empty(), "source forwarded refused case{case}"),
            }
        }
        assert!(bytes.is_empty());
    }
    use crate::net::wifi::{
        Band, RadioStatus, RawRate,
        security::{Cipher, InstallOutcome, Integrity, ReplaySeed, SecurityStatus, TransmitSeed},
        station::{Join, wire::AssociationRequest},
    };

    const LOCAL: Mac = Mac([2, 1, 2, 3, 4, 5]);
    const AP: Mac = Mac([2, 6, 7, 8, 9, 10]);
    const SOURCE: Mac = Mac([4, 1, 2, 3, 4, 5]);
    struct Policy(bool);
    impl RegulatoryPolicy for Policy {
        fn allow_management_tx(&mut self, _: Channel) -> bool {
            self.0
        }
        fn allow_data_tx(&mut self, _: Channel) -> bool {
            self.0
        }
    }

    fn key(slot: u16, scope: KeyScope, seed: TransmitSeed) -> KeySlot {
        // Pure model has no physical slots, DMA, or deferred users.
        let mut result = unsafe { KeySlot::new(slot).unwrap() };
        let index = if matches!(scope, KeyScope::Pairwise(_)) {
            0
        } else {
            2
        };
        let ticket = result
            .begin_install(
                index,
                Cipher::Ccmp128,
                &[slot as u8; 16],
                ReplaySeed::ZERO,
                scope,
                seed,
            )
            .unwrap();
        result
            .complete_install(ticket, InstallOutcome::Accepted)
            .unwrap();
        result
    }

    fn station(policy: PortPolicy, host: bool) -> (Station, Vec<KeySlot>) {
        // The full association/actual-ACK transition is covered by parent tests;
        // these fixtures start at its established input boundary.
        let mut elements = vec![0, 1, b'x', 1, 1, 0x8c];
        if policy == PortPolicy::Controlled {
            elements.extend_from_slice(&[
                48, 18, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2,
            ]);
        }
        let mut station = Station::new(LOCAL).unwrap();
        station.phase = Phase::Associated;
        station.epoch = 42;
        station.join = Some(Join {
            bssid: AP,
            channel: Channel {
                band: Band::Ghz5,
                number: 36,
                frequency_mhz: 5180,
            },
            policy,
            request: AssociationRequest::new(
                if policy == PortPolicy::Open { 1 } else { 0x11 },
                10,
                elements,
            )
            .unwrap(),
        });
        let seed = if host {
            TransmitSeed::host(PacketNumber::new(0).unwrap())
        } else {
            TransmitSeed::FIRMWARE_FRESH
        };
        let keys = vec![
            key(1, KeyScope::Pairwise(AP), seed),
            key(2, KeyScope::Group(AP), TransmitSeed::RECEIVE_ONLY),
        ];
        (station, keys)
    }

    fn packet(destination: Mac, protocol: u16, security: SecurityStatus) -> Mpdu {
        let mut bytes = vec![0; 24];
        bytes[..2].copy_from_slice(
            &(if security.key.is_some() {
                0x4208_u16
            } else {
                0x0208_u16
            })
            .to_le_bytes(),
        );
        bytes[4..10].copy_from_slice(&destination.0);
        bytes[10..16].copy_from_slice(&AP.0);
        bytes[16..22].copy_from_slice(&SOURCE.0);
        bytes.extend_from_slice(&RFC1042);
        bytes.extend_from_slice(&protocol.to_be_bytes());
        bytes.extend_from_slice(&[1, 2, 3]);
        Mpdu::new(
            bytes,
            RadioStatus {
                band: Band::Ghz5,
                channel: 36,
                frequency_mhz: 5180,
                signal_dbm: Some(-40),
                chain_signal_dbm: [None; 4],
                rate: RawRate {
                    layout: 1,
                    words: [0; 4],
                },
                rx_rate: None,
                tsf: None,
            },
            security,
        )
        .unwrap()
    }

    fn protected(key: KeyIdentity, pn: u64) -> SecurityStatus {
        SecurityStatus {
            key: Some(key),
            pn: PacketNumber::new(pn),
            decrypted: true,
            integrity: Integrity::Verified,
            iv_stripped: true,
            mic_stripped: true,
            ..SecurityStatus::default()
        }
    }

    fn eth(destination: Mac, protocol: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&destination.0);
        bytes.extend_from_slice(&LOCAL.0);
        bytes.extend_from_slice(&protocol.to_be_bytes());
        bytes.extend_from_slice(&[1, 2, 3]);
        bytes
    }

    #[test]
    fn separately_boxed_keys_keep_exact_original_replay_and_publication_guards() {
        use alloc::boxed::Box;
        let (mut station, mut original) = station(PortPolicy::Controlled, false);
        let mut gtk = Box::new(original.pop().unwrap());
        let mut ptk = Box::new(original.pop().unwrap());
        let mut unrelated = Box::new(key(9, KeyScope::Group(AP), TransmitSeed::RECEIVE_ONLY));
        let ptk_id = ptk.installed().unwrap();
        let gtk_id = gtk.installed().unwrap();
        station.authorize_port(42, &ptk, &gtk).unwrap();
        let plan = station
            .prepare_msdu_refs(
                42,
                &eth(SOURCE, 0x0800),
                TxClass::Data,
                SequenceOwner::Device,
                &mut [&mut *gtk, &mut *ptk, &mut *unrelated],
                &mut Policy(true),
            )
            .unwrap();
        assert_eq!(plan.protection(), Protection::Firmware { key: ptk_id });
        station
            .validate_tx_plan_refs(&plan, &[&*unrelated, &*ptk, &*gtk], &mut Policy(true))
            .unwrap();
        assert_eq!(
            station.validate_tx_plan_refs(&plan, &[&*ptk], &mut Policy(true)),
            Err(Error::ClosedPort)
        );
        assert_eq!(
            station.validate_tx_plan_refs(&plan, &[&*ptk, &*gtk], &mut Policy(false)),
            Err(Error::Regulatory)
        );
        let pair = packet(LOCAL, 0x0800, protected(ptk_id, 7));
        assert!(matches!(
            station.receive_msdu_refs(41, &pair, &mut [&mut *ptk, &mut *gtk]),
            Err(Error::Stale)
        ));
        assert!(matches!(
            station.receive_msdu_refs(42, &pair, &mut [&mut *gtk, &mut *unrelated, &mut *ptk]),
            Ok(Ingress::Data(_))
        ));
        // The same original owner observes replay even outside the borrowed array.
        assert!(matches!(ptk.authorize(&pair), Err(security::Error::Replay)));
        let group = packet(Mac::BROADCAST, 0x0800, protected(gtk_id, 7));
        assert!(matches!(
            station.receive_msdu_refs(42, &group, &mut [&mut *ptk, &mut *gtk]),
            Ok(Ingress::Data(_))
        ));
        assert!(matches!(
            gtk.authorize(&group),
            Err(security::Error::Replay)
        ));
        // Unrelated same-scope slots do not acquire another slot's replay state.
        let foreign = packet(
            Mac::BROADCAST,
            0x0800,
            protected(unrelated.installed().unwrap(), 7),
        );
        assert!(unrelated.authorize(&foreign).is_ok());
        ptk.invalidate();
        assert_eq!(
            station.validate_tx_plan_refs(&plan, &[&*ptk, &*gtk], &mut Policy(true)),
            Err(Error::ClosedPort)
        );
        assert!(matches!(
            station.receive_msdu_refs(42, &pair, &mut [&mut *ptk, &mut *gtk]),
            Err(Error::WrongKey)
        ));
    }

    #[test]
    fn open_data_bridge_uses_real_station_addresses_and_rfc1042() {
        let (station, mut keys) = station(PortPolicy::Open, false);
        let Ingress::Data(bytes) = station
            .receive_msdu(
                42,
                &packet(LOCAL, 0x0800, SecurityStatus::default()),
                &mut keys,
            )
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(&bytes[..6], LOCAL.0);
        assert_eq!(&bytes[6..12], SOURCE.0);
        assert_eq!(&bytes[12..], &[8, 0, 1, 2, 3]);
    }

    #[test]
    fn closed_port_routes_only_eapol_to_the_real_authentication_owner() {
        let (station, mut keys) = station(PortPolicy::Controlled, false);
        assert!(matches!(
            station.receive_msdu(
                42,
                &packet(LOCAL, 0x0800, SecurityStatus::default()),
                &mut keys
            ),
            Err(Error::ClosedPort)
        ));
        for destination in [LOCAL, PAE_GROUP] {
            assert!(matches!(
                station.receive_msdu(
                    42,
                    &packet(destination, EAPOL, SecurityStatus::default()),
                    &mut keys
                ),
                Ok(Ingress::ControlPort {
                    encrypted: false,
                    key: None,
                    ..
                })
            ));
        }
        assert!(matches!(
            station.receive_msdu(
                42,
                &packet(Mac::BROADCAST, EAPOL, SecurityStatus::default()),
                &mut keys
            ),
            Err(Error::WrongPeer)
        ));
    }

    #[test]
    fn authenticated_key_does_not_implicitly_authorize_data_but_allows_eapol() {
        let (mut station, mut keys) = station(PortPolicy::Controlled, false);
        let ptk = keys[0].installed().unwrap();
        assert!(matches!(
            station.receive_msdu(42, &packet(LOCAL, EAPOL, protected(ptk, 1)), &mut keys),
            Ok(Ingress::ControlPort {
                encrypted: true,
                key: Some(_),
                ..
            })
        ));
        assert!(matches!(
            station.receive_msdu(42, &packet(LOCAL, 0x0800, protected(ptk, 2)), &mut keys),
            Err(Error::ClosedPort)
        ));
        station.authorize_port(42, &keys[0], &keys[1]).unwrap();
        assert!(matches!(
            station.receive_msdu(42, &packet(LOCAL, 0x0800, protected(ptk, 3)), &mut keys),
            Ok(Ingress::Data(_))
        ));
        assert!(matches!(
            station.receive_msdu(42, &packet(LOCAL, 0x0800, protected(ptk, 3)), &mut keys),
            Err(Error::Crypto(security::Error::Replay))
        ));
        assert!(matches!(
            station.receive_msdu(
                42,
                &packet(LOCAL, 0x0800, SecurityStatus::default()),
                &mut keys
            ),
            Err(Error::Unencrypted)
        ));
    }

    #[test]
    fn group_and_pairwise_scope_and_current_key_generation_are_not_interchangeable() {
        let (mut station, mut keys) = station(PortPolicy::Controlled, false);
        let ptk = keys[0].installed().unwrap();
        let gtk = keys[1].installed().unwrap();
        station.authorize_port(42, &keys[0], &keys[1]).unwrap();
        assert!(matches!(
            station.receive_msdu(
                42,
                &packet(Mac::BROADCAST, 0x0800, protected(ptk, 1)),
                &mut keys
            ),
            Err(Error::WrongKey)
        ));
        assert!(matches!(
            station.receive_msdu(
                42,
                &packet(Mac::BROADCAST, 0x0800, protected(gtk, 1)),
                &mut keys
            ),
            Ok(Ingress::Data(_))
        ));
        keys[0].invalidate();
        assert!(matches!(
            station.receive_msdu(42, &packet(LOCAL, 0x0800, protected(ptk, 2)), &mut keys),
            Err(Error::WrongKey)
        ));
    }

    #[test]
    fn stale_channel_integrity_and_aggregate_failures_do_not_advance_replay() {
        let (mut station, mut keys) = station(PortPolicy::Controlled, false);
        station.authorize_port(42, &keys[0], &keys[1]).unwrap();
        let key = keys[0].installed().unwrap();
        let packet = packet(LOCAL, 0x0800, protected(key, 1));
        assert!(matches!(
            station.receive_msdu(41, &packet, &mut keys),
            Err(Error::Stale)
        ));
        let mut altered = packet.clone();
        altered.radio.channel = 40;
        assert!(matches!(
            station.receive_msdu(42, &altered, &mut keys),
            Err(Error::WrongChannel)
        ));
        altered = packet.clone();
        altered.fcs_error = true;
        assert!(matches!(
            station.receive_msdu(42, &altered, &mut keys),
            Err(Error::Integrity)
        ));
        altered = packet.clone();
        altered.aggregation.ampdu = Some(1);
        assert!(matches!(
            station.receive_msdu(42, &altered, &mut keys),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            station.receive_msdu(42, &packet, &mut keys),
            Ok(Ingress::Data(_))
        ));
    }

    #[test]
    fn host_iv_plan_reserves_pn_and_keeps_cipher_mic_as_explicit_hardware_work() {
        let (mut station, mut keys) = station(PortPolicy::Controlled, true);
        station.authorize_port(42, &keys[0], &keys[1]).unwrap();
        let key = keys[0].installed().unwrap();
        let first = station
            .prepare_msdu(
                42,
                &eth(SOURCE, 0x0800),
                TxClass::Data,
                SequenceOwner::Host,
                &mut keys,
                &mut Policy(true),
            )
            .unwrap();
        assert_eq!(
            first.protection(),
            Protection::HostIv {
                key,
                pn: PacketNumber::new(1).unwrap()
            }
        );
        assert_eq!(
            &first.plaintext_mpdu()[24..32],
            &[1, 0, 0, 0x20, 0, 0, 0, 0]
        );
        assert_eq!(
            &first.plaintext_mpdu()[32..],
            &[0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 1, 2, 3]
        );
        let next = station
            .prepare_msdu(
                42,
                &eth(SOURCE, 0x0800),
                TxClass::Data,
                SequenceOwner::Host,
                &mut keys,
                &mut Policy(true),
            )
            .unwrap();
        assert!(matches!(next.protection(),Protection::HostIv{pn,..} if pn.value()==2));
    }

    #[test]
    fn firmware_crypto_has_no_host_iv_and_eapol_policy_cannot_leak_data() {
        let (mut station, mut keys) = station(PortPolicy::Controlled, false);
        let key = keys[0].installed().unwrap();
        assert!(matches!(
            station.prepare_msdu(
                42,
                &eth(SOURCE, 0x0800),
                TxClass::Data,
                SequenceOwner::Host,
                &mut keys,
                &mut Policy(true)
            ),
            Err(Error::ClosedPort)
        ));
        let eapol = station
            .prepare_msdu(
                42,
                &eth(AP, EAPOL),
                TxClass::ControlPortProtected(key),
                SequenceOwner::Host,
                &mut keys,
                &mut Policy(true),
            )
            .unwrap();
        assert_eq!(eapol.protection(), Protection::Firmware { key });
        assert!(eapol.control_port());
        assert_eq!(
            &eapol.plaintext_mpdu()[24..],
            &[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e, 1, 2, 3]
        );
        assert!(matches!(
            station.prepare_msdu(
                42,
                &eth(AP, 0x0800),
                TxClass::ControlPortPlaintext,
                SequenceOwner::Host,
                &mut keys,
                &mut Policy(true)
            ),
            Err(Error::WrongPeer)
        ));
        assert!(matches!(
            station.prepare_msdu(
                42,
                &eth(AP, EAPOL),
                TxClass::Data,
                SequenceOwner::Host,
                &mut keys,
                &mut Policy(true)
            ),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn regulatory_denial_does_not_reserve_nonce_and_host_generation_is_rechecked() {
        let (mut station, mut keys) = station(PortPolicy::Controlled, true);
        station.authorize_port(42, &keys[0], &keys[1]).unwrap();
        let key = keys[0].installed().unwrap();
        assert!(matches!(
            station.prepare_msdu(
                42,
                &eth(SOURCE, 0x0800),
                TxClass::Data,
                SequenceOwner::Host,
                &mut keys,
                &mut Policy(false)
            ),
            Err(Error::Regulatory)
        ));
        assert_eq!(keys[0].host_tx_counter(key).unwrap().value(), 0);
        keys[0].invalidate();
        assert!(matches!(
            station.prepare_msdu(
                42,
                &eth(SOURCE, 0x0800),
                TxClass::Data,
                SequenceOwner::Host,
                &mut keys,
                &mut Policy(true)
            ),
            Err(Error::ClosedPort)
        ));
    }

    #[test]
    fn rfc1042_aarp_ipx_exceptions_and_bridge_tunnel_match_linux() {
        for protocol in [0x0800, AARP, IPX] {
            let mut payload = RFC1042.to_vec();
            payload.extend_from_slice(&protocol.to_be_bytes());
            payload.extend_from_slice(&[1, 2, 3]);
            let output = ethernet(LOCAL, SOURCE, &payload).unwrap();
            if matches!(protocol, AARP | IPX) {
                assert_eq!(&output[12..14], &[0, 11]);
                assert_eq!(&output[14..], payload);
            } else {
                assert_eq!(&output[12..], &[8, 0, 1, 2, 3]);
            }
            payload[..6].copy_from_slice(&BRIDGE_TUNNEL);
            assert_eq!(
                &ethernet(LOCAL, SOURCE, &payload).unwrap()[12..14],
                &protocol.to_be_bytes()
            );
        }
    }

    #[test]
    fn all_protocol_conversions_match_unchanged_linux_sanitizer_oracle() {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        for prefix in [RFC1042, BRIDGE_TUNNEL, [0xab, 0xaa, 3, 0, 0, 0]] {
            for protocol in 0..=u16::MAX {
                let mut payload = prefix.to_vec();
                payload.extend_from_slice(&protocol.to_be_bytes());
                payload.extend_from_slice(&[1, 2, 3]);
                let converted = ethernet(LOCAL, SOURCE, &payload).unwrap();
                digest.update((converted.len() as u16).to_le_bytes());
                digest.update(&converted);
            }
        }
        // Reproduce using tests/reference/wifi_data_oracle.py: full unchanged
        // ieee80211_data_to_8023_exthdr and dependencies, ASan/UBSan, 196608 PDUs.
        assert_eq!(
            <[u8; 32]>::from(digest.finalize()),
            [
                0xa5, 0x09, 0x08, 0x95, 0xf7, 0x0e, 0x3a, 0x9f, 0xb0, 0x62, 0x3d, 0x1f, 0x6d, 0x04,
                0xa9, 0x2a, 0xbf, 0xe0, 0xf3, 0xd8, 0x04, 0xf3, 0xdf, 0x42, 0xd4, 0x19, 0xd0, 0x3e,
                0x29, 0xa4, 0x76, 0xe8,
            ]
        );
    }

    #[test]
    fn short_llc_and_exact_mtu_bounds_are_preserved() {
        for length in 0..8 {
            let payload = &RFC1042.repeat(2)[..length];
            let converted = ethernet(LOCAL, SOURCE, payload).unwrap();
            assert_eq!(&converted[12..14], &(length as u16).to_be_bytes());
            assert_eq!(&converted[14..], payload);
        }
        let mut payload = RFC1042.to_vec();
        payload.extend_from_slice(&[8, 0]);
        payload.extend_from_slice(&vec![0x5a; MAX_FRAME - 14]);
        let converted = ethernet(LOCAL, SOURCE, &payload).unwrap();
        assert_eq!(converted.len(), MAX_FRAME);
        assert_eq!(msdu(&converted).unwrap().3, payload);
        payload.push(0);
        assert_eq!(
            ethernet(LOCAL, SOURCE, &payload),
            Err(Error::InvalidEthernet)
        );
        assert_eq!(msdu(&converted[..13]), Err(Error::InvalidEthernet));
        assert_eq!(msdu(&vec![0; MAX_FRAME + 1]), Err(Error::InvalidEthernet));
        let mut invalid_length = eth(SOURCE, 4);
        assert_eq!(msdu(&invalid_length), Err(Error::InvalidEthernet));
        invalid_length[12..14].copy_from_slice(&3_u16.to_be_bytes());
        assert_eq!(msdu(&invalid_length).unwrap().3, [1, 2, 3]);
    }

    #[test]
    fn queued_plan_permission_is_revoked_by_port_epoch_key_or_policy_change() {
        let (mut station, mut keys) = station(PortPolicy::Controlled, true);
        station.authorize_port(42, &keys[0], &keys[1]).unwrap();
        let plan = station
            .prepare_msdu(
                42,
                &eth(SOURCE, 0x0800),
                TxClass::Data,
                SequenceOwner::Host,
                &mut keys,
                &mut Policy(true),
            )
            .unwrap();
        station
            .validate_tx_plan(&plan, &keys, &mut Policy(true))
            .unwrap();
        assert_eq!(
            station.validate_tx_plan(&plan, &keys, &mut Policy(false)),
            Err(Error::Regulatory)
        );
        station.close_port();
        assert_eq!(
            station.validate_tx_plan(&plan, &keys, &mut Policy(true)),
            Err(Error::ClosedPort)
        );
        station.authorize_port(42, &keys[0], &keys[1]).unwrap();
        station.epoch = 43;
        assert_eq!(
            station.validate_tx_plan(&plan, &keys, &mut Policy(true)),
            Err(Error::Stale)
        );
        station.epoch = 42;
        keys[0].invalidate();
        assert_eq!(
            station.validate_tx_plan(&plan, &keys, &mut Policy(true)),
            Err(Error::ClosedPort)
        );
    }

    #[test]
    fn protected_eapol_plan_cannot_outlive_its_acknowledged_key() {
        let (mut station, mut keys) = station(PortPolicy::Controlled, false);
        let key = keys[0].installed().unwrap();
        let plan = station
            .prepare_msdu(
                42,
                &eth(AP, EAPOL),
                TxClass::ControlPortProtected(key),
                SequenceOwner::Host,
                &mut keys,
                &mut Policy(true),
            )
            .unwrap();
        station
            .validate_tx_plan(&plan, &keys, &mut Policy(true))
            .unwrap();
        keys[0].invalidate();
        assert_eq!(
            station.validate_tx_plan(&plan, &keys, &mut Policy(true)),
            Err(Error::WrongKey)
        );
        assert!(matches!(
            station.prepare_msdu(
                42,
                &eth(AP, EAPOL),
                TxClass::ControlPortProtected(key),
                SequenceOwner::Host,
                &mut keys,
                &mut Policy(true)
            ),
            Err(Error::WrongKey)
        ));
    }

    #[test]
    fn eapol_cannot_bypass_negotiated_cipher_or_unsupported_pairwise_key_id() {
        for (index, cipher) in [(1, Cipher::Ccmp128), (0, Cipher::Gcmp128)] {
            let (mut station, mut keys) = station(PortPolicy::Controlled, true);
            // Isolated model; this synthetic physical slot has no DMA/work users.
            let mut alternate = unsafe { KeySlot::new(34).unwrap() };
            let ticket = alternate
                .begin_install(
                    index,
                    cipher,
                    &[0x5a; 16],
                    ReplaySeed::ZERO,
                    KeyScope::Pairwise(AP),
                    TransmitSeed::host(PacketNumber::new(0).unwrap()),
                )
                .unwrap();
            alternate
                .complete_install(ticket, InstallOutcome::Accepted)
                .unwrap();
            keys[0] = alternate;
            let key = keys[0].installed().unwrap();
            assert!(matches!(
                station.receive_msdu(42, &packet(LOCAL, EAPOL, protected(key, 1)), &mut keys),
                Err(Error::Unsupported(_)) | Err(Error::WrongKey)
            ));
            assert!(matches!(
                station.prepare_msdu(
                    42,
                    &eth(AP, EAPOL),
                    TxClass::ControlPortProtected(key),
                    SequenceOwner::Host,
                    &mut keys,
                    &mut Policy(true)
                ),
                Err(Error::Unsupported(_)) | Err(Error::WrongKey)
            ));
            assert_eq!(keys[0].host_tx_counter(key).unwrap().value(), 0);
        }
    }

    #[test]
    fn foreign_ap_receiver_fragment_and_monitor_frames_cannot_poison_replay() {
        let (mut station, mut keys) = station(PortPolicy::Controlled, false);
        station.authorize_port(42, &keys[0], &keys[1]).unwrap();
        let key = keys[0].installed().unwrap();
        let valid = packet(LOCAL, 0x0800, protected(key, 1));
        for variant in 0..5 {
            let mut bytes = valid.bytes().to_vec();
            match variant {
                0 => bytes[10] ^= 4, // actual AP transmitter mismatch
                1 => bytes[4] ^= 4,  // foreign unicast receiver
                2 => bytes[1] |= 4,  // more fragments
                3 => bytes[22] |= 1, // nonzero fragment number
                _ => {}
            }
            let mut invalid = Mpdu::new(bytes, valid.radio.clone(), valid.security).unwrap();
            invalid.monitor_only = variant == 4;
            assert!(station.receive_msdu(42, &invalid, &mut keys).is_err());
        }
        assert!(matches!(
            station.receive_msdu(42, &valid, &mut keys),
            Ok(Ingress::Data(_))
        ));
    }

    #[test]
    fn host_and_device_sequence_ownership_are_explicit_and_independent_of_air_status() {
        let (mut station, mut keys) = station(PortPolicy::Open, false);
        station.sequence = 0xfff;
        for (owner, expected, bytes) in [
            (
                SequenceOwner::Host,
                SequenceAssignment::Host(0xfff),
                [0xf0, 0xff],
            ),
            (SequenceOwner::Device, SequenceAssignment::Device, [0, 0]),
            (SequenceOwner::Host, SequenceAssignment::Host(0), [0, 0]),
        ] {
            let plan = station
                .prepare_msdu(
                    42,
                    &eth(SOURCE, 0x0800),
                    TxClass::Data,
                    owner,
                    &mut keys,
                    &mut Policy(true),
                )
                .unwrap();
            assert_eq!(plan.sequence(), expected);
            assert_eq!(&plan.plaintext_mpdu()[22..24], bytes);
            assert_eq!(plan.into_parts().4, expected);
        }
        assert_eq!(station.sequence, 1);
    }
}
