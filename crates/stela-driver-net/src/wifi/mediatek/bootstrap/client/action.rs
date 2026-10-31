// SPDX-License-Identifier: GPL-2.0-only
// The action frame handling follows pinned Linux mac80211/rx.c and
// spectmgmt.c.
//! Unprotected action frames of the current association that neither block
//! ack nor a channel switch took. As mac80211's `ieee80211_rx_h_action`, the
//! station consumes the ones it implements; frames an OS registration matches
//! reach the OS (`cfg80211_rx_mgmt`); an SA Query request is answered
//! (`ieee80211_process_sa_query_req`); and any other unicast one goes back to
//! its sender with the category's 0x80 bit set (`ieee80211_rx_h_action_return`).
use super::*;

const SPECTRUM_MANAGEMENT: u8 = 0;
const BLOCK_ACK: u8 = 3;
const PUBLIC: u8 = 4;
const SA_QUERY: u8 = 8;
const PROTECTED_DUAL: u8 = 9;
const HT: u8 = 7;
const SELF_PROTECTED: u8 = 15;
const VHT: u8 = 21;
const PROTECTED_EHT: u8 = 37;
/// `IEEE80211_MIN_ACTION_SIZE(action_code)`.
const CODED: usize = 26;
/// Replies waiting for transmission; a reply beyond them is dropped, as an
/// skb that fails to allocate is.
const REPLIES: usize = 8;
/// OS frame registrations, as `cfg80211_mgmt_registrations` holds them.
const REGISTRATIONS: usize = 32;

#[derive(Default)]
pub(super) struct State {
    registrations: Vec<Vec<u8>>,
    pub(super) replies: VecDeque<Vec<u8>>,
}

/// What the receive path does with an action frame.
pub(super) enum Receive {
    /// A Block Ack action for the station's block-ack owner.
    BlockAck,
    /// Deliver the native frame to the OS.
    Os,
    /// Consumed.
    Done,
}

/// `ieee80211_rx_h_action`'s verdict for a station.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kernel {
    BlockAck,
    /// Handled in the kernel; mt7925 has no `sta_rc_update`, so the AP's
    /// operating mode changes no firmware state.
    Handled,
    /// Handled, and mac80211 reports it (`cfg80211_sta_opmode_change_notify`).
    Notify,
    /// A spectrum measurement request, refused as
    /// `ieee80211_process_measurement_req` does.
    Measurement,
    /// `IEEE80211_RX_MALFORMED_ACTION_FRM`: never offered to the OS.
    Invalid,
    Continue,
}

/// `ieee80211_rx_h_action` for a station frame from the current AP, or a
/// public, self-protected or spectrum management action from another sender;
/// `ap` and `bssid` say whether the AP sent it within its BSS.
fn kernel(
    frame: &[u8],
    ap: bool,
    bssid: bool,
    five_ghz: bool,
    ht: Option<u16>,
    he: bool,
) -> Kernel {
    use Kernel::*;
    let len = frame.len();
    let code = frame.get(25).copied();
    match frame[24] {
        HT => {
            if (ht.is_none() && !he) || len < CODED + 1 {
                return Invalid;
            }
            match code {
                // An AP's SM power save only matters to an AP.
                Some(1) => Handled,
                // Notify Channel Width, 20 or any.
                Some(0) if frame[26] > 1 => Invalid,
                Some(0) if ht.is_some_and(|cap| cap & 0x0002 != 0) => Notify,
                Some(0) => Handled,
                _ => Invalid,
            }
        }
        PUBLIC | PROTECTED_DUAL if len < CODED => Invalid,
        // A short Extended Channel Switch Announcement from the AP.
        PUBLIC | PROTECTED_DUAL if ap && bssid && code == Some(4) && len < CODED + 4 => Invalid,
        VHT if len < CODED => Invalid,
        VHT => match code {
            // Operating Mode Notification.
            Some(2) if len < CODED + 1 => Invalid,
            Some(2) => Notify,
            // Group ID Management: mt7925 is no MU-MIMO group owner.
            Some(1) if len < CODED + 24 => Invalid,
            Some(1) => Handled,
            _ => Continue,
        },
        BLOCK_ACK if len < CODED => Continue,
        BLOCK_ACK => match code {
            Some(0 | 1) if len >= CODED + 7 => BlockAck,
            Some(2) if len >= CODED + 4 => BlockAck,
            _ => Invalid,
        },
        SPECTRUM_MANAGEMENT if code == Some(0) && five_ghz && len >= CODED + 6 => Measurement,
        SELF_PROTECTED if len < CODED => Continue,
        // Mesh peering and group key actions reach only a mesh point.
        SELF_PROTECTED if matches!(code, Some(1..=5)) => Invalid,
        // TTLM, EPCS and link reconfiguration need a multi-link station,
        // which this one never is; each handler then returns.
        PROTECTED_EHT if len < CODED => Continue,
        PROTECTED_EHT => match code {
            Some(0) if len < CODED + 1 => Invalid,
            Some(1) if len < CODED + 3 => Invalid,
            Some(4) if len < CODED + 3 => Invalid,
            Some(12) if len < CODED + 2 + 3 => Invalid,
            Some(0 | 1 | 2 | 4 | 5 | 12) => Handled,
            _ => Continue,
        },
        _ => Continue,
    }
}

impl<I: BarIo, Q: QueueIo, C: 'static> Client<I, Q, C> {
    /// Offer the OS action frames whose body starts with `prefix`, as
    /// `NL80211_CMD_REGISTER_FRAME` does; registrations outlive associations.
    pub fn register_action(&mut self, prefix: &[u8]) -> Result<(), Error> {
        let action = &mut self.state_mut().action;
        if prefix.is_empty() {
            return Err(Error::Unsupported);
        }
        if action.registrations.iter().any(|r| r == prefix) {
            return Ok(());
        }
        if action.registrations.len() == REGISTRATIONS {
            return Err(Error::Busy);
        }
        let mut registration = Vec::new();
        registration
            .try_reserve_exact(prefix.len())
            .map_err(|_| Error::NoMemory)?;
        registration.extend_from_slice(prefix);
        action
            .registrations
            .try_reserve(1)
            .map_err(|_| Error::NoMemory)?;
        action.registrations.push(registration);
        Ok(())
    }

    /// Withdraw a registration made with `register_action`.
    pub fn unregister_action(&mut self, prefix: &[u8]) {
        self.state_mut()
            .action
            .registrations
            .retain(|r| r != prefix);
    }

    /// Whether a reply waits for `progress_action_replies`.
    pub fn pending_action_reply(&self) -> bool {
        !self.state().action.replies.is_empty()
    }

    /// The receive handlers from `ieee80211_rx_h_action` through
    /// `ieee80211_rx_h_action_return` for an unprotected action frame.
    pub(super) fn receive_action(s: &mut Owned<I, Q, C>, frame: &Mpdu) -> Result<Receive, Error> {
        let frame = Self::translated(s, frame);
        Self::receive_plain_action(s, &frame, frame.bytes())
    }

    /// `receive_action` for an action frame a PMF association authenticated,
    /// `body` being its decrypted body.
    pub(super) fn receive_protected_action(
        s: &mut Owned<I, Q, C>,
        frame: &Mpdu,
        body: &[u8],
    ) -> Result<Receive, Error> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(24 + body.len())
            .map_err(|_| Error::NoMemory)?;
        bytes.extend_from_slice(&frame.bytes()[..24]);
        bytes.extend_from_slice(body);
        Self::receive_plain_action(s, frame, &bytes)
    }

    fn receive_plain_action(
        s: &mut Owned<I, Q, C>,
        frame: &Mpdu,
        bytes: &[u8],
    ) -> Result<Receive, Error> {
        let p = s.profile.ok_or(Error::WrongProfile)?;
        let h = frame.header();
        // ieee80211_rx_h_mgmt_check drops a runt action.
        let Some(&category) = bytes.get(24) else {
            return Ok(Receive::Done);
        };
        let (local, peer) = Self::association_addresses(s, p);
        let group_link = h
            .receiver
            .is_multicast()
            .then(|| Self::other_link(s, &frame.radio))
            .flatten();
        let peer = if h.receiver.is_multicast() {
            group_link.unwrap_or(p).peer
        } else {
            peer
        };
        let ap = h.transmitter == Some(peer);
        if !ap && !matches!(category, SPECTRUM_MANAGEMENT | PUBLIC | SELF_PROTECTED) {
            return Ok(Receive::Done);
        }
        let context = match group_link {
            Some(profile) => {
                &s.links
                    .iter()
                    .find(|link| link.profile == profile)
                    .ok_or(Error::WrongProfile)?
                    .context
            }
            None => s.modern.as_ref().ok_or(Error::WrongPhase)?.context(),
        };
        let negotiated = context.negotiated();
        let verdict = kernel(
            bytes,
            ap,
            bytes.get(16..22) == Some(peer.0.as_slice()),
            frame.radio.band == wifi::Band::Ghz5,
            negotiated.ht.as_ref().map(|ht| ht.capability),
            negotiated.he.is_some(),
        );
        // An OS management session without PMF owns protected management
        // beyond block ack and its own SA Queries. A PMF association's
        // replies are the station's own, protected when robust.
        let protect = s.management.is_some() && !s.station.requires_protected_management();
        match verdict {
            Kernel::BlockAck => return Ok(Receive::BlockAck),
            Kernel::Handled => return Ok(Receive::Done),
            Kernel::Notify => return Ok(Receive::Os),
            Kernel::Measurement if protect => return Ok(Receive::Os),
            Kernel::Measurement => {
                // ieee80211_send_refuse_measurement_request
                let mut reply = Vec::new();
                if reply.try_reserve_exact(CODED + 6).is_ok() {
                    reply.extend_from_slice(&[0xd0, 0, 0, 0]);
                    reply.extend_from_slice(&bytes[10..16]);
                    reply.extend_from_slice(&local.0);
                    reply.extend_from_slice(&bytes[16..22]);
                    reply.extend_from_slice(&[0, 0, SPECTRUM_MANAGEMENT, 2, bytes[26], 39, 3]);
                    reply.extend_from_slice(&[bytes[29], 1 << 2, bytes[31]]);
                    Self::queue_reply(s, reply);
                }
                return Ok(Receive::Done);
            }
            Kernel::Invalid | Kernel::Continue => {}
        }
        // ieee80211_rx_h_userspace_mgmt
        if verdict == Kernel::Continue
            && s.action
                .registrations
                .iter()
                .any(|r| bytes[24..].starts_with(r))
        {
            return Ok(Receive::Os);
        }
        // ieee80211_rx_h_action_post_userspace
        if category == SA_QUERY && bytes.get(25) == Some(&0) {
            if h.receiver == local
                && ap
                && bytes.get(16..22) == Some(peer.0.as_slice())
                && bytes.len() >= CODED + 2
            {
                if protect {
                    return Ok(Receive::Os);
                }
                let mut reply = Vec::new();
                if reply.try_reserve_exact(CODED + 2).is_ok() {
                    reply.extend_from_slice(&[0xd0, 0, 0, 0]);
                    reply.extend_from_slice(&peer.0);
                    reply.extend_from_slice(&local.0);
                    reply.extend_from_slice(&peer.0);
                    reply.extend_from_slice(&[0, 0, SA_QUERY, 1, bytes[26], bytes[27]]);
                    Self::queue_reply(s, reply);
                }
            }
            return Ok(Receive::Done);
        }
        // ieee80211_rx_h_action_return
        if h.receiver.is_multicast() || category & 0x80 != 0 {
            return Ok(Receive::Done);
        }
        if protect {
            return Ok(Receive::Os);
        }
        let mut reply = Vec::new();
        if reply.try_reserve_exact(bytes.len()).is_ok() {
            reply.extend_from_slice(bytes);
            reply[24] |= 0x80;
            reply.copy_within(10..16, 4);
            reply[10..16].copy_from_slice(&local.0);
            Self::queue_reply(s, reply);
        }
        Ok(Receive::Done)
    }

    fn queue_reply(s: &mut Owned<I, Q, C>, reply: Vec<u8>) {
        let replies = &mut s.action.replies;
        if replies.len() < REPLIES && replies.try_reserve(1).is_ok() {
            replies.push_back(reply);
        }
    }

    /// `ieee80211_tx_skb` for the oldest reply under the association's
    /// management admission: a robust reply on a PMF association is
    /// encrypted with its PTK, and one without keys yet is dropped, as
    /// `ieee80211_tx_h_select_key` drops it.
    ///
    /// # Safety
    /// As `progress_block_ack`.
    pub unsafe fn progress_action_reply<
        H: wifi::regulatory::HardwarePolicy,
        O: wifi::regulatory::OsPolicy,
    >(
        &mut self,
        authority: &mut wifi::regulatory::Owner<H, O>,
        admission: wifi::regulatory::AssociationAdmission,
        source: &dyn PageSource,
    ) -> Result<(), Error> {
        let s = self.state_mut();
        if s.phase != Phase::Associated {
            return Err(Error::WrongPhase);
        }
        let reply = s.action.replies.front().ok_or(Error::WrongPhase)?;
        let (bytes, prepared) = if s.station.requires_protected_management() {
            let robust = !matches!(reply[24], 4 | 7 | 11 | 15 | 20 | 21 | 22 | 127);
            let session = match (robust, s.management.clone()) {
                (true, None) => {
                    s.action.replies.pop_front();
                    return Ok(());
                }
                (_, session) => session.filter(|_| robust),
            };
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(reply.len())
                .map_err(|_| Error::NoMemory)?;
            bytes.extend_from_slice(reply);
            if session.is_some() {
                bytes[1] |= 0x40;
            }
            let (config, mut owner, grant) = Self::prepare_submission(
                s,
                &bytes,
                session.as_ref().map(|session| session.pairwise_key()),
                true,
                true,
            )?;
            owner.management = session;
            (bytes, (config, owner, grant))
        } else {
            let submission = Self::prepare_ba_submission(s, reply)?;
            (
                submission.bytes,
                (submission.config, submission.owner, submission.grant),
            )
        };
        let mut started = false;
        // SAFETY: covered by this function's own safety contract.
        let result = unsafe {
            authority.publish_association(
                admission,
                &s.station,
                wifi::regulatory::AssociationUse::Management,
                |_, _| {
                    started = true;
                    Self::publish_submission(&mut s.controller, source, &bytes, prepared)
                },
            )
        }
        .map_err(Error::Regulatory)?;
        let uncertain = s.controller.state().data_tx.as_ref().unwrap().is_poisoned();
        if started && (result.is_ok() || uncertain) {
            s.action.replies.pop_front();
        }
        if uncertain {
            s.phase = Phase::Quarantined;
        }
        result.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut frame = vec![0xd0, 0];
        frame.resize(24, 0);
        frame.extend_from_slice(body);
        frame
    }

    #[test]
    fn station_actions_take_mac80211s_verdicts() {
        use Kernel::*;
        let ht = Some(0x0002);
        let verdict = |body: &[u8]| kernel(&frame(body), true, true, true, ht, false);
        // Notify Channel Width to any width, a bad width and SM power save.
        assert!(verdict(&[HT, 0, 1]) == Notify);
        assert!(verdict(&[HT, 0, 2]) == Invalid);
        assert!(verdict(&[HT, 1, 0]) == Handled);
        assert!(kernel(&frame(&[HT, 0, 1]), true, true, true, None, false) == Invalid);
        assert!(kernel(&frame(&[HT, 0, 1]), true, true, true, Some(0), false) == Handled);
        // VHT Operating Mode Notification, and a short one.
        assert!(verdict(&[VHT, 2, 0]) == Notify);
        assert!(verdict(&[VHT, 2]) == Invalid);
        assert!(verdict(&[VHT, 9]) == Continue);
        // ADDBA request lengths and an unknown block ack code.
        assert!(verdict(&[BLOCK_ACK, 0, 0, 0, 0, 0, 0, 0, 0]) == BlockAck);
        assert!(verdict(&[BLOCK_ACK, 0, 0]) == Invalid);
        assert!(verdict(&[BLOCK_ACK, 7, 0, 0, 0, 0]) == Invalid);
        // A measurement request on 5 GHz only.
        let request = [SPECTRUM_MANAGEMENT, 0, 1, 38, 3, 1, 0, 0];
        assert!(verdict(&request) == Measurement);
        assert!(kernel(&frame(&request), true, true, false, ht, false) == Continue);
        assert!(verdict(&[SELF_PROTECTED, 1]) == Invalid);
        assert!(verdict(&[PUBLIC, 4, 0]) == Invalid);
        assert!(verdict(&[PUBLIC, 10, 0]) == Continue);
        assert!(verdict(&[PROTECTED_EHT, 2]) == Handled);
        assert!(verdict(&[PROTECTED_EHT, 1, 0]) == Invalid);
    }
}
