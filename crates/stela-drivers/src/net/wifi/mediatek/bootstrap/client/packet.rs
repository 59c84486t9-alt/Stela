// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Actual packet publication, RX interpretation and canonical key-state binding.
use super::*;

impl<I: BarIo, Q: QueueIo, C: 'static> Client<I, Q, C> {
    pub(super) fn submit(
        s: &mut Owned<I, Q, C>,
        bytes: &[u8],
        key: Option<KeyIdentity>,
        management: bool,
        minimum_rate: bool,
        source: &dyn PageSource,
    ) -> Result<Receipt, Error> {
        let prepared = Self::prepare_submission(s, bytes, key, management, minimum_rate)?;
        let result = Self::publish_submission(&mut s.controller, source, bytes, prepared);
        if matches!(result, Err(Error::GrantTimeout)) {
            // The actual peer and grant were already programmed. Retain the
            // complete owner even though this packet was never published.
            s.phase = Phase::Quarantined;
        }
        if s.controller.state().data_tx.as_ref().unwrap().is_poisoned() {
            s.phase = Phase::Quarantined;
        }
        result
    }
    pub(super) fn prepare_submission(
        s: &Owned<I, Q, C>,
        bytes: &[u8],
        key: Option<KeyIdentity>,
        management: bool,
        minimum_rate: bool,
    ) -> Result<(txwi::Config, PacketOwner<C>, Option<u64>), Error> {
        let p = s.profile.ok_or(Error::WrongPhase)?;
        if s.format_generation != Some(s.peer_generation) {
            return Err(Error::WrongPhase);
        }
        let h = Header::parse(bytes).map_err(Error::Frame)?;
        if h.fragmented() || h.amsdu || h.tid.is_some_and(|tid| tid >= 8) {
            return Err(Error::Unsupported);
        }
        if h.tid.is_some() && (s.phase != Phase::Associated || s.modern.is_none()) {
            return Err(Error::WrongPhase);
        }
        if let Some(m) = s.modern.as_ref() {
            s.station
                .validate_association_context(m.context())
                .map_err(Error::Station)?;
        }
        let epoch = s.station.association_epoch().ok_or(Error::WrongPhase)?;
        let index = if p.channel.band == wifi::Band::Ghz2 {
            14
        } else {
            18
        } + p.basic_rates.trailing_zeros() as u8;
        let config = txwi::Config {
            chip: Chip::Mt7925,
            wcid: p.wcid,
            vif: Some(txwi::Vif {
                omac: p.interface.omac_index,
                wmm: p.interface.wmm_index,
                band: p.interface.band_index,
                mld: false,
            }),
            phy_band_one: false,
            queue: if management {
                txwi::Queue::Management
            } else {
                txwi::Queue::Data {
                    access_category: h.tid.map_or(if minimum_rate { 0 } else { 2 }, |tid| {
                        [2, 3, 3, 2, 1, 1, 0, 0][usize::from(tid)]
                    }),
                }
            },
            pid: 0,
            frame: txwi::Frame {
                bytes: bytes.len(),
                header_bytes: h.length as u8,
                kind: if management {
                    txwi::Kind::Management
                } else {
                    txwi::Kind::Data
                },
                subtype: ((h.control >> 4) & 15) as u8,
                tid: h.tid.unwrap_or(0),
                multicast: h.receiver.is_multicast(),
                fragment: txwi::Fragment::None,
                sequence: txwi::Sequence::Hardware,
                minimum_rate,
            },
            protect: key.is_some(),
            no_ack: h.receiver.is_multicast(),
            hardware_amsdu: false,
            fixed_rate: if s.modern.is_some() && !management && !minimum_rate {
                None
            } else {
                Some(txwi::FixedRate::Connac3(index))
            },
        };
        let context = PacketOwner {
            resource: s.controller.state().resource.clone(),
            association: epoch,
            key,
            context: s.modern.as_ref().map(|m| m.context().clone()),
            tid: h.tid,
            tx_ba: None,
        };
        let grant = if management && s.phase == Phase::Joining {
            Some(s.roc_deadline.ok_or(Error::GrantTimeout)?)
        } else {
            None
        };
        Ok((config, context, grant))
    }
    pub(super) fn publish_submission(
        controller: &mut Controller<I, Q, C>,
        source: &dyn PageSource,
        bytes: &[u8],
        (config, context, grant): (txwi::Config, PacketOwner<C>, Option<u64>),
    ) -> Result<Receipt, Error> {
        let controller = controller.state_mut();
        let clock = controller.control.clock;
        controller
            .data_tx
            .as_mut()
            .unwrap()
            .submit_if(source, config, bytes, context, || {
                grant.is_none_or(|deadline| clock.now_us() < deadline)
            })
            .map_err(|e| {
                if e == data::Error::PublicationRefused {
                    Error::GrantTimeout
                } else {
                    Error::Ring(e)
                }
            })
    }
    pub fn transmit(
        &mut self,
        epoch: u64,
        ethernet: &[u8],
        class: TxClass,
        source: &dyn PageSource,
        policy: &mut impl station::RegulatoryPolicy,
    ) -> Result<Receipt, Error> {
        let s = self.state_mut();
        if s.phase != Phase::Associated {
            return Err(Error::WrongPhase);
        }
        if s.modern.is_some() {
            return Err(Error::ModernAdmissionRequired);
        }
        let ptk = s.ptk.as_mut().ok_or(Error::NoKey)?;
        let gtk = s.gtk.as_mut().ok_or(Error::NoKey)?;
        let mut keys = [ptk.slot_mut(), gtk.slot_mut()];
        let plan = s
            .station
            .prepare_msdu_refs(
                epoch,
                ethernet,
                class,
                SequenceOwner::Device,
                &mut keys,
                policy,
            )
            .map_err(Error::Data)?;
        s.station
            .validate_tx_plan_refs(&plan, &keys, policy)
            .map_err(Error::Data)?;
        let key = match plan.protection() {
            Protection::None => None,
            Protection::Firmware { key } => Some(key),
            Protection::HostIv { .. } => return Err(Error::Unsupported),
        };
        Self::submit(
            s,
            plan.plaintext_mpdu(),
            key,
            false,
            plan.control_port(),
            source,
        )
    }
    /// Native modern single-MSDU publication. Optional QoS TID uses the actual
    /// current WMM context and source queue mapping; firmware owns sequence,
    /// IV/PN/cipher and its qualified rate set. Receipt is not an air ACK.
    ///
    /// # Safety
    /// The exact same-controller/authority retention and revocation contract of
    /// `configure_modern` applies. Both real canonical guards stay held through
    /// actual DMA preparation and producer publication; the original key,
    /// context and radio-policy owners survive all hardware/deferred users.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn transmit_modern<
        H: wifi::regulatory::HardwarePolicy,
        O: wifi::regulatory::OsPolicy,
    >(
        &mut self,
        authority: &mut wifi::regulatory::Owner<H, O>,
        admission: wifi::regulatory::AssociationAdmission,
        epoch: u64,
        ethernet: &[u8],
        class: TxClass,
        tid: Option<u8>,
        source: &dyn PageSource,
        policy: &mut impl station::RegulatoryPolicy,
    ) -> Result<Receipt, Error> {
        let s = self.state_mut();
        if s.phase != Phase::Associated {
            return Err(Error::WrongPhase);
        }
        let context = s
            .modern
            .as_ref()
            .ok_or(Error::WrongPhase)?
            .context()
            .clone();
        let ptk = s.ptk.as_mut().ok_or(Error::NoKey)?;
        let gtk = s.gtk.as_mut().ok_or(Error::NoKey)?;
        let mut keys = [ptk.slot_mut(), gtk.slot_mut()];
        let plan = if let Some(tid) = tid {
            s.station
                .prepare_qos_msdu_refs(epoch, ethernet, class, &context, tid, &mut keys, policy)
        } else {
            s.station.prepare_msdu_refs(
                epoch,
                ethernet,
                class,
                SequenceOwner::Device,
                &mut keys,
                policy,
            )
        }
        .map_err(Error::Data)?;
        s.station
            .validate_tx_plan_refs(&plan, &keys, policy)
            .map_err(Error::Data)?;
        let key = match plan.protection() {
            Protection::None => None,
            Protection::Firmware { key } => Some(key),
            Protection::HostIv { .. } => return Err(Error::Unsupported),
        };
        let prepared =
            Self::prepare_submission(s, plan.plaintext_mpdu(), key, false, plan.control_port())?;
        let outcome = unsafe {
            authority.publish_association(
                admission,
                &s.station,
                wifi::regulatory::AssociationUse::Data,
                |_, _| {
                    Self::publish_submission(
                        &mut s.controller,
                        source,
                        plan.plaintext_mpdu(),
                        prepared,
                    )
                },
            )
        }
        .map_err(Error::Regulatory)?;
        if s.controller.state().data_tx.as_ref().unwrap().is_poisoned() {
            s.phase = Phase::Quarantined;
        }
        outcome
    }
    /// Observe actual source queue progress and free packets only after both
    /// descriptor consumption and matching exact-once hardware TX-free. The
    /// returned records do not synthesize an air ACK from DMA release.
    pub fn poll_released(&mut self) -> Result<Vec<Released<PacketOwner<C>>>, Error> {
        let s = self.state_mut();
        let q = s.controller.state_mut().data_tx.as_mut().unwrap();
        while q.poll_consumed().map_err(Error::Ring)?.is_some() {}
        let mut out = Vec::new();
        while let Some(r) = q.take_released().map_err(Error::Ring)? {
            out.push(r)
        }
        if s.phase == Phase::Removing && q.outstanding_tokens() == 0 && q.pending_descriptors() == 0
        {
            Self::remove(s, s.remove_ticket.ok_or(Error::WrongPhase)?)?;
        }
        Ok(out)
    }
    pub(super) fn normalized(
        s: &mut Owned<I, Q, C>,
        raw: &[u8],
        grouped: bool,
        policy: &mut impl scan::Policy,
    ) -> Result<Mpdu, Error> {
        let d = rx::decode(Chip::Mt7925, raw).map_err(Error::Rx)?;
        let band = match d.channel.band {
            rx::Band::Ghz2 => wifi::Band::Ghz2,
            rx::Band::Ghz5 => wifi::Band::Ghz5,
            rx::Band::Ghz6 => return Err(Error::Unsupported),
        };
        let channel = policy
            .lookup_channel(band, d.channel.number)
            .ok_or(Error::WrongProfile)?;
        if !policy.allow_receive(channel) {
            return Err(Error::WrongProfile);
        }
        let header = Header::parse(d.payload).map_err(Error::Frame)?;
        if d.fragment || (!grouped && (d.ampdu || d.amsdu.is_some())) {
            return Err(Error::Unsupported);
        }
        if header.data_present() {
            let p = s.profile.ok_or(Error::WrongProfile)?;
            // mt792x_rx_get_wcid first resolves actual raw peer WCID, then
            // maps a non-U2M frame through that peer's VIF to its BCMC slot.
            // A copied raw BCMC number is not a validated peer lookup.
            if d.wcid != p.wcid
                || d.unicast_to_me == header.receiver.is_multicast()
                || s.format_generation != Some(s.peer_generation)
            {
                return Err(Error::WrongProfile);
            }
        }
        let mut security = SecurityStatus::default();
        if header.protected() {
            if !matches!(s.phase, Phase::Associated)
                || s.format_generation != Some(s.peer_generation)
            {
                return Err(Error::WrongPhase);
            }
            let p = s.profile.ok_or(Error::WrongProfile)?;
            if channel != p.channel {
                return Err(Error::WrongProfile);
            }
            let owner = if header.receiver.is_multicast() {
                s.gtk.as_ref()
            } else {
                s.ptk.as_ref()
            }
            .ok_or(Error::NoKey)?;
            let key = owner.slot().installed().ok_or(Error::NoKey)?;
            // Trust comes from actual completed DMA + exact retained WCID/key
            // context. Raw security bits alone cannot manufacture generation.
            let effective_wcid = p
                .receive_slot(d.wcid, d.unicast_to_me)
                .ok_or(Error::WrongProfile)?;
            if effective_wcid != key.slot()
                || d.security.key_index != key.index()
                || d.security.mode
                    != match key.cipher() {
                        Cipher::Ccmp128 => 4,
                        Cipher::Ccmp256 => 10,
                        Cipher::Gcmp128 => 11,
                        Cipher::Gcmp256 => 12,
                    }
                || d.security.cipher_mismatch
                || d.security.cipher_length_mismatch
                || !d.security.decrypted
            {
                return Err(Error::WrongProfile);
            }
            let pn = match d.security.packet_number_be {
                Some(pn) => {
                    let value = pn
                        .into_iter()
                        .fold(0u64, |value, byte| (value << 8) | u64::from(byte));
                    PacketNumber::new(value)
                }
                None if grouped && d.amsdu.is_some_and(|a| !a.first) => None,
                None => return Err(Error::WrongProfile),
            };
            security = SecurityStatus {
                key: Some(key),
                pn,
                decrypted: true,
                integrity: if d.security.icv_error || d.security.tkip_mic_error {
                    Integrity::Failed
                } else {
                    Integrity::Verified
                },
                iv_stripped: d.security.iv_stripped,
                mic_stripped: d.security.mic_stripped,
                icv_error: d.security.icv_error,
                tkip_mic_error: d.security.tkip_mic_error,
                ..SecurityStatus::default()
            };
        }
        let mut frame = Mpdu::new(
            d.normalize(header.length).map_err(Error::Rx)?,
            wifi::RadioStatus {
                band,
                channel: channel.number,
                frequency_mhz: channel.frequency_mhz,
                signal_dbm: d
                    .signal
                    .and_then(|v| v.dbm.into_iter().filter(|v| *v < 0).max()),
                chain_signal_dbm: d.signal.map_or([None; 4], |v| {
                    v.dbm.map(|x| if x < 0 { Some(x) } else { None })
                }),
                rate: wifi::RawRate {
                    layout: 0x7925,
                    words: d.rxv.unwrap_or([0; 4]),
                },
                tsf: d.timestamp_low.map(wifi::Timestamp::Low32),
            },
            security,
        )
        .map_err(Error::Frame)?;
        frame.fcs_error = d.fcs_error;
        frame.monitor_only = d.only_monitor;
        frame.raw_status = d.base[..4].try_into().unwrap();
        if grouped {
            frame.aggregation.ampdu = if d.ampdu { d.timestamp_low } else { None };
            frame.aggregation.amsdu = d.amsdu.map(|a| wifi::Amsdu {
                index: 0,
                first: a.first,
                last: a.last,
            });
        }
        Ok(frame)
    }
}
