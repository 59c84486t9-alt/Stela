// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2025 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
//! Completed-RB to immutable raw-MPDU receipt composition. A receipt
//! records one real queue epoch; it is not association/key/replay permission or
//! a normalized OS frame. The missing platform/radio phase remains explicit.
use super::super::receive::mpdu::{self, Metadata};
use super::hcmd::{CapturedNotification, NotificationPoll};
use super::*;

pub enum MpduProgress {
    Pending,
    /// Unrelated traffic must be consumed by its real owner before another
    /// complete RB can fit. No packet or DMA ownership is silently dropped.
    Backpressure {
        notifications: usize,
    },
    Observed(ObservedMpdu),
    Rejected(RejectedMpdu),
}
pub struct ObservedMpdu {
    captured: CapturedNotification,
    metadata: Metadata,
    rate_format_2: bool,
    descriptor_bytes: usize,
    mpdu_bytes: usize,
}
/// Historical normalized bytes keep the receive epoch. They are not
/// rebound to a new association because a later caller has one.
pub struct NormalizedMpdu {
    _epoch: Arc<()>,
    normalized: mpdu::normalize::Normalized,
}
impl NormalizedMpdu {
    pub fn frame(&self) -> &crate::net::wifi::frame::Mpdu {
        &self.normalized.frame
    }
    pub fn crypto(&self) -> mpdu::normalize::Crypto {
        self.normalized.crypto
    }
    pub fn key_index(&self) -> Option<u8> {
        self.normalized.key_index
    }
}
impl ObservedMpdu {
    /// Normalize the immutable completed RX bytes using the kept
    /// firmware rate-layout decision. Key/integrity remain unchecked.
    pub fn normalize(&self) -> Result<NormalizedMpdu, mpdu::normalize::Error> {
        let normalized = mpdu::normalize::normalize(
            self.metadata,
            self.raw_mpdu(),
            self.packet_flags(),
            self.rate_format_2,
        )?;
        Ok(NormalizedMpdu {
            _epoch: self.captured.epoch.clone(),
            normalized,
        })
    }
    pub fn metadata(&self) -> Metadata {
        self.metadata
    }
    pub fn packet_flags(&self) -> u32 {
        u32::from_le_bytes(self.captured.bytes[..4].try_into().unwrap())
    }
    pub fn receive_queue(&self) -> u8 {
        ((self.packet_flags() >> 16) & 63) as u8
    }
    pub fn raw_packet(&self) -> &[u8] {
        &self.captured.bytes
    }
    pub fn descriptor(&self) -> &[u8] {
        &self.captured.bytes[8..8 + self.descriptor_bytes]
    }
    pub fn raw_mpdu(&self) -> &[u8] {
        let start = 8 + self.descriptor_bytes;
        &self.captured.bytes[start..start + self.mpdu_bytes]
    }
    pub fn trailing(&self) -> &[u8] {
        &self.captured.bytes[8 + self.descriptor_bytes + self.mpdu_bytes..]
    }
}
pub struct RejectedMpdu {
    captured: CapturedNotification,
    error: mpdu::Error,
}
impl RejectedMpdu {
    pub fn error(&self) -> mpdu::Error {
        self.error
    }
    pub fn raw_packet(&self) -> &[u8] {
        &self.captured.bytes
    }
}
impl<Q: BootIo> RomBoot<'_, Q> {
    pub(super) fn decode_captured_mpdu(
        &self,
        captured: CapturedNotification,
    ) -> Result<MpduProgress, Error> {
        if !self.hcmd.owns_capture(&captured) {
            return Err(Error::ReceiveEpoch);
        }
        match mpdu::Observation::parse_raw(&self.firmware, self.profile.family(), &captured.bytes) {
            Ok(observed) => {
                let metadata = observed.metadata();
                let descriptor_bytes = observed.descriptor().len();
                let mpdu_bytes = observed.raw_mpdu().len();
                Ok(MpduProgress::Observed(ObservedMpdu {
                    captured,
                    metadata,
                    rate_format_2: super::super::transmit::rate_format_2(
                        &self.firmware,
                        self.profile.family(),
                    )
                    .is_ok(),
                    descriptor_bytes,
                    mpdu_bytes,
                }))
            }
            Err(error) => Ok(MpduProgress::Rejected(RejectedMpdu { captured, error })),
        }
    }
}
impl<Q: BootIo> ColdRadio<'_, Q> {
    /// Poll raw observations from the owned initial queue 0. This can
    /// diagnose firmware traffic while PlatformConfigurationRequired remains
    /// unresolved; it does not advance that phase or authorize OS delivery.
    /// Completed bytes are captured before explicit pool rearm, so returned
    /// immutable receipts survive subsequent device writes to the same RB.
    pub fn poll_mpdu_observation(&mut self) -> Result<MpduProgress, Error> {
        if self.phase() != ColdRadioPhase::PlatformConfigurationRequired
            || self.initialized.boot.state != State::PnvmObserved
        {
            return Err(Error::State);
        }
        let boot = &mut self.initialized.boot;
        if let Some(captured) = boot.hcmd.take_matching(0xc1, 0) {
            return boot.decode_captured_mpdu(captured);
        }
        if matches!(
            boot.poll_one_notification_buffer()?,
            NotificationPoll::Backpressure
        ) {
            return Ok(MpduProgress::Backpressure {
                notifications: boot.hcmd.notification_count(),
            });
        }
        if let Some(captured) = boot.hcmd.take_matching(0xc1, 0) {
            boot.decode_captured_mpdu(captured)
        } else {
            Ok(MpduProgress::Pending)
        }
    }
}
