// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
//! Private receive permission borrowing the programmed native owner.
use super::*;
use crate::wifi::{
    intel::mcc::channel,
    regulatory::{HardwareLease, HardwarePolicy, OsLease, OsPolicy},
};
pub(super) struct Hardware<'p, 'a, Q: BootIo, B: BiosIo> {
    pub(super) board: &'p mut Ax200BoardPolicy<'a, Q, B>,
    pub(super) selection: &'p SelectedCountry,
    pub(super) channels: &'p [channel::Observation],
    pub(super) native: regulatory::NativeContext,
}
pub(super) struct Guard<'g, 'p, 'a, Q: BootIo, B: BiosIo> {
    owner: &'g mut Hardware<'p, 'a, Q, B>,
}
impl<'a, Q: BootIo, B: BiosIo> Hardware<'_, 'a, Q, B> {
    fn boot(&mut self) -> &mut RomBoot<'a, Q> {
        &mut self.board.scan.mcc.setup.lari.radio.initialized.boot
    }
    pub(super) fn channel(&self, band: Band, number: u16) -> Option<Channel> {
        let information = &self.board.initialized_nvm().information;
        let sku_bit = match band {
            Band::Ghz2 => 1,
            Band::Ghz5 => 2,
            Band::Ghz6 => return None,
        };
        if information.lar_enabled == 0 || information.mac_sku_flags & sku_bit == 0 {
            return None;
        }
        let observation = self.channels.iter().find(|ch| {
            let matches_band = matches!(
                (ch.channel.band, band),
                (channel::Band::Ghz2, Band::Ghz2) | (channel::Band::Ghz5, Band::Ghz5)
            );
            matches_band
                && ch.channel.number == number
                && ch.valid
                && ch.index < information.channel_count
        })?;
        let channel = Channel {
            band,
            number,
            frequency_mhz: observation.channel.frequency_mhz,
        };
        // Original CountryIo-selected pinned DB and complete 20MHz footprint.
        self.selection
            .country
            .rule(u32::from(channel.frequency_mhz) * 1000, 20_000)?;
        Some(channel)
    }
    /// Whether the firmware's own channel list lets a frame start here.
    fn initiates(&self, channel: Channel) -> bool {
        self.channels.iter().any(|ch| {
            ch.channel.number == channel.number
                && ch.channel.frequency_mhz == channel.frequency_mhz
                && !ch.restrictions.no_initiate_radiation
        })
    }
}
// SAFETY: private construction borrows the unique fully ACKed original native
// MAC/board/MCC owner and its Country selection, never public receipts.
// Its exclusive mutable borrow serializes controlled reset/programming through
// the HCMD handoff. Receive and firmware-built scan probes are admitted; every
// other TX operation (including autonomous association/ACK) is refused. The kept OS
// attachment must coordinate post-publication revocation with this native owner
// or hardware enforcement, as required by unsafe begin_scan.
unsafe impl<'p, 'a, Q: BootIo, B: BiosIo> HardwarePolicy for Hardware<'p, 'a, Q, B> {
    type Lease<'g>
        = Guard<'g, 'p, 'a, Q, B>
    where
        Self: 'g;
    fn acquire(&mut self) -> Option<Self::Lease<'_>> {
        let boot = self.boot();
        if boot.state != State::PnvmObserved || boot.hcmd.pending_is_present() {
            return None;
        }
        // A pending country-change notification invalidates the private applied
        // epoch; it is not consumed as an invented replacement MCC permission.
        if boot.hcmd.has_matching(0xc9, 0) {
            return None;
        }
        Some(Guard { owner: self })
    }
}
impl<Q: BootIo, B: BiosIo> HardwareLease for Guard<'_, '_, '_, Q, B> {
    fn context(&self) -> regulatory::NativeContext {
        self.owner.native
    }
    fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel> {
        self.owner.channel(band, number)
    }
    fn allows(&mut self, operation: regulatory::Operation) -> bool {
        match operation {
            regulatory::Operation::Receive(ch) => {
                self.owner.channel(ch.band, ch.number) == Some(ch)
            }
            regulatory::Operation::Transmit {
                channel,
                purpose: regulatory::Purpose::Probe,
                ..
            } => {
                self.owner.channel(channel.band, channel.number) == Some(channel)
                    && self.owner.initiates(channel)
            }
            regulatory::Operation::Transmit { .. } => false,
        }
    }
}
impl<Q: BootIo, B: BiosIo> Guard<'_, '_, '_, Q, B> {
    /// # Safety
    /// The private caller has validated the complete operation under both real
    /// hardware and OS leases. Its closure must preserve the same exclusive
    /// native requester/domain and perform only that checked publication.
    pub(super) unsafe fn with_boot<T>(
        &mut self,
        operation: impl FnOnce(&mut RomBoot<'_, Q>) -> T,
    ) -> T {
        operation(self.owner.boot())
    }
    pub(super) unsafe fn submit(
        &mut self,
        id: Id,
        bytes: &[u8],
        source: &dyn PageSource,
    ) -> Result<CommandTicket, Error> {
        // SAFETY: original-owner page contract forwarded by Ax200Scan::start;
        // caller encodes the exact guarded receive-only scan or unbound PHY.
        unsafe { self.owner.boot().submit_command(id, bytes, source) }
    }
}
pub(super) struct Os<'p, O: CountryIo + OsPolicy> {
    pub(super) service: &'p mut O,
    pub(super) selection_revision: u64,
}
// SAFETY: unsafe begin_scan checks the two interfaces as the SAME
// selection/DB service. Delegation returns its lease, not copied flags.
unsafe impl<O: CountryIo + OsPolicy> OsPolicy for Os<'_, O> {
    type Lease<'g>
        = O::Lease<'g>
    where
        Self: 'g;
    fn acquire(&mut self, native: regulatory::NativeContext) -> Option<Self::Lease<'_>> {
        if !self.service.current(self.selection_revision).ok()? {
            return None;
        }
        self.service.acquire(native)
    }
}
/// Protocol-only adapter used *inside* the guarded publication closure,
/// after the complete exact request was checked under both real leases. It is
/// never exposed or installed as a HardwarePolicy/OsPolicy provider.
pub(super) struct CheckedRequest<'r>(pub(super) &'r protocol::Request);
impl protocol::Policy for CheckedRequest<'_> {
    fn allow_receive(&mut self, channel: Channel) -> bool {
        self.0.channels().contains(&channel)
    }
    fn allow_probe(&mut self, channel: Channel) -> bool {
        self.0.active() && self.0.channels().contains(&channel)
    }
    fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel> {
        self.0
            .channels()
            .iter()
            .copied()
            .find(|ch| ch.band == band && ch.number == number)
    }
}
struct ReceivePolicy<'h, 'o, H: HardwareLease, O: OsLease> {
    hardware: &'h mut H,
    os: &'o mut O,
}
impl<H: HardwareLease, O: OsLease> protocol::Policy for ReceivePolicy<'_, '_, H, O> {
    fn allow_receive(&mut self, channel: Channel) -> bool {
        let operation = regulatory::Operation::Receive(channel);
        self.hardware.lookup_channel(channel.band, channel.number) == Some(channel)
            && self.hardware.allows(operation)
            && self.os.allows(operation)
    }
    fn allow_probe(&mut self, _: Channel) -> bool {
        false
    }
    fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel> {
        self.hardware.lookup_channel(band, number)
    }
}
pub(super) fn observe<Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy>(
    parts: country::ScanPolicyParts<'_, '_, Q, B, O>,
    native: regulatory::NativeContext,
    scanner: &protocol::Scanner,
    ticket: protocol::Ticket,
    frame: &crate::wifi::frame::Mpdu,
) -> Result<protocol::result::Bss, Ax200ScanError> {
    let mut hardware = Hardware {
        board: parts.board,
        selection: parts.selection,
        channels: parts.channels,
        native,
    };
    let mut service = Os {
        service: parts.os,
        selection_revision: parts.selection.revision,
    };
    // H then O guards also cover observed/advertised-channel result
    // checks; copied earlier admission cannot admit newly revoked reception.
    let mut guard = hardware.acquire().ok_or(Ax200ScanError::Regulatory(
        regulatory::Error::HardwareUnavailable,
    ))?;
    let mut os = service
        .acquire(guard.context())
        .ok_or(Ax200ScanError::Regulatory(regulatory::Error::OsUnavailable))?;
    scanner
        .observe(
            ticket,
            frame,
            &mut ReceivePolicy {
                hardware: &mut guard,
                os: &mut os,
            },
        )
        .map_err(Ax200ScanError::Protocol)
}
