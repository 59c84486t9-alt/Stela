// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Domain/SAR-rate-power continuation of the same genuine retained CLC owner.
//! Completion observations never implement a trusted HardwarePolicy provider.
use super::{Execution, Mailbox, PCI_TIMEOUT_US, Packet, Phase, QueueIo, Reply};
use crate::net::wifi::mediatek::{
    identity::Chip,
    mcu::{Event, domain, power},
};
use alloc::vec::Vec;

pub struct Inputs<'a> {
    pub domain: domain::Inputs<'a>,
    pub power: power::Inputs<'a>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step {
    Domain,
    Power { request: usize, kind: power::Kind },
}
#[derive(Debug)]
pub enum Observation {
    OneWayDmaCompleted,
    GenericResponse(Reply),
    PseRead {
        reply: Reply,
        register: u32,
        value: u32,
    },
}
#[derive(Debug)]
pub struct Fact {
    pub step: Step,
    pub sequence: u8,
    pub observed: Observation,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Clc(super::Error),
    Domain(domain::Error),
    Power(power::Error),
    AlreadyPrepared,
    NotPrepared,
    WrongPhase,
    WrongCountry,
    CapabilitiesIncomplete,
    BandSelection,
    NoMemory,
    Transport {
        step: Step,
        failure: super::TransportFailure,
    },
    Malformed {
        step: Step,
        error: power::Error,
    },
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek domain/SAR-rate-power execution: {self:?}")
    }
}
impl core::error::Error for Error {}
pub(super) struct Chain {
    domain: domain::Request,
    power: power::Plan,
    facts: Vec<Fact>,
    interrupted: Option<Reply>,
    start_facts: Vec<Fact>,
}

impl<C: 'static> Execution<C> {
    /// # Safety
    /// Extend the existing genuine retained `resource` authority/ownership to
    /// these exact channel and resolved per-channel/per-rate half-dBm inputs,
    /// resolved after consuming this owner's actual completed CLC facts.
    /// They must derive from actual chip/board/chain, completed CLC restrictions
    /// (including MT7925 BE_CTRL), requested power, trusted current OS/location
    /// domain, actual SAR and ACPI/DTS limits. Actual absence must be proven;
    /// missing values cannot use zero/127/unlimited defaults. For every source
    /// fixed power-list channel, limits faithfully represent all applicable
    /// constraints; disabled channels remain disabled in the domain. The real
    /// guards and board/chain/source-policy resources must remain retained by C
    /// through all uncertain/completed firmware/radio users, with raw changes
    /// and revocation serialized as in `prepare`. Copied raw flags or arrays
    /// alone cannot satisfy this. This method creates no applied-policy receipt.
    pub unsafe fn prepare_remaining<W: QueueIo, F: QueueIo, R: QueueIo>(
        &mut self,
        mailbox: &Mailbox<W, F, R>,
        inputs: Inputs<'_>,
    ) -> Result<(), Error> {
        let state = self.owned_mut();
        if state.owner != mailbox.owner {
            return Err(Error::Clc(super::Error::WrongMailbox));
        }
        if state.phase != Phase::CompletedFacts {
            return Err(Error::WrongPhase);
        }
        if state.remaining.is_some() {
            return Err(Error::AlreadyPrepared);
        }
        Self::check_inputs(
            mailbox,
            &state.auxiliary,
            &state.capabilities,
            &state.eeprom,
        )
        .map_err(Error::Clc)?;
        if inputs.domain.alpha2 != state.plan.requested_alpha2()
            || inputs.power.alpha2 != state.plan.requested_alpha2()
        {
            return Err(Error::WrongCountry);
        }
        let phy = state
            .capabilities
            .observed()
            .phy()
            .ok_or(Error::CapabilitiesIncomplete)?;
        // Optional absent6GHz observation selects no6GHz source protocol; the
        // original None remains in the owned actual report and grants no band.
        let mut expected = [
            phy.has_2ghz(),
            phy.has_5ghz(),
            state.capabilities.observed().six_ghz().unwrap_or(false),
        ];
        if mailbox.identity.chip == Chip::Mt7925 {
            // Source rate-power skips6GHz when the last now-completed CLC
            // rule's flags are zero. This only selects the bounded source plan;
            // the actual CLC completion and its retained source context precede
            // this planning operation, with no predicted response permission.
            expected[2] &= state
                .plan
                .requests()
                .iter()
                .filter_map(|r| r.pending_channel_flags())
                .next_back()
                .is_some_and(|f| f != 0);
        }
        let domain =
            domain::Request::build(mailbox.identity.chip, inputs.domain).map_err(Error::Domain)?;
        let power =
            power::Plan::build(mailbox.identity.chip, inputs.power).map_err(Error::Power)?;
        if power.bands() != expected
            || domain
                .counts()
                .iter()
                .zip(expected)
                .any(|(&n, allowed)| n != 0 && !allowed)
        {
            return Err(Error::BandSelection);
        }
        let mut facts = Vec::new();
        facts
            .try_reserve_exact(1 + power.requests().len())
            .map_err(|_| Error::NoMemory)?;
        state.remaining = Some(Chain {
            domain,
            power,
            facts,
            interrupted: None,
            start_facts: Vec::new(),
        });
        Ok(())
    }
    pub fn remaining_facts(&self) -> &[Fact] {
        self.owned()
            .remaining
            .as_ref()
            .map_or(&[], |c| c.facts.as_slice())
    }
    pub fn interrupted_remaining_reply(&self) -> Option<&Reply> {
        self.owned()
            .remaining
            .as_ref()
            .and_then(|c| c.interrupted.as_ref())
    }
    pub fn remaining_completed(&self) -> bool {
        self.owned().phase == Phase::RemainingFacts
    }
    /// Continue the actual completed CLC with domain and complete source rate-
    /// power/PSE exactly once under the same retained authority. CLC is never
    /// restarted/replayed. Return means raw protocol facts, including source
    /// one-way boundaries, never an admitted radio or policy.
    pub fn execute_all<W: QueueIo, F: QueueIo, R: QueueIo>(
        &mut self,
        mailbox: &mut Mailbox<W, F, R>,
    ) -> Result<(), Error> {
        self.execute_all_timed(mailbox, PCI_TIMEOUT_US)
    }
    pub(in super::super) fn execute_all_timed<W: QueueIo, F: QueueIo, R: QueueIo>(
        &mut self,
        mailbox: &mut Mailbox<W, F, R>,
        timeout_us: u64,
    ) -> Result<(), Error> {
        if self.owned().remaining.is_none() {
            return Err(Error::NotPrepared);
        }
        let state = self.owned_mut();
        if state.owner != mailbox.owner {
            return Err(Error::Clc(super::Error::WrongMailbox));
        }
        if state.phase != Phase::CompletedFacts {
            return Err(Error::WrongPhase);
        }
        Self::check_inputs(
            mailbox,
            &state.auxiliary,
            &state.capabilities,
            &state.eeprom,
        )
        .map_err(Error::Clc)?;
        let chain = state.remaining.as_mut().unwrap();
        state.phase = Phase::RemainingUncertain;
        for index in 0..=chain.power.requests().len() {
            let (step, packet) = if index == 0 {
                (
                    Step::Domain,
                    Packet::Domain(mailbox.encoder.encode_domain(&chain.domain)),
                )
            } else {
                let request = index - 1;
                let body = &chain.power.requests()[request];
                (
                    Step::Power {
                        request,
                        kind: body.kind(),
                    },
                    Packet::Power(mailbox.encoder.encode_power(body)),
                )
            };
            let sequence = packet.sequence();
            if let Err(failure) = mailbox.execute(&packet, timeout_us) {
                chain.interrupted = mailbox.interrupted_regulatory_reply.take();
                return Err(Error::Transport { step, failure });
            }
            let observed = if !packet.expects_response() {
                Observation::OneWayDmaCompleted
            } else {
                let reply = mailbox
                    .interrupted_regulatory_reply
                    .take()
                    .expect("actual completed domain/power response");
                if matches!(
                    step,
                    Step::Power {
                        kind: power::Kind::PseFlush,
                        ..
                    }
                ) {
                    let event = Event::parse(mailbox.identity.chip, &reply.frame.bytes)
                        .expect("matched actual PSE response");
                    match power::flush_value(event.payload) {
                        Ok((register, value)) => Observation::PseRead {
                            reply,
                            register,
                            value,
                        },
                        Err(error) => {
                            chain.interrupted = Some(reply);
                            return Err(Error::Malformed { step, error });
                        }
                    }
                } else {
                    Observation::GenericResponse(reply)
                }
            };
            chain.facts.push(Fact {
                step,
                sequence,
                observed,
            });
        }
        state.phase = Phase::RemainingFacts;
        Ok(())
    }
}

impl<C: 'static> Execution<C> {
    pub fn start_facts(&self) -> &[Fact] {
        self.owned()
            .remaining
            .as_ref()
            .map_or(&[], |c| c.start_facts.as_slice())
    }
    /// Vendor initial lifecycle only: source repeats the same resolved domain
    /// at first start. This does not replay CLC or manufacture new authority.
    pub(in crate::net::wifi::mediatek) fn start_domain<W: QueueIo, F: QueueIo, R: QueueIo>(
        &mut self,
        mailbox: &mut Mailbox<W, F, R>,
    ) -> Result<(), Error> {
        let s = self.owned_mut();
        if s.owner != mailbox.owner {
            return Err(Error::Clc(super::Error::WrongMailbox));
        }
        if s.phase != Phase::RemainingFacts {
            return Err(Error::WrongPhase);
        }
        Self::check_inputs(mailbox, &s.auxiliary, &s.capabilities, &s.eeprom)
            .map_err(Error::Clc)?;
        let chain = s.remaining.as_mut().ok_or(Error::NotPrepared)?;
        chain
            .start_facts
            .try_reserve_exact(1 + chain.power.requests().len())
            .map_err(|_| Error::NoMemory)?;
        s.phase = Phase::StartUncertain;
        let packet = Packet::Domain(mailbox.encoder.encode_domain(&chain.domain));
        Self::start_exchange(mailbox, chain, Step::Domain, packet)?;
        s.phase = Phase::StartDomainFacts;
        Ok(())
    }
    pub(in crate::net::wifi::mediatek) fn start_power<W: QueueIo, F: QueueIo, R: QueueIo>(
        &mut self,
        mailbox: &mut Mailbox<W, F, R>,
    ) -> Result<(), Error> {
        let s = self.owned_mut();
        if s.owner != mailbox.owner {
            return Err(Error::Clc(super::Error::WrongMailbox));
        }
        if s.phase != Phase::StartDomainFacts || mailbox.identity.chip == Chip::Mt7925 {
            return Err(Error::WrongPhase);
        }
        Self::check_inputs(mailbox, &s.auxiliary, &s.capabilities, &s.eeprom)
            .map_err(Error::Clc)?;
        s.phase = Phase::StartUncertain;
        let chain = s.remaining.as_mut().ok_or(Error::NotPrepared)?;
        for request in 0..chain.power.requests().len() {
            let body = &chain.power.requests()[request];
            let step = Step::Power {
                request,
                kind: body.kind(),
            };
            let packet = Packet::Power(mailbox.encoder.encode_power(body));
            Self::start_exchange(mailbox, chain, step, packet)?;
        }
        s.phase = Phase::StartPowerFacts;
        Ok(())
    }
    fn start_exchange<W: QueueIo, F: QueueIo, R: QueueIo>(
        mailbox: &mut Mailbox<W, F, R>,
        chain: &mut Chain,
        step: Step,
        packet: Packet,
    ) -> Result<(), Error> {
        let sequence = packet.sequence();
        if let Err(failure) = mailbox.execute(&packet, PCI_TIMEOUT_US) {
            chain.interrupted = mailbox.interrupted_regulatory_reply.take();
            return Err(Error::Transport { step, failure });
        }
        let observed = if !packet.expects_response() {
            Observation::OneWayDmaCompleted
        } else {
            let reply = mailbox
                .interrupted_regulatory_reply
                .take()
                .expect("actual initial repeat response");
            if matches!(
                step,
                Step::Power {
                    kind: power::Kind::PseFlush,
                    ..
                }
            ) {
                let event = Event::parse(mailbox.identity.chip, &reply.frame.bytes)
                    .expect("actual PSE event");
                match power::flush_value(event.payload) {
                    Ok((register, value)) => Observation::PseRead {
                        reply,
                        register,
                        value,
                    },
                    Err(error) => {
                        chain.interrupted = Some(reply);
                        return Err(Error::Malformed { step, error });
                    }
                }
            } else {
                Observation::GenericResponse(reply)
            }
        };
        chain.start_facts.push(Fact {
            step,
            sequence,
            observed,
        });
        Ok(())
    }
}

impl<C: 'static> Execution<C> {
    /// Private view of this retained owner's actual completed MT7925 chain.
    /// No public copied receipt can manufacture a programmed policy.
    pub(in crate::net::wifi::mediatek) fn programmed_mt7925(
        &self,
    ) -> Option<(&domain::Request, &power::Plan)> {
        let state = self.owned();
        let chain = state.remaining.as_ref()?;
        (state.phase == Phase::StartDomainFacts
            && chain.domain.chip() == Chip::Mt7925
            && chain.facts.len() == 1 + chain.power.requests().len()
            && chain.start_facts.len() == 1
            && chain.interrupted.is_none())
        .then_some((&chain.domain, &chain.power))
    }
    pub(in crate::net::wifi::mediatek) fn initial_channel_present(
        &self,
        band: crate::net::wifi::Band,
        channel: u8,
    ) -> bool {
        let Some(c) = self.owned().remaining.as_ref() else {
            return false;
        };
        let counts = c.domain.counts();
        let index = match band {
            crate::net::wifi::Band::Ghz2 => 0,
            crate::net::wifi::Band::Ghz5 => 1,
            crate::net::wifi::Band::Ghz6 => 2,
        };
        let first: usize = counts[..index].iter().map(|&n| usize::from(n)).sum();
        let header = if c.domain.chip() == Chip::Mt7925 {
            16
        } else {
            12
        };
        c.domain.body()[header..]
            .as_chunks::<8>()
            .0
            .iter()
            .skip(first)
            .take(counts[index] as usize)
            .any(|e| u16::from_le_bytes([e[0], e[1]]) == u16::from(channel))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use crate::net::wifi::mediatek::mailbox::clc::tests::*;
    use crate::net::wifi::mediatek::mailbox::clc::{Execution, Fact};
    use crate::net::wifi::mediatek::{
        download::{PortState, TransportFailure},
        identity::Chip,
        mcu::Event,
    };
    use crate::net::wifi::{
        Band,
        mediatek::{
            mailbox::clc::remaining::{
                Error as RemainingError, Inputs as RemainingInputs, Observation, Step,
            },
            mcu::{domain, power},
        },
    };
    use alloc::{sync::Arc, vec::Vec};
    use core::sync::atomic::{AtomicUsize, Ordering};

    pub(crate) fn caps(chip: Chip, bands: [bool; 3]) -> Vec<u8> {
        let mut bytes = vec![3, 0, 0xa5, 0x5a];
        let mut phy = [1, 1, 1, 0, 2, 0, 1, 1, 0, 0, 0, 1, 1];
        phy[10] = u8::from(bands[0]) | (u8::from(bands[1]) << 1);
        for (tag, body) in [
            (8u32, &phy[..if chip == Chip::Mt7925 { 13 } else { 12 }]),
            (0x18, &[u8::from(bands[2])][..]),
            (0x20, &1u64.to_le_bytes()[..]),
        ] {
            if chip == Chip::Mt7925 {
                bytes.extend_from_slice(&(tag as u16).to_le_bytes());
                bytes.extend_from_slice(&((body.len() + 4) as u16).to_le_bytes());
            } else {
                bytes.extend_from_slice(&tag.to_le_bytes());
                bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
            }
            bytes.extend_from_slice(body);
        }
        bytes
    }
    pub(crate) fn complete_caps(fixture: &mut Fixture, bands: [bool; 3]) {
        fixture.model.lock().unwrap().capability_payload =
            Some(caps(fixture.mailbox.identity.chip, bands));
        fixture.capabilities = Some(fixture.mailbox.query_capabilities().unwrap());
    }
    pub(crate) fn rates(chip: Chip, band: Band) -> Vec<power::Channel> {
        power::channels(chip, band)
            .iter()
            .map(|&hardware_value| power::Channel {
                hardware_value,
                limits: power::Limits::uniform(-3),
            })
            .collect()
    }
    pub(crate) fn domain_channels(band: Band) -> Vec<domain::Channel> {
        vec![domain::Channel {
            hardware_value: match band {
                Band::Ghz2 => 1,
                Band::Ghz5 => 36,
                Band::Ghz6 => 1,
            },
            flags: 2 | 16 | 32 | 128 | 256 | 8192 | (1 << 20),
        }]
    }
    pub(crate) fn prepare(
        owner: &mut Execution<Guard>,
        fixture: &Fixture,
        alpha2: [u8; 2],
        bands: &[Vec<power::Channel>; 3],
    ) -> Result<(), RemainingError> {
        let chan: [Vec<domain::Channel>; 3] = core::array::from_fn(|i| {
            if bands[i].is_empty() {
                Vec::new()
            } else {
                domain_channels([Band::Ghz2, Band::Ghz5, Band::Ghz6][i])
            }
        });
        prepare_with_channels(owner, fixture, alpha2, bands, &chan)
    }
    pub(crate) fn prepare_with_channels(
        owner: &mut Execution<Guard>,
        fixture: &Fixture,
        alpha2: [u8; 2],
        bands: &[Vec<power::Channel>; 3],
        chan: &[Vec<domain::Channel>; 3],
    ) -> Result<(), RemainingError> {
        // Install the actual source-policy fixture behind the same retained Guard,
        // not an unrelated drop counter. Every device DMA consumer checks these
        // exact retained restrictions/rate inputs before mutating modeled hardware.
        {
            let mut model = fixture.model.lock().unwrap();
            if model.regulatory_expected_domain.is_none() {
                model.regulatory_expected_domain = domain::Request::build(
                    fixture.mailbox.identity.chip,
                    domain::Inputs {
                        alpha2,
                        channels_2ghz: &chan[0],
                        channels_5ghz: &chan[1],
                        channels_6ghz: &chan[2],
                    },
                )
                .ok()
                .map(|r| r.body().to_vec());
                for (band, entries) in bands.iter().enumerate() {
                    for entry in entries {
                        model.regulatory_expected_power.insert(
                            (band as u8 + 1, entry.hardware_value),
                            entry.limits.sku(
                                fixture.mailbox.identity.chip,
                                [Band::Ghz2, Band::Ghz5, Band::Ghz6][band],
                            ),
                        );
                    }
                }
            }
        }
        // SAFETY: the actual retained model guard owns stopped radio and the
        // fixture source-policy state for these explicit restricted channels and
        // resolved rate arrays. The same guard is checked by each real DMA read;
        // no native HardwarePolicy/OS authority is manufactured by this test.
        unsafe {
            owner.prepare_remaining(
                &fixture.mailbox,
                RemainingInputs {
                    domain: domain::Inputs {
                        alpha2,
                        channels_2ghz: &chan[0],
                        channels_5ghz: &chan[1],
                        channels_6ghz: &chan[2],
                    },
                    power: power::Inputs {
                        alpha2,
                        ghz2: (!bands[0].is_empty()).then_some(bands[0].as_slice()),
                        ghz5: (!bands[1].is_empty()).then_some(bands[1].as_slice()),
                        ghz6: (!bands[2].is_empty()).then_some(bands[2].as_slice()),
                    },
                },
            )
        }
    }
    #[test]
    fn coherent_clc_domain_power_dma_response_and_pse_facts_keep_genuine_owner() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            for retain in [false, true] {
                let mut fixture = Fixture::new(chip, Some(1));
                complete_caps(&mut fixture, [true, true, false]);
                let drops = Arc::new(AtomicUsize::new(0));
                let mut owner = fixture.claim(inputs(Some(1)), &drops).unwrap();
                assert_eq!(
                    owner.execute_all(&mut fixture.mailbox),
                    Err(RemainingError::NotPrepared)
                );
                let bands = [rates(chip, Band::Ghz2), rates(chip, Band::Ghz5), Vec::new()];
                owner.execute(&mut fixture.mailbox).unwrap();
                prepare(&mut owner, &fixture, *b"US", &bands).unwrap();
                assert_eq!(
                    prepare(&mut owner, &fixture, *b"US", &bands),
                    Err(RemainingError::AlreadyPrepared)
                );
                owner.execute_all(&mut fixture.mailbox).unwrap();
                assert!(owner.remaining_completed() && !owner.is_quarantined());
                let model = fixture.model.lock().unwrap();
                assert!(model.regulatory_domain && model.clc_guard && model.clc_processing);
                assert_eq!(
                    model.regulatory_power.len(),
                    if chip == Chip::Mt7925 { 60 } else { 62 }
                );
                assert_eq!(
                    owner.remaining_facts().len(),
                    model.regulatory_commands.len()
                );
                for (fact, packet) in owner
                    .remaining_facts()
                    .iter()
                    .zip(&model.regulatory_commands)
                {
                    assert_eq!(fact.sequence, packet[39]);
                    match &fact.observed {
                        Observation::OneWayDmaCompleted => assert_ne!(chip, Chip::Mt7925),
                        Observation::GenericResponse(reply) => {
                            assert_eq!(chip, Chip::Mt7925);
                            assert!(reply.dma_released);
                            assert!(
                                Event::parse(chip, &reply.frame.bytes)
                                    .unwrap()
                                    .payload
                                    .is_empty()
                            );
                        }
                        Observation::PseRead {
                            reply,
                            register,
                            value,
                        } => {
                            assert_ne!(chip, Chip::Mt7925);
                            assert_eq!(*register, 0x820c8000);
                            assert_eq!(*value, 0xefbeadde);
                            assert!(reply.dma_released);
                            assert!(matches!(
                                fact.step,
                                Step::Power {
                                    kind: power::Kind::PseFlush,
                                    ..
                                }
                            ));
                        }
                    }
                }
                drop(model);
                assert_eq!(
                    owner.execute_all(&mut fixture.mailbox),
                    Err(RemainingError::WrongPhase)
                );
                if retain {
                    drop(owner);
                    assert_eq!(drops.load(Ordering::Relaxed), 0);
                } else {
                    fixture.drain();
                    unsafe { owner.retire_after_quiesce() };
                    drop(owner);
                    assert_eq!(drops.load(Ordering::Relaxed), 1);
                }
                fixture.release();
                assert_eq!(drops.load(Ordering::Relaxed), usize::from(!retain));
            }
        }
    }
    #[test]
    fn remaining_refusal_retains_completed_clc_before_any_domain_or_power_publication() {
        for mode in 0..5 {
            let chip = Chip::Mt7925;
            let mut fixture = Fixture::new(chip, Some(1));
            if mode != 0 {
                complete_caps(&mut fixture, [true, true, false]);
            }
            let drops = Arc::new(AtomicUsize::new(0));
            let mut owner = fixture.claim(inputs(Some(1)), &drops).unwrap();
            owner.execute(&mut fixture.mailbox).unwrap();
            let mut bands = [rates(chip, Band::Ghz2), rates(chip, Band::Ghz5), Vec::new()];
            let expected = match mode {
                0 => RemainingError::CapabilitiesIncomplete,
                1 => RemainingError::WrongCountry,
                2 => {
                    bands[1].clear();
                    RemainingError::BandSelection
                }
                3 => {
                    bands[2] = rates(chip, Band::Ghz6);
                    RemainingError::BandSelection
                }
                4 => {
                    bands[0].pop();
                    RemainingError::Power(power::Error::Channels {
                        band: Band::Ghz2,
                        expected: 14,
                        actual: 13,
                    })
                }
                _ => unreachable!(),
            };
            assert_eq!(
                prepare(
                    &mut owner,
                    &fixture,
                    if mode == 1 { *b"CN" } else { *b"US" },
                    &bands
                ),
                Err(expected)
            );
            assert_eq!(fixture.model.lock().unwrap().clc_commands.len(), 2);
            assert!(owner.remaining_facts().is_empty());
            drop(owner);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
            fixture.release();
        }
    }
    #[test]
    fn actual_partial_domain_power_failure_early_reply_and_bad_pse_never_release_policy_guard() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            for mode in 0..5 {
                if mode == 4 && chip == Chip::Mt7925 {
                    continue;
                }
                let mut fixture = Fixture::new(chip, Some(1));
                complete_caps(&mut fixture, [true, true, false]);
                let drops = Arc::new(AtomicUsize::new(0));
                let mut owner = fixture.claim(inputs(Some(1)), &drops).unwrap();
                let bands = [rates(chip, Band::Ghz2), rates(chip, Band::Ghz5), Vec::new()];
                owner.execute(&mut fixture.mailbox).unwrap();
                prepare(&mut owner, &fixture, *b"US", &bands).unwrap();
                {
                    let mut model = fixture.model.lock().unwrap();
                    match mode {
                        0 => model.regulatory_fail_publication_at = Some(1),
                        1 => model.regulatory_fail_publication_at = Some(2),
                        2 => {
                            model.regulatory_no_reply_at =
                                Some(if chip == Chip::Mt7925 { 2 } else { 3 })
                        }
                        3 => {
                            model.regulatory_hide_tx_index_at =
                                Some(if chip == Chip::Mt7925 { 2 } else { 3 })
                        }
                        4 => model.regulatory_malformed_pse = true,
                        _ => unreachable!(),
                    }
                }
                let failure = owner
                    .execute_all_timed(&mut fixture.mailbox, 1000)
                    .unwrap_err();
                assert!(owner.is_quarantined() && !owner.remaining_completed());
                assert!(fixture.model.lock().unwrap().regulatory_domain);
                assert_eq!(drops.load(Ordering::Relaxed), 0);
                if mode == 4 {
                    assert!(matches!(
                        failure,
                        RemainingError::Malformed {
                            error: power::Error::TruncatedFlush,
                            ..
                        }
                    ));
                    assert!(!fixture.mailbox.is_poisoned());
                    assert!(owner.interrupted_remaining_reply().unwrap().dma_released);
                } else {
                    assert!(matches!(
                        failure,
                        RemainingError::Transport {
                            failure: TransportFailure {
                                port: PortState::Uncertain,
                                ..
                            },
                            ..
                        }
                    ));
                    assert!(fixture.mailbox.is_poisoned());
                    if mode == 3 {
                        assert!(!owner.interrupted_remaining_reply().unwrap().dma_released);
                    }
                }
                let count = fixture.model.lock().unwrap().regulatory_commands.len();
                assert_eq!(
                    owner.execute_all(&mut fixture.mailbox),
                    Err(RemainingError::WrongPhase)
                );
                assert_eq!(
                    fixture.model.lock().unwrap().regulatory_commands.len(),
                    count
                );
                drop(owner);
                assert_eq!(drops.load(Ordering::Relaxed), 0);
                fixture.release();
                assert_eq!(drops.load(Ordering::Relaxed), 0);
            }
        }
    }
    #[test]
    #[ignore = "requires full unchanged source rate/SAR/batch/MCU oracle"]
    fn all_source_rate_plans_cross_coherent_native_clc_domain_power_and_pse_dma() {
        let root = std::path::PathBuf::from(std::env::var("STELA_MT792X_POWER_ORACLE").unwrap());
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            for source in power::tests::sources(&root, chip) {
                let mut bytes = Vec::new();
                for slot in [0, 1] {
                    let mut rec = record(chip, slot);
                    let at = if chip == Chip::Mt7925 { 32 } else { 16 };
                    rec[at..at + 2].copy_from_slice(&source.alpha2);
                    if chip == Chip::Mt7925 && !source.clc_nonzero {
                        rec[37] = 0;
                    }
                    bytes.extend_from_slice(&rec);
                }
                let mut fixture = Fixture::with_clc(chip, Some(1), &bytes, 0);
                complete_caps(&mut fixture, source.hardware_bands);
                let drops = Arc::new(AtomicUsize::new(0));
                let mut input = inputs(Some(1));
                input.alpha2 = source.alpha2;
                let mut owner = fixture.claim(input, &drops).unwrap();
                owner.execute(&mut fixture.mailbox).unwrap();
                prepare(&mut owner, &fixture, source.alpha2, &source.bands).unwrap();
                owner.execute_all(&mut fixture.mailbox).unwrap();
                assert!(owner.remaining_completed());
                let model = fixture.model.lock().unwrap();
                assert_eq!(model.regulatory_commands.len(), source.wire.len() + 1);
                for (actual, expected) in model.regulatory_commands[1..].iter().zip(&source.wire) {
                    let mut packet = expected.packet.clone();
                    packet[39] = actual[39];
                    assert_eq!(*actual, packet);
                }
                let expected: usize = source.bands.iter().map(Vec::len).sum();
                assert_eq!(model.regulatory_power.len(), expected);
                drop(model);
                fixture.drain();
                unsafe { owner.retire_after_quiesce() };
                drop(owner);
                assert_eq!(drops.load(Ordering::Relaxed), 1);
                fixture.release();
            }
        }
    }

    #[test]
    #[ignore = "requires six exact redistributable firmware images"]
    fn actual_images_execute_retained_clc_domain_power_chain_past_provider_lifetime() {
        let images = std::path::PathBuf::from(std::env::var("STELA_MT792X_FIRMWARE").unwrap());
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let mut fixture = Fixture::with_ram(
                chip,
                Some(1),
                std::fs::read(images.join(chip.ram_name())).unwrap(),
                std::fs::read(images.join(chip.patch_name())).unwrap(),
                0,
            );
            complete_caps(&mut fixture, [true, true, false]);
            let drops = Arc::new(AtomicUsize::new(0));
            let mut owner = fixture.claim(inputs(Some(1)), &drops).unwrap();
            let bands = [rates(chip, Band::Ghz2), rates(chip, Band::Ghz5), Vec::new()];
            owner.execute(&mut fixture.mailbox).unwrap();
            prepare(&mut owner, &fixture, *b"US", &bands).unwrap();
            owner.execute_all(&mut fixture.mailbox).unwrap();
            assert!(owner.remaining_completed());
            assert!(!owner.auxiliary().release_information().is_empty());
            fixture.drain();
            unsafe { owner.retire_after_quiesce() };
            drop(owner);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            fixture.release();
        }
    }

    #[test]
    fn actual_clc_reply_resolves_domain_and_power_without_replay_and_failed_resolution_retains_owner()
     {
        for chip in [Chip::Mt7921, Chip::Mt7922] {
            for returned_flags in [0u8, 1] {
                for fail_plan in [false, true] {
                    let mut fixture = Fixture::new(chip, Some(1));
                    complete_caps(&mut fixture, [true, true, false]);
                    fixture.model.lock().unwrap().clc_payload.as_mut().unwrap()[8] = returned_flags;
                    let drops = Arc::new(AtomicUsize::new(0));
                    let mut owner = fixture.claim(inputs(Some(1)), &drops).unwrap();
                    assert_eq!(owner.facts().len(), 0);
                    owner.execute(&mut fixture.mailbox).unwrap();
                    let flags = owner
                        .facts()
                        .iter()
                        .filter_map(|fact| match fact {
                            Fact::Response { observed, .. } => {
                                observed.connac2().map(|info| info.channel_flags)
                            }
                            _ => None,
                        })
                        .next_back()
                        .unwrap();
                    assert_eq!(flags, returned_flags);
                    assert_eq!(owner.facts().len(), 2);
                    // The same actual source-policy guard now resolves source UNII4
                    // restrictions from the completed reply. Source get_ch_power applies
                    // the channel regulatory cap only while enabled; the disabled channel
                    // remains excluded from the domain even if its raw rate limit differs.
                    let enabled = flags & 1 != 0;
                    let mut bands = [rates(chip, Band::Ghz2), rates(chip, Band::Ghz5), Vec::new()];
                    bands[1]
                        .iter_mut()
                        .find(|c| c.hardware_value == 169)
                        .unwrap()
                        .limits = power::Limits::uniform(if enabled { -10 } else { -3 });
                    let chans = [
                        domain_channels(Band::Ghz2),
                        vec![
                            domain::Channel {
                                hardware_value: 36,
                                flags: 2,
                            },
                            domain::Channel {
                                hardware_value: 169,
                                flags: if enabled { 2 } else { 3 },
                            },
                        ],
                        Vec::new(),
                    ];
                    if fail_plan {
                        bands[0].pop();
                    }
                    let result =
                        prepare_with_channels(&mut owner, &fixture, *b"US", &bands, &chans);
                    if fail_plan {
                        assert!(matches!(
                            result,
                            Err(RemainingError::Power(power::Error::Channels {
                                expected: 14,
                                actual: 13,
                                ..
                            }))
                        ));
                        assert_eq!(owner.facts().len(), 2);
                        assert!(owner.completed_facts());
                        assert!(owner.remaining_facts().is_empty());
                        assert!(fixture.model.lock().unwrap().regulatory_commands.is_empty());
                        assert!(
                            fixture
                                .mailbox
                                .download_binding()
                                .unwrap()
                                .matches_auxiliary(owner.auxiliary())
                        );
                        drop(owner);
                        assert_eq!(drops.load(Ordering::Relaxed), 0);
                        fixture.release();
                        assert_eq!(drops.load(Ordering::Relaxed), 0);
                        continue;
                    }
                    result.unwrap();
                    owner.execute_all(&mut fixture.mailbox).unwrap();
                    let model = fixture.model.lock().unwrap();
                    assert_eq!(model.clc_commands.len(), 2, "never replay completed CLC");
                    assert_eq!(
                        model.regulatory_commands[0][64 + 9],
                        if enabled { 2 } else { 1 }
                    );
                    assert_eq!(
                        model.regulatory_power[&(2, 169)],
                        power::Limits::uniform(if enabled { -10 } else { -3 })
                            .sku(chip, Band::Ghz5)
                    );
                    drop(model);
                    fixture.drain();
                    unsafe { owner.retire_after_quiesce() };
                    drop(owner);
                    assert_eq!(drops.load(Ordering::Relaxed), 1);
                    fixture.release();
                }
            }
        }
    }
}
