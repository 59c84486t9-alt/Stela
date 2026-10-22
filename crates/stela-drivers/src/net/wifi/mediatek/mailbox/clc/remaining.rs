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
