// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Native CLC execution retaining the actual stopped-radio/source-policy owner
//! and exact downloaded input. Raw completions never qualify applied policy.
use super::{CapabilityReport, Mailbox, PCI_TIMEOUT_US, Packet, QueueIo, TransportFailure};
use crate::net::wifi::mediatek::{
    firmware::{
        auxiliary::{self, Auxiliary},
        clc::{self as plan, Inputs, Plan},
    },
    mcu::{Event, clc as codec},
    ring::rx::Frame,
};
use alloc::{alloc::alloc, boxed::Box, vec::Vec};
use core::alloc::Layout;

pub mod remaining;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reply {
    pub sequence: u8,
    pub dma_released: bool,
    pub frame: Frame,
}
/// Only the actual source protocol observation. Neither variant proves that
/// a country, channel, power limit or radio permission has been applied.
#[derive(Debug)]
pub enum Fact {
    OneWayDmaCompleted {
        request: usize,
        sequence: u8,
    },
    Response {
        request: usize,
        reply: Reply,
        observed: codec::Response,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongMailbox,
    PoisonedMailbox,
    MissingImageBinding,
    WrongImage,
    WrongReports,
    ChipFlagsMismatch,
    Selection(auxiliary::Error),
    Plan(plan::Error),
    NoMemory,
    AlreadyAttempted,
    Transport {
        request: usize,
        failure: TransportFailure,
    },
    Malformed {
        request: usize,
        error: codec::Error,
    },
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek native CLC execution: {self:?}")
    }
}
impl core::error::Error for Error {}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Fresh,
    Quarantined,
    CompletedFacts,
    RemainingUncertain,
    RemainingFacts,
    StartUncertain,
    StartDomainFacts,
    StartPowerFacts,
    Retired,
}
struct Owned<C> {
    resource: C,
    owner: u64,
    auxiliary: Auxiliary,
    capabilities: CapabilityReport,
    eeprom: super::eeprom::Report,
    plan: Plan,
    inputs: Inputs,
    phase: Phase,
    facts: Vec<Fact>,
    interrupted: Option<Reply>,
    remaining: Option<remaining::Chain>,
}
/// The actual authority/resource guard is owned, not a borrowed revision or a
/// promise ending on Err. Any publication retains this entire owner on Drop,
/// including successful raw completion, until independent genuine quiescence.
pub struct Execution<C: 'static> {
    owned: Option<Box<Owned<C>>>,
}

impl<C: 'static> Execution<C> {
    /// # Safety
    /// `resource` retains the genuine exclusive function/controller claim and
    /// currently stopped/drained radio, actual firmware/reset/image epoch, and
    /// trusted source country/location/ACPI/MTCL/power-limit resources used by
    /// `inputs`. These actual resources/authority guards must remain valid
    /// through partial/uncertain firmware processing and completed raw facts,
    /// even if this value/mailbox is dropped or its DMA queues are released.
    /// No old radio/policy users remain. Serialize all raw firmware/reset/radio
    /// and policy mutations with this owner for its entire retained lifetime.
    /// Changing/revoking those authorities requires stopping/canceling/draining
    /// real pending radio/firmware/IRQ/work users or source-proven enforcement.
    /// Merely retaining copied integers or an Arc unrelated to those resources
    /// cannot satisfy this contract. The bound observations below do not
    /// authenticate source-opaque EEPROM fields or provide these authorities.
    /// This executes only CLC; the full actual CLC→domain→SAR/rate-power chain
    /// and trusted OS intersection remain required before any radio admission.
    pub unsafe fn prepare<W: QueueIo, F: QueueIo, R: QueueIo>(
        mailbox: &Mailbox<W, F, R>,
        auxiliary: Auxiliary,
        capabilities: CapabilityReport,
        eeprom: super::eeprom::Report,
        inputs: Inputs,
        resource: C,
    ) -> Result<Self, Error> {
        Self::check_inputs(mailbox, &auxiliary, &capabilities, &eeprom)?;
        // An actually completed optional-TLV-absent query is distinct from no
        // query and from observed Some(0). The pinned zero-initialized source
        // chip_cap selects one-way C2 protocol in that case, not a capability
        // or policy permission. Preserve the original None in the owned report.
        if inputs.chip_capabilities != capabilities.observed().chip_flags().unwrap_or(0) {
            return Err(Error::ChipFlagsMismatch);
        }
        let selection = auxiliary
            .select_clc(eeprom.observed().byte())
            .map_err(Error::Selection)?;
        let plan = Plan::build(&selection, inputs).map_err(Error::Plan)?;
        let mut facts = Vec::new();
        facts
            .try_reserve_exact(plan.requests().len())
            .map_err(|_| Error::NoMemory)?;
        // Reserve the owner itself fallibly before the first device mutation.
        // Existing plan/encoder/RX transport allocations retain their inherited
        // allocation contracts; this is not a claim that they are all fallible.
        // SAFETY: `Owned` is not zero-sized.
        let storage = unsafe { alloc(Layout::new::<Owned<C>>()) }.cast::<Owned<C>>();
        if storage.is_null() {
            return Err(Error::NoMemory);
        }
        // SAFETY: covered by this function's own safety contract.
        unsafe {
            storage.write(Owned {
                resource,
                owner: mailbox.owner,
                auxiliary,
                capabilities,
                eeprom,
                plan,
                inputs,
                phase: Phase::Fresh,
                facts,
                interrupted: None,
                remaining: None,
            });
            Ok(Self {
                owned: Some(Box::from_raw(storage)),
            })
        }
    }
    fn check_inputs<W: QueueIo, F: QueueIo, R: QueueIo>(
        mailbox: &Mailbox<W, F, R>,
        auxiliary: &Auxiliary,
        capabilities: &CapabilityReport,
        eeprom: &super::eeprom::Report,
    ) -> Result<(), Error> {
        if mailbox.is_poisoned() {
            return Err(Error::PoisonedMailbox);
        }
        let binding = mailbox
            .download_binding()
            .ok_or(Error::MissingImageBinding)?;
        if !binding.matches_auxiliary(auxiliary) {
            return Err(Error::WrongImage);
        }
        if !capabilities.belongs_to(mailbox)
            || !eeprom.belongs_to(mailbox)
            || capabilities.identity() != mailbox.identity
            || eeprom.identity() != mailbox.identity
        {
            return Err(Error::WrongReports);
        }
        Ok(())
    }
    fn owned(&self) -> &Owned<C> {
        self.owned.as_deref().expect("owned native CLC context")
    }
    fn owned_mut(&mut self) -> &mut Owned<C> {
        self.owned.as_deref_mut().expect("owned native CLC context")
    }
    pub fn resource(&self) -> &C {
        &self.owned().resource
    }
    pub fn auxiliary(&self) -> &Auxiliary {
        &self.owned().auxiliary
    }
    pub fn capabilities(&self) -> &CapabilityReport {
        &self.owned().capabilities
    }
    pub fn eeprom(&self) -> &super::eeprom::Report {
        &self.owned().eeprom
    }
    pub fn plan(&self) -> &Plan {
        &self.owned().plan
    }
    /// Exact original source observations retained with their genuine guard.
    /// This is not a new applied-policy or radio-permission receipt.
    pub(in crate::net::wifi::mediatek) fn source_inputs(&self) -> Inputs {
        self.owned().inputs
    }
    pub fn facts(&self) -> &[Fact] {
        &self.owned().facts
    }
    pub fn interrupted_reply(&self) -> Option<&Reply> {
        self.owned().interrupted.as_ref()
    }
    pub fn is_quarantined(&self) -> bool {
        matches!(
            self.owned().phase,
            Phase::Quarantined | Phase::RemainingUncertain
        )
    }
    pub fn completed_facts(&self) -> bool {
        matches!(
            self.owned().phase,
            Phase::CompletedFacts | Phase::RemainingFacts
        )
    }

    /// Publish each exact source request once through the existing actual
    /// mailbox/DMA/sequence owner. Successful return is raw protocol completion
    /// only; keep the stopped radio and policy resources retained afterward.
    pub fn execute<W: QueueIo, F: QueueIo, R: QueueIo>(
        &mut self,
        mailbox: &mut Mailbox<W, F, R>,
    ) -> Result<(), Error> {
        self.execute_timed(mailbox, PCI_TIMEOUT_US)
    }

    pub(super) fn execute_timed<W: QueueIo, F: QueueIo, R: QueueIo>(
        &mut self,
        mailbox: &mut Mailbox<W, F, R>,
        timeout_us: u64,
    ) -> Result<(), Error> {
        let state = self.owned_mut();
        if state.owner != mailbox.owner {
            return Err(Error::WrongMailbox);
        }
        if state.phase != Phase::Fresh {
            return Err(Error::AlreadyAttempted);
        }
        Self::check_inputs(
            mailbox,
            &state.auxiliary,
            &state.capabilities,
            &state.eeprom,
        )?;
        // From now even a partial/uncertain publication may have changed real
        // firmware. No error or Drop may release the genuine context owner.
        state.phase = Phase::Quarantined;
        for (request, body) in state.plan.requests().iter().enumerate() {
            debug_assert_eq!(body.chip(), mailbox.identity.chip);
            let packet = Packet::Clc(mailbox.encoder.encode_clc(body));
            if let Err(failure) = mailbox.execute(&packet, timeout_us) {
                state.interrupted = mailbox.interrupted_clc_reply.take();
                return Err(Error::Transport { request, failure });
            }
            let Packet::Clc(packet) = packet else {
                unreachable!()
            };
            if packet.completion() == plan::Completion::OneWay {
                state.facts.push(Fact::OneWayDmaCompleted {
                    request,
                    sequence: packet.sequence(),
                });
                continue;
            }
            let reply = mailbox
                .interrupted_clc_reply
                .take()
                .expect("actual completed CLC response");
            let event =
                Event::parse(mailbox.identity.chip, &reply.frame.bytes).expect("matched CLC event");
            let observed = match codec::Response::parse(&packet, event.payload) {
                Ok(observed) => observed,
                Err(error) => {
                    state.interrupted = Some(reply);
                    return Err(Error::Malformed { request, error });
                }
            };
            state.facts.push(Fact::Response {
                request,
                reply,
                observed,
            });
        }
        state.phase = Phase::CompletedFacts;
        Ok(())
    }
    /// # Safety
    /// Independently stop/cancel/drain actual firmware command processing and
    /// every radio TX/RX, policy/image consumer, IRQ/deferred worker and DMA user
    /// of this real context, including uncertain requests/late completions.
    /// WFDMA idle, host timeout, queue removal and one-way DMA completion alone
    /// are insufficient. This neither qualifies policy nor resets/rebinds the
    /// mailbox. The caller still owns any independent mailbox/queue teardown.
    pub unsafe fn retire_after_quiesce(&mut self) {
        self.owned_mut().phase = Phase::Retired;
    }
}
impl<C: 'static> Drop for Execution<C> {
    fn drop(&mut self) {
        if let Some(owned) = self.owned.take()
            && !matches!(owned.phase, Phase::Fresh | Phase::Retired)
        {
            core::mem::forget(owned);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use crate::net::wifi::mediatek::{
        download::{PortState, Transport, TransportFailure},
        firmware::{
            Requests,
            tests::{catalog, patch_bytes},
        },
        identity::Chip,
        mailbox::{tests::*, *},
        mcu::{Command, Event},
    };
    use crate::net::wifi::mediatek::{
        firmware::{
            auxiliary::Auxiliary,
            clc::{Completion, Environment, Inputs},
        },
        mailbox::clc::{Error, Execution, Fact},
    };
    use alloc::{sync::Arc, vec::Vec};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    pub(crate) struct Guard {
        pub(crate) model: Arc<Mutex<Response>>,
        pub(crate) drops: Arc<AtomicUsize>,
    }
    impl Guard {
        pub(crate) fn new(model: &Arc<Mutex<Response>>, drops: &Arc<AtomicUsize>) -> Self {
            let mut state = model.lock().unwrap();
            assert!(!state.clc_guard && !state.clc_processing);
            state.clc_guard = true;
            Self {
                model: model.clone(),
                drops: drops.clone(),
            }
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            let mut state = self.model.lock().unwrap();
            assert!(
                !state.clc_processing,
                "actual pending firmware users must retain guard"
            );
            state.clc_guard = false;
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub(crate) fn inputs(flags: Option<u64>) -> Inputs {
        Inputs {
            alpha2: *b"US",
            environment: Environment::Outdoor,
            chip_capabilities: flags.unwrap_or(0),
            power_limits_node: true,
            power_type: 2,
            acpi_flags: 0xa5,
            mtcl_configuration: 0x123456aa,
            world_mtcl_configuration: 0x876543bb,
        }
    }
    pub(crate) fn capability_flags(chip: Chip, flags: Option<u64>) -> Vec<u8> {
        let mut bytes = vec![u8::from(flags.is_some()), 0, 0xa5, 0x5a];
        if let Some(flags) = flags {
            if chip == Chip::Mt7925 {
                bytes.extend_from_slice(&[0x20, 0, 12, 0]);
            } else {
                bytes.extend_from_slice(&[0x20, 0, 0, 0, 8, 0, 0, 0]);
            }
            bytes.extend_from_slice(&flags.to_le_bytes());
        }
        bytes
    }
    pub(crate) fn clc_response(chip: Chip) -> Vec<u8> {
        if chip == Chip::Mt7925 {
            vec![]
        } else {
            (0u8..75).map(|n| n.wrapping_mul(3)).collect()
        }
    }
    pub(crate) fn record(chip: Chip, slot: u8) -> Vec<u8> {
        let mut bytes = vec![0; 16];
        bytes[4] = slot;
        bytes[5] = if chip == Chip::Mt7925 { 2 } else { 1 };
        if chip == Chip::Mt7925 {
            bytes[8] = 1;
            let mut segment = [0; 16];
            segment[0] = 1;
            segment[4..8].copy_from_slice(&24u32.to_le_bytes());
            segment[8..12].copy_from_slice(&20u32.to_le_bytes());
            bytes.extend_from_slice(&segment);
            bytes.extend_from_slice(b"US");
            bytes.extend_from_slice(&[7, 9, 1, 0xa3, 0, 0]);
        } else {
            bytes.extend_from_slice(b"US");
            bytes.extend_from_slice(&[7, 9, 20, 0]);
        }
        bytes.extend_from_slice(&[0x5a; 20]);
        let n = bytes.len() as u32;
        bytes[..4].copy_from_slice(&n.to_le_bytes());
        bytes
    }
    pub(crate) fn clc_bytes(chip: Chip) -> Vec<u8> {
        let mut bytes = record(chip, 0);
        bytes.extend_from_slice(&record(chip, 1));
        bytes
    }
    pub(crate) fn ram(clc: &[u8]) -> Vec<u8> {
        // Actual private Prepared bytes contain a real downloaded region and a
        // separate non-download CLC region; the complete image hash binds both.
        let mut bytes = vec![0x61; 11];
        bytes.extend_from_slice(clc);
        for (length, address, features, kind) in [
            (11u32, 0x910000u32, 0x21, 0),
            (clc.len() as u32, 0, 0x40, 2),
        ] {
            let mut descriptor = [0; 40];
            descriptor[16..20].copy_from_slice(&address.to_le_bytes());
            descriptor[20..24].copy_from_slice(&length.to_le_bytes());
            descriptor[24] = features;
            descriptor[25] = kind;
            bytes.extend_from_slice(&descriptor);
        }
        let mut trailer = [0; 36];
        trailer[..5].copy_from_slice(&[0x10, 0, 2, 2, 1]);
        bytes.extend_from_slice(&trailer);
        bytes
    }
    pub(crate) struct Fixture {
        pub(crate) mailbox: TestMailbox,
        pub(crate) model: Arc<Mutex<Response>>,
        pub(crate) wm: ModelState,
        pub(crate) auxiliary: Option<Auxiliary>,
        pub(crate) capabilities: Option<CapabilityReport>,
        pub(crate) eeprom: Option<eeprom::Report>,
    }
    impl Fixture {
        pub(crate) fn new(chip: Chip, flags: Option<u64>) -> Self {
            Self::with_clc(chip, flags, &clc_bytes(chip), 0)
        }
        pub(crate) fn with_clc(chip: Chip, flags: Option<u64>, clc: &[u8], eeprom: u8) -> Self {
            Self::with_ram(chip, flags, ram(clc), patch_bytes(), eeprom)
        }
        pub(crate) fn with_ram(
            chip: Chip,
            flags: Option<u64>,
            ram: Vec<u8>,
            patch: Vec<u8>,
            eeprom: u8,
        ) -> Self {
            let model = Arc::new(Mutex::new(Response {
                capability_payload: Some(capability_flags(chip, flags)),
                encapsulation_payload: Some(eeprom_body(chip, eeprom)),
                clc_payload: Some(clc_response(chip)),
                require_firmware_start: true,
                ..Response::default()
            }));
            let (mut mailbox, wm, _, _) = setup_controlled(chip, true, false, 3, model.clone());
            let requests = Requests::new(&identity(chip));
            let provider = catalog(&requests, patch, ram);
            let prepared = requests.load(&provider).unwrap();
            let auxiliary = prepared.retain_auxiliary();
            mailbox.download_with_binding(&prepared).unwrap();
            drop(prepared);
            drop(provider);
            let capabilities = mailbox.query_capabilities().unwrap();
            let eeprom = mailbox.query_encapsulation().unwrap();
            Self {
                mailbox,
                model,
                wm,
                auxiliary: Some(auxiliary),
                capabilities: Some(capabilities),
                eeprom: Some(eeprom),
            }
        }
        pub(crate) fn claim(
            &mut self,
            input: Inputs,
            drops: &Arc<AtomicUsize>,
        ) -> Result<Execution<Guard>, Error> {
            let guard = Guard::new(&self.model, drops);
            // SAFETY: guard owns the actual serialized stopped model requester and
            // source-policy state used by these explicit fixture inputs. Firmware
            // checks that guard before every actual DMA-read CLC publication.
            unsafe {
                Execution::prepare(
                    &self.mailbox,
                    self.auxiliary.take().unwrap(),
                    self.capabilities.take().unwrap(),
                    self.eeprom.take().unwrap(),
                    input,
                    guard,
                )
            }
        }
        pub(crate) fn drain(&mut self) {
            self.model.lock().unwrap().clc_processing = false;
            {
                let mut state = self.wm.lock().unwrap();
                state.index = state.head;
            }
        }
        pub(crate) fn release(&mut self) {
            self.drain();
            // SAFETY: actual modeled firmware/radio/deferred processing and every
            // requester queue user has stopped independently of any MCU response.
            unsafe { self.mailbox.release_after_quiesce() }.unwrap();
        }
    }
    #[test]
    fn native_clc_preserves_absent_zero_and_event_protocol_and_completed_owner() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            for flags in [None, Some(0), Some(1)] {
                let mut fixture = Fixture::new(chip, flags);
                let drops = Arc::new(AtomicUsize::new(0));
                let mut owner = fixture.claim(inputs(flags), &drops).unwrap();
                assert_eq!(owner.capabilities().observed().chip_flags(), flags);
                assert_eq!(owner.eeprom().observed().byte(), 0);
                assert_eq!(owner.plan().requests().len(), 2);
                owner.execute(&mut fixture.mailbox).unwrap();
                assert!(owner.completed_facts() && !owner.is_quarantined());
                assert_eq!(owner.facts().len(), 2);
                assert!(owner.interrupted_reply().is_none());
                assert!(owner.resource().model.lock().unwrap().clc_guard);
                let model = fixture.model.lock().unwrap();
                assert_eq!(model.clc_commands.len(), 2);
                assert!(model.clc_processing);
                for (index, (request, fact)) in owner
                    .plan()
                    .requests()
                    .iter()
                    .zip(owner.facts())
                    .enumerate()
                {
                    let packet = &model.clc_commands[index];
                    assert_eq!(
                        &packet[if chip == Chip::Mt7925 { 48 } else { 64 }..],
                        request.body()
                    );
                    match fact {
                        Fact::OneWayDmaCompleted { request, sequence } => {
                            assert_eq!(*request, index);
                            assert_eq!(*sequence, packet[39]);
                            assert_ne!(chip, Chip::Mt7925);
                            assert_eq!(flags.unwrap_or(0) & 1, 0);
                        }
                        Fact::Response {
                            request,
                            reply,
                            observed,
                        } => {
                            assert_eq!(*request, index);
                            assert!(reply.dma_released);
                            assert_eq!(reply.sequence, packet[39]);
                            assert_eq!(observed.raw(), clc_response(chip));
                            if chip == Chip::Mt7925 {
                                assert!(observed.connac2().is_none());
                            } else {
                                assert_eq!(observed.connac2().unwrap().channel_flags, 24);
                                assert_eq!(observed.trailing(), &clc_response(chip)[72..]);
                            }
                        }
                    }
                }
                drop(model);
                assert_eq!(
                    owner.execute(&mut fixture.mailbox),
                    Err(Error::AlreadyAttempted)
                );
                if flags == Some(0) {
                    fixture.drain();
                    // SAFETY: actual model firmware/policy/radio users stopped.
                    unsafe { owner.retire_after_quiesce() };
                    drop(owner);
                    assert_eq!(drops.load(Ordering::Relaxed), 1);
                } else {
                    drop(owner); // even completed raw facts cannot drop real C
                    assert_eq!(drops.load(Ordering::Relaxed), 0);
                }
                fixture.release();
                assert_eq!(drops.load(Ordering::Relaxed), usize::from(flags == Some(0)));
            }
        }
    }
    #[test]
    fn native_clc_checks_actual_image_reports_flags_and_live_binding_before_publication() {
        for mode in 0..7 {
            let chip = Chip::Mt7922;
            let mut fixture = Fixture::new(chip, Some(1));
            let drops = Arc::new(AtomicUsize::new(0));
            let mut input = inputs(Some(1));
            let mut other = Fixture::new(chip, Some(1));
            let expected = match mode {
                0 => {
                    fixture.mailbox.download_binding = None;
                    Error::MissingImageBinding
                }
                1 => {
                    let requests = Requests::new(&identity(chip));
                    let mut bytes = clc_bytes(chip);
                    *bytes.last_mut().unwrap() ^= 1;
                    let provider = catalog(&requests, patch_bytes(), ram(&bytes));
                    fixture.auxiliary = Some(requests.load(&provider).unwrap().retain_auxiliary());
                    Error::WrongImage
                }
                2 => {
                    fixture.capabilities = other.capabilities.take();
                    Error::WrongReports
                }
                3 => {
                    fixture.eeprom = other.eeprom.take();
                    Error::WrongReports
                }
                4 => {
                    input.chip_capabilities = 0;
                    Error::ChipFlagsMismatch
                }
                5 => {
                    fixture.mailbox.poisoned = true;
                    Error::PoisonedMailbox
                }
                6 => {
                    // Malformed selected source bytes must refuse atomically,
                    // before any CLC publication, even under exact image binding.
                    fixture.release();
                    fixture = Fixture::with_clc(chip, Some(1), &[1, 0, 0, 0], 0);
                    Error::Selection(
                        crate::net::wifi::mediatek::firmware::auxiliary::Error::TruncatedHeader {
                            offset: 0,
                        },
                    )
                }
                _ => unreachable!(),
            };
            assert!(matches!(fixture.claim(input, &drops), Err(e) if e == expected));
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert!(fixture.model.lock().unwrap().clc_commands.is_empty());
            fixture.release();
            other.release();
        }
        for mode in 0..2 {
            let mut fixture = Fixture::new(Chip::Mt7921, Some(1));
            let drops = Arc::new(AtomicUsize::new(0));
            let mut owner = fixture.claim(inputs(Some(1)), &drops).unwrap();
            let mut other = Fixture::new(Chip::Mt7921, Some(1));
            if mode == 0 {
                assert_eq!(owner.execute(&mut other.mailbox), Err(Error::WrongMailbox));
            } else {
                fixture
                    .mailbox
                    .command(Command::PatchSemaphore as u8, &0u32.to_le_bytes())
                    .unwrap();
                assert_eq!(
                    owner.execute(&mut fixture.mailbox),
                    Err(Error::MissingImageBinding)
                );
            }
            assert!(!owner.is_quarantined());
            drop(owner);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            assert!(fixture.model.lock().unwrap().clc_commands.is_empty());
            fixture.release();
            other.release();
        }
    }
    #[test]
    fn native_clc_partial_uncertain_and_malformed_execution_retains_actual_guard_on_drop() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            for mode in 0..6 {
                if mode == 5 && chip == Chip::Mt7925 {
                    continue;
                }
                let mut fixture = Fixture::new(chip, Some(1));
                let drops = Arc::new(AtomicUsize::new(0));
                let mut owner = fixture.claim(inputs(Some(1)), &drops).unwrap();
                {
                    let mut model = fixture.model.lock().unwrap();
                    match mode {
                        0 => model.clc_no_reply_after = Some(2),
                        1 => model.clc_fail_publication_after = Some(2),
                        2 => model.clc_hide_tx_index = true,
                        3 => model.unsolicited = true,
                        4 => model.drop = true,
                        5 => model.clc_payload = Some(vec![0; 71]),
                        _ => unreachable!(),
                    }
                }
                let result = owner
                    .execute_timed(&mut fixture.mailbox, 1_000)
                    .unwrap_err();
                assert!(owner.is_quarantined() && !owner.completed_facts());
                let completed = if mode < 2 { 1 } else { 0 };
                assert_eq!(owner.facts().len(), completed);
                if mode == 5 {
                    assert!(matches!(result, Error::Malformed { request: 0, .. }));
                    assert!(!fixture.mailbox.is_poisoned());
                    assert!(owner.interrupted_reply().unwrap().dma_released);
                    assert_eq!(
                        Event::parse(chip, &owner.interrupted_reply().unwrap().frame.bytes)
                            .unwrap()
                            .payload
                            .len(),
                        71
                    );
                } else {
                    assert!(matches!(
                        result,
                        Error::Transport {
                            failure: TransportFailure {
                                port: PortState::Uncertain,
                                ..
                            },
                            ..
                        }
                    ));
                    assert!(fixture.mailbox.is_poisoned());
                    if mode == 2 {
                        assert!(!owner.interrupted_reply().unwrap().dma_released);
                    }
                }
                let count = fixture.model.lock().unwrap().clc_commands.len();
                assert_eq!(
                    owner.execute(&mut fixture.mailbox),
                    Err(Error::AlreadyAttempted)
                );
                assert_eq!(fixture.model.lock().unwrap().clc_commands.len(), count);
                drop(owner);
                assert_eq!(drops.load(Ordering::Relaxed), 0);
                assert!(fixture.model.lock().unwrap().clc_guard);
                fixture.release();
                assert_eq!(drops.load(Ordering::Relaxed), 0);
            }
        }
    }

    #[test]
    #[ignore = "requires unchanged full CLC country-helper and MCU-writer oracle"]
    fn full_source_clc_plans_execute_through_one_native_requester_and_exact_wire_bytes() {
        let root = std::path::PathBuf::from(std::env::var("STELA_MT792X_CLC_WIRE_ORACLE").unwrap());
        for (chip, number) in [
            (Chip::Mt7921, 7921),
            (Chip::Mt7922, 7922),
            (Chip::Mt7925, 7925),
        ] {
            let country =
                std::fs::read(root.join(alloc::format!("country/{number}.trace"))).unwrap();
            let wire = std::fs::read(root.join(alloc::format!("{number}.trace"))).unwrap();
            let mut at = 0;
            let mut wire_at = 0;
            for _ in 0..108 {
                let meta = &country[at..at + 23];
                at += 23;
                let n = u32::from_le_bytes(country[at..at + 4].try_into().unwrap()) as usize;
                at += 4;
                let flags = u64::from_le_bytes(meta[7..15].try_into().unwrap());
                let mut fixture =
                    Fixture::with_clc(chip, Some(flags), &country[at..at + n], meta[0]);
                at += n;
                let count =
                    usize::from(u16::from_le_bytes(country[at..at + 2].try_into().unwrap()));
                at += 2;
                let input = Inputs {
                    alpha2: meta[1..3].try_into().unwrap(),
                    environment: match meta[3] {
                        0 => Environment::Any,
                        1 => Environment::Indoor,
                        2 => Environment::Outdoor,
                        _ => unreachable!(),
                    },
                    acpi_flags: meta[4],
                    power_type: meta[5],
                    power_limits_node: meta[6] != 0,
                    chip_capabilities: flags,
                    mtcl_configuration: u32::from_le_bytes(meta[15..19].try_into().unwrap()),
                    world_mtcl_configuration: u32::from_le_bytes(meta[19..23].try_into().unwrap()),
                };
                let mut sequence = fixture.eeprom.as_ref().unwrap().reply().sequence;
                let drops = Arc::new(AtomicUsize::new(0));
                let mut owner = fixture.claim(input, &drops).unwrap();
                assert_eq!(owner.plan().requests().len(), count);
                owner.execute(&mut fixture.mailbox).unwrap();
                assert_eq!(owner.facts().len(), count);
                assert_eq!(fixture.model.lock().unwrap().clc_commands.len(), count);
                for (index, (request, fact)) in owner
                    .plan()
                    .requests()
                    .iter()
                    .zip(owner.facts())
                    .enumerate()
                {
                    let wait = country[at + 4] != 0;
                    let pending_flags = country[at + 5];
                    let n = usize::from(u16::from_le_bytes(
                        country[at + 6..at + 8].try_into().unwrap(),
                    ));
                    at += 8;
                    assert_eq!(request.body(), &country[at..at + n]);
                    at += n;
                    assert_eq!(request.completion() != Completion::OneWay, wait);
                    if chip == Chip::Mt7925 {
                        assert_eq!(request.pending_channel_flags(), Some(pending_flags));
                    }
                    let n = usize::from(u16::from_le_bytes(
                        wire[wire_at..wire_at + 2].try_into().unwrap(),
                    ));
                    wire_at += 2;
                    let mut expected = wire[wire_at..wire_at + n].to_vec();
                    wire_at += n;
                    sequence = sequence % 15 + 1;
                    expected[39] = sequence; // real shared boot/query/runtime sequence epoch
                    assert_eq!(fixture.model.lock().unwrap().clc_commands[index], expected);
                    match fact {
                        Fact::OneWayDmaCompleted {
                            sequence: actual, ..
                        } => {
                            assert!(!wait);
                            assert_eq!(*actual, sequence);
                        }
                        Fact::Response { reply, .. } => {
                            assert!(wait && reply.dma_released);
                            assert_eq!(reply.sequence, sequence);
                        }
                    }
                }
                fixture.drain();
                // SAFETY: actual model CLC processing/radio/policy users drained.
                unsafe { owner.retire_after_quiesce() };
                drop(owner);
                assert_eq!(drops.load(Ordering::Relaxed), 1);
                fixture.release();
            }
            assert_eq!(at, country.len());
            assert_eq!(wire_at, wire.len());
        }
    }

    #[test]
    #[ignore = "requires the exact six actual redistributable firmware images"]
    fn actual_downloaded_images_and_owned_reports_execute_clc_past_provider_lifetime() {
        let images = std::path::PathBuf::from(std::env::var("STELA_MT792X_FIRMWARE").unwrap());
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            for flags in [None, Some(1)] {
                let mut fixture = Fixture::with_ram(
                    chip,
                    flags,
                    std::fs::read(images.join(chip.ram_name())).unwrap(),
                    std::fs::read(images.join(chip.patch_name())).unwrap(),
                    0,
                );
                let drops = Arc::new(AtomicUsize::new(0));
                let mut owner = fixture.claim(inputs(flags), &drops).unwrap();
                assert!(!owner.auxiliary().release_information().is_empty());
                assert!(!owner.plan().requests().is_empty());
                owner.execute(&mut fixture.mailbox).unwrap();
                assert!(owner.completed_facts());
                assert_eq!(owner.facts().len(), owner.plan().requests().len());
                assert_eq!(owner.capabilities().observed().chip_flags(), flags);
                assert!(
                    owner
                        .auxiliary()
                        .select_clc(owner.eeprom().observed().byte())
                        .unwrap()
                        .region()
                        .is_some()
                );
                fixture.drain();
                // SAFETY: actual modeled firmware/policy/radio/deferred users stop.
                unsafe { owner.retire_after_quiesce() };
                drop(owner);
                assert_eq!(drops.load(Ordering::Relaxed), 1);
                fixture.release();
            }
        }
    }
}
