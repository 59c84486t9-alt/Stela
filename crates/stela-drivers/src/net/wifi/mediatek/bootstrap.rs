// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
// Copyright (C) 2020-2023 MediaTek Inc.
//! Retained ordinary PCIe bootstrap, including every source selectable queue.
//! Actual protocol facts never publish an associated Link or qualify policy.
use super::{
    control::{self, Control, bootstrap::MacInitialized, rx_ring, tx_ring},
    firmware::{Prepared, auxiliary::Auxiliary, clc::Inputs as ClcInputs},
    identity::{Chip, Identity},
    mailbox::{
        self, Mailbox,
        bootstrap::Fact,
        clc::{Execution, remaining},
    },
    mcu::{bootstrap::Request, device::Context},
    registers::{self, BarIo, MmioBar, Registers},
    ring::{
        self, MmioQueue, QueueIo, TxRing,
        data::DataRing,
        rx::{Assembly, Frame, RxRing},
    },
};
use crate::{
    Clock,
    bus::dma::{mapping::DmaDomain, memory::PageSource},
    net::wifi::Band,
};
use alloc::{alloc::alloc, boxed::Box, sync::Arc, vec::Vec};
use core::{alloc::Layout, ptr::NonNull};

pub mod client;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Fresh,
    Queues,
    Firmware,
    Clc,
    Policy,
    Mac,
    StartFacts,
    Quarantined,
    Retired,
}
#[derive(Debug)]
pub enum Error {
    NoMemory,
    WrongPhase,
    MissingPolicy,
    MissingCapabilities,
    RequiredRfkill,
    ChannelNotInDomain,
    UnsupportedBand,
    FirmwareStatus(u32),
    UnvalidatedHeaderFormat { wcid: u16 },
    Interface(mailbox::device::Error),
    WrongFirmware,
    Register(registers::Error),
    Control(control::Error),
    Ring(ring::Error),
    Data(ring::data::Error),
    Mailbox(mailbox::Cause),
    Transport(super::download::TransportFailure),
    Download(mailbox::firmware::Error),
    Capabilities(mailbox::CapabilityQueryFailure),
    Eeprom(mailbox::eeprom::Failure),
    Clc(mailbox::clc::Error),
    Remaining(remaining::Error),
    Codec(super::mcu::bootstrap::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek bootstrap: {self:?}")
    }
}
impl core::error::Error for Error {}
pub(in crate::net::wifi::mediatek) struct NativeWindow {
    base: NonNull<u8>,
    bytes: usize,
    owner: Arc<dyn core::any::Any>,
}
struct Owned<I: BarIo, Q: QueueIo, C: 'static> {
    identity: Identity,
    control: Control<I>,
    resource: Arc<C>,
    phase: Phase,
    aspm: Option<bool>,
    native: Option<NativeWindow>,
    mailbox: Option<Mailbox<Q, Q, Q>>,
    data_tx: Option<DataRing<Q, client::PacketOwner<C>>>,
    data_rx: Option<RxRing<Q>>,
    data_assembly: Assembly,
    // Retain partially installed rings before enabling or constructing mailbox.
    wm: Option<TxRing<Q>>,
    fwdl: Option<TxRing<Q>>,
    event: Option<RxRing<Q>>,
    runtime: Option<RxRing<Q>>,
    capabilities: Option<mailbox::CapabilityReport>,
    eeprom: Option<mailbox::eeprom::Report>,
    auxiliary: Option<Auxiliary>,
    policy: Option<Execution<Arc<C>>>,
    facts: Vec<Fact>,
    mac: Option<MacInitialized>,
    counters: Option<[u32; 11]>,
    counter_reset_ticks: Option<u64>,
}
/// Drop after the first actual mutation retains the entire real context,
/// including fully completed facts. Independent actual quiescence is required
/// to release it. Polling is serialized and device IRQ sources stay masked.
pub struct Controller<I: BarIo, Q: QueueIo, C: 'static> {
    owned: Option<Box<Owned<I, Q, C>>>,
}
impl<C: 'static> Controller<MmioBar, MmioQueue, C> {
    /// # Safety
    /// Actual observed `identity`, powered exclusive PCI/BAR claim and UC
    /// mapping `base..base+bytes`, retained by `owner`, meet MmioBar/Registers
    /// and QueueIo contracts. `resource` is the genuine live controller/board/
    /// firmware/policy ownership guard, not unrelated copied facts. There are
    /// no old firmware/IRQ/deferred/DMA/token users or possible late responses;
    /// the function's complete ordinary queue/WTBL namespace is exclusively
    /// owned in a genuine initial sequencing epoch. This is not established by
    /// an idle register, a caller integer or a firmware restart command.
    /// Calibrate `clock` on the actual executing CPU. All later DMA installs
    /// require this same actual requester's qualified WB coherence with ATS,
    /// NoSnoop/PRI/PASID off and its canonical PageSource/DmaDomain. Do not
    /// qualify physical hardware from the QEMU or WB cache-type observation.
    /// Serialize all raw reset/IRQ/power/firmware paths for this retained owner.
    /// This claims the WLAN function and its initial firmware epoch. The
    /// source WLAN NIC_POWER_CTRL restart is not a Bluetooth setup command;
    /// the pinned source establishes no mandatory PCIe-before-USB probe order.
    /// Any external shared power/reset path must retain and quiesce every
    /// affected function's actual users before changing their resources.
    /// Neither a local phase nor a copied combo ID grants shared reset or
    /// recovery authority. Automatic shared reset remains unsupported.
    pub unsafe fn new(
        identity: Identity,
        base: NonNull<u8>,
        bytes: usize,
        owner: Arc<dyn core::any::Any>,
        resource: Arc<C>,
        clock: Clock,
    ) -> Result<Self, Error> {
        // The largest fixed/remap BAR windows need the donor's complete mapped
        // BAR (C2:1MiB,C3:2MiB); queue arithmetic is checked again per use.
        if bytes
            < if identity.chip == Chip::Mt7925 {
                0x200000
            } else {
                0x100000
            }
        {
            return Err(Error::Register(registers::Error::OutsideBar));
        }
        let io = unsafe { MmioBar::from_owned_window(base, bytes, owner.clone()) }
            .map_err(Error::Register)?;
        let registers = unsafe { Registers::new(identity.chip, io) };
        let control = unsafe { Control::new(registers, clock) }.map_err(Error::Control)?;
        Self::claim(
            identity,
            control,
            resource,
            Some(NativeWindow { base, bytes, owner }),
        )
    }
    /// # Safety
    /// `source`/`domain` are actually attached to this requester's retained
    /// physical ownership and meet the genuine coherent-WB/32-bit constraints
    /// documented by ring::TxRing::install and this Controller's constructor.
    /// They must not belong to another function or synthetic physical aliases.
    /// `aspm` is the actual retained requester ASPM-supported state; its source
    /// wake-delay selection remains bound through the subsequent MCU setup.
    pub unsafe fn install(
        &mut self,
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        aspm: bool,
    ) -> Result<(), Error> {
        let n = self.state().native.as_ref().expect("native mapping");
        let base = n.base;
        let bytes = n.bytes;
        let owner = n.owner.clone();
        unsafe {
            self.install_with(source, domain, aspm, move |offset| {
                if (offset as usize)
                    .checked_add(16)
                    .is_none_or(|end| end > bytes)
                {
                    return Err(Error::Register(registers::Error::OutsideBar));
                }
                let p =
                    NonNull::new_unchecked(base.as_ptr().add(offset as usize).cast::<[u32; 4]>());
                Ok(MmioQueue::from_window(p, owner.clone()))
            })
        }
    }
}
impl<I: BarIo, Q: QueueIo, C: 'static> Controller<I, Q, C> {
    // Vendor model/native constructors preserve the exclusive initial WLAN
    // ownership contract above; this is not an alternative physical admission.
    pub(in crate::net::wifi::mediatek) fn claim(
        identity: Identity,
        control: Control<I>,
        resource: Arc<C>,
        native: Option<NativeWindow>,
    ) -> Result<Self, Error> {
        if control.chip() != identity.chip {
            return Err(Error::WrongPhase);
        }
        let mut facts = Vec::new();
        facts.try_reserve_exact(12).map_err(|_| Error::NoMemory)?;
        let p = unsafe { alloc(Layout::new::<Owned<I, Q, C>>()) }.cast::<Owned<I, Q, C>>();
        if p.is_null() {
            return Err(Error::NoMemory);
        }
        unsafe {
            p.write(Owned {
                identity,
                control,
                resource,
                phase: Phase::Fresh,
                aspm: None,
                native,
                mailbox: None,
                data_tx: None,
                data_rx: None,
                data_assembly: Assembly::default(),
                wm: None,
                fwdl: None,
                event: None,
                runtime: None,
                capabilities: None,
                eeprom: None,
                auxiliary: None,
                policy: None,
                facts,
                mac: None,
                counters: None,
                counter_reset_ticks: None,
            });
            Ok(Self {
                owned: Some(Box::from_raw(p)),
            })
        }
    }
    fn state(&self) -> &Owned<I, Q, C> {
        self.owned.as_deref().expect("retained controller")
    }
    fn state_mut(&mut self) -> &mut Owned<I, Q, C> {
        self.owned.as_deref_mut().expect("retained controller")
    }
    pub fn phase(&self) -> Phase {
        self.state().phase
    }
    pub fn facts(&self) -> &[Fact] {
        &self.state().facts
    }
    pub fn mac_observations(&self) -> Option<&MacInitialized> {
        self.state().mac.as_ref()
    }
    pub fn mailbox(&self) -> Option<&Mailbox<Q, Q, Q>> {
        self.state().mailbox.as_ref()
    }
    pub fn policy(&self) -> Option<&Execution<Arc<C>>> {
        self.state().policy.as_ref()
    }
    fn require(&self, phase: Phase) -> Result<(), Error> {
        if self.phase() == phase {
            Ok(())
        } else {
            Err(Error::WrongPhase)
        }
    }
    pub(in crate::net::wifi::mediatek) unsafe fn install_with(
        &mut self,
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        aspm: bool,
        mut queue: impl FnMut(u32) -> Result<Q, Error>,
    ) -> Result<(), Error> {
        self.require(Phase::Fresh)?;
        let s = self.state_mut();
        s.phase = Phase::Quarantined;
        s.aspm = Some(aspm);
        s.control.driver_own(aspm).map_err(Error::Control)?;
        if s.identity.chip == Chip::Mt7925 {
            // mt7925_pci_probe: actual driver-own, WFSYS reset, then DMA init.
            // No ring is allocated/published or engine enabled before its ACK.
            unsafe { s.control.initial_wfsys_reset() }.map_err(Error::Control)?;
        }
        s.control.stop_dma(true).map_err(Error::Control)?;
        s.control.mask_interrupts().map_err(Error::Control)?;
        s.control.verify_unused_queues().map_err(Error::Control)?;
        s.control
            .disable_global_translation()
            .map_err(Error::Control)?;
        let c3 = s.identity.chip == Chip::Mt7925;
        // Exact source order and complete layout; each returned mapping/queue
        // is retained before any subsequent fallible allocation/publication.
        s.data_tx = Some(
            unsafe {
                DataRing::install(
                    queue(tx_ring(0))?,
                    source,
                    domain.clone(),
                    2048,
                    s.identity.chip,
                )
            }
            .map_err(Error::Data)?,
        );
        s.control.initial_tx_ext().map_err(Error::Control)?;
        s.wm = Some(
            unsafe {
                TxRing::install(
                    queue(tx_ring(if c3 { 15 } else { 17 }))?,
                    source,
                    domain.clone(),
                    256,
                )
            }
            .map_err(Error::Ring)?,
        );
        s.fwdl = Some(
            unsafe { TxRing::install(queue(tx_ring(16))?, source, domain.clone(), 128) }
                .map_err(Error::Ring)?,
        );
        s.event = Some(
            unsafe {
                RxRing::install(
                    queue(rx_ring(0))?,
                    source,
                    domain.clone(),
                    if c3 { 512 } else { 8 },
                )
            }
            .map_err(Error::Ring)?,
        );
        if !c3 {
            s.runtime = Some(
                unsafe { RxRing::install(queue(rx_ring(4))?, source, domain.clone(), 512) }
                    .map_err(Error::Ring)?,
            );
        }
        s.data_rx = Some(
            unsafe { RxRing::install(queue(rx_ring(2))?, source, domain, 1536) }
                .map_err(Error::Ring)?,
        );
        unsafe { s.control.start_dma_polling() }.map_err(Error::Control)?;
        // All real selected queues and owners now precede actual enablement.
        // Constructor still requires the independently qualified fresh epoch.
        s.mailbox = Some(
            unsafe {
                Mailbox::from_rings_with_runtime_rx(
                    s.identity,
                    s.wm.take().unwrap(),
                    s.fwdl.take().unwrap(),
                    s.event.take().unwrap(),
                    s.runtime.take(),
                    s.control.clock,
                )
            }
            .map_err(Error::Mailbox)?,
        );
        s.phase = Phase::Queues;
        Ok(())
    }
    /// Actual NIC restart is one-way DMA completion, followed by real power
    /// observation and full bound download. The same private mailbox continues
    /// source sequence numbers; no public diagnostic can forge that permission.
    /// Consume the genuine initial WLAN sequencing epoch exactly once. This
    /// path issues no Bluetooth WMT or CONNV3 subsystem reset. Failure retains
    /// this function's uncertain resources and cannot be retried in this owner;
    /// it does not grant a caller shared power/reset or sibling recovery.
    pub fn boot(&mut self, prepared: &Prepared<'_>) -> Result<(), Error> {
        self.require(Phase::Queues)?;
        if *prepared.requests() != super::firmware::Requests::new(&self.state().identity) {
            return Err(Error::WrongFirmware);
        }
        let s = self.state_mut();
        s.phase = Phase::Quarantined;
        s.control
            .prepare_firmware(s.aspm.expect("qualified actual PCI ASPM state"))
            .map_err(Error::Control)?;
        let m = s.mailbox.as_mut().unwrap();
        let fact = m
            .initial(&Request::restart(s.identity.chip))
            .map_err(Error::Transport)?;
        s.facts.push(fact);
        s.control.poll_firmware_power_on().map_err(Error::Control)?;
        m.download_after_source_restart(prepared)
            .map_err(Error::Download)?;
        s.control.poll_n9_ready().map_err(Error::Control)?;
        s.capabilities = Some(m.query_capabilities().map_err(Error::Capabilities)?);
        s.eeprom = Some(m.query_encapsulation().map_err(Error::Eeprom)?);
        s.auxiliary = Some(prepared.retain_auxiliary());
        s.phase = Phase::Firmware;
        Ok(())
    }
    pub fn capabilities(&self) -> Option<&mailbox::CapabilityReport> {
        self.state()
            .capabilities
            .as_ref()
            .or_else(|| self.policy().map(Execution::capabilities))
    }
    /// # Safety
    /// Resource passed at construction genuinely retains all source-policy/
    /// stopped-radio authority required by Execution::prepare for these actual
    /// inputs and this exact downloaded image; none is inferred from raw NIC
    /// flags. The guard remains owned throughout partial/completed execution.
    pub unsafe fn execute_clc(&mut self, inputs: ClcInputs) -> Result<(), Error> {
        self.require(Phase::Firmware)?;
        let s = self.state_mut();
        s.phase = Phase::Quarantined;
        let p = unsafe {
            Execution::prepare(
                s.mailbox.as_ref().unwrap(),
                s.auxiliary.take().unwrap(),
                s.capabilities.take().unwrap(),
                s.eeprom.take().unwrap(),
                inputs,
                s.resource.clone(),
            )
        }
        .map_err(Error::Clc)?;
        s.policy = Some(p);
        s.phase = Phase::Quarantined;
        s.policy
            .as_mut()
            .unwrap()
            .execute(s.mailbox.as_mut().unwrap())
            .map_err(Error::Clc)?;
        s.phase = Phase::Clc;
        Ok(())
    }
    /// # Safety
    /// Same actual retained authority must meet Execution::prepare_remaining:
    /// consume real CLC reply restrictions first, resolve all genuine board/
    /// OS/SAR/per-rate limits, and retain/serialize their revocation. No defaults
    /// or policy provider are synthesized by this wire execution.
    pub unsafe fn execute_remaining(&mut self, inputs: remaining::Inputs<'_>) -> Result<(), Error> {
        self.require(Phase::Clc)?;
        let s = self.state_mut();
        unsafe {
            s.policy
                .as_mut()
                .unwrap()
                .prepare_remaining(s.mailbox.as_ref().unwrap(), inputs)
        }
        .map_err(Error::Remaining)?;
        s.phase = Phase::Quarantined;
        s.policy
            .as_mut()
            .unwrap()
            .execute_all(s.mailbox.as_mut().unwrap())
            .map_err(Error::Remaining)?;
        s.phase = Phase::Policy;
        Ok(())
    }
    /// # Safety
    /// The genuine source EEPROM/board override is resolved and retained in C
    /// before EFUSE mode. This initial profile excludes override images needing
    /// a different buffer mode. No live peer/WTBL/key users may exist.
    pub unsafe fn initialize_mac(&mut self) -> Result<(), Error> {
        self.require(Phase::Policy)?;
        let s = self.state_mut();
        s.phase = Phase::Quarantined;
        for request in [
            Request::firmware_log(s.identity.chip),
            Request::efuse_mode(s.identity.chip),
        ] {
            let fact = s
                .mailbox
                .as_mut()
                .unwrap()
                .initial(&request)
                .map_err(Error::Transport)?;
            s.facts.push(fact);
        }
        s.mac = Some(unsafe { s.control.initialize_mac_raw() }.map_err(Error::Control)?);
        if s.identity.chip != Chip::Mt7925 {
            let fact = s
                .mailbox
                .as_mut()
                .unwrap()
                .initial(&Request::rts(s.identity.chip))
                .map_err(Error::Transport)?;
            s.facts.push(fact);
        }
        s.phase = Phase::Mac;
        Ok(())
    }
    /// # Safety
    /// Current actual source-policy/OS intersection authorizes this exact
    /// initial non-MLO legacy20 channel and radio operations. C retains those
    /// real guards through queued/uncertain radio/firmware users and revocation.
    /// Raw policy command completion alone cannot satisfy this precondition.
    /// StartFacts remains separate from association, RF-kill/watchdog/event
    /// service, secure data admission and a guest Ethernet Link.
    pub unsafe fn start(
        &mut self,
        band: Band,
        channel: u8,
        frequency_mhz: u16,
    ) -> Result<(), Error> {
        self.require(Phase::Mac)?;
        if band == Band::Ghz6 {
            return Err(Error::UnsupportedBand);
        }
        super::mcu::bootstrap::validate_channel(band, channel, frequency_mhz)
            .map_err(Error::Codec)?;
        let s = self.state_mut();
        let p = s.policy.as_mut().ok_or(Error::MissingPolicy)?;
        let caps = p.capabilities().observed();
        if caps.chip_flags().unwrap_or(0) & 8 != 0 {
            return Err(Error::RequiredRfkill);
        }
        let antenna = caps
            .phy()
            .ok_or(Error::MissingCapabilities)?
            .antenna_mask()
            .map_err(|_| Error::MissingCapabilities)?;
        // Exact existing resolved domain membership, not a frequency formula
        // or power-array presence masquerading as trusted channel authority.
        if !p.initial_channel_present(band, channel) {
            return Err(Error::ChannelNotInDomain);
        }
        let c3 = s.identity.chip == Chip::Mt7925;
        let rxpath = if c3 {
            None
        } else {
            Some(
                Request::rx_path(s.identity.chip, band, channel, frequency_mhz, antenna)
                    .map_err(Error::Codec)?,
            )
        };
        s.phase = Phase::Quarantined;
        let m = s.mailbox.as_mut().unwrap();
        if !c3 {
            let f = m
                .initial(&Request::mac_enable(s.identity.chip, true).map_err(Error::Codec)?)
                .map_err(Error::Transport)?;
            s.facts.push(f);
        }
        p.start_domain(m).map_err(Error::Remaining)?;
        if let Some(r) = rxpath {
            let f = m.initial(&r).map_err(Error::Transport)?;
            s.facts.push(f);
            p.start_power(m).map_err(Error::Remaining)?;
        } else {
            let f = m
                .initial(&Request::rts(s.identity.chip))
                .map_err(Error::Transport)?;
            s.facts.push(f);
        }
        s.counters = Some(s.control.reset_mac_counters().map_err(Error::Control)?);
        s.counter_reset_ticks = Some(s.control.clock.now_us());
        if !c3 {
            for value in [1, 2] {
                let f = m
                    .initial(&Request::radio_led(s.identity.chip, value).map_err(Error::Codec)?)
                    .map_err(Error::Transport)?;
                s.facts.push(f);
            }
        }
        s.phase = Phase::StartFacts;
        Ok(())
    }
    /// # Safety
    /// C genuinely owns/reserves these actual initial interface BSS/OMAC/WMM/
    /// WCID indices for this requester, with the per-chip caller ordering and
    /// source selector documented by Interface::claim. No live prior owner or
    /// concurrent resource allocator exists. This helper implements the actual
    /// two-command registration; no peer/associated state is inferred.
    pub unsafe fn register_interface(
        &mut self,
        context: Context,
    ) -> Result<mailbox::device::Interface<Arc<C>>, Error> {
        if !matches!(self.phase(), Phase::Mac | Phase::StartFacts) {
            return Err(Error::WrongPhase);
        }
        let s = self.state_mut();
        let mut interface = unsafe {
            mailbox::device::Interface::claim(
                s.mailbox.as_ref().unwrap(),
                context,
                s.resource.clone(),
            )
        }
        .map_err(Error::Interface)?;
        let old = s.phase;
        s.phase = Phase::Quarantined;
        match interface.activate(s.mailbox.as_mut().unwrap()) {
            Ok(()) => {
                s.phase = old;
                Ok(interface)
            }
            Err(e) => Err(Error::Interface(e)),
        }
    }
    /// Actual source per-WCID disable, bound to an already acknowledged
    /// resource owner. It is not peer creation/association or format admission
    /// for any other slot. The interface itself retains its resources on Err.
    /// C3's actual WMWA generic completion is retained as raw evidence and
    /// returns UnvalidatedHeaderFormat; it cannot validate peer format or a
    /// ready/radio permission. Received translation always remains refused.
    /// # Safety
    /// The registered real Interface owns this actual peer WCID and serializes
    /// all WTBL/peer/key consumers, including through uncertain command error.
    /// For a peer slot this requires its actual source station installation;
    /// a BSS registration alone never creates that peer. Every future peer must
    /// receive its own real disable before raw80211 data admission.
    pub unsafe fn disable_peer_translation<T: 'static>(
        &mut self,
        interface: &mailbox::device::Interface<T>,
        wcid: u16,
        peer: bool,
    ) -> Result<(), Error> {
        if !matches!(self.phase(), Phase::Mac | Phase::StartFacts) {
            return Err(Error::WrongPhase);
        }
        let s = self.state_mut();
        let context: Context = interface.registered_context().ok_or(Error::WrongPhase)?;
        if !interface.belongs_to(s.mailbox.as_ref().unwrap()) {
            return Err(Error::WrongPhase);
        }
        let request =
            Request::raw_translation(s.identity.chip, context, wcid, peer).map_err(Error::Codec)?;
        s.facts.try_reserve(1).map_err(|_| Error::NoMemory)?;
        let old = s.phase;
        s.phase = Phase::Quarantined;
        let fact = s
            .mailbox
            .as_mut()
            .unwrap()
            .initial(&request)
            .map_err(Error::Transport)?;
        let rejected = match &fact {
            Fact::StationResult { status, .. } if *status != 0 => Some(*status),
            Fact::StationResult { .. } => None,
            Fact::GenericResponse(_) if s.identity.chip == Chip::Mt7925 => None,
            _ => unreachable!("source per-WCID completion"),
        };
        s.facts.push(fact);
        if let Some(status) = rejected {
            return Err(Error::FirmwareStatus(status));
        }
        if s.identity.chip == Chip::Mt7925 {
            // The strict WMWA source parser returns a generic transport fact.
            // It cannot establish a validated per-peer format or grant a
            // publication prerequisite. Preserve usable transport and raw
            // bytes, but leave this exact requirement explicitly incomplete.
            s.phase = old;
            return Err(Error::UnvalidatedHeaderFormat { wcid });
        }
        s.phase = old;
        Ok(())
    }
    /// Deliver actual MCU/TX-free/unsolicited frames to the real serialized
    /// event owner, including when no command is pending. This performs no
    /// guessed classification, token release, rfkill or watchdog servicing.
    pub fn poll_events(&mut self) -> Result<Vec<Frame>, Error> {
        if !matches!(
            self.phase(),
            Phase::Queues
                | Phase::Firmware
                | Phase::Clc
                | Phase::Policy
                | Phase::Mac
                | Phase::StartFacts
        ) {
            return Err(Error::WrongPhase);
        }
        let s = self.state_mut();
        let result = s
            .mailbox
            .as_mut()
            .unwrap()
            .poll_events()
            .map_err(Error::Mailbox);
        if result.is_err() {
            s.phase = Phase::Quarantined;
        }
        result
    }
    /// Drain one actual data descriptor chain for the vendor decoder/event
    /// owner. This grants no association, key, replay, channel or MSDU authority.
    pub fn poll_data(&mut self) -> Result<Option<Frame>, Error> {
        if !matches!(self.phase(), Phase::Mac | Phase::StartFacts) {
            return Err(Error::WrongPhase);
        }
        let s = self.state_mut();
        let result = (|| {
            let Some(fragment) = s.data_rx.as_mut().unwrap().poll().map_err(Error::Ring)? else {
                return Ok(None);
            };
            s.data_assembly.push(fragment).map_err(Error::Ring)
        })();
        if result.is_err() {
            s.phase = Phase::Quarantined;
        }
        result
    }
    /// # Safety
    /// Independent real source/policy/radio/firmware, PCIe DMA/IOTLB, every
    /// IRQ/deferred user and late response are stopped/cancelled/drained.
    /// Neither this controller's stop register nor a successful one-way command
    /// is sufficient. On failed mapping removal all real owners stay retained.
    pub unsafe fn retire_after_quiesce(&mut self) -> Result<(), Error> {
        let s = self.state_mut();
        s.phase = Phase::Quarantined;
        if let Some(m) = s.mailbox.as_mut() {
            unsafe { m.release_after_quiesce() }.map_err(Error::Ring)?;
        }
        if let Some(q) = s.data_tx.as_mut() {
            unsafe { q.release_after_quiesce() }.map_err(Error::Data)?;
        }
        for q in [&mut s.event, &mut s.runtime, &mut s.data_rx]
            .into_iter()
            .flatten()
        {
            unsafe { q.release_after_quiesce() }.map_err(Error::Ring)?;
        }
        for q in [&mut s.wm, &mut s.fwdl].into_iter().flatten() {
            unsafe { q.release_after_quiesce() }.map_err(Error::Ring)?;
        }
        if let Some(p) = s.policy.as_mut() {
            unsafe { p.retire_after_quiesce() };
        }
        s.phase = Phase::Retired;
        Ok(())
    }
}
impl<I: BarIo, Q: QueueIo, C: 'static> Drop for Controller<I, Q, C> {
    fn drop(&mut self) {
        if let Some(s) = self.owned.take()
            && !matches!(s.phase, Phase::Fresh | Phase::Retired)
        {
            core::mem::forget(s);
        }
    }
}
