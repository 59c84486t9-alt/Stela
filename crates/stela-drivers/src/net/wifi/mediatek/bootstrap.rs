// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
// Copyright (C) 2020-2023 MediaTek Inc.
//! Retained ordinary PCIe bootstrap, including every source selectable queue.
//! Actual protocol facts never publish an associated Link or qualify policy.
use super::{
    control::{self, Control, mac::MacInitialized, rx_ring, tx_ring},
    firmware::{Prepared, auxiliary::Auxiliary, clc::Inputs as ClcInputs},
    identity::{Chip, Identity},
    mailbox::{
        self, Mailbox,
        clc::{Execution, remaining},
        init::Fact,
    },
    mcu::{device::Context, init::Request},
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
    Codec(super::mcu::init::Error),
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
        // SAFETY: covered by this function's own safety contract.
        let io = unsafe { MmioBar::from_owned_window(base, bytes, owner.clone()) }
            .map_err(Error::Register)?;
        // SAFETY: covered by this function's own safety contract.
        let registers = unsafe { Registers::new(identity.chip, io) };
        // SAFETY: covered by this function's own safety contract.
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
        // SAFETY: covered by this function's own safety contract.
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
        // SAFETY: `Owned` is not zero-sized.
        let p = unsafe { alloc(Layout::new::<Owned<I, Q, C>>()) }.cast::<Owned<I, Q, C>>();
        if p.is_null() {
            return Err(Error::NoMemory);
        }
        // SAFETY: `p` is a fresh, non-null allocation for one `Owned`.
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
            // SAFETY: mt7925_pci_probe: actual driver-own, WFSYS reset, then DMA init.
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
            // SAFETY: covered by this function's own safety contract.
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
            // SAFETY: covered by this function's own safety contract.
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
            // SAFETY: covered by this function's own safety contract.
            unsafe { TxRing::install(queue(tx_ring(16))?, source, domain.clone(), 128) }
                .map_err(Error::Ring)?,
        );
        s.event = Some(
            // SAFETY: covered by this function's own safety contract.
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
                // SAFETY: covered by this function's own safety contract.
                unsafe { RxRing::install(queue(rx_ring(4))?, source, domain.clone(), 512) }
                    .map_err(Error::Ring)?,
            );
        }
        s.data_rx = Some(
            // SAFETY: covered by this function's own safety contract.
            unsafe { RxRing::install(queue(rx_ring(2))?, source, domain, 1536) }
                .map_err(Error::Ring)?,
        );
        // SAFETY: covered by this function's own safety contract.
        unsafe { s.control.start_dma_polling() }.map_err(Error::Control)?;
        // All real selected queues and owners now precede actual enablement.
        // Constructor still requires the independently qualified fresh epoch.
        s.mailbox = Some(
            // SAFETY: covered by this function's own safety contract.
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
        // SAFETY: covered by this function's own safety contract.
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
        // SAFETY: covered by this function's own safety contract.
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
        // SAFETY: covered by this function's own safety contract.
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
        super::mcu::init::validate_channel(band, channel, frequency_mhz).map_err(Error::Codec)?;
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
        // SAFETY: covered by this function's own safety contract.
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
            // SAFETY: covered by this function's own safety contract.
            unsafe { m.release_after_quiesce() }.map_err(Error::Ring)?;
        }
        if let Some(q) = s.data_tx.as_mut() {
            // SAFETY: covered by this function's own safety contract.
            unsafe { q.release_after_quiesce() }.map_err(Error::Data)?;
        }
        for q in [&mut s.event, &mut s.runtime, &mut s.data_rx]
            .into_iter()
            .flatten()
        {
            // SAFETY: covered by this function's own safety contract.
            unsafe { q.release_after_quiesce() }.map_err(Error::Ring)?;
        }
        for q in [&mut s.wm, &mut s.fwdl].into_iter().flatten() {
            // SAFETY: covered by this function's own safety contract.
            unsafe { q.release_after_quiesce() }.map_err(Error::Ring)?;
        }
        if let Some(p) = s.policy.as_mut() {
            // SAFETY: covered by this function's own safety contract.
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

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use crate::net::wifi::mediatek::mailbox::clc::{remaining::tests::*, tests::*};
    use crate::net::wifi::mediatek::{
        firmware::{
            Requests,
            tests::{catalog, patch_bytes},
        },
        identity::Chip,
        mailbox::tests::*,
        ring::{
            self, QueueIo,
            rx::tests::device_receive,
            tests::{Domain, Io, Memory, Source, State},
        },
    };
    use crate::net::wifi::{
        Band,
        mediatek::{
            bootstrap::{Controller, Error as BootError, Phase},
            control::Control,
            mcu::{domain, power},
            registers::{self, BarIo, Registers},
        },
    };
    use alloc::collections::BTreeMap;
    use alloc::{sync::Arc, vec::Vec};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    #[derive(Default)]
    pub(crate) struct DeviceBar {
        pub(crate) values: BTreeMap<u32, u32>,
        pub(crate) log: Vec<(u32, u32, u32)>,
        pub(crate) fail_at: Option<usize>,
        pub(crate) busy_wtbl: bool,
        pub(crate) ignore_global: bool,
        pub(crate) wfsys_cleared: bool,
        pub(crate) wfsys_no_ack: bool,
        pub(crate) fw: Option<Arc<Mutex<Response>>>,
    }
    #[derive(Clone)]
    pub(crate) struct Bar(pub(crate) Arc<Mutex<DeviceBar>>);
    unsafe impl BarIo for Bar {
        fn read32(&mut self, offset: u32) -> Result<u32, registers::Error> {
            let mut b = self.0.lock().unwrap();
            if offset == 0xe00f0
                && b.fw
                    .as_ref()
                    .is_some_and(|r| r.lock().unwrap().firmware_started)
            {
                b.values.insert(offset, 3);
            }
            let mut value = b.values.get(&offset).copied().unwrap_or(0);
            if b.busy_wtbl && matches!(offset, 0x34230 | 0x34380) {
                value |= 1 << 31;
            }
            b.log.push((0, offset, value));
            if b.fail_at == Some(b.log.len()) {
                return Err(registers::Error::AccessFailed);
            }
            Ok(value)
        }
        fn write32(&mut self, offset: u32, value: u32) -> Result<(), registers::Error> {
            let mut b = self.0.lock().unwrap();
            b.log.push((1, offset, value));
            if b.fail_at == Some(b.log.len()) {
                return Err(registers::Error::AccessFailed);
            }
            if b.ignore_global && matches!(offset, 0xf000 | 0xe800) {
                return Ok(());
            }
            // Device ownership handshake, not an echo of the host request.
            if offset == 0xe0010 {
                b.values.insert(offset, if value == 1 { 4 } else { 0 });
            } else if (0x40000..0x50000).contains(&offset)
                && b.values.get(&0xfe24c).copied().unwrap_or(0) & 0xffff == 0x1806
            {
                b.values.insert(offset, 0);
            } else if offset == 0xf0140 {
                if value & 1 == 0 {
                    b.wfsys_cleared = true;
                    b.values.insert(offset, value & !16);
                } else {
                    let ack = b.wfsys_cleared && !b.wfsys_no_ack;
                    b.values
                        .insert(offset, if ack { value | 16 } else { value & !16 });
                }
            } else {
                b.values.insert(offset, value);
            }
            Ok(())
        }
    }
    pub(crate) struct Q {
        pub(crate) inner: Inner,
        pub(crate) bar: Bar,
        pub(crate) offset: u32,
        pub(crate) runtime: ModelState,
        pub(crate) response: Arc<Mutex<Response>>,
    }
    pub(crate) enum Inner {
        Tx(DeviceIo),
        Rx(Io),
    }
    unsafe impl QueueIo for Q {
        fn configure(&mut self, address: u32, count: u16) -> Result<(), ring::Error> {
            {
                let mut b = self.bar.0.lock().unwrap();
                b.log.push((2, self.offset, address));
                b.values.insert(self.offset, address);
                b.values.insert(self.offset + 4, u32::from(count));
            }
            match &mut self.inner {
                Inner::Tx(q) => q.configure(address, count),
                Inner::Rx(q) => q.configure(address, count),
            }
        }
        fn device_index(&mut self) -> Result<u16, ring::Error> {
            match &mut self.inner {
                Inner::Tx(q) => q.device_index(),
                Inner::Rx(q) => q.device_index(),
            }
        }
        fn publish(&mut self, head: u16) -> Result<(), ring::Error> {
            self.bar
                .0
                .lock()
                .unwrap()
                .values
                .insert(self.offset + 8, u32::from(head));
            match &mut self.inner {
                Inner::Tx(q) => {
                    if self.response.lock().unwrap().firmware_started && q.chip != Chip::Mt7925 {
                        q.rx = self.runtime.clone();
                    }
                    q.publish(head)
                }
                Inner::Rx(q) => q.publish(head),
            }
        }
    }
    pub(crate) struct NativeGuard {
        pub(crate) model: Arc<Mutex<Response>>,
        pub(crate) bar: Bar,
        pub(crate) drops: Arc<AtomicUsize>,
    }
    impl Drop for NativeGuard {
        fn drop(&mut self) {
            let mut r = self.model.lock().unwrap();
            assert!(!r.clc_processing);
            assert_eq!(
                self.bar
                    .0
                    .lock()
                    .unwrap()
                    .values
                    .get(&0xd4208)
                    .copied()
                    .unwrap_or(0)
                    & 5,
                0
            );
            r.clc_guard = false;
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub(crate) type Native = Controller<Bar, Q, NativeGuard>;
    pub(crate) struct NativeFixture {
        pub(crate) controller: Native,
        pub(crate) model: Arc<Mutex<Response>>,
        pub(crate) bar: Bar,
        pub(crate) queues: BTreeMap<u32, ModelState>,
        pub(crate) drops: Arc<AtomicUsize>,
        pub(crate) memory: Arc<Mutex<Memory>>,
        pub(crate) chip: Chip,
    }
    impl NativeFixture {
        pub(crate) fn new(chip: Chip) -> Self {
            let model = Arc::new(Mutex::new(Response {
                capability_payload: Some(caps(chip, [true, true, false])),
                encapsulation_payload: Some(eeprom_body(chip, 0)),
                clc_payload: Some(clc_response(chip)),
                initial_execution: true,
                device_execution: true,
                require_firmware_start: true,
                clc_guard: true,
                ..Response::default()
            }));
            let bar = Bar(Arc::new(Mutex::new(DeviceBar {
                values: BTreeMap::from([(0xe00f0, 1)]),
                fw: Some(model.clone()),
                ..DeviceBar::default()
            })));
            let clock = model_clock();
            let control =
                unsafe { Control::new(Registers::new(chip, bar.clone()), clock) }.unwrap();
            let drops = Arc::new(AtomicUsize::new(0));
            let guard = Arc::new(NativeGuard {
                model: model.clone(),
                bar: bar.clone(),
                drops: drops.clone(),
            });
            let controller = Controller::claim(identity(chip), control, guard, None).unwrap();
            let memory = Arc::new(Mutex::new(Memory::default()));
            let queues = [
                0xd4300, 0xd43f0, 0xd4410, 0xd4400, 0xd4500, 0xd4540, 0xd4520,
            ]
            .into_iter()
            .map(|o| {
                (
                    o,
                    Arc::new(Mutex::new(State {
                        memory: memory.clone(),
                        ..State::default()
                    })),
                )
            })
            .collect();
            Self {
                controller,
                model,
                bar,
                queues,
                drops,
                memory,
                chip,
            }
        }
        pub(crate) fn install(&mut self) -> Result<(), BootError> {
            let domain: Arc<dyn crate::bus::dma::mapping::DmaDomain> =
                Arc::new(Domain(self.memory.clone()));
            let bar = self.bar.clone();
            let response = self.model.clone();
            let states = self.queues.clone();
            let chip = self.chip;
            let is_c3 = chip == Chip::Mt7925;
            unsafe {
                self.controller
                    .install_with(&Source, domain, false, move |offset| {
                        let state = states.get(&offset).unwrap().clone();
                        let inner = if offset == 0xd4400
                            || offset == if is_c3 { 0xd43f0 } else { 0xd4410 }
                        {
                            Inner::Tx(DeviceIo {
                                io: Io(state),
                                rx: states[&0xd4500].clone(),
                                chip,
                                reply: true,
                                wrong_seq: false,
                                delay: 3,
                                polls: 0,
                                pending_index: None,
                                fwdl: offset == 0xd4400,
                                response: response.clone(),
                            })
                        } else {
                            Inner::Rx(Io(state))
                        };
                        Ok(Q {
                            inner,
                            bar: bar.clone(),
                            offset,
                            runtime: states[&0xd4540].clone(),
                            response: response.clone(),
                        })
                    })
            }
        }
        pub(crate) fn boot(&mut self, chip: Chip) {
            let requests = Requests::new(&identity(chip));
            let provider = catalog(&requests, patch_bytes(), ram(&clc_bytes(chip)));
            let prepared = requests.load(&provider).unwrap();
            self.controller.boot(&prepared).unwrap();
        }
        pub(crate) fn policy(&mut self, chip: Chip) {
            self.policy_bands(chip, [true, true, false]);
        }
        pub(crate) fn policy_bands(&mut self, chip: Chip, enabled: [bool; 3]) {
            let chan: [Vec<domain::Channel>; 3] = core::array::from_fn(|i| {
                if enabled[i] {
                    domain_channels([Band::Ghz2, Band::Ghz5, Band::Ghz6][i])
                } else {
                    vec![]
                }
            });
            self.policy_channels(chip, enabled, chan);
        }
        pub(crate) fn policy_channels(
            &mut self,
            chip: Chip,
            enabled: [bool; 3],
            chan: [Vec<domain::Channel>; 3],
        ) {
            self.policy_channel_power(chip, enabled, chan, |_, _| power::Limits::uniform(-3));
        }
        pub(crate) fn policy_channel_power(
            &mut self,
            chip: Chip,
            enabled: [bool; 3],
            chan: [Vec<domain::Channel>; 3],
            mut limits: impl FnMut(Band, u8) -> power::Limits,
        ) {
            let flags = self
                .controller
                .capabilities()
                .unwrap()
                .observed()
                .chip_flags();
            unsafe { self.controller.execute_clc(inputs(flags)) }.unwrap();
            let bands: [Vec<power::Channel>; 3] = core::array::from_fn(|i| {
                if enabled[i] {
                    let band = [Band::Ghz2, Band::Ghz5, Band::Ghz6][i];
                    let mut rates = rates(chip, band);
                    for c in &mut rates {
                        c.limits = limits(band, c.hardware_value);
                    }
                    rates
                } else {
                    vec![]
                }
            });
            {
                let mut model = self.model.lock().unwrap();
                model.regulatory_expected_domain = Some(
                    domain::Request::build(
                        chip,
                        domain::Inputs {
                            alpha2: *b"US",
                            channels_2ghz: &chan[0],
                            channels_5ghz: &chan[1],
                            channels_6ghz: &chan[2],
                        },
                    )
                    .unwrap()
                    .body()
                    .to_vec(),
                );
                for (b, cs) in bands.iter().enumerate() {
                    for c in cs {
                        model.regulatory_expected_power.insert(
                            (b as u8 + 1, c.hardware_value),
                            c.limits.sku(chip, [Band::Ghz2, Band::Ghz5, Band::Ghz6][b]),
                        );
                    }
                }
            }
            unsafe {
                self.controller.execute_remaining(
                    crate::net::wifi::mediatek::mailbox::clc::remaining::Inputs {
                        domain: domain::Inputs {
                            alpha2: *b"US",
                            channels_2ghz: &chan[0],
                            channels_5ghz: &chan[1],
                            channels_6ghz: &chan[2],
                        },
                        power: power::Inputs {
                            alpha2: *b"US",
                            ghz2: enabled[0].then_some(&bands[0]),
                            ghz5: enabled[1].then_some(&bands[1]),
                            ghz6: enabled[2].then_some(&bands[2]),
                        },
                    },
                )
            }
            .unwrap();
        }
        pub(crate) fn retire(&mut self) {
            self.model.lock().unwrap().clc_processing = false;
            self.bar.0.lock().unwrap().values.insert(0xd4208, 0);
            unsafe { self.controller.retire_after_quiesce() }.unwrap();
        }
    }

    #[test]
    fn initial_mt7925_wfsys_ack_precedes_dma_stop_and_every_queue_publication() {
        let mut f = NativeFixture::new(Chip::Mt7925);
        f.bar.0.lock().unwrap().values.insert(0xf0140, 0xa5a50011);
        f.install().unwrap();
        {
            let b = f.bar.0.lock().unwrap();
            let own = b.log.iter().position(|v| *v == (0, 0xe0010, 0)).unwrap();
            let clear = b
                .log
                .iter()
                .position(|v| *v == (1, 0xf0140, 0xa5a50010))
                .unwrap();
            let set = b
                .log
                .iter()
                .position(|v| *v == (1, 0xf0140, 0xa5a50001))
                .unwrap();
            let ack = b
                .log
                .iter()
                .enumerate()
                .skip(set + 1)
                .find(|(_, v)| **v == (0, 0xf0140, 0xa5a50011))
                .unwrap()
                .0;
            let dma = b
                .log
                .iter()
                .position(|v| v.0 == 1 && v.1 == 0xd4208)
                .unwrap();
            let queue = b.log.iter().position(|v| v.0 == 2).unwrap();
            assert!(own < clear && clear < set && set < ack && ack < dma && dma < queue);
            assert_eq!(
                b.log.iter().filter(|v| v.0 == 1 && v.1 == 0xf0140).count(),
                2
            );
        }
        assert!(matches!(f.install(), Err(BootError::WrongPhase)));
        f.retire();
    }

    #[test]
    fn initial_wfsys_failure_retains_controller_before_any_dma_publication_or_retry() {
        for fail in [None, Some(3), Some(4), Some(5), Some(6), Some(7)] {
            let mut f = NativeFixture::new(Chip::Mt7925);
            {
                let mut b = f.bar.0.lock().unwrap();
                b.wfsys_no_ack = true;
                b.fail_at = fail;
            }
            assert!(matches!(f.install(), Err(BootError::Control(_))));
            assert_eq!(f.controller.phase(), Phase::Quarantined);
            assert!(f.memory.lock().unwrap().mappings.is_empty());
            assert!(f.queues.values().all(|q| q.lock().unwrap().count == 0));
            let count = {
                let b = f.bar.0.lock().unwrap();
                assert!(!b.log.iter().any(|v| v.0 == 2 || v.1 == 0xd4208));
                b.log.len()
            };
            assert!(matches!(f.install(), Err(BootError::WrongPhase)));
            assert_eq!(f.bar.0.lock().unwrap().log.len(), count);
            let drops = f.drops.clone();
            drop(f);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn complete_source_bootstrap_owns_all_queues_and_real_runtime_transition() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let mut f = NativeFixture::new(chip);
            f.install().unwrap();
            assert_eq!(f.controller.phase(), Phase::Queues);
            for (offset, count) in [
                (0xd4300, 2048),
                (
                    if chip == Chip::Mt7925 {
                        0xd43f0
                    } else {
                        0xd4410
                    },
                    256,
                ),
                (0xd4400, 128),
                (0xd4500, if chip == Chip::Mt7925 { 512 } else { 8 }),
                (0xd4520, 1536),
            ] {
                assert_eq!(f.queues[&offset].lock().unwrap().count, count);
            }
            assert_eq!(
                f.queues[&0xd4540].lock().unwrap().count,
                if chip == Chip::Mt7925 { 0 } else { 512 }
            );
            {
                let memory = f.memory.lock().unwrap();
                let mut end = 0;
                for (&a, (pins, _, _)) in &memory.mappings {
                    assert!(a >= end);
                    end = a + pins.bytes() as u64;
                }
            }
            f.boot(chip);
            assert_eq!(f.controller.phase(), Phase::Firmware);
            assert_eq!(f.controller.facts().len(), 1);
            assert!(matches!(
                f.controller.facts()[0],
                crate::net::wifi::mediatek::mailbox::init::Fact::OneWayDmaCompleted {
                    kind: crate::net::wifi::mediatek::mcu::init::Kind::Restart,
                    sequence: 1
                }
            ));
            assert!(
                f.controller
                    .mailbox()
                    .unwrap()
                    .download_binding()
                    .unwrap()
                    .outcome()
                    .firmware_start_acknowledged
            );
            if chip != Chip::Mt7925 {
                assert!(f.queues[&0xd4540].lock().unwrap().index > 0);
            }
            f.policy(chip);
            assert_eq!(f.controller.phase(), Phase::Policy);
            unsafe { f.controller.initialize_mac() }.unwrap();
            let mac = f.controller.mac_observations().unwrap();
            assert_eq!(mac.wtbl.len(), 20);
            assert_eq!(mac.global_format.value & (1 << 19), 0);
            assert_eq!(
                mac.fixed_rate_entries,
                if chip == Chip::Mt7925 { 12 } else { 0 }
            );
            let n = f.model.lock().unwrap().clc_commands.len();
            unsafe { f.controller.start(Band::Ghz5, 36, 5180) }.unwrap();
            assert_eq!(f.controller.phase(), Phase::StartFacts);
            assert_eq!(f.model.lock().unwrap().clc_commands.len(), n);
            assert_eq!(
                f.controller.policy().unwrap().start_facts().len(),
                if chip == Chip::Mt7925 {
                    1
                } else {
                    1 + f.controller.policy().unwrap().remaining_facts().len() - 1
                }
            );
            let wm = if chip == Chip::Mt7925 {
                0xd43f0
            } else {
                0xd4410
            };
            let published = f.queues[&wm].lock().unwrap().completed.clone();
            let cmd = |p: &Vec<u8>| {
                if p[43] & 2 != 0 {
                    (p[34], 0xff)
                } else {
                    (p[36], p[41])
                }
            };
            let domain = published
                .iter()
                .rposition(|p| {
                    cmd(p)
                        == if chip == Chip::Mt7925 {
                            (0x15, 0xff)
                        } else {
                            (0x0f, 0)
                        }
                })
                .unwrap();
            if chip == Chip::Mt7925 {
                let rts = published.iter().rposition(|p| cmd(p) == (8, 0xff)).unwrap();
                assert!(domain < rts);
            } else {
                let mac = published
                    .iter()
                    .position(|p| cmd(p) == (0xed, 0x46))
                    .unwrap();
                let path = published
                    .iter()
                    .position(|p| cmd(p) == (0xed, 0x4e))
                    .unwrap();
                let first_power = published
                    .iter()
                    .enumerate()
                    .find(|(i, p)| *i > domain && cmd(p) == (0x5d, 0))
                    .unwrap()
                    .0;
                let leds = published
                    .iter()
                    .enumerate()
                    .filter(|(_, p)| cmd(p) == (0xed, 5))
                    .map(|(i, _)| i)
                    .collect::<Vec<_>>();
                assert!(
                    mac < domain
                        && domain < path
                        && path < first_power
                        && first_power < leds[0]
                        && leds[0] < leds[1]
                );
            }
            assert!(unsafe { f.controller.start(Band::Ghz5, 36, 5180) }.is_err());
            f.retire();
            let drops = f.drops.clone();
            drop(f);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn partial_mac_and_initial_publication_failures_retain_actual_guard_and_context() {
        for chip in [Chip::Mt7921, Chip::Mt7925] {
            for fail in [0, 1] {
                let mut f = NativeFixture::new(chip);
                f.install().unwrap();
                f.boot(chip);
                f.policy(chip);
                if fail == 0 {
                    f.bar.0.lock().unwrap().busy_wtbl = true;
                } else {
                    let mut m = f.model.lock().unwrap();
                    m.initial_fail_at = Some(m.initial_commands.len() + 1);
                }
                assert!(unsafe { f.controller.initialize_mac() }.is_err());
                assert_eq!(f.controller.phase(), Phase::Quarantined);
                let drops = f.drops.clone();
                drop(f);
                assert_eq!(drops.load(Ordering::Relaxed), 0);
            }
        }
    }
    #[test]
    fn dormant_foreign_queue_is_refused_before_any_dma_publication() {
        let mut f = NativeFixture::new(Chip::Mt7925);
        f.bar.0.lock().unwrap().values.insert(0xd4514, 17);
        assert!(matches!(
            f.install(),
            Err(BootError::Control(
                crate::net::wifi::mediatek::control::Error::Readback {
                    address: 0xd4514,
                    ..
                }
            ))
        ));
        assert!(f.memory.lock().unwrap().mappings.is_empty());
        let drops = f.drops.clone();
        drop(f);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn actual_global_and_source_per_wcid_controls_match_receive_format() {
        use crate::net::wifi::mediatek::{mcu::device::Context, rx};
        for chip in [Chip::Mt7921, Chip::Mt7925] {
            let mut f = NativeFixture::new(chip);
            f.install().unwrap();
            f.boot(chip);
            f.policy(chip);
            unsafe { f.controller.initialize_mac() }.unwrap();
            let context = Context {
                bss_index: 0,
                omac_index: 0,
                band_index: if chip == Chip::Mt7925 { 0xff } else { 0 },
                wmm_index: 0,
                link_index: 0,
                broadcast_wcid: 19,
                address: crate::net::Mac([2, 1, 2, 3, 4, 5]),
            };
            // Explicit independent peer-lifetime boundary: a qualified model
            // owner reserves an already established WCID1. This bootstrap does
            // not implement or claim that missing association/STA installation.
            f.model.lock().unwrap().qualified_peer_slots.insert(1);
            if chip == Chip::Mt7925 {
                f.model.lock().unwrap().status = 0xdeadbeef;
            }
            let interface = unsafe { f.controller.register_interface(context) }.unwrap();
            let disabled = unsafe { f.controller.disable_peer_translation(&interface, 1, true) };
            if chip == Chip::Mt7925 {
                assert!(matches!(
                    disabled,
                    Err(BootError::UnvalidatedHeaderFormat { wcid: 1 })
                ));
            } else {
                disabled.unwrap();
            }
            assert!(f.model.lock().unwrap().raw_disabled.contains(&1));
            if chip == Chip::Mt7925 {
                assert!(
                    matches!(f.controller.facts().last(),Some(crate::net::wifi::mediatek::mailbox::init::Fact::GenericResponse(r)) if r.frame.bytes.ends_with(&0xdeadbeefu32.to_le_bytes()))
                );
            }

            let global = f.controller.mac_observations().unwrap().global_format.value;
            let base = if chip == Chip::Mt7925 { 32 } else { 24 };
            for wcid in [1u16, 2] {
                // Device chooses actual descriptor format from both independently
                // applied controls. An unconfigured peer stays explicit foreign.
                let translated = global & (1 << 19) != 0
                    || !f.model.lock().unwrap().raw_disabled.contains(&wcid);
                let mut bytes = vec![0; base + 24];
                let len = bytes.len() as u32;
                bytes[..4].copy_from_slice(&(len | (2 << 27)).to_le_bytes());
                bytes[4..8].copy_from_slice(&u32::from(wcid).to_le_bytes());
                if translated {
                    bytes[8..12].copy_from_slice(
                        &(1u32 << if chip == Chip::Mt7925 { 7 } else { 13 }).to_le_bytes(),
                    );
                }
                bytes[12..16].copy_from_slice(&(36u32 << 8).to_le_bytes());
                bytes[base] = 8;
                device_receive(&f.queues[&0xd4520], &bytes, true, 0);
                let frame = f.controller.poll_data().unwrap().unwrap();
                if translated {
                    assert!(matches!(
                        rx::decode(chip, &frame.bytes),
                        Err(rx::Error::UnsupportedTranslation)
                    ));
                } else {
                    let decoded = rx::decode(chip, &frame.bytes).unwrap();
                    assert_eq!(decoded.wcid, 1);
                    assert_eq!(decoded.payload, &bytes[base..]);
                }
            }
            // An actual interface deactivation/drain is required to free it. This
            // test deliberately drops a live resource: its real guard is retained
            // even after the separately qualified controller/radio teardown.
            drop(interface);
            f.retire();
            let drops = f.drops.clone();
            drop(f);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
        }
    }
    #[test]
    #[ignore = "requires unchanged bootstrap helpers/writers and complete MAC oracle"]
    fn composed_bootstrap_matches_source_mac_effects_and_all_initial_packet_bytes() {
        let root =
            std::path::PathBuf::from(std::env::var("STELA_MT792X_BOOTSTRAP_ORACLE").unwrap());
        for (chip, id) in [
            (Chip::Mt7921, 7921),
            (Chip::Mt7922, 7922),
            (Chip::Mt7925, 7925),
        ] {
            for seed in 0u32..=16 {
                let trace = std::fs::read(root.join(if seed == 0 {
                    alloc::format!("{id}-mac.trace")
                } else {
                    alloc::format!("{id}-mac-{seed}.trace")
                }))
                .unwrap();
                let n = u32::from_le_bytes(trace[..4].try_into().unwrap()) as usize;
                assert_eq!(trace.len(), 4 + n * 12);
                let mut source = trace[4..]
                    .as_chunks::<12>()
                    .0
                    .iter()
                    .map(|r| {
                        (
                            u32::from_le_bytes(r[..4].try_into().unwrap()),
                            u32::from_le_bytes(r[4..8].try_into().unwrap()),
                            u32::from_le_bytes(r[8..].try_into().unwrap()),
                        )
                    })
                    .filter(|r| r.0 != 2)
                    .collect::<Vec<_>>();
                let initial = |offset: u32| {
                    if seed == 0 {
                        0
                    } else {
                        offset.wrapping_mul(0x10203) ^ seed.wrapping_mul(0x9e3779b9)
                    }
                };
                let mut f = NativeFixture::new(chip);
                f.install().unwrap();
                f.boot(chip);
                f.policy(chip);
                {
                    let mut bar = f.bar.0.lock().unwrap();
                    for (_, offset, _) in &source {
                        let mut value = initial(*offset);
                        if matches!(*offset, 0x34230 | 0x34380) {
                            value &= !(1 << 31);
                        }
                        bar.values.insert(*offset, value);
                    }
                    bar.log.clear();
                }
                unsafe { f.controller.initialize_mac() }.unwrap();
                let mut native = f.bar.0.lock().unwrap().log.clone();
                let global = if chip == Chip::Mt7925 { 0xe800 } else { 0xf000 };
                let with_deagg = initial(global) | (1 << 15);
                assert_eq!(native.pop(), Some((0, global, with_deagg & !(1 << 19))));
                if chip == Chip::Mt7925 {
                    assert_eq!(
                        native.drain(4..6).collect::<Vec<_>>(),
                        vec![
                            (0, global, with_deagg),
                            (1, global, with_deagg & !(1 << 19))
                        ]
                    );
                }
                let counters = source.split_off(source.len() - 15);
                if chip != Chip::Mt7925 {
                    assert_eq!(source[5], (1, global, with_deagg | (1 << 19)));
                    source[5].2 &= !(1 << 19);
                }
                assert_eq!(native, source, "complete source MAC {chip:?} seed{seed}");
                f.bar.0.lock().unwrap().log.clear();
                unsafe { f.controller.start(Band::Ghz5, 36, 5180) }.unwrap();
                assert_eq!(f.bar.0.lock().unwrap().log, counters);
                let trace =
                    std::fs::read(root.join(alloc::format!("{id}-commands.trace"))).unwrap();
                let mut at = 0;
                let mut source = Vec::<Vec<u8>>::new();
                while at < trace.len() {
                    let n = u16::from_le_bytes(trace[at + 5..at + 7].try_into().unwrap()) as usize;
                    at += 7 + n;
                    let n = u16::from_le_bytes(trace[at..at + 2].try_into().unwrap()) as usize;
                    at += 2;
                    source.push(trace[at..at + n].to_vec());
                    at += n;
                }
                for actual in &f.model.lock().unwrap().initial_commands {
                    assert!(
                        source.iter().any(|expected| {
                            let mut expected = expected.clone();
                            expected[39] = actual[39];
                            expected == *actual
                        }),
                        "actual source packet {chip:?} {:02x?}",
                        actual
                    );
                }
                f.retire();
            }
        }
    }
    #[test]
    #[ignore = "requires the exact six redistributable source firmware images"]
    fn all_actual_images_boot_the_full_native_layout_before_source_initialization() {
        let images = std::path::PathBuf::from(std::env::var("STELA_MT792X_FIRMWARE").unwrap());
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let mut f = NativeFixture::new(chip);
            f.install().unwrap();
            let requests = Requests::new(&identity(chip));
            let provider = catalog(
                &requests,
                std::fs::read(images.join(chip.patch_name())).unwrap(),
                std::fs::read(images.join(chip.ram_name())).unwrap(),
            );
            let prepared = requests.load(&provider).unwrap();
            f.controller.boot(&prepared).unwrap();
            drop(prepared);
            drop(provider);
            assert!(
                f.controller
                    .mailbox()
                    .unwrap()
                    .download_binding()
                    .unwrap()
                    .outcome()
                    .firmware_start_acknowledged
            );
            f.policy(chip);
            unsafe { f.controller.initialize_mac() }.unwrap();
            unsafe { f.controller.start(Band::Ghz5, 36, 5180) }.unwrap();
            f.retire();
        }
    }
    #[test]
    fn independent_rom_and_runtime_fragment_streams_never_concatenate() {
        let mut f = NativeFixture::new(Chip::Mt7921);
        f.install().unwrap();
        device_receive(&f.queues[&0xd4500], &[0xaa, 0xab], false, 0);
        device_receive(&f.queues[&0xd4540], &[0xbb, 0xbc], true, 0);
        let events = f.controller.poll_events().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].bytes, [0xbb, 0xbc]);
        device_receive(&f.queues[&0xd4500], &[0xac, 0xad], true, 0);
        let events = f.controller.poll_events().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].bytes, [0xaa, 0xab, 0xac, 0xad]);
        f.retire();
    }
    #[test]
    fn missing_live_rfkill_service_refuses_start_before_any_radio_command() {
        for chip in [Chip::Mt7921, Chip::Mt7925] {
            let mut f = NativeFixture::new(chip);
            {
                let mut m = f.model.lock().unwrap();
                let p = m.capability_payload.as_mut().unwrap();
                let n = p.len();
                p[n - 8..].copy_from_slice(&9u64.to_le_bytes());
            }
            f.install().unwrap();
            f.boot(chip);
            f.policy(chip);
            unsafe { f.controller.initialize_mac() }.unwrap();
            let count = f.model.lock().unwrap().initial_commands.len();
            let reg = f.model.lock().unwrap().regulatory_commands.len();
            assert!(matches!(
                unsafe { f.controller.start(Band::Ghz5, 36, 5180) },
                Err(BootError::RequiredRfkill)
            ));
            assert_eq!(f.controller.phase(), Phase::Mac);
            assert_eq!(f.model.lock().unwrap().initial_commands.len(), count);
            assert_eq!(f.model.lock().unwrap().regulatory_commands.len(), reg);
            f.retire();
        }
    }
    #[test]
    fn wrong_prepared_input_refuses_before_restart_or_firmware_mutation() {
        let mut f = NativeFixture::new(Chip::Mt7921);
        f.install().unwrap();
        let r = Requests::new(&identity(Chip::Mt7925));
        let provider = catalog(&r, patch_bytes(), ram(&clc_bytes(Chip::Mt7925)));
        let p = r.load(&provider).unwrap();
        assert!(matches!(
            f.controller.boot(&p),
            Err(BootError::WrongFirmware)
        ));
        assert_eq!(f.controller.phase(), Phase::Queues);
        assert!(f.model.lock().unwrap().initial_commands.is_empty());
        f.retire();
    }
}
