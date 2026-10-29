//! The Apple T8112 device models (`platform::apple`) as the engine's
//! [`Devices`]: one [`Bus`] for the guest physical address space, an
//! [`InterruptLatch`] for the wires, AIC input forwarding and reset requests.
//! The models own every register decision; this adapter only routes accesses
//! and time, and turns each `MmioError` into an explicit refusal.
pub mod t6000_pmgr;

pub use crate::platform::apple::pmu::RtcEpoch;
use crate::platform::usb::{
    Function, Speed,
    ecm::Ecm,
    hid::Peripheral,
    hub::{self, Hub},
    session::Session as UsbSession,
    storage::MassStorage,
};
pub use crate::platform::usb::{
    ecm::Counters as UsbNetworkCounters,
    host::{Descriptor as UsbDescriptor, MuxEndpoints},
    mux::{State as MuxState, StreamId as MuxStream, StreamState as MuxStreamState},
    session::Log as UsbLog,
};
use alloc::{boxed::Box, format, string::String, vec, vec::Vec};
use core::cell::Cell;
use stela_compiler::aarch64::system::registers::Encoding;
use stela_drivers::{block::BlockDevice, input::Input, net::Mac};
use stela_engine::machine::engine::ConsumedPair;
use stela_engine::machine::engine::DeviceError;
use stela_engine::machine::engine::Devices;
use stela_engine::machine::engine::Memory;
use stela_engine::machine::engine::Reset;
use stela_engine::machine::engine::Start;
use stela_engine::machine::engine::Transition;
use stela_engine::machine::registers::Lines;
use stela_engine::system::access::AccessKind;
use stela_soc_data::board::PowerOwner;

use crate::platform::apple::aes;
use crate::platform::apple::aes::Aes;
use crate::platform::apple::agx::firmware::Coprocessor as GfxCoprocessor;
use crate::platform::apple::agx::sgx::Sgx;
use crate::platform::apple::agx::uat;
use crate::platform::apple::agx::uat::Agent;
use crate::platform::apple::aic::Aic2;
use crate::platform::apple::aic1::Aic1;
use crate::platform::apple::amcc::Amcc;
use crate::platform::apple::ans;
use crate::platform::apple::ans::Ans;
use crate::platform::apple::asc;
use crate::platform::apple::asc::Asc;
use crate::platform::apple::atc_phy;
use crate::platform::apple::atc_phy::AtcPhy;
use crate::platform::apple::bridge::Bridge;
use crate::platform::apple::cluster;
use crate::platform::apple::cluster::Cluster;
use crate::platform::apple::core_counters::CoreCounters;
use crate::platform::apple::coresight;
use crate::platform::apple::coresight::PcSampler;
use crate::platform::apple::coresight::SoftwareLock;
use crate::platform::apple::cpm::Cpm;
use crate::platform::apple::cpustart::CpuStart;
use crate::platform::apple::dart;
use crate::platform::apple::dart::Dart;
use crate::platform::apple::dcp;
use crate::platform::apple::display as display_hw;
use crate::platform::apple::dpe::Dpe;
use crate::platform::apple::dwc3;
use crate::platform::apple::dwc3::Dwc3;
use crate::platform::apple::dwc3::PortState;
use crate::platform::apple::energy;
use crate::platform::apple::energy::Energy;
use crate::platform::apple::fuse;
use crate::platform::apple::fuse::AonFuses;
use crate::platform::apple::gpio::Gpio;
use crate::platform::apple::gpio::Net;
use crate::platform::apple::gpio::OpenDrain;
use crate::platform::apple::hpm::Firmware;
use crate::platform::apple::hpm::Hpm;
use crate::platform::apple::hpm::Summary;
use crate::platform::apple::i2c;
use crate::platform::apple::i2c::I2c;
use crate::platform::apple::ipi;
use crate::platform::apple::ipi::Affinity;
use crate::platform::apple::ipi::FastIpi;
use crate::platform::apple::lockdown;
use crate::platform::apple::lockdown::Lockdown;
use crate::platform::apple::perf::PerfCounters;
use crate::platform::apple::pmgr::ACTIVE;
use crate::platform::apple::pmgr::DomainState;
use crate::platform::apple::pmgr::POWER_GATED;
use crate::platform::apple::pmgr::Pmgr;
use crate::platform::apple::pmgr::PowerState;
use crate::platform::apple::pmp;
use crate::platform::apple::pmu;
use crate::platform::apple::pmu::Pmu;
use crate::platform::apple::power::Power;
use crate::platform::apple::rtkit::RtKit;
use crate::platform::apple::sart;
use crate::platform::apple::sart::Sart;
use crate::platform::apple::sep;
use crate::platform::apple::sep::Sep;
use crate::platform::apple::smc;
use crate::platform::apple::smc::Smc;
use crate::platform::apple::spi::Spi;
use crate::platform::apple::spmi::Spmi;
use crate::platform::apple::uart::S5lUart;
use crate::platform::apple::wake;
use crate::platform::apple::wake::WakeMasks;
use crate::platform::apple::wdt;
use crate::platform::apple::wdt::AppleWdt;
use stela_contracts::bus::Access;
use stela_contracts::bus::Bus;
use stela_contracts::bus::DeviceId;
use stela_contracts::bus::LifecycleState;
use stela_contracts::bus::MapError;
use stela_contracts::bus::MmioDevice;
use stela_contracts::bus::MmioError;
use stela_contracts::bus::Width;
use stela_contracts::interrupt::CpuIndex;
use stela_contracts::interrupt::InterruptLatch;
use stela_soc_data::aic::Aic2Config;
use stela_soc_data::pmgr::coverage;
use stela_soc_data::pmgr::coverage::Consumer;
use stela_soc_data::pmgr::coverage::LifecycleSinks;
use {stela_contracts::dma::Physical, stela_contracts::dma::Port};

mod canonical_reads;
mod canonical_writes;
mod display_resources;
pub mod memory_resources;
mod pmp_dma;
mod pmp_services;
pub use pmp_dma::{ExplicitRuntimeConfiguration, SourceProvenance};
mod processor_power;
mod service;
mod sleep;
mod t8112_memory;
pub use service::{AicDelivery, ServiceBatch, ServiceInput};
pub use sleep::PowerLog;
pub use t8112_memory::cold as t8112_cold;

#[cfg(test)]
use stela_soc_data::aic::AIC1_EVENT;
use stela_soc_data::aic::AicLayout;
pub use {
    crate::platform::apple::asc::Lines as AscLines, crate::platform::apple::dcp::Log as DisplayLog,
    crate::platform::apple::nor, crate::platform::apple::pmp::native as native_pmp,
    crate::platform::apple::pmp::native::services::Clock as NativePmpClock,
    crate::platform::apple::scanout::ChannelMasks as ScanoutMasks,
    crate::platform::apple::scanout::Mode as ScanoutMode,
    crate::platform::apple::scanout::PixelFormat as ScanoutFormat,
    crate::platform::apple::scanout::Scanout, crate::platform::apple::sep::Entropy as SepEntropy,
    crate::platform::apple::sep::image::signature::Evidence as SepSignatureEvidence,
    crate::platform::apple::sep::image::signature::ManifestEvidence as SepManifestEvidence,
    crate::platform::apple::sep::image::signature::inspect as inspect_sep_signature,
    crate::platform::apple::sep::image::signature::verify_manifest as verify_sep_manifest_signature,
    crate::platform::apple::sep::state as sep_state,
    crate::platform::apple::smc::WriteLog as SmcWriteLog, crate::platform::apple::typec,
    crate::platform::apple::uart::ConsoleBusy, crate::platform::apple::uart::ConsoleSink,
    stela_contracts::interrupt::AicInput,
};

/// One guest physical range of a device: DeviceTree `reg` translated
/// through the parent `ranges`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub physical: u64,
    pub bytes: u64,
}

pub struct AppleDevices {
    bus: Bus,
    latch: InterruptLatch,
    aic: Option<Controller>,
    reset: Option<Reset>,
    service: ServiceBatch,
    memory_controller: Option<DeviceId>,
    /// DCS/PTD storage is separate from the AMCC lock controller.
    memory_publication: Option<DeviceId>,
    ipi: Option<FastIpi>,
    masters: Vec<Master>,
    coprocessors: Vec<(&'static str, DeviceId)>,
    /// The SPI controller holding the NOR die.
    nor: Option<DeviceId>,
    storage_masters: Vec<(DeviceId, DeviceId)>,
    /// The GFX coprocessor's ASC and the `sgx` block whose UAT it masters
    /// memory through.
    gfx_masters: Vec<(DeviceId, DeviceId)>,
    sep_masters: Vec<SepMaster>,
    dcp_masters: Vec<DcpMaster>,
    /// One wired-OR owner per physical DART input, across logical groups.
    dart_irqs: Vec<(AicInput, dart::SharedIrq)>,
    usb_masters: Vec<UsbMaster>,
    cpu_start: Option<CpuStarter>,
    reset_vectors: Vec<Option<DeviceId>>,
    /// Each PE's CLPC sampler counters (`platform::apple::core_counters`),
    /// by PE number.
    core_counters: Vec<Option<DeviceId>>,
    pc_samplers: Vec<(usize, u64, DeviceId)>,
    starts: Vec<Start>,
    selects: Vec<SelectWire>,
    /// The AP GPIO bank's base and the board nets on its input pins.
    gpio: Option<(u64, Vec<(u32, Net)>)>,
    /// The other GPIO banks' phandles and the board nets on their client
    /// pins.
    aux_gpios: Vec<(u32, Vec<(u32, Net)>)>,
    typec_ports: Vec<(u32, typec::Port)>,
    phys: Vec<PhyBinding>,
    pmgr: Option<DeviceId>,
    power_clients: Vec<PowerClient>,
    power_devices: Vec<PowerDevice>,
    power_refusals: Vec<(u64, String)>,
    power_configured: bool,
    processor_power: Option<processor_power::AssignedPower>,
    native_pmp_dma: Option<pmp_dma::PmpDma>,
    native_pmp_services: Option<pmp_services::NativePmpServices>,
    /// The SoC's sleep and wake (`sleep`).
    sleep: sleep::SocSleep,
    rtc_clock: Option<pmu::RtcClock>,
    /// Every PMU's oscillator, the RTC's among them.
    pmu_clocks: Vec<pmu::RtcClock>,
    /// The latest count a board entry was given, and the entry; the first
    /// entry given an earlier count, with it, for the stop it causes.
    time_seen: Cell<(u64, &'static str)>,
    time_regression: Cell<Option<[(u64, &'static str); 2]>>,
}

/// The host polls its USB sessions once a high-speed microframe, in which
/// a bulk pipe moves at most 13 512-byte packets (USB 2.0 Table 5-10).
const USB_POLL_TICKS: u64 = 24_000_000 / 8000;
const USB_PACKETS_PER_MICROFRAME: usize = 13;
/// A native host handle, owned by this AppleDevices instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbId(DeviceId);
struct PhyBinding {
    phandle: u32,
    port: u32,
    device: DeviceId,
    retention: bool,
    pipe: Option<(u64, u64)>,
    events: (u64, u64),
}
struct UsbMaster {
    device: DeviceId,
    phy: DeviceId,
    phy_changed: bool,
    dart: DeviceId,
    stream: usize,
    session: UsbSession,
    port: UsbPort,
    /// The Type-C connector's `port-number` and shared cable state.
    number: u32,
    connector: typec::Port,
    /// The hub cabled to the connector, with the input peripheral and the
    /// host's disks behind it, when this port is the downstream-facing
    /// (host) side.
    peripheral: Option<Hub<Attachments>>,
    next_poll: u64,
    attached: bool,
    epoch: u64,
    retention: bool,
    session_reset: bool,
}
impl UsbMaster {
    fn cancel_session(&mut self, reset: bool) -> Result<(), &'static str> {
        self.session_reset |= reset;
        if self.session_reset {
            self.session.detach()?;
            self.attached = false;
            self.next_poll = 0;
            self.session_reset = false;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct UsbPort {
    generation: u64,
    ready: bool,
}
impl UsbPort {
    /// Device-mode readiness from the connector: attached as UFP with VBUS.
    fn of(connector: &typec::Port) -> Self {
        let snapshot = connector.snapshot();
        Self {
            generation: snapshot.generation,
            ready: snapshot
                .connection
                .is_some_and(|c| c.role == typec::DataRole::Ufp && c.vbus),
        }
    }
}
/// The USB2 function a downstream-facing attach with VBUS cables to the
/// host personality, by its speed.
/// What the native hub carries besides the keyboard and pointer.
#[derive(Default)]
pub struct UsbCables {
    /// Host disks, each a USB mass storage device (at most five with a
    /// network adapter, six without).
    pub disks: Vec<Box<dyn BlockDevice>>,
    /// A USB Ethernet adapter with this station address.
    pub network: Option<Mac>,
}

impl UsbCables {
    /// The disks the hub has ports for beside the keyboard and pointer and,
    /// with `network`, the Ethernet adapter.
    pub const fn disk_ports(network: bool) -> usize {
        hub::MAX_PORTS - 1 - network as usize
    }
}

/// The functions on the native hub's ports: the keyboard and pointer on
/// port 1, the Ethernet adapter on port 2 when there is one, then one mass
/// storage device per host disk.
struct Attachments {
    input: Peripheral,
    network: Option<Ecm>,
    disks: Vec<MassStorage>,
}

impl Attachments {
    fn port(&mut self, port: usize) -> &mut dyn Function {
        let first_disk = 1 + usize::from(self.network.is_some());
        match (port, &mut self.network) {
            (0, _) => &mut self.input,
            (1, Some(network)) => network,
            (n, _) => &mut self.disks[n - first_disk],
        }
    }
}

impl hub::Ports for Attachments {
    fn count(&self) -> usize {
        1 + usize::from(self.network.is_some()) + self.disks.len()
    }
    fn speed(&self, port: usize) -> Speed {
        if port == 0 { Speed::Full } else { Speed::High }
    }
    fn function(&mut self, port: usize) -> &mut dyn Function {
        self.port(port)
    }
    fn function_ref(&self, port: usize) -> &dyn Function {
        let first_disk = 1 + usize::from(self.network.is_some());
        match (port, &self.network) {
            (0, _) => &self.input,
            (1, Some(network)) => network,
            (n, _) => &self.disks[n - first_disk],
        }
    }
}

fn host_function(connector: &typec::Port) -> Option<typec::Usb2Speed> {
    connector
        .snapshot()
        .connection
        .filter(|c| c.role == typec::DataRole::Dfp && c.vbus)
        .map(|c| c.speed)
}

impl PortState for UsbPort {
    fn generation(&self) -> u64 {
        self.generation
    }
    fn high_speed_device_ready(&self) -> bool {
        self.ready
    }
}

struct SelectWire {
    spi: DeviceId,
    physical: u64,
}

/// The CPU start registers and each PE's MPIDR_EL1 (Aff1 its cluster, Aff0
/// its core), by which a released core finds its PE.
struct CpuStarter {
    device: DeviceId,
    mpidrs: Vec<u64>,
}

/// Supplies shared by one DART, with its hardware retention property.
struct PowerDevice {
    physical: u64,
    device: DeviceId,
    retention: bool,
}

struct PowerClient {
    resources: String,
    device: DeviceId,
    owner: PowerOwner,
    domains: Vec<(u64, DomainState)>,
    retention: bool,
}

/// An AES engine and the DART stream its DMA goes through.
#[derive(Debug, Clone, Copy)]
struct Master {
    aes: DeviceId,
    dart: DeviceId,
    stream: usize,
}

/// A SEP and the DT-selected DART stream carrying its firmware DMA.
struct SepMaster {
    sep: DeviceId,
    dart: DeviceId,
    stream: usize,
}

/// The per-machine inputs the SEP binds its own trust and key state to: the
/// AP's effective security mode (shared fuses), the ECID (`/chosen`
/// `unique-chip-id`), and where its durable state lives.
pub struct SepProvisioning {
    pub security: Option<stela_soc_data::sep::SecurityMode>,
    pub ecid: u64,
    /// Observe (`--sep-observe`): advertise and log `sks`/`pnon`/`scrd`.
    pub observe: bool,
    pub state: sep::state::Location,
}

/// The DCPEXT coprocessor's ASC, the DART stream it masters its shared
/// memory through, and the display pipe's DART stream its swap surfaces are
/// mapped in, once placed.
struct DcpMaster {
    asc: DeviceId,
    dart: DeviceId,
    stream: usize,
    surface: Option<(DeviceId, usize)>,
}

/// A DART on the bus, for [`AppleDevices::add_aes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DartId(DeviceId);

/// The mapped AIC and which model it is.
#[derive(Debug, Clone, Copy)]
enum Controller {
    V1(DeviceId),
    V2(DeviceId),
}

fn describe(error: MmioError) -> DeviceError {
    match error {
        MmioError::Unmapped { .. } => DeviceError::NoDevice,
        MmioError::Misaligned { address, width } => DeviceError::Refused(format!(
            "misaligned {}-byte device access at {address:#x}",
            width.bytes()
        )),
        MmioError::Unsupported {
            device,
            offset,
            width,
            direction,
            reason,
        } => DeviceError::Refused(format!(
            "{device} {direction:?} of {} bytes at offset {offset:#x}: {reason}",
            width.bytes()
        )),
    }
}

fn describe_transfer(error: MmioError) -> DeviceError {
    match describe(error) {
        DeviceError::NoDevice => DeviceError::TransferRefused("unmapped DMA service".into()),
        DeviceError::Refused(reason) | DeviceError::TransferRefused(reason) => {
            DeviceError::TransferRefused(reason)
        }
    }
}

/// Native client boundary: enqueues bytes, exposes backpressure, and never
/// executes guest code. Advance the machine between calls while connecting.
pub struct UsbClient<'a>(&'a mut UsbSession);
#[cfg(test)]
impl<'a> UsbClient<'a> {
    pub(crate) fn test_session(session: &'a mut UsbSession) -> Self {
        Self(session)
    }
}
impl UsbClient<'_> {
    pub fn mux_state(&self) -> MuxState {
        self.0.mux_state()
    }
    pub fn control_ready(&self) -> bool {
        self.0.control_ready()
    }
    pub fn open(&mut self, port: u16) -> Result<MuxStream, &'static str> {
        self.0.open(port)
    }
    pub fn state(&self, stream: MuxStream) -> Result<MuxStreamState, &'static str> {
        self.0.state(stream)
    }
    pub fn write(&mut self, stream: MuxStream, bytes: &[u8]) -> Result<usize, &'static str> {
        self.0.write(stream, bytes)
    }
    pub fn read(&mut self, stream: MuxStream, bytes: &mut [u8]) -> Result<usize, &'static str> {
        self.0.read(stream, bytes)
    }
    pub fn close(&mut self, stream: MuxStream) -> Result<(), &'static str> {
        self.0.close(stream)
    }
    pub fn release(&mut self, stream: MuxStream) -> Result<(), &'static str> {
        self.0.release(stream)
    }
    pub fn query_type(&mut self) -> Result<(), &'static str> {
        self.0.query_type()
    }
}

impl Default for AppleDevices {
    fn default() -> Self {
        Self::new()
    }
}

/// A DCPEXT nub as the board describes it: its register aperture, AIC
/// interrupts, whether it starts quiesced, and its role and identity.
pub struct DcpextNub {
    pub wrapper: Range,
    pub interrupts: [u32; 4],
    pub quiesced: bool,
    pub role: &'static str,
    pub identity: stela_soc_data::dcp::ExternalIdentity,
}

/// The DART streams a DCPEXT masters: its link region's stream, the
/// `window` its firmware maps through it, and the display pipe's surface
/// stream when it is placed.
pub struct DcpextDma {
    pub link: (DartId, usize),
    pub window: Option<u64>,
    pub surface: Option<(DartId, usize)>,
}

impl AppleDevices {
    #[cfg(feature = "native-profile")]
    pub fn advance_statistics(&self) -> stela_contracts::bus::AdvanceStatistics {
        self.bus.advance_statistics()
    }

    /// The board's devices with PE zero receiving the boot handoff.
    pub fn new() -> Self {
        Self::for_boot_processor(0)
    }

    /// The board's existing PE receiving the boot handoff. PE indices keep
    /// DeviceTree order; the selected index also owns CPU_STS and SoC wake.
    /// The mount validates it against the same roster passed to the engine.
    pub fn for_boot_processor(boot_processor: usize) -> Self {
        Self {
            bus: Bus::new(),
            latch: InterruptLatch::new(),
            aic: None,
            reset: None,
            service: ServiceBatch::default(),
            memory_controller: None,
            memory_publication: None,
            ipi: None,
            masters: Vec::new(),
            storage_masters: Vec::new(),
            gfx_masters: Vec::new(),
            coprocessors: Vec::new(),
            nor: None,
            sep_masters: Vec::new(),
            dcp_masters: Vec::new(),
            dart_irqs: Vec::new(),
            usb_masters: Vec::new(),
            cpu_start: None,
            reset_vectors: Vec::new(),
            core_counters: Vec::new(),
            pc_samplers: Vec::new(),
            starts: Vec::new(),
            selects: Vec::new(),
            gpio: None,
            aux_gpios: Vec::new(),
            typec_ports: Vec::new(),
            phys: Vec::new(),
            pmgr: None,
            power_clients: Vec::new(),
            power_devices: Vec::new(),
            power_refusals: Vec::new(),
            power_configured: false,
            processor_power: None,
            native_pmp_dma: None,
            native_pmp_services: None,
            sleep: sleep::SocSleep::for_boot_processor(boot_processor),
            rtc_clock: None,
            pmu_clocks: Vec::new(),
            time_seen: Cell::new((0, "start")),
            time_regression: Cell::new(None),
        }
    }

    /// The NOR sectors the guest changed since the last call, as (offset,
    /// bytes), for the host to persist.
    pub fn nor_dirty(&mut self) -> Vec<(usize, Vec<u8>)> {
        self.nor
            .and_then(|id| self.bus.device_mut::<Spi>(id))
            .map_or_else(Vec::new, Spi::take_dirty)
    }

    /// Drain the `sks`/`pnon`/`scrd` traffic the SEP observed this run under
    /// `--sep-observe`, as log lines. Empty when observation is off.
    pub fn sep_observations(&mut self) -> Vec<String> {
        let ids: Vec<DeviceId> = self.sep_masters.iter().map(|master| master.sep).collect();
        let mut lines = Vec::new();
        for id in ids {
            if let Some(sep) = self.bus.device_mut::<Sep>(id) {
                lines.extend(sep.observations());
            }
        }
        lines
    }

    /// The coprocessor requests answered with an error reply for the first
    /// time since the last call, as log lines naming the coprocessor.
    pub fn take_unmodeled(&mut self) -> Vec<String> {
        let mut lines = Vec::new();
        let ids: Vec<(&'static str, DeviceId)> = self.coprocessors.clone();
        for (role, id) in ids {
            if let Some(asc) = self.bus.device_mut::<Asc>(id) {
                lines.extend(
                    asc.take_unmodeled()
                        .into_iter()
                        .map(|l| format!("{role} {l}")),
                );
            }
        }
        let ids: Vec<DeviceId> = self.sep_masters.iter().map(|master| master.sep).collect();
        for id in ids {
            if let Some(sep) = self.bus.device_mut::<Sep>(id) {
                lines.extend(sep.take_unmodeled().into_iter().map(|l| format!("SEP {l}")));
            }
        }
        lines
    }

    /// State of native RTKit coprocessors, without register side effects.
    pub fn coprocessor_diagnostics(&self) -> Vec<String> {
        self.coprocessors
            .iter()
            .map(|&(role, id)| {
                let asc = self.bus.device::<Asc>(id).expect("coprocessor wrapper");
                format!("{role} {}", asc.diagnostic())
            })
            .collect()
    }

    /// Apple's fast-IPI registers for PEs with these MPIDR_EL1 values, in PE
    /// order: each PE's cluster and CPU number are its Aff1 and Aff0.
    pub fn add_fast_ipi(&mut self, mpidrs: &[u64]) {
        let cpus = mpidrs
            .iter()
            .map(|&mpidr| Affinity {
                cluster: (mpidr >> 8) as u8,
                cpu: mpidr as u8,
            })
            .collect();
        self.ipi = Some(FastIpi::new(cpus));
    }

    fn map(&mut self, device: DeviceId, ranges: &[Range]) -> Result<(), MapError> {
        let mut offset = 0;
        for range in ranges {
            self.bus.map(device, range.physical, range.bytes, offset)?;
            offset += range.bytes;
        }
        Ok(())
    }

    /// Places the AP GPIO bank before its clients: chip-select outputs, a
    /// pulled-up net on each I2C line and on each client interrupt pin.
    pub fn add_gpio(
        &mut self,
        bank: &stela_soc_data::board::GpioBank,
        selects: &[u32],
        interrupts: &[u32],
    ) -> Result<(), String> {
        let mut nets: Vec<(u32, Net)> = Vec::new();
        for &pin in bank.i2c_lines.iter().chain(interrupts) {
            if !nets.iter().any(|(p, _)| *p == pin) {
                nets.push((pin, Net::new()));
            }
        }
        let lines = bank
            .lines
            .iter()
            .map(|&irq| AicInput::new(0, irq))
            .collect();
        let gpio = Gpio::with_profile(bank.profile, bank.pins, lines, selects, nets.clone())
            .and_then(|gpio| gpio.with_groups(bank.groups as usize))
            .map_err(String::from)?;
        let id = self.bus.add(Box::new(gpio));
        self.bus
            .map(id, bank.physical, bank.bytes, 0)
            .map_err(|e| format!("GPIO placement: {e:?}"))?;
        self.register_power_device(bank.physical, id, false)?;
        self.gpio = Some((bank.physical, nets));
        Ok(())
    }

    /// Places another GPIO bank (`aop-gpio`, `smc-gpio`) with a pulled-up
    /// board net on each pin its clients name. A pin no device drives reads
    /// its pull-up; the board model that drives one, such as the HDMI
    /// converter's hot-plug output, attaches through [`Self::gpio_line`]
    /// before the guest runs.
    pub fn add_aux_gpio(&mut self, aux: &stela_soc_data::board::AuxGpioBank) -> Result<(), String> {
        if self
            .aux_gpios
            .iter()
            .any(|(phandle, _)| *phandle == aux.bank.phandle)
        {
            return Err(format!("GPIO bank {} placed twice", aux.name));
        }
        let nets: Vec<(u32, Net)> = aux
            .client_pins
            .iter()
            .map(|&pin| (pin, Net::new()))
            .collect();
        let lines = aux
            .bank
            .lines
            .iter()
            .map(|&irq| AicInput::new(0, irq))
            .collect();
        let gpio = Gpio::with_profile(aux.bank.profile, aux.bank.pins, lines, &[], nets.clone())
            .and_then(|gpio| gpio.with_groups(aux.bank.groups as usize))
            .map_err(|error| format!("{}: {error}", aux.name))?;
        let id = self.bus.add(Box::new(gpio));
        self.bus
            .map(id, aux.bank.physical, aux.bank.bytes, 0)
            .map_err(|e| format!("{} placement: {e:?}", aux.name))?;
        self.register_power_device(aux.bank.physical, id, false)?;
        self.aux_gpios.push((aux.bank.phandle, nets));
        Ok(())
    }

    /// A driver on `pin` of the GPIO bank with phandle `bank`: released, the
    /// pin reads high; pulled low, it reads low.
    pub fn gpio_line(&mut self, bank: u32, pin: u32) -> Result<OpenDrain, String> {
        let (_, nets) = self
            .aux_gpios
            .iter()
            .find(|(phandle, _)| *phandle == bank)
            .ok_or_else(|| format!("no auxiliary GPIO bank with phandle {bank:#x}"))?;
        let (_, net) = nets
            .iter()
            .find(|(p, _)| *p == pin)
            .ok_or_else(|| format!("GPIO pin {pin} has no client in bank {bank:#x}"))?;
        net.open_drain().map_err(String::from)
    }

    fn gpio_net(&self, pin: u32) -> Result<&Net, String> {
        self.gpio
            .as_ref()
            .and_then(|(_, nets)| nets.iter().find(|(p, _)| *p == pin))
            .map(|(_, net)| net)
            .ok_or_else(|| format!("GPIO pin {pin} has no placed board net"))
    }

    /// The shared cable state of one Type-C connector.
    fn typec_port(&mut self, number: u32) -> typec::Port {
        if let Some((_, port)) = self.typec_ports.iter().find(|(n, _)| *n == number) {
            return port.clone();
        }
        let port = typec::Port::new();
        self.typec_ports.push((number, port.clone()));
        port
    }

    /// Installs the DT-derived SPI controller, one NOR die and
    /// its external GPIO CS wire (or the internal PIN.CS connection). An
    /// external CS requires the placed GPIO bank.
    pub fn add_spi_nor(&mut self, placement: &stela_soc_data::board::SpiNor) -> Result<(), String> {
        let device = placement.device;
        let spi = self.bus.add(Box::new(Spi::new(
            placement.image.clone(),
            AicInput::new(0, device.irq as u16),
            placement.select.is_some(),
        )));
        self.bus
            .map(spi, device.physical, device.bytes, 0)
            .map_err(|e| format!("SPI placement: {e:?}"))?;
        self.register_power_device(device.physical, spi, false)?;
        self.nor = Some(spi);
        if let Some(pin) = placement.select {
            let (base, _) = self.gpio.as_ref().ok_or("SPI CS requires the GPIO bank")?;
            self.selects.push(SelectWire {
                spi,
                physical: base + u64::from(pin) * 4,
            });
        }
        Ok(())
    }

    /// The S5L console UART at its DeviceTree ranges.
    pub fn add_uart<C: ConsoleSink + 'static>(
        &mut self,
        console: C,
        ranges: &[Range],
        irq: Option<AicInput>,
    ) -> Result<(), String> {
        let first = ranges.first().ok_or("UART has no canonical aperture")?;
        let device = self.bus.add(Box::new(S5lUart::new(console, irq)));
        self.map(device, ranges)
            .map_err(|error| format!("UART placement: {error:?}"))?;
        self.register_power_device(first.physical, device, false)
    }

    /// The lock pair at the end of one DT-placed CoreSight component page.
    pub fn add_coresight_lock(&mut self, physical: u64) -> Result<(), MapError> {
        let device = self.bus.add(Box::new(SoftwareLock::new()));
        self.bus.map(
            device,
            physical
                .checked_add(coresight::ACCESS)
                .ok_or(MapError::Overflow)?,
            8,
            coresight::ACCESS,
        )
    }

    /// The UTTDBG sampler of PE `cpu`, at its DT-placed UTT region base.
    pub fn add_coresight_sampler(&mut self, cpu: usize, physical: u64) -> Result<(), MapError> {
        let register = physical
            .checked_add(coresight::PC_SAMPLE)
            .ok_or(MapError::Overflow)?;
        let device = self.bus.add(Box::new(PcSampler::default()));
        self.bus.map(device, register, 8, coresight::PC_SAMPLE)?;
        self.pc_samplers.push((cpu, register, device));
        Ok(())
    }

    /// The lockdown registers of a CPU implementation block named `name`,
    /// with CONTROL at `control`, at `range`; a PE's `cpu-impl-reg` also
    /// holds that PE's RVBAR, which the boot firmware locked on `reset`, its
    /// run state CPU_STS and CORE_THRTL_CFG2.
    /// Only those registers are mapped: the block also holds the PE's or
    /// cluster's energy accumulators (`platform::apple::energy`).
    pub fn add_lockdown(
        &mut self,
        name: &'static str,
        control: u64,
        range: Range,
        reset: Option<(usize, u64)>,
    ) -> Result<(), MapError> {
        if let Some((cpu, _)) = reset
            && let Some(existing) = self.reset_vectors.get(cpu).copied().flatten()
        {
            return Err(MapError::Overlap { existing });
        }
        let mut model = Lockdown::new(name, control);
        let mut bindings = vec![(
            range
                .physical
                .checked_add(control)
                .ok_or(MapError::Overflow)?,
            lockdown::BYTES,
            control,
        )];
        if let Some((pe, entry)) = reset {
            model = model.with_reset_vector(entry);
            model.set_running(self.processor_running(pe));
            for offset in lockdown::PE_WORDS {
                let start = range
                    .physical
                    .checked_add(offset)
                    .ok_or(MapError::Overflow)?;
                bindings.push((start, lockdown::WORD_BYTES, offset));
            }
        }
        // Publish the reset-vector owner only after every bank fits.
        let device = self.bus.install(Box::new(model), &bindings)?;
        if let Some((pe, _)) = reset {
            if self.reset_vectors.len() <= pe {
                self.reset_vectors.resize(pe + 1, None);
            }
            self.reset_vectors[pe] = Some(device);
        }
        Ok(())
    }

    /// PE startup words when its original block has no legacy PIO lock pair.
    /// Publish its reset-vector binding only after all three words are mapped.
    pub fn add_processor_registers(
        &mut self,
        cpu: usize,
        range: Range,
        entry: u64,
    ) -> Result<(), MapError> {
        if let Some(existing) = self.reset_vectors.get(cpu).copied().flatten() {
            return Err(MapError::Overlap { existing });
        }
        if !range.physical.is_multiple_of(lockdown::WORD_BYTES) {
            return Err(MapError::Unaligned);
        }
        range
            .physical
            .checked_add(range.bytes)
            .ok_or(MapError::Overflow)?;
        let mut model = Lockdown::processor(entry);
        model.set_running(self.processor_running(cpu));
        let mut bindings = Vec::new();
        for offset in lockdown::PE_WORDS {
            if offset
                .checked_add(lockdown::WORD_BYTES)
                .is_none_or(|end| end > range.bytes)
            {
                return Err(MapError::Overflow);
            }
            let physical = range
                .physical
                .checked_add(offset)
                .ok_or(MapError::Overflow)?;
            bindings.push((physical, lockdown::WORD_BYTES, offset));
        }
        let device = self.bus.install(Box::new(model), &bindings)?;
        if self.reset_vectors.len() <= cpu {
            self.reset_vectors.resize(cpu + 1, None);
        }
        self.reset_vectors[cpu] = Some(device);
        Ok(())
    }

    /// The PMGR's CPU start registers for `clusters` clusters at `physical`,
    /// releasing the PEs with these MPIDR_EL1 values, in PE order, at the
    /// RVBARs of their `cpu-impl-reg` blocks.
    pub fn add_cpu_start(
        &mut self,
        physical: u64,
        clusters: u8,
        mpidrs: &[u64],
    ) -> Result<(), String> {
        if self.cpu_start.is_some() {
            return Err("CPU start owner is already bound".into());
        }
        let device = self
            .bus
            .install(
                Box::new(CpuStart::new(clusters)),
                &[(physical, stela_soc_data::cpustart::bytes(clusters), 0)],
            )
            .map_err(|error| format!("CPU start placement: {error:?}"))?;
        self.cpu_start = Some(CpuStarter {
            device,
            mpidrs: mpidrs.to_vec(),
        });
        Ok(())
    }

    /// PE `cpu`'s CLPC sampler counters of `layout`, whose windows lie in
    /// its `cpu-impl-reg` at `physical`; its MRS and MSR of the counters
    /// reach the same model (`system_register`).
    pub fn add_core_counters(
        &mut self,
        cpu: usize,
        physical: u64,
        layout: stela_soc_data::core_counters::Layout,
    ) -> Result<(), MapError> {
        let device = self.bus.add(Box::new(CoreCounters::new(layout)));
        for (offset, bytes) in layout.windows() {
            let start = physical.checked_add(offset).ok_or(MapError::Overflow)?;
            self.bus.map(device, start, bytes, offset)?;
        }
        if self.core_counters.len() <= cpu {
            self.core_counters.resize(cpu + 1, None);
        }
        self.core_counters[cpu] = Some(device);
        Ok(())
    }

    /// PE `cpu`'s `cpu-impl-reg` CPU_STS follows its power.
    fn set_processor_running(&mut self, cpu: usize, running: bool) {
        if let Some(block) = self.reset_vectors.get(cpu).copied().flatten()
            && let Some(lockdown) = self.bus.device_mut::<Lockdown>(block)
        {
            lockdown.set_running(running);
        }
    }

    /// The reset address in PE `cpu`'s `cpu-impl-reg` RVBAR.
    fn locked_reset_vector(&self, cpu: usize) -> Option<u64> {
        let block = self.reset_vectors.get(cpu).copied().flatten()?;
        self.bus.device::<Lockdown>(block)?.reset_address()
    }

    /// The AMCC's lock registers at each aperture of `layout`, with the
    /// regions iBoot programmed per CTRR group (`[base, base + bytes)`), and the
    /// memory cache's registers when the board shows its `cache`.
    pub fn add_memory_controller(
        &mut self,
        apertures: &[u64],
        layout: stela_soc_data::amcc::Layout,
        programmed: stela_soc_data::amcc::Programmed,
        cache: Option<stela_soc_data::amcc::Cache>,
    ) -> Result<(), String> {
        let device = self.map_lock_controller(apertures, layout, programmed, cache)?;
        self.memory_controller = Some(device);
        Ok(())
    }

    /// A separately owned I/O-access controller protects the same boot run
    /// at its declared aperture map; it does not replace the DRAM controller.
    pub fn add_io_access_controller(
        &mut self,
        apertures: &[u64],
        layout: stela_soc_data::amcc::Layout,
        programmed: stela_soc_data::amcc::Programmed,
    ) -> Result<(), String> {
        self.map_lock_controller(apertures, layout, programmed, None)?;
        Ok(())
    }

    fn map_lock_controller(
        &mut self,
        apertures: &[u64],
        layout: stela_soc_data::amcc::Layout,
        programmed: stela_soc_data::amcc::Programmed,
        cache: Option<stela_soc_data::amcc::Cache>,
    ) -> Result<DeviceId, String> {
        if cache.is_some() {
            return Err(
                "MCC/DCS/PTD mount requires an actual qualified memory, drain and service owner"
                    .into(),
            );
        }
        if layout.cache_status.is_some_and(|status| {
            layout
                .stride
                .checked_mul(u64::from(layout.planes))
                .is_none_or(|end| status.offset >= end)
        }) {
            return Err(
                "AMCC shared MCC status requires the prepared joint memory resource owner".into(),
            );
        }
        let model = Amcc::new(layout, apertures.len(), programmed, cache).map_err(String::from)?;
        let ranges: alloc::vec::Vec<(u64, u64, u64)> = apertures
            .iter()
            .enumerate()
            .map(|(index, &physical)| {
                let offset = u64::try_from(index)
                    .ok()
                    .and_then(|index| index.checked_mul(layout.aperture_bytes))
                    .ok_or("CTRR device aperture offsets overflow")?;
                Ok((physical, layout.aperture_bytes, offset))
            })
            .collect::<Result<_, String>>()?;
        self.bus
            .install(Box::new(model), &ranges)
            .map_err(|error| format!("CTRR controller placement: {error:?}"))
    }

    /// The memory cache controller's `channels` DRAM channels, sharing
    /// `range` evenly, and the PMP's PTD bank at `ptd` with its `ranges`.
    pub fn add_memory_channels(
        &mut self,
        range: Range,
        channels: usize,
        ptd: u64,
        ranges: &[stela_soc_data::ptd::Range],
    ) -> Result<(), String> {
        let _ = (range, channels, ptd, ranges);
        Err("MCC/DCS/PTD mount requires an actual qualified memory, drain and service owner".into())
    }

    /// Place an explicitly described ANS2, its started RTKit coprocessor
    /// (listing [`ans::RTKIT_ENDPOINT`]) and SART. Split the shared NVMe bank
    /// around SART's idle word so each physical byte has one owner. The boot
    /// chain's choice is to start the native RTKit service before handing off
    /// to SPTM.
    pub fn add_ans(
        &mut self,
        placement: &stela_soc_data::board::AnsController,
        backing: Box<dyn stela_drivers::block::BlockDevice>,
        build: &stela_formats::builds::Build,
    ) -> Result<(), String> {
        let irq = |n| AicInput::new(0, n);
        let rtkit = RtKit::new(
            vec![(ans::RTKIT_ENDPOINT, Box::new(ans::Endpoint) as Box<_>)],
            build.rtkit_version,
        )
        .map_err(String::from)?;
        let wrapper = Asc::booted(
            Box::new(rtkit),
            AscLines::from_interrupts(placement.interrupts.map(irq)),
        )
        .map_err(String::from)?;
        // The placement requires the boot stage's NVMe security hand-off,
        // which leaves the controller in linear submission mode.
        let controller = Ans::with_geometry(
            backing,
            &placement.namespaces,
            Some(irq(placement.completion_irq)),
            placement.geometry,
        )
        .map_err(String::from)?
        .handed_off_linear();
        let asc = self.bus.add(Box::new(wrapper));
        self.coprocessors.push(("ANS", asc));
        self.bus
            .map(asc, placement.wrapper.0, placement.wrapper.1, 0)
            .map_err(|e| format!("ANS ASC placement: {e:?}"))?;
        let bounds = if placement.sart_exclusive_bounds {
            stela_soc_data::sart::Bounds::Exclusive
        } else {
            stela_soc_data::sart::Bounds::Inclusive
        };
        let sart = self
            .bus
            .add(Box::new(Sart::with_layout(bounds, placement.sart_layout)));
        self.bus
            .map(sart, placement.sart.0, placement.sart.1, 0)
            .map_err(|e| format!("SART placement: {e:?}"))?;
        self.bus
            .map(sart, placement.sart_idle, 4, sart::IDLE)
            .map_err(|e| format!("SART idle placement: {e:?}"))?;
        if let Some(canary) = placement.sart_canary {
            self.bus
                .map(sart, canary, 4, sart::CANARY)
                .map_err(|e| format!("SART power canary placement: {e:?}"))?;
        }
        let ans = self.bus.add(Box::new(controller));
        let (base, bytes) = placement.nvme;
        let before = placement
            .sart_idle
            .checked_sub(base)
            .ok_or("SART idle word precedes NVMe")?;
        let after = before
            .checked_add(4)
            .filter(|&end| end <= bytes)
            .ok_or("SART idle word outside NVMe")?;
        for (offset, bytes) in [(0, before), (after, bytes - after)] {
            if bytes != 0 {
                self.bus
                    .map(ans, base + offset, bytes, offset)
                    .map_err(|e| format!("ANS placement: {e:?}"))?;
            }
        }
        if let Some((base, _)) = placement.vdma {
            self.bus
                .map(
                    ans,
                    base + ans::VDMA_CACHE_OFFSET,
                    placement.geometry.vdma_bytes(),
                    ans::VDMA_CACHE,
                )
                .map_err(|e| format!("ANS VDMA cache placement: {e:?}"))?;
        }
        self.storage_masters.push((ans, sart));
        // These are three banks of the same ANS resource. In particular a
        // later protected-NVMe/SART veto must precede any ASC reset effects.
        self.register_power_device(placement.wrapper.0, asc, false)?;
        self.register_power_device(placement.wrapper.0, ans, false)?;
        self.register_power_device(placement.wrapper.0, sart, false)?;
        Ok(())
    }

    /// Place an explicitly described SMC: its started, user-power-managed
    /// RTKit with the native key endpoint, the shared page at the nub's
    /// region base, and the hardware watchdog bank AppleSMC disarms. The
    /// rest of the nub region, the coprocessor's own memory, stays unmapped.
    pub fn add_smc(
        &mut self,
        placement: &stela_soc_data::board::SmcController,
        build: &stela_formats::builds::Build,
    ) -> Result<(), String> {
        let sram = smc::Sram::default();
        let keys = placement
            .gpio_keys
            .iter()
            .map(|&name| (name, smc::Key::gpio()))
            .collect();
        let endpoint = Smc::new(sram.clone(), placement.region.0, keys)
            .map_err(String::from)?
            .with_wake_bits(placement.wake_bits);
        let mut rtkit = RtKit::new(
            vec![(smc::ENDPOINT, Box::new(endpoint))],
            build.rtkit_version,
        )
        .map_err(String::from)?;
        if placement.quiesced {
            rtkit = rtkit.quiesced();
        }
        let wrapper = Asc::booted(
            Box::new(rtkit),
            AscLines::from_interrupts(placement.interrupts.map(|n| AicInput::new(0, n))),
        )
        .map_err(String::from)?;
        let asc = self.bus.add(Box::new(wrapper));
        self.coprocessors.push(("SMC", asc));
        self.bus
            .map(asc, placement.wrapper.0, placement.wrapper.1, 0)
            .map_err(|e| format!("SMC ASC placement: {e:?}"))?;
        let window = self.bus.add(Box::new(smc::SramWindow(sram)));
        self.bus
            .map(window, placement.region.0, smc::SRAM_BYTES, 0)
            .map_err(|e| format!("SMC shared page placement: {e:?}"))?;
        if let Some((base, bytes)) = placement.watchdog {
            let watchdog = self.bus.add(Box::new(smc::Watchdog));
            self.bus
                .map(watchdog, base, bytes.min(smc::WATCHDOG_BYTES), 0)
                .map_err(|e| format!("SMC watchdog placement: {e:?}"))?;
        }
        Ok(())
    }

    /// Place an explicitly described PMP: its started, user-power-managed
    /// RTKit with the native `PMPEndpoint1` (`pmp::Pmp`). Its PTD bank is
    /// the memory cache's ([`Self::add_memory_channels`]).
    pub fn add_pmp(
        &mut self,
        placement: &stela_soc_data::board::PmpController,
        build: &stela_formats::builds::Build,
    ) -> Result<(), String> {
        let mut rtkit = RtKit::new(
            vec![(pmp::ENDPOINT, Box::new(pmp::Pmp::default()))],
            build.rtkit_version,
        )
        .map_err(String::from)?;
        if placement.quiesced {
            rtkit = rtkit.quiesced();
        }
        let wrapper = Asc::booted(
            Box::new(rtkit),
            AscLines::from_interrupts(placement.interrupts.map(|n| AicInput::new(0, n))),
        )
        .map_err(String::from)?;
        let asc = self.bus.add(Box::new(wrapper));
        self.coprocessors.push(("PMP", asc));
        self.bus
            .map(asc, placement.wrapper.0, placement.wrapper.1, 0)
            .map_err(|e| format!("PMP ASC placement: {e:?}"))?;
        self.register_power_device(placement.wrapper.0, asc, false)
    }

    /// Place the AGX GPU: the started GFX coprocessor (RTKit with the native
    /// GFX endpoints, `agx::firmware`) behind its ASC wrapper, and the `sgx`
    /// register block whose MMU configuration roots the UAT the firmware
    /// masters memory through.
    pub fn add_gfx(
        &mut self,
        placement: &stela_soc_data::board::GfxController,
        build: &stela_formats::builds::Build,
    ) -> Result<(), String> {
        let sgx_physical = placement
            .sgx
            .first()
            .ok_or("SGX has no canonical register aperture")?
            .0;
        let sgx = Sgx::handed_off(placement.gpu, placement.ttbat, placement.shared_l2)
            .map_err(String::from)?;
        let power = sgx
            .firmware_power(&placement.sgx)
            .and_then(|power| power.with_asc_wrapper(placement.wrapper.0))
            .map_err(String::from)?;
        let native_control = power.native_asc_control();
        let coprocessor =
            GfxCoprocessor::with_power(placement.gpu.family, power, build).map_err(String::from)?;
        let wrapper = Asc::booted(
            Box::new(coprocessor),
            AscLines::from_interrupts(placement.interrupts.map(|n| AicInput::new(0, n))),
        )
        .map_err(String::from)?;
        let asc = self.bus.add(Box::new(wrapper));
        self.coprocessors.push(("GFX", asc));
        self.bus
            .map(asc, placement.wrapper.0, placement.wrapper.1, 0)
            .map_err(|e| format!("GFX ASC placement: {e:?}"))?;
        // T8112's 64 MiB `sgx` window spans the `gfx-asc` wrapper and a PMGR
        // fabric bridge; each physical byte has one owner, so each bank owns
        // only what the smaller banks placed before it leave.
        let block = self.bus.add(Box::new(sgx));
        for &(base, bytes, offset) in &placement.sgx {
            self.bus
                .map_gaps(block, base, bytes, offset)
                .map_err(|e| format!("sgx placement: {e:?}"))?;
        }
        if let Some(control) = native_control
            && !self
                .bus
                .route(control, Width::Double)
                .is_ok_and(|(owner, _)| owner == block)
        {
            return Err(
                "GFX native ASC control is not wholly owned by its mounted SGX bank".into(),
            );
        }
        self.gfx_masters.push((asc, block));
        // sgx and gfx-asc are distinct root resources, coupled by their
        // shared original PMGR domain, not an invented parent/child owner.
        self.register_power_device(placement.wrapper.0, asc, false)?;
        self.register_power_device(sgx_physical, block, false)?;
        Ok(())
    }

    /// Place the `dcpext` display coprocessor: its booted RTKit (reusing the
    /// common ASC wrapper) carrying the IOMFB link endpoint and the AFK/EPIC
    /// endpoints, presenting one fixed connected monitor to `scanout`, and
    /// mastering the AP's link region through `dart` stream `stream`
    /// (`window` as `dcp::Coprocessor::new` takes it) and reading swap
    /// surfaces through `surface`, the display pipe's DART stream
    /// (`dart-dispext0` stream 0 on J473AP), when it is placed. The DCPEXT
    /// nub is `quiesced`, so (like the SMC) the coprocessor acknowledges the
    /// AP's wake once RTKit enumeration completes behind the boot-chain
    /// handoff. This does not admit DCPEXT in `stela_soc_data::board::models` (see
    /// `platform::apple::dcp`).
    pub fn add_dcpext(
        &mut self,
        nub: DcpextNub,
        scanout: Box<dyn Scanout>,
        dma: DcpextDma,
        build: &stela_formats::builds::Build,
    ) -> Result<(), String> {
        let DcpextNub {
            wrapper,
            interrupts,
            quiesced,
            role,
            identity,
        } = nub;
        let DcpextDma {
            link: (dart, stream),
            window,
            surface,
        } = dma;
        if wrapper.bytes < asc::WRAPPER_BYTES {
            return Err("DCPEXT register aperture is incomplete".into());
        }
        self.validate_native_dart("DCP firmware", dart, stream)?;
        if let Some((dart, stream)) = surface {
            self.validate_native_dart("DCP surface", dart, stream)?;
        }
        let mut coprocessor = dcp::Coprocessor::for_external(scanout, window, identity, build)
            .map_err(String::from)?;
        if quiesced {
            coprocessor = coprocessor.quiesced();
        }
        let wrap = Asc::booted(
            Box::new(coprocessor),
            AscLines::from_interrupts(interrupts.map(|n| AicInput::new(0, n as u16))),
        )
        .map_err(String::from)?;
        let asc = self.bus.add(Box::new(wrap));
        self.coprocessors.push((role, asc));
        self.dcp_masters.push(DcpMaster {
            asc,
            dart: dart.0,
            stream,
            surface: surface.map(|(dart, stream)| (dart.0, stream)),
        });
        self.bus
            .map(asc, wrapper.physical, wrapper.bytes, 0)
            .map_err(|e| format!("DCPEXT ASC placement: {e:?}"))?;
        self.register_power_device(wrapper.physical, asc, false)
    }

    /// Place the display-hardware register apertures around the DCP
    /// (`dispext0`, `dptx-phy`, `display-crossbar0`): present but with no
    /// modeled register meaning, since the DCP firmware programs them. Each
    /// `(name, range)` is one aperture; an access by the AP refuses, named.
    pub fn add_display(&mut self, regions: &[(&'static str, Range)]) -> Result<(), String> {
        for &(name, range) in regions {
            let device = self.bus.add(Box::new(display_hw::Region::new(name)));
            self.bus
                .map(device, range.physical, range.bytes, 0)
                .map_err(|e| format!("{name} placement: {e:?}"))?;
        }
        Ok(())
    }

    /// Place a visible SPMI controller and its PMUs. Bank B is the device's
    /// second 16 KiB and `reg[2]`, where placed, its third. A primary PMU's
    /// RTC starts at `wall` when the engine
    /// knows the host's time.
    pub fn add_spmi(
        &mut self,
        placement: &stela_soc_data::board::SpmiController,
        wall: Option<stela_soc_data::pmu::WallClock>,
    ) -> Result<(), String> {
        if placement.pmus.iter().any(|pmu| pmu.rtc_helper.is_some()) {
            return Err("SMC RTC helper requires an explicit virtual RTC epoch authority".into());
        }
        self.add_spmi_with_epoch(
            placement,
            wall,
            pmu::RtcEpoch {
                counter: 0,
                ticks: 0,
            },
        )
    }

    /// The boot resource owner explicitly declares this virtual oscillator
    /// origin; it is not an Apple persisted/reset-state measurement.
    pub fn add_spmi_with_epoch(
        &mut self,
        placement: &stela_soc_data::board::SpmiController,
        wall: Option<stela_soc_data::pmu::WallClock>,
        epoch: pmu::RtcEpoch,
    ) -> Result<(), String> {
        self.add_spmi_with_resources(placement, wall, epoch, &[])
    }

    /// Every outside-scratch fault log and off-to-wake source requires
    /// explicitly declared initial history. SIDs are local to this
    /// controller; entries are complete and unique.
    pub fn add_spmi_with_resources(
        &mut self,
        placement: &stela_soc_data::board::SpmiController,
        wall: Option<stela_soc_data::pmu::WallClock>,
        epoch: pmu::RtcEpoch,
        history: &[(u8, stela_soc_data::pmu::Retained, Vec<u8>)],
    ) -> Result<(), String> {
        for (index, (sid, kind, bytes)) in history.iter().enumerate() {
            if history[..index]
                .iter()
                .any(|(previous, other, _)| previous == sid && other == kind)
            {
                return Err("duplicate PMU retained-history owner".into());
            }
            let (_, window) = placement
                .pmus
                .iter()
                .filter(|pmu| pmu.sid == *sid)
                .flat_map(|pmu| pmu.retained())
                .find(|(owner, _)| owner == kind)
                .ok_or("retained history has no matching outside-scratch PMU owner")?;
            if bytes.len() != usize::from(window.bytes) {
                return Err("PMU initial retained history is incomplete".into());
            }
        }
        if placement.pmus.iter().flat_map(|pmu| pmu.retained()).count() != history.len() {
            return Err("PMU outside-scratch histories require explicit initial bytes".into());
        }
        let irq = u16::try_from(placement.irq).map_err(|_| "SPMI AIC line above 65535")?;
        let mut controller =
            Spmi::with_configuration(AicInput::new(0, irq), placement.configuration);
        // Construct/preflight every slave and global service before publishing any owner.
        let mut primary = None;
        let mut primary_clock = None;
        for pmu in &placement.pmus {
            if pmu.primary && pmu.rtc.is_none() {
                return Err("PMU primary system service requires a qualified RTC owner".into());
            }
            let configuration = pmu.configuration(|kind, _| {
                let (_, _, bytes) = history
                    .iter()
                    .find(|(sid, owner, _)| *sid == pmu.sid && *owner == kind)
                    .expect("all retained owners preflighted");
                Ok(bytes.clone())
            })?;
            let clock = pmu::RtcClock::new(epoch).map_err(String::from)?;
            let model = Pmu::with_clock(configuration, clock, wall.filter(|_| pmu.rtc.is_some()))
                .map_err(String::from)?;
            self.pmu_clocks.extend(model.rtc_clock());
            if let Some(profile) = pmu.rtc_helper {
                if !pmu.primary || self.rtc_clock.is_some() || primary_clock.is_some() {
                    return Err("RTC helper has no unique primary oscillator owner".into());
                }
                self.smc()
                    .map_err(String::from)?
                    .check_bind_rtc()
                    .map_err(String::from)?;
                primary_clock = Some((
                    model
                        .rtc_clock()
                        .ok_or("RTC helper has no actual PMU oscillator")?,
                    profile,
                ));
            }
            if pmu.primary {
                if self.sleep.pmu.is_some() || primary.is_some() {
                    return Err("multiple primary PMU system-service owners".into());
                }
                primary = Some(model.interrupt());
            }
            if let Some(vector) = pmu.interrupt {
                controller.attach_with_interrupt(pmu.sid, vector, Box::new(model))
            } else {
                controller.attach(pmu.sid, Box::new(model))
            }
            .map_err(String::from)?;
        }
        let id = self.bus.add(Box::new(controller));
        for (bank, &(base, bytes)) in placement.banks.iter().enumerate() {
            self.bus
                .map(id, base, bytes, bank as u64 * stela_soc_data::spmi::BANK_B)
                .map_err(|e| format!("SPMI bank placement: {e:?}"))?;
        }
        if let Some((base, bytes)) = placement.bank_c {
            self.bus
                .map(id, base, bytes, stela_soc_data::spmi::BANK_C)
                .map_err(|e| format!("SPMI reg[2] placement: {e:?}"))?;
        }
        if let Some((clock, profile)) = primary_clock {
            self.smc()
                .map_err(String::from)?
                .bind_rtc(clock.clone(), profile)
                .map_err(String::from)?;
            self.rtc_clock = Some(clock);
        }
        if let Some(primary) = primary {
            self.sleep.pmu = Some(primary);
        }
        Ok(())
    }

    /// Place an explicitly visible I2C controller. Addressed but unchecked
    /// targets refuse; hiding a target must not turn its protocol into success.
    /// `firmware` returns a board firmware image by its guest file name; an
    /// HPM die runs `USB-C_<personality>.bin` and drives its manager's
    /// interrupt net, whose summary the manager's own address reports.
    pub fn add_i2c<'f>(
        &mut self,
        placement: &stela_soc_data::board::I2cController,
        firmware: &dyn Fn(&str) -> Option<&'f [u8]>,
    ) -> Result<(), String> {
        let device = placement.device;
        let mut model = I2c::new(AicInput::new(0, device.irq as u16));
        // Each die's alert output on its manager's interrupt net, which the
        // manager's summary samples.
        let mut alerts = Vec::new();
        for target in &placement.targets {
            if target.compatible != stela_soc_data::board::HPM {
                continue;
            }
            let name = stela_soc_data::board::hpm_firmware_file(
                target.firmware.as_deref().ok_or("HPM names no firmware")?,
            );
            let image =
                firmware(&name).ok_or_else(|| format!("board firmware {name} was not supplied"))?;
            let die = Firmware::from_image(image).map_err(|e| format!("{name}: {e}"))?;
            let port = self.typec_port(target.port.ok_or("HPM has no port number")?);
            let pin = target.interrupt.ok_or("HPM has no bus-manager interrupt")?;
            let alert = self.gpio_net(pin)?.open_drain()?;
            let hpm = Hpm::new(port, die, target.address).with_interrupt(alert.clone());
            model
                .attach(target.address, Box::new(hpm))
                .map_err(String::from)?;
            alerts.push((pin, target.address, alert));
        }
        for target in &placement.targets {
            let reason = match target.compatible.as_str() {
                stela_soc_data::board::HPM => continue,
                stela_soc_data::board::HPM_MANAGER => {
                    let dies = alerts
                        .iter()
                        .filter(|(pin, ..)| Some(*pin) == target.interrupt)
                        .map(|(_, address, alert)| (*address, alert.clone()))
                        .collect();
                    let summary = Summary::new(dies).map_err(String::from)?;
                    model
                        .attach(target.address, Box::new(summary))
                        .map_err(String::from)?;
                    continue;
                }
                stela_soc_data::board::RETIMER => "ATC retimer register protocol is undetermined",
                _ => "I2C target protocol is not modeled",
            };
            model
                .attach(target.address, Box::new(i2c::Unmodeled(reason)))
                .map_err(String::from)?;
        }
        let id = self.bus.add(Box::new(model));
        self.bus
            .map(id, device.physical, device.bytes, 0)
            .map_err(|e| format!("I2C placement: {e:?}"))?;
        self.register_power_device(device.physical, id, false)
    }

    /// Place canonical PHY regions once. ADT aliases inside the core resolve
    /// by physical address; no length concatenation or duplicate storage.
    pub fn add_atc_phy(
        &mut self,
        placement: &stela_soc_data::board::TypecPhy,
    ) -> Result<(), String> {
        if placement.phandle == 0
            || placement.port == 0
            || self.phys.iter().any(|phy| phy.phandle == placement.phandle)
        {
            return Err("ATC PHY has an invalid/duplicate phandle or invalid connector".into());
        }
        let id = self.bus.add(Box::new(AtcPhy::new()));
        let pipe = placement.pipe.map(|pipe| (pipe, atc_phy::PIPE));
        for ((physical, bytes), offset) in [
            (placement.usb2, atc_phy::USB2),
            (placement.core, 0),
            (placement.events, atc_phy::EVENTS),
        ]
        .into_iter()
        .chain(pipe)
        {
            self.bus
                .map(id, physical, bytes, offset)
                .map_err(|error| format!("ATC PHY placement: {error:?}"))?;
        }
        self.phys.push(PhyBinding {
            phandle: placement.phandle,
            port: placement.port,
            device: id,
            retention: placement.retention,
            pipe: placement.pipe,
            events: placement.events,
        });
        Ok(())
    }

    /// Independently programmed DT TRAD windows with a shared fault wire.
    /// Returned IDs keep DT instance order. This does not choose a USB DMA
    /// stream or resolve a mapper to one instance.
    pub fn add_dart_group(
        &mut self,
        ranges: &[Range],
        streams: usize,
        irq: Option<AicInput>,
        apf: Option<(u64, usize)>,
    ) -> Result<Vec<DartId>, MapError> {
        if ranges.is_empty() {
            return Err(MapError::Empty);
        }
        self.place_dart_group(Dart::group(streams, irq, ranges.len()), ranges, apf, irq)
    }

    /// Select the DT register/table family before publishing windows.
    /// Legacy filter and capture variants need their own native contracts.
    pub fn add_dart_group_for_profile(
        &mut self,
        profile: stela_soc_data::dart::Profile,
        ranges: &[Range],
        streams: usize,
        irq: Option<AicInput>,
        apf: Option<(u64, usize)>,
    ) -> Result<Vec<DartId>, String> {
        if !profile.is_t8110() && apf.is_some() {
            return Err("legacy DART APF topology and filtering are unsupported".into());
        }
        if !profile.is_t8110() && ranges.len() > 5 {
            return Err(
                "legacy DART topology exceeds the recovered five-instance placement".into(),
            );
        }
        if apf.is_some_and(|(physical, slices)| {
            !physical.is_multiple_of(stela_soc_data::dart::DAPF_BYTES)
                || slices == 0
                || slices as u64 > stela_soc_data::dart::DAPF_BYTES / 0x40
        }) {
            return Err("DART APF requires one aligned window with a native slice count".into());
        }
        if ranges.iter().any(|range| {
            !profile.admits_window(range.bytes)
                || !range
                    .physical
                    .is_multiple_of(stela_soc_data::dart::DAPF_BYTES)
                || range.physical.checked_add(range.bytes).is_none()
        }) {
            return Err(
                "DART translation ranges must be aligned windows of the profile's register file"
                    .into(),
            );
        }
        let models = Dart::group_for_profile(profile, streams, irq, ranges.len())?;
        self.place_dart_group(models, ranges, apf, irq)
            .map_err(|error| format!("DART native placement: {error:?}"))
    }

    fn place_dart_group(
        &mut self,
        models: Vec<Dart>,
        ranges: &[Range],
        apf: Option<(u64, usize)>,
        irq: Option<AicInput>,
    ) -> Result<Vec<DartId>, MapError> {
        let mut models = models;
        self.share_dart_irq(&mut models, irq);
        let mut ids = Vec::new();
        for (index, (mut dart, range)) in models.into_iter().zip(ranges).enumerate() {
            if index == 0
                && let Some((_, slices)) = apf
            {
                dart = dart.with_apf(slices);
            }
            let device = self.bus.add(Box::new(dart));
            self.map(device, &[*range])?;
            if index == 0
                && let Some((physical, _)) = apf
            {
                self.bus.map(
                    device,
                    physical,
                    stela_soc_data::dart::DAPF_BYTES,
                    dart::DAPF_OFFSET,
                )?;
            }
            ids.push(DartId(device));
        }
        Ok(ids)
    }

    /// Fresh models have no asserted source and were built with this exact
    /// input. Bind before publishing any aperture, preserving all existing
    /// groups on the physical wire when a later group is added.
    fn share_dart_irq(&mut self, models: &mut [Dart], input: Option<AicInput>) {
        let Some(input) = input else { return };
        let shared = match self.dart_irqs.iter().find(|(key, _)| *key == input) {
            Some((_, shared)) => shared.clone(),
            None => {
                let shared = dart::SharedIrq::new(input);
                self.dart_irqs.push((input, shared.clone()));
                shared
            }
        };
        for model in models {
            model
                .bind_shared_irq(&shared)
                .expect("fresh DART retains its declared inactive physical input");
        }
    }

    /// Map the capture view of an existing DART, sharing its lifecycle.
    /// Validate and map before attaching so a failed placement changes neither
    /// the device's capabilities nor the physical address map.
    pub fn add_dart_smmu(&mut self, dart: DartId, range: Range) -> Result<(), String> {
        if range.bytes != dart::SMMU_BYTES || !range.physical.is_multiple_of(dart::SMMU_BYTES) {
            return Err("DART SMMU range must be one aligned 16 KiB aperture".into());
        }
        let model = self
            .bus
            .device::<Dart>(dart.0)
            .ok_or("DART SMMU owner is not a DART")?;
        if !model.supports_smmu() {
            return Err("DART generation has no supported paired SMMU capture format".into());
        }
        if model.has_smmu() {
            return Err("DART already has a paired SMMU view".into());
        }
        self.bus
            .map(dart.0, range.physical, range.bytes, dart::SMMU_OFFSET)
            .map_err(|error| format!("DART SMMU mapping: {error:?}"))?;
        self.bus
            .device_mut::<Dart>(dart.0)
            .expect("validated DART owner remains present")
            .enable_smmu()
            .expect("validated DART capture support and uniqueness remain unchanged");
        Ok(())
    }

    /// A `dart,t8110` of `streams` streams at `range`.
    pub fn add_dart(
        &mut self,
        range: Range,
        streams: usize,
        irq: Option<AicInput>,
        apf: Option<(u64, usize)>,
    ) -> Result<DartId, MapError> {
        let mut model = Dart::new(streams, irq);
        self.share_dart_irq(core::slice::from_mut(&mut model), irq);
        if let Some((_, slices)) = apf {
            model = model.with_apf(slices);
        }
        let device = self.bus.add(Box::new(model));
        self.bus.map(device, range.physical, range.bytes, 0)?;
        if let Some((physical, _)) = apf {
            self.bus.map(
                device,
                physical,
                stela_soc_data::dart::DAPF_BYTES,
                dart::DAPF_OFFSET,
            )?;
        }
        Ok(DartId(device))
    }

    /// SEP ROM prefix at DT wrapper/auxiliary ranges, on its four mailbox
    /// lines and dart-sep stream. This does not admit SEP in `stela_soc_data::board::models`.
    pub fn add_sep(
        &mut self,
        [wrapper, auxiliary]: [Range; 2],
        lines: asc::Lines,
        (dart, stream): (DartId, usize),
        entropy: Box<dyn sep::Entropy>,
        provisioning: SepProvisioning,
    ) -> Result<(), String> {
        let SepProvisioning {
            security,
            ecid,
            observe,
            state,
        } = provisioning;
        if wrapper.bytes < asc::WRAPPER_BYTES || auxiliary.bytes == 0 {
            return Err("SEP register apertures are incomplete".into());
        }
        let owner = self
            .bus
            .device::<Dart>(dart.0)
            .ok_or("SEP DMA owner is not a mounted DART")?;
        if stream >= owner.stream_capacity() {
            return Err("SEP incoming stream exceeds its mounted DART capacity".into());
        }
        let device = self.bus.add(Box::new(
            Sep::new(entropy, lines, security, ecid, observe, state).map_err(String::from)?,
        ));
        self.bus
            .map(device, wrapper.physical, wrapper.bytes, 0)
            .map_err(|e| format!("SEP wrapper placement: {e:?}"))?;
        self.bus
            .map(
                device,
                auxiliary.physical,
                auxiliary.bytes,
                sep::AUXILIARY_OFFSET,
            )
            .map_err(|e| format!("SEP auxiliary placement: {e:?}"))?;
        self.sep_masters.push(SepMaster {
            sep: device,
            dart: dart.0,
            stream,
        });
        Ok(())
    }

    /// Place the core once, with reg[2]/reg[8] sharing reg[0]'s bytes.
    /// Platform windows keep distinct refusing offsets; reg[3] and reg[4]
    /// are the pipehandler and core event block, which the ATC PHY placement
    /// owns (`atc-phy-parent`). IRQ indices 0..3
    /// are from AppleUSBXDCI::goOnBus (KC 0x42f5338/5380/53c8/5d24),
    /// passed unchanged to EventHandler::withParameters; initializePlatformSettings
    /// at 0x4338e74 chooses four handlers. The fifth ADT IRQ is not an event ring.
    pub fn add_usb(
        &mut self,
        placement: &stela_soc_data::board::UsbController,
        dart: DartId,
    ) -> Result<UsbId, String> {
        self.validate_native_dart("USB", dart, placement.stream as usize)?;
        let binding = self
            .phys
            .iter()
            .find(|phy| phy.phandle == placement.phy && phy.port == placement.port)
            .ok_or_else(|| {
                format!(
                    "USB atc-phy-parent {:#x} has no placed PHY on connector {}",
                    placement.phy, placement.port
                )
            })?;
        if binding.pipe != Some(placement.ranges[3]) || binding.events != placement.ranges[4] {
            return Err(
                "USB PHY lacks the matching physical pipehandler reset/event windows".into(),
            );
        }
        let phy = binding.device;
        let state = self
            .bus
            .device::<AtcPhy>(phy)
            .expect("placed PHY type")
            .usb2_state();
        let connector = self.typec_port(placement.port);
        let irqs = core::array::from_fn(|n| AicInput::new(0, placement.irqs[n] as u16));
        let mut model = Dwc3::new(irqs);
        model.set_phy_state(
            state.controller_reset,
            state.ready,
            state.clocked,
            state.quiesced,
            &mut Access::new(0, 0, &mut self.latch),
        );
        let device = self.bus.add(Box::new(model));
        let (physical, bytes) = placement.ranges[0];
        self.bus
            .map(device, physical, bytes, 0)
            .map_err(|e| format!("DWC3 placement: {e:?}"))?;
        for index in [1, 5, 6, 7] {
            let (physical, bytes) = placement.ranges[index];
            self.bus
                .map(
                    device,
                    physical,
                    bytes,
                    dwc3::PLATFORM_WINDOW_BASE + index as u64 * dwc3::PLATFORM_WINDOW_STRIDE,
                )
                .map_err(|e| format!("USB platform window {index}: {e:?}"))?;
        }
        self.usb_masters.push(UsbMaster {
            device,
            phy,
            phy_changed: true,
            dart: dart.0,
            stream: placement.stream as usize,
            session: UsbSession::new(),
            port: UsbPort::of(&connector),
            number: placement.port,
            connector,
            peripheral: None,
            next_poll: 0,
            attached: false,
            epoch: 0,
            retention: placement.retention,
            session_reset: false,
        });
        Ok(UsbId(device))
    }
    /// A cable change on one Type-C connector, as the external peer makes
    /// it. The connector's HPM dies and USB controller observe the same state.
    pub fn set_connection(
        &mut self,
        connector: u32,
        connection: Option<typec::Attached>,
    ) -> Result<(), &'static str> {
        self.typec_port(connector).set_connection(connection)?;
        Ok(())
    }
    /// Cables a native high-speed hub to Type-C connector `connector`,
    /// this machine being the downstream-facing port that sources VBUS: the
    /// HPM reports the attach and the controller's host personality finds
    /// the hub on its USB2 port. The keyboard and pointer sit on the hub's
    /// first port, and `cables` names the USB Ethernet adapter and mass
    /// storage devices on the next ones.
    pub fn attach_input(&mut self, connector: u32, cables: UsbCables) -> Result<(), &'static str> {
        let UsbCables { disks, network } = cables;
        if 1 + usize::from(network.is_some()) + disks.len() > hub::MAX_PORTS {
            return Err("the native hub has seven ports");
        }
        let network = network.map(Ecm::new).transpose()?;
        let disks = disks
            .into_iter()
            .map(MassStorage::of)
            .collect::<Result<Vec<_>, _>>()?;
        let master = self
            .usb_masters
            .iter_mut()
            .find(|master| master.number == connector)
            .ok_or("no USB controller on that connector")?;
        let attachments = Attachments {
            input: Peripheral::new(),
            network,
            disks,
        };
        master.peripheral = Some(Hub::new(attachments, "0001")?);
        master.connector.set_connection(Some(typec::Attached {
            orientation: typec::Orientation::Normal,
            role: typec::DataRole::Dfp,
            source: true,
            vbus: true,
            speed: typec::Usb2Speed::High,
        }))?;
        Ok(())
    }

    fn usb_network(&mut self) -> Result<&mut Ecm, &'static str> {
        self.usb_masters
            .iter_mut()
            .find_map(|master| master.peripheral.as_mut()?.ports.network.as_mut())
            .ok_or("no USB Ethernet adapter is attached")
    }

    /// A frame from the host network for the guest's USB Ethernet adapter;
    /// dropped as the adapter's filter and queue decide.
    pub fn network_deliver(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        self.usb_network()?.deliver(frame);
        Ok(())
    }

    /// Whether the guest has its USB Ethernet link up, and the adapter's
    /// counters; `None` without an adapter.
    pub fn network_status(&mut self) -> Option<(bool, UsbNetworkCounters)> {
        let network = self.usb_network().ok()?;
        Some((network.up(), network.counters()))
    }

    /// Whether the guest's USB Ethernet adapter has room for a frame from
    /// the host network; false without an adapter.
    pub fn network_room(&mut self) -> bool {
        self.usb_network().is_ok_and(|network| network.has_room())
    }

    /// The next frame the guest sent through its USB Ethernet adapter.
    pub fn network_take(&mut self) -> Option<Vec<u8>> {
        self.usb_network().ok()?.take()
    }

    /// The keyboard LEDs the guest set on the attached peripheral, Num Lock
    /// in bit 0 as input LED codes number them.
    pub fn keyboard_leds(&self) -> Option<u8> {
        self.usb_masters
            .iter()
            .find_map(|master| master.peripheral.as_ref())
            .map(|peripheral| peripheral.ports.input.leds())
    }

    /// One host input change for the attached peripheral.
    pub fn input(&mut self, input: Input) -> Result<(), &'static str> {
        self.usb_masters
            .iter_mut()
            .find_map(|master| master.peripheral.as_mut())
            .ok_or("no input peripheral is attached")?
            .ports
            .input
            .input(input)
    }

    /// The machine's power button went down or up. The SMC reports it to
    /// the AP as a HID button notification once the AP has enabled them;
    /// while the SoC sleeps a press is a wake source instead (`sleep`).
    pub fn power_button(&mut self, pressed: bool) -> Result<(), &'static str> {
        if self.smc()?.power_button(pressed) {
            self.wake(smc::WakeSource::PowerButton);
        }
        Ok(())
    }

    fn publish_rtc_time(&self, now: u64) -> Result<(), DeviceError> {
        if let Some(clock) = &self.rtc_clock {
            clock
                .publish(now)
                .map_err(|reason| DeviceError::Refused(reason.into()))?;
        }
        Ok(())
    }
    /// Record the count board entry `entry` was given.
    fn observe_time(&self, now: u64, entry: &'static str) {
        let seen = self.time_seen.get();
        if now < seen.0 {
            if self.time_regression.get().is_none() {
                self.time_regression.set(Some([(now, entry), seen]));
            }
        } else {
            self.time_seen.set((now, entry));
        }
    }

    /// A PMU oscillator's last backwards counter, and the first board entry
    /// given an earlier count than another, for a stop's reason.
    fn rtc_regression(&self) -> String {
        let mut reason = String::new();
        if let Some((now, published)) = self
            .rtc_clock
            .iter()
            .chain(&self.pmu_clocks)
            .find_map(pmu::RtcClock::regression)
        {
            reason += &format!(" (PMU counter {now:#x} after publication {published:#x})");
        }
        if let Some([(now, entry), (seen, before)]) = self.time_regression.get() {
            reason += &format!(" ({entry} at {now:#x} after {before} at {seen:#x})");
        }
        reason
    }

    fn publish_rtc_time_or_halt(&mut self, now: u64) -> bool {
        if let Err(error) = self.publish_rtc_time(now) {
            if self.reset.is_none() {
                self.reset = Some(Reset {
                    transition: Transition::Halt,
                    reason: format!(
                        "RTC service time refused: {error:?}{}",
                        self.rtc_regression()
                    ),
                });
            }
            false
        } else {
            true
        }
    }

    /// The SMC's native key endpoint.
    fn smc(&mut self) -> Result<&mut Smc, &'static str> {
        let &(_, id) = self
            .coprocessors
            .iter()
            .find(|(role, _)| *role == "SMC")
            .ok_or("the board has no SMC")?;
        self.bus
            .device_mut::<Asc>(id)
            .and_then(Asc::firmware_mut::<RtKit>)
            .and_then(|rtkit| rtkit.endpoint_mut::<Smc>(smc::ENDPOINT))
            .ok_or("the SMC coprocessor has no native key endpoint")
    }

    pub fn usb_client(&mut self, id: UsbId) -> Result<UsbClient<'_>, &'static str> {
        let master = self
            .usb_masters
            .iter_mut()
            .find(|master| master.device == id.0)
            .ok_or("unknown USB controller")?;
        let reset = self
            .bus
            .device_mut::<Dwc3>(master.device)
            .expect("USB master owns DWC3")
            .take_session_reset();
        master.cancel_session(reset)?;
        Ok(UsbClient(&mut master.session))
    }
    /// One observed key write, including its unchanged raw reply or refusal.
    pub fn take_smc_log(&mut self) -> Option<SmcWriteLog> {
        self.smc().ok()?.take_log()
    }

    /// Pure preflight of boxed ownership and incoming-SID capacity.
    /// Boot adapters validate every declared bank/mapper before publication;
    /// this does not enable DMA or check a physical traffic classifier.
    pub fn validate_native_dart(
        &self,
        name: &str,
        dart: DartId,
        stream: usize,
    ) -> Result<(), String> {
        let owner = self
            .bus
            .device::<Dart>(dart.0)
            .ok_or_else(|| format!("{name} DMA owner is not a mounted DART"))?;
        if stream >= owner.stream_capacity() {
            return Err(format!(
                "{name} incoming stream exceeds its mounted DART capacity"
            ));
        }
        Ok(())
    }

    /// The next entry of a display coprocessor's log: what the guest sent
    /// the DCP model and what it answered or refused.
    pub fn take_display_log(&mut self) -> Option<DisplayLog> {
        let ids: Vec<DeviceId> = self.dcp_masters.iter().map(|master| master.asc).collect();
        ids.into_iter().find_map(|id| {
            self.bus
                .device_mut::<Asc>(id)
                .and_then(Asc::firmware_mut::<dcp::Coprocessor>)
                .and_then(dcp::Coprocessor::take_log)
        })
    }

    /// Each USB controller's connector, whether a host session is attached
    /// and, while one cannot be, why: for the boot log.
    pub fn usb_diagnostics(&self) -> Vec<String> {
        self.usb_masters
            .iter()
            .map(|master| {
                let controller = self.bus.device::<Dwc3>(master.device).expect("USB core");
                let phy = self.bus.device::<AtcPhy>(master.phy).expect("USB PHY");
                let why = match controller.unavailable() {
                    Some(why) if !controller.phy_ready() => {
                        format!(" unavailable={why}: {}", phy.usb2_unready().unwrap_or("?"))
                    }
                    Some(why) => format!(" unavailable={why}"),
                    None => String::new(),
                };
                let host = controller
                    .host_summary()
                    .map_or_else(String::new, |host| format!(" host=[{host}]"));
                format!(
                    "port={} attached={}{why}{host}",
                    master.number, master.attached
                )
            })
            .collect()
    }

    pub fn take_usb_log(&mut self) -> Option<UsbLog> {
        self.usb_masters
            .iter_mut()
            .find_map(|master| master.session.take_log())
    }

    /// The next line of a USB controller's host trace, with its port.
    pub fn take_usb_host_trace(&mut self) -> Option<(u32, String)> {
        self.usb_masters.iter().find_map(|master| {
            self.bus
                .device_mut::<Dwc3>(master.device)
                .and_then(Dwc3::take_host_trace)
                .map(|line| (master.number, line))
        })
    }

    /// An `aes,s8000` the ADT describes in `config`, at its block and
    /// key-disable ranges and, from version 5, its DKey range, whose DMA
    /// goes through `stream` of `dart` and whose UID1 key is `uid`, if the
    /// board has one.
    pub fn add_aes(
        &mut self,
        ranges: &[Range],
        config: stela_soc_data::aes::Config,
        irq: Option<AicInput>,
        (dart, stream): (DartId, usize),
        uid: Option<[u8; 32]>,
    ) -> Result<(), String> {
        self.validate_native_dart("AES", dart, stream)?;
        let expected = if config.has_dkey() { 3 } else { 2 };
        if ranges.len() != expected {
            return Err(format!(
                "AES aes-version {} has {expected} register ranges, not {}",
                config.version,
                ranges.len()
            ));
        }
        if ranges[0].bytes != aes::BLOCK_BYTES {
            return Err(format!(
                "AES block registers span {:#x} bytes, not the modeled {:#x}",
                ranges[0].bytes,
                aes::BLOCK_BYTES
            ));
        }
        if ranges[1].bytes != config.key_disable.bytes {
            return Err("AES key-disable range differs from its layout".into());
        }
        let engine = Aes::new(config, irq, uid).map_err(String::from)?;
        let device = self.bus.add(Box::new(engine));
        self.map(device, ranges)
            .map_err(|error| format!("AES placement: {error:?}"))?;
        self.register_power_device(ranges[0].physical, device, false)?;
        self.masters.push(Master {
            aes: device,
            dart: dart.0,
            stream,
        });
        Ok(())
    }

    /// The PMGR power-state registers at `registers`, in `blocks` of guest
    /// PA. Each starts active under the existing boot assumption; this is
    /// not a checked transfer of the original firmware's control words.
    pub fn add_power_states(&mut self, blocks: &[Range], registers: &[u64]) -> Result<(), String> {
        if self.pmgr.is_some() {
            return Err("PMGR lifecycle owner is already bound".into());
        }
        let states = registers.iter().map(|&address| PowerState {
            address,
            initial: ACTIVE,
        });
        let model = Pmgr::new(states).map_err(|error| format!("PMGR states: {error:?}"))?;
        // The model's offsets are guest PAs. Publish all banks together.
        let bindings: Vec<_> = blocks
            .iter()
            .map(|block| (block.physical, block.bytes, block.physical))
            .collect();
        let device = self
            .bus
            .install(Box::new(model), &bindings)
            .map_err(|error| format!("PMGR placement: {error:?}"))?;
        self.pmgr = Some(device);
        Ok(())
    }

    /// Register a model's checked lifecycle boundary against its
    /// canonical first physical aperture. Several real banks may serve one
    /// hardware owner; a bank must not receive conflicting duplicate inputs.
    pub fn register_power_device(
        &mut self,
        physical: u64,
        device: DeviceId,
        retention: bool,
    ) -> Result<(), String> {
        if self.power_configured
            || self
                .power_devices
                .iter()
                .any(|entry| entry.device == device)
        {
            return Err("native lifecycle registration is duplicate or already bound".into());
        }
        if self.bus.lifecycle(device).is_none() {
            return Err(format!(
                "native lifecycle at {physical:#x} has no actual model hook"
            ));
        }
        self.power_devices.push(PowerDevice {
            physical,
            device,
            retention,
        });
        Ok(())
    }

    /// Account for every original resource before connecting lifecycle.
    /// Mapper views have the same hardware owner as their DART. Other
    /// hardware needs its own real sinks. Validate all links before enabling
    /// any register control.
    pub fn connect_power_resources(
        &mut self,
        states: &stela_soc_data::board::PowerStates,
        darts: &[Vec<DartId>],
        retention: &[bool],
    ) -> Result<(), String> {
        if self.power_configured || darts.len() != retention.len() {
            return Err("PMGR binding is duplicate or has mismatched DART groups".into());
        }
        let pmgr = self
            .pmgr
            .and_then(|id| self.bus.device::<Pmgr>(id))
            .ok_or("PMGR resources have no mapped power-state model")?;
        let complete = LifecycleSinks {
            clock: true,
            power: true,
            quiesce: true,
            reset: true,
        };
        let mut devices = Vec::new();
        for instances in darts {
            if instances.is_empty() {
                return Err("PMGR binding has an empty DART group".into());
            }
            for dart in instances {
                if self.bus.device::<Dart>(dart.0).is_none() || devices.contains(&dart.0) {
                    return Err("PMGR binding is duplicate or not a DART".into());
                }
                devices.push(dart.0);
            }
        }
        let power_requirements = states.power_requirements()?;
        let mut consumers = Vec::new();
        for (id, resource) in states.resources.iter().enumerate() {
            let connected = resource.owner.is_some_and(|owner| match owner {
                PowerOwner::Mmio(physical) => self
                    .power_devices
                    .iter()
                    .any(|entry| entry.physical == physical),
                _ => true,
            });
            if connected && resource.admission == coverage::Admission::Unavailable {
                return Err(format!("{} is both unavailable and placed", resource.name));
            }
            if resource.owner.is_some_and(|owner| match owner {
                PowerOwner::Dart(index) => index >= darts.len(),
                PowerOwner::Usb(index) => index >= self.usb_masters.len(),
                PowerOwner::Phy(index) => index >= self.phys.len(),
                PowerOwner::Mmio(_) => false,
            }) {
                return Err(format!(
                    "{} names an unplaced hardware lifecycle owner",
                    resource.name
                ));
            }
            consumers.push(Consumer {
                id,
                name: &resource.name,
                clocks: resource.activated_clocks(),
                power: &power_requirements[id],
                admission: resource.admission,
                sinks: if connected {
                    complete
                } else {
                    LifecycleSinks::default()
                },
            });
        }
        let coverage = coverage::analyze(&states.domains, &consumers)
            .map_err(|error| format!("PMGR resource coverage: {error:?}"))?;
        if coverage.len() != states.registers.len()
            || coverage.iter().any(|record| {
                !states.registers.contains(&record.address)
                    || pmgr.domain_state(record.address).is_none()
            })
        {
            return Err("PMGR resource graph differs from mapped power states".into());
        }
        let mut clients = darts
            .iter()
            .enumerate()
            .flat_map(|(index, instances)| {
                instances
                    .iter()
                    .map(move |dart| (PowerOwner::Dart(index), dart.0, retention[index]))
            })
            .collect::<Vec<_>>();
        clients.extend(
            self.usb_masters
                .iter()
                .enumerate()
                .map(|(index, master)| (PowerOwner::Usb(index), master.device, master.retention)),
        );
        clients.extend(
            self.phys
                .iter()
                .enumerate()
                .map(|(index, phy)| (PowerOwner::Phy(index), phy.device, phy.retention)),
        );
        clients.extend(self.power_devices.iter().map(|entry| {
            (
                PowerOwner::Mmio(entry.physical),
                entry.device,
                entry.retention,
            )
        }));
        let mut links = Vec::new();
        for (owner, device, retention) in clients {
            let domains = coverage
                .iter()
                .filter(|record| {
                    record
                        .consumers
                        .iter()
                        .any(|consumer| states.resources[consumer.id].owner == Some(owner))
                })
                .map(|record| {
                    (
                        record.address,
                        pmgr.domain_state(record.address).expect("validated domain"),
                    )
                })
                .collect::<Vec<_>>();
            let resources = states
                .resources
                .iter()
                .filter(|resource| resource.owner == Some(owner))
                .map(|resource| resource.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            links.push(PowerClient {
                resources,
                device,
                owner,
                domains,
                retention,
            });
        }
        // A domain no inventoried resource names is controller-only: it
        // completes its own state machine and has no client to deliver to.
        let refusals = coverage
            .iter()
            .filter(|record| !record.bindable() && !record.controller_only())
            .map(|record| {
                let names = record
                    .consumers
                    .iter()
                    .filter(|consumer| {
                        consumer.admission == coverage::Admission::Required
                            && !consumer.sinks.complete()
                    })
                    .map(|consumer| consumer.name.as_str())
                    .collect::<Vec<_>>();
                let identities = states
                    .domains
                    .iter()
                    .filter(|domain| domain.address == Some(record.address))
                    .map(|domain| {
                        format!(
                            "{:?} (die {} ID {:#x})",
                            domain.name, domain.id.die, domain.id.device
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                (
                    record.address,
                    format!(
                        "{identities}: lifecycle sinks missing for {}",
                        names.join(", ")
                    ),
                )
            })
            .collect();
        let pmgr = self
            .bus
            .device_mut::<Pmgr>(self.pmgr.expect("validated PMGR"))
            .expect("PMGR type");
        for record in coverage {
            let result = if record.bindable() || record.controller_only() {
                pmgr.bind_lifecycle(record.address)
            } else {
                pmgr.refuse_lifecycle(record.address)
            };
            result.map_err(|error| format!("PMGR resource binding: {error:?}"))?;
        }
        self.power_clients = links;
        self.power_refusals = refusals;
        self.power_configured = true;
        Ok(())
    }

    /// Resource names for domains whose consumers still lack sinks.
    pub fn power_refusals(&self) -> &[(u64, String)] {
        &self.power_refusals
    }

    /// A CPU cluster's PMGR registers at `base`: its register window, with
    /// the DVMR tables the boot firmware programmed, and its `pstates`
    /// performance-state slots.
    pub fn add_cpu_cluster(
        &mut self,
        base: u64,
        dvmr: &[(u64, u64)],
        pstates: usize,
        counter_capacity: usize,
        mapped: bool,
        events: &[u8],
    ) -> Result<(), String> {
        let model = Cluster::new(dvmr, pstates)
            .and_then(|c| c.with_counters(counter_capacity, mapped, events))
            .map_err(String::from)?;
        let table = model.pstate_bytes();
        let device = self.bus.add(Box::new(model));
        for (offset, bytes) in [
            (cluster::ACC_OFFSET, cluster::ACC_BYTES),
            (cluster::PSTATE_OFFSET, table),
            (cluster::SCRATCH[0], 8),
            (cluster::SCRATCH[1], 8),
        ] {
            self.bus
                .map(device, base + offset, bytes, offset)
                .map_err(|error| format!("CPU cluster placement: {error:?}"))?;
        }
        Ok(())
    }

    /// CPM throttlers and restore command in the DT-validated CPM window.
    pub fn add_cpm_power(&mut self, physical: u64, performance: bool) -> Result<(), String> {
        let model = Cpm::new(performance);
        let offsets = model.offsets();
        let device = self.bus.add(Box::new(model));
        for offset in offsets {
            self.bus
                .map(
                    device,
                    physical
                        .checked_add(offset)
                        .ok_or("CPM address overflows")?,
                    8,
                    offset,
                )
                .map_err(|e| format!("CPM power placement: {e:?}"))?;
        }
        Ok(())
    }

    /// One fabric bridge; only described configuration and command words map.
    pub fn add_bridge(
        &mut self,
        physical: u64,
        fields: &[(u64, u32)],
        header: [u8; 4],
        configs: &[[u8; 36]],
        axi: Option<[u8; 4]>,
    ) -> Result<(), String> {
        let model = Bridge::new(fields, header, configs, axi).map_err(String::from)?;
        let spans = model.spans();
        let device = self.bus.add(Box::new(model));
        for (o, n) in spans {
            self.bus
                .map(
                    device,
                    physical.checked_add(o).ok_or("bridge address overflows")?,
                    n,
                    o,
                )
                .map_err(|e| format!("bridge placement: {e:?}"))?;
        }
        Ok(())
    }

    /// SOC DPE sample aliases and enable words, each mapped sparsely.
    pub fn add_soc_dpe(&mut self, physical: u64, samples: &[(u64, bool)]) -> Result<(), String> {
        let model = Dpe::new(samples).map_err(String::from)?;
        let spans = model.spans();
        let device = self.bus.add(Box::new(model));
        for (o, n) in spans {
            self.bus
                .map(
                    device,
                    physical.checked_add(o).ok_or("SOC DPE address overflows")?,
                    n,
                    o,
                )
                .map_err(|e| format!("SOC DPE placement: {e:?}"))?;
        }
        Ok(())
    }

    /// A typed SOC configuration bank at its DT `reg` address.
    pub fn add_soc_power(
        &mut self,
        physical: u64,
        kind: stela_soc_data::power::Kind,
    ) -> Result<(), String> {
        let model = Power::new(kind);
        let device = self.bus.add(Box::new(model));
        for offset in kind.offsets() {
            self.bus
                .map(
                    device,
                    physical
                        .checked_add(offset)
                        .ok_or("SOC power address overflows")?,
                    4,
                    offset,
                )
                .map_err(|e| format!("SOC power placement: {e:?}"))?;
        }
        Ok(())
    }

    /// The eight active-low AOP wake masks at the board's `reg` bank +8,
    /// with the source number of the SMC's wake of the AP when the board
    /// names it.
    pub fn add_wake_masks(
        &mut self,
        physical: u64,
        valid: [u32; wake::WORDS],
        smc_wake: Option<u8>,
    ) -> Result<(), String> {
        let device = self.bus.add(Box::new(WakeMasks::new(valid)));
        self.sleep.wake_masks = Some((device, smc_wake));
        self.bus
            .map(device, physical, wake::BYTES, 0)
            .map_err(|error| format!("AOP wake mask placement: {error:?}"))
    }

    /// One version-1 PMGR performance bank, at its `perf-regs` global word.
    pub fn add_performance_counters(
        &mut self,
        physical: u64,
        selectors: &[u16],
    ) -> Result<(), String> {
        let model = PerfCounters::new(selectors).map_err(String::from)?;
        let spans = model.spans();
        let device = self.bus.add(Box::new(model));
        for (offset, bytes) in spans {
            self.bus
                .map(
                    device,
                    physical
                        .checked_add(offset)
                        .ok_or("PMGR performance address overflows")?,
                    bytes,
                    offset,
                )
                .map_err(|error| format!("PMGR performance placement: {error:?}"))?;
        }
        Ok(())
    }

    /// A CPU/CPM energy bank at its absolute `hw-dpe-reg` address. Map only
    /// the two accumulators and, for CPM, its separate configuration word.
    pub fn add_cpu_energy(&mut self, physical: u64, cpm: bool) -> Result<(), String> {
        let device = self.bus.add(Box::new(Energy::new(cpm)));
        self.bus
            .map(device, physical, energy::COUNTER_BYTES, 0)
            .map_err(|error| format!("CPU energy placement: {error:?}"))?;
        if cpm {
            self.bus
                .map(
                    device,
                    physical
                        .checked_add(energy::CONTROL_OFFSET)
                        .ok_or("CPM energy configuration address overflows")?,
                    8,
                    energy::CONTROL_OFFSET,
                )
                .map_err(|error| format!("CPM energy configuration placement: {error:?}"))?;
        }
        Ok(())
    }

    /// The always-on eFuse block at `physical`.
    pub fn add_aon_fuses(&mut self, physical: u64) -> Result<(), String> {
        let device = self.bus.add(Box::new(AonFuses));
        self.bus
            .map(device, physical, fuse::FUSE_BYTES, 0)
            .map_err(|error| format!("eFuse placement: {error:?}"))
    }

    /// The SoC watchdog; `now` is the counter value its timers start from.
    pub fn add_watchdog(
        &mut self,
        ranges: &[Range],
        irq: Option<AicInput>,
        now: u64,
    ) -> Result<(), MapError> {
        let device = self.bus.add(Box::new(AppleWdt::new(irq, now)));
        self.map(device, ranges)
    }

    /// The main watchdog and its independently DT-placed optional side words.
    pub fn add_watchdog_with_side(
        &mut self,
        range: Range,
        side: Option<&stela_soc_data::board::WatchdogSide>,
        irq: Option<AicInput>,
        now: u64,
    ) -> Result<(), String> {
        let Some(side) = side else {
            return self
                .add_watchdog(&[range], irq, now)
                .map_err(|e| format!("{e:?}"));
        };
        if !(2..=4).contains(&side.words.len()) {
            return Err("watchdog side controls require two to four complete words".into());
        }
        let shared_flags = side.words.len() == 4 && side.words[0] == side.words[3];
        let end = range
            .physical
            .checked_add(range.bytes)
            .ok_or("watchdog primary extent overflows")?;
        for (index, &physical) in side.words.iter().enumerate() {
            let last = physical
                .checked_add(4)
                .ok_or("watchdog side extent overflows")?;
            if !physical.is_multiple_of(4) {
                return Err("watchdog side word is unaligned".into());
            }
            if physical < end && range.physical < last {
                return Err("watchdog side word overlaps primary timer registers".into());
            }
            if side.words[..index].contains(&physical) && !(shared_flags && index == 3) {
                return Err("watchdog side alias lacks a qualified shared register owner".into());
            }
        }
        let mut triggers = Vec::new();
        for &(physical, mask, value) in &side.triggers {
            let last = physical
                .checked_add(4)
                .ok_or("watchdog trigger extent overflows")?;
            if !physical.is_multiple_of(4) || mask == 0 || value & !mask != 0 {
                return Err("watchdog trigger word or mask is invalid".into());
            }
            if (physical < end && range.physical < last) || side.words.contains(&physical) {
                return Err("watchdog trigger aliases a different register role".into());
            }
            if let Some(&previous) = triggers
                .iter()
                .find(|&&(address, _, _)| address == physical)
            {
                if previous != (physical, mask, value) {
                    return Err("watchdog shared trigger has conflicting configurations".into());
                }
            } else {
                triggers.push((physical, mask, value));
            }
        }
        let mut model = AppleWdt::new(irq, now).with_side_controls();
        if shared_flags {
            model = model.with_shared_panic_flags();
        }
        let device = self.bus.add(Box::new(model));
        self.map(device, &[range]).map_err(|e| format!("{e:?}"))?;
        let offsets = [
            wdt::PANIC_SAVE,
            wdt::MECHANISM,
            wdt::CONFIGURATION,
            wdt::POWER_OFF,
        ];
        for (index, (&physical, offset)) in side.words.iter().zip(offsets).enumerate() {
            if !(shared_flags && index == 3) {
                self.bus
                    .map(device, physical, 4, offset)
                    .map_err(|e| format!("{e:?}"))?;
            }
        }
        for (physical, mask, _) in triggers {
            let trigger = self.bus.add(Box::new(wdt::CoreTrigger::new(mask)));
            self.bus
                .map(trigger, physical, 4, 0)
                .map_err(|e| format!("{e:?}"))?;
        }
        Ok(())
    }

    /// The AIC at `physical`, serving this PE. NR_IRQ is each die's inputs
    /// (`machine::soc::InterruptController`), which the model reports in its
    /// INFO or CAP0 register (m1n1 `aic.c`, Linux `irq-apple-aic.c`). An
    /// AICv2's or AICv3's `layout` gives its MAX_IRQ and populated dies and
    /// says where its per-die arrays, timestamp slots and event register
    /// are; an AICv1's are fixed.
    pub fn add_aic(&mut self, physical: u64, nr_irq: u16, layout: AicLayout) -> Result<(), String> {
        self.add_aic_for_processors(physical, nr_irq, layout, 1)
    }

    /// Serve the unchanged board PE indices and default AICv2/v3 delivery to
    /// the selected boot PE. Group-bit affinity still requires its independent
    /// source-checked binding; this supplies no guessed target groups.
    pub fn add_aic_for_processors(
        &mut self,
        physical: u64,
        nr_irq: u16,
        layout: AicLayout,
        cpus: usize,
    ) -> Result<(), String> {
        if cpus == 0 || cpus > u64::BITS as usize || self.sleep.boot >= cpus {
            return Err("AIC boot PE is outside the served processor roster".into());
        }
        if self.aic.is_some() {
            return Err("AIC owner is already bound".into());
        }
        let (model, span, v1): (Box<dyn MmioDevice>, u64, bool) = match layout {
            AicLayout::V1 => {
                let aic = Aic1::new(nr_irq, cpus)
                    .map_err(|error| format!("AIC1 configuration: {error:?}"))?;
                (Box::new(aic), Aic1::span(), true)
            }
            AicLayout::V2 {
                version,
                irq_config,
                max_irq,
                event,
                timestamps,
                timestamp_base,
                dies,
            } => {
                let config = Aic2Config {
                    version,
                    timestamps: usize::from(timestamps),
                    timestamp_base,
                    nr_irq,
                    max_irq,
                    irq_config,
                    event_offset: event,
                    cpus,
                    default_cpus: 1 << self.sleep.boot,
                };
                let aic = Aic2::stacked(config, dies)
                    .map_err(|error| format!("AIC2 configuration: {error:?}"))?;
                let span = aic.span();
                (Box::new(aic), span, false)
            }
        };
        let id = self
            .bus
            .install(model, &[(physical, span, 0)])
            .map_err(|error| format!("AIC placement: {error:?}"))?;
        let device = if v1 {
            Controller::V1(id)
        } else {
            Controller::V2(id)
        };
        self.aic = Some(device);
        if matches!(device, Controller::V2(_)) {
            self.register_power_device(physical, id, false)?;
        }
        Ok(())
    }

    fn settle_phys(&mut self, cpu: CpuIndex, now: u64) {
        for master in &mut self.usb_masters {
            let state = self
                .bus
                .device::<AtcPhy>(master.phy)
                .expect("USB retains actual PHY")
                .usb2_state();
            let mut access = Access::new(cpu, now, &mut self.latch);
            let changed = self
                .bus
                .device_mut::<Dwc3>(master.device)
                .expect("USB retains actual core")
                .set_phy_state(
                    state.controller_reset,
                    state.ready,
                    state.clocked,
                    state.quiesced,
                    &mut access,
                );
            master.phy_changed |= changed;
            self.service
                .retain_reset(&mut self.reset, reset_reason(&access));
        }
    }

    fn settle_lifecycle(&mut self, cpu: CpuIndex, now: u64) {
        self.settle_power(cpu, now);
        self.settle_phys(cpu, now);
    }

    /// Validate every affected bank before a PMGR request can change
    /// its register or any client. A missing functional device is not created
    /// by controller-state completion. Partial capability failures are atomic.
    fn check_power_request(&mut self, physical: u64, value: u64) -> Result<(), DeviceError> {
        let Some(pmgr) = self.pmgr.and_then(|id| self.bus.device::<Pmgr>(id)) else {
            return Ok(());
        };
        if pmgr.domain_state(physical).is_none() {
            return Ok(());
        }
        let transition = pmgr.preview(physical, value as u32).map_err(|reason| {
            let resources = self
                .power_refusals
                .iter()
                .find(|(address, _)| *address == physical)
                .map(|(_, resources)| resources.as_str())
                .unwrap_or("request validation");
            let control = pmgr.control_word(physical).expect("described PMGR domain");
            DeviceError::Refused(format!(
                "PMGR domain {physical:#x} ({resources}): {reason}; current control {control:#010x}, requested {value:#010x}"
            ))
        })?;
        if transition.before == transition.after {
            return Ok(());
        }
        for link in &self.power_clients {
            if !matches!(link.owner, PowerOwner::Mmio(_))
                || !link.domains.iter().any(|(address, _)| *address == physical)
            {
                continue;
            }
            let states = link
                .domains
                .iter()
                .map(|(address, state)| {
                    if *address == physical {
                        transition.after
                    } else {
                        *state
                    }
                })
                .collect::<Vec<_>>();
            let proposed = LifecycleState {
                powered: states.iter().all(|state| state.power != POWER_GATED),
                clocked: states.iter().all(|state| state.power == ACTIVE),
                quiesced: states.iter().any(|state| state.disabled),
                reset: states.iter().any(|state| state.reset),
                retention: link.retention,
            };
            self.bus
                .lifecycle(link.device)
                .expect("binding checked actual lifecycle hook")
                .check_lifecycle(proposed)
                .map_err(|reason| {
                    DeviceError::Refused(format!(
                        "PMGR domain {physical:#x} ({}): {reason}",
                        link.resources
                    ))
                })?;
        }
        Ok(())
    }

    /// Replay each edge: off/on or reset assertion/release must still
    /// discard ordinary state even if the final image is active again.
    /// Infallible after binding, this runs before the next client effect,
    /// including after a bus/service operation returned a partial failure.
    fn settle_power(&mut self, cpu: CpuIndex, now: u64) {
        let Some(pmgr) = self.pmgr else {
            return;
        };
        let transitions = self
            .bus
            .device_mut::<Pmgr>(pmgr)
            .expect("PMGR type")
            .take_transitions();
        for transition in transitions {
            for link in &mut self.power_clients {
                let Some((_, state)) = link
                    .domains
                    .iter_mut()
                    .find(|(address, _)| *address == transition.address)
                else {
                    continue;
                };
                debug_assert_eq!(*state, transition.before, "PMGR lifecycle edge order");
                *state = transition.after;
                let powered = link
                    .domains
                    .iter()
                    .all(|(_, state)| state.power != POWER_GATED);
                let clocked = link.domains.iter().all(|(_, state)| state.power == ACTIVE);
                let quiesced = link.domains.iter().any(|(_, state)| state.disabled);
                let reset = link.domains.iter().any(|(_, state)| state.reset);
                let mut access = Access::new(cpu, now, &mut self.latch);
                match link.owner {
                    PowerOwner::Dart(_) => {
                        let dart = self
                            .bus
                            .device_mut::<Dart>(link.device)
                            .expect("binding checked DART");
                        dart.set_quiesced(quiesced);
                        dart.set_clock(clocked);
                        dart.set_reset(reset, &mut access);
                        dart.set_power(powered, link.retention, &mut access);
                    }
                    PowerOwner::Usb(_) => {
                        let usb = self
                            .bus
                            .device_mut::<Dwc3>(link.device)
                            .expect("binding checked USB controller");
                        usb.set_quiesced(quiesced);
                        usb.set_clock(clocked, &access);
                        usb.set_reset(reset, &mut access);
                        usb.set_power(powered, link.retention, &mut access);
                    }
                    PowerOwner::Mmio(_) => {
                        let state = LifecycleState {
                            powered,
                            clocked,
                            quiesced,
                            reset,
                            retention: link.retention,
                        };
                        self.bus
                            .lifecycle(link.device)
                            .expect("binding checked actual lifecycle hook")
                            .set_lifecycle(state, &mut access);
                    }
                    PowerOwner::Phy(_) => {
                        let phy = self
                            .bus
                            .device_mut::<AtcPhy>(link.device)
                            .expect("binding checked PHY");
                        phy.set_quiesced(quiesced);
                        phy.set_clock(clocked);
                        phy.set_reset(reset);
                        phy.set_power(powered, link.retention);
                    }
                }
                self.service
                    .retain_reset(&mut self.reset, reset_reason(&access));
            }
            self.settle_phys(cpu, now);
            self.service.lifecycle.push(transition);
        }
    }
}

fn width(bytes: u8) -> Result<Width, DeviceError> {
    Width::from_bytes(u64::from(bytes))
        .ok_or_else(|| DeviceError::Refused(format!("{bytes}-byte device access")))
}

fn reset_reason(access: &Access<'_>) -> Option<Reset> {
    access.reset_request().map(|request| Reset {
        transition: request.transition,
        reason: format!(
            "{}: {} at counter {}",
            request.device, request.reason, request.at
        ),
    })
}

impl Devices for AppleDevices {
    fn pc_sample_target(&self, physical: u64, bytes: u8) -> Option<usize> {
        self.pc_samplers
            .iter()
            .find_map(|&(cpu, register, _)| (physical == register && bytes == 4).then_some(cpu))
    }

    fn observe_pc_sample(&mut self, physical: u64, pc: u64) {
        if let Some(&(_, _, device)) = self
            .pc_samplers
            .iter()
            .find(|&&(_, register, _)| register == physical)
        {
            self.bus
                .device_mut::<PcSampler>(device)
                .expect("registered PC sampler")
                .observe(pc);
        }
    }

    fn read(&mut self, cpu: usize, physical: u64, bytes: u8, now: u64) -> Result<u64, DeviceError> {
        self.observe_time(now, "read");
        let consumed = self.consume_scalar_read(cpu, physical, bytes, now, None)?;
        consumed.settlement?;
        Ok(consumed.value)
    }

    fn requires_canonical_read(
        &self,
        _cpu: usize,
        physical: u64,
        shape: stela_engine::machine::engine::DeviceReadShape,
    ) -> bool {
        self.read_needs_ram(physical, shape)
    }

    /// CPU PMGR registers, which settle the board's processors, and the
    /// memory controller words that drain or flush to RAM.
    fn requires_canonical_write(&self, _cpu: usize, physical: u64, bytes: u8) -> bool {
        self.is_processor_power_register(physical)
            || self.read_needs_ram(
                physical,
                stela_engine::machine::engine::DeviceReadShape::Scalar { bytes },
            )
            || width(bytes).is_ok_and(|width| self.empty_cache_flush_needs_ram(physical, width))
    }

    fn read_canonical(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        now: u64,
        memory: &mut dyn stela_engine::machine::engine::CanonicalDeviceMemory,
    ) -> Result<stela_engine::machine::engine::ConsumedScalar, DeviceError> {
        self.observe_time(now, "read");
        self.consume_scalar_read(cpu, physical, bytes, now, Some(memory))
    }

    fn read_pair_canonical(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        now: u64,
        _memory: &mut dyn stela_engine::machine::engine::CanonicalDeviceMemory,
    ) -> Result<ConsumedPair, DeviceError> {
        self.observe_time(now, "paired read");
        // Only the Prepared publication/status owner has a checked
        // whole-pair read. Never consume two unrelated scalar registers here.
        self.read_pair(cpu, physical, bytes, now)?.ok_or_else(|| {
            DeviceError::TransferRefused(
                "canonical pair has no qualified whole-register owner".into(),
            )
        })
    }

    fn read_pair(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        now: u64,
    ) -> Result<Option<ConsumedPair>, DeviceError> {
        self.observe_time(now, "paired read");
        // Probe without effects: both members must belong to the same
        // joint resource at consecutive offsets, not adjacent PAs.
        let Some(width) = Width::from_bytes(u64::from(bytes)) else {
            return Ok(None);
        };
        let Ok((device, offset)) = self.bus.route(physical, width) else {
            return Ok(None);
        };
        let Some(next) = physical.checked_add(u64::from(bytes)) else {
            return Ok(None);
        };
        let Some(next_offset) = offset.checked_add(u64::from(bytes)) else {
            return Ok(None);
        };
        if self.bus.route(next, width).ok() != Some((device, next_offset)) {
            return Ok(None);
        }
        if !memory_resources::resource_for(&self.bus, device)
            .is_some_and(|owner| owner.supports_pair(offset, bytes))
        {
            return Ok(None);
        }
        self.publish_rtc_time(now)?;
        self.settle_lifecycle(cpu, now);
        let mut access = Access::new(cpu, now, &mut self.latch);
        let values = memory_resources::resource_for(&self.bus, device)
            .expect("paired read retains the prepared resource")
            .read_pair_values(offset, bytes, &mut access)
            .map_err(|reason| DeviceError::Refused(reason.into()))?;
        let reset = reset_reason(&access);
        let settlement = self.settle(cpu, now, reset);
        Ok(Some(ConsumedPair { values, settlement }))
    }

    fn write(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
    ) -> Result<(), DeviceError> {
        self.observe_time(now, "write");
        use stela_engine::machine::engine::ConsumedWrite;
        match self.consume_scalar_write(cpu, physical, bytes, value, now, None)? {
            ConsumedWrite::Complete { settlement } => settlement,
            ConsumedWrite::Prefix { error, .. } | ConsumedWrite::Unknown { error } => Err(error),
        }
    }

    fn write_canonical(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
        owners: &mut dyn stela_engine::machine::engine::CanonicalDeviceWrite,
    ) -> Result<stela_engine::machine::engine::ConsumedWrite, DeviceError> {
        self.observe_time(now, "write");
        if let Some(completed) =
            self.consume_processor_power_write(cpu, physical, bytes, value, now, owners)?
        {
            return Ok(completed);
        }
        use stela_engine::machine::engine::CanonicalDeviceMemory;
        let mut memory = owners.memory()?;
        memory.fence_cpu_memory();
        self.consume_scalar_write(cpu, physical, bytes, value, now, Some(&mut memory))
    }

    fn system_register(
        &mut self,
        cpu: usize,
        encoding: Encoding,
        write: Option<u64>,
        now: u64,
    ) -> Option<Result<u64, &'static str>> {
        self.observe_time(now, "System register");
        if !self.publish_rtc_time_or_halt(now) {
            return Some(Err("RTC counter publication refused; board halted"));
        }
        if let Some(device) = self.core_counters.get(cpu).copied().flatten()
            && let Some(value) = self
                .bus
                .device_mut::<CoreCounters>(device)
                .and_then(|counters| counters.register(encoding, write))
        {
            return Some(Ok(value));
        }
        let register = stela_engine::machine::fast_ipi::Register::decode(encoding)?;
        let ipi = self.ipi.as_mut()?;
        let kind = match write {
            Some(value) => AccessKind::Write { value },
            None => AccessKind::Read,
        };
        Some(
            ipi.access(cpu, register, kind, now, &mut self.latch)
                .map_err(|error| match error {
                    ipi::IpiError::UnknownCpu(_) => "fast IPI from a PE the board does not have",
                    ipi::IpiError::Unsupported(_, reason) => reason,
                }),
        )
    }

    fn serves_register(&self, encoding: Encoding) -> bool {
        self.ipi.is_some() && stela_engine::machine::fast_ipi::Register::decode(encoding).is_some()
            || self.core_counters.iter().flatten().any(|&device| {
                self.bus
                    .device::<CoreCounters>(device)
                    .is_some_and(|counters| counters.serves(encoding))
            })
    }

    fn lines(&mut self, cpu: usize, now: u64) -> Lines {
        self.observe_time(now, "lines");
        if !self.publish_rtc_time_or_halt(now) {
            return Lines::default();
        }
        self.settle_lifecycle(cpu, now);
        if let Some(ipi) = self.ipi.as_mut() {
            ipi.advance(now, &mut self.latch);
        }
        let mut access = Access::new(cpu, now, &mut self.latch);
        let advanced = self.bus.advance(&mut access);
        let reset = reset_reason(&access);
        let settled = self.settle(cpu, now, reset);
        if let Err(error) = advanced.map_err(describe).and(settled)
            && self.reset.is_none()
        {
            // A model that cannot advance stops the machine like a reset
            // would, with the model's own reason.
            self.reset = Some(Reset {
                transition: Transition::Halt,
                reason: format!("device advance refused: {error:?}{}", self.rtc_regression()),
            });
        }
        self.watch_pmu();
        // The AIC and the fast-IPI lines are the AP's, powered off with it.
        if self.sleep.asleep {
            return Lines::default();
        }
        let pins = self.latch.pins(cpu);
        Lines {
            irq: pins.irq,
            fiq: pins.fiq,
        }
    }

    /// The latched pins: [`Self::lines`] advances every device and settles
    /// every PE's pins at once, so another PE's need no advance until a
    /// device changes or its deadline passes.
    fn pins(&mut self, cpu: usize) -> Option<Lines> {
        if self.sleep.asleep {
            return Some(Lines::default());
        }
        let pins = self.latch.pins(cpu);
        Some(Lines {
            irq: pins.irq,
            fiq: pins.fiq,
        })
    }

    fn deadline(&mut self, now: u64) -> Option<u64> {
        self.observe_time(now, "deadline");
        if !self.publish_rtc_time_or_halt(now) {
            return None;
        }
        self.settle_lifecycle(0, now);
        // Time-driven state is the board's, not a PE's: the access names
        // cpu0.
        let deferred = self
            .ipi
            .as_mut()
            .and_then(|ipi| ipi.advance(now, &mut self.latch));
        let mut access = Access::new(0, now, &mut self.latch);
        let advanced = self.bus.advance(&mut access);
        let reset = reset_reason(&access);
        let device = advanced.as_ref().ok().copied().flatten();
        let settled = self.settle(0, now, reset);
        if let Err(error) = advanced.map_err(describe).and(settled) {
            if self.reset.is_none() {
                self.reset = Some(Reset {
                    transition: Transition::Halt,
                    reason: format!("device advance refused: {error:?}{}", self.rtc_regression()),
                });
            }
            return None;
        }
        self.watch_pmu();
        let usb = self
            .usb_masters
            .iter()
            .filter(|master| {
                (master.port.ready || master.attached)
                    && self
                        .bus
                        .device::<Dwc3>(master.device)
                        .is_some_and(Dwc3::lifecycle_active)
            })
            .map(|master| master.next_poll)
            .min();
        let device = match (device, usb) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        match (deferred, device) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    fn take_reset(&mut self) -> Option<Reset> {
        self.reset.take()
    }

    fn take_start(&mut self) -> Option<Start> {
        (!self.starts.is_empty()).then(|| self.starts.remove(0))
    }

    fn reset_vector(&self, cpu: usize) -> Option<u64> {
        self.locked_reset_vector(cpu)
    }

    fn processor_power(&mut self, cpu: usize, on: bool) {
        self.processor_powered(cpu, on);
    }

    /// An AICv2 or AICv3 stops sending IRQs to a CPU whose SIQ_CFG_EL1
    /// refuses them; an AICv1 is not documented to consult it.
    fn irq_steering(&mut self, cpu: usize, refuses: bool, now: u64) {
        self.observe_time(now, "IRQ steering");
        let Some(Controller::V2(id)) = self.aic else {
            return;
        };
        let mut access = Access::new(cpu, now, &mut self.latch);
        if let Some(aic) = self.bus.device_mut::<Aic2>(id) {
            aic.steer(cpu, refuses, &mut access);
        }
    }

    /// A sleeping SoC with no alarm due waits for the host's power button.
    fn waits_on_host(&self) -> bool {
        self.sleep.asleep
    }

    fn take_host_service(&mut self) -> bool {
        self.usb_masters
            .iter_mut()
            .fold(false, |due, master| master.session.take_due() | due)
    }

    fn memory_lock(&self) -> stela_engine::machine::mmu::MemoryLocks {
        let Some(device) = self.memory_controller else {
            return [None; stela_soc_data::amcc::GROUPS];
        };
        if let Some(locked) = memory_resources::resource_for(&self.bus, device)
            .and_then(|owner| owner.locked_regions())
        {
            locked
        } else if let Some(owner) = self
            .bus
            .device::<memory_resources::t8112::cache::EmptyResource>(device)
        {
            owner.locked_regions()
        } else if let Some(owner) = self
            .bus
            .device::<memory_resources::t8112::amcc::LockResource>(device)
        {
            owner.locked_regions()
        } else {
            self.bus
                .device::<Amcc>(device)
                .map_or([None; stela_soc_data::amcc::GROUPS], Amcc::locked_regions)
        }
    }

    fn dma_deadline(&self) -> Option<u64> {
        self.usb_masters
            .iter()
            .filter_map(|master| {
                let port = UsbPort::of(&master.connector);
                let controller = self.bus.device::<Dwc3>(master.device);
                if !controller.is_some_and(Dwc3::lifecycle_active) {
                    return None;
                }
                if master.phy_changed
                    || port != master.port
                    || controller.is_some_and(Dwc3::host_pending)
                {
                    return Some(0);
                }
                let poll = (port.ready || master.attached).then_some(master.next_poll);
                let function = master.peripheral.as_ref().map(|p| p as &dyn Function);
                let host = controller.and_then(|c| c.host_deadline(function));
                poll.into_iter().chain(host).min()
            })
            .chain(self.native_pmp_dma_deadline())
            .chain(self.native_pmp_services_deadline())
            // When to look for a storage command's host transfer.
            .chain(
                self.storage_masters
                    .iter()
                    .filter_map(|&(ans, _)| self.bus.device::<Ans>(ans)?.host_look()),
            )
            .min()
    }

    fn transfer(
        &mut self,
        cpu: usize,
        memory: &mut dyn Memory,
        now: u64,
    ) -> Result<(), DeviceError> {
        self.observe_time(now, "transfer");
        self.publish_rtc_time(now)?;
        self.settle_lifecycle(cpu, now);
        // SAFETY: the persistent native binding admits only the canonical
        // execution path. Its held cohort/fenced Host sessions and
        // exclusive synchronous device owner remain live through this step.
        unsafe {
            self.service_native_pmp_services(cpu, now)?;
            self.service_native_pmp_dma(cpu, memory, now)?;
            self.service_native_pmp_services(cpu, now)?;
        }
        for master in &self.masters {
            let (aes, dart) = self
                .bus
                .pair_mut::<Aes, Dart>(master.aes, master.dart)
                .expect("a master names an AES engine and its DART");
            if !aes.pending() {
                continue;
            }
            let mut access = Access::new(cpu, now, &mut self.latch);
            let mut port = Port {
                iommu: dart,
                stream: master.stream,
                memory,
                access: &mut access,
            };
            aes.run(&mut port).map_err(describe_transfer)?;
        }
        for &(ans, sart) in &self.storage_masters {
            let (ans, sart) = self
                .bus
                .pair_mut::<Ans, Sart>(ans, sart)
                .expect("a storage master names ANS2 and SART");
            if !ans.pending(now) {
                continue;
            }
            let mut access = Access::new(cpu, now, &mut self.latch);
            let mut port = Port {
                iommu: &mut Physical,
                stream: 0,
                memory,
                access: &mut access,
            };
            ans.run(&mut port, sart)
                .map_err(|error| match describe_transfer(error) {
                    DeviceError::TransferRefused(reason) => DeviceError::TransferRefused(format!(
                        "{reason}; ANS last submission {:02x?}",
                        ans.last_submission()
                    )),
                    other => other,
                })?;
        }
        for &(asc, block) in &self.gfx_masters {
            let (asc, block) = self
                .bus
                .pair_mut::<Asc, Sgx>(asc, block)
                .expect("a GFX master names its ASC and sgx block");
            if !asc.dma_pending() {
                continue;
            }
            let mut access = Access::new(cpu, now, &mut self.latch);
            let mut view = block.uat().agent(Agent::Firmware);
            let mut port = Port {
                iommu: &mut view,
                stream: uat::FIRMWARE_CONTEXT,
                memory: &mut *memory,
                access: &mut access,
            };
            if let Err(reason) = asc.service_dma(&mut port) {
                // The walk's evidence: the last fault and the firmware
                // context's TTBAT words, as the guest left them.
                let uat = block.uat();
                let words = uat.ttbat().map(|base| {
                    let address = base + uat::FIRMWARE_CONTEXT as u64 * 16;
                    let mut bytes = [0u8; 16];
                    memory.read(address, &mut bytes).then_some((address, bytes))
                });
                // The nonzero entries of the faulting half's root table.
                let root = |words: &[u8; 16], half: usize| {
                    u64::from_le_bytes(words[half * 8..half * 8 + 8].try_into().unwrap())
                        & 0xff_ffff_c000
                };
                let half = uat
                    .last_fault()
                    .map_or(1, |fault| usize::from(fault.address >> uat::IAS & 1 != 0));
                let mut entries = Vec::new();
                if let Some(Some((_, words))) = words {
                    let table = root(&words, half);
                    for index in 0..2048u64 {
                        if entries.len() == 8 {
                            break;
                        }
                        let mut entry = [0u8; 8];
                        if memory.read(table + index * 8, &mut entry) && entry != [0; 8] {
                            entries.push((index, u64::from_le_bytes(entry)));
                        }
                    }
                }
                return Err(DeviceError::TransferRefused(format!(
                    "GFX firmware DMA: {reason}; last UAT fault {:x?}; context TTBAT {:x?}; \
                     root entries {:x?}",
                    uat.last_fault(),
                    words,
                    entries
                )));
            }
        }
        for master in &self.sep_masters {
            let (sep, dart) = self
                .bus
                .pair_mut::<Sep, Dart>(master.sep, master.dart)
                .expect("a SEP master names its model and DART");
            if !sep.pending() {
                continue;
            }
            let mut access = Access::new(cpu, now, &mut self.latch);
            let mut port = Port {
                iommu: dart,
                stream: master.stream,
                memory,
                access: &mut access,
            };
            sep.transfer(&mut port).map_err(describe_transfer)?;
        }
        for master in &self.dcp_masters {
            let presenting = self
                .bus
                .device_mut::<Asc>(master.asc)
                .filter(|asc| asc.execution_enabled())
                .and_then(Asc::firmware_mut::<dcp::Coprocessor>)
                .is_some_and(|coprocessor| coprocessor.frame_pending());
            if presenting {
                let (surface, stream) = master.surface.ok_or_else(|| {
                    DeviceError::TransferRefused(
                        "DCPEXT swap surface: the display pipe's DART (dart-dispext0) is not placed"
                            .into(),
                    )
                })?;
                let (asc, dart) = self
                    .bus
                    .pair_mut::<Asc, Dart>(master.asc, surface)
                    .expect("a DCP master names its ASC and surface DART");
                let coprocessor = asc
                    .firmware_mut::<dcp::Coprocessor>()
                    .expect("a DCP master's ASC runs the DCP model");
                let mut access = Access::new(cpu, now, &mut self.latch);
                let mut port = Port {
                    iommu: dart,
                    stream,
                    memory,
                    access: &mut access,
                };
                coprocessor.present(&mut port).map_err(|reason| {
                    DeviceError::TransferRefused(format!("DCPEXT swap surface: {reason}"))
                })?;
            }
            let (asc, dart) = self
                .bus
                .pair_mut::<Asc, Dart>(master.asc, master.dart)
                .expect("a DCP master names its ASC and DART");
            if !asc.dma_pending() {
                continue;
            }
            let mut access = Access::new(cpu, now, &mut self.latch);
            let mut port = Port {
                iommu: dart,
                stream: master.stream,
                memory,
                access: &mut access,
            };
            asc.service_dma(&mut port).map_err(|reason| {
                DeviceError::TransferRefused(format!("DCPEXT link DMA: {reason}"))
            })?;
        }
        for master in &mut self.usb_masters {
            let (controller, dart) = self
                .bus
                .pair_mut::<Dwc3, Dart>(master.device, master.dart)
                .expect("USB master retains its DART");
            let mut access = Access::new(cpu, now, &mut self.latch);
            let mut port = Port {
                iommu: dart,
                stream: master.stream,
                memory,
                access: &mut access,
            };
            let fail =
                |why: &str| DeviceError::TransferRefused(format!("USB device advance: {why}"));
            master
                .cancel_session(controller.take_session_reset())
                .map_err(fail)?;
            let connector = UsbPort::of(&master.connector);
            if connector != master.port {
                // A new cable generation cancels the previous connection's work.
                master.session.detach().map_err(fail)?;
                master.attached = false;
                master.port = connector;
                master.next_poll = 0;
            }
            // A kept clock/quiesce pause preserves the external session;
            // connector changes still cancel it, and reset/power loss above
            // invalidates it before any new USB or DMA transaction.
            if !controller.lifecycle_active() {
                continue;
            }
            let physical_port = UsbPort {
                generation: master.port.generation,
                ready: master.port.ready && controller.phy_ready(),
            };
            controller.sync_port(&physical_port).map_err(fail)?;
            controller
                .attach_host_function(
                    controller
                        .phy_ready()
                        .then(|| host_function(&master.connector))
                        .flatten(),
                )
                .map_err(fail)?;
            let function = master.peripheral.as_mut().map(|p| p as &mut dyn Function);
            controller.service_host(&mut port, function).map_err(fail)?;
            controller.flush(&mut port).map_err(fail)?;
            let ready = controller.available();
            if !ready && master.attached {
                master.session.detach().map_err(fail)?;
                master.attached = false;
            }
            if ready && !master.attached {
                master.epoch = master
                    .epoch
                    .checked_add(1)
                    .ok_or_else(|| fail("USB connection generation exhausted"))?;
                master.session.attach(master.epoch).map_err(fail)?;
                master.attached = true;
            }
            if now >= master.next_poll {
                master.next_poll = now.saturating_add(USB_POLL_TICKS);
                let advanced = (0..USB_PACKETS_PER_MICROFRAME)
                    .try_for_each(|_| master.session.advance(&mut controller.peer(&mut port), now))
                    .and_then(|()| controller.flush(&mut port));
                advanced.map_err(|why| match controller.dma_fault() {
                    Some(fault) => fail(&format!("{why}: {fault:x?}")),
                    None => fail(why),
                })?;
            }
            master.phy_changed = false;
        }
        self.settle(cpu, now, None)
    }
}

#[cfg(test)]
mod tests;
