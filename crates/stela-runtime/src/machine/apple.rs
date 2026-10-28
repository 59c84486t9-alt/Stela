//! The Apple T8112 device models (`platform::apple`) as the engine's
//! [`Devices`]: one [`Bus`] for the guest physical address space, an
//! [`InterruptLatch`] for the wires, AIC input forwarding and reset requests.
//! The models own every register decision; this adapter only routes accesses
//! and time, and turns each `MmioError` into an explicit refusal.
pub mod t6000_pmgr;

use super::{
    engine::{ConsumedPair, DeviceError, Devices, Memory, Reset, Start, Transition},
    registers::Lines,
    soc::PowerOwner,
};
pub use crate::platform::apple::pmu::{RtcEpoch, WallClock};
use crate::platform::apple::{
    aes::{self, Aes},
    agx::{
        firmware::Coprocessor as GfxCoprocessor,
        sgx::Sgx,
        uat::{self, Agent},
    },
    aic::{Aic2, Aic2Config},
    aic1::Aic1,
    amcc::{self, Amcc},
    ans::{self, Ans},
    asc::{self, Asc},
    atc_phy::{self, AtcPhy},
    bridge::Bridge,
    bus::{Access, Bus, DeviceId, LifecycleState, MapError, MmioDevice, MmioError, Width},
    cluster::{self, Cluster},
    core_counters::{self, CoreCounters},
    coresight::{self, PcSampler, SoftwareLock},
    cpm::Cpm,
    cpustart::{self, CpuStart},
    dart::{self, Dart},
    dcp, display as display_hw,
    dpe::Dpe,
    dwc3::{self, Dwc3, PortState},
    energy::{self, Energy},
    fuse::{self, AonFuses},
    gpio::{Gpio, Net, OpenDrain},
    hpm::{Firmware, Hpm, Summary},
    i2c::{self, I2c},
    interrupt::{CpuIndex, InterruptLatch},
    ipi::{self, Affinity, FastIpi},
    lockdown::{self, Lockdown},
    perf::PerfCounters,
    pmgr::{
        ACTIVE, DomainState, POWER_GATED, Pmgr, PowerState,
        coverage::{self, Consumer, LifecycleSinks},
    },
    pmp,
    pmu::{self, Pmu},
    power::{self, Power},
    ptd,
    rtkit::RtKit,
    sart::{self, Sart},
    sep::{self, Sep},
    smc::{self, Smc},
    spi::Spi,
    spmi::{self, Spmi},
    uart::S5lUart,
    wake::{self, WakeMasks},
    wdt::{self, AppleWdt},
};
use crate::platform::dma::{Physical, Port};
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
use crate::system::access::{AccessKind, Encoding};
use alloc::{boxed::Box, format, string::String, vec, vec::Vec};
use core::cell::Cell;
use stela_drivers::{block::BlockDevice, input::Input, net::Mac};

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

pub use crate::platform::apple::{
    aic::{AIC2_IRQ_CFG, AIC3_IRQ_CFG, AicLayout},
    aic1::AIC1_EVENT,
    asc::Lines as AscLines,
    dart::Profile as DartProfile,
    dcp::Log as DisplayLog,
    interrupt::AicInput,
    nor,
    pmp::native::{self as native_pmp, services::Clock as NativePmpClock},
    scanout::{
        ChannelMasks as ScanoutMasks, Mode as ScanoutMode, PixelFormat as ScanoutFormat, Scanout,
    },
    sep::Entropy as SepEntropy,
    sep::image::signature::{
        Evidence as SepSignatureEvidence, ManifestEvidence as SepManifestEvidence,
        inspect as inspect_sep_signature, verify_manifest as verify_sep_manifest_signature,
    },
    sep::state as sep_state,
    smc::WriteLog as SmcWriteLog,
    typec,
    uart::{ConsoleBusy, ConsoleSink},
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
    pub security: Option<sep::SecurityMode>,
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

impl AppleDevices {
    #[cfg(feature = "native-profile")]
    pub fn advance_statistics(&self) -> crate::platform::apple::bus::AdvanceStatistics {
        self.bus.advance_statistics()
    }

    /// The board's devices with PE zero receiving the boot handoff.
    pub fn new() -> Self {
        Self::for_boot_processor(0)
    }

    /// The board's existing PE receiving the boot handoff. PE indices retain
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
        bank: &super::soc::GpioBank,
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
    pub fn add_aux_gpio(&mut self, aux: &super::soc::AuxGpioBank) -> Result<(), String> {
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
    pub fn add_spi_nor(&mut self, placement: &super::soc::SpiNor) -> Result<(), String> {
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
        // Publish the reset-vector owner only after every actual bank fits.
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
                &[(physical, cpustart::bytes(clusters), 0)],
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
        layout: core_counters::Layout,
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
        layout: amcc::Layout,
        programmed: amcc::Programmed,
        cache: Option<amcc::Cache>,
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
        layout: amcc::Layout,
        programmed: amcc::Programmed,
    ) -> Result<(), String> {
        self.map_lock_controller(apertures, layout, programmed, None)?;
        Ok(())
    }

    fn map_lock_controller(
        &mut self,
        apertures: &[u64],
        layout: amcc::Layout,
        programmed: amcc::Programmed,
        cache: Option<amcc::Cache>,
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
        ranges: &[ptd::Range],
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
        placement: &super::soc::AnsController,
        backing: Box<dyn stela_drivers::block::BlockDevice>,
        build: &crate::builds::Build,
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
            sart::Bounds::Exclusive
        } else {
            sart::Bounds::Inclusive
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
        placement: &super::soc::SmcController,
        build: &crate::builds::Build,
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
        placement: &super::soc::PmpController,
        build: &crate::builds::Build,
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
        placement: &super::soc::GfxController,
        build: &crate::builds::Build,
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
    /// handoff. This does not admit DCPEXT in `soc::models` (see
    /// `platform::apple::dcp`).
    #[allow(clippy::too_many_arguments)]
    pub fn add_dcpext(
        &mut self,
        wrapper: Range,
        interrupts: [u32; 4],
        quiesced: bool,
        role: &'static str,
        identity: dcp::ExternalIdentity,
        scanout: Box<dyn Scanout>,
        (dart, stream): (DartId, usize),
        window: Option<u64>,
        surface: Option<(DartId, usize)>,
        build: &crate::builds::Build,
    ) -> Result<(), String> {
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
        placement: &super::soc::SpmiController,
        wall: Option<pmu::WallClock>,
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
        placement: &super::soc::SpmiController,
        wall: Option<pmu::WallClock>,
        epoch: pmu::RtcEpoch,
    ) -> Result<(), String> {
        self.add_spmi_with_resources(placement, wall, epoch, &[])
    }

    /// Every outside-scratch fault log and off-to-wake source requires
    /// explicitly declared initial history. SIDs are local to this
    /// controller; entries are complete and unique.
    pub fn add_spmi_with_resources(
        &mut self,
        placement: &super::soc::SpmiController,
        wall: Option<pmu::WallClock>,
        epoch: pmu::RtcEpoch,
        history: &[(u8, pmu::Retained, Vec<u8>)],
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
                .map(id, base, bytes, bank as u64 * spmi::BANK_B)
                .map_err(|e| format!("SPMI bank placement: {e:?}"))?;
        }
        if let Some((base, bytes)) = placement.bank_c {
            self.bus
                .map(id, base, bytes, spmi::BANK_C)
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

    /// Place an explicitly visible I2C controller. Addressed but unqualified
    /// targets refuse; hiding a target must not turn its protocol into success.
    /// `firmware` returns a board firmware image by its guest file name; an
    /// HPM die runs `USB-C_<personality>.bin` and drives its manager's
    /// interrupt net, whose summary the manager's own address reports.
    pub fn add_i2c<'f>(
        &mut self,
        placement: &super::soc::I2cController,
        firmware: &dyn Fn(&str) -> Option<&'f [u8]>,
    ) -> Result<(), String> {
        let device = placement.device;
        let mut model = I2c::new(AicInput::new(0, device.irq as u16));
        // Each die's alert output on its manager's interrupt net, which the
        // manager's summary samples.
        let mut alerts = Vec::new();
        for target in &placement.targets {
            if target.compatible != super::soc::HPM {
                continue;
            }
            let name = super::soc::hpm_firmware_file(
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
                super::soc::HPM => continue,
                super::soc::HPM_MANAGER => {
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
                super::soc::RETIMER => "ATC retimer register protocol is undetermined",
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
    pub fn add_atc_phy(&mut self, placement: &super::soc::TypecPhy) -> Result<(), String> {
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
    /// Returned IDs retain DT instance order. This does not choose a USB DMA
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

    /// Select the actual DT register/table family before publishing windows.
    /// Legacy filter and capture variants need their own native contracts.
    pub fn add_dart_group_for_profile(
        &mut self,
        profile: dart::Profile,
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
            !physical.is_multiple_of(dart::DAPF_BYTES)
                || slices == 0
                || slices as u64 > dart::DAPF_BYTES / 0x40
        }) {
            return Err("DART APF requires one aligned window with a native slice count".into());
        }
        if ranges.iter().any(|range| {
            !profile.admits_window(range.bytes)
                || !range.physical.is_multiple_of(dart::DAPF_BYTES)
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
                self.bus
                    .map(device, physical, dart::DAPF_BYTES, dart::DAPF_OFFSET)?;
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
            self.bus
                .map(device, physical, dart::DAPF_BYTES, dart::DAPF_OFFSET)?;
        }
        Ok(DartId(device))
    }

    /// SEP ROM prefix at DT wrapper/auxiliary ranges, on its four mailbox
    /// lines and dart-sep stream. This does not admit SEP in `soc::models`.
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
    /// Platform windows retain distinct refusing offsets; reg[3] and reg[4]
    /// are the pipehandler and core event block, which the ATC PHY placement
    /// owns (`atc-phy-parent`). IRQ indices 0..3
    /// are from AppleUSBXDCI::goOnBus (KC 0x42f5338/5380/53c8/5d24),
    /// passed unchanged to EventHandler::withParameters; initializePlatformSettings
    /// at 0x4338e74 chooses four handlers. The fifth ADT IRQ is not an event ring.
    pub fn add_usb(
        &mut self,
        placement: &super::soc::UsbController,
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

    /// Pure preflight of actual boxed ownership and incoming-SID capacity.
    /// Boot adapters validate every declared bank/mapper before publication;
    /// this does not enable DMA or qualify a physical traffic classifier.
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
        config: aes::Config,
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
    /// not a qualified transfer of the original firmware's control words.
    pub fn add_power_states(&mut self, blocks: &[Range], registers: &[u64]) -> Result<(), String> {
        if self.pmgr.is_some() {
            return Err("PMGR lifecycle owner is already bound".into());
        }
        let states = registers.iter().map(|&address| PowerState {
            address,
            initial: ACTIVE,
        });
        let model = Pmgr::new(states).map_err(|error| format!("PMGR states: {error:?}"))?;
        // The model's offsets are guest PAs. Publish all actual banks together.
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

    /// Register an actual model's checked lifecycle boundary against its
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
        states: &super::soc::PowerStates,
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

    /// Resource names for domains whose actual consumers still lack sinks.
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
    pub fn add_soc_power(&mut self, physical: u64, kind: power::Kind) -> Result<(), String> {
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
        side: Option<&super::soc::WatchdogSide>,
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
    /// source-qualified binding; this supplies no guessed target groups.
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

    /// Validate every actual affected bank before a PMGR request can change
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
        shape: super::engine::DeviceReadShape,
    ) -> bool {
        self.read_needs_ram(physical, shape)
    }

    /// CPU PMGR registers, which settle the board's processors, and the
    /// memory controller words that drain or flush to RAM.
    fn requires_canonical_write(&self, _cpu: usize, physical: u64, bytes: u8) -> bool {
        self.is_processor_power_register(physical)
            || self.read_needs_ram(physical, super::engine::DeviceReadShape::Scalar { bytes })
            || width(bytes).is_ok_and(|width| self.empty_cache_flush_needs_ram(physical, width))
    }

    fn read_canonical(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        now: u64,
        memory: &mut dyn super::engine::CanonicalDeviceMemory,
    ) -> Result<super::engine::ConsumedScalar, DeviceError> {
        self.observe_time(now, "read");
        self.consume_scalar_read(cpu, physical, bytes, now, Some(memory))
    }

    fn read_pair_canonical(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        now: u64,
        _memory: &mut dyn super::engine::CanonicalDeviceMemory,
    ) -> Result<ConsumedPair, DeviceError> {
        self.observe_time(now, "paired read");
        // Only the actual Prepared publication/status owner has a qualified
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
        // Probe without effects: both members must belong to the same actual
        // joint resource at consecutive offsets, not merely adjacent PAs.
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
        use super::engine::ConsumedWrite;
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
        owners: &mut dyn super::engine::CanonicalDeviceWrite,
    ) -> Result<super::engine::ConsumedWrite, DeviceError> {
        self.observe_time(now, "write");
        if let Some(completed) =
            self.consume_processor_power_write(cpu, physical, bytes, value, now, owners)?
        {
            return Ok(completed);
        }
        use super::engine::CanonicalDeviceMemory;
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
        let register = ipi::Register::decode(encoding)?;
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
        self.ipi.is_some() && ipi::Register::decode(encoding).is_some()
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

    fn memory_lock(&self) -> super::mmu::MemoryLocks {
        let Some(device) = self.memory_controller else {
            return [None; amcc::GROUPS];
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
                .map_or([None; amcc::GROUPS], Amcc::locked_regions)
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
        // execution path. Its actual held cohort/fenced Host sessions and
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
            // A retained clock/quiesce pause preserves the external session;
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
mod tests {
    use super::*;

    /// The J473 `/arm-io/aes`: version 3, one key-disable word.
    fn j473_aes() -> aes::Config {
        aes::Config {
            version: 3,
            address_width: aes::DEFAULT_ADDRESS_WIDTH,
            key_disable: aes::KeyDisable {
                bytes: 0x8000,
                word: 0,
                keys: [None; 3],
            },
        }
    }
    use crate::platform::{
        apple::bus::MmioDevice,
        dma::{Iommu, tests::Ram},
    };
    use alloc::{rc::Rc, vec::Vec};
    use core::cell::RefCell;

    #[test]
    fn a_board_entry_given_an_earlier_count_is_named_in_the_stop_reason() {
        let d = AppleDevices::new();
        d.observe_time(10, "lines");
        assert_eq!(d.rtc_regression(), "");
        d.observe_time(5, "deadline");
        d.observe_time(3, "read");
        assert_eq!(d.rtc_regression(), " (deadline at 0x5 after lines at 0xa)");
    }

    #[test]
    fn native_dart_mounts_program_the_selected_register_bank_and_transfer_real_dma_bytes() {
        use crate::platform::dma::{Memory as _, Port, tests::Ram};
        const ROOT: u64 = 0x8_0000_0000;
        const PAGE: u64 = 0x4000;
        for profile in [
            dart::Profile::T8020,
            dart::Profile::T6000,
            dart::Profile::T8110,
        ] {
            let mut d = AppleDevices::new();
            let ranges = [
                Range {
                    physical: 0x2_7000_0000,
                    bytes: PAGE,
                },
                Range {
                    physical: 0x2_7008_0000,
                    bytes: PAGE,
                },
            ];
            let ids = d
                .add_dart_group_for_profile(profile, &ranges, 16, None, None)
                .unwrap();
            let mut ram = Ram::new(ROOT, (4 * PAGE) as usize);
            let descriptor = |physical: u64| {
                if profile == dart::Profile::T8020 {
                    physical | 1
                } else {
                    physical >> 4 | 1
                }
            };
            ram.put_u64(ROOT + 8, descriptor(ROOT + PAGE));
            ram.put_u64(ROOT + PAGE + 8, descriptor(ROOT + 2 * PAGE) | 0xfff << 40);
            let (enabled, tcr, ttbr, ttbr_value, translate) = if profile == dart::Profile::T8110 {
                (0xc00, 0x1004, 0x1404, ROOT >> 12 | 1, 1)
            } else {
                (0xfc, 0x104, 0x210, ROOT >> 12 | 1 << 31, 1 << 7)
            };
            for (offset, value) in [(enabled, 2), (tcr, translate), (ttbr, ttbr_value)] {
                d.write(0, ranges[0].physical + offset, 4, value, 0)
                    .unwrap();
            }
            assert_eq!(d.read(0, ranges[0].physical + tcr, 4, 0), Ok(translate));
            assert_eq!(d.read(0, ranges[1].physical + tcr, 4, 0), Ok(0));
            let mut a = Access::new(0, 0, &mut d.latch);
            let mut port = Port {
                iommu: d.bus.device_mut::<Dart>(ids[0].0).unwrap(),
                stream: 1,
                memory: &mut ram,
                access: &mut a,
            };
            port.write(0x0200_4007, &[2, 4, 6, 8]).unwrap();
            let mut actual = [0; 4];
            assert!(ram.read(ROOT + 2 * PAGE + 7, &mut actual));
            assert_eq!(actual, [2, 4, 6, 8]);
        }
    }

    #[test]
    fn revision_2_2_mounts_whole_windows_beside_the_filter_and_capture_views() {
        let mut d = AppleDevices::new();
        let ranges = [
            Range {
                physical: 0x2_7000_0000,
                bytes: 0x20000,
            },
            Range {
                physical: 0x2_7004_0000,
                bytes: 0xc000,
            },
        ];
        // A window selects its register file; neither revision mounts the
        // other's, nor a window without a recovered register file.
        for (profile, bytes) in [
            (dart::Profile::T8110, 0xc000),
            (dart::Profile::T8110Rev22, 0x4000),
            (dart::Profile::T8110Rev22, 0x8000),
            (dart::Profile::T8110Rev22, 0x24000),
        ] {
            let range = Range {
                physical: ranges[0].physical,
                bytes,
            };
            assert!(
                d.add_dart_group_for_profile(profile, &[range], 16, None, None)
                    .is_err()
            );
            assert!(d.read(0, range.physical, 4, 0).is_err());
        }
        let apf = 0x2_7002_0000;
        let ids = d
            .add_dart_group_for_profile(
                dart::Profile::T8110Rev22,
                &ranges,
                16,
                None,
                Some((apf, 16)),
            )
            .unwrap();
        let smmu = Range {
            physical: 0x2_7005_4000,
            bytes: 0x4000,
        };
        d.add_dart_smmu(ids[1], smmu).unwrap();
        for range in ranges {
            assert_eq!(d.read(0, range.physical + 8, 4, 0), Ok(0x2a2a_0202));
            assert_eq!(d.read(0, range.physical + 0x4000, 4, 0), Ok(0));
            assert!(d.read(0, range.physical + 0x100, 4, 0).is_err());
        }
        assert!(d.read(0, ranges[0].physical + 0xc000, 4, 0).is_err());
        assert!(d.read(0, ranges[0].physical + 0x1fffc, 4, 0).is_err());
        // The filter's slices stay reachable at their own window.
        d.write(0, apf + 8, 4, 0x1234_0000, 0).unwrap();
        assert_eq!(d.read(0, apf + 8, 4, 0), Ok(0x1234_0000));
        assert!(d.read(0, smmu.physical, 4, 0).is_err());
    }

    #[test]
    fn unsupported_legacy_mount_features_refuse_before_any_aperture_is_published() {
        let mut d = AppleDevices::new();
        let range = Range {
            physical: 0x2_7000_0000,
            bytes: 0x4000,
        };
        for (streams, apf) in [(64, None), (16, Some((0x2_7010_0000, 1)))] {
            assert!(
                d.add_dart_group_for_profile(dart::Profile::T8020, &[range], streams, None, apf)
                    .is_err()
            );
            assert!(d.read(0, range.physical, 4, 0).is_err());
        }
        for invalid in [
            Range {
                physical: range.physical,
                bytes: 0,
            },
            Range {
                physical: range.physical,
                bytes: 0x8000,
            },
            Range {
                physical: range.physical + 4,
                bytes: 0x4000,
            },
            Range {
                physical: !0x3fff,
                bytes: 0x4000,
            },
        ] {
            assert!(
                d.add_dart_group_for_profile(dart::Profile::T6000, &[invalid], 16, None, None)
                    .is_err()
            );
            assert!(d.read(0, range.physical, 4, 0).is_err());
        }
        assert!(
            d.add_dart_group_for_profile(dart::Profile::T8020, &[range], 0, None, None)
                .is_err()
        );
        assert!(
            d.add_dart_group_for_profile(dart::Profile::T8020, &[], 16, None, None)
                .is_err()
        );
        let ids = d
            .add_dart_group_for_profile(dart::Profile::T8020, &[range], 16, None, None)
            .unwrap();
        let smmu = Range {
            physical: 0x2_7020_0000,
            bytes: 0x4000,
        };
        assert!(d.add_dart_smmu(ids[0], smmu).is_err());
        assert!(d.read(0, smmu.physical, 4, 0).is_err());
    }

    #[test]
    fn coresight_components_keep_independent_locks_and_do_not_claim_debug_controls() {
        let mut d = AppleDevices::new();
        let bases = [0x2_1001_0000, 0x2_1101_0000];
        for base in bases {
            d.add_coresight_lock(base).unwrap();
            assert_eq!(d.read(0, base + coresight::STATUS, 4, 0), Ok(3));
        }
        d.write(0, bases[0] + coresight::ACCESS, 4, 0xc5acce55, 0)
            .unwrap();
        assert_eq!(d.read(0, bases[0] + coresight::STATUS, 4, 0), Ok(1));
        assert_eq!(d.read(0, bases[1] + coresight::STATUS, 4, 0), Ok(3));
        assert!(d.read(0, bases[0], 4, 0).is_err());
        assert!(d.write(0, bases[0] + coresight::ACCESS, 8, 0, 0).is_err());
    }

    fn powered_dart(retention: bool, supplies: usize) -> (AppleDevices, DartId, u64, u64) {
        powered_dart_with(retention, supplies, |_| {})
    }

    /// A declared synthetic physical supply for actual mounted native banks.
    /// Tests choose retention explicitly; production constructors do not infer
    /// it from an RTKit retained-sleep capability.
    fn connect_native_power(
        d: &mut AppleDevices,
        supply: u64,
        resources: &[(&str, u64)],
        retained: bool,
    ) {
        use super::super::soc::{PowerResource, PowerStates};
        let gate = coverage::DomainId { die: 0, device: 1 };
        let states = PowerStates {
            implicit: Vec::new(),
            blocks: vec![(supply, 4)],
            registers: vec![supply],
            domains: vec![coverage::Domain {
                name: String::new(),
                id: gate,
                address: Some(supply),
                parents: [None; 4],
            }],
            resources: resources
                .iter()
                .map(|&(name, physical)| PowerResource {
                    clock_role: crate::machine::soc::ClockRole::Consumer,
                    name: name.into(),
                    clocks: vec![gate],
                    power: vec![],
                    owner: Some(PowerOwner::Mmio(physical)),
                    admission: coverage::Admission::Required,
                })
                .collect(),
        };
        for device in &mut d.power_devices {
            device.retention = retained;
        }
        d.add_power_states(
            &[Range {
                physical: supply,
                bytes: 4,
            }],
            &[supply],
        )
        .unwrap();
        d.connect_power_resources(&states, &[], &[]).unwrap();
        assert!(d.power_refusals().is_empty());
    }

    fn powered_dart_with(
        retention: bool,
        supplies: usize,
        edit: impl FnOnce(&mut super::super::soc::PowerStates),
    ) -> (AppleDevices, DartId, u64, u64) {
        use super::super::soc::{PowerResource, PowerStates};
        use coverage::{Domain, DomainId};
        let mut d = AppleDevices::new();
        let supply = 0x2_3b70_0100;
        let base = 0x2_3500_4000;
        let registers = (0..supplies)
            .map(|index| supply + index as u64 * 8)
            .collect::<Vec<_>>();
        let ids = (0..supplies)
            .map(|index| DomainId {
                die: 0,
                device: index as u16 + 1,
            })
            .collect::<Vec<_>>();
        let mut states = PowerStates {
            implicit: Vec::new(),
            blocks: vec![(supply, supplies as u64 * 8)],
            registers: registers.clone(),
            domains: registers
                .iter()
                .zip(&ids)
                .map(|(&address, &id)| Domain {
                    name: String::new(),
                    id,
                    address: Some(address),
                    parents: [None; 4],
                })
                .collect(),
            resources: vec![PowerResource {
                clock_role: crate::machine::soc::ClockRole::Consumer,
                name: "/arm-io/dart".into(),
                clocks: ids,
                power: Vec::new(),
                owner: Some(PowerOwner::Dart(0)),
                admission: coverage::Admission::Required,
            }],
        };
        edit(&mut states);
        d.add_power_states(
            &[Range {
                physical: supply,
                bytes: supplies as u64 * 8,
            }],
            &registers,
        )
        .unwrap();
        let dart = d
            .add_dart(
                Range {
                    physical: base,
                    bytes: 0x4000,
                },
                16,
                None,
                None,
            )
            .unwrap();
        d.connect_power_resources(&states, &[vec![dart]], &[retention])
            .unwrap();
        (d, dart, supply, base)
    }

    fn powered_serial_controllers() -> (AppleDevices, Console, u64, [u64; 3]) {
        use super::super::soc::{Device, I2cController, PowerResource, PowerStates, SpiNor};
        use coverage::{Admission, Domain, DomainId};
        let mut d = AppleDevices::new();
        let supply = 0x2_3b70_0100;
        let bases = [UART, 0x2_3501_0000, 0x2_3510_4000];
        let id = DomainId { die: 0, device: 1 };
        let states = PowerStates {
            implicit: Vec::new(),
            blocks: vec![(supply, 4)],
            registers: vec![supply],
            domains: vec![Domain {
                name: String::new(),
                id,
                address: Some(supply),
                parents: [None; 4],
            }],
            resources: bases
                .iter()
                .zip(["uart", "i2c", "spi"])
                .map(|(&physical, name)| PowerResource {
                    clock_role: crate::machine::soc::ClockRole::Consumer,
                    name: name.into(),
                    clocks: vec![id],
                    power: vec![],
                    owner: Some(PowerOwner::Mmio(physical)),
                    admission: Admission::Required,
                })
                .collect(),
        };
        let console = Console::default();
        d.add_uart(
            console.clone(),
            &[Range {
                physical: bases[0],
                bytes: 0x4000,
            }],
            None,
        )
        .unwrap();
        d.add_i2c(
            &I2cController {
                device: Device {
                    physical: bases[1],
                    bytes: 0x1000,
                    irq: 761,
                },
                targets: vec![],
            },
            &|_| None,
        )
        .unwrap();
        d.add_spi_nor(&SpiNor {
            device: Device {
                physical: bases[2],
                bytes: 0x1000,
                irq: 749,
            },
            image: crate::platform::apple::nor::Image::fresh(),
            select: None,
        })
        .unwrap();
        assert_eq!(
            d.power_devices.len(),
            3,
            "actual constructors register each bank once"
        );
        d.add_power_states(
            &[Range {
                physical: supply,
                bytes: 4,
            }],
            &[supply],
        )
        .unwrap();
        d.connect_power_resources(&states, &[], &[]).unwrap();
        assert!(d.power_refusals().is_empty());
        (d, console, supply, bases)
    }

    #[test]
    fn pmgr_serial_constructor_hooks_gate_actual_mmio_and_preserve_retained_configuration() {
        let (mut d, console, supply, [uart, i2c, spi]) = powered_serial_controllers();
        for (address, value) in [(uart, 3), (i2c + 0x30, 0x1234), (spi + 0x30, 7)] {
            d.write(0, address, 4, value, 0).unwrap();
        }
        d.write(0, uart + 0x20, 4, u64::from(b'a'), 0).unwrap();
        for client in &mut d.power_clients {
            client.retention = true; // Explicit synthetic policy, not a J473 retention claim.
        }
        for request in [4, 0] {
            d.write(0, supply, 4, request, 0).unwrap();
            for address in [uart, i2c + 0x30, spi + 0x30] {
                assert!(d.read(0, address, 4, 0).is_err());
            }
            d.write(0, supply, 4, 15, 0).unwrap();
            for (address, value) in [(uart, 3), (i2c + 0x30, 0x1234), (spi + 0x30, 7)] {
                assert_eq!(d.read(0, address, 4, 0), Ok(value));
            }
        }
        assert_eq!(*console.0.borrow(), b"a");
    }

    #[test]
    fn pmgr_serial_reset_preflights_actual_nor_before_clearing_other_controllers() {
        let (mut d, console, supply, [uart, i2c, spi]) = powered_serial_controllers();
        d.write(0, uart + 0x20, 4, u64::from(b'a'), 0).unwrap();
        d.write(0, spi + 0x0c, 4, 0, 0).unwrap(); // Internal CS low.
        d.write(0, spi + 0x4c, 4, 1, 0).unwrap();
        d.write(0, spi + 0x10, 4, 3, 0).unwrap(); // READ, missing address.
        d.write(0, spi, 4, 1, 0).unwrap();
        d.write(0, supply, 4, 0x40f, 0).unwrap();
        let before = d.read(0, supply, 4, 0).unwrap();
        assert!(matches!(d.write(0, supply, 4, 0x8000040f, 0),
            Err(DeviceError::Refused(reason)) if reason.contains("incomplete NOR")));
        assert_eq!(d.read(0, supply, 4, 0), Ok(before));
        assert_eq!(d.read(0, uart, 4, 0), Ok(3));
        assert_eq!(d.read(0, i2c + 0x1c, 4, 0), Ok(0));
        d.write(0, supply, 4, 15, 0).unwrap();
        d.write(0, spi + 0x4c, 4, 3, 0).unwrap();
        for _ in 0..3 {
            d.write(0, spi + 0x10, 4, 0, 0).unwrap();
        }
        // Closing the now-complete command allows an actual shared reset.
        d.write(0, spi + 0x0c, 4, 2, 0).unwrap();
        for request in [0x40f, 0x8000040f, 0x40f, 15] {
            d.write(0, supply, 4, request, 0).unwrap();
        }
        for address in [uart, i2c + 0x1c, spi] {
            assert!(
                d.read(0, address, 4, 0).is_err(),
                "unknown reset image at {address:#x}"
            );
        }
        assert_eq!(*console.0.borrow(), b"a");
    }

    /// A checked native bank fixture shares an actual mounted DART's supply.
    /// Its refusal models an explicitly unqualified destructive transition,
    /// without claiming another physical controller implementation.
    struct CheckedPowerBank {
        reject: bool,
        committed: Vec<LifecycleState>,
    }
    impl crate::platform::apple::bus::Lifecycle for CheckedPowerBank {
        fn check_lifecycle(&self, state: LifecycleState) -> Result<(), &'static str> {
            if self.reject && (!state.powered || state.reset) {
                Err("native bank destructive transition remains unqualified")
            } else {
                Ok(())
            }
        }
        fn set_lifecycle(&mut self, state: LifecycleState, _: &mut Access<'_>) {
            self.committed.push(state);
        }
    }
    impl MmioDevice for CheckedPowerBank {
        fn lifecycle(&mut self) -> Option<&mut dyn crate::platform::apple::bus::Lifecycle> {
            Some(self)
        }
        fn name(&self) -> &'static str {
            "checked-power-bank"
        }
        fn read(&mut self, _: u64, _: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
            Ok(self.committed.len() as u64)
        }
        fn write(&mut self, _: u64, _: Width, _: u64, _: &mut Access<'_>) -> Result<(), MmioError> {
            Ok(())
        }
    }

    #[test]
    fn repeated_resource_names_do_not_cross_connect_native_power_domains() {
        use super::super::soc::{PowerResource, PowerStates};
        use coverage::{Admission, Domain, DomainId};
        let mut d = AppleDevices::new();
        let supply = 0x2_3b70_0100;
        let native = [0x2_3600_0000, 0x2_3601_0000];
        let registers = [supply, supply + 8];
        let ids = [1, 2].map(|device| DomainId { die: 0, device });
        let states = PowerStates {
            implicit: Vec::new(),
            blocks: vec![(supply, 16)],
            registers: registers.into(),
            domains: registers
                .into_iter()
                .zip(ids)
                .map(|(address, id)| Domain {
                    name: String::new(),
                    id,
                    address: Some(address),
                    parents: [None; 4],
                })
                .collect(),
            resources: native
                .into_iter()
                .zip(ids)
                .map(|(physical, id)| PowerResource {
                    clock_role: crate::machine::soc::ClockRole::Consumer,
                    name: "/arm-io/repeated".into(),
                    clocks: vec![id],
                    power: vec![],
                    owner: Some(PowerOwner::Mmio(physical)),
                    admission: Admission::Required,
                })
                .collect(),
        };
        d.add_power_states(
            &[Range {
                physical: supply,
                bytes: 16,
            }],
            &registers,
        )
        .unwrap();
        for physical in native {
            let bank = d.bus.add(Box::new(CheckedPowerBank {
                reject: false,
                committed: vec![],
            }));
            d.bus.map(bank, physical, 4, 0).unwrap();
            d.register_power_device(physical, bank, true).unwrap();
        }
        d.connect_power_resources(&states, &[], &[]).unwrap();
        assert_eq!(d.power_clients[0].domains.len(), 1);
        assert_eq!(d.power_clients[0].domains[0].0, supply);
        assert_eq!(d.power_clients[1].domains.len(), 1);
        assert_eq!(d.power_clients[1].domains[0].0, supply + 8);
        d.write(0, supply, 4, 0x3f4, 0).unwrap();
        assert_eq!(d.read(0, native[0], 4, 0), Ok(1));
        assert_eq!(d.read(0, native[1], 4, 0), Ok(0));
        d.write(0, supply + 8, 4, 0x3f4, 0).unwrap();
        assert_eq!(d.read(0, native[0], 4, 0), Ok(1));
        assert_eq!(d.read(0, native[1], 4, 0), Ok(1));
    }

    #[test]
    fn pmgr_all_native_banks_preflight_before_register_or_actual_dart_effects() {
        use super::super::soc::{PowerResource, PowerStates};
        use coverage::{Admission, Domain, DomainId};
        let mut d = AppleDevices::new();
        let supply = 0x2_3b70_0100;
        let base = 0x2_3500_4000;
        let canonical = 0x2_3600_0000;
        let gate = DomainId { die: 0, device: 1 };
        let states = PowerStates {
            implicit: Vec::new(),
            blocks: vec![(supply, 4)],
            registers: vec![supply],
            domains: vec![Domain {
                name: String::new(),
                id: gate,
                address: Some(supply),
                parents: [None; 4],
            }],
            resources: [
                ("/arm-io/dart", PowerOwner::Dart(0)),
                ("/arm-io/checked-native", PowerOwner::Mmio(canonical)),
            ]
            .map(|(name, owner)| PowerResource {
                clock_role: crate::machine::soc::ClockRole::Consumer,
                name: name.into(),
                clocks: vec![gate],
                power: vec![],
                owner: Some(owner),
                admission: Admission::Required,
            })
            .into(),
        };
        d.add_power_states(
            &[Range {
                physical: supply,
                bytes: 4,
            }],
            &[supply],
        )
        .unwrap();
        let dart = d
            .add_dart(
                Range {
                    physical: base,
                    bytes: 0x4000,
                },
                16,
                None,
                None,
            )
            .unwrap();
        let first = d.bus.add(Box::new(CheckedPowerBank {
            reject: false,
            committed: vec![],
        }));
        let second = d.bus.add(Box::new(CheckedPowerBank {
            reject: true,
            committed: vec![],
        }));
        d.register_power_device(canonical, first, false).unwrap();
        d.register_power_device(canonical, second, false).unwrap();
        assert!(d.register_power_device(canonical, first, false).is_err());
        let pmgr = d.pmgr.unwrap();
        assert!(d.register_power_device(canonical, pmgr, false).is_err());
        d.connect_power_resources(&states, &[vec![dart]], &[false])
            .unwrap();
        assert!(d.register_power_device(canonical, second, false).is_err());
        d.write(0, base + 0x1000, 4, 1, 0).unwrap();
        let before = d.read(0, supply, 4, 0).unwrap();
        let failure = d.write(0, supply, 4, 0x3f0, 0).unwrap_err();
        assert!(
            matches!(failure, DeviceError::Refused(reason) if reason.contains("checked-native") && reason.contains("unqualified"))
        );
        assert_eq!(d.read(0, supply, 4, 0), Ok(before));
        assert_eq!(d.read(0, base + 0x1000, 4, 0), Ok(1));
        assert!(
            d.bus
                .device_mut::<Pmgr>(pmgr)
                .unwrap()
                .take_transitions()
                .is_empty()
        );
        for bank in [first, second] {
            assert!(
                d.bus
                    .device::<CheckedPowerBank>(bank)
                    .unwrap()
                    .committed
                    .is_empty()
            );
        }
        // No lifecycle change: configuration and width validation do not ask
        // a native bank to qualify an unrelated destructive transition.
        d.write(0, supply, 4, 0x1000f, 0).unwrap();
        assert!(d.write(0, supply, 8, 0, 0).is_err());
        for request in [4, 15, 0x40f] {
            d.write(0, supply, 4, request, 0).unwrap();
        }
        let before = d.read(0, supply, 4, 0).unwrap();
        assert!(d.write(0, supply, 4, 0x8000040f, 0).is_err());
        assert_eq!(d.read(0, supply, 4, 0), Ok(before));
        d.bus.device_mut::<CheckedPowerBank>(second).unwrap().reject = false;
        for request in [0x8000040f, 0x40f, 15, 0, 15] {
            d.write(0, supply, 4, request, 0).unwrap();
        }
        assert_eq!(d.read(0, base + 0x1000, 4, 0), Ok(0));
        for bank in [first, second] {
            let edges = &d.bus.device::<CheckedPowerBank>(bank).unwrap().committed;
            assert_eq!(edges.len(), 8);
            assert!(!edges[0].clocked && edges[0].powered);
            assert!(edges[1].clocked);
            assert!(edges[2].quiesced);
            assert!(edges[3].reset);
            assert!(!edges[4].reset && edges[4].quiesced);
            assert!(!edges[5].quiesced);
            assert!(!edges[6].powered);
            assert!(edges[7].powered);
        }
    }

    #[test]
    fn pmgr_power_gates_reset_dart_tables_but_clock_gates_and_retention_preserve_them() {
        for retention in [false, true] {
            let (mut d, _, supply, base) = powered_dart(retention, 1);
            d.write(0, base + 0x1000, 4, 1, 0).unwrap();
            d.write(0, supply, 4, 4, 0).unwrap();
            assert!(d.read(0, base + 0x1000, 4, 0).is_err());
            d.write(0, supply, 4, 15, 0).unwrap();
            assert_eq!(d.read(0, base + 0x1000, 4, 0), Ok(1));
            d.write(0, supply, 4, 0, 0).unwrap();
            assert!(d.read(0, base + 0x1000, 4, 0).is_err());
            d.write(0, supply, 4, 15, 0).unwrap();
            assert_eq!(d.read(0, base + 0x1000, 4, 0), Ok(u64::from(retention)));
        }
    }

    #[test]
    fn paired_smmu_shares_dart_power_and_reset() {
        let (mut d, owner, supply, base) = powered_dart(false, 1);
        let smmu = 0x2_7130_0000;
        d.add_dart_smmu(
            owner,
            Range {
                physical: smmu,
                bytes: dart::SMMU_BYTES,
            },
        )
        .unwrap();
        assert_eq!(d.read(0, smmu, 4, 0), Ok(0));
        assert!(d.read(0, smmu, 8, 0).is_err());
        assert!(d.read(0, smmu + 0x2000, 4, 0).is_err());
        d.write(0, supply, 4, 0, 0).unwrap();
        assert!(d.read(0, base, 4, 0).is_err());
        assert!(d.read(0, smmu, 4, 0).is_err());
        d.write(0, supply, 4, 15, 0).unwrap();
        assert_eq!(d.read(0, smmu, 4, 0), Ok(0));
        for reset in [true, false] {
            let mut access = Access::new(0, 0, &mut d.latch);
            d.bus
                .device_mut::<Dart>(owner.0)
                .unwrap()
                .set_reset(reset, &mut access);
            assert_eq!(d.read(0, smmu, 4, 0).is_err(), reset);
            assert_eq!(d.read(0, base, 4, 0).is_err(), reset);
        }
    }

    #[test]
    fn mounted_t6000_groups_preserve_each_fault_on_the_same_physical_wire() {
        use crate::platform::apple::interrupt::Wire;
        let mut d = AppleDevices::new();
        let input = AicInput::new(0, 873);
        d.add_aic(0x2_3b0c_0000, 1152, AicLayout::aic2(0x8000, 16))
            .unwrap();
        let mut ids = Vec::new();
        for base in [0x2_8930_4000, 0x2_8930_c000] {
            ids.push(
                d.add_dart_group_for_profile(
                    dart::Profile::T6000,
                    &[Range {
                        physical: base,
                        bytes: dart::DAPF_BYTES,
                    }],
                    16,
                    Some(input),
                    None,
                )
                .unwrap()[0],
            );
        }
        assert_eq!(d.dart_irqs.len(), 1);
        let mut ram = Ram::new(0, 0x4000);
        for id in &ids {
            let mut access = Access::new(0, 0, &mut d.latch);
            assert!(
                d.bus
                    .device_mut::<Dart>(id.0)
                    .unwrap()
                    .translate(&mut ram, 0, 0, 0, false, &mut access)
                    .is_err()
            );
        }
        assert!(d.latch.is_asserted(Wire::Aic(input)));
        d.write(0, 0x2_8930_4040, 4, 1, 0).unwrap();
        assert!(d.latch.is_asserted(Wire::Aic(input)));
        d.write(0, 0x2_8930_c040, 4, 1, 0).unwrap();
        assert!(!d.latch.is_asserted(Wire::Aic(input)));
    }

    #[test]
    fn t6000_paired_umms_shares_reset_and_invalidates_only_unknown_configuration() {
        let mut d = AppleDevices::new();
        let base = 0x2_8930_4000;
        let umms = 0x2_8930_0000;
        let id = d
            .add_dart_group_for_profile(
                dart::Profile::T6000,
                &[Range {
                    physical: base,
                    bytes: dart::DAPF_BYTES,
                }],
                16,
                None,
                None,
            )
            .unwrap()[0];
        d.add_dart_smmu(
            id,
            Range {
                physical: umms,
                bytes: dart::SMMU_BYTES,
            },
        )
        .unwrap();
        assert_eq!(d.read(0, umms, 4, 0), Ok(0));
        assert_eq!(d.read(0, umms + 0x20, 4, 0), Ok(0));
        d.write(0, umms + 0x20, 4, 1 << 31, 0).unwrap();
        {
            let mut a = Access::new(0, 0, &mut d.latch);
            d.bus
                .device_mut::<Dart>(id.0)
                .unwrap()
                .set_reset(true, &mut a);
        }
        assert!(d.read(0, base, 4, 0).is_err());
        assert!(d.read(0, umms, 4, 0).is_err());
        {
            let mut a = Access::new(0, 0, &mut d.latch);
            d.bus
                .device_mut::<Dart>(id.0)
                .unwrap()
                .set_reset(false, &mut a);
        }
        assert_eq!(d.read(0, umms, 4, 0), Ok(0));
        assert!(d.read(0, umms + 0x20, 4, 0).is_err());
        d.write(0, umms + 0x20, 4, 0, 0).unwrap();
        assert_eq!(d.read(0, umms + 0x20, 4, 0), Ok(0));
        assert!(d.read(0, umms + 0x2000, 4, 0).is_err());
    }

    #[test]
    fn failed_smmu_placement_does_not_attach_or_publish_a_view() {
        let mut d = AppleDevices::new();
        let base = 0x2_3500_4000;
        let smmu = 0x2_7130_0000;
        {
            let profile = dart::Profile::T8020;
            let legacy = d
                .bus
                .add(Box::new(Dart::for_profile(profile, 16, None).unwrap()));
            assert!(
                d.add_dart_smmu(
                    DartId(legacy),
                    Range {
                        physical: smmu,
                        bytes: dart::SMMU_BYTES,
                    }
                )
                .unwrap_err()
                .contains("no supported paired SMMU")
            );
            assert!(!d.bus.device::<Dart>(legacy).unwrap().has_smmu());
            assert!(d.read(0, smmu, 4, 0).is_err());
        }
        let owner = d
            .add_dart(
                Range {
                    physical: base,
                    bytes: 0x4000,
                },
                16,
                None,
                None,
            )
            .unwrap();
        for range in [
            Range {
                physical: smmu + 4,
                bytes: dart::SMMU_BYTES,
            },
            Range {
                physical: smmu,
                bytes: dart::SMMU_BYTES / 2,
            },
            Range {
                physical: base,
                bytes: dart::SMMU_BYTES,
            },
            Range {
                physical: !(dart::SMMU_BYTES - 1),
                bytes: dart::SMMU_BYTES,
            },
        ] {
            assert!(d.add_dart_smmu(owner, range).is_err());
            assert!(!d.bus.device::<Dart>(owner.0).unwrap().has_smmu());
            assert!(d.read(0, smmu, 4, 0).is_err());
        }
        d.add_dart_smmu(
            owner,
            Range {
                physical: smmu,
                bytes: dart::SMMU_BYTES,
            },
        )
        .unwrap();
        let other = smmu + dart::SMMU_BYTES;
        assert!(
            d.add_dart_smmu(
                owner,
                Range {
                    physical: other,
                    bytes: dart::SMMU_BYTES
                }
            )
            .is_err()
        );
        assert_eq!(d.read(0, smmu, 4, 0), Ok(0));
        assert!(d.read(0, other, 4, 0).is_err());
    }

    #[test]
    fn pmgr_replays_queued_off_on_and_reset_edges_before_the_next_client_access() {
        for reset in [false, true] {
            let (mut d, _, supply, base) = powered_dart(reset, 1);
            d.write(0, base + 0x1000, 4, 1, 0).unwrap();
            let writes = if reset {
                vec![0x40f, 0x8000_040f, 0x40f, 0xf]
            } else {
                vec![0, 15]
            };
            let mut access = Access::new(0, 0, &mut d.latch);
            let pmgr = d.bus.device_mut::<Pmgr>(d.pmgr.unwrap()).unwrap();
            for value in writes {
                pmgr.write(supply, Width::Word, value, &mut access).unwrap();
            }
            assert_eq!(pmgr.domain_state(supply).unwrap().power, ACTIVE);
            // The failed access must still deliver earlier accepted edges.
            assert!(d.write(0, base + 1, 4, 0, 0).is_err());
            assert_eq!(d.read(0, base + 0x1000, 4, 0), Ok(0));
            assert!(
                d.bus
                    .device_mut::<Pmgr>(d.pmgr.unwrap())
                    .unwrap()
                    .take_transitions()
                    .is_empty()
            );
        }
    }

    #[test]
    fn pmgr_unavailable_shared_consumers_keep_actual_native_lifecycle_effects_in_all_directions() {
        use super::super::soc::PowerResource;
        for retention in [false, true] {
            let (mut d, _, supply, base) = powered_dart_with(retention, 1, |states| {
                states.resources.push(PowerResource {
                    clock_role: crate::machine::soc::ClockRole::Consumer,
                    name: "/arm-io/unavailable".into(),
                    clocks: states.resources[0].clocks.clone(),
                    power: vec![],
                    owner: None,
                    admission: coverage::Admission::Unavailable,
                });
            });
            assert!(d.power_refusals().is_empty());
            d.write(0, base + 0x1000, 4, 1, 0).unwrap();
            d.write(0, supply, 4, 0x3f4, 0).unwrap(); // Read-only actual nibble is ignored.
            assert!(d.read(0, base + 0x1000, 4, 0).is_err());
            d.write(0, supply, 4, 15, 0).unwrap();
            assert_eq!(d.read(0, base + 0x1000, 4, 0), Ok(1));
            d.write(0, supply, 4, 0x3f0, 0).unwrap(); // Original global sweep encoding.
            assert!(d.read(0, base + 0x1000, 4, 0).is_err());
            assert_eq!(
                d.bus.device::<Pmgr>(d.pmgr.unwrap()).unwrap().state(supply),
                Some(POWER_GATED)
            );
            d.write(0, supply, 4, 15, 0).unwrap();
            assert_eq!(d.read(0, base + 0x1000, 4, 0), Ok(u64::from(retention)));
            d.write(0, base + 0x1000, 4, 1, 0).unwrap();
            for value in [0x40f, 0x8000040f, 0x40f, 15] {
                d.write(0, supply, 4, value, 0).unwrap();
            }
            assert_eq!(d.read(0, base + 0x1000, 4, 0), Ok(0));
            assert_eq!(d.read(0, 0x2_3501_0000, 4, 0), Err(DeviceError::NoDevice));
        }
    }

    #[test]
    fn pmgr_domains_no_resource_names_complete_controller_state_with_no_client() {
        use super::super::soc::PowerStates;
        // J473AP ISP_SYS: the board exposes no ISP, and XNU power-gates it.
        let supply = 0x2_3b70_0438;
        let states = PowerStates {
            implicit: Vec::new(),
            blocks: vec![(supply, 4)],
            registers: vec![supply],
            domains: vec![coverage::Domain {
                name: "ISP_SYS".into(),
                id: coverage::DomainId {
                    die: 0,
                    device: 0x7a,
                },
                address: Some(supply),
                parents: [None; 4],
            }],
            resources: Vec::new(),
        };
        let mut d = AppleDevices::new();
        d.add_power_states(
            &[Range {
                physical: supply,
                bytes: 4,
            }],
            &states.registers,
        )
        .unwrap();
        d.connect_power_resources(&states, &[], &[]).unwrap();
        assert!(d.power_refusals().is_empty() && d.power_clients.is_empty());
        d.write(0, supply, 4, 0x3f0, 0).unwrap();
        assert_eq!(d.read(0, supply, 4, 0), Ok(0x100));
        for value in [0x10f, 0x40f, 0x8000_040f, 0x40f, 15] {
            d.write(0, supply, 4, value, 0).unwrap();
        }
        assert_eq!(d.read(0, supply, 4, 0), Ok(0xff));
    }

    #[test]
    fn pmgr_unavailable_only_domains_model_controller_state_without_functional_device_credit() {
        use super::super::soc::{PowerResource, PowerStates};
        let supply = 0x2_3b70_8020;
        let id = coverage::DomainId { die: 0, device: 1 };
        let states = PowerStates {
            implicit: Vec::new(),
            blocks: vec![(supply, 4)],
            registers: vec![supply],
            domains: vec![coverage::Domain {
                name: String::new(),
                id,
                address: Some(supply),
                parents: [None; 4],
            }],
            resources: vec![PowerResource {
                clock_role: crate::machine::soc::ClockRole::Consumer,
                name: "/arm-io/unavailable".into(),
                clocks: vec![id],
                power: vec![],
                owner: None,
                admission: coverage::Admission::Unavailable,
            }],
        };
        let mut d = AppleDevices::new();
        d.add_power_states(
            &[Range {
                physical: supply,
                bytes: 4,
            }],
            &states.registers,
        )
        .unwrap();
        d.connect_power_resources(&states, &[], &[]).unwrap();
        for state in [0u8, 4, 15, 4, 0, 15] {
            d.write(0, supply, 4, 0x3f0 | u64::from(state), 0).unwrap();
            assert_eq!(
                d.bus.device::<Pmgr>(d.pmgr.unwrap()).unwrap().state(supply),
                Some(state)
            );
        }
        for value in [0x40f, 0x8000040f, 0x40f, 15] {
            d.write(0, supply, 4, value, 0).unwrap();
        }
        assert!(d.power_clients.is_empty());
        assert_eq!(d.read(0, 0x2_3501_0000, 4, 0), Err(DeviceError::NoDevice));
    }

    #[test]
    fn pmgr_multi_supply_inhibits_activity_until_every_clock_and_reset_is_released() {
        let (mut d, dart, supply, base) = powered_dart(true, 2);
        d.write(0, base + 0x1000, 4, 1, 0).unwrap();
        d.write(0, supply, 4, 4, 0).unwrap();
        d.write(0, supply + 8, 4, 4, 0).unwrap();
        d.write(0, supply, 4, 15, 0).unwrap();
        assert!(d.read(0, base + 0x1000, 4, 0).is_err());
        d.write(0, supply + 8, 4, 15, 0).unwrap();
        assert_eq!(d.read(0, base + 0x1000, 4, 0), Ok(1));
        d.write(0, supply, 4, 0x40f, 0).unwrap();
        let mut access = Access::new(0, 0, &mut d.latch);
        assert!(
            d.bus
                .device_mut::<Dart>(dart.0)
                .unwrap()
                .translate(&mut Ram::new(0, 0x1000), 0, 0, 0, false, &mut access)
                .is_err()
        );
        d.write(0, supply, 4, 0x8000_040f, 0).unwrap();
        d.write(0, supply + 8, 4, 0x8000_040f, 0).unwrap();
        d.write(0, supply, 4, 15, 0).unwrap();
        assert!(d.read(0, base + 0x1000, 4, 0).is_err());
        d.write(0, supply + 8, 4, 15, 0).unwrap();
        assert_eq!(d.read(0, base + 0x1000, 4, 0), Ok(0));
    }

    #[test]
    fn pmgr_shared_parents_and_aliases_refuse_only_the_uncovered_hardware_domains() {
        use super::super::soc::PowerResource;
        use coverage::{Domain, DomainId};
        let id = |device| DomainId { die: 0, device };
        let (mut d, _, supply, base) = powered_dart_with(false, 3, |states| {
            states.domains[1].parents = [Some(id(1)), None, None, None];
            states.domains.push(Domain {
                name: String::new(),
                id: id(4),
                address: states.domains[1].address,
                parents: [Some(id(3)), None, None, None],
            });
            states.resources[0].clocks = vec![id(2)];
            for (name, device) in [("controller", 1), ("firmware-endpoint", 3)] {
                states.resources.push(PowerResource {
                    clock_role: crate::machine::soc::ClockRole::Consumer,
                    name: name.into(),
                    clocks: vec![],
                    power: vec![id(device)],
                    owner: None,
                    admission: coverage::Admission::Required,
                });
            }
        });
        assert_eq!(d.power_refusals().len(), 2);
        d.write(0, base + 0x1000, 4, 1, 0).unwrap();
        for (address, consumer) in [(supply, "controller"), (supply + 16, "firmware-endpoint")] {
            for value in [0, 4, 0x40f, 0x8000_040f] {
                let error = d.write(0, address, 4, value, 0).unwrap_err();
                let message = format!("{error:?}");
                assert!(message.contains(consumer));
                assert!(message.contains("current control 0x000000ff"));
                assert!(message.contains(&format!("requested {value:#010x}")));
                assert_eq!(d.read(0, address, 4, 0), Ok(0xff));
                assert_eq!(d.read(0, base + 0x1000, 4, 0), Ok(1));
            }
        }
        // The exclusive child remains connected even though its two alias
        // parents have unrelated unsupported hardware consumers.
        d.write(0, supply + 8, 4, 0x40f, 0).unwrap();
        d.write(0, supply + 8, 4, 0x8000_040f, 0).unwrap();
        d.write(0, supply + 8, 4, 15, 0).unwrap();
        assert_eq!(d.read(0, base + 0x1000, 4, 0), Ok(0));
    }

    #[test]
    fn pmgr_accepted_edges_survive_a_later_wire_delivery_failure() {
        use crate::platform::apple::interrupt::{InterruptSink, Wire};
        let (mut d, _, supply, base) = powered_dart(false, 1);
        d.write(0, base + 0x1000, 4, 1, 0).unwrap();
        d.latch.set_level(Wire::Aic(AicInput::new(0, 1)), true);
        // PMGR accepts the edge and DART clears first; the unrelated AIC
        // delivery then refuses. No later client may see pre-gate state.
        assert!(d.write(0, supply, 4, 0, 0).is_err());
        assert_eq!(
            d.bus
                .device::<Pmgr>(d.pmgr.unwrap())
                .unwrap()
                .domain_state(supply)
                .unwrap()
                .power,
            POWER_GATED
        );
        assert_eq!(d.pending_service().unwrap().lifecycle().len(), 1);
        assert!(d.write(0, supply, 4, 15, 1).is_err());
        assert_eq!(d.pending_service().unwrap().lifecycle().len(), 2);
        // Supplying the missing actual owner can resume the retained edge;
        // neither the earlier power-off nor the later power-on is replayed.
        d.add_aic(0x7000_0000, 32, AicLayout::V1).unwrap();
        d.settle(0, 2, None).unwrap();
        assert!(d.pending_service().is_none());
        assert_eq!(d.read(0, base + 0x1000, 4, 0), Ok(0));
    }

    #[test]
    fn watchdog_routes_separate_side_words_without_claiming_intervening_addresses() {
        let mut d = AppleDevices::new();
        let base = 0x2_3d2b_0000;
        let side = [base + 0xc218, base + 0x8008, base + 0x800c, base + 0x8020];
        let trigger = 0x2_1002_0304;
        d.add_watchdog_with_side(
            Range {
                physical: base,
                bytes: 0x4000,
            },
            Some(&super::super::soc::WatchdogSide {
                words: side.to_vec(),
                triggers: alloc::vec![(trigger, 0xf, 1)],
            }),
            None,
            0,
        )
        .unwrap();
        assert_eq!(d.read(0, side[0], 4, 0), Ok(0));
        d.write(0, side[0], 4, 1, 0).unwrap();
        assert_eq!(d.read(0, side[0], 4, 0), Ok(1));
        d.write(0, side[1], 4, 0, 0).unwrap();
        assert!(d.read(0, side[1], 4, 0).is_err());
        d.write(0, side[2], 4, 0x10, 0).unwrap();
        assert_eq!(d.read(0, side[2], 4, 0), Ok(0x10));
        assert_eq!(d.read(0, side[3], 4, 0), Ok(0));
        assert!(d.read(0, side[0] + 4, 4, 0).is_err());
        assert!(d.read(0, base + 0x5000, 4, 0).is_err());
        d.write(0, trigger, 4, 1, 0).unwrap();
        assert_eq!(d.read(0, trigger, 4, 0), Ok(1));
        assert!(d.read(0, trigger + 4, 4, 0).is_err());
    }

    #[test]
    fn watchdog_shares_declared_flags_and_refuses_unqualified_aliases_before_mapping() {
        let base = 0x2_922b_0000;
        let flags = base + 0x8020;
        let words = [flags, base + 0x802c, base + 0x8008, flags];
        let trigger = 0x2_1002_0304;
        let range = Range {
            physical: base,
            bytes: 0x4000,
        };
        let side = super::super::soc::WatchdogSide {
            words: words.to_vec(),
            triggers: alloc::vec![(trigger, 0xf, 1), (trigger, 0xf, 1)],
        };
        let mut d = AppleDevices::new();
        d.add_watchdog_with_side(range, Some(&side), None, 0)
            .unwrap();
        d.write(0, flags, 4, 0xabcd_0001, 0).unwrap();
        let old = d.read(0, flags, 4, 0).unwrap();
        d.write(0, flags, 4, old | 4, 0).unwrap();
        assert_eq!(d.read(0, flags, 4, 0), Ok(0xabcd_0005));
        assert_eq!(d.read(0, words[2], 4, 0), Ok(0));
        assert!(d.read(0, words[1], 4, 0).is_err());
        assert_eq!(d.read(0, base, 4, 0), Ok(0));
        d.write(0, trigger, 4, 1, 0).unwrap();
        assert_eq!(d.read(0, trigger, 4, 0), Ok(1));
        assert!(d.read(0, flags + 4, 4, 0).is_err());

        let mut bad_cases = Vec::new();
        let mut bad = side.clone();
        bad.words[1] = flags;
        bad_cases.push(bad);
        let mut bad = side.clone();
        bad.words[2] = flags;
        bad_cases.push(bad);
        let mut bad = side.clone();
        bad.words[0] = base;
        bad_cases.push(bad);
        let mut bad = side.clone();
        bad.words[0] += 1;
        bad_cases.push(bad);
        let mut bad = side.clone();
        bad.words[0] = u64::MAX - 3;
        bad_cases.push(bad);
        let mut bad = side.clone();
        bad.words.push(base + 0x9000);
        bad_cases.push(bad);
        let mut bad = side.clone();
        bad.words.truncate(1);
        bad_cases.push(bad);
        let mut bad = side.clone();
        bad.triggers[1].1 = 3;
        bad_cases.push(bad);
        let mut bad = side.clone();
        bad.triggers[0].0 = flags;
        bad_cases.push(bad);
        for bad in bad_cases {
            let mut d = AppleDevices::new();
            assert!(
                d.add_watchdog_with_side(range, Some(&bad), None, 0)
                    .is_err()
            );
            assert!(d.read(0, base, 4, 0).is_err(), "no primary view published");
            assert!(d.read(0, flags, 4, 0).is_err(), "no side view published");
        }
    }

    #[test]
    fn implementation_windows_share_lockdown_energy_and_cpm_without_overlap() {
        let mut d = AppleDevices::new();
        let cpm = 0x2_11e4_0000;
        let cpu = 0x2_1105_0000;
        d.add_lockdown(
            "cpm-impl-reg",
            0x9000,
            Range {
                physical: cpm,
                bytes: 0x10000,
            },
            None,
        )
        .unwrap();
        d.add_cpm_power(cpm, true).unwrap();
        d.add_cpu_energy(cpm + 0x8000, true).unwrap();
        d.add_lockdown(
            "cpu-impl-reg",
            0x5000,
            Range {
                physical: cpu,
                bytes: 0x10000,
            },
            Some((0, 0x8000_0000)),
        )
        .unwrap();
        d.add_cpu_energy(cpu + 0x9000, false).unwrap();
        assert_eq!(d.read(0, cpm + 0x9008, 8, 0), Ok(0));
        assert_eq!(d.read(0, cpu, 8, 0), Ok(0x8000_0001));
        d.write(0, cpm + 0x250, 8, 1 << 63, 0).unwrap();
        assert_eq!(d.read(0, cpm + 0x250, 8, 0), Ok(1 << 63));
        d.write(0, cpm + 0x40f8, 8, 1, 0).unwrap();
        assert!(d.read(0, cpm + 0x40f8, 8, 0).is_err());
        assert!(d.read(0, cpm + 0x1234, 8, 0).is_err());
    }

    #[test]
    fn external_gpio_cs_delimits_nor_commands_across_controller_transfers() {
        use super::super::soc::{Device, GpioBank, SpiNor};
        const SPI: u64 = 0x10000;
        const GPIO: u64 = 0x20000;
        const PIN: u64 = GPIO + 49 * 4;
        let mut devices = AppleDevices::new();
        devices
            .add_aic(0x100000, 1024, AicLayout::aic2(0x8000, 0))
            .unwrap();
        let bank = GpioBank {
            profile: crate::platform::apple::gpio::Profile::T8101,
            no_restore_pins: Vec::new(),
            physical: GPIO,
            bytes: 0x1000,
            pins: 213,
            groups: 7,
            phandle: 106,
            lines: (199..206).collect(),
            i2c_lines: Vec::new(),
        };
        devices.add_gpio(&bank, &[49], &[]).unwrap();
        devices
            .add_spi_nor(&SpiNor {
                device: Device {
                    physical: SPI,
                    bytes: 0x4000,
                    irq: 749,
                },
                image: nor::Image::fresh(),
                select: Some(49),
            })
            .unwrap();
        fn transfer(devices: &mut AppleDevices, bytes: &[u8]) -> Vec<u8> {
            devices.write(0, SPI, 4, 0, 0).unwrap();
            devices.write(0, SPI, 4, 12, 0).unwrap();
            devices
                .write(0, SPI + 0x34, 4, bytes.len() as u64, 0)
                .unwrap();
            devices
                .write(0, SPI + 0x4c, 4, bytes.len() as u64, 0)
                .unwrap();
            for &b in bytes {
                devices.write(0, SPI + 0x10, 4, u64::from(b), 0).unwrap();
            }
            devices.write(0, SPI, 4, 1, 0).unwrap();
            (0..bytes.len())
                .map(|_| devices.read(0, SPI + 0x20, 4, 0).unwrap() as u8)
                .collect()
        }
        devices.write(0, PIN, 4, 2, 0).unwrap();
        transfer(&mut devices, &[0x06]);
        devices.write(0, PIN, 4, 3, 0).unwrap();
        devices.write(0, PIN, 4, 2, 0).unwrap();
        transfer(&mut devices, &[0x02, 0, 0, 0]);
        transfer(&mut devices, &[0x42, 0x24]);
        devices.write(0, PIN, 4, 3, 0).unwrap();
        devices.write(0, PIN, 4, 2, 0).unwrap();
        transfer(&mut devices, &[0x03, 0, 0, 0]);
        assert_eq!(transfer(&mut devices, &[0xff, 0xff]), [0x42, 0x24]);
        devices.write(0, PIN, 4, 3, 0).unwrap();
        // An incomplete address cannot release CS or mutate the GPIO word.
        devices.write(0, PIN, 4, 2, 0).unwrap();
        transfer(&mut devices, &[0x20, 0]);
        assert!(devices.write(0, PIN, 4, 3, 0).is_err());
        assert_eq!(devices.read(0, PIN, 4, 0), Ok(2));
    }

    #[test]
    fn ans_dma_and_sart_idle_share_the_nvme_aperture_without_aliasing() {
        use crate::machine::soc::AnsController;
        use crate::platform::apple::{ans, sart};
        use crate::platform::dma::tests::Ram;
        use stela_drivers::block::RamDisk;
        const NVME: u64 = 0x2_7bcc_0000;
        const SART: u64 = 0x2_7bc5_0000;
        const WRAPPER: u64 = 0x2_7740_0000;
        const VDMA: u64 = 0x2_7b10_0000;
        const RAM: u64 = 0x8_0000_0000;
        const SUPPLY: u64 = 0x2_3b70_0428;
        let placement = AnsController {
            geometry: ans::QueueGeometry::DEFAULT,
            wrapper: (WRAPPER, 0x6c000),
            nvme: (NVME, 0x60000),
            vdma: Some((VDMA, 0x44000)),
            sart: (SART, 0xc000),
            sart_layout: sart::Layout::V3,
            sart_idle: NVME + 0x13e8,
            sart_canary: None,
            sart_exclusive_bounds: false,
            interrupts: [718, 717, 720, 719],
            completion_irq: 724,
            namespaces: alloc::vec![ans::Description {
                id: 1,
                kind: 1,
                blocks: 0
            }],
            clock_gates: alloc::vec![coverage::DomainId {
                die: 0,
                device: 125
            }],
            power_gates: alloc::vec![coverage::DomainId {
                die: 0,
                device: 125
            }],
        };
        let mut devices = AppleDevices::new();
        devices
            .add_aic(0x2_3b0c_0000, 1152, AicLayout::aic2(0x8000, 0))
            .unwrap();
        devices
            .add_ans(
                &placement,
                Box::new(RamDisk::new("backing", 16, 4096)),
                crate::builds::DEFAULT,
            )
            .unwrap();
        assert_eq!(devices.power_devices.len(), 4);
        assert!(
            devices
                .power_devices
                .iter()
                .filter(|bank| bank.physical != 0x2_3b0c_0000)
                .all(|bank| bank.physical == WRAPPER)
        );
        connect_native_power(&mut devices, SUPPLY, &[("/arm-io/ans", WRAPPER)], true);
        assert_eq!(devices.read(0, WRAPPER + 0x44, 4, 0), Ok(1 << 4));
        // The roll call lists 0x20, which RTBuddy publishes as the
        // ANS2Endpoint1 service the NVMe driver waits for.
        walk_rtkit_start(&mut devices, WRAPPER);
        // The ASC has no owned mailbox work and qualifies native cold reset;
        // the later NVMe bank must veto before either it or PMGR changes.
        let pmgr_before = devices.read(0, SUPPLY, 4, 0).unwrap();
        devices.write(0, SUPPLY, 4, 0x40f, 0).unwrap();
        let quiesced = devices.read(0, SUPPLY, 4, 0).unwrap();
        let failure = devices.write(0, SUPPLY, 4, 0x8000_040f, 0).unwrap_err();
        assert!(
            matches!(failure, DeviceError::Refused(reason) if reason.contains("ANS physical reset"))
        );
        assert_eq!(devices.read(0, SUPPLY, 4, 0), Ok(quiesced));
        assert_eq!(devices.read(0, WRAPPER + 0x44, 4, 0), Ok(1 << 4));
        devices.write(0, SUPPLY, 4, 15, 0).unwrap();
        assert_eq!(devices.read(0, SUPPLY, 4, 0), Ok(pmgr_before));
        devices.write(0, WRAPPER + 0x8800, 8, 1, 0).unwrap();
        // A request the ANS firmware does not implement is reported once.
        devices.write(0, WRAPPER + 0x8808, 8, 0x20, 0).unwrap();
        assert_eq!(devices.take_unmodeled().len(), 1);
        devices.write(0, NVME + 0x13e8, 4, 1, 0).unwrap();
        assert_eq!(devices.read(0, NVME + 0x13e8, 4, 0), Ok(1));
        assert_eq!(devices.read(0, NVME + 0x1300, 4, 0), Ok(0xde71_ce55));
        assert!(devices.read(0, NVME + 0x13ec, 4, 0).is_err());
        for (at, value) in [
            (SART + 0x40, RAM / sart::PAGE),
            (SART + 0x80, 16),
            (SART, 0xff),
            (NVME + 0x24, 0x0001_0001),
            (NVME + 0x28, RAM),
            (NVME + 0x30, RAM + 0x1000),
            (NVME + 0x28108, RAM + 0x2000),
            (NVME + 0x24908, 1),
            (NVME + 0x14, 0x0046_0001),
        ] {
            let width = if [NVME + 0x28, NVME + 0x30, NVME + 0x28108].contains(&at) {
                8
            } else {
                4
            };
            devices.write(0, at, width, value, 0).unwrap();
        }
        let mut ram = Ram::new(RAM, 0x10000);
        let mut command = [0; 64];
        command[0] = 6;
        command[24..32].copy_from_slice(&(RAM + 0x4000).to_le_bytes());
        command[40] = 1;
        let mut tcb = [0; 128];
        tcb[1] = 1;
        tcb[24..32].copy_from_slice(&(RAM + 0x4000).to_le_bytes());
        assert!(Memory::write(&mut ram, RAM, &command));
        assert!(Memory::write(&mut ram, RAM + 0x2000, &tcb));
        devices.write(0, NVME + 0x2490c, 4, 0, 0).unwrap();
        // A real accepted command is frozen through each retained gate.
        for gate in [4, 0x40f, 0] {
            devices.write(0, SUPPLY, 4, gate, 0).unwrap();
            devices.transfer(0, &mut ram, 0).unwrap();
            let mut empty = [1; 16];
            assert!(Memory::read(&mut ram, RAM + 0x1000, &mut empty));
            assert_eq!(empty, [0; 16]);
            devices.write(0, SUPPLY, 4, 15, 0).unwrap();
        }
        devices.transfer(0, &mut ram, 0).unwrap();
        let mut completion = [0; 16];
        assert!(Memory::read(&mut ram, RAM + 0x1000, &mut completion));
        assert_eq!(completion[14], 1);
        let mut model = [0; 10];
        assert!(Memory::read(&mut ram, RAM + 0x4000 + 24, &mut model));
        assert_eq!(&model, b"Stela ANS2");
        // The completed tag's VDMA cache entry holds no DMA permissions, the
        // state SPTM's UNMAP_PAGES requires; other words have no model.
        let entry = VDMA + ans::VDMA_CACHE_OFFSET;
        assert_eq!(devices.read(0, entry, 4, 0), Ok(0));
        assert_eq!(devices.read(0, entry + 63 * 32, 4, 0), Ok(0));
        assert!(devices.read(0, entry + 4, 4, 0).is_err());
        assert!(devices.write(0, entry, 4, 0, 0).is_err());
        assert!(
            devices
                .read(0, entry + ans::VDMA_CACHE_BYTES, 4, 0)
                .is_err()
        );
    }

    #[test]
    fn an_aux_gpio_bank_reads_the_lines_its_board_drives() {
        use crate::machine::soc::{AuxGpioBank, GpioBank};
        const BANK: u64 = 0x2_4a82_0000;
        const HPD: u32 = 0x31;
        let aux = AuxGpioBank {
            name: "aop-gpio".into(),
            bank: GpioBank {
                profile: crate::platform::apple::gpio::Profile::T8101,
                no_restore_pins: Vec::new(),
                physical: BANK,
                bytes: 0x4000,
                pins: 0x36,
                groups: 7,
                phandle: 0x6b,
                lines: alloc::vec![0x12d, 0x12e, 0x12f, 0x130, 0x131, 0x132, 0x133],
                i2c_lines: Vec::new(),
            },
            client_pins: alloc::vec![0x28, HPD],
        };
        let mut devices = AppleDevices::new();
        devices
            .add_aic(0x2_3b0c_0000, 1152, AicLayout::aic2(0x8000, 0))
            .unwrap();
        devices.add_aux_gpio(&aux).unwrap();
        assert!(devices.add_aux_gpio(&aux).is_err());
        let hpd = devices.gpio_line(0x6b, HPD).unwrap();
        assert!(devices.gpio_line(0x6b, 0x30).is_err());
        assert!(devices.gpio_line(0x6c, HPD).is_err());
        // An interrupt-disabled input with its receiver on reads the net.
        let pin = BANK + 4 * u64::from(HPD);
        devices.write(0, pin, 4, 0xe | 1 << 9, 0).unwrap();
        assert_eq!(devices.read(0, pin, 4, 0).unwrap() & 1, 1);
        hpd.pull_low(true);
        assert_eq!(devices.read(0, pin, 4, 0).unwrap() & 1, 0);
    }

    /// Every message waiting in an ASC wrapper's outbox, as (endpoint,
    /// payload).
    fn mailbox_drain(devices: &mut AppleDevices, wrapper: u64) -> Vec<(u64, u64)> {
        let mut messages = Vec::new();
        while devices.read(0, wrapper + 0x8114, 4, 0).unwrap() & 1 << 17 == 0 {
            let payload = devices.read(0, wrapper + 0x8830, 8, 0).unwrap();
            let endpoint = devices.read(0, wrapper + 0x8838, 8, 0).unwrap() & 0xff;
            messages.push((endpoint, payload));
        }
        messages
    }

    /// The AP side of the RTKit start-up handshake restore boot s25 logged
    /// for a coprocessor listing one application endpoint 0x20, word for
    /// word, up to the client driver's STARTEP of it, except that group 0
    /// now also lists the crashlog endpoint. The coprocessor must end
    /// enumeration with the power-on announcement the AP waits for.
    fn walk_rtkit_start(devices: &mut AppleDevices, wrapper: u64) {
        let send = |devices: &mut AppleDevices, payload| {
            devices.write(0, wrapper + 0x8800, 8, payload, 0).unwrap();
            devices.write(0, wrapper + 0x8808, 8, 0, 0).unwrap();
            mailbox_drain(devices, wrapper)
        };
        assert_eq!(
            mailbox_drain(devices, wrapper),
            [(0, 0x0010_0000_000c_000c)]
        );
        assert_eq!(
            send(devices, 0x0020_0000_000c_000c),
            [(0, 0x0080_0000_0000_0003)]
        );
        assert_eq!(
            send(devices, 0x0080_0000_0000_0001),
            [(0, 0x0088_0001_0000_0001)]
        );
        assert_eq!(
            send(devices, 0x0088_0001_0000_0000),
            [(0, 0x0070_0000_0000_0020)]
        );
        assert!(send(devices, 0x0050_0020_0000_0002).is_empty());
    }

    #[test]
    fn pmp_places_a_running_user_managed_wrapper() {
        use crate::machine::soc::PmpController;
        const WRAPPER: u64 = 0x2_3bc0_0000;
        let mut devices = AppleDevices::new();
        devices
            .add_aic(0x2_3b0c_0000, 1152, AicLayout::aic2(0x8000, 0))
            .unwrap();
        devices
            .add_pmp(
                &PmpController {
                    wrapper: (WRAPPER, 0x6c000),
                    interrupts: [0x275, 0x274, 0x277, 0x276],
                    quiesced: false,
                    mapper: None,
                },
                crate::builds::DEFAULT,
            )
            .unwrap();
        assert_eq!(devices.power_devices.len(), 2);
        assert_eq!(devices.power_devices[1].physical, WRAPPER);
        let supply = 0x2_3b70_0410;
        connect_native_power(&mut devices, supply, &[("/arm-io/pmp", WRAPPER)], false);
        // Its committed HELLO survives a real clock gate without restarting
        // native firmware or fabricating an additional message on release.
        devices.write(0, supply, 4, 4, 0).unwrap();
        assert!(devices.read(0, WRAPPER + 0x8830, 8, 0).is_err());
        devices.write(0, supply, 4, 15, 0).unwrap();
        // Started and running; its HELLO waits in the outbox.
        assert_eq!(devices.read(0, WRAPPER + 0x44, 4, 0), Ok(1 << 4));
        assert_eq!(devices.coprocessor_diagnostics().len(), 1);
        assert!(devices.coprocessor_diagnostics()[0].starts_with("PMP "));
        // A user-power-managed nub is still awaited to running.
        walk_rtkit_start(&mut devices, WRAPPER);
    }

    #[test]
    fn gfx_native_control_cannot_bind_over_another_mounted_bank() {
        use crate::machine::soc::GfxController;
        use crate::platform::apple::agx::generation;
        const WRAPPER: u64 = 0x2_0640_0000;
        const CONTROL: u64 = WRAPPER + 0x14_0120;
        let placement = GfxController {
            gpu: generation::by_chip(0x8112).unwrap(),
            wrapper: (WRAPPER, 0x6c000),
            interrupts: [0x2c6, 0x2c5, 0x2c8, 0x2c7],
            sgx: vec![(0x2_0400_0000, 0x400_0000, 0)],
            ttbat: 0x8_0000_0000,
            shared_l2: 0x8_0000_8000,
        };
        // Reject a complete foreign word and a foreign upper half. Declared
        // SGX geometry alone cannot qualify either physical bus layout.
        for (base, bytes) in [(CONTROL, 8), (CONTROL + 4, 4)] {
            let mut devices = AppleDevices::new();
            let foreign = devices.bus.add(Box::new(CheckedPowerBank {
                reject: true,
                committed: Vec::new(),
            }));
            devices.bus.map(foreign, base, bytes, 0).unwrap();
            assert_eq!(
                devices.add_gfx(&placement, crate::builds::DEFAULT),
                Err("GFX native ASC control is not wholly owned by its mounted SGX bank".into())
            );
            assert!(devices.gfx_masters.is_empty());
            assert_eq!(devices.bus.route(base, Width::Word), Ok((foreign, 0)));
            assert!(
                devices
                    .bus
                    .device::<CheckedPowerBank>(foreign)
                    .unwrap()
                    .committed
                    .is_empty()
            );
        }
    }

    #[test]
    fn pro_max_and_ultra_gfx_keep_their_sparse_original_banks() {
        use crate::machine::soc::GfxController;
        use crate::platform::apple::agx::generation;
        // 26A434 original ADTs: J314s/c, J375c/d, J414s/c and J180d.
        // arm-io/ranges translates the child bases by 0x2_0000_0000.
        // G13X/G14X use their own callback programs, not G14G's private
        // wrapper+0x140120 word (docs/research/agx.md, sections 3 and 6).
        const SGX: u64 = 0x4_0400_0000;
        const WRAPPER: u64 = 0x4_0640_0000;
        for chip in [0x6000, 0x6001, 0x6002, 0x6020, 0x6021, 0x6022] {
            let info_bytes = if chip < 0x6020 { 0x20000 } else { 0x16c000 };
            let placement = GfxController {
                gpu: generation::by_chip(chip).unwrap(),
                wrapper: (WRAPPER, 0x6c000),
                interrupts: [0x2c6, 0x2c5, 0x2c8, 0x2c7],
                sgx: vec![(SGX, 0x100000, 0), (SGX + 0xd00000, info_bytes, 0xd00000)],
                ttbat: 0x100_0000_0000,
                shared_l2: 0x100_0000_8000,
            };
            let mut devices = AppleDevices::new();
            devices.add_gfx(&placement, crate::builds::DEFAULT).unwrap();
            let (asc, block) = devices.gfx_masters[0];
            assert_eq!(
                devices.bus.route(WRAPPER + 0x8110, Width::Word),
                Ok((asc, 0x8110))
            );
            assert_eq!(
                devices.bus.route(SGX + 0xd04000, Width::Word),
                Ok((block, 0xd04000))
            );
            assert!(devices.read(0, SGX + 0xd04000, 4, 0).is_ok());
            // No fabricated SGX aperture or successful control-word effect.
            assert!(
                devices
                    .bus
                    .route(WRAPPER + 0x14_0120, Width::Double)
                    .is_err()
            );
            assert!(devices.bus.route(SGX + 0x200000, Width::Word).is_err());
        }
    }

    #[test]
    fn gfx_firmware_reads_its_initdata_through_the_uat_the_sgx_mmu_roots() {
        use crate::machine::soc::GfxController;
        use crate::platform::apple::agx::{firmware, generation, uat as table};
        use crate::platform::dma::tests::Ram;
        const WRAPPER: u64 = 0x2_0640_0000;
        const SGX: u64 = 0x2_0400_0000;
        const RAM: u64 = 0x8_0000_0000;
        const SUPPLY: u64 = 0x2_3b70_0430;
        let placement = GfxController {
            gpu: generation::by_chip(0x8112).unwrap(),
            wrapper: (WRAPPER, 0x6c000),
            interrupts: [0x2c6, 0x2c5, 0x2c8, 0x2c7],
            sgx: vec![(SGX, 0x400_0000, 0)],
            ttbat: RAM,
            shared_l2: RAM + 0x8000,
        };
        let mut devices = AppleDevices::new();
        devices
            .add_aic(0x2_3b0c_0000, 1152, AicLayout::aic2(0x8000, 0))
            .unwrap();
        devices.add_gfx(&placement, crate::builds::DEFAULT).unwrap();
        assert_eq!(devices.power_devices.len(), 3);
        assert_eq!(devices.power_devices[1].physical, WRAPPER);
        assert_eq!(devices.power_devices[2].physical, SGX);
        connect_native_power(
            &mut devices,
            SUPPLY,
            &[("/arm-io/gfx-asc", WRAPPER), ("/arm-io/sgx", SGX)],
            true,
        );
        // The coprocessor is running and the sgx identity reads through the bus.
        assert_eq!(devices.read(0, WRAPPER + 0x44, 4, 0), Ok(1 << 4));
        assert_eq!(devices.read(0, SGX + 0xd0_4000, 4, 0).unwrap() >> 24, 5);
        assert!(devices.read(0, SGX + 0x10, 4, 0).is_err());
        // The wrapper inside the sgx window stays the ASC's.
        assert!(devices.read(0, WRAPPER + 0x8110, 4, 0).is_ok());
        let (_, block) = devices.gfx_masters[0];
        assert_eq!(
            devices.bus.route(WRAPPER + 0x14_0120, Width::Double),
            Ok((block, 0x254_0120))
        );

        // The TTBAT, context 0's empty TTBR1 root, and one firmware page of
        // the shared kernel window through the shared L2, as SPTM leaves
        // them.
        let mut ram = Ram::new(RAM, 0x4000 * 5);
        let va = 0xffff_ffa0_0000_0000_u64;
        let (_, idx) = table::indices(va);
        let [ttbr0, ttbr1] = table::encode_gptbat(0, 0, RAM + 0x4000);
        ram.put_u64(RAM, ttbr0 & !1);
        ram.put_u64(RAM + 8, ttbr1);
        ram.put_u64(
            RAM + 0x8000 + idx[1] as u64 * 8,
            table::encode_table(RAM + 0xc000),
        );
        let flags = table::Flags {
            access: table::Access::Firmware,
            memory: table::MemoryAttr::Uncached,
            global: true,
            pxn: false,
            uxn: true,
            gpu_access: true,
        };
        ram.put_u64(
            RAM + 0xc000 + idx[2] as u64 * 8,
            table::encode_pte(RAM + 0x1_0000, &flags),
        );
        // The kext's root: magic, the +0x28 words and its object pointers.
        ram.put_u64(RAM + 0x1_0000, generation::MAGIC_G13_G14G);
        ram.put_u64(RAM + 0x1_0028, 1 << 32);
        for field in [0x08, 0x18, 0x20, 0xa8, 0xb0, 0xb8, 0xc0] {
            ram.put_u64(RAM + 0x1_0000 + field, va + 0x1000);
        }
        // The boot stage handed the MMU off enabled at the TTBAT, so
        // setupMMUConfig returns at once.
        assert_eq!(devices.read(0, SGX + 0xd0_8000, 4, 0), Ok(1));
        assert_eq!(devices.read(0, SGX + 0xd0_802c, 4, 0), Ok(RAM >> 14));

        // RTKit start-up over the mailbox.
        let send = |devices: &mut AppleDevices, endpoint: u64, payload: u64| {
            devices.write(0, WRAPPER + 0x8800, 8, payload, 0).unwrap();
            devices.write(0, WRAPPER + 0x8808, 8, endpoint, 0).unwrap();
        };
        let receive = |devices: &mut AppleDevices| {
            let payload = devices.read(0, WRAPPER + 0x8830, 8, 0).unwrap();
            let endpoint = devices.read(0, WRAPPER + 0x8838, 8, 0).unwrap() & 0xff;
            (endpoint, payload)
        };
        let mgmt = |kind: u64, fields: u64| kind << 52 | fields;
        assert_eq!(receive(&mut devices), (0, mgmt(1, 12 | 12 << 16)));
        send(&mut devices, 0, mgmt(2, 12 | 12 << 16));
        // Group 0: the management and crashlog endpoints.
        assert_eq!(receive(&mut devices), (0, mgmt(8, 3)));
        send(&mut devices, 0, mgmt(8, 3));
        // 0x20 and 0x21 are bits 0 and 1 of the last group, 1.
        assert_eq!(receive(&mut devices), (0, mgmt(8, 1 << 51 | 1 << 32 | 3)));
        send(&mut devices, 0, mgmt(8, 1 << 51 | 1 << 32 | 3));
        assert_eq!(receive(&mut devices), (0, mgmt(7, 0x20)));
        for endpoint in [0x20, 0x21] {
            send(&mut devices, 0, mgmt(5, endpoint << 32 | 2));
        }
        devices.write(0, SUPPLY, 4, 0x40f, 0).unwrap();
        let before = devices.read(0, SUPPLY, 4, 0).unwrap();
        let failure = devices.write(0, SUPPLY, 4, 0x8000_040f, 0).unwrap_err();
        assert!(
            matches!(failure, DeviceError::Refused(reason) if reason.contains("SGX physical reset"))
        );
        assert_eq!(devices.read(0, SUPPLY, 4, 0), Ok(before));
        assert_eq!(devices.read(0, WRAPPER + 0x44, 4, 0), Ok(1 << 4));
        devices.write(0, SUPPLY, 4, 15, 0).unwrap();
        // notifyFirmwareStarted's initdata message, then the firmware's read.
        send(&mut devices, 0x20, 0x81 << 48 | (va & ((1 << 44) - 1)));
        for gate in [4, 0x40f, 0] {
            devices.write(0, SUPPLY, 4, gate, 0).unwrap();
            devices.transfer(0, &mut ram, 0).unwrap();
            assert!(
                !devices
                    .bus
                    .device::<Asc>(devices.gfx_masters[0].0)
                    .unwrap()
                    .firmware::<firmware::Coprocessor>()
                    .unwrap()
                    .protocol()
                    .with(|state| state.initdata_checked)
            );
            devices.write(0, SUPPLY, 4, 15, 0).unwrap();
        }
        devices.transfer(0, &mut ram, 0).unwrap();
        let checked = devices
            .bus
            .device::<Asc>(devices.gfx_masters[0].0)
            .and_then(|asc| asc.firmware::<firmware::Coprocessor>())
            .map(|gfx| gfx.protocol().with(|state| state.initdata_checked));
        assert_eq!(checked, Some(true));
    }

    #[test]
    fn smc_places_a_running_wrapper_its_shared_page_and_watchdog() {
        use crate::machine::soc::SmcController;
        const WRAPPER: u64 = 0x2_3e40_0000;
        const WATCHDOG: u64 = 0x2_3e81_0000;
        const REGION: u64 = 0x2_3fe0_0000;
        let placement = SmcController {
            wrapper: (WRAPPER, 0x6c000),
            interrupts: [0x1f4, 0x1f3, 0x1f6, 0x1f5],
            watchdog: Some((WATCHDOG, 0x14)),
            region: (REGION, 0x10_0000),
            gpio_keys: alloc::vec![smc::code(b"gP16")],
            quiesced: true,
            wake_bits: smc::WakeBits::default(),
        };
        let mut devices = AppleDevices::new();
        devices
            .add_aic(0x2_3b0c_0000, 1152, AicLayout::aic2(0x8000, 0))
            .unwrap();
        assert!(devices.power_button(true).is_err());
        devices.add_smc(&placement, crate::builds::DEFAULT).unwrap();
        // The press waits in the key endpoint until the AP enables
        // notifications.
        devices.power_button(true).unwrap();
        devices.power_button(false).unwrap();
        assert_eq!(devices.read(0, WRAPPER + 0x44, 4, 0), Ok(1 << 4));
        devices.write(0, REGION + 8, 8, 0x1122_3344, 0).unwrap();
        assert_eq!(devices.read(0, REGION + 8, 8, 0), Ok(0x1122_3344));
        // The coprocessor's own memory past the shared page has no model.
        assert!(devices.read(0, REGION + smc::SRAM_BYTES, 4, 0).is_err());
        assert_eq!(devices.read(0, WATCHDOG + 0xc, 4, 0), Ok(0));
        devices.write(0, WATCHDOG + 0xc, 4, 0, 0).unwrap();
        assert_eq!(devices.coprocessor_diagnostics().len(), 1);
    }

    #[test]
    fn rtc_publication_precedes_every_timed_service_and_refuses_stale_effects() {
        let epoch = pmu::RtcEpoch {
            counter: 100,
            ticks: 1234,
        };
        let clock = pmu::RtcClock::new(epoch).unwrap();
        let mut devices = AppleDevices::new();
        devices.rtc_clock = Some(clock.clone());
        let timer = 0x2_922b_0000;
        devices
            .add_watchdog(
                &[Range {
                    physical: timer,
                    bytes: 0x4000,
                }],
                None,
                epoch.counter,
            )
            .unwrap();
        assert!(clock.published_ticks().is_err());
        devices.write(0, timer + 4, 4, 50, epoch.counter).unwrap();
        assert_eq!(clock.published_ticks(), Ok(epoch.ticks));
        let hz = crate::platform::apple::counter::FREQUENCY_HZ;
        let ticks = |seconds| epoch.ticks + seconds * pmu::RTC_HZ;
        devices.read(0, timer + 4, 4, epoch.counter + hz).unwrap();
        assert_eq!(clock.published_ticks(), Ok(ticks(1)));
        let mut ram = Ram::new(0x800000000, 0x4000);
        devices
            .transfer(0, &mut ram, epoch.counter + 2 * hz)
            .unwrap();
        assert_eq!(clock.published_ticks(), Ok(ticks(2)));
        assert_eq!(
            devices.system_register(
                0,
                Encoding::new(3, 0, 0, 0, 0),
                None,
                epoch.counter + 3 * hz
            ),
            None
        );
        assert_eq!(clock.published_ticks(), Ok(ticks(3)));
        devices.lines(0, epoch.counter + 4 * hz);
        assert_eq!(clock.published_ticks(), Ok(ticks(4)));
        devices.deadline(epoch.counter + 5 * hz);
        assert_eq!(clock.published_ticks(), Ok(ticks(5)));
        // An old counter cannot change the timer or replace the last sample.
        assert!(devices.write(0, timer + 4, 4, 99, epoch.counter).is_err());
        assert_eq!(clock.published_ticks(), Ok(ticks(5)));
        assert_eq!(
            devices.read(0, timer + 4, 4, epoch.counter + 5 * hz),
            Ok(50)
        );
        // Lines/deadline cannot return Result; they retain an explicit halt.
        devices.lines(0, epoch.counter);
        let reset = devices.reset.take().unwrap();
        assert_eq!(reset.transition, Transition::Halt);
        assert!(reset.reason.contains("RTC"));
        devices.deadline(epoch.counter);
        assert_eq!(devices.reset.take().unwrap().transition, Transition::Halt);
    }

    #[test]
    fn native_dma_constructors_preflight_every_actual_owner_before_publication() {
        const DART: u64 = 0x235004000;
        const AES: u64 = 0x23500c000;
        const WRAPPER: u64 = 0x271c00000;
        struct UnusedScreen;
        impl Scanout for UnusedScreen {
            fn mode(&self) -> ScanoutMode {
                panic!("DCP used scanout before owner preflight")
            }
            fn present(&mut self, _: &[u8]) -> Result<(), &'static str> {
                unreachable!()
            }
        }
        fn refuse(d: &mut AppleDevices, dart: DartId, input: usize) {
            assert!(
                d.add_aes(
                    &[
                        Range {
                            physical: AES,
                            bytes: aes::BLOCK_BYTES
                        },
                        Range {
                            physical: 0x23d2dc000,
                            bytes: 0x8000
                        }
                    ],
                    j473_aes(),
                    None,
                    (dart, input),
                    None
                )
                .unwrap_err()
                .contains("DART")
            );
            assert!(
                d.add_dcpext(
                    Range {
                        physical: WRAPPER,
                        bytes: 0x6c000
                    },
                    [1, 2, 3, 4],
                    false,
                    "DCPEXT",
                    dcp::ExternalIdentity::Unnumbered,
                    Box::new(UnusedScreen),
                    (dart, input),
                    None,
                    None,
                    crate::builds::DEFAULT
                )
                .unwrap_err()
                .contains("DART")
            );
            let mut usb = usb_placement();
            usb.stream = input as u32;
            assert!(d.add_usb(&usb, dart).unwrap_err().contains("DART"));
            assert!(d.masters.is_empty() && d.dcp_masters.is_empty() && d.usb_masters.is_empty());
            for address in [AES, WRAPPER + 0x8114, usb.ranges[0].0 + 0x20] {
                assert!(d.read(0, address, 4, 0).is_err());
            }
        }
        for profile in [dart::Profile::T6000, dart::Profile::T8110] {
            let mut other = AppleDevices::new();
            let absent = other
                .add_dart(
                    Range {
                        physical: DART,
                        bytes: 0x4000,
                    },
                    2,
                    None,
                    None,
                )
                .unwrap();
            let mut d = AppleDevices::new();
            refuse(&mut d, absent, 1);
            d.add_aic(0x23b0c0000, 1152, AicLayout::aic2(0x8000, 0))
                .unwrap();
            let (Controller::V1(id) | Controller::V2(id)) = d.aic.unwrap();
            refuse(&mut d, DartId(id), 1);
            let owner = d
                .add_dart_group_for_profile(
                    profile,
                    &[Range {
                        physical: DART,
                        bytes: 0x4000,
                    }],
                    2,
                    None,
                    None,
                )
                .unwrap()[0];
            // Validate actual constructed capacity2, not the generation's limit.
            refuse(&mut d, owner, 2);
            refuse(&mut d, owner, u32::MAX as usize);
            assert!(
                d.add_dcpext(
                    Range {
                        physical: WRAPPER,
                        bytes: 0x6c000
                    },
                    [1, 2, 3, 4],
                    false,
                    "DCPEXT",
                    dcp::ExternalIdentity::Unnumbered,
                    Box::new(UnusedScreen),
                    (owner, 1),
                    None,
                    Some((owner, 2)),
                    crate::builds::DEFAULT
                )
                .unwrap_err()
                .contains("DCP surface")
            );
            assert!(d.coprocessors.is_empty() && d.dcp_masters.is_empty());
            assert!(d.read(0, WRAPPER + 0x8114, 4, 0).is_err());
            // Every refusal left the apertures available for a valid native retry.
            d.add_aes(
                &[
                    Range {
                        physical: AES,
                        bytes: aes::BLOCK_BYTES,
                    },
                    Range {
                        physical: 0x23d2dc000,
                        bytes: 0x8000,
                    },
                ],
                j473_aes(),
                None,
                (owner, 1),
                None,
            )
            .unwrap();
            assert_eq!(d.masters[0].stream, 1);
            let _phy = add_usb_phy(&mut d);
            d.add_usb(&usb_placement(), owner).unwrap();
            assert_eq!(d.usb_masters[0].stream, 1);
        }
    }

    #[test]
    fn mounted_dcpext_retained_pm_gates_suppress_real_surface_dma_and_scanout() {
        use crate::platform::apple::dcp::{link, swap};
        struct Screen(Rc<RefCell<usize>>);
        impl Scanout for Screen {
            fn mode(&self) -> ScanoutMode {
                ScanoutMode {
                    width: 1,
                    height: 1,
                    format: ScanoutFormat::Bgra8888,
                }
            }
            fn present(&mut self, rows: &[u8]) -> Result<(), &'static str> {
                assert_eq!(rows, [1, 2, 3, 255]);
                *self.0.borrow_mut() += 1;
                Ok(())
            }
        }
        struct CountMemory {
            ram: Ram,
            reads: usize,
            writes: usize,
        }
        impl Memory for CountMemory {
            fn read(&mut self, address: u64, bytes: &mut [u8]) -> bool {
                self.reads += 1;
                self.ram.read(address, bytes)
            }
            fn write(&mut self, address: u64, bytes: &[u8]) -> bool {
                self.writes += 1;
                self.ram.write(address, bytes)
            }
        }
        const WRAPPER: u64 = 0x2_71c0_0000;
        const DART: u64 = 0x2_7130_c000;
        const RAM: u64 = 0x8_0000_0000;
        const REGION: u64 = RAM + 0x4000;
        const PIXELS: u64 = RAM + 0xd0000;
        const SUPPLY: u64 = 0x2_3b70_0380;
        fn send(d: &mut AppleDevices, endpoint: u64, payload: u64) {
            d.write(0, WRAPPER + 0x8800, 8, payload, 0).unwrap();
            d.write(0, WRAPPER + 0x8808, 8, endpoint, 0).unwrap();
        }
        fn call(
            d: &mut AppleDevices,
            memory: &mut CountMemory,
            tag: &[u8; 4],
            input: &[u8],
            output: u32,
        ) {
            let stream = link::Stream {
                owner: link::Owner::Ap,
                index: 1,
            };
            let header = link::Header {
                tag: *tag,
                input: input.len() as u32,
                output,
            };
            let at = REGION + stream.calls();
            assert!(memory.ram.write(at, &header.bytes()));
            assert!(memory.ram.write(at + 12, input));
            send(
                d,
                0x37,
                link::Word::Rpc(link::Rpc {
                    answer: false,
                    stream,
                    opens: true,
                    offset: 0,
                    length: header.length().unwrap(),
                    token: 0,
                })
                .encode(),
            );
            d.transfer(0, memory, 0).unwrap();
            let reply = mailbox_drain(d, WRAPPER);
            assert_eq!(reply.len(), 1);
            assert_eq!(reply[0].0, 0x37);
        }
        let mut d = AppleDevices::new();
        d.add_aic(0x2_3b0c_0000, 1152, AicLayout::aic2(0x8000, 0))
            .unwrap();
        let dart = d
            .add_dart(
                Range {
                    physical: DART,
                    bytes: 0x4000,
                },
                16,
                None,
                None,
            )
            .unwrap();
        let frames = Rc::new(RefCell::new(0));
        d.add_dcpext(
            Range {
                physical: WRAPPER,
                bytes: 0x6c000,
            },
            [0x243, 0x242, 0x245, 0x244],
            false,
            "DCPEXT",
            dcp::ExternalIdentity::Unnumbered,
            Box::new(Screen(frames.clone())),
            (dart, 5),
            Some(RAM),
            Some((dart, 5)),
            crate::builds::DEFAULT,
        )
        .unwrap();
        connect_native_power(&mut d, SUPPLY, &[("/arm-io/dcpext", WRAPPER)], true);
        d.write(0, DART + 0x1014, 4, 6, 0).unwrap();
        d.write(0, DART + 0xc00, 4, 1 << 5, 0).unwrap();
        assert_eq!(mailbox_drain(&mut d, WRAPPER).len(), 1);
        for payload in [
            2 << 52 | 12 | 12 << 16,
            8 << 52 | 1,
            8 << 52 | 1 << 51 | 1 << 32,
            5 << 52 | 0x37 << 32 | 2,
        ] {
            send(&mut d, 0, payload);
            mailbox_drain(&mut d, WRAPPER);
        }
        let mut memory = CountMemory {
            ram: Ram::new(RAM, 0x100000),
            reads: 0,
            writes: 0,
        };
        assert!(memory.ram.write(REGION + 12, &4u32.to_le_bytes()));
        send(&mut d, 0x37, link::Word::Region { dva: 0x4000 }.encode());
        d.transfer(0, &mut memory, 0).unwrap();
        assert_eq!(mailbox_drain(&mut d, WRAPPER).len(), 1);
        call(&mut d, &mut memory, b"A406", &[0; 0x10], 8);
        assert!(memory.ram.write(PIXELS, &[1, 2, 3, 255]));
        call(
            &mut d,
            &mut memory,
            b"A407",
            &swap::tests::submission(1, &[(0, 1, 1, PIXELS)]),
            0xc,
        );
        for gate in [4, 0x40f, 0] {
            d.write(0, SUPPLY, 4, gate, 0).unwrap();
            let before = (memory.reads, memory.writes);
            d.transfer(0, &mut memory, 0).unwrap();
            assert_eq!((memory.reads, memory.writes), before);
            assert_eq!(*frames.borrow(), 0);
            assert!(
                d.bus
                    .device::<Asc>(d.dcp_masters[0].asc)
                    .unwrap()
                    .firmware::<dcp::Coprocessor>()
                    .unwrap()
                    .frame_pending()
            );
            d.write(0, SUPPLY, 4, 15, 0).unwrap();
        }
        d.transfer(0, &mut memory, 0).unwrap();
        assert_eq!(*frames.borrow(), 1);
        assert!(
            !d.bus
                .device::<Asc>(d.dcp_masters[0].asc)
                .unwrap()
                .firmware::<dcp::Coprocessor>()
                .unwrap()
                .frame_pending()
        );
        d.transfer(0, &mut memory, 0).unwrap();
        assert_eq!(*frames.borrow(), 1);
    }

    #[test]
    fn dcpext_enumerates_its_rtkit_and_the_display_regions_refuse() {
        struct Screen;
        impl Scanout for Screen {
            fn mode(&self) -> ScanoutMode {
                ScanoutMode {
                    width: 1920,
                    height: 1080,
                    format: ScanoutFormat::Bgra8888,
                }
            }
            fn present(&mut self, _rows: &[u8]) -> Result<(), &'static str> {
                Ok(())
            }
        }
        const WRAPPER: u64 = 0x2_71c0_0000;
        const DISPEXT: u64 = 0x2_7000_0000;
        let mut devices = AppleDevices::new();
        devices
            .add_aic(0x2_3b0c_0000, 1152, AicLayout::aic2(0x8000, 0))
            .unwrap();
        let dart = devices
            .add_dart(
                Range {
                    physical: 0x2_7130_c000,
                    bytes: 0x4000,
                },
                16,
                None,
                None,
            )
            .unwrap();
        devices
            .add_dcpext(
                Range {
                    physical: WRAPPER,
                    bytes: 0x6c000,
                },
                [0x242, 0x242, 0x245, 0x244],
                true,
                "DCPEXT",
                dcp::ExternalIdentity::Unnumbered,
                Box::new(Screen),
                (dart, 5),
                Some(0x8_0000_0000),
                None,
                crate::builds::DEFAULT,
            )
            .unwrap();
        devices
            .add_display(&[(
                "dispext0",
                Range {
                    physical: DISPEXT,
                    bytes: 0x61c000,
                },
            )])
            .unwrap();
        // The ASC wrapper runs (RUN bit set by the boot-chain handoff).
        assert_eq!(devices.read(0, WRAPPER + 0x44, 4, 0), Ok(1 << 4));
        assert_eq!(devices.coprocessor_diagnostics().len(), 1);
        // A display register has no modeled meaning and refuses.
        assert!(devices.read(0, DISPEXT, 4, 0).is_err());
    }

    #[test]
    fn energy_banks_route_only_their_described_words() {
        let mut devices = AppleDevices::new();
        let cpm = 0x2_11e4_8000;
        let core = 0x2_1005_9000;
        devices.add_cpu_energy(cpm, true).unwrap();
        devices.add_cpu_energy(core, false).unwrap();
        assert_eq!(devices.read(0, cpm, 8, 0), Ok(0));
        devices
            .write(0, cpm + 8, 8, 0x1234_5678_ffff_0000, 0)
            .unwrap();
        assert_eq!(devices.read(0, cpm + 8, 8, 99), Ok(0x1234_5678_ffff_0000));
        assert_eq!(devices.read(0, core + 8, 8, 99), Ok(0));
        assert_eq!(devices.read(0, cpm + energy::CONTROL_OFFSET, 8, 0), Ok(0));
        devices
            .write(0, cpm + energy::CONTROL_OFFSET, 8, 0xa800_0000_0000_0000, 0)
            .unwrap();
        assert_eq!(
            devices.read(0, cpm + energy::CONTROL_OFFSET, 8, 0),
            Ok(0xa800_0000_0000_0000)
        );
        assert!(devices.read(0, cpm + 16, 8, 0).is_err());
        assert!(
            devices
                .read(0, core + energy::CONTROL_OFFSET, 8, 0)
                .is_err()
        );
    }

    /// A PE's sampler counters are one value through its own MRS and MSR
    /// and through any PE's access to its `cpu-impl-reg` window.
    #[test]
    fn a_pes_sampler_counters_share_its_registers_and_window() {
        let mut devices = AppleDevices::new();
        let layout = core_counters::layout(0x8112).unwrap();
        let blocks = [0x2_1005_0000, 0x2_1015_0000];
        for (cpu, physical) in blocks.into_iter().enumerate() {
            devices.add_core_counters(cpu, physical, layout).unwrap();
        }
        let aon_2 = Encoding::new(3, 7, 15, 4, 3);
        let stall_1 = Encoding::new(3, 1, 15, 9, 3);
        assert_eq!(devices.system_register(1, aon_2, Some(77), 0), Some(Ok(0)));
        // PE 0 samples PE 1's counter remotely; its own is untouched.
        assert_eq!(devices.read(0, blocks[1] + 0x4020, 8, 0), Ok(77));
        assert_eq!(devices.read(0, blocks[0] + 0x4020, 8, 0), Ok(0));
        devices.write(0, blocks[1] + 0x6038, 8, 1 << 47, 0).unwrap();
        assert_eq!(
            devices.system_register(1, stall_1, None, 0),
            Some(Ok(1 << 47))
        );
        assert_eq!(devices.system_register(0, stall_1, None, 0), Some(Ok(0)));
        // A register the T8112 lacks is not the board's.
        let aon_3 = Encoding::new(3, 7, 15, 6, 3);
        assert_eq!(devices.system_register(1, aon_3, None, 0), None);
        assert!(devices.read(0, blocks[1] + 0x4030, 8, 0).is_err());
    }

    #[test]
    fn performance_banks_map_sparse_words_without_claiming_holes() {
        let mut devices = AppleDevices::new();
        let base = 0x2_3d2b_4000;
        devices.add_performance_counters(base, &[2, 7]).unwrap();
        assert_eq!(devices.read(0, base, 4, 0), Ok(0));
        devices.write(0, base, 4, 1, 0).unwrap();
        devices.write(0, base + 0x120, 4, 3, 0).unwrap();
        devices.write(0, base + 0x128, 4, 0x1234, 0).unwrap();
        devices.write(0, base + 0x12c, 4, 0x5678, 0).unwrap();
        assert_eq!(devices.read(0, base + 0x120, 4, 0), Ok(3));
        assert_eq!(devices.read(0, base + 0x128, 4, 0), Ok(0x1234));
        assert_eq!(devices.read(0, base + 0x12c, 4, 0), Ok(0x5678));
        assert!(devices.read(0, base + 0x124, 4, 0).is_err());
        assert!(devices.read(0, base + 0x130, 4, 0).is_err());
        assert!(devices.read(0, base + 0x128, 8, 0).is_err());
    }

    #[test]
    fn aop_masks_route_at_the_bank_plus_eight() {
        let mut devices = AppleDevices::new();
        let base = 0x2_3d00_4008;
        let mut valid = [u32::MAX; wake::WORDS];
        valid[7] = 0x7fff_ffff;
        devices.add_wake_masks(base, valid, None).unwrap();
        for (word, &mask) in valid.iter().enumerate() {
            let physical = base + word as u64 * 4;
            assert_eq!(devices.read(0, physical, 4, 0), Ok(u64::from(mask)));
            devices.write(0, physical, 4, u64::from(mask), 0).unwrap();
            assert_eq!(devices.read(0, physical, 4, 0), Ok(u64::from(mask)));
        }
        assert!(devices.read(0, base - 4, 4, 0).is_err());
        assert!(devices.read(0, base + wake::BYTES, 4, 0).is_err());
    }

    #[derive(Clone, Default)]
    struct Console(Rc<RefCell<Vec<u8>>>);
    impl ConsoleSink for Console {
        fn transmit(&mut self, byte: u8) -> Result<(), ConsoleBusy> {
            self.0.borrow_mut().push(byte);
            Ok(())
        }
    }

    const UART: u64 = 0x2_3520_0000;

    /// XNU's fast-IPI send and acknowledge between T8112 PEs, through the
    /// board's System registers: IPI_RR_GLOBAL_EL1 to cluster 1 CPU 0, then
    /// IPI_SR_EL1 on that PE; other encodings are not the board's.
    #[test]
    fn fast_ipis_raise_and_clear_the_target_pes_fiq() {
        let request = Encoding::new(3, 5, 15, 0, 1);
        let status = Encoding::new(3, 5, 15, 1, 1);
        let mut devices = AppleDevices::new();
        devices.add_fast_ipi(&[0x8000_0000, 0x8000_0001, 0x8000_0100, 0x8000_0101]);
        assert_eq!(
            devices.system_register(0, request, Some(1 << 16), 0),
            Some(Ok(0))
        );
        assert!(devices.lines(2, 0).fiq && !devices.lines(0, 0).fiq);
        assert_eq!(devices.system_register(2, status, None, 0), Some(Ok(1)));
        assert_eq!(devices.system_register(2, status, Some(1), 0), Some(Ok(0)));
        assert!(!devices.lines(2, 0).fiq);
        assert_eq!(
            devices.system_register(0, Encoding::new(3, 5, 15, 2, 0), None, 0),
            None
        );
        assert!(matches!(
            devices.system_register(0, request, Some(1 << 16 | 3 << 28), 0),
            Some(Err(_))
        ));
    }

    #[test]
    fn a_start_bit_releases_its_pe_at_the_locked_rvbar() {
        const START: u64 = 0x2_3b73_4000;
        const ENTRY: u64 = 0x8_0300_c388;
        let mpidrs = [0x8000_0000, 0x8000_0001, 0x8000_0100, 0x8000_0101];
        let mut devices = AppleDevices::new();
        for pe in 0..4 {
            let range = Range {
                physical: 0x2_1005_0000 + 0x10_0000 * pe as u64,
                bytes: 0x9010,
            };
            devices
                .add_lockdown("cpu-impl-reg", 0x5000, range, Some((pe, ENTRY)))
                .unwrap();
        }
        devices.add_cpu_start(START, 2, &mpidrs).unwrap();
        // The kernel's sequence for cluster 1 core 1: its startup bit, then
        // both clusters' start words.
        devices.write(0, START + 4, 4, 1 << 5, 0).unwrap();
        assert_eq!(devices.take_start(), None);
        devices.write(0, START + 8, 4, 0, 0).unwrap();
        devices.write(0, START + 0xc, 4, 1 << 1, 0).unwrap();
        assert_eq!(
            devices.take_start(),
            Some(Start {
                cpu: 3,
                address: 0x8_0300_c000
            })
        );
        assert_eq!(devices.take_start(), None);
        // RVBAR_EL2 reads the same reset address.
        assert_eq!(devices.reset_vector(3), Some(0x8_0300_c000));
        // A core the board does not have refuses.
        assert!(devices.write(0, START + 0xc, 4, 1 << 2, 0).is_err());
    }

    #[test]
    fn processor_startup_words_bind_once_without_legacy_lockdown() {
        const BASE: u64 = 0x2_1005_0000;
        const ENTRY: u64 = 0x100_0300_c000;
        let mut devices = AppleDevices::new();
        let range = Range {
            physical: BASE,
            bytes: 0x9008,
        };
        devices.add_processor_registers(0, range, ENTRY).unwrap();
        assert_eq!(devices.read(0, BASE, 8, 0), Ok(ENTRY | 1));
        assert_eq!(devices.read(0, BASE + lockdown::CPU_STS, 8, 0), Ok(1));
        devices.set_processor_running(0, false);
        assert_eq!(devices.read(0, BASE + lockdown::CPU_STS, 8, 0), Ok(0));
        assert_eq!(devices.locked_reset_vector(0), Some(ENTRY));
        devices
            .write(0, BASE + lockdown::CORE_THRTL_CFG2, 8, 0xb2 << 56, 0)
            .unwrap();
        assert_eq!(
            devices.read(0, BASE + lockdown::CORE_THRTL_CFG2, 8, 0),
            Ok(0xb2 << 56)
        );
        for offset in [0x5000, 0x5008, 0x9000, 0x9008] {
            assert!(devices.bus.route(BASE + offset, Width::Double).is_err());
        }
        assert!(matches!(
            devices.add_processor_registers(0, range, ENTRY),
            Err(MapError::Overlap { .. })
        ));
    }

    #[test]
    fn cpu_status_initially_runs_only_the_selected_handoff_pe() {
        const BASE: u64 = 0x2_1005_0000;
        const ENTRY: u64 = 0x100_0300_c000;
        for legacy in [false, true] {
            let mut devices = AppleDevices::for_boot_processor(2);
            for pe in 0..4 {
                let range = Range {
                    physical: BASE + pe as u64 * 0x10_0000,
                    bytes: 0x9010,
                };
                if legacy {
                    devices
                        .add_lockdown("cpu-impl-reg", 0x5000, range, Some((pe, ENTRY)))
                        .unwrap();
                } else {
                    devices.add_processor_registers(pe, range, ENTRY).unwrap();
                }
                assert_eq!(
                    devices.read(2, range.physical + lockdown::CPU_STS, 8, 0),
                    Ok(u64::from(pe == 2))
                );
                assert_eq!(devices.locked_reset_vector(pe), Some(ENTRY));
            }
            devices.processor_power(2, false);
            assert_eq!(
                devices.read(2, BASE + 0x20_0000 + lockdown::CPU_STS, 8, 0),
                Ok(0)
            );
        }
    }

    #[test]
    fn aic_default_delivery_uses_the_selected_boot_pe_and_keeps_every_pe_served() {
        const AIC: u64 = 0x2_3b0c_0000;
        for (layout, irq_config, event) in [
            (AicLayout::aic2(0x8000, 0), 0x2000, 0x8000),
            (AicLayout::aic3(0x40000, 0), 0x10000, 0x40000),
        ] {
            let mut devices = AppleDevices::for_boot_processor(2);
            devices
                .add_aic_for_processors(AIC, 1152, layout, 4)
                .unwrap();
            let software =
                AIC + irq_config + 4 * u64::from(crate::platform::apple::aic::AIC2_MAX_IRQ);
            devices.write(2, AIC + 0x14, 4, 1, 0).unwrap();
            devices.write(2, software, 4, 1 << 7, 0).unwrap();
            // MASK_CLR follows SW_SET, SW_CLR and MASK_SET, each MAX_IRQ/8 bytes.
            devices.write(2, software + 3 * 512, 4, 1 << 7, 0).unwrap();
            for pe in [0, 1, 3] {
                assert!(!devices.lines(pe, 0).irq);
                assert_eq!(devices.read(pe, AIC + event, 4, 0), Ok(0));
            }
            assert!(devices.lines(2, 0).irq);
            assert_eq!(devices.read(2, AIC + event, 4, 0), Ok(1 << 16 | 7));
            assert!(!devices.lines(2, 0).irq);
        }
        let mut devices = AppleDevices::for_boot_processor(4);
        for cpus in [0, 4, 65] {
            assert!(
                devices
                    .add_aic_for_processors(AIC, 1152, AicLayout::aic2(0x8000, 0), cpus)
                    .is_err()
            );
            assert!(devices.aic.is_none());
            assert!(devices.bus.route(AIC, Width::Word).is_err());
        }
        devices
            .add_aic_for_processors(AIC, 1152, AicLayout::aic2(0x8000, 0), 5)
            .unwrap();
    }

    #[test]
    fn processor_startup_word_installation_is_atomic_for_every_conflict() {
        const BASE: u64 = 0x2_1005_0000;
        let range = Range {
            physical: BASE,
            bytes: 0x9008,
        };
        for conflict in lockdown::PE_WORDS {
            let mut devices = AppleDevices::new();
            let foreign = devices.bus.add(Box::new(CheckedPowerBank {
                reject: true,
                committed: Vec::new(),
            }));
            devices.bus.map(foreign, BASE + conflict, 8, 0).unwrap();
            assert!(
                devices
                    .add_processor_registers(2, range, 0x100_0300_c000)
                    .is_err()
            );
            assert!(devices.reset_vectors.is_empty());
            assert_eq!(
                devices.bus.route(BASE + conflict, Width::Double),
                Ok((foreign, 0))
            );
            for offset in lockdown::PE_WORDS
                .into_iter()
                .filter(|offset| *offset != conflict)
            {
                assert!(devices.bus.route(BASE + offset, Width::Double).is_err());
            }
        }
        let mut devices = AppleDevices::new();
        for bad in [
            Range {
                physical: BASE + 1,
                bytes: 0x9008,
            },
            Range {
                physical: BASE,
                bytes: lockdown::CORE_THRTL_CFG2 + 4,
            },
            Range {
                physical: u64::MAX - 7,
                bytes: 0x9008,
            },
        ] {
            assert!(
                devices
                    .add_processor_registers(0, bad, 0x100_0300_c000)
                    .is_err()
            );
            assert!(devices.reset_vectors.is_empty());
            assert!(devices.bus.route(BASE, Width::Double).is_err());
        }
    }

    #[test]
    fn lockdown_maps_only_its_registers_beside_the_energy_accumulators() {
        // J473AP cpu0's `cpu-impl-reg` and cluster 0's `cpm-impl-reg`, with
        // their accumulators at +0x9000 and +0x8000.
        let (cpu, cpm) = (0x2_1005_0000, 0x2_10e4_0000);
        let mut devices = AppleDevices::new();
        for (name, physical, control, reset) in [
            ("cpu-impl-reg", cpu, 0x5000, Some((0, 0x8_0300_c388))),
            ("cpm-impl-reg", cpm, 0x9000, None),
        ] {
            let range = Range {
                physical,
                bytes: 0x9010,
            };
            devices.add_lockdown(name, control, range, reset).unwrap();
        }
        devices
            .add_cpu_energy(cpu + energy::CORE_OFFSET, false)
            .unwrap();
        devices.add_cpu_energy(cpm + 0x8000, true).unwrap();
        assert_eq!(devices.read(0, cpu, 8, 0), Ok(0x8_0300_c001));
        assert_eq!(devices.read(0, cpu + 0x5008, 8, 0), Ok(0));
        assert_eq!(devices.read(0, cpm + 0x9000, 8, 0), Ok(0));
        assert_eq!(devices.read(0, cpu + 0x9008, 8, 0), Ok(0));
        // The boot PE runs: XNU's cpu_exit_wait polls CPU_STS until 0, which
        // the PE's power-down gives it.
        assert_ne!(devices.read(0, cpu + lockdown::CPU_STS, 8, 0), Ok(0));
        devices.processor_power(0, false);
        assert_eq!(devices.read(0, cpu + lockdown::CPU_STS, 8, 0), Ok(0));
        assert_eq!(
            devices.read(0, cpu + lockdown::CORE_THRTL_CFG2, 8, 0),
            Ok(0)
        );
        // The rest of each block reaches no model.
        assert!(devices.read(0, cpu + 0x108, 8, 0).is_err());
        assert!(devices.read(0, cpm, 8, 0).is_err());
        assert!(devices.read(0, cpm + lockdown::CPU_STS, 8, 0).is_err());
    }

    #[test]
    fn routes_the_console_and_refuses_unmapped_and_unknown_registers() {
        let console = Console::default();
        let mut devices = AppleDevices::new();
        devices
            .add_uart(
                console.clone(),
                &[Range {
                    physical: UART,
                    bytes: 0x4000,
                }],
                None,
            )
            .unwrap();
        // UTRSTAT reports an empty transmitter; UTXH sends one byte.
        assert_eq!(devices.read(0, UART + 0x10, 4, 0).unwrap() & 6, 6);
        for byte in *b"ok" {
            devices
                .write(0, UART + 0x20, 4, u64::from(byte), 0)
                .unwrap();
        }
        assert_eq!(console.0.borrow().as_slice(), b"ok");
        assert_eq!(
            devices.read(0, 0x2_0000_0000, 4, 0),
            Err(DeviceError::NoDevice)
        );
        assert!(matches!(
            devices.read(0, UART + 0x3c, 4, 0),
            Err(DeviceError::Refused(reason)) if reason.contains("UVER")
        ));
        assert!(!devices.lines(0, 0).irq);
        assert_eq!(devices.take_reset(), None);
    }

    #[test]
    fn places_an_aic2_with_derived_counts_and_routes_uart_wires_to_it() {
        let mut devices = AppleDevices::new();
        devices
            .add_uart(
                Console::default(),
                &[Range {
                    physical: UART,
                    bytes: 0x4000,
                }],
                Some(AicInput::new(0, 739)),
            )
            .unwrap();
        devices
            .add_aic(0x2_3b0c_0000, 1152, AicLayout::aic2(0x8000, 16))
            .unwrap();
        // CAP0 (offset 4) reports NR_IRQ in bits 15:0.
        assert_eq!(devices.read(0, 0x2_3b0c_0004, 4, 0).unwrap() & 0xffff, 1152);
        assert!(
            devices
                .add_aic(0x2_3b0c_0000, 1152, AicLayout::aic2(0x10, 16))
                .is_err()
        );
    }

    /// J274AP (M1): `aic,1` at 0x2_3b10_0000 with 896 inputs, the UART on 605.
    #[test]
    fn places_an_aic1_and_routes_uart_wires_to_it() {
        const AIC: u64 = 0x2_3b10_0000;
        let mut devices = AppleDevices::new();
        devices
            .add_uart(
                Console::default(),
                &[Range {
                    physical: UART,
                    bytes: 0x4000,
                }],
                Some(AicInput::new(0, 605)),
            )
            .unwrap();
        devices.add_aic(AIC, 896, AicLayout::V1).unwrap();
        // INFO (offset 4) reports NR_IRQ in bits 15:0, and WHOAMI cpu0.
        assert_eq!(devices.read(0, AIC + 0x4, 4, 0).unwrap() & 0xffff, 896);
        assert_eq!(devices.read(0, AIC + 0x2000, 4, 0).unwrap(), 0);
        // Target the UART line at cpu0 and unmask it.
        devices.write(0, AIC + 0x3000 + 4 * 605, 4, 1, 0).unwrap();
        devices
            .write(0, AIC + 0x4180 + 4 * (605 / 32), 4, 1 << (605 % 32), 0)
            .unwrap();
        // XNU `apple_uart_enable_irq`: with the TX trigger at 0 and UCON's
        // TX threshold interrupt enabled, sending a byte raises input 605.
        let ufcon = devices.read(0, UART + 0x8, 4, 0).unwrap();
        devices
            .write(0, UART + 0x8, 4, ufcon & !(0b11 << 6), 0)
            .unwrap();
        let ucon = devices.read(0, UART + 0x4, 4, 0).unwrap();
        devices.write(0, UART + 0x4, 4, ucon | 1 << 13, 0).unwrap();
        assert!(!devices.lines(0, 0).irq);
        devices
            .write(0, UART + 0x20, 4, u64::from(b'x'), 0)
            .unwrap();
        assert!(devices.lines(0, 0).irq);
        assert_eq!(
            devices.read(0, AIC + AIC1_EVENT, 4, 0).unwrap(),
            1 << 16 | 605
        );
        assert!(!devices.lines(0, 0).irq, "the event read masked the IRQ");
        assert!(matches!(
            devices.read(0, AIC + 0x5008, 4, 0),
            Err(DeviceError::Refused(reason)) if reason.contains("per-CPU")
        ));
    }

    /// The AES engine's DMA runs in the write that starts it, through its
    /// DART stream: here a bypassed one, ECB with the FIPS-197 C.1 key.
    #[test]
    fn aes_writes_move_data_through_the_dart_stream() {
        use crate::platform::dma::tests::Ram;
        const DART: u64 = 0x2_3500_4000;
        const AES: u64 = 0x2_3500_c000;
        const RAM: u64 = 0x8_0000_0000;
        let mut devices = AppleDevices::new();
        let dart = devices
            .add_dart(
                Range {
                    physical: DART,
                    bytes: 0x4000,
                },
                16,
                None,
                None,
            )
            .unwrap();
        let ranges = [
            Range {
                physical: AES,
                bytes: 0x4000,
            },
            Range {
                physical: 0x2_3d2d_c000,
                bytes: 0x8000,
            },
        ];
        devices
            .add_aes(&ranges, j473_aes(), None, (dart, 1), None)
            .unwrap();
        let mut ram = Ram::new(RAM, 0x1000);
        let plain: Vec<u8> = (0..16).map(|byte| byte * 0x11).collect();
        assert!(Memory::write(&mut ram, RAM, &plain));
        // Stream 1 enabled and bypassed: TCR BYPASS_DART | BYPASS_DAPF.
        for (offset, value) in [(0xc00, 0b10), (0x1004, 0b110)] {
            devices.write(0, DART + offset, 4, value, 0).unwrap();
        }
        let key: Vec<u64> = (0..4)
            .map(|word| u64::from(0x0302_0100_u32 + 0x0404_0404 * word))
            .collect();
        let command =
            [0x1010_0000]
                .into_iter()
                .chain(key)
                .chain([0x5000_0010, 0x0008_0008, 0, 0x100]);
        devices.write(0, AES + 0x8, 4, 1, 0).unwrap();
        for word in command {
            devices.write(0, AES + 0x200, 4, word, 0).unwrap();
            devices.transfer(0, &mut ram, 0).unwrap();
        }
        let mut out = [0; 16];
        assert!(Memory::read(&mut ram, RAM + 0x100, &mut out));
        assert_eq!(
            out,
            [
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
                0xc5, 0x5a
            ]
        );
        // The FIFO drained: EMPTY with LEVEL 0.
        assert_eq!(devices.read(0, AES + 0x24, 4, 0).unwrap() & 0xff02, 0b10);
    }

    /// A J773g-shaped version 5 engine owns its DKey range third; its key
    /// words follow the ADT offsets.
    #[test]
    fn version_5_aes_places_its_dkey_range_after_the_key_disable_words() {
        const DART: u64 = 0x1_ad00_4000;
        const AES: u64 = 0x1_ad00_c000;
        const DISABLE: u64 = 0x1_882d_c000;
        const DKEY: u64 = 0x1_8807_8000;
        let mut devices = AppleDevices::new();
        let dart = devices
            .add_dart(
                Range {
                    physical: DART,
                    bytes: 0x4000,
                },
                16,
                None,
                None,
            )
            .unwrap();
        let config = aes::Config {
            version: 5,
            address_width: 42,
            key_disable: aes::KeyDisable {
                bytes: 0x8000,
                word: 0,
                keys: [Some(0x40), Some(0x44), Some(0x48)],
            },
        };
        let ranges = [(AES, 0x4000), (DISABLE, 0x8000), (DKEY, 0x4000)]
            .map(|(physical, bytes)| Range { physical, bytes });
        assert!(
            devices
                .add_aes(&ranges[..2], config, None, (dart, 1), None)
                .unwrap_err()
                .contains("has 3 register ranges, not 2")
        );
        devices
            .add_aes(&ranges, config, None, (dart, 1), None)
            .unwrap();
        assert_eq!(devices.read(0, DISABLE, 4, 0).unwrap(), 0xf);
        assert_eq!(devices.read(0, DISABLE + 0x40, 4, 0).unwrap(), 0);
        assert!(devices.write(0, DKEY + 4, 4, 1, 0).is_err());
    }
    #[test]
    fn sep_native_nonzero_routes_read_actual_firmware_and_preflight_owner_capacity() {
        use crate::platform::apple::sep::message::{Frame, ROM};
        const DART: u64 = 0x25d2c0000;
        const SEP: u64 = 0x25e400000;
        const AUX: u64 = 0x25e050000;
        const RAM: u64 = 0x800000000;
        let ranges = [
            Range {
                physical: SEP,
                bytes: 0x6c000,
            },
            Range {
                physical: AUX,
                bytes: 0x60000,
            },
        ];
        let add = |d: &mut AppleDevices, owner, input| {
            d.add_sep(
                ranges,
                asc::Lines::default(),
                (owner, input),
                Box::new(|b: &mut [u8]| {
                    b.fill(0xa5);
                    Ok(())
                }),
                SepProvisioning {
                    security: None,
                    ecid: 0xa5a5_0006,
                    observe: false,
                    state: sep::state::Location::Volatile,
                },
            )
        };
        for (profile, input, context) in
            [(dart::Profile::T8110, 4, 4), (dart::Profile::T6000, 5, 4)]
        {
            let mut unrelated = AppleDevices::new();
            let absent = unrelated
                .add_dart(
                    Range {
                        physical: DART,
                        bytes: 0x4000,
                    },
                    16,
                    None,
                    None,
                )
                .unwrap();
            let mut d = AppleDevices::new();
            assert!(
                add(&mut d, absent, input)
                    .unwrap_err()
                    .contains("not a mounted DART")
            );
            d.add_aic(0x23b100000, 16, AicLayout::V1).unwrap();
            let (Controller::V1(id) | Controller::V2(id)) = d.aic.unwrap();
            let foreign = DartId(id);
            assert!(
                add(&mut d, foreign, input)
                    .unwrap_err()
                    .contains("not a mounted DART")
            );
            let owner = d
                .add_dart_group_for_profile(
                    profile,
                    &[Range {
                        physical: DART,
                        bytes: 0x4000,
                    }],
                    16,
                    None,
                    None,
                )
                .unwrap()[0];
            assert!(add(&mut d, owner, 16).unwrap_err().contains("capacity"));
            assert!(
                add(&mut d, owner, usize::MAX)
                    .unwrap_err()
                    .contains("capacity")
            );
            assert!(d.sep_masters.is_empty());
            assert!(d.read(0, SEP + 0x8114, 4, 0).is_err());
            add(&mut d, owner, input).unwrap();
            assert_eq!(d.sep_masters[0].stream, input);
            d.write(0, SEP + 0x8114, 4, 1, 0).unwrap();
            let regs = if profile == dart::Profile::T8110 {
                [
                    (0xc00, 1u64 << context),
                    (0x1000 + 4 * context, 6),
                    (0x80, 0),
                ]
            } else {
                // Source5 -> context4, all other sources identity. Only
                // context4 is enabled/bypassed; retain input5 independently.
                [
                    (0xfc, 1u64 << context),
                    (0x100 + 4 * context, 1 << 8),
                    (0x84, 0x07060404),
                ]
            };
            for (offset, value) in regs {
                if profile == dart::Profile::T6000 || offset != 0x80 {
                    d.write(0, DART + offset, 4, value, 0).unwrap();
                }
            }
            let send = |d: &mut AppleDevices, ram: &mut Ram, opcode, data| {
                let frame = Frame {
                    service: ROM,
                    tag: 1,
                    opcode,
                    parameter: 0,
                    data,
                };
                d.write(0, SEP + 0x8800, 8, frame.mailbox().payload, 0)
                    .unwrap();
                d.write(0, SEP + 0x8808, 8, 0, 0).unwrap();
                d.transfer(0, ram, 0).unwrap();
                let reply = Frame::from_payload(d.read(0, SEP + 0x8830, 8, 0).unwrap());
                d.read(0, SEP + 0x8838, 8, 0).unwrap();
                reply
            };
            let mut ram = Ram::new(RAM, 0x8000);
            let image = crate::img4::tests::im4p(b"sepi", b"stela-sepos");
            ram.bytes[..image.len()].copy_from_slice(&image);
            assert_eq!(send(&mut d, &mut ram, 5, 0).opcode, 105);
            assert_eq!(send(&mut d, &mut ram, 6, (RAM >> 12) as u32).opcode, 106);
        }
    }

    #[test]
    fn sep_rom_accepts_firmware_under_stela_policy_and_reaches_os_active() {
        use crate::platform::{
            apple::sep::message::{self, Frame, ROM},
            dma::tests::Ram,
        };
        const DART: u64 = 0x25d2c0000;
        const SEP: u64 = 0x25e400000;
        const AUX: u64 = 0x25e050000;
        const RAM: u64 = 0x800000000;

        // Build a SEP mapped on dart-sep stream 0, with its outbox enabled.
        fn board() -> AppleDevices {
            let mut devices = AppleDevices::new();
            let dart = devices
                .add_dart(
                    Range {
                        physical: DART,
                        bytes: 0x4000,
                    },
                    1,
                    None,
                    None,
                )
                .unwrap();
            devices
                .add_sep(
                    [
                        Range {
                            physical: SEP,
                            bytes: 0x6c000,
                        },
                        Range {
                            physical: AUX,
                            bytes: 0x60000,
                        },
                    ],
                    asc::Lines::default(),
                    (dart, 0),
                    Box::new(|b: &mut [u8]| {
                        b.fill(0xa5);
                        Ok(())
                    }),
                    SepProvisioning {
                        security: None,
                        ecid: 0xa5a5_0006,
                        observe: false,
                        state: sep::state::Location::Volatile,
                    },
                )
                .unwrap();
            devices.write(0, SEP + 0x8114, 4, 1, 0).unwrap(); // enable outbox
            devices
        }

        fn send(
            devices: &mut AppleDevices,
            ram: &mut Ram,
            frame: Frame,
        ) -> Result<(), DeviceError> {
            devices
                .write(0, SEP + 0x8800, 8, frame.mailbox().payload, 0)
                .unwrap();
            let written = devices.write(0, SEP + 0x8808, 8, 0, 0);
            written.and_then(|()| devices.transfer(0, ram, 0))
        }

        fn recv(devices: &mut AppleDevices) -> Frame {
            let payload = devices.read(0, SEP + 0x8830, 8, 0).unwrap();
            devices.read(0, SEP + 0x8838, 8, 0).unwrap();
            Frame::from_payload(payload)
        }

        // The real IPSW SEP payload is a bare encrypted `sepi`; Stela accepts
        // it under its own policy and boots its native sepOS.
        let image = crate::img4::tests::im4p(b"sepi", b"stela-sepos");
        let mut devices = board();
        let mut ram = Ram::new(RAM, 0x8000);
        ram.bytes[..image.len()].copy_from_slice(&image);
        // Map the delivered container into the SEP's dart-sep stream.
        devices.write(0, DART + 0xc00, 4, 1, 0).unwrap();
        devices.write(0, DART + 0x1000, 4, 6, 0).unwrap(); // TCR BYPASS_DART|BYPASS_DAPF

        send(
            &mut devices,
            &mut ram,
            Frame {
                service: ROM,
                tag: 1,
                opcode: 5,
                parameter: 0,
                data: 0,
            },
        )
        .unwrap();
        assert_eq!(recv(&mut devices).opcode, 105, "BootTz0 ack");
        send(
            &mut devices,
            &mut ram,
            Frame {
                service: ROM,
                tag: 1,
                opcode: 6,
                parameter: 0,
                data: (RAM >> 12) as u32,
            },
        )
        .unwrap();
        assert_eq!(recv(&mut devices).opcode, 106, "SEP accepted IMG4");
        // The AP maps a real, separate directory through dart-sep. This
        // fixture advertises no channels, so its first entry is the required
        // terminator. OS active follows successful directory DMA.
        ram.bytes[0x4000..0x4004].copy_from_slice(&u32::from_be_bytes(*b"null").to_le_bytes());
        send(
            &mut devices,
            &mut ram,
            Frame {
                service: message::BOOT,
                tag: 0,
                opcode: 4,
                parameter: 0,
                data: ((RAM + 0x4000) >> 12) as u32,
            },
        )
        .unwrap();
        let active = recv(&mut devices);
        assert_eq!((active.service, active.tag, active.opcode), (0, 0, 21));

        // A malformed container refuses with no boot acknowledgement.
        let mut devices = board();
        let mut ram = Ram::new(RAM, 0x8000);
        ram.bytes[..8].copy_from_slice(b"\x30\x06\x16\x04IM4P");
        devices.write(0, DART + 0xc00, 4, 1, 0).unwrap();
        devices.write(0, DART + 0x1000, 4, 6, 0).unwrap(); // TCR BYPASS_DART|BYPASS_DAPF
        send(
            &mut devices,
            &mut ram,
            Frame {
                service: ROM,
                tag: 1,
                opcode: 5,
                parameter: 0,
                data: 0,
            },
        )
        .unwrap();
        recv(&mut devices);
        let refusal = send(
            &mut devices,
            &mut ram,
            Frame {
                service: ROM,
                tag: 1,
                opcode: 6,
                parameter: 0,
                data: (RAM >> 12) as u32,
            },
        );
        assert!(
            matches!(refusal, Err(DeviceError::TransferRefused(reason)) if reason.contains("payload type is malformed"))
        );
    }
    fn usb_placement() -> super::super::soc::UsbController {
        const BASE: u64 = 0x382280000;
        super::super::soc::UsbController {
            ranges: [
                (BASE, 0x11800),
                (0x382200000, 0x4000),
                (BASE + 0xc000, 0x5800),
                (0x382a84000, 0x4000),
                (0x382800000, 0x4000),
                (0x382a80000, 0x4000),
                (0x382000000, 0x4000),
                (0x382080000, 0x4000),
                (BASE + 0xd000, 0x4000),
            ],
            irqs: [1031, 1032, 1033, 1034, 990],
            iommu: 0,
            phandle: Some(0xa5),
            mapper: 0xa4,
            mapper_context: 1,
            stream: 1,
            port: 1,
            retention: false,
            phy: 0xa2,
        }
    }

    fn add_usb_phy(d: &mut AppleDevices) -> super::super::soc::TypecPhy {
        let placement = super::super::soc::TypecPhy {
            phandle: 0xa2,
            port: 1,
            retention: true,
            views: Vec::new(),
            usb2: (0x382a90000, atc_phy::WINDOW_BYTES),
            core: (0x383000000, atc_phy::CORE_BYTES),
            pipe: Some((0x382a84000, atc_phy::WINDOW_BYTES)),
            events: (0x382800000, atc_phy::WINDOW_BYTES),
        };
        d.add_atc_phy(&placement).unwrap();
        placement
    }

    fn release_usb_phy(d: &mut AppleDevices, phy: &super::super::soc::TypecPhy) {
        // Actual USB2 RUN, reset/SIDDQ release, core supply/reset release,
        // and pipehandler controller RESET_N without clamp.
        for (address, value) in [
            (phy.usb2.0, 2),
            (phy.usb2.0 + 4, 4),
            (phy.core.0 + 0x20000, 3 | 8 | 16),
            (phy.core.0 + 0x20008, 1),
            (phy.pipe.unwrap().0 + 0x1c, 1),
        ] {
            d.write(0, address, 4, value, 0).unwrap();
        }
    }

    #[test]
    fn mounted_usb_dma_service_failure_is_protected_from_survey_substitution() {
        let mut d = AppleDevices::new();
        let dart = d
            .add_dart(
                Range {
                    physical: 0x382f00000,
                    bytes: 0x4000,
                },
                16,
                None,
                None,
            )
            .unwrap();
        let phy = add_usb_phy(&mut d);
        let placement = usb_placement();
        d.add_usb(&placement, dart).unwrap();
        release_usb_phy(&mut d, &phy);
        let base = placement.ranges[0].0;
        let table = 0x800008000u64;
        let events = 0x800009000u64;
        let mut ram = Ram::new(0x800000000, 0x10000);
        ram.put_u64(table, events);
        ram.put_u64(table + 8, 16);
        d.write(0, base + 0x468, 4, 1, 0).unwrap();
        d.write(0, base + 0x470, 4, table as u32 as u64, 0).unwrap();
        d.write(0, base + 0x474, 4, table >> 32, 0).unwrap();
        // The actual placed stream is still disabled. Loading this real
        // event segment table must fail through DART, never survey-success.
        for now in [0, 10] {
            let error = d.transfer(0, &mut ram, now).unwrap_err();
            assert!(
                matches!(error, DeviceError::TransferRefused(ref reason) if reason.starts_with("USB device advance:"))
            );
        }
        let mut untouched = [0; 16];
        assert!(ram.read(events, &mut untouched));
        assert_eq!(untouched, [0; 16]);
    }

    #[test]
    fn actual_phy_clock_and_retained_supply_freeze_usb_time_while_quiesce_does_not() {
        use super::super::soc::{PowerResource, PowerStates};
        use coverage::{Domain, DomainId};
        let mut d = AppleDevices::new();
        let dart = d
            .add_dart(
                Range {
                    physical: 0x382f00000,
                    bytes: 0x4000,
                },
                16,
                None,
                None,
            )
            .unwrap();
        let phy = add_usb_phy(&mut d);
        let placement = usb_placement();
        d.add_usb(&placement, dart).unwrap();
        release_usb_phy(&mut d, &phy);
        let supply = 0x23d280100;
        let id = DomainId { die: 0, device: 1 };
        let states = PowerStates {
            implicit: Vec::new(),
            registers: vec![supply],
            blocks: vec![(supply, 4)],
            domains: vec![Domain {
                name: String::new(),
                id,
                address: Some(supply),
                parents: [None; 4],
            }],
            resources: vec![PowerResource {
                clock_role: crate::machine::soc::ClockRole::Consumer,
                name: "/arm-io/atc-phy0".into(),
                clocks: vec![id],
                power: vec![],
                owner: Some(PowerOwner::Phy(0)),
                admission: coverage::Admission::Required,
            }],
        };
        d.add_power_states(
            &[Range {
                physical: supply,
                bytes: 4,
            }],
            &states.registers,
        )
        .unwrap();
        d.connect_power_resources(&states, &[vec![dart]], &[false])
            .unwrap();
        let base = placement.ranges[0].0;
        d.write(0, base + 0x20, 4, 1, 0).unwrap();
        assert_eq!(d.read(0, base + 0x440, 4, 15_000), Ok(5));
        d.write(0, supply, 4, 4, 15_000).unwrap();
        d.write(0, base + 0x20, 4, 1, 800_000).unwrap();
        assert!(d.read(0, phy.usb2.0, 4, 900_000).is_err());
        assert_eq!(d.read(0, base + 0x440, 4, 900_000), Ok(5));
        d.write(0, supply, 4, 15, 900_000).unwrap();
        d.write(0, supply, 4, 0x40f, 900_000).unwrap();
        assert_eq!(d.read(0, base + 0x440, 4, 915_000), Ok(10));
        assert!(
            !d.bus
                .device::<Dwc3>(d.usb_masters[0].device)
                .unwrap()
                .lifecycle_active()
        );
        d.write(0, supply, 4, 15, 915_000).unwrap();
        d.write(0, supply, 4, 0, 915_000).unwrap();
        assert_eq!(d.read(0, base + 0x440, 4, 1_915_000), Ok(10));
        d.write(0, supply, 4, 15, 1_915_000).unwrap();
        assert_eq!(d.read(0, base + 0x440, 4, 1_930_000), Ok(15));
    }

    #[test]
    fn phy_phandles_distinguish_standalone_views_on_the_same_connector() {
        let mut devices = AppleDevices::new();
        let first = add_usb_phy(&mut devices);
        let mut auxiliary = first.clone();
        auxiliary.phandle += 1;
        auxiliary.pipe = None;
        // Original 26A434 J414s/J416s/J474s have four ATC PHYs: PHY3
        // repeats port 1, but no USB DRD names its distinct phandle.
        const OTHER_APERTURE: u64 = 0x1_0000_0000;
        auxiliary.usb2.0 += OTHER_APERTURE;
        auxiliary.core.0 += OTHER_APERTURE;
        auxiliary.events.0 += OTHER_APERTURE;
        devices.add_atc_phy(&auxiliary).unwrap();
        assert_eq!(devices.phys.len(), 2);
        assert!(
            devices
                .add_atc_phy(&auxiliary)
                .unwrap_err()
                .contains("phandle")
        );
        assert_eq!(devices.phys.len(), 2);
        let dart = devices
            .add_dart(
                Range {
                    physical: 0x382f00000,
                    bytes: 0x4000,
                },
                16,
                None,
                None,
            )
            .unwrap();
        let mut placement = usb_placement();
        placement.phy = auxiliary.phandle;
        assert!(
            devices
                .add_usb(&placement, dart)
                .unwrap_err()
                .contains("pipehandler")
        );
        placement.phy = first.phandle;
        devices.add_usb(&placement, dart).unwrap();
        assert_eq!(devices.usb_masters[0].phy, devices.phys[0].device);
    }

    #[test]
    fn usb_requires_actual_phy_binding_and_retained_phy_pauses_preserve_sessions() {
        use super::super::soc::{PowerResource, PowerStates};
        use coverage::{Domain, DomainId};
        let mut d = AppleDevices::new();
        let base_dart = 0x382f00000;
        let dart = d
            .add_dart(
                Range {
                    physical: base_dart,
                    bytes: 0x4000,
                },
                16,
                None,
                None,
            )
            .unwrap();
        let placement = usb_placement();
        assert!(
            d.add_usb(&placement, dart)
                .unwrap_err()
                .contains("no placed PHY")
        );
        let phy = add_usb_phy(&mut d);
        // An unbound PHY with no physical reset aperture is a supported
        // standalone topology, but cannot silently hold a USB core forever.
        let saved_pipe = d.phys[0].pipe.take();
        assert!(
            d.add_usb(&placement, dart)
                .unwrap_err()
                .contains("pipehandler")
        );
        d.phys[0].pipe = saved_pipe;
        d.add_usb(&placement, dart).unwrap();
        let base = placement.ranges[0].0;
        assert!(d.read(0, base + 0xc704, 4, 0).is_err());
        release_usb_phy(&mut d, &phy);
        let supply = 0x23d280100;
        let id = DomainId { die: 0, device: 1 };
        let states = PowerStates {
            implicit: Vec::new(),
            registers: vec![supply],
            blocks: vec![(supply, 4)],
            domains: vec![Domain {
                name: String::new(),
                id,
                address: Some(supply),
                parents: [None; 4],
            }],
            resources: vec![PowerResource {
                clock_role: crate::machine::soc::ClockRole::Consumer,
                name: "/arm-io/atc-phy0".into(),
                clocks: vec![id],
                power: vec![],
                owner: Some(PowerOwner::Phy(0)),
                admission: coverage::Admission::Required,
            }],
        };
        d.add_power_states(
            &[Range {
                physical: supply,
                bytes: 4,
            }],
            &states.registers,
        )
        .unwrap();
        d.connect_power_resources(&states, &[vec![dart]], &[false])
            .unwrap();
        assert!(d.power_refusals().is_empty());
        d.write(0, base_dart + 0xc00, 4, 2, 0).unwrap();
        d.write(0, base_dart + 0x1004, 4, 6, 0).unwrap();
        let cable = typec::Attached {
            orientation: typec::Orientation::Normal,
            role: typec::DataRole::Ufp,
            source: false,
            vbus: true,
            speed: typec::Usb2Speed::High,
        };
        d.set_connection(1, Some(cable)).unwrap();
        d.write(0, base + 0xc704, 4, 1 << 31, 0).unwrap();
        let mut ram = Ram::new(0x800000000, 0x10000);
        d.transfer(0, &mut ram, 0).unwrap();
        assert_eq!(d.usb_masters[0].epoch, 1);
        for (tick, value) in [(10, 4), (40, 0), (70, 0x40f)] {
            // clock gate, retained off, quiesce
            d.write(0, supply, 4, value, tick).unwrap();
            d.transfer(0, &mut ram, tick + 10).unwrap();
            assert!(d.usb_masters[0].attached);
            assert_eq!(d.usb_masters[0].epoch, 1);
            assert_eq!(d.read(0, base + 0xc704, 4, tick + 10), Ok(1 << 31));
            d.write(0, supply, 4, 15, tick + 20).unwrap();
            d.transfer(0, &mut ram, tick + 20).unwrap();
        }
        // A rapid electrical isolate/release must still cancel the old
        // native session even when final-ready is true at service time.
        d.write(0, phy.usb2.0, 4, 2 | 4, 100).unwrap();
        d.write(0, phy.usb2.0, 4, 2, 100).unwrap();
        d.transfer(0, &mut ram, 100).unwrap();
        assert_eq!(d.usb_masters[0].epoch, 2);
        assert_eq!(d.typec_port(1).snapshot().connection, Some(cable));
        // PHY PMGR reset reaches the actual pipehandler/controller bank.
        for value in [0x40f, 0x8000040f, 0x40f, 15] {
            d.write(0, supply, 4, value, 110).unwrap();
        }
        assert!(d.read(0, base + 0xc704, 4, 110).is_err());
        d.transfer(0, &mut ram, 110).unwrap();
        assert!(!d.usb_masters[0].attached);
        release_usb_phy(&mut d, &phy);
        assert_eq!(d.read(0, base + 0xc704, 4, 110), Ok(0));
        d.write(0, base + 0xc704, 4, 1 << 31, 120).unwrap();
        d.transfer(0, &mut ram, 120).unwrap();
        assert_eq!(d.usb_masters[0].epoch, 3);
    }

    #[test]
    fn pmgr_shared_usb_leaf_pauses_both_clients_and_cancels_sessions_only_on_reset_or_detach() {
        use super::super::soc::{PowerResource, PowerStates};
        use coverage::{Domain, DomainId};
        let id = |device| DomainId { die: 0, device };
        let mut d = AppleDevices::new();
        d.add_aic(0x3b0c0000, 1100, AicLayout::aic2(0x8000, 0))
            .unwrap();
        let dart_base = 0x382f00000;
        let dart = d
            .add_dart(
                Range {
                    physical: dart_base,
                    bytes: 0x4000,
                },
                16,
                None,
                None,
            )
            .unwrap();
        let phy = add_usb_phy(&mut d);
        let placement = usb_placement();
        let usb = d.add_usb(&placement, dart).unwrap();
        release_usb_phy(&mut d, &phy);
        let base = placement.ranges[0].0;
        let supply = 0x23d280098;
        let states = PowerStates {
            implicit: Vec::new(),
            registers: vec![supply, supply + 8],
            blocks: vec![(supply, 12)],
            domains: vec![
                Domain {
                    name: String::new(),
                    id: id(0x210),
                    address: None,
                    parents: [Some(id(0x108)), None, None, None],
                },
                Domain {
                    name: String::new(),
                    id: id(0x108),
                    address: Some(supply),
                    parents: [Some(id(2)), None, None, None],
                },
                Domain {
                    name: String::new(),
                    id: id(2),
                    address: Some(supply + 8),
                    parents: [None; 4],
                },
            ],
            resources: vec![
                PowerResource {
                    clock_role: crate::machine::soc::ClockRole::Consumer,
                    name: "dart-usb0".into(),
                    clocks: vec![id(0x210)],
                    power: vec![],
                    owner: Some(PowerOwner::Dart(0)),
                    admission: coverage::Admission::Required,
                },
                PowerResource {
                    clock_role: crate::machine::soc::ClockRole::Consumer,
                    name: "usb-drd0".into(),
                    clocks: vec![id(0x108)],
                    power: vec![],
                    owner: Some(PowerOwner::Usb(0)),
                    admission: coverage::Admission::Required,
                },
                PowerResource {
                    clock_role: crate::machine::soc::ClockRole::Consumer,
                    name: "usb-drd0/port-hs".into(),
                    clocks: vec![id(0x108)],
                    power: vec![],
                    owner: Some(PowerOwner::Usb(0)),
                    admission: coverage::Admission::Required,
                },
                PowerResource {
                    clock_role: crate::machine::soc::ClockRole::Consumer,
                    name: "acio0".into(),
                    clocks: vec![id(2)],
                    power: vec![],
                    owner: None,
                    admission: coverage::Admission::Required,
                },
                PowerResource {
                    clock_role: crate::machine::soc::ClockRole::Consumer,
                    name: "atc-phy0".into(),
                    clocks: vec![],
                    power: vec![],
                    owner: Some(PowerOwner::Phy(0)),
                    admission: coverage::Admission::Required,
                },
            ],
        };
        d.add_power_states(
            &[Range {
                physical: supply,
                bytes: 12,
            }],
            &states.registers,
        )
        .unwrap();
        d.connect_power_resources(&states, &[vec![dart]], &[false])
            .unwrap();
        assert_eq!(d.power_refusals().len(), 1);
        assert!(d.write(0, supply + 8, 4, 0, 0).is_err());
        let host = typec::Attached {
            orientation: typec::Orientation::Normal,
            role: typec::DataRole::Ufp,
            source: false,
            vbus: true,
            speed: typec::Usb2Speed::High,
        };
        d.set_connection(1, Some(host)).unwrap();
        let restore_dart = |d: &mut AppleDevices| {
            d.write(0, dart_base + 0xc00, 4, 2, 0).unwrap();
            d.write(0, dart_base + 0x1004, 4, 6, 0).unwrap();
        };
        restore_dart(&mut d);
        d.write(0, base + 0xc704, 4, 1 << 31, 0).unwrap(); // DCTL RUN
        let mut ram = Ram::new(0x800000000, 0x10000);
        d.transfer(0, &mut ram, 0).unwrap();
        assert!(d.usb_masters[0].attached);
        assert_eq!(d.usb_masters[0].epoch, 1);
        d.write(0, supply, 4, 4, 10).unwrap();
        assert!(d.read(0, base + 0xc704, 4, 10).is_err());
        assert!(d.read(0, dart_base + 0x1004, 4, 10).is_err());
        assert_eq!(d.dma_deadline(), None);
        d.transfer(0, &mut ram, 20).unwrap();
        assert!(d.usb_masters[0].attached);
        assert_eq!(d.usb_masters[0].epoch, 1);
        d.write(0, supply, 4, 15, 30).unwrap();
        d.transfer(0, &mut ram, 30).unwrap();
        assert_eq!(d.usb_masters[0].epoch, 1);
        for value in [0x40f, 0x8000040f, 0x40f, 15] {
            d.write(0, supply, 4, value, 40).unwrap();
        }
        assert_eq!(d.typec_port(1).snapshot().connection, Some(host));
        restore_dart(&mut d);
        d.transfer(0, &mut ram, 50).unwrap();
        assert!(!d.usb_masters[0].attached);
        assert_eq!(d.read(0, base + 0xc704, 4, 50), Ok(0));
        d.write(0, base + 0xc704, 4, 1 << 31, 60).unwrap();
        d.transfer(0, &mut ram, 60).unwrap();
        assert!(d.usb_masters[0].attached);
        assert_eq!(d.usb_masters[0].epoch, 2);
        // Cable removal cancels the connection even while the clock is off.
        d.write(0, supply, 4, 4, 70).unwrap();
        d.set_connection(1, None).unwrap();
        d.transfer(0, &mut ram, 70).unwrap();
        assert!(!d.usb_masters[0].attached);
        d.set_connection(1, Some(host)).unwrap();
        d.transfer(0, &mut ram, 80).unwrap();
        d.write(0, supply, 4, 15, 90).unwrap();
        d.transfer(0, &mut ram, 90).unwrap();
        assert!(d.usb_masters[0].attached);
        assert_eq!(d.usb_masters[0].epoch, 3);
        assert_eq!(
            d.usb_client(usb).unwrap().mux_state(),
            MuxState::Negotiating
        );
    }

    #[test]
    fn usb_core_aliases_platform_refusals_and_port_driven_polling() {
        const BASE: u64 = 0x382280000;
        let mut devices = AppleDevices::new();
        let dart = devices
            .add_dart(
                Range {
                    physical: 0x382f00000,
                    bytes: 0x4000,
                },
                16,
                Some(AicInput::new(0, 1035)),
                None,
            )
            .unwrap();
        let phy = add_usb_phy(&mut devices);
        let placement = usb_placement();
        let id = devices.add_usb(&placement, dart).unwrap();
        release_usb_phy(&mut devices, &phy);
        assert_eq!(devices.read(0, BASE + 0xc120, 4, 0), Ok(0x5533_300a));
        devices
            .write(0, placement.ranges[2].0 + 0x700, 4, 5 << 3, 0)
            .unwrap();
        assert_eq!(devices.read(0, BASE + 0xc700, 4, 0), Ok(5 << 3));
        // DRD_USB31_CFG's RAM status and the power block's request are
        // modeled; the other platform words refuse.
        for index in [1, 5] {
            assert_eq!(devices.read(0, placement.ranges[index].0, 4, 0), Ok(0));
        }
        for index in [6, 7, 8] {
            assert!(matches!(
                devices.read(0, placement.ranges[index].0, 4, 0),
                Err(DeviceError::Refused(_))
            ));
        }
        // The pipehandler and core event block are the actual ATC PHY's.
        assert_eq!(devices.read(0, placement.ranges[3].0 + 0x1c, 4, 0), Ok(1));
        assert_eq!(devices.read(0, placement.ranges[4].0, 4, 0), Ok(0));
        devices.transfer(0, &mut Ram::new(0, 0x1000), 0).unwrap();
        assert_eq!(devices.dma_deadline(), None);
        let host = typec::Attached {
            orientation: typec::Orientation::Normal,
            role: typec::DataRole::Ufp,
            source: false,
            vbus: true,
            speed: typec::Usb2Speed::High,
        };
        devices.set_connection(1, Some(host)).unwrap();
        assert_eq!(devices.dma_deadline(), Some(0));
        let mut ram = crate::platform::dma::tests::Ram::new(0x800000000, 0x10000);
        devices.transfer(0, &mut ram, 0).unwrap();
        assert_eq!(devices.dma_deadline(), Some(USB_POLL_TICKS));
        assert!(devices.usb_client(id).unwrap().open(62078).is_err());
        // Without VBUS the controller is not ready; the change detaches.
        let unpowered = typec::Attached {
            vbus: false,
            ..host
        };
        devices.set_connection(1, Some(unpowered)).unwrap();
        assert_eq!(devices.dma_deadline(), Some(0));
        devices.transfer(0, &mut ram, USB_POLL_TICKS).unwrap();
        assert_eq!(devices.dma_deadline(), None);
    }
}
