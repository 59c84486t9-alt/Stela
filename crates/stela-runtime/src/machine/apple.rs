//! The Apple T8112 device models (`platform::apple`) as the engine's
//! [`Devices`]: one [`Bus`] for the guest physical address space, an
//! [`InterruptLatch`] for the wires, AIC input forwarding and reset requests.
//! The models own every register decision; this adapter only routes accesses
//! and time, and turns each `MmioError` into an explicit refusal.
use super::{
    engine::{DeviceError, Devices, Memory, Start},
    registers::Lines,
};
use crate::platform::apple::{
    aes::{self, Aes},
    aic::{Aic2, Aic2Config},
    aic1::Aic1,
    amcc::{self, Amcc},
    ans::Ans,
    asc::{self, Asc},
    atc_phy::{self, AtcPhy},
    bridge::Bridge,
    bus::{Access, Bus, DeviceId, MapError, MmioError, Width},
    cluster::{self, Cluster},
    coresight::{self, SoftwareLock},
    cpm::Cpm,
    cpustart::{self, CpuStart},
    dart::{self, Dart},
    dcs::Dcs,
    dpe::Dpe,
    dwc3::{self, Dwc3, PortState},
    energy::{self, Energy},
    fuse::{self, AonFuses},
    gpio::{Gpio, Net},
    hpm::{Firmware, Hpm, Summary},
    i2c::{self, I2c},
    interrupt::{CpuIndex, InterruptLatch},
    ipi::{self, Affinity, FastIpi},
    lockdown::{self, Lockdown},
    perf::PerfCounters,
    pmgr::{ACTIVE, POWER_GATED, Pmgr, PowerState},
    power::{self, Power},
    ptd::{self, Ptd},
    rtkit::{Management, RtKit},
    sart::{self, Sart},
    sep::{self, Sep},
    spi::Spi,
    uart::S5lUart,
    wake::{self, WakeMasks},
    wdt::{self, AppleWdt},
};
use crate::platform::dma::Port;
use crate::platform::usb::{
    Function,
    hid::{Input, Peripheral},
    session::Session as UsbSession,
};
pub use crate::platform::usb::{
    host::{Descriptor as UsbDescriptor, MuxEndpoints},
    mux::{State as MuxState, StreamId as MuxStream, StreamState as MuxStreamState},
    session::Log as UsbLog,
};
use crate::system::access::{AccessKind, Encoding};
use alloc::{boxed::Box, format, string::String, vec::Vec};

pub use crate::platform::apple::{
    aic::{AIC2_IRQ_CFG, AIC3_IRQ_CFG, AicLayout},
    aic1::AIC1_EVENT,
    asc::Lines as AscLines,
    interrupt::AicInput,
    nor,
    sep::Entropy as SepEntropy,
    sep::image::signature::{
        Evidence as SepSignatureEvidence, ManifestEvidence as SepManifestEvidence,
        inspect as inspect_sep_signature, verify_manifest as verify_sep_manifest_signature,
    },
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
    reset: Option<String>,
    memory_controller: Option<DeviceId>,
    ipi: Option<FastIpi>,
    masters: Vec<Master>,
    storage_wrappers: Vec<DeviceId>,
    storage_masters: Vec<(DeviceId, DeviceId)>,
    sep_masters: Vec<SepMaster>,
    usb_masters: Vec<UsbMaster>,
    cpu_start: Option<CpuStarter>,
    reset_vectors: Vec<Option<DeviceId>>,
    starts: Vec<Start>,
    selects: Vec<SelectWire>,
    /// The AP GPIO bank's base and the board nets on its input pins.
    gpio: Option<(u64, Vec<(u32, Net)>)>,
    typec_ports: Vec<(u32, typec::Port)>,
    pmgr: Option<DeviceId>,
    dart_power: Vec<DartPower>,
}

const USB_POLL_TICKS: u64 = 24_000_000 / 8000;
/// A native host handle, owned by this AppleDevices instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbId(DeviceId);
struct UsbMaster {
    device: DeviceId,
    dart: DeviceId,
    stream: usize,
    session: UsbSession,
    port: UsbPort,
    /// The Type-C connector's `port-number` and shared cable state.
    number: u32,
    connector: typec::Port,
    /// The input peripheral cabled to the connector when this port is the
    /// downstream-facing (host) side.
    peripheral: Option<Peripheral>,
    next_poll: u64,
    attached: bool,
    epoch: u64,
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
struct DartPower {
    device: DeviceId,
    domains: Vec<u64>,
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
    /// The board's devices; PE numbers are the DeviceTree's cpu numbers, 0
    /// being the running cpu0.
    pub fn new() -> Self {
        Self {
            bus: Bus::new(),
            latch: InterruptLatch::new(),
            aic: None,
            reset: None,
            memory_controller: None,
            ipi: None,
            masters: Vec::new(),
            storage_masters: Vec::new(),
            storage_wrappers: Vec::new(),
            sep_masters: Vec::new(),
            usb_masters: Vec::new(),
            cpu_start: None,
            reset_vectors: Vec::new(),
            starts: Vec::new(),
            selects: Vec::new(),
            gpio: None,
            typec_ports: Vec::new(),
            pmgr: None,
            dart_power: Vec::new(),
        }
    }

    /// State of native storage coprocessors, without register side effects.
    pub fn storage_diagnostics(&self) -> Vec<String> {
        self.storage_wrappers
            .iter()
            .map(|&id| {
                self.bus
                    .device::<Asc>(id)
                    .expect("storage wrapper")
                    .diagnostic()
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
        let gpio = Gpio::new(bank.pins, lines, selects, nets.clone()).map_err(String::from)?;
        let id = self.bus.add(Box::new(gpio));
        self.bus
            .map(id, bank.physical, bank.bytes, 0)
            .map_err(|e| format!("GPIO placement: {e:?}"))?;
        self.gpio = Some((bank.physical, nets));
        Ok(())
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

    /// Installs the DT-derived SPI controller, one in-memory NOR die and
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
    ) -> Result<(), MapError> {
        let device = self.bus.add(Box::new(S5lUart::new(console, irq)));
        self.map(device, ranges)
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

    /// The lockdown registers of a CPU implementation block named `name`,
    /// with CONTROL at `control`, at `range`; a PE's `cpu-impl-reg` also
    /// holds that PE's RVBAR, which the boot firmware locked on `reset`.
    /// Only those registers are mapped: the block also holds the PE's or
    /// cluster's energy accumulators (`platform::apple::energy`).
    pub fn add_lockdown(
        &mut self,
        name: &'static str,
        control: u64,
        range: Range,
        reset: Option<(usize, u64)>,
    ) -> Result<(), MapError> {
        let mut model = Lockdown::new(name, control);
        if let Some((_, entry)) = reset {
            model = model.with_reset_vector(entry);
        }
        let device = self.bus.add(Box::new(model));
        if let Some((pe, _)) = reset {
            if self.reset_vectors.len() <= pe {
                self.reset_vectors.resize(pe + 1, None);
            }
            self.reset_vectors[pe] = Some(device);
        }
        // The board checked that CONTROL and MASK lie inside the block.
        self.bus
            .map(device, range.physical + control, lockdown::BYTES, control)?;
        if reset.is_some() {
            self.bus
                .map(device, range.physical, lockdown::RVBAR_BYTES, 0)?;
        }
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
        let device = self.bus.add(Box::new(CpuStart::new(clusters)));
        self.bus
            .map(device, physical, cpustart::bytes(clusters), 0)
            .map_err(|error| format!("CPU start placement: {error:?}"))?;
        self.cpu_start = Some(CpuStarter {
            device,
            mpidrs: mpidrs.to_vec(),
        });
        Ok(())
    }

    /// Turn the cores the CPU start registers released into PE starts.
    fn release_cores(&mut self) -> Result<(), DeviceError> {
        let Some(starter) = &self.cpu_start else {
            return Ok(());
        };
        let released = self
            .bus
            .device_mut::<CpuStart>(starter.device)
            .expect("the CPU start id names its model")
            .take();
        for core in released {
            let affinity = u64::from(core.cluster) << 8 | u64::from(core.core);
            let cpu = starter
                .mpidrs
                .iter()
                .position(|&mpidr| mpidr & 0xffff == affinity)
                .ok_or_else(|| {
                    DeviceError::Refused(format!(
                        "CPU start of cluster {} core {}, which the board does not have",
                        core.cluster, core.core
                    ))
                })?;
            let address = self
                .reset_vectors
                .get(cpu)
                .copied()
                .flatten()
                .and_then(|block| self.bus.device::<Lockdown>(block)?.reset_address())
                .ok_or_else(|| {
                    DeviceError::Refused(format!("CPU start of PE {cpu}, which has no RVBAR"))
                })?;
            self.starts.push(Start { cpu, address });
        }
        Ok(())
    }

    /// The AMCC's lock registers at each aperture of `layout`, with the
    /// CTRR-A region iBoot programmed (`[base, base + bytes)`), and the
    /// memory cache's registers when the board shows its `cache`.
    pub fn add_memory_controller(
        &mut self,
        apertures: &[u64],
        layout: amcc::Layout,
        programmed: Option<(u64, u64)>,
        cache: Option<amcc::Cache>,
    ) -> Result<(), String> {
        let model = Amcc::new(layout, apertures.len(), programmed, cache).map_err(String::from)?;
        let device = self.bus.add(Box::new(model));
        let ranges: alloc::vec::Vec<Range> = apertures
            .iter()
            .map(|&physical| Range {
                physical,
                bytes: layout.aperture_bytes,
            })
            .collect();
        self.map(device, &ranges)
            .map_err(|error| format!("AMCC placement: {error:?}"))?;
        self.memory_controller = Some(device);
        Ok(())
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
        let stride = range.bytes / channels.max(1) as u64;
        let model = Dcs::new(channels, stride).map_err(String::from)?;
        let device = self.bus.add(Box::new(model));
        self.map(device, &[range])
            .map_err(|error| format!("DCS placement: {error:?}"))?;
        let model = Ptd::new(ranges).map_err(String::from)?;
        let device = self.bus.add(Box::new(model));
        self.bus
            .map(device, ptd, ptd::PTD_BYTES, 0)
            .map_err(|error| format!("PTD placement: {error:?}"))
    }

    /// Place an explicitly described ANS2, its started RTKit management
    /// coprocessor and SART. Split the shared NVMe bank around SART's idle
    /// word so each physical byte has one owner. The boot chain's choice is
    /// to start the native RTKit service before handing off to SPTM.
    pub fn add_ans(
        &mut self,
        placement: &super::soc::AnsController,
        backing: Box<dyn crate::platform::pc::block::BlockDevice>,
    ) -> Result<(), String> {
        let irq = |n| AicInput::new(0, n);
        let rtkit = RtKit::new(Vec::new(), Management::Ordinary).map_err(String::from)?;
        let wrapper = Asc::booted(
            Box::new(rtkit),
            AscLines::from_interrupts(placement.interrupts.map(irq)),
        )
        .map_err(String::from)?;
        let controller = Ans::new(
            backing,
            &placement.namespaces,
            Some(irq(placement.completion_irq)),
        )
        .map_err(String::from)?;
        let asc = self.bus.add(Box::new(wrapper));
        self.storage_wrappers.push(asc);
        self.bus
            .map(asc, placement.wrapper.0, placement.wrapper.1, 0)
            .map_err(|e| format!("ANS ASC placement: {e:?}"))?;
        let sart = self.bus.add(Box::new(Sart::default()));
        self.bus
            .map(sart, placement.sart.0, placement.sart.1, 0)
            .map_err(|e| format!("SART placement: {e:?}"))?;
        self.bus
            .map(sart, placement.sart_idle, 4, sart::IDLE)
            .map_err(|e| format!("SART idle placement: {e:?}"))?;
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
        self.storage_masters.push((ans, sart));
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
            let name = format!(
                "USB-C_{}.bin",
                target.firmware.as_deref().ok_or("HPM names no firmware")?
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
            .map_err(|e| format!("I2C placement: {e:?}"))
    }

    /// Place canonical PHY regions once. ADT aliases inside the core resolve
    /// by physical address; no length concatenation or duplicate storage.
    pub fn add_atc_phy(&mut self, placement: &super::soc::TypecPhy) -> Result<(), MapError> {
        let id = self.bus.add(Box::new(AtcPhy::new()));
        for ((physical, bytes), offset) in [
            (placement.usb2, atc_phy::USB2),
            (placement.core, 0),
            (placement.pipe, atc_phy::PIPE),
            (placement.events, atc_phy::EVENTS),
        ] {
            self.bus.map(id, physical, bytes, offset)?;
        }
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
        let mut ids = Vec::new();
        for (index, (mut dart, range)) in Dart::group(streams, irq, ranges.len())
            .into_iter()
            .zip(ranges)
            .enumerate()
        {
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

    /// A `dart,t8110` of `streams` streams at `range`.
    pub fn add_dart(
        &mut self,
        range: Range,
        streams: usize,
        irq: Option<AicInput>,
        apf: Option<(u64, usize)>,
    ) -> Result<DartId, MapError> {
        let mut model = Dart::new(streams, irq);
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
    ) -> Result<(), String> {
        if wrapper.bytes < asc::WRAPPER_BYTES || auxiliary.bytes == 0 {
            return Err("SEP register apertures are incomplete".into());
        }
        if stream != 0 {
            return Err("SEP requires dart-sep stream zero".into());
        }
        let device = self
            .bus
            .add(Box::new(Sep::new(entropy, lines).map_err(String::from)?));
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
        let connector = self.typec_port(placement.port);
        let irqs = core::array::from_fn(|n| AicInput::new(0, placement.irqs[n] as u16));
        let device = self.bus.add(Box::new(Dwc3::new(irqs)));
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
    /// Cables the native keyboard and pointer to Type-C connector
    /// `connector`, this machine being the downstream-facing port that
    /// sources VBUS: the HPM reports the attach and the controller's host
    /// personality finds a full-speed device on its USB2 port.
    pub fn attach_input(&mut self, connector: u32) -> Result<(), &'static str> {
        let master = self
            .usb_masters
            .iter_mut()
            .find(|master| master.number == connector)
            .ok_or("no USB controller on that connector")?;
        master.peripheral = Some(Peripheral::new());
        master.connector.set_connection(Some(typec::Attached {
            orientation: typec::Orientation::Normal,
            role: typec::DataRole::Dfp,
            source: true,
            vbus: true,
            speed: typec::Usb2Speed::Full,
        }))?;
        Ok(())
    }

    /// One host input change for the attached peripheral.
    pub fn input(&mut self, input: Input) -> Result<(), &'static str> {
        self.usb_masters
            .iter_mut()
            .find_map(|master| master.peripheral.as_mut())
            .ok_or("no input peripheral is attached")?
            .input(input)
    }

    pub fn usb_client(&mut self, id: UsbId) -> Result<UsbClient<'_>, &'static str> {
        let master = self
            .usb_masters
            .iter_mut()
            .find(|master| master.device == id.0)
            .ok_or("unknown USB controller")?;
        Ok(UsbClient(&mut master.session))
    }
    pub fn take_usb_log(&mut self) -> Option<UsbLog> {
        self.usb_masters
            .iter_mut()
            .find_map(|master| master.session.take_log())
    }

    /// An `aes,s8000` of `aes-version` `version` at its block and
    /// key-disable ranges, whose DMA goes through `stream` of `dart` and
    /// whose UID1 key is `uid`, if the board has one.
    pub fn add_aes(
        &mut self,
        [block, key_disable]: [Range; 2],
        version: u32,
        irq: Option<AicInput>,
        (dart, stream): (DartId, usize),
        uid: Option<[u8; 32]>,
    ) -> Result<(), String> {
        if block.bytes != aes::BLOCK_BYTES {
            return Err(format!(
                "AES block registers span {:#x} bytes, not the modeled {:#x}",
                block.bytes,
                aes::BLOCK_BYTES
            ));
        }
        let device = self.bus.add(Box::new(Aes::new(version, irq, uid)));
        self.map(device, &[block, key_disable])
            .map_err(|error| format!("AES placement: {error:?}"))?;
        self.masters.push(Master {
            aes: device,
            dart: dart.0,
            stream,
        });
        Ok(())
    }

    /// The PMGR power-state registers at `registers`, in `blocks` of guest
    /// PA. The boot firmware's states are not handed off, so each starts
    /// active.
    pub fn add_power_states(&mut self, blocks: &[Range], registers: &[u64]) -> Result<(), String> {
        let states = registers.iter().map(|&address| PowerState {
            address,
            initial: ACTIVE,
        });
        let model = Pmgr::new(states).map_err(|error| format!("PMGR states: {error:?}"))?;
        let device = self.bus.add(Box::new(model));
        for block in blocks {
            // The model's offsets are guest PAs.
            self.bus
                .map(device, block.physical, block.bytes, block.physical)
                .map_err(|error| format!("PMGR placement: {error:?}"))?;
        }
        self.pmgr = Some(device);
        Ok(())
    }

    /// Connect a DART to the translated PMGR supplies its DT names. Empty
    /// supply lists require no PMGR. Every supplied address must be modeled.
    pub fn connect_dart_power(
        &mut self,
        dart: DartId,
        domains: &[u64],
        retention: bool,
    ) -> Result<(), String> {
        if domains.is_empty() {
            return Ok(());
        }
        let pmgr = self
            .pmgr
            .and_then(|id| self.bus.device::<Pmgr>(id))
            .ok_or("DART supplies have no PMGR")?;
        if domains.iter().any(|&address| pmgr.state(address).is_none()) {
            return Err("DART names an undescribed PMGR supply".into());
        }
        if self.bus.device::<Dart>(dart.0).is_none()
            || self.dart_power.iter().any(|p| p.device == dart.0)
        {
            return Err("DART supply binding is duplicate or not a DART".into());
        }
        self.dart_power.push(DartPower {
            device: dart.0,
            domains: domains.to_vec(),
            retention,
        });
        Ok(())
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
        let offsets = model.offsets();
        let device = self.bus.add(Box::new(model));
        for o in offsets {
            self.bus
                .map(
                    device,
                    physical.checked_add(o).ok_or("bridge address overflows")?,
                    4,
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

    /// The eight active-low AOP wake masks at the board's `reg` bank +8.
    pub fn add_wake_masks(
        &mut self,
        physical: u64,
        valid: [u32; wake::WORDS],
    ) -> Result<(), String> {
        let device = self.bus.add(Box::new(WakeMasks::new(valid)));
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
    ) -> Result<(), MapError> {
        let Some(side) = side else {
            return self.add_watchdog(&[range], irq, now);
        };
        let device = self
            .bus
            .add(Box::new(AppleWdt::new(irq, now).with_side_controls()));
        self.map(device, &[range])?;
        let offsets = [
            wdt::PANIC_SAVE,
            wdt::MECHANISM,
            wdt::CONFIGURATION,
            wdt::POWER_OFF,
        ];
        for (&physical, offset) in side.words.iter().zip(offsets) {
            self.bus.map(device, physical, 4, offset)?;
        }
        for &(physical, mask, _) in &side.triggers {
            let trigger = self.bus.add(Box::new(wdt::CoreTrigger::new(mask)));
            self.bus.map(trigger, physical, 4, 0)?;
        }
        Ok(())
    }

    /// The AIC at `physical`, serving this PE. NR_IRQ is the number of
    /// inputs the board wires (one more than the highest DeviceTree
    /// `interrupts` value under the AIC), which the model reports in its INFO
    /// or CAP0 register (m1n1 `aic.c`, Linux `irq-apple-aic.c`). An AICv2's
    /// MAX_IRQ rounds it up to a whole 32-bit mask word and its `layout`
    /// says where its per-die arrays and event register are; an AICv1's are
    /// fixed.
    pub fn add_aic(&mut self, physical: u64, nr_irq: u16, layout: AicLayout) -> Result<(), String> {
        let (device, span) = match layout {
            AicLayout::V1 => {
                let aic = Aic1::new(nr_irq, 1)
                    .map_err(|error| format!("AIC1 configuration: {error:?}"))?;
                let device = self.bus.add(Box::new(aic));
                (Controller::V1(device), Aic1::span())
            }
            AicLayout::V2 {
                version,
                irq_config,
                max_irq,
                event,
                timestamps,
            } => {
                let config = Aic2Config {
                    version,
                    timestamps: usize::from(timestamps),
                    nr_irq,
                    max_irq: max_irq.unwrap_or(nr_irq.div_ceil(32) * 32),
                    irq_config,
                    event_offset: event,
                    cpus: 1,
                    default_cpus: 1,
                    target_groups: [None; 4],
                };
                let aic =
                    Aic2::new(config).map_err(|error| format!("AIC2 configuration: {error:?}"))?;
                let span = aic.span();
                let device = self.bus.add(Box::new(aic));
                (Controller::V2(device), span)
            }
        };
        self.aic = Some(device);
        let (Controller::V1(id) | Controller::V2(id)) = device;
        self.bus
            .map(id, physical, span, 0)
            .map_err(|error| format!("AIC placement: {error:?}"))
    }

    /// Forward queued device wires into the AIC and record a reset request;
    /// `cpu` is the PE whose access or time step queued them.
    fn settle(
        &mut self,
        cpu: CpuIndex,
        now: u64,
        reset: Option<String>,
    ) -> Result<(), DeviceError> {
        if self.reset.is_none() {
            self.reset = reset;
        }
        for link in &self.dart_power {
            let pmgr = self
                .bus
                .device::<Pmgr>(self.pmgr.expect("binding checked PMGR"))
                .expect("PMGR type");
            let powered = link
                .domains
                .iter()
                .all(|&a| pmgr.state(a) != Some(POWER_GATED));
            let mut access = Access::new(cpu, now, &mut self.latch);
            self.bus
                .device_mut::<Dart>(link.device)
                .expect("binding checked DART")
                .set_power(powered, link.retention, &mut access);
        }
        self.release_cores()?;
        loop {
            let inputs = self.latch.take_aic_inputs();
            if inputs.is_empty() {
                return Ok(());
            }
            let Some(aic) = self.aic else {
                return Err(DeviceError::Refused(format!(
                    "AIC input {:?} changed but no AIC model is mapped",
                    inputs[0].0
                )));
            };
            let mut access = Access::new(cpu, now, &mut self.latch);
            for (input, level) in inputs {
                let result = match aic {
                    Controller::V1(id) => self
                        .bus
                        .device_mut::<Aic1>(id)
                        .expect("the AIC id names an Aic1")
                        .set_input(input, level, &mut access)
                        .map_err(|error| format!("{error:?}")),
                    Controller::V2(id) => self
                        .bus
                        .device_mut::<Aic2>(id)
                        .expect("the AIC id names an Aic2")
                        .set_input(input, level, &mut access)
                        .map_err(|error| format!("{error:?}")),
                };
                result.map_err(|error| DeviceError::Refused(format!("AIC input: {error}")))?;
            }
        }
    }
}

fn width(bytes: u8) -> Result<Width, DeviceError> {
    Width::from_bytes(u64::from(bytes))
        .ok_or_else(|| DeviceError::Refused(format!("{bytes}-byte device access")))
}

fn reset_reason(access: &Access<'_>) -> Option<String> {
    access.reset_request().map(|request| {
        format!(
            "{}: {} at counter {}",
            request.device, request.reason, request.at
        )
    })
}

impl Devices for AppleDevices {
    fn read(&mut self, cpu: usize, physical: u64, bytes: u8, now: u64) -> Result<u64, DeviceError> {
        let width = width(bytes)?;
        let mut access = Access::new(cpu, now, &mut self.latch);
        let value = self
            .bus
            .read(physical, width, &mut access)
            .map_err(describe)?;
        let reset = reset_reason(&access);
        self.settle(cpu, now, reset)?;
        Ok(value)
    }

    fn write(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
    ) -> Result<(), DeviceError> {
        let width = width(bytes)?;
        // Validate the NOR CS edge before the GPIO word changes. This keeps
        // an incomplete-command refusal atomic across the two devices.
        for wire in self
            .selects
            .iter()
            .filter(|w| w.physical == physical && width == Width::Word)
        {
            let high = Gpio::driven_level(value as u32)
                .ok_or_else(|| DeviceError::Refused("SPI CS must remain a GPIO output".into()))?;
            self.bus
                .device::<Spi>(wire.spi)
                .expect("SPI wire")
                .check_cs(high)
                .map_err(|e| DeviceError::Refused(e.into()))?;
        }
        let mut access = Access::new(cpu, now, &mut self.latch);
        self.bus
            .write(physical, width, value, &mut access)
            .map_err(describe)?;
        for wire in self.selects.iter().filter(|w| w.physical == physical) {
            self.bus
                .device_mut::<Spi>(wire.spi)
                .expect("SPI wire")
                .set_cs(value & 1 != 0)
                .map_err(|e| DeviceError::Refused(e.into()))?;
        }
        let reset = reset_reason(&access);
        self.settle(cpu, now, reset)
    }

    fn system_register(
        &mut self,
        cpu: usize,
        encoding: Encoding,
        write: Option<u64>,
        now: u64,
    ) -> Option<Result<u64, &'static str>> {
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

    fn lines(&mut self, cpu: usize, now: u64) -> Lines {
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
            self.reset = Some(format!("device advance refused: {error:?}"));
        }
        let pins = self.latch.pins(cpu);
        Lines {
            irq: pins.irq,
            fiq: pins.fiq,
        }
    }

    fn deadline(&mut self, now: u64) -> Option<u64> {
        // Time-driven state is the board's, not a PE's: the access names
        // cpu0.
        let deferred = self
            .ipi
            .as_mut()
            .and_then(|ipi| ipi.advance(now, &mut self.latch));
        let mut access = Access::new(0, now, &mut self.latch);
        let device = self.bus.advance(&mut access).ok().flatten();
        let usb = self
            .usb_masters
            .iter()
            .filter(|master| master.port.ready || master.attached)
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

    fn take_reset(&mut self) -> Option<String> {
        self.reset.take()
    }

    fn take_start(&mut self) -> Option<Start> {
        (!self.starts.is_empty()).then(|| self.starts.remove(0))
    }

    fn memory_lock(&self) -> Option<(u64, u64)> {
        let device = self.memory_controller?;
        self.bus.device::<Amcc>(device)?.locked_region()
    }

    fn dma_deadline(&self) -> Option<u64> {
        self.usb_masters
            .iter()
            .filter_map(|master| {
                let port = UsbPort::of(&master.connector);
                let controller = self.bus.device::<Dwc3>(master.device);
                if port != master.port || controller.is_some_and(Dwc3::host_pending) {
                    return Some(0);
                }
                let poll = (port.ready || master.attached).then_some(master.next_poll);
                let function = master.peripheral.as_ref().map(|p| p as &dyn Function);
                let host = controller.and_then(|c| c.host_deadline(function));
                poll.into_iter().chain(host).min()
            })
            .min()
    }

    fn transfer(
        &mut self,
        cpu: usize,
        memory: &mut dyn Memory,
        now: u64,
    ) -> Result<(), DeviceError> {
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
            if !ans.pending() {
                continue;
            }
            let mut access = Access::new(cpu, now, &mut self.latch);
            let mut port = Port {
                iommu: sart,
                stream: 0,
                memory,
                access: &mut access,
            };
            ans.run(&mut port)
                .map_err(|error| match describe_transfer(error) {
                    DeviceError::TransferRefused(reason) => DeviceError::TransferRefused(format!(
                        "{reason}; ANS last submission {:02x?}",
                        ans.last_submission()
                    )),
                    other => other,
                })?;
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
            sep.transfer(&mut port).map_err(describe)?;
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
            let fail = |why: &str| DeviceError::Refused(format!("USB device advance: {why}"));
            let connector = UsbPort::of(&master.connector);
            if connector != master.port {
                // A new cable generation cancels the previous connection's work.
                master.session.detach().map_err(fail)?;
                master.attached = false;
                master.port = connector;
                master.next_poll = 0;
            }
            controller.sync_port(&master.port).map_err(fail)?;
            controller
                .attach_host_function(host_function(&master.connector))
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
                master
                    .session
                    .advance(&mut controller.peer(&mut port), now)
                    .map_err(fail)?;
                controller.flush(&mut port).map_err(fail)?;
            }
        }
        self.settle(cpu, now, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{rc::Rc, vec::Vec};
    use core::cell::RefCell;

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

    #[test]
    fn pmgr_power_gates_reset_dart_tables_but_clock_gates_and_retention_preserve_them() {
        for retention in [false, true] {
            let mut d = AppleDevices::new();
            let supply = 0x2_3b70_0100;
            let base = 0x2_3500_4000;
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
            d.connect_dart_power(dart, &[supply], retention).unwrap();
            d.write(0, base + 0x1000, 4, 1, 0).unwrap();
            d.write(0, supply, 4, 4, 0).unwrap();
            assert_eq!(d.read(0, base + 0x1000, 4, 0), Ok(1));
            d.write(0, supply, 4, 0, 0).unwrap();
            assert!(d.read(0, base + 0x1000, 4, 0).is_err());
            d.write(0, supply, 4, 15, 0).unwrap();
            assert_eq!(d.read(0, base + 0x1000, 4, 0), Ok(u64::from(retention)));
            assert!(d.connect_dart_power(dart, &[supply + 4], false).is_err());
        }
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
            physical: GPIO,
            bytes: 0x1000,
            pins: 213,
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
        use crate::platform::dma::tests::Ram;
        use crate::platform::{
            apple::{ans, sart},
            pc::block::tests::RamDisk,
        };
        const NVME: u64 = 0x2_7bcc_0000;
        const SART: u64 = 0x2_7bc5_0000;
        const WRAPPER: u64 = 0x2_7740_0000;
        const RAM: u64 = 0x8_0000_0000;
        let placement = AnsController {
            wrapper: (WRAPPER, 0x6c000),
            nvme: (NVME, 0x60000),
            sart: (SART, 0xc000),
            sart_idle: NVME + 0x13e8,
            interrupts: [718, 717, 720, 719],
            completion_irq: 724,
            namespaces: alloc::vec![ans::Description {
                id: 1,
                kind: 1,
                blocks: 0
            }],
            clock_gates: alloc::vec![125],
            power_gates: alloc::vec![125],
        };
        let mut devices = AppleDevices::new();
        devices
            .add_aic(0x2_3b0c_0000, 1152, AicLayout::aic2(0x8000, 0))
            .unwrap();
        devices
            .add_ans(&placement, Box::new(RamDisk::new("backing", 16, 4096)))
            .unwrap();
        assert_eq!(devices.read(0, WRAPPER + 0x44, 4, 0), Ok(1 << 4));
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
        devices.transfer(0, &mut ram, 0).unwrap();
        let mut completion = [0; 16];
        assert!(Memory::read(&mut ram, RAM + 0x1000, &mut completion));
        assert_eq!(completion[14], 1);
        let mut model = [0; 10];
        assert!(Memory::read(&mut ram, RAM + 0x4000 + 24, &mut model));
        assert_eq!(&model, b"Stela ANS2");
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
        devices.add_wake_masks(base, valid).unwrap();
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
        // A core the board does not have refuses.
        assert!(devices.write(0, START + 0xc, 4, 1 << 2, 0).is_err());
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
        // The rest of each block reaches no model.
        assert!(devices.read(0, cpu + 0x100, 8, 0).is_err());
        assert!(devices.read(0, cpm, 8, 0).is_err());
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
        devices.add_aes(ranges, 3, None, (dart, 1), None).unwrap();
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
    #[test]
    fn sep_firmware_dma_faults_or_refuses_authentication_without_a_boot_ack() {
        use crate::platform::{
            apple::sep::message::{Frame, ROM},
            dma::tests::Ram,
        };
        const DART: u64 = 0x25d2c0000;
        const SEP: u64 = 0x25e400000;
        const AUX: u64 = 0x25e050000;
        const RAM: u64 = 0x800000000;
        let (signed_payload, manifest) = sep::image::signature::tests::inputs();
        for (image, refusal) in [
            (
                b"\x30\x06\x16\x04IM4P".to_vec(),
                "payload type is malformed",
            ),
            (
                crate::img4::tests::im4p(b"sepi", b"synthetic"),
                "bare IM4P has no manifest",
            ),
            (
                crate::img4::compose(&signed_payload, &manifest),
                "signature evidence verified; trust constraints",
            ),
        ] {
            for enable in [false, true] {
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
                        Box::new(|_: &mut [u8]| Err("unused entropy")),
                    )
                    .unwrap();
                devices.write(0, SEP + 0x8114, 4, 1, 0).unwrap();
                if enable {
                    devices.write(0, DART + 0xc00, 4, 1, 0).unwrap();
                    devices.write(0, DART + 0x1000, 4, 6, 0).unwrap();
                }
                let mut ram = Ram::new(RAM, 0x1000);
                ram.bytes[..image.len()].copy_from_slice(&image);
                let before = ram.bytes.clone();
                for (opcode, data) in [(5, 0), (6, (RAM >> 12) as u32)] {
                    let message = Frame {
                        service: ROM,
                        tag: 1,
                        opcode,
                        parameter: 0,
                        data,
                    }
                    .mailbox();
                    devices
                        .write(0, SEP + 0x8800, 8, message.payload, 0)
                        .unwrap();
                    devices.write(0, SEP + 0x8808, 8, 0, 0).unwrap();
                    let result = devices.transfer(0, &mut ram, 0);
                    if opcode == 5 {
                        result.unwrap();
                        devices.read(0, SEP + 0x8830, 8, 0).unwrap();
                        devices.read(0, SEP + 0x8838, 8, 0).unwrap();
                    } else {
                        let Err(DeviceError::Refused(reason)) = result else {
                            panic!("SEP must not boot from an unauthenticated image");
                        };
                        assert!(reason.contains(if enable { refusal } else { "DMA fault" }));
                        assert_eq!(devices.read(0, SEP + 0x8114, 4, 0).unwrap(), 1 | 1 << 17);
                        assert_eq!(ram.bytes, before);
                    }
                }
                assert!(
                    matches!(devices.read(0, AUX, 4, 0), Err(DeviceError::Refused(reason)) if reason.contains("auxiliary"))
                );
                assert!(matches!(
                    devices.read(0, SEP + 0x6c000, 4, 0),
                    Err(DeviceError::NoDevice)
                ));
            }
        }
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
        let placement = super::super::soc::UsbController {
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
            stream: 1,
            port: 1,
        };
        let id = devices.add_usb(&placement, dart).unwrap();
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
        // The pipehandler and core event block are the ATC PHY's.
        for index in [3, 4] {
            assert_eq!(
                devices.read(0, placement.ranges[index].0, 4, 0),
                Err(DeviceError::NoDevice)
            );
        }
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
