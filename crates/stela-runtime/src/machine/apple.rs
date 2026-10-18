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
    bridge::Bridge,
    bus::{Access, Bus, DeviceId, MapError, MmioError, Width},
    cluster::{self, Cluster},
    cpm::Cpm,
    cpustart::{self, CpuStart},
    dart::{self, Dart},
    dcs::Dcs,
    dpe::Dpe,
    energy::{self, Energy},
    fuse::{self, AonFuses},
    interrupt::{CpuIndex, InterruptLatch},
    ipi::{self, Affinity, FastIpi},
    lockdown::{self, Lockdown},
    perf::PerfCounters,
    pmgr::{ACTIVE, Pmgr, PowerState},
    power::{self, Power},
    ptd::{self, Ptd},
    uart::S5lUart,
    wake::{self, WakeMasks},
    wdt::AppleWdt,
};
use crate::platform::dma::Port;
use crate::system::access::{AccessKind, Encoding};
use alloc::{boxed::Box, format, string::String, vec::Vec};

pub use crate::platform::apple::{
    aic::{AIC2_IRQ_CFG, AIC3_IRQ_CFG, AicLayout},
    aic1::AIC1_EVENT,
    interrupt::AicInput,
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
    cpu_start: Option<CpuStarter>,
    reset_vectors: Vec<Option<DeviceId>>,
    starts: Vec<Start>,
}

/// The CPU start registers and each PE's MPIDR_EL1 (Aff1 its cluster, Aff0
/// its core), by which a released core finds its PE.
struct CpuStarter {
    device: DeviceId,
    mpidrs: Vec<u64>,
}

/// An AES engine and the DART stream its DMA goes through.
#[derive(Debug, Clone, Copy)]
struct Master {
    aes: DeviceId,
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
            cpu_start: None,
            reset_vectors: Vec::new(),
            starts: Vec::new(),
        }
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
        let mut access = Access::new(cpu, now, &mut self.latch);
        self.bus
            .write(physical, width, value, &mut access)
            .map_err(describe)?;
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
            aes.run(&mut port).map_err(describe)?;
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
}
