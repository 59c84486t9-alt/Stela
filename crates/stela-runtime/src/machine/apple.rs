//! The Apple T8112 device models (`platform::apple`) as the engine's
//! [`Devices`]: one [`Bus`] for the guest physical address space, an
//! [`InterruptLatch`] for the wires, AIC input forwarding and reset requests.
//! The models own every register decision; this adapter only routes accesses
//! and time, and turns each `MmioError` into an explicit refusal.
use super::{
    engine::{DeviceError, Devices, Memory},
    registers::Lines,
};
use crate::platform::apple::{
    aes::{self, Aes},
    aic::{Aic2, Aic2Config},
    aic1::Aic1,
    amcc::{self, Amcc},
    bus::{Access, Bus, DeviceId, MapError, MmioError, Width},
    dart::Dart,
    interrupt::{CpuIndex, InterruptLatch},
    ipi::{self, Affinity, FastIpi},
    lockdown::Lockdown,
    pmgr::{ACTIVE, Pmgr, PowerState},
    uart::S5lUart,
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

    /// The lockdown registers of a CPU implementation block named `name`
    /// at `range`, with CONTROL `control` bytes from its start.
    pub fn add_lockdown(
        &mut self,
        name: &'static str,
        control: u64,
        range: Range,
    ) -> Result<(), MapError> {
        let device = self.bus.add(Box::new(Lockdown::new(name, control)));
        self.map(device, &[range])
    }

    /// The AMCC's lock registers at each aperture of `layout`, with the
    /// CTRR-A region iBoot programmed (`[base, base + bytes)`).
    pub fn add_memory_controller(
        &mut self,
        apertures: &[u64],
        layout: amcc::Layout,
        programmed: Option<(u64, u64)>,
    ) -> Result<(), String> {
        let model = Amcc::new(layout, apertures.len(), programmed).map_err(String::from)?;
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

    /// A `dart,t8110` of `streams` streams at `range`.
    pub fn add_dart(
        &mut self,
        range: Range,
        streams: usize,
        irq: Option<AicInput>,
    ) -> Result<DartId, MapError> {
        let device = self.bus.add(Box::new(Dart::new(streams, irq)));
        self.map(device, &[range])?;
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
