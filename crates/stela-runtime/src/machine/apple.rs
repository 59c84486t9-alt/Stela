//! The Apple T8112 device models (`platform::apple`) as the engine's
//! [`Devices`]: one [`Bus`] for the guest physical address space, an
//! [`InterruptLatch`] for the wires, AIC input forwarding and reset requests.
//! The models own every register decision; this adapter only routes accesses
//! and time, and turns each `MmioError` into an explicit refusal.
use super::{
    engine::{DeviceError, Devices},
    registers::Lines,
};
use crate::platform::apple::{
    aic::{Aic2, Aic2Config},
    aic1::Aic1,
    bus::{Access, Bus, DeviceId, MapError, MmioError, Width},
    interrupt::{CpuIndex, InterruptLatch},
    uart::S5lUart,
    wdt::AppleWdt,
};
use alloc::{boxed::Box, format, string::String};

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
}

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
        }
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
            AicLayout::V2 { irq_config, event } => {
                let config = Aic2Config {
                    nr_irq,
                    max_irq: nr_irq.div_ceil(32) * 32,
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

    fn lines(&mut self, cpu: usize, now: u64) -> Lines {
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
        let mut access = Access::new(0, now, &mut self.latch);
        self.bus.advance(&mut access).ok().flatten()
    }

    fn take_reset(&mut self) -> Option<String> {
        self.reset.take()
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
        let v2 = |event| AicLayout::V2 {
            irq_config: AIC2_IRQ_CFG,
            event,
        };
        devices.add_aic(0x2_3b0c_0000, 1152, v2(0x8000)).unwrap();
        // CAP0 (offset 4) reports NR_IRQ in bits 15:0.
        assert_eq!(devices.read(0, 0x2_3b0c_0004, 4, 0).unwrap() & 0xffff, 1152);
        assert!(devices.add_aic(0x2_3b0c_0000, 1152, v2(0x10)).is_err());
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
}
