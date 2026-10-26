// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2017-2018 Hans de Goede <hdegoede@redhat.com>
// Copyright (C) 2024 Bootlin
// Copyright (C) 2024 Linaro Ltd.
// Copyright (C) 2023 Dmitry Baryshkov <dmitry.baryshkov@linaro.org>
// Copyright (c) 2026 Stela contributors
//! Physical Type-C switches/retimers. The platform binds actual board devices,
//! powered I²C targets, supplies, clocks, GPIOs and upstream route topology.
//! An observation or mode request never invents those resources or a GPU link.

use crate::bus::i2c::{self, Address, Bus, Operation};

pub mod nb7vpq904m;
pub mod pi3usb30532;
pub mod pmc;
pub mod ps8830;
pub mod tusb1046;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Orientation {
    None,
    Normal,
    Reverse,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pin {
    C,
    D,
    E,
    F,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayPort {
    pub pin: Pin,
    pub status: u32,
    pub configuration: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Safe,
    Usb,
    Usb2,
    Usb3,
    DisplayPort(DisplayPort),
    Thunderbolt {
        cable_mode: u32,
        enter_vdo: u32,
        device_mode: u32,
    },
    Usb4 {
        enter_usb: u32,
        active_link_training: bool,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    TimerBudget {
        microseconds: u64,
    },
    I2c {
        register: u8,
        write: bool,
        error: i2c::Error,
    },
    Power {
        operation: PowerOperation,
        error: ResourceError,
    },
    UnsupportedMode(Mode),
    NoOrientation,
    InvalidLaneMapping([u8; 4]),
    NeedsInitialization,
    NeedsPlatformReset,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Supply {
    Vdd33,
    Vdd33Cap,
    Vdd,
    VddAr,
    VddAt,
    VddIo,
    Vcc,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowerOperation {
    Supply(Supply, bool),
    Reset(bool),
    Enable(bool),
    Clock(bool),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceError {
    Unavailable,
    Status(u64),
    I2c(i2c::Error),
}
/// Actual board-selected resource operations. Absence/failure must be explicit;
/// no dummy/no-op power provider is included. Providers retain resource leases.
/// Operations establish this device's owned enable/reset vote, not an unchecked
/// global rail refcount. Setting false is idempotent, including after a failed
/// enable whose physical effects are uncertain.
pub trait Power {
    fn set(&mut self, operation: PowerOperation) -> Result<(), ResourceError>;
}

/// One actual route node. A platform-resolved chain may call orientation from
/// upstream to downstream, then mode from retimer to upstream mux, matching the
/// Linux callbacks. There is no connector/topology inference in this trait.
pub trait Route {
    fn set_orientation(&mut self, orientation: Orientation) -> Result<(), Error>;
    fn set_mode(&mut self, mode: Mode) -> Result<(), Error>;
}

struct Registers<B: Bus> {
    bus: B,
    address: Address,
    fault: Option<Error>,
}
impl<B: Bus> Registers<B> {
    fn new(bus: B, address: Address) -> Self {
        Self {
            bus,
            address,
            fault: None,
        }
    }
    fn healthy(&self) -> Result<(), Error> {
        self.fault.map_or(Ok(()), Err)
    }
    fn poison(&mut self, error: Error) -> Error {
        self.fault = Some(error);
        error
    }
    fn read(&mut self, register: u8) -> Result<u8, Error> {
        self.healthy()?;
        self.read_raw(register).map_err(|error| self.poison(error))
    }
    fn read_raw(&mut self, register: u8) -> Result<u8, Error> {
        let mut value = [0];
        self.bus
            .transaction(
                self.address,
                &mut [Operation::Write(&[register]), Operation::Read(&mut value)],
            )
            .map_err(|error| Error::I2c {
                register,
                write: false,
                error,
            })?;
        Ok(value[0])
    }
    fn write(&mut self, register: u8, value: u8) -> Result<(), Error> {
        self.healthy()?;
        self.bus
            .transaction(self.address, &mut [Operation::Write(&[register, value])])
            .map_err(|error| {
                self.poison(Error::I2c {
                    register,
                    write: true,
                    error,
                })
            })
    }
    fn update(&mut self, register: u8, mask: u8, value: u8) -> Result<(), Error> {
        let old = self.read(register)?;
        let new = (old & !mask) | (value & mask);
        if new != old {
            self.write(register, new)?;
        }
        Ok(())
    }
}

fn require_orientation(orientation: Orientation, mode: Mode) -> Result<(), Error> {
    if orientation == Orientation::None && !matches!(mode, Mode::Safe | Mode::Usb2) {
        return Err(Error::NoOrientation);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::usb::typec::ucsi::Timer;
    use alloc::{rc::Rc, vec::Vec};
    use core::cell::{Cell, RefCell};
    use nb7vpq904m::Nb7vpq904m;
    use pi3usb30532::Pi3usb30532;
    use ps8830::Ps8830;
    use tusb1046::Tusb1046;

    #[derive(Clone, Copy)]
    enum Kind {
        Plain,
        Parade,
        OnSemi,
    }
    #[derive(Default)]
    struct PowerState {
        supplies: u8,
        clock: bool,
        reset: bool,
        enable: bool,
        calls: usize,
        fail_at: usize,
        fail_after: bool,
        operations: Vec<PowerOperation>,
        moments: Vec<u64>,
        now: Rc<Cell<u64>>,
    }
    impl PowerState {
        fn new() -> Self {
            Self {
                fail_at: usize::MAX,
                ..Self::default()
            }
        }
    }
    #[derive(Clone)]
    struct DevicePower(Rc<RefCell<PowerState>>);
    impl Power for DevicePower {
        fn set(&mut self, operation: PowerOperation) -> Result<(), ResourceError> {
            let mut model = self.0.borrow_mut();
            model.calls += 1;
            model.operations.push(operation);
            let now = model.now.get();
            model.moments.push(now);
            let fail = model.calls == model.fail_at;
            if fail && !model.fail_after {
                return Err(ResourceError::Status(0x42));
            }
            match operation {
                PowerOperation::Supply(supply, enabled) => {
                    let bit = match supply {
                        Supply::Vdd33 => 0,
                        Supply::Vdd33Cap => 1,
                        Supply::Vdd => 2,
                        Supply::VddAr => 3,
                        Supply::VddAt => 4,
                        Supply::VddIo => 5,
                        Supply::Vcc => 6,
                    };
                    if enabled {
                        model.supplies |= 1 << bit;
                    } else {
                        model.supplies &= !(1 << bit);
                    }
                }
                PowerOperation::Clock(enabled) => model.clock = enabled,
                PowerOperation::Reset(reset) => model.reset = reset,
                PowerOperation::Enable(enabled) => model.enable = enabled,
            }
            if fail {
                Err(ResourceError::Status(0x42))
            } else {
                Ok(())
            }
        }
    }
    struct Model {
        registers: [u8; 256],
        log: Vec<(bool, u8, u8)>,
        calls: usize,
        fail_at: usize,
        fail_after: bool,
        kind: Kind,
        power: Rc<RefCell<PowerState>>,
        moments: Vec<u64>,
    }
    #[derive(Clone)]
    struct Device(Rc<RefCell<Model>>);
    impl Bus for Device {
        fn transaction(
            &mut self,
            address: Address,
            operations: &mut [Operation<'_>],
        ) -> Result<(), i2c::Error> {
            assert_eq!(address, Address::SevenBit(0x20));
            let mut model = self.0.borrow_mut();
            model.calls += 1;
            let now = model.power.borrow().now.get();
            model.moments.push(now);
            let fail = model.calls == model.fail_at;
            let error = || i2c::Error {
                kind: i2c::ErrorKind::Aborted {
                    kind: i2c::AbortKind::DataNack,
                    source: 0x1234,
                },
                recovery: i2c::Recovery::Disabled,
            };
            if fail && !model.fail_after {
                return Err(error());
            }
            {
                let power = model.power.borrow();
                let accessible = match model.kind {
                    Kind::Plain => true,
                    Kind::Parade => power.supplies == 0x3f && power.clock && !power.reset,
                    Kind::OnSemi => power.supplies & 0x40 != 0 && power.enable,
                };
                if !accessible {
                    return Err(i2c::Error {
                        kind: i2c::ErrorKind::Aborted {
                            kind: i2c::AbortKind::AddressNack,
                            source: 1,
                        },
                        recovery: i2c::Recovery::Disabled,
                    });
                }
            }
            match operations {
                [Operation::Write(pointer), Operation::Read(output)] => {
                    assert_eq!(pointer.len(), 1);
                    assert_eq!(output.len(), 1);
                    let value = model.registers[usize::from(pointer[0])];
                    output[0] = value;
                    model.log.push((true, pointer[0], value));
                }
                [Operation::Write(bytes)] => {
                    assert_eq!(bytes.len(), 2);
                    model.registers[usize::from(bytes[0])] = bytes[1];
                    model.log.push((false, bytes[0], bytes[1]));
                }
                _ => panic!("physical mux requires byte-data register protocol"),
            }
            if fail { Err(error()) } else { Ok(()) }
        }
    }
    #[derive(Default)]
    struct Time(Rc<Cell<u64>>);
    impl Timer for Time {
        fn now_us(&self) -> u64 {
            self.0.get()
        }
        fn delay_us(&self, microseconds: u64) {
            self.0.set(self.0.get() + microseconds);
        }
    }
    fn fixture(
        kind: Kind,
    ) -> (
        Device,
        DevicePower,
        Rc<RefCell<Model>>,
        Rc<RefCell<PowerState>>,
    ) {
        let power = Rc::new(RefCell::new(PowerState::new()));
        let model = Rc::new(RefCell::new(Model {
            registers: [0; 256],
            log: Vec::new(),
            calls: 0,
            fail_at: usize::MAX,
            fail_after: false,
            kind,
            power: power.clone(),
            moments: Vec::new(),
        }));
        (
            Device(model.clone()),
            DevicePower(power.clone()),
            model,
            power,
        )
    }
    fn dp(pin: Pin) -> Mode {
        Mode::DisplayPort(DisplayPort {
            pin,
            status: 0x80,
            configuration: (match pin {
                Pin::C => 4,
                Pin::D => 8,
                Pin::E => 16,
                Pin::F => 32,
            }) << 8,
        })
    }
    fn address() -> Address {
        Address::SevenBit(0x20)
    }

    #[test]
    fn simple_muxes_preserve_actual_orientation_and_register_neighbors() {
        for byte in 0..=255 {
            for orientation in [Orientation::Normal, Orientation::Reverse] {
                for mode in [Mode::Safe, Mode::Usb, dp(Pin::C), dp(Pin::D), dp(Pin::E)] {
                    let (device, _, model, _) = fixture(Kind::Plain);
                    model.borrow_mut().registers[0] = byte;
                    let mut pi = Pi3usb30532::probe(device, address()).unwrap();
                    pi.set_orientation(orientation).unwrap();
                    pi.set_mode(mode).unwrap();
                    let conf = model.borrow().registers[0];
                    assert_eq!(conf & 1 != 0, orientation == Orientation::Reverse);
                    assert_eq!(
                        conf & 6,
                        match mode {
                            Mode::Safe => 0,
                            Mode::Usb => 4,
                            Mode::DisplayPort(data) if data.pin == Pin::D => 6,
                            _ => 2,
                        }
                    );
                    let (device, _, model, _) = fixture(Kind::Plain);
                    model.borrow_mut().registers[10] = byte;
                    let mut ti = Tusb1046::probe(device, address()).unwrap();
                    ti.set_orientation(orientation).unwrap();
                    ti.set_mode(mode).unwrap();
                    let conf = model.borrow().registers[10];
                    assert_eq!(conf & !7, byte & !7);
                    assert_eq!(conf & 4 != 0, orientation == Orientation::Reverse);
                    assert_eq!(
                        conf & 3,
                        match mode {
                            Mode::Safe => 0,
                            Mode::Usb => 1,
                            Mode::DisplayPort(data) if data.pin == Pin::D => 3,
                            _ => 2,
                        }
                    );
                }
            }
        }
    }
    #[test]
    fn unsupported_or_orientationless_requests_never_succeed_or_modify_hardware() {
        let (device, _, model, _) = fixture(Kind::Plain);
        let mut pi = Pi3usb30532::probe(device, address()).unwrap();
        let calls = model.borrow().calls;
        assert_eq!(pi.set_mode(Mode::Usb), Err(Error::NoOrientation));
        assert_eq!(
            pi.set_mode(dp(Pin::F)),
            Err(Error::UnsupportedMode(dp(Pin::F)))
        );
        assert_eq!(model.borrow().calls, calls);
        pi.set_orientation(Orientation::Reverse).unwrap();
        pi.set_mode(Mode::Usb).unwrap();
        pi.set_orientation(Orientation::None).unwrap();
        assert_eq!(pi.configuration(), 0);
        let (device, _, model, _) = fixture(Kind::Plain);
        let mut ti = Tusb1046::probe(device, address()).unwrap();
        let calls = model.borrow().calls;
        let mode = Mode::Usb4 {
            enter_usb: 0,
            active_link_training: false,
        };
        assert_eq!(ti.set_mode(mode), Err(Error::UnsupportedMode(mode)));
        assert_eq!(model.borrow().calls, calls);
    }
    #[test]
    fn every_simple_mux_io_failure_quarantines_later_register_access() {
        for fail_after in [false, true] {
            let (device, _, model, _) = fixture(Kind::Plain);
            let mut pi = Pi3usb30532::probe(device, address()).unwrap();
            model.borrow_mut().fail_at = 2;
            model.borrow_mut().fail_after = fail_after;
            assert!(matches!(
                pi.set_orientation(Orientation::Reverse),
                Err(Error::I2c { .. })
            ));
            assert_eq!(pi.configuration(), 0);
            let calls = model.borrow().calls;
            assert!(pi.set_orientation(Orientation::Normal).is_err());
            assert_eq!(model.borrow().calls, calls);
            for step in [2, 3] {
                let (device, _, model, _) = fixture(Kind::Plain);
                let mut ti = Tusb1046::probe(device, address()).unwrap();
                model.borrow_mut().fail_at = step;
                model.borrow_mut().fail_after = fail_after;
                assert!(matches!(
                    ti.set_orientation(Orientation::Reverse),
                    Err(Error::I2c { .. })
                ));
                let calls = model.borrow().calls;
                assert!(ti.set_orientation(Orientation::Normal).is_err());
                assert_eq!(model.borrow().calls, calls);
            }
        }
    }
    #[test]
    fn nb7_lane_map_orientation_and_mode_program_actual_channels() {
        for lanes in [[0, 1, 2, 3], [3, 2, 1, 0]] {
            for orientation in [Orientation::Normal, Orientation::Reverse] {
                for mode in [
                    Mode::Safe,
                    Mode::Usb,
                    dp(Pin::C),
                    dp(Pin::D),
                    dp(Pin::E),
                    dp(Pin::F),
                ] {
                    let (device, power, model, resources) = fixture(Kind::OnSemi);
                    model.borrow_mut().registers.fill(0xa5);
                    let mut retimer = Nb7vpq904m::new(device, address(), power);
                    retimer.initialize(lanes).unwrap();
                    assert_eq!(retimer.version(), Some(0xa5));
                    retimer.set_orientation(orientation).unwrap();
                    retimer.set_mode(mode).unwrap();
                    let model = model.borrow();
                    let swap = lanes[0] == 3;
                    let reverse = orientation == Orientation::Reverse;
                    match mode {
                        Mode::Safe => assert_eq!(model.registers[0], 0xfb),
                        Mode::Usb => {
                            assert_eq!(model.registers[0], if reverse ^ swap { 0x3b } else { 0xcb })
                        }
                        Mode::DisplayPort(data) if matches!(data.pin, Pin::C | Pin::E) => {
                            assert_eq!(model.registers[0], 0xf5)
                        }
                        _ => {
                            assert_eq!(model.registers[0], if reverse ^ swap { 0xf1 } else { 0xf3 })
                        }
                    }
                    for channel in 0..4 {
                        assert_eq!(model.registers[1 + channel * 2] & !14, 0xa5 & !14);
                        assert_eq!(model.registers[2 + channel * 2] & !6, 0xa5 & !6);
                        assert_eq!(model.registers[0x18 + channel * 2] & !3, 0xa5 & !3);
                        assert_eq!(model.registers[0x19 + channel * 2] & !3, 0xa5 & !3);
                    }
                    drop(model);
                    retimer.shutdown().unwrap();
                    let resources = resources.borrow();
                    assert!(!resources.enable);
                    assert_eq!(resources.supplies, 0);
                }
            }
        }
    }
    #[test]
    fn nb7_rejects_unknown_lane_maps_and_propagates_every_channel_failure() {
        let (device, power, model, resources) = fixture(Kind::OnSemi);
        let mut retimer = Nb7vpq904m::new(device, address(), power);
        assert_eq!(
            retimer.initialize([1, 0, 2, 3]),
            Err(Error::InvalidLaneMapping([1, 0, 2, 3]))
        );
        assert_eq!(model.borrow().calls, 0);
        assert_eq!(resources.borrow().calls, 0);
        let (device, power, model, _) = fixture(Kind::OnSemi);
        let mut baseline = Nb7vpq904m::new(device, address(), power);
        baseline.initialize([0, 1, 2, 3]).unwrap();
        let first = model.borrow().calls + 1;
        baseline.set_orientation(Orientation::Normal).unwrap();
        let last = model.borrow().calls;
        for fail_at in first..=last {
            let (device, power, model, resources) = fixture(Kind::OnSemi);
            let mut retimer = Nb7vpq904m::new(device, address(), power);
            retimer.initialize([0, 1, 2, 3]).unwrap();
            model.borrow_mut().fail_at = fail_at;
            model.borrow_mut().fail_after = true;
            assert!(matches!(
                retimer.set_orientation(Orientation::Normal),
                Err(Error::I2c { .. })
            ));
            assert_eq!(resources.borrow().supplies, 0);
            assert!(!resources.borrow().enable);
            let calls = model.borrow().calls;
            assert!(retimer.set_mode(Mode::Usb).is_err());
            assert_eq!(model.borrow().calls, calls);
        }
    }
    #[test]
    fn parade_real_power_order_reset_hold_and_firmware_delays_are_required() {
        let (device, power, model, resources) = fixture(Kind::Parade);
        resources.borrow_mut().reset = true;
        let mut retimer = Ps8830::new(
            device,
            address(),
            power,
            Time(resources.borrow().now.clone()),
        );
        assert_eq!(retimer.in_reset(), None);
        retimer.initialize().unwrap();
        assert!(retimer.initial_probe_error().is_some());
        assert_eq!(retimer.in_reset(), Some(true));
        assert_eq!(resources.borrow().supplies, 0);
        assert!(resources.borrow().clock);
        assert!(resources.borrow().reset);
        {
            let resources = resources.borrow();
            assert_eq!(&resources.moments[..3], &[0, 0, 4_000]);
            let release = resources
                .operations
                .iter()
                .position(|op| *op == PowerOperation::Reset(false))
                .unwrap();
            assert_eq!(resources.moments[release], 8_000);
            assert_eq!(resources.now.get(), 68_000);
            assert_eq!(&model.borrow().moments[..2], &[4_000, 68_000]);
        }
        retimer.set_orientation(Orientation::Reverse).unwrap();
        retimer.set_mode(Mode::Usb3).unwrap();
        assert_eq!(resources.borrow().now.get(), 132_000);
        assert_eq!(&model.borrow().registers[..3], &[0x23, 0, 0]);
        retimer.set_mode(dp(Pin::D)).unwrap();
        assert_eq!(&model.borrow().registers[..3], &[0x23, 0x87, 0]);
        retimer
            .set_mode(Mode::Usb4 {
                enter_usb: 2 << 19,
                active_link_training: false,
            })
            .unwrap();
        assert_eq!(&model.borrow().registers[..3], &[7, 0, 128]);
        retimer
            .set_mode(Mode::Thunderbolt {
                cable_mode: 1 << 25,
                enter_vdo: 1 << 23,
                device_mode: 0,
            })
            .unwrap();
        assert_eq!(&model.borrow().registers[..3], &[7, 0, 17]);
        retimer.set_mode(Mode::Usb2).unwrap();
        assert_eq!(retimer.in_reset(), Some(true));
        assert_eq!(resources.borrow().supplies, 0);
        assert!(resources.borrow().clock);
        retimer.shutdown().unwrap();
        assert!(!resources.borrow().clock);
        assert_eq!(retimer.applied(), None);
    }
    #[test]
    fn parade_power_failures_before_or_after_effect_are_quarantined_and_cleanup_is_real() {
        let (device, power, _, resources) = fixture(Kind::Parade);
        let mut baseline = Ps8830::new(
            device,
            address(),
            power,
            Time(resources.borrow().now.clone()),
        );
        baseline.initialize().unwrap();
        let calls = resources.borrow().calls;
        for fail_after in [false, true] {
            for fail_at in 1..=calls {
                let (device, power, model, resources) = fixture(Kind::Parade);
                resources.borrow_mut().fail_at = fail_at;
                resources.borrow_mut().fail_after = fail_after;
                let mut retimer = Ps8830::new(
                    device,
                    address(),
                    power,
                    Time(resources.borrow().now.clone()),
                );
                assert!(matches!(retimer.initialize(), Err(Error::Power { .. })));
                assert!(retimer.fault().is_some());
                assert_eq!(retimer.in_reset(), None);
                assert_eq!(resources.borrow().supplies, 0);
                assert!(!resources.borrow().clock);
                assert!(resources.borrow().reset);
                let calls = model.borrow().calls;
                let power_calls = resources.borrow().calls;
                assert!(retimer.set_orientation(Orientation::Normal).is_err());
                assert_eq!(model.borrow().calls, calls);
                assert_eq!(resources.borrow().calls, power_calls);
            }
        }
    }
    #[test]
    fn parade_partial_register_publication_cannot_claim_a_configured_path() {
        for step in 1..=3 {
            let (device, power, model, resources) = fixture(Kind::Parade);
            let mut retimer = Ps8830::new(
                device,
                address(),
                power,
                Time(resources.borrow().now.clone()),
            );
            retimer.initialize().unwrap();
            retimer.set_orientation(Orientation::Normal).unwrap();
            let calls = model.borrow().calls;
            model.borrow_mut().fail_at = calls + step;
            model.borrow_mut().fail_after = true;
            assert!(matches!(
                retimer.set_mode(dp(Pin::C)),
                Err(Error::I2c { .. })
            ));
            assert_eq!(retimer.applied(), None);
            assert_eq!(retimer.in_reset(), None);
            assert_eq!(resources.borrow().supplies, 0);
            assert!(!resources.borrow().clock);
            assert!(resources.borrow().reset);
        }
    }

    #[test]
    fn absent_real_power_resources_cannot_initialize_a_retimer() {
        struct Missing;
        impl Power for Missing {
            fn set(&mut self, _operation: PowerOperation) -> Result<(), ResourceError> {
                Err(ResourceError::Unavailable)
            }
        }
        let (device, _, model, resources) = fixture(Kind::Plain);
        let mut parade = Ps8830::new(
            device,
            address(),
            Missing,
            Time(resources.borrow().now.clone()),
        );
        assert_eq!(
            parade.initialize(),
            Err(Error::Power {
                operation: PowerOperation::Supply(Supply::Vdd33, true),
                error: ResourceError::Unavailable
            })
        );
        assert_eq!(model.borrow().calls, 0);
        assert!(!parade.cleanup_errors().is_empty());
        assert_eq!(parade.in_reset(), None);
        let (device, _, model, _) = fixture(Kind::Plain);
        let mut onsemi = Nb7vpq904m::new(device, address(), Missing);
        assert_eq!(
            onsemi.initialize([0, 1, 2, 3]),
            Err(Error::Power {
                operation: PowerOperation::Supply(Supply::Vcc, true),
                error: ResourceError::Unavailable
            })
        );
        assert_eq!(model.borrow().calls, 0);
        assert_eq!(onsemi.version(), None);
    }
    #[test]
    fn nb7_uncertain_power_failure_and_parade_secondary_cleanup_error_are_retained() {
        for fail_after in [false, true] {
            for fail_at in [1, 2] {
                let (device, power, model, resources) = fixture(Kind::OnSemi);
                resources.borrow_mut().fail_at = fail_at;
                resources.borrow_mut().fail_after = fail_after;
                let mut retimer = Nb7vpq904m::new(device, address(), power);
                assert!(matches!(
                    retimer.initialize([0, 1, 2, 3]),
                    Err(Error::Power { .. })
                ));
                assert_eq!(model.borrow().calls, 0);
                assert_eq!(resources.borrow().supplies, 0);
                assert!(!resources.borrow().enable);
            }
        }
        let (device, power, model, resources) = fixture(Kind::Parade);
        let mut retimer = Ps8830::new(
            device,
            address(),
            power,
            Time(resources.borrow().now.clone()),
        );
        retimer.initialize().unwrap();
        retimer.set_orientation(Orientation::Normal).unwrap();
        let io_calls = model.borrow().calls;
        model.borrow_mut().fail_at = io_calls + 1;
        let power_calls = resources.borrow().calls;
        resources.borrow_mut().fail_at = power_calls + 8;
        assert!(matches!(
            retimer.set_mode(Mode::Usb),
            Err(Error::I2c { .. })
        ));
        assert!(matches!(retimer.fault(), Some(Error::I2c { .. })));
        assert!(matches!(
            retimer.cleanup_errors(),
            [Error::Power {
                operation: PowerOperation::Reset(true),
                ..
            }]
        ));
        assert_eq!(resources.borrow().supplies, 0);
        assert!(!resources.borrow().clock);
        assert_eq!(retimer.applied(), None);
    }
    #[test]
    #[ignore = "requires pinned unchanged Linux mux/retimer C oracle trace"]
    fn unchanged_linux_mux_and_retimer_programming_oracle() {
        let path =
            std::env::var("STELA_TYPEC_MUX_ORACLE").expect("STELA_TYPEC_MUX_ORACLE trace path");
        let trace = std::fs::read_to_string(path).unwrap();
        let mut cases = [0; 4];
        for line in trace.lines() {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            let number = |index: usize| fields[index].parse::<usize>().unwrap();
            let orientation = |value| match value {
                0 => Orientation::None,
                1 => Orientation::Normal,
                2 => Orientation::Reverse,
                _ => panic!("unknown source orientation"),
            };
            let mode = |value| match value {
                0 => Mode::Safe,
                1 => Mode::Usb,
                2 => dp(Pin::C),
                3 => dp(Pin::D),
                4 => dp(Pin::E),
                5 => dp(Pin::F),
                _ => panic!("unknown source mux state"),
            };
            match fields[0] {
                "P" | "T" => {
                    assert_eq!(number(4), 0);
                    assert_eq!(number(5), 0);
                    let (device, _, model, _) = fixture(Kind::Plain);
                    let register = if fields[0] == "P" { 0 } else { 10 };
                    model.borrow_mut().registers[register] = number(1) as u8;
                    if fields[0] == "P" {
                        let mut mux = Pi3usb30532::probe(device, address()).unwrap();
                        model.borrow_mut().log.clear();
                        mux.set_orientation(orientation(number(2))).unwrap();
                        mux.set_mode(mode(number(3))).unwrap();
                        cases[0] += 1;
                    } else {
                        let mut mux = Tusb1046::probe(device, address()).unwrap();
                        model.borrow_mut().log.clear();
                        mux.set_orientation(orientation(number(2))).unwrap();
                        mux.set_mode(mode(number(3))).unwrap();
                        cases[1] += 1;
                    }
                    let model = model.borrow();
                    assert_eq!(usize::from(model.registers[register]), number(6));
                    assert_eq!(model.log.iter().filter(|entry| !entry.0).count(), number(7));
                }
                "N" => {
                    assert_eq!(number(5), 0);
                    let (device, power, model, _) = fixture(Kind::OnSemi);
                    model.borrow_mut().registers.fill(number(1) as u8);
                    let mut retimer = Nb7vpq904m::new(device, address(), power);
                    retimer
                        .initialize(if number(2) == 0 {
                            [0, 1, 2, 3]
                        } else {
                            [3, 2, 1, 0]
                        })
                        .unwrap();
                    retimer.set_orientation(orientation(number(3))).unwrap();
                    retimer.set_mode(mode(number(4))).unwrap();
                    let expected: Vec<_> = fields[6]
                        .as_bytes()
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|pair| {
                            u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap()
                        })
                        .collect();
                    assert_eq!(&model.borrow().registers[..32], expected);
                    cases[2] += 1;
                }
                "S" => {
                    assert_eq!(number(4), 0);
                    let (device, power, model, resources) = fixture(Kind::Parade);
                    let mut retimer = Ps8830::new(
                        device,
                        address(),
                        power,
                        Time(resources.borrow().now.clone()),
                    );
                    retimer.initialize().unwrap();
                    retimer.set_orientation(orientation(number(1))).unwrap();
                    let flags = number(3) as u32;
                    let mode = match number(2) {
                        0 => Mode::Safe,
                        1 => Mode::Usb,
                        2 => Mode::Usb2,
                        3 => Mode::Usb3,
                        4 => dp(Pin::C),
                        5 => dp(Pin::D),
                        6 => dp(Pin::E),
                        7 => Mode::Thunderbolt {
                            cable_mode: if flags & 1 != 0 { 1 << 25 } else { 0 },
                            enter_vdo: if flags & 2 != 0 { 1 << 23 } else { 0 },
                            device_mode: 0,
                        },
                        8 => Mode::Usb4 {
                            enter_usb: flags << 19,
                            active_link_training: false,
                        },
                        _ => panic!("unknown source retimer state"),
                    };
                    let before = resources.borrow().now.get();
                    retimer.set_mode(mode).unwrap();
                    assert_eq!(
                        &model.borrow().registers[..3],
                        &[number(5) as u8, number(6) as u8, number(7) as u8]
                    );
                    assert_eq!(retimer.in_reset(), Some(number(8) != 0));
                    assert_eq!(usize::from(resources.borrow().supplies), number(9));
                    assert_eq!(resources.borrow().now.get() - before, number(10) as u64);
                    cases[3] += 1;
                }
                _ => panic!("unknown source trace row"),
            }
        }
        assert_eq!(cases, [2816, 2816, 96, 32]);
    }
}
