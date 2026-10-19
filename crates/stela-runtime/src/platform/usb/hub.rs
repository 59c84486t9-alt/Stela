//! A native USB 2.0 high-speed hub with a single transaction translator
//! (USB 2.0 chapter 11), as a host port's [`Function`] whose downstream
//! ports carry other functions.
//!
//! Evidence: USB 2.0 11.23 (hub descriptors and the device, qualifier and
//! configuration a high-speed hub reports, 11.23.1), 11.24.2 (hub class
//! requests), 11.24.2.6-7 (hub and port status and change bits), 11.5
//! (downstream port states) and 11.12.1 (the status change endpoint's
//! bitmap). On J473 macOS `AppleUSB20Hub` (KC `0x451599c`) matches
//! bDeviceClass 9, bDeviceSubClass 0.
//!
//! The hub reports individual port power switching and individual
//! over-current protection, no port indicators and a TT think time of 8
//! full-speed bit times; its ports are removable. Port reset completes at
//! once: the port is Enabled with C_PORT_RESET set and its function reset,
//! as at the end of the 10 ms reset signaling (11.5.1.5). Resume likewise
//! completes at once with C_PORT_SUSPEND. The xHCI controller above routes
//! a slot to a downstream function by its route string, so the hub carries
//! no split transactions itself: its TT holds no buffered state, which
//! makes CLEAR_TT_BUFFER and RESET_TT complete with nothing to clear.
//! Refused (STALL): PORT_TEST, PORT_INDICATOR, GET_TT_STATE and STOP_TT
//! (vendor-defined state formats), and setting hub features.
use super::{
    BusPeer, Function, Reply, Speed, Token,
    control::{
        self, CLASS, CLEAR_FEATURE, Control, DEVICE, DEVICE_QUALIFIER, Descriptors, ENDPOINT,
        ENDPOINT_HALT, GET_DESCRIPTOR, GET_INTERFACE, GET_STATUS, INTERFACE, Outcome,
        RECIPIENT_DEVICE, RECIPIENT_ENDPOINT, RECIPIENT_INTERFACE, RECIPIENT_OTHER, Requests,
        SET_FEATURE, SET_INTERFACE, STANDARD, Setup,
    },
};
use alloc::{string::String, vec, vec::Vec};

/// The most ports one status-change byte reports.
pub const MAX_PORTS: usize = 7;
const STATUS_ENDPOINT: u8 = 0x81;
const HUB_DESCRIPTOR: u8 = 0x29;
/// Individual port power switching, individual over-current protection.
const CHARACTERISTICS: u16 = 0x0009;
/// Power-on to power-good, in 2 ms units.
const POWER_ON_TO_GOOD: u8 = 5;
const CONTROLLER_CURRENT_MA: u8 = 50;
/// High speed: 2^(12-1) microframes; full speed: 255 frames.
const HIGH_SPEED_INTERVAL: u8 = 12;
const FULL_SPEED_INTERVAL: u8 = 255;

const CLEAR_TT_BUFFER: u8 = 8;
const RESET_TT: u8 = 9;

// Port features (11.24.2, table 11-17) and status bits (11.24.2.7.1).
const PORT_CONNECTION: u16 = 0;
const PORT_ENABLE: u16 = 1;
const PORT_SUSPEND: u16 = 2;
const PORT_RESET: u16 = 4;
const PORT_POWER: u16 = 8;
const PORT_LOW_SPEED: u16 = 9;
const PORT_HIGH_SPEED: u16 = 10;
const C_PORT_CONNECTION: u16 = 16;
const C_PORT_ENABLE: u16 = 17;
const C_PORT_SUSPEND: u16 = 18;
const C_PORT_OVER_CURRENT: u16 = 19;
const C_PORT_RESET: u16 = 20;
const C_HUB_LOCAL_POWER: u16 = 0;
const C_HUB_OVER_CURRENT: u16 = 1;

const fn bit(feature: u16) -> u16 {
    1 << feature
}

/// The functions on a hub's downstream ports, by zero-based port index.
pub trait Ports {
    fn count(&self) -> usize;
    fn speed(&self, port: usize) -> Speed;
    /// Whether a function is cabled to the port now.
    fn attached(&self, _port: usize) -> bool {
        true
    }
    fn function(&mut self, port: usize) -> &mut dyn Function;
    fn function_ref(&self, port: usize) -> &dyn Function;
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct Port {
    status: u16,
    change: u16,
}

struct State {
    ports: Vec<Port>,
    halted: bool,
}

/// The hub's class and interface requests over its ports.
struct Context<'a, P: Ports> {
    state: &'a mut State,
    functions: &'a mut P,
}

pub struct Hub<P: Ports> {
    control: Control,
    state: State,
    /// The downstream functions.
    pub ports: P,
}

fn descriptors(serial: &str) -> Descriptors {
    let device = [
        18,
        DEVICE,
        0x00,
        0x02, // USB 2.0
        9,
        0,
        1, // hub, single TT
        control::EP0_PACKET as u8,
        0x09,
        0x12, // vendor 0x1209 (pid.codes)
        0x01,
        0x00, // its test product ID
        0x00,
        0x01,
        1,
        2,
        3,
        1,
    ];
    let configuration = |interval: u8| {
        control::configuration(
            1,
            0,
            &[
                &[9, INTERFACE, 0, 0, 1, 9, 0, 0, 0],
                &[7, ENDPOINT, STATUS_ENDPOINT, 3, 1, 0, interval],
            ],
        )
    };
    // At full speed a hub has no TT: protocol 0 (11.23.1).
    let qualifier = [
        10,
        DEVICE_QUALIFIER,
        0x00,
        0x02,
        9,
        0,
        0,
        control::EP0_PACKET as u8,
        1,
        0,
    ];
    Descriptors {
        device,
        configuration: configuration(HIGH_SPEED_INTERVAL),
        other_speed: Some((qualifier, configuration(FULL_SPEED_INTERVAL))),
        strings: vec![
            String::from("Stela"),
            String::from("Stela USB 2.0 Hub"),
            String::from(serial),
        ],
    }
}

impl<P: Ports> Hub<P> {
    pub fn new(ports: P, serial: &str) -> Result<Self, &'static str> {
        if !(1..=MAX_PORTS).contains(&ports.count()) {
            return Err("a hub has one to seven downstream ports");
        }
        Ok(Self {
            control: Control::new(descriptors(serial)),
            state: State {
                ports: vec![Port::default(); ports.count()],
                halted: false,
            },
            ports,
        })
    }

    fn context(&mut self) -> (&mut Control, Context<'_, P>) {
        (
            &mut self.control,
            Context {
                state: &mut self.state,
                functions: &mut self.ports,
            },
        )
    }

    /// Brings each powered port's connection status in line with its cable
    /// (11.24.2.7.1.1): a change sets C_PORT_CONNECTION, and a
    /// disconnection disables the port.
    fn detect(&mut self) {
        for (n, port) in self.state.ports.iter_mut().enumerate() {
            if port.status & bit(PORT_POWER) == 0 {
                continue;
            }
            let attached = self.ports.attached(n);
            let connected = port.status & bit(PORT_CONNECTION) != 0;
            if attached && !connected {
                port.status |= bit(PORT_CONNECTION);
                if self.ports.speed(n) == Speed::Low {
                    port.status |= bit(PORT_LOW_SPEED);
                }
                port.change |= bit(PORT_CONNECTION);
            } else if !attached && connected {
                port.status &= bit(PORT_POWER);
                port.change |= bit(PORT_CONNECTION);
            }
        }
    }

    /// The status change bitmap (11.12.4): bit 0 the hub, bit n port n.
    fn changes(&self) -> u8 {
        self.state
            .ports
            .iter()
            .enumerate()
            .filter(|(_, port)| port.change != 0)
            .fold(0, |bitmap, (n, _)| bitmap | 1 << (n + 1))
    }

    fn usable(&self, port: u8) -> Option<usize> {
        let n = usize::from(port).checked_sub(1)?;
        let status = self.state.ports.get(n)?.status;
        let enabled = bit(PORT_CONNECTION) | bit(PORT_ENABLE) | bit(PORT_POWER);
        (status & enabled == enabled && status & bit(PORT_SUSPEND) == 0).then_some(n)
    }
}

/// The port wIndex names, from 1.
fn port(ports: &mut [Port], index: u16) -> Result<(usize, &mut Port), ()> {
    let n = usize::from(index as u8).checked_sub(1).ok_or(())?;
    if index >> 8 != 0 {
        return Err(());
    }
    ports.get_mut(n).map(|p| (n, p)).ok_or(())
}

impl<P: Ports> Context<'_, P> {
    fn port(&mut self, index: u16) -> Result<(usize, &mut Port), ()> {
        port(&mut self.state.ports, index)
    }

    fn set_port_feature(&mut self, setup: Setup) -> Result<Outcome, ()> {
        let (n, port) = port(&mut self.state.ports, setup.index)?;
        let powered = port.status & bit(PORT_POWER) != 0;
        match setup.value {
            PORT_POWER => port.status |= bit(PORT_POWER),
            PORT_RESET if powered && port.status & bit(PORT_CONNECTION) != 0 => {
                port.status &= !(bit(PORT_SUSPEND) | bit(PORT_HIGH_SPEED));
                port.status |= bit(PORT_ENABLE);
                if self.functions.speed(n) == Speed::High {
                    port.status |= bit(PORT_HIGH_SPEED);
                }
                port.change |= bit(PORT_RESET);
                self.functions.function(n).reset().map_err(|_| ())?;
            }
            // Reset of an unconnected or unpowered port has no effect.
            PORT_RESET => {}
            PORT_SUSPEND if port.status & bit(PORT_ENABLE) != 0 => port.status |= bit(PORT_SUSPEND),
            PORT_SUSPEND => {}
            _ => return Err(()),
        }
        Ok(Outcome::Done)
    }

    fn clear_port_feature(&mut self, setup: Setup) -> Result<Outcome, ()> {
        let (_, port) = self.port(setup.index)?;
        match setup.value {
            PORT_ENABLE => port.status &= !(bit(PORT_ENABLE) | bit(PORT_SUSPEND)),
            PORT_SUSPEND if port.status & bit(PORT_SUSPEND) != 0 => {
                port.status &= !bit(PORT_SUSPEND);
                port.change |= bit(PORT_SUSPEND);
            }
            PORT_SUSPEND => {}
            // Power off disconnects; a reconnection follows power on.
            PORT_POWER => port.status = 0,
            C_PORT_CONNECTION | C_PORT_ENABLE | C_PORT_SUSPEND | C_PORT_OVER_CURRENT
            | C_PORT_RESET => port.change &= !bit(setup.value - C_PORT_CONNECTION),
            _ => return Err(()),
        }
        Ok(Outcome::Done)
    }
}

impl<P: Ports> Requests for Context<'_, P> {
    fn configure(&mut self, value: u8) -> Result<(), ()> {
        self.state.halted = false;
        if value == 0 {
            // Back to Address: ports lose power (11.11).
            self.state.ports.fill(Port::default());
        }
        Ok(())
    }

    fn request(&mut self, setup: Setup, _data: &[u8]) -> Result<Outcome, ()> {
        let read = setup.device_to_host();
        match (setup.kind(), setup.recipient(), setup.request, read) {
            (CLASS, RECIPIENT_DEVICE, GET_DESCRIPTOR, true)
                if setup.value >> 8 == u16::from(HUB_DESCRIPTOR) && setup.value & 0xff == 0 =>
            {
                let count = self.state.ports.len() as u8;
                let [low, high] = CHARACTERISTICS.to_le_bytes();
                Ok(Outcome::Data(vec![
                    9,
                    HUB_DESCRIPTOR,
                    count,
                    low,
                    high,
                    POWER_ON_TO_GOOD,
                    CONTROLLER_CURRENT_MA,
                    0,    // every port removable
                    0xff, // PortPwrCtrlMask, all ones (11.23.2.1)
                ]))
            }
            (CLASS, RECIPIENT_DEVICE, GET_STATUS, true) if setup.value == 0 => {
                // Local power good, no over-current, no changes.
                Ok(Outcome::Data(vec![0; 4]))
            }
            (CLASS, RECIPIENT_DEVICE, CLEAR_FEATURE, false)
                if matches!(setup.value, C_HUB_LOCAL_POWER | C_HUB_OVER_CURRENT) =>
            {
                Ok(Outcome::Done)
            }
            (CLASS, RECIPIENT_OTHER, GET_STATUS, true) if setup.value == 0 => {
                let (_, port) = self.port(setup.index)?;
                let mut bytes = port.status.to_le_bytes().to_vec();
                bytes.extend_from_slice(&port.change.to_le_bytes());
                Ok(Outcome::Data(bytes))
            }
            (CLASS, RECIPIENT_OTHER, SET_FEATURE, false) => self.set_port_feature(setup),
            (CLASS, RECIPIENT_OTHER, CLEAR_FEATURE, false) => self.clear_port_feature(setup),
            (CLASS, RECIPIENT_OTHER, CLEAR_TT_BUFFER | RESET_TT, false) => {
                // Single TT: wIndex is the port for RESET_TT, 1 for
                // CLEAR_TT_BUFFER (11.24.2.3, 11.24.2.9).
                match setup.request {
                    RESET_TT => self.port(setup.index).map(|_| Outcome::Done),
                    _ => Ok(Outcome::Done),
                }
            }
            (STANDARD, RECIPIENT_INTERFACE, GET_STATUS, true) if setup.index == 0 => {
                Ok(Outcome::Data(vec![0, 0]))
            }
            (STANDARD, RECIPIENT_INTERFACE, GET_INTERFACE, true) if setup.index == 0 => {
                Ok(Outcome::Data(vec![0]))
            }
            (STANDARD, RECIPIENT_INTERFACE, SET_INTERFACE, false)
                if setup.index == 0 && setup.value == 0 =>
            {
                self.state.halted = false;
                Ok(Outcome::Done)
            }
            (STANDARD, RECIPIENT_ENDPOINT, GET_STATUS, true)
                if setup.index == u16::from(STATUS_ENDPOINT) =>
            {
                Ok(Outcome::Data(vec![u8::from(self.state.halted), 0]))
            }
            (STANDARD, RECIPIENT_ENDPOINT, CLEAR_FEATURE | SET_FEATURE, false)
                if setup.index == u16::from(STATUS_ENDPOINT) && setup.value == ENDPOINT_HALT =>
            {
                self.state.halted = setup.request == SET_FEATURE;
                Ok(Outcome::Done)
            }
            _ => Err(()),
        }
    }
}

impl<P: Ports> BusPeer for Hub<P> {
    /// A reset from the hub's own upstream port: Default state, every
    /// downstream port unpowered (11.24.2.7.1).
    fn reset(&mut self) -> Result<(), &'static str> {
        let (control, mut context) = self.context();
        control.reset(&mut context)?;
        self.state.ports.fill(Port::default());
        self.state.halted = false;
        Ok(())
    }

    fn packet(
        &mut self,
        endpoint: u8,
        token: Token,
        data: &mut [u8],
    ) -> Result<Reply, &'static str> {
        match (endpoint, token) {
            (0, _) => {
                let (control, mut context) = self.context();
                let reply = control.packet(token, data, &mut context);
                self.detect();
                reply
            }
            (_, Token::Setup) => Err("SETUP to a non-control endpoint"),
            (STATUS_ENDPOINT, Token::In) if self.control.configuration() != 0 => {
                if self.state.halted {
                    return Ok(Reply::Stall);
                }
                self.detect();
                match self.changes() {
                    0 => Ok(Reply::Nak),
                    bitmap if !data.is_empty() => {
                        data[0] = bitmap;
                        Ok(Reply::Ack(1))
                    }
                    _ => Err("status change IN without a buffer"),
                }
            }
            _ => Ok(Reply::Stall),
        }
    }
}

impl<P: Ports> Function for Hub<P> {
    fn set_time(&mut self, now: u64) {
        for n in 0..self.ports.count() {
            self.ports.function(n).set_time(now);
        }
        self.detect();
    }

    fn ready_at(&self, endpoint: u8) -> Option<u64> {
        let configured = self.control.configuration() != 0 && !self.state.halted;
        let attach = self.state.ports.iter().enumerate().any(|(n, port)| {
            port.status & bit(PORT_POWER) != 0
                && self.ports.attached(n) != (port.status & bit(PORT_CONNECTION) != 0)
        });
        (endpoint == STATUS_ENDPOINT && configured && (self.changes() != 0 || attach)).then_some(0)
    }

    fn downstream(&mut self, port: u8) -> Option<&mut dyn Function> {
        let n = self.usable(port)?;
        Some(self.ports.function(n))
    }

    fn downstream_ref(&self, port: u8) -> Option<&dyn Function> {
        let n = self.usable(port)?;
        Some(self.ports.function_ref(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::usb::control::{
        GET_CONFIGURATION, SET_ADDRESS, SET_CONFIGURATION,
        tests::{setup, transfer},
    };

    /// A function that counts its resets and answers one IN endpoint.
    #[derive(Default)]
    struct Probe {
        resets: usize,
        now: u64,
    }
    impl BusPeer for Probe {
        fn reset(&mut self) -> Result<(), &'static str> {
            self.resets += 1;
            Ok(())
        }
        fn packet(&mut self, _: u8, _: Token, _: &mut [u8]) -> Result<Reply, &'static str> {
            Ok(Reply::Ack(0))
        }
    }
    impl Function for Probe {
        fn set_time(&mut self, now: u64) {
            self.now = now;
        }
        fn ready_at(&self, _: u8) -> Option<u64> {
            None
        }
    }

    struct Two {
        functions: [Probe; 2],
        speeds: [Speed; 2],
        attached: [bool; 2],
    }
    impl Ports for Two {
        fn count(&self) -> usize {
            2
        }
        fn speed(&self, port: usize) -> Speed {
            self.speeds[port]
        }
        fn attached(&self, port: usize) -> bool {
            self.attached[port]
        }
        fn function(&mut self, port: usize) -> &mut dyn Function {
            &mut self.functions[port]
        }
        fn function_ref(&self, port: usize) -> &dyn Function {
            &self.functions[port]
        }
    }

    fn configured() -> Hub<Two> {
        let mut hub = Hub::new(
            Two {
                functions: Default::default(),
                speeds: [Speed::Full, Speed::High],
                attached: [true, true],
            },
            "HUB1",
        )
        .unwrap();
        let device = transfer(&mut hub, setup(0x80, GET_DESCRIPTOR, 0x100, 0, 18), &[]).unwrap();
        assert_eq!((device[4], device[5], device[6]), (9, 0, 1));
        transfer(&mut hub, setup(0, SET_ADDRESS, 3, 0, 0), &[]).unwrap();
        transfer(&mut hub, setup(0, SET_CONFIGURATION, 1, 0, 0), &[]).unwrap();
        assert_eq!(
            transfer(&mut hub, setup(0x80, GET_CONFIGURATION, 0, 0, 1), &[]).unwrap(),
            [1]
        );
        hub
    }

    fn port_status(hub: &mut Hub<Two>, port: u16) -> (u16, u16) {
        let bytes = transfer(hub, setup(0xa3, GET_STATUS, 0, port, 4), &[]).unwrap();
        (
            u16::from_le_bytes([bytes[0], bytes[1]]),
            u16::from_le_bytes([bytes[2], bytes[3]]),
        )
    }

    fn status_change(hub: &mut Hub<Two>) -> Reply {
        let mut byte = [0u8; 1];
        let reply = hub.packet(STATUS_ENDPOINT, Token::In, &mut byte).unwrap();
        if let Reply::Ack(1) = reply {
            return Reply::Ack(usize::from(byte[0]));
        }
        reply
    }

    #[test]
    fn descriptors_describe_a_two_port_single_tt_hub() {
        let mut hub = configured();
        let hub_descriptor =
            transfer(&mut hub, setup(0xa0, GET_DESCRIPTOR, 0x2900, 0, 71), &[]).unwrap();
        assert_eq!(hub_descriptor, [9, 0x29, 2, 0x09, 0, 5, 50, 0, 0xff]);
        let qualifier = transfer(&mut hub, setup(0x80, GET_DESCRIPTOR, 0x600, 0, 10), &[]).unwrap();
        assert_eq!(qualifier[6], 0, "no TT at full speed");
        let config = transfer(&mut hub, setup(0x80, GET_DESCRIPTOR, 0x200, 0, 255), &[]).unwrap();
        assert_eq!(&config[9..18], &[9, INTERFACE, 0, 0, 1, 9, 0, 0, 0]);
        assert_eq!(config[24], HIGH_SPEED_INTERVAL);
        assert_eq!(
            transfer(&mut hub, setup(0xa0, GET_STATUS, 0, 0, 4), &[]).unwrap(),
            [0; 4]
        );
    }

    #[test]
    fn powered_ports_connect_reset_and_route_to_their_functions() {
        let mut hub = configured();
        assert_eq!(status_change(&mut hub), Reply::Nak);
        assert!(hub.downstream(1).is_none());
        for port in 1..=2 {
            transfer(&mut hub, setup(0x23, SET_FEATURE, PORT_POWER, port, 0), &[]).unwrap();
        }
        assert_eq!(hub.ready_at(STATUS_ENDPOINT), Some(0));
        assert_eq!(status_change(&mut hub), Reply::Ack(0b110));
        assert_eq!(port_status(&mut hub, 1), (0x0101, 0x0001));
        transfer(
            &mut hub,
            setup(0x23, CLEAR_FEATURE, C_PORT_CONNECTION, 1, 0),
            &[],
        )
        .unwrap();
        transfer(&mut hub, setup(0x23, SET_FEATURE, PORT_RESET, 1, 0), &[]).unwrap();
        assert_eq!(port_status(&mut hub, 1), (0x0103, 0x0010));
        assert_eq!(hub.ports.functions[0].resets, 1);
        transfer(
            &mut hub,
            setup(0x23, CLEAR_FEATURE, C_PORT_RESET, 1, 0),
            &[],
        )
        .unwrap();
        transfer(&mut hub, setup(0x23, SET_FEATURE, PORT_RESET, 2, 0), &[]).unwrap();
        // The high-speed function reports high speed once enabled.
        assert_eq!(port_status(&mut hub, 2).0, 0x0503);
        assert!(hub.downstream(1).is_some() && hub.downstream_ref(2).is_some());
        assert!(hub.downstream(3).is_none() && hub.downstream(0).is_none());
        hub.set_time(77);
        assert_eq!(hub.ports.functions[1].now, 77);
        // Suspend hides the function until resume, which reports a change.
        transfer(&mut hub, setup(0x23, SET_FEATURE, PORT_SUSPEND, 1, 0), &[]).unwrap();
        assert!(hub.downstream(1).is_none());
        transfer(
            &mut hub,
            setup(0x23, CLEAR_FEATURE, PORT_SUSPEND, 1, 0),
            &[],
        )
        .unwrap();
        assert_eq!(port_status(&mut hub, 1), (0x0103, 0x0004));
        assert!(hub.downstream(1).is_some());
    }

    #[test]
    fn detach_power_off_and_unsupported_features() {
        let mut hub = configured();
        transfer(&mut hub, setup(0x23, SET_FEATURE, PORT_POWER, 1, 0), &[]).unwrap();
        transfer(&mut hub, setup(0x23, SET_FEATURE, PORT_RESET, 1, 0), &[]).unwrap();
        hub.ports.attached[0] = false;
        assert_eq!(hub.ready_at(STATUS_ENDPOINT), Some(0));
        hub.set_time(1);
        assert_eq!(port_status(&mut hub, 1), (0x0100, 0x0011));
        assert!(hub.downstream(1).is_none());
        transfer(&mut hub, setup(0x23, CLEAR_FEATURE, PORT_POWER, 1, 0), &[]).unwrap();
        assert_eq!(port_status(&mut hub, 1).0, 0);
        for feature in [21, 22] {
            assert!(transfer(&mut hub, setup(0x23, SET_FEATURE, feature, 1, 0), &[]).is_err());
        }
        assert!(transfer(&mut hub, setup(0xa3, 10, 0, 1, 4), &[]).is_err());
        assert!(transfer(&mut hub, setup(0x23, SET_FEATURE, PORT_POWER, 3, 0), &[]).is_err());
        transfer(&mut hub, setup(0x23, CLEAR_TT_BUFFER, 0x0081, 1, 0), &[]).unwrap();
        transfer(&mut hub, setup(0x23, RESET_TT, 0, 1, 0), &[]).unwrap();
        // A halted status endpoint STALLs until cleared.
        transfer(&mut hub, setup(0x02, SET_FEATURE, 0, 0x81, 0), &[]).unwrap();
        assert_eq!(status_change(&mut hub), Reply::Stall);
        transfer(&mut hub, setup(0x02, CLEAR_FEATURE, 0, 0x81, 0), &[]).unwrap();
        assert_eq!(status_change(&mut hub), Reply::Ack(0b10));
        hub.reset().unwrap();
        assert_eq!(hub.state.ports, [Port::default(); 2]);
    }
}
