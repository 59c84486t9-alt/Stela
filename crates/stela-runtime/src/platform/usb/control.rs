//! The default control pipe of a native function: setup, data and status
//! stages packet by packet, and the standard device requests (USB 2.0
//! sections 8.5.3, 9.3 and 9.4).
//!
//! [`Control`] owns the device state USB 2.0 9.1 defines (Default,
//! Address, Configured), answers the device-recipient standard requests
//! from the function's [`Descriptors`], and hands every other request
//! (interface and endpoint recipients, class and vendor requests) to the
//! function's [`Requests`]. A request either side does not implement is a
//! request error: the pipe STALLs until the next SETUP (8.5.3.4).
//!
//! Remote wakeup and test modes are not supported: the configuration
//! descriptors say so (bmAttributes bit 5 clear), and SET_FEATURE of
//! DEVICE_REMOTE_WAKEUP or TEST_MODE STALLs.
use super::{Reply, Token};
use alloc::{string::String, vec::Vec};

pub const EP0_PACKET: usize = 64;

pub const GET_STATUS: u8 = 0;
pub const CLEAR_FEATURE: u8 = 1;
pub const SET_FEATURE: u8 = 3;
pub const SET_ADDRESS: u8 = 5;
pub const GET_DESCRIPTOR: u8 = 6;
pub const GET_CONFIGURATION: u8 = 8;
pub const SET_CONFIGURATION: u8 = 9;
pub const GET_INTERFACE: u8 = 10;
pub const SET_INTERFACE: u8 = 11;
pub const ENDPOINT_HALT: u16 = 0;

pub const DEVICE: u8 = 1;
pub const CONFIGURATION: u8 = 2;
pub const STRING: u8 = 3;
pub const INTERFACE: u8 = 4;
pub const ENDPOINT: u8 = 5;
pub const DEVICE_QUALIFIER: u8 = 6;
pub const OTHER_SPEED_CONFIGURATION: u8 = 7;
const ENGLISH: u16 = 0x0409;

/// bmRequestType fields (9.3.1).
pub const DEVICE_TO_HOST: u8 = 0x80;
pub const STANDARD: u8 = 0x00;
pub const CLASS: u8 = 0x20;
pub const RECIPIENT_DEVICE: u8 = 0;
pub const RECIPIENT_INTERFACE: u8 = 1;
pub const RECIPIENT_ENDPOINT: u8 = 2;
pub const RECIPIENT_OTHER: u8 = 3;

/// One SETUP packet's fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setup {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

impl Setup {
    pub fn parse(bytes: [u8; 8]) -> Self {
        Self {
            request_type: bytes[0],
            request: bytes[1],
            value: u16::from_le_bytes([bytes[2], bytes[3]]),
            index: u16::from_le_bytes([bytes[4], bytes[5]]),
            length: u16::from_le_bytes([bytes[6], bytes[7]]),
        }
    }

    pub fn device_to_host(&self) -> bool {
        self.request_type & DEVICE_TO_HOST != 0
    }

    pub fn kind(&self) -> u8 {
        self.request_type & 0x60
    }

    pub fn recipient(&self) -> u8 {
        self.request_type & 0x1f
    }
}

/// A request's outcome before its status stage. `Err(())` is a request
/// error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// IN data; the host may take fewer bytes than this.
    Data(Vec<u8>),
    /// No data stage, or OUT data accepted.
    Done,
}

/// What a function says about itself to the standard requests.
#[derive(Debug, Clone)]
pub struct Descriptors {
    pub device: [u8; 18],
    /// The configuration at the current speed, complete with its interface,
    /// class and endpoint descriptors.
    pub configuration: Vec<u8>,
    /// A high-speed capable device's qualifier and other-speed
    /// configuration (9.6.2, 9.6.4); `None` for a full-speed-only device,
    /// which STALLs those requests.
    pub other_speed: Option<([u8; 10], Vec<u8>)>,
    /// String descriptors 1.. in US English.
    pub strings: Vec<String>,
}

/// String descriptor `text` (9.6.7).
pub fn string(text: &str) -> Vec<u8> {
    let mut bytes = alloc::vec![0, STRING];
    bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    bytes[0] = bytes.len() as u8;
    bytes
}

/// A configuration descriptor of `parts` (interfaces, class-specific and
/// endpoint descriptors), with its total length and interface count.
pub fn configuration(value: u8, power_ma: u16, parts: &[&[u8]]) -> Vec<u8> {
    let mut bytes = alloc::vec![
        9,
        CONFIGURATION,
        0,
        0,
        0,
        value,
        0,
        0xc0,
        (power_ma / 2) as u8
    ];
    let mut interfaces = 0;
    for part in parts {
        if part.get(1) == Some(&INTERFACE) && part.get(3) == Some(&0) {
            interfaces += 1;
        }
        bytes.extend_from_slice(part);
    }
    let total = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&total.to_le_bytes());
    bytes[4] = interfaces;
    bytes
}

/// The class, vendor, interface and endpoint requests of a function.
pub trait Requests {
    /// The host selected configuration `value` (0: back to Address).
    /// `Err(())` refuses a value the device does not have.
    fn configure(&mut self, value: u8) -> Result<(), ()>;
    /// A request [`Control`] does not answer itself, with its OUT data.
    fn request(&mut self, setup: Setup, data: &[u8]) -> Result<Outcome, ()>;
}

#[derive(Debug, Clone)]
enum Stage {
    Idle,
    In {
        data: Vec<u8>,
        sent: usize,
        /// The host's wLength.
        length: usize,
        done: bool,
    },
    Out {
        setup: Setup,
        data: Vec<u8>,
    },
    /// The status stage of a request that succeeded; SET_ADDRESS takes
    /// effect after it (9.4.6).
    Status(Option<u8>),
    Stalled,
}

#[derive(Debug, Clone)]
pub struct Control {
    pub descriptors: Descriptors,
    address: u8,
    configuration: u8,
    stage: Stage,
}

impl Control {
    pub fn new(descriptors: Descriptors) -> Self {
        Self {
            descriptors,
            address: 0,
            configuration: 0,
            stage: Stage::Idle,
        }
    }

    #[cfg(test)]
    pub fn address(&self) -> u8 {
        self.address
    }

    pub fn configuration(&self) -> u8 {
        self.configuration
    }

    /// A bus reset: back to the Default state (9.1.1.3).
    pub fn reset(&mut self, requests: &mut dyn Requests) -> Result<(), &'static str> {
        self.address = 0;
        self.stage = Stage::Idle;
        if self.configuration != 0 {
            self.configuration = 0;
            requests
                .configure(0)
                .map_err(|()| "function refused deconfiguration at reset")?;
        }
        Ok(())
    }

    /// One transaction on endpoint 0.
    pub fn packet(
        &mut self,
        token: Token,
        data: &mut [u8],
        requests: &mut dyn Requests,
    ) -> Result<Reply, &'static str> {
        Ok(match token {
            Token::Setup => {
                let bytes = <[u8; 8]>::try_from(&*data).map_err(|_| "a SETUP packet is 8 bytes")?;
                self.setup(Setup::parse(bytes), requests);
                Reply::Ack(8)
            }
            Token::In => self.control_in(data),
            Token::Out => self.control_out(data, requests),
        })
    }

    fn setup(&mut self, setup: Setup, requests: &mut dyn Requests) {
        self.stage = if !setup.device_to_host() && setup.length != 0 {
            Stage::Out {
                setup,
                data: Vec::new(),
            }
        } else {
            match self.request(setup, &[], requests) {
                Ok((Outcome::Data(mut data), _)) if setup.device_to_host() => {
                    data.truncate(usize::from(setup.length));
                    Stage::In {
                        done: setup.length == 0,
                        data,
                        sent: 0,
                        length: usize::from(setup.length),
                    }
                }
                Ok((Outcome::Done, effect)) if setup.length == 0 => Stage::Status(effect),
                _ => Stage::Stalled,
            }
        };
    }

    fn control_in(&mut self, buffer: &mut [u8]) -> Reply {
        match &mut self.stage {
            Stage::In {
                data,
                sent,
                length,
                done,
            } if !*done => {
                let n = (data.len() - *sent).min(EP0_PACKET).min(buffer.len());
                buffer[..n].copy_from_slice(&data[*sent..*sent + n]);
                *sent += n;
                // A short (possibly zero-length) packet, or exactly the
                // requested length, ends the data stage (8.5.3.2).
                *done = n < EP0_PACKET || *sent == *length;
                Reply::Ack(n)
            }
            Stage::Status(effect) => {
                if let Some(address) = *effect {
                    self.address = address;
                }
                self.stage = Stage::Idle;
                Reply::Ack(0)
            }
            _ => {
                self.stage = Stage::Stalled;
                Reply::Stall
            }
        }
    }

    fn control_out(&mut self, data: &[u8], requests: &mut dyn Requests) -> Reply {
        match &mut self.stage {
            // The host's status stage, after all or part of the IN data.
            Stage::In { .. } if data.is_empty() => {
                self.stage = Stage::Idle;
                Reply::Ack(0)
            }
            Stage::Out {
                setup,
                data: so_far,
            } => {
                so_far.extend_from_slice(data);
                let length = usize::from(setup.length);
                if so_far.len() < length && data.len() == EP0_PACKET {
                    return Reply::Ack(data.len());
                }
                let (setup, so_far) = (*setup, core::mem::take(so_far));
                self.stage = match self.request(setup, &so_far, requests) {
                    Ok((Outcome::Done, effect)) if so_far.len() == length => Stage::Status(effect),
                    _ => Stage::Stalled,
                };
                Reply::Ack(data.len())
            }
            _ => {
                self.stage = Stage::Stalled;
                Reply::Stall
            }
        }
    }

    /// Evaluates a request whose data stage, if any, is complete; the
    /// second value is a deferred address.
    fn request(
        &mut self,
        setup: Setup,
        data: &[u8],
        requests: &mut dyn Requests,
    ) -> Result<(Outcome, Option<u8>), ()> {
        let standard_device = setup.kind() == STANDARD && setup.recipient() == RECIPIENT_DEVICE;
        if !standard_device {
            // Interface and endpoint requests need a configuration
            // (9.4: undefined in the Address state), except endpoint 0's.
            let endpoint_zero = setup.recipient() == RECIPIENT_ENDPOINT && setup.index & 0x7f == 0;
            if setup.kind() == STANDARD && endpoint_zero {
                return match (setup.request, setup.device_to_host()) {
                    (GET_STATUS, true) => Ok((Outcome::Data(alloc::vec![0, 0]), None)),
                    (CLEAR_FEATURE, false) if setup.value == ENDPOINT_HALT => {
                        Ok((Outcome::Done, None))
                    }
                    _ => Err(()),
                };
            }
            if self.configuration == 0 && setup.kind() == STANDARD {
                return Err(());
            }
            return requests.request(setup, data).map(|outcome| (outcome, None));
        }
        let reply = |bytes: &[u8]| Ok((Outcome::Data(bytes.to_vec()), None));
        let d = &self.descriptors;
        match (setup.request, setup.device_to_host()) {
            // Self-powered (the configuration says so), no remote wakeup.
            (GET_STATUS, true) if setup.value == 0 && setup.index == 0 => reply(&[1, 0]),
            (SET_ADDRESS, false)
                if setup.value <= 127 && setup.index == 0 && self.configuration == 0 =>
            {
                Ok((Outcome::Done, Some(setup.value as u8)))
            }
            (GET_DESCRIPTOR, true) => match ((setup.value >> 8) as u8, setup.value as u8) {
                (DEVICE, 0) => reply(&d.device),
                (CONFIGURATION, 0) => reply(&d.configuration),
                (DEVICE_QUALIFIER, 0) => d.other_speed.as_ref().map_or(Err(()), |o| reply(&o.0)),
                (OTHER_SPEED_CONFIGURATION, 0) => {
                    d.other_speed
                        .as_ref()
                        .map_or(Err(()), |(_, configuration)| {
                            let mut bytes = configuration.clone();
                            bytes[1] = OTHER_SPEED_CONFIGURATION;
                            Ok((Outcome::Data(bytes), None))
                        })
                }
                (STRING, 0) => reply(&[4, STRING, 0x09, 0x04]),
                (STRING, n) if setup.index == ENGLISH => d
                    .strings
                    .get(usize::from(n) - 1)
                    .map_or(Err(()), |text| reply(&string(text))),
                _ => Err(()),
            },
            (GET_CONFIGURATION, true) => reply(&[self.configuration]),
            (SET_CONFIGURATION, false) if setup.value <= 255 && self.address != 0 => {
                let value = setup.value as u8;
                let ours = d.configuration.get(5).copied();
                if value != 0 && Some(value) != ours {
                    return Err(());
                }
                requests.configure(value)?;
                self.configuration = value;
                Ok((Outcome::Done, None))
            }
            _ => Err(()),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::platform::usb::BusPeer;

    /// A control transfer through `peer`'s endpoint 0, packet by packet as
    /// a host controller would run it: `Err` is a STALL.
    pub(crate) fn transfer(
        peer: &mut dyn BusPeer,
        setup: [u8; 8],
        out: &[u8],
    ) -> Result<Vec<u8>, ()> {
        assert_eq!(
            peer.packet(0, Token::Setup, &mut setup.clone()),
            Ok(Reply::Ack(8))
        );
        let length = usize::from(u16::from_le_bytes([setup[6], setup[7]]));
        let mut data = Vec::new();
        if setup[0] & 0x80 != 0 {
            while data.len() < length {
                let mut packet = [0u8; EP0_PACKET];
                match peer.packet(0, Token::In, &mut packet).unwrap() {
                    Reply::Ack(n) => {
                        data.extend_from_slice(&packet[..n]);
                        if n < EP0_PACKET {
                            break;
                        }
                    }
                    Reply::Stall => return Err(()),
                    Reply::Nak => panic!("control IN NAK"),
                }
            }
            match peer.packet(0, Token::Out, &mut []).unwrap() {
                Reply::Ack(0) => Ok(data),
                _ => Err(()),
            }
        } else {
            for chunk in out.chunks(EP0_PACKET) {
                if peer.packet(0, Token::Out, &mut chunk.to_vec()).unwrap() == Reply::Stall {
                    return Err(());
                }
            }
            match peer.packet(0, Token::In, &mut []).unwrap() {
                Reply::Ack(0) => Ok(data),
                _ => Err(()),
            }
        }
    }

    pub(crate) fn setup(
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        length: u16,
    ) -> [u8; 8] {
        let mut bytes = [request_type, request, 0, 0, 0, 0, 0, 0];
        bytes[2..4].copy_from_slice(&value.to_le_bytes());
        bytes[4..6].copy_from_slice(&index.to_le_bytes());
        bytes[6..8].copy_from_slice(&length.to_le_bytes());
        bytes
    }

    struct Echo {
        control: Control,
        configured: u8,
        stored: Vec<u8>,
    }

    impl Requests for (u8, Vec<u8>) {
        fn configure(&mut self, value: u8) -> Result<(), ()> {
            self.0 = value;
            Ok(())
        }
        fn request(&mut self, setup: Setup, data: &[u8]) -> Result<Outcome, ()> {
            match (setup.request_type, setup.request) {
                (0x41, 1) => {
                    self.1 = data.to_vec();
                    Ok(Outcome::Done)
                }
                (0xc1, 2) => Ok(Outcome::Data(self.1.clone())),
                _ => Err(()),
            }
        }
    }

    impl BusPeer for Echo {
        fn reset(&mut self) -> Result<(), &'static str> {
            let mut inner = (self.configured, core::mem::take(&mut self.stored));
            let result = self.control.reset(&mut inner);
            (self.configured, self.stored) = inner;
            result
        }
        fn packet(
            &mut self,
            endpoint: u8,
            token: Token,
            data: &mut [u8],
        ) -> Result<Reply, &'static str> {
            assert_eq!(endpoint, 0);
            let mut inner = (self.configured, core::mem::take(&mut self.stored));
            let reply = self.control.packet(token, data, &mut inner);
            (self.configured, self.stored) = inner;
            reply
        }
    }

    fn echo() -> Echo {
        let device = [
            18, DEVICE, 0, 2, 0, 0, 0, 64, 0x09, 0x12, 1, 0, 0, 1, 1, 0, 0, 1,
        ];
        let configuration = configuration(1, 100, &[&[9, INTERFACE, 0, 0, 0, 0xff, 0, 0, 0]]);
        Echo {
            control: Control::new(Descriptors {
                device,
                configuration: configuration.clone(),
                other_speed: Some((
                    [10, DEVICE_QUALIFIER, 0, 2, 0, 0, 0, 64, 1, 0],
                    configuration,
                )),
                strings: alloc::vec![String::from("Stela")],
            }),
            configured: 0,
            stored: Vec::new(),
        }
    }

    #[test]
    fn standard_requests_follow_the_device_states() {
        let mut d = echo();
        let device = transfer(&mut d, setup(0x80, GET_DESCRIPTOR, 0x100, 0, 64), &[]).unwrap();
        assert_eq!(device.len(), 18);
        // The host may ask for fewer bytes than the descriptor has.
        assert_eq!(
            transfer(&mut d, setup(0x80, GET_DESCRIPTOR, 0x100, 0, 8), &[])
                .unwrap()
                .len(),
            8
        );
        let config = transfer(&mut d, setup(0x80, GET_DESCRIPTOR, 0x200, 0, 255), &[]).unwrap();
        assert_eq!(u16::from_le_bytes([config[2], config[3]]), 18);
        assert_eq!(config[4], 1);
        let other = transfer(&mut d, setup(0x80, GET_DESCRIPTOR, 0x700, 0, 255), &[]).unwrap();
        assert_eq!(other[1], OTHER_SPEED_CONFIGURATION);
        assert_eq!(
            transfer(
                &mut d,
                setup(0x80, GET_DESCRIPTOR, 0x301, ENGLISH, 255),
                &[]
            )
            .unwrap(),
            string("Stela")
        );
        assert!(
            transfer(
                &mut d,
                setup(0x80, GET_DESCRIPTOR, 0x302, ENGLISH, 255),
                &[]
            )
            .is_err()
        );
        // Configuration needs an address; interface requests need both.
        assert!(transfer(&mut d, setup(0, SET_CONFIGURATION, 1, 0, 0), &[]).is_err());
        assert!(transfer(&mut d, setup(0x81, GET_STATUS, 0, 0, 2), &[]).is_err());
        transfer(&mut d, setup(0, SET_ADDRESS, 9, 0, 0), &[]).unwrap();
        assert_eq!(d.control.address(), 9);
        assert!(transfer(&mut d, setup(0, SET_CONFIGURATION, 2, 0, 0), &[]).is_err());
        transfer(&mut d, setup(0, SET_CONFIGURATION, 1, 0, 0), &[]).unwrap();
        assert_eq!(d.configured, 1);
        assert_eq!(
            transfer(&mut d, setup(0x80, GET_CONFIGURATION, 0, 0, 1), &[]).unwrap(),
            [1]
        );
        assert!(transfer(&mut d, setup(0, SET_FEATURE, 1, 0, 0), &[]).is_err());
        d.reset().unwrap();
        assert_eq!(
            (d.control.address(), d.control.configuration(), d.configured),
            (0, 0, 0)
        );
    }

    #[test]
    fn class_requests_reach_the_function_with_their_data() {
        let mut d = echo();
        transfer(&mut d, setup(0, SET_ADDRESS, 1, 0, 0), &[]).unwrap();
        transfer(&mut d, setup(0, SET_CONFIGURATION, 1, 0, 0), &[]).unwrap();
        let payload: Vec<u8> = (0..150).collect();
        transfer(&mut d, setup(0x41, 1, 0, 0, 150), &payload).unwrap();
        assert_eq!(
            transfer(&mut d, setup(0xc1, 2, 0, 0, 200), &[]).unwrap(),
            payload
        );
        // A reply of whole packets shorter than wLength ends with a ZLP.
        transfer(&mut d, setup(0x41, 1, 0, 0, 64), &payload[..64]).unwrap();
        assert_eq!(
            d.packet(0, Token::Setup, &mut setup(0xc1, 2, 0, 0, 200)),
            Ok(Reply::Ack(8))
        );
        let mut packet = [0u8; EP0_PACKET];
        assert_eq!(d.packet(0, Token::In, &mut packet), Ok(Reply::Ack(64)));
        assert_eq!(d.packet(0, Token::In, &mut packet), Ok(Reply::Ack(0)));
        assert_eq!(d.packet(0, Token::In, &mut packet), Ok(Reply::Stall));
        // An unknown request STALLs, and the next SETUP clears the stall.
        assert!(transfer(&mut d, setup(0xc1, 9, 0, 0, 1), &[]).is_err());
        assert_eq!(
            transfer(&mut d, setup(0x80, GET_CONFIGURATION, 0, 0, 1), &[]).unwrap(),
            [1]
        );
    }
}
