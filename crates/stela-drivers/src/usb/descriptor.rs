//! The controller-neutral USB device framework: standard requests, SETUP
//! packets and the interfaces and endpoints of a configuration descriptor
//! (USB 2.0 9.3, 9.4 and 9.6, USB 3.2 9.6.7), for every host controller.
use alloc::vec::Vec;

// bmRequestType: direction, type and recipient (USB 2.0 Table 9-2).
pub const DEVICE_TO_HOST: u8 = 0x80;
pub const TYPE_CLASS: u8 = 0x20;
pub const TYPE_VENDOR: u8 = 0x40;
pub const RECIPIENT_INTERFACE: u8 = 0x01;
pub const RECIPIENT_ENDPOINT: u8 = 0x02;
pub const RECIPIENT_OTHER: u8 = 0x03;

// Standard requests and descriptors (USB 2.0 9.4, 9.6).
pub const GET_STATUS: u8 = 0;
pub const CLEAR_FEATURE: u8 = 1;
pub const SET_FEATURE: u8 = 3;
pub const GET_DESCRIPTOR: u8 = 6;
pub const SET_CONFIGURATION: u8 = 9;
pub const SET_INTERFACE: u8 = 11;
pub const DEVICE_DESCRIPTOR: u8 = 1;
pub const CONFIGURATION_DESCRIPTOR: u8 = 2;
pub const STRING_DESCRIPTOR: u8 = 3;
pub const INTERFACE_DESCRIPTOR: u8 = 4;
pub const ENDPOINT_DESCRIPTOR: u8 = 5;
pub const INTERFACE_ASSOCIATION_DESCRIPTOR: u8 = 11;
pub(crate) const SS_ENDPOINT_COMPANION: u8 = 0x30;

/// An eight-byte SETUP packet.
pub fn setup(request_type: u8, request: u8, value: u16, index: u16, length: u16) -> [u8; 8] {
    let [v0, v1] = value.to_le_bytes();
    let [i0, i1] = index.to_le_bytes();
    let [l0, l1] = length.to_le_bytes();
    [request_type, request, v0, v1, i0, i1, l0, l1]
}

/// USB 3.x endpoint companion, kept with the endpoint it immediately follows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SuperSpeedCompanion {
    pub max_burst: u8,
    pub attributes: u8,
    pub bytes_per_interval: u16,
}

/// An endpoint as its descriptor describes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub address: u8,
    pub attributes: u8,
    pub max_packet: u16,
    pub interval: u8,
    pub companion: Option<SuperSpeedCompanion>,
}

impl Endpoint {
    pub fn is_in(&self) -> bool {
        self.address & 0x80 != 0
    }
    pub fn kind(&self) -> u8 {
        self.attributes & 3
    }
}

/// One interface setting from a configuration descriptor, with the class
/// descriptors that follow it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub number: u8,
    pub alternate: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub endpoints: Vec<Endpoint>,
    /// Descriptors between this interface's and the next one's, endpoints
    /// excluded, whole (length and type first).
    pub extra: Vec<Vec<u8>>,
}

/// The interfaces of a configuration descriptor, in order.
pub fn interfaces(configuration: &[u8]) -> Vec<Interface> {
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut at = 0;
    let mut preceding_endpoint = false;
    while at + 2 <= configuration.len() {
        let length = usize::from(configuration[at]);
        if length < 2 || at + length > configuration.len() {
            break;
        }
        let d = &configuration[at..at + length];
        match d[1] {
            INTERFACE_DESCRIPTOR if length >= 9 => interfaces.push(Interface {
                number: d[2],
                alternate: d[3],
                class: d[5],
                subclass: d[6],
                protocol: d[7],
                endpoints: Vec::new(),
                extra: Vec::new(),
            }),
            ENDPOINT_DESCRIPTOR if length >= 7 => {
                if let Some(interface) = interfaces.last_mut() {
                    interface.endpoints.push(Endpoint {
                        address: d[2],
                        attributes: d[3],
                        max_packet: u16::from_le_bytes([d[4], d[5]]),
                        interval: d[6],
                        companion: None,
                    });
                }
            }
            _ => {
                if let Some(interface) = interfaces.last_mut() {
                    if d[1] == SS_ENDPOINT_COMPANION
                        && length == 6
                        && preceding_endpoint
                        && let Some(endpoint) = interface.endpoints.last_mut()
                    {
                        endpoint.companion = Some(SuperSpeedCompanion {
                            max_burst: d[2],
                            attributes: d[3],
                            bytes_per_interval: u16::from_le_bytes([d[4], d[5]]),
                        });
                    }
                    // Preserve the original bytes, including recognized companions.
                    interface.extra.push(d.to_vec());
                }
            }
        }
        preceding_endpoint = d[1] == ENDPOINT_DESCRIPTOR && length >= 7;
        at += length;
    }
    interfaces
}
