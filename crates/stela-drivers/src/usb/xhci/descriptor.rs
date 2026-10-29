//! A device's identity and the interfaces and endpoints of its
//! configuration descriptor (USB 2.0 9.6, USB 3.2 9.6.7).
use super::*;

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
    pub(in crate::usb) fn validate_context(&self, speed: u8) -> Result<(), BlockError> {
        endpoint::Context::new(self, speed).map(|_| ())
    }
    /// The endpoint's Device Context Index.
    pub fn dci(&self) -> u8 {
        let number = self.address & 0xf;
        2 * number + u8::from(self.address & 0x80 != 0)
    }
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

/// A device the controller addressed, with what it said about itself.
#[derive(Clone, Debug)]
pub struct Device {
    /// Complete original PLA_TCR0 read; matching uses the donor's normalized
    /// version mask below while diagnostics keep every observed register bit.
    pub vendor_ethernet_tcr: Option<u32>,
    /// Read-only vendor Ethernet chip identity observed before configuration
    /// selection, matching Linux r8152's cfgselector preflight. None means no
    /// verified identity; product IDs alone never select a vendor backend.
    pub vendor_ethernet_revision: Option<u16>,
    /// Opaque ownership of this exact addressed device, including slot generation.
    pub id: super::SlotId,
    /// Hardware slot number for diagnostics; never an ownership credential.
    pub slot: u8,
    pub speed: u8,
    /// Where it is: the controller's PCI function, root port and hub ports.
    pub location: String,
    pub descriptor: [u8; 18],
    /// Every complete configuration descriptor in GET_DESCRIPTOR index order.
    /// The descriptor's bConfigurationValue is independent of that index.
    pub configurations: Vec<Vec<u8>>,
    /// Selected configuration bytes; selection alone does not configure hardware.
    pub configuration: Vec<u8>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
    /// The language of the device's strings, when it has any.
    pub language: Option<u16>,
}

impl Device {
    pub fn configuration_value(&self) -> u8 {
        self.configuration.get(5).copied().unwrap_or(0)
    }
    /// A name for logs: the product string, or the IDs.
    pub fn name(&self) -> String {
        match &self.product {
            Some(product) => product.clone(),
            None => format!(
                "{:04x}:{:04x}",
                u16::from_le_bytes([self.descriptor[8], self.descriptor[9]]),
                u16::from_le_bytes([self.descriptor[10], self.descriptor[11]])
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_descriptors_split_into_interfaces_with_their_endpoints() {
        let configuration = [
            9, 2, 32, 0, 1, 1, 0, 0x80, 50, // configuration
            9, 4, 0, 0, 2, 8, 6, 0x50, 0, // interface
            7, 5, 0x81, 2, 0, 2, 0, // bulk in
            7, 5, 0x02, 2, 0, 2, 0, // bulk out
        ];
        let found = interfaces(&configuration);
        assert_eq!(found.len(), 1);
        assert_eq!(
            (found[0].class, found[0].subclass, found[0].protocol),
            (8, 6, 0x50)
        );
        assert_eq!(found[0].endpoints[0].dci(), 3);
        assert_eq!(found[0].endpoints[1].dci(), 4);
        assert_eq!(found[0].endpoints[0].max_packet, 512);
    }
}
