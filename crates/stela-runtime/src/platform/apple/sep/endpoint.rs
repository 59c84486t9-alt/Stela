//! SEP service discovery records, not RTKit roll-call bitmaps.
//!
//! `AppleSEPDiscovery::_msgReceived`, kernel file 0x2d64a00..0x2d64d1c:
//! opcode 0 gives a fourcc name and service ID; opcode 1 gives four OOL
//! capacity bytes for that ID. Only then does `_exposeNub` create a client.
//! Capacities remain opaque until their units and directions are recovered;
//! this module must not allocate buffers or acknowledge OOL setup from them.
use super::message::{self, Frame};
use alloc::vec::Vec;

const ADVERTISE_NAME: u8 = 0;
const ADVERTISE_CAPACITIES: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Service {
    pub id: u8,
    /// The protocol's raw fourcc integer; no host-endian string conversion.
    pub name: u32,
    pub capacities: [u8; 4],
}

/// An immutable catalog, supplied only for services with real implementations.
/// No allocation from an older sepOS endpoint map is built in.
pub struct Catalog {
    services: Vec<Service>,
}

impl Catalog {
    pub fn new(services: Vec<Service>) -> Result<Self, &'static str> {
        for (index, service) in services.iter().enumerate() {
            if service.id >= message::DISCOVERY {
                return Err("SEP discovery/boot IDs cannot name application services");
            }
            if services[..index]
                .iter()
                .any(|s| s.id == service.id || s.name == service.name)
            {
                return Err("SEP service IDs and names must each be unique");
            }
        }
        Ok(Self { services })
    }

    /// Stage all advertisements in validated catalog order, with each name
    /// preceding its capacity record. This does not start or enable a service.
    pub fn advertisements(&self) -> Vec<Frame> {
        self.services
            .iter()
            .flat_map(|service| {
                [
                    Frame {
                        service: message::DISCOVERY,
                        tag: 0,
                        opcode: ADVERTISE_NAME,
                        parameter: service.id,
                        data: service.name,
                    },
                    Frame {
                        service: message::DISCOVERY,
                        tag: 0,
                        opcode: ADVERTISE_CAPACITIES,
                        parameter: service.id,
                        data: u32::from_le_bytes(service.capacities),
                    },
                ]
            })
            .collect()
    }

    pub fn service(&self, id: u8) -> Result<&Service, &'static str> {
        self.services
            .iter()
            .find(|s| s.id == id)
            .ok_or("SEP service is not implemented")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn service_ids_are_discovered_not_taken_from_rtkit_or_a_firmware_version() {
        let one = Service {
            id: 0x12,
            name: 0x736b_7300,
            capacities: [1, 2, 3, 4],
        };
        let two = Service {
            id: 0x1b,
            name: 0x7879_7a00,
            capacities: [0; 4],
        };
        let catalog = Catalog::new(vec![one, two]).unwrap();
        let messages = catalog.advertisements();
        assert_eq!(messages.len(), 4);
        assert_eq!(
            (
                messages[0].service,
                messages[0].opcode,
                messages[0].parameter,
                messages[0].data
            ),
            (message::DISCOVERY, 0, 0x12, 0x736b_7300)
        );
        assert_eq!(
            (messages[1].opcode, messages[1].parameter, messages[1].data),
            (1, 0x12, 0x0403_0201)
        );
        assert_eq!(catalog.service(0x1b), Ok(&two));
        assert!(catalog.service(0x13).is_err());
        assert!(Catalog::new(vec![one, Service { id: one.id, ..two }]).is_err());
        assert!(
            Catalog::new(vec![
                one,
                Service {
                    name: one.name,
                    ..two
                }
            ])
            .is_err()
        );
        for id in [message::DISCOVERY, message::BOOT, message::ROM] {
            assert!(Catalog::new(vec![Service { id, ..one }]).is_err());
        }
    }
}
