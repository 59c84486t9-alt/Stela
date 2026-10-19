//! SEP service discovery records, not RTKit roll-call bitmaps.
//!
//! `AppleSEPDiscovery::_msgReceived`, kernel file 0x2d64a00..0x2d64d1c:
//! opcode 0 gives a fourcc name and service ID; opcode 1 gives four OOL
//! capacity bytes for that ID. Only then does `_exposeNub` create a client.
//! The AP keys each record by ID and name, logs duplicates and panics on a
//! capacity record whose ID it has not seen (0x2d64ba4..0x2d64bc0) or whose
//! bytes change (0x2d64bec..0x2d64c28), so a catalog is advertised once, each
//! name before its capacities.
//!
//! The capacity bytes are, in order, the AP-to-SEP (send) OOL minimum and
//! maximum and the SEP-to-AP (receive) minimum and maximum, counted in SEP
//! pages: `AppleSEPDeviceService::getSendOolMinPages` .. `getReceiveOolMaxPages`
//! 0x2d7b9b8..0x2d7b9e8 read info bytes 5..8, and `getSepPageSize` 0x2d7b998
//! scales them by 16 KiB when the SEP node has `aarch64` (4 KiB otherwise).
//! `AppleSEPManager::_sendMessageGated` 0x2d6abb8..0x2d6abc4 sends only to
//! IDs below 0x20 (or the boot services), so application IDs are 1..=0x1f.
use super::message::{self, Frame};
use alloc::vec::Vec;

const ADVERTISE_NAME: u8 = 0;
const ADVERTISE_CAPACITIES: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Service {
    pub id: u8,
    /// The protocol's raw fourcc integer; no host-endian string conversion.
    pub name: u32,
    /// [send minimum, send maximum, receive minimum, receive maximum] pages.
    pub capacities: [u8; 4],
}

/// The largest application service ID the AP will address.
pub const MAX_SERVICE: u8 = 0x1f;

impl Service {
    /// Whether an OOL registration of `bytes` in the given direction fits the
    /// advertised page range (`input`: AP-to-SEP).
    pub fn accepts(&self, input: bool, bytes: u32, page: u32) -> bool {
        let [minimum, maximum] = if input {
            [self.capacities[0], self.capacities[1]]
        } else {
            [self.capacities[2], self.capacities[3]]
        };
        maximum != 0 && (u32::from(minimum) * page..=u32::from(maximum) * page).contains(&bytes)
    }
}

/// An immutable catalog, supplied only for services with real implementations.
/// No allocation from an older sepOS endpoint map is built in.
pub struct Catalog {
    services: Vec<Service>,
}

impl Catalog {
    /// No implemented application service: discovery stays silent.
    pub fn empty() -> Self {
        Self {
            services: Vec::new(),
        }
    }

    pub fn new(services: Vec<Service>) -> Result<Self, &'static str> {
        for (index, service) in services.iter().enumerate() {
            if service.id == message::CONTROL || service.id > MAX_SERVICE {
                return Err("SEP application service IDs are 1..=0x1f");
            }
            let [send_min, send_max, receive_min, receive_max] = service.capacities;
            if send_min > send_max || receive_min > receive_max {
                return Err("SEP service OOL minimum exceeds its maximum");
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
        for id in [0, 0x20, message::DISCOVERY, message::BOOT, message::ROM] {
            assert!(Catalog::new(vec![Service { id, ..one }]).is_err());
        }
        assert!(
            Catalog::new(vec![Service {
                capacities: [2, 1, 0, 0],
                ..one
            }])
            .is_err()
        );
    }

    #[test]
    fn capacities_are_page_ranges_per_direction() {
        let xart = Service {
            id: 0x10,
            name: 0x7861_7273,
            capacities: [2, 2, 1, 2],
        };
        const PAGE: u32 = 0x4000;
        assert!(xart.accepts(true, 0x8000, PAGE));
        assert!(!xart.accepts(true, 0x4000, PAGE));
        assert!(xart.accepts(false, 0x4000, PAGE));
        assert!(!xart.accepts(false, 0x8001, PAGE));
        let silent = Service {
            capacities: [0; 4],
            ..xart
        };
        assert!(!silent.accepts(true, 0, PAGE));
    }
}
