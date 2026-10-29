//! Recover endpoint/pipe-usage association from original configuration bytes.
//! Interface.extra alone omits endpoint boundaries and cannot establish this.
// SPDX-License-Identifier: GPL-2.0-only
// Linux uas-detect.h::uas_find_endpoints at the crate's pinned reference.
use crate::usb::xhci::{Device, Endpoint, Interface};

#[derive(Clone, Debug)]
pub struct Binding {
    interface: u8,
    alternate: u8,
    configuration: u8,
    endpoints: [Endpoint; 4],
    pub(super) flags: super::quirks::Flags,
}
impl Binding {
    pub fn new(device: &Device, interface: &Interface) -> Result<Self, &'static str> {
        if (interface.class, interface.subclass, interface.protocol) != (8, 6, 0x62) {
            return Err("not SCSI-transparent UAS");
        }
        let mut binding = Self::from_raw(&device.configuration, interface)?;
        let vendor = u16::from_le_bytes(device.descriptor[8..10].try_into().unwrap());
        let product = u16::from_le_bytes(device.descriptor[10..12].try_into().unwrap());
        let revision = u16::from_le_bytes(device.descriptor[12..14].try_into().unwrap());
        binding.flags = super::quirks::Flags::from_id(vendor, product, revision);
        let streams = binding.endpoints[1]
            .companion
            .map_or(0, |c| c.attributes & 31);
        if binding.flags.ignored()
            || dynamic_ignored(
                vendor,
                product,
                device.speed,
                device.configuration[8],
                streams,
                device.manufacturer.as_deref(),
                device.product.as_deref(),
            )
        {
            return Err("source-listed enclosure requires BOT instead of UAS");
        }
        // The accepted nonzero-power ASM105x profile is the source's
        // ASM1053 branch, which must keep its 240-sector transfer ceiling.
        // Preserve the policy even while the current native TD limit is lower.
        if vendor == 0x174c && matches!(product, 0x5106 | 0x55aa) && device.configuration[8] != 0 {
            binding.flags = binding.flags.limit_to_240_sectors();
        }
        Ok(binding)
    }
    fn from_raw(raw: &[u8], interface: &Interface) -> Result<Self, &'static str> {
        if raw.len() < 9
            || raw[0] != 9
            || raw[1] != 2
            || usize::from(u16::from_le_bytes([raw[2], raw[3]])) != raw.len()
            || raw[5] == 0
        {
            return Err("invalid UAS configuration inventory");
        }
        let mut endpoints = [None; 4];
        let mut active = false;
        let mut found = false;
        let mut preceding = None;
        let mut at = 0;
        let mut count = 0;
        let mut endpoint_bitmap = 0u32;
        while at < raw.len() {
            let length = usize::from(*raw.get(at).ok_or("truncated UAS descriptor")?);
            if length < 2 || at.checked_add(length).is_none_or(|end| end > raw.len()) {
                return Err("truncated UAS descriptor");
            }
            let d = &raw[at..at + length];
            match d[1] {
                4 => {
                    if length < 9 {
                        return Err("short UAS interface descriptor");
                    }
                    active = d[2] == interface.number && d[3] == interface.alternate;
                    preceding = None;
                    if active {
                        if found
                            || (d[5], d[6], d[7]) != (8, 6, 0x62)
                            || usize::from(d[4]) != interface.endpoints.len()
                        {
                            return Err("UAS interface inventory disagreement");
                        }
                        found = true;
                    }
                }
                5 if active => {
                    if length < 7 {
                        return Err("short UAS endpoint descriptor");
                    }
                    let endpoint = interface
                        .endpoints
                        .iter()
                        .copied()
                        .find(|ep| ep.address == d[2])
                        .ok_or("UAS endpoint absent from inventory")?;
                    if endpoint.attributes != d[3]
                        || endpoint.max_packet != u16::from_le_bytes([d[4], d[5]])
                        || endpoint.interval != d[6]
                        || endpoint.kind() != 2
                        || endpoint.address & 0x7f == 0
                        || endpoint.address & 0x70 != 0
                    {
                        return Err("UAS endpoint inventory disagreement");
                    }
                    if endpoint_bitmap & (1u32 << endpoint.dci()) != 0 {
                        return Err("duplicate UAS endpoint address");
                    }
                    endpoint_bitmap |= 1u32 << endpoint.dci();
                    preceding = Some(endpoint);
                    count += 1;
                }
                0x24 if active => {
                    if length != 4 || !(1..=4).contains(&d[2]) {
                        return Err("invalid UAS pipe usage descriptor");
                    }
                    let ep = preceding.ok_or("orphan UAS pipe usage descriptor")?;
                    let index = usize::from(d[2] - 1);
                    if endpoints[index].is_some()
                        || endpoints
                            .iter()
                            .flatten()
                            .any(|old: &Endpoint| old.address == ep.address)
                    {
                        return Err("duplicate UAS pipe usage");
                    }
                    let expected_in = matches!(index, 1 | 2);
                    if ep.is_in() != expected_in {
                        return Err("wrong UAS pipe direction");
                    }
                    endpoints[index] = Some(ep);
                }
                _ => {}
            }
            at += length;
        }
        if !found || count != interface.endpoints.len() || endpoints.iter().any(Option::is_none) {
            return Err("incomplete UAS pipe inventory");
        }
        Ok(Self {
            interface: interface.number,
            alternate: interface.alternate,
            configuration: raw[5],
            endpoints: endpoints.map(Option::unwrap),
            flags: super::quirks::Flags::default(),
        })
    }
    pub fn interface(&self) -> u8 {
        self.interface
    }
    pub fn alternate(&self) -> u8 {
        self.alternate
    }
    pub fn configuration_value(&self) -> u8 {
        self.configuration
    }
    /// Only status/data endpoints use the common nonzero UAS tag as Stream ID.
    pub fn stream_endpoints(&self) -> [u8; 3] {
        [
            self.endpoints[1].address,
            self.endpoints[2].address,
            self.endpoints[3].address,
        ]
    }
    /// Command OUT, status IN, data IN, data OUT, from pipe-usage IDs.
    pub fn endpoints(&self) -> [Endpoint; 4] {
        self.endpoints
    }
}

fn dynamic_ignored(
    vendor: u16,
    product: u16,
    speed: u8,
    power: u8,
    status_streams: u8,
    manufacturer: Option<&str>,
    model: Option<&str>,
) -> bool {
    (vendor == 0x174c
        && matches!(product, 0x5106 | 0x55aa)
        && power != 0
        && (speed < crate::usb::xhci::SUPER_SPEED || status_streams == 5))
        || (vendor == 0x0bda
            && product == 0x9210
            && manufacturer == Some("HIKSEMI")
            && model == Some("MD202"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    fn raw(order: [u8; 4]) -> Vec<u8> {
        let mut raw = vec![9, 2, 0, 0, 1, 1, 0, 0x80, 50, 9, 4, 2, 1, 4, 8, 6, 0x62, 0];
        for pipe in order {
            let address = [1, 0x82, 0x83, 4][usize::from(pipe - 1)];
            raw.extend_from_slice(&[7, 5, address, 2, 0, 2, 0]);
            // Real class descriptors may follow an SS companion/other extra;
            // association remains with the exact preceding endpoint.
            raw.extend_from_slice(&[3, 0x25, 0]);
            raw.extend_from_slice(&[4, 0x24, pipe, 0]);
        }
        let length = raw.len() as u16;
        raw[2..4].copy_from_slice(&length.to_le_bytes());
        raw
    }
    #[test]
    fn pipe_roles_follow_endpoint_boundaries_in_every_descriptor_order() {
        for a in 1..=4 {
            for b in 1..=4 {
                for c in 1..=4 {
                    for d in 1..=4 {
                        if [a, b, c, d]
                            .iter()
                            .enumerate()
                            .any(|(i, x)| [a, b, c, d][..i].contains(x))
                        {
                            continue;
                        }
                        let raw = raw([a, b, c, d]);
                        let interface = crate::usb::xhci::interfaces(&raw).remove(0);
                        let binding = Binding::from_raw(&raw, &interface).unwrap();
                        assert_eq!(binding.endpoints().map(|ep| ep.address), [1, 0x82, 0x83, 4]);
                        assert_eq!(binding.alternate(), 1);
                    }
                }
            }
        }
    }
    #[test]
    fn orphan_duplicate_missing_wrong_direction_and_truncation_never_bind() {
        let original = raw([1, 2, 3, 4]);
        for mutation in 0..5 {
            let mut raw = original.clone();
            match mutation {
                0 => raw[18..22].copy_from_slice(&[4, 0x24, 1, 0]),
                1 => raw[18 + 14 + 12] = 1,
                2 => raw[18 + 12] = 0,
                3 => raw[18 + 2] = 0x81,
                _ => {
                    raw.pop();
                }
            }
            let mut interfaces = crate::usb::xhci::interfaces(&raw);
            let interface = interfaces.remove(0);
            assert!(
                Binding::from_raw(&raw, &interface).is_err(),
                "mutation {mutation}"
            );
        }
    }
    #[test]
    fn accepted_asm1053_binding_keeps_240_sector_limit_and_asm1153_does_not() {
        for power in [0, 36] {
            let original = raw([1, 2, 3, 4]);
            let mut configuration = original[..18].to_vec();
            configuration[8] = power;
            for (index, endpoint) in original[18..].as_chunks::<14>().0.iter().enumerate() {
                configuration.extend_from_slice(&endpoint[..7]);
                configuration.extend_from_slice(&[6, 48, 0, if index == 0 { 0 } else { 4 }, 0, 0]);
                configuration.extend_from_slice(&endpoint[10..]);
            }
            let length = configuration.len() as u16;
            configuration[2..4].copy_from_slice(&length.to_le_bytes());
            let interface = crate::usb::xhci::interfaces(&configuration).remove(0);
            let mut device = crate::usb::xhci::model::device(vec![configuration.clone()]);
            device.configuration = configuration;
            device.speed = crate::usb::xhci::SUPER_SPEED;
            device.descriptor[8..12].copy_from_slice(&[0x4c, 0x17, 0xaa, 0x55]);
            let binding = Binding::new(&device, &interface).unwrap();
            assert_eq!(binding.flags.bits() & 128 != 0, power != 0);
            assert_eq!(binding.flags.max_transfer_bytes(), super::super::MAX_TD);
        }
    }
    #[test]
    fn source_dynamic_bridge_policy_uses_observed_revision_capacity_and_strings() {
        assert!(dynamic_ignored(0x174c, 0x5106, 3, 36, 0, None, None));
        assert!(dynamic_ignored(0x174c, 0x55aa, 4, 36, 5, None, None));
        assert!(!dynamic_ignored(0x174c, 0x55aa, 4, 0, 5, None, None));
        assert!(!dynamic_ignored(0x174c, 0x55aa, 4, 36, 4, None, None));
        assert!(dynamic_ignored(
            0x0bda,
            0x9210,
            4,
            0,
            0,
            Some("HIKSEMI"),
            Some("MD202")
        ));
        assert!(!dynamic_ignored(
            0x0bda,
            0x9210,
            4,
            0,
            0,
            None,
            Some("MD202")
        ));
    }
}
