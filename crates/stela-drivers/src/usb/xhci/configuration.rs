//! Complete configuration validation and class-driver-based selection. USB 2.0
//! 9.6.3/9.6.5/9.6.6: descriptor indices, values and alternate settings are
//! separate namespaces. Unknown class descriptors remain in the raw inventory.
use super::*;

pub(super) fn validate(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.len() < 9
        || bytes[0] != 9
        || bytes[1] != CONFIGURATION_DESCRIPTOR
        || usize::from(u16::from_le_bytes([bytes[2], bytes[3]])) != bytes.len()
        || bytes[5] == 0
    {
        return Err("invalid USB configuration header/length/value");
    }
    let mut settings = Vec::new();
    let mut numbers = Vec::new();
    let mut zero = Vec::new();
    let mut active_endpoints = Vec::new();
    let mut setting_endpoints = Vec::new();
    let mut interface = None;
    let mut at = 9;
    while at < bytes.len() {
        if at + 2 > bytes.len() {
            return Err("truncated USB descriptor");
        }
        let length = usize::from(bytes[at]);
        if length < 2 || at + length > bytes.len() {
            return Err("invalid USB descriptor length");
        }
        let d = &bytes[at..at + length];
        match d[1] {
            CONFIGURATION_DESCRIPTOR => return Err("nested USB configuration descriptor"),
            INTERFACE_DESCRIPTOR => {
                if length < 9 {
                    return Err("short USB interface descriptor");
                }
                if interface.is_some_and(|(_, expected)| expected != setting_endpoints.len()) {
                    return Err("USB endpoint descriptor count mismatch");
                }
                if settings.contains(&(d[2], d[3])) {
                    return Err("duplicate USB interface alternate setting");
                }
                settings.push((d[2], d[3]));
                if !numbers.contains(&d[2]) {
                    numbers.push(d[2]);
                }
                if d[3] == 0 {
                    zero.push(d[2]);
                }
                interface = Some((d[3], usize::from(d[4])));
                setting_endpoints.clear();
            }
            ENDPOINT_DESCRIPTOR => {
                if length < 7 {
                    return Err("short USB endpoint descriptor");
                }
                let Some((alternate, _)) = interface else {
                    return Err("orphan USB endpoint descriptor");
                };
                if d[2] & 0x70 != 0 || d[2] & 0x0f == 0 || (d[4] | d[5]) == 0 {
                    return Err("invalid USB endpoint address/packet size");
                }
                if setting_endpoints.contains(&d[2])
                    || (alternate == 0 && active_endpoints.contains(&d[2]))
                {
                    return Err("duplicate active USB endpoint address");
                }
                setting_endpoints.push(d[2]);
                if alternate == 0 {
                    active_endpoints.push(d[2]);
                }
            }
            _ => {}
        }
        at += length;
    }
    if interface.is_some_and(|(_, expected)| expected != setting_endpoints.len())
        || numbers.len() != usize::from(bytes[4])
        || zero.len() != numbers.len()
    {
        return Err("USB interface/endpoint count or alternate-zero mismatch");
    }
    Ok(())
}

pub(super) fn plan(
    device: &Device,
    interface: &Interface,
    all: &[Interface],
) -> Result<Plan, &'static str> {
    match interface.class {
        storage::CLASS => storage::plan(interface),
        hid::CLASS => hid::plan(interface),
        cdc::COMMUNICATIONS => cdc::plan(interface, all),
        bluetooth::CLASS => bluetooth::Binding::new(device, interface).map(Plan::Bluetooth),
        _ => Err("no class driver for this interface"),
    }
}

/// All simultaneously active settings, including interfaces left to other
/// drivers, must have distinct endpoint addresses. Class functions must own
/// disjoint interfaces; two CDC masters cannot both claim one data interface.
fn active_settings(all: &[Interface], selected: &[(u8, u8)]) -> Result<(), &'static str> {
    let mut endpoints = Vec::new();
    for interface in all {
        let alternate = selected
            .iter()
            .find(|(number, _)| *number == interface.number)
            .map_or(0, |(_, alternate)| *alternate);
        if interface.alternate != alternate {
            continue;
        }
        for endpoint in &interface.endpoints {
            if endpoints.contains(&endpoint.address) {
                return Err("USB alternate settings activate overlapping endpoints");
            }
            endpoints.push(endpoint.address);
        }
    }
    Ok(())
}

/// Choose the unique configuration offering the greatest number of supported
/// functions. No supported function leaves the first descriptor selected only
/// for unused-interface diagnostics; bind will issue no configuration request.
pub(super) fn select(device: &mut Device) -> Result<(), &'static str> {
    let mut best = None;
    let mut maximum = 0;
    let mut ambiguous = false;
    for index in 0..device.configurations.len() {
        device.configuration = device.configurations[index].clone();
        let all = interfaces(&device.configuration);
        let mut count = 0;
        let mut endpoints = Vec::new();
        let mut claimed = Vec::new();
        for interface in all.iter().filter(|i| i.alternate == 0 && i.class != 10) {
            if device.descriptor[4] == HUB_CLASS && interface.class == HUB_CLASS {
                if interface.endpoints.len() == 1
                    && interface.endpoints[0].kind() == 3
                    && interface.endpoints[0].is_in()
                {
                    count += 1;
                }
            } else if let Ok(binding) = plan(device, interface, &all) {
                let mut settings = vec![(interface.number, 0)];
                if let Plan::Ethernet(binding) = &binding {
                    settings.push(binding.data_setting());
                }
                for (number, alternate) in settings {
                    if claimed.iter().any(|(previous, _)| *previous == number) {
                        return Err("supported USB functions claim the same interface");
                    }
                    claimed.push((number, alternate));
                }
                for endpoint in binding.endpoints() {
                    if endpoints.contains(&endpoint.address) {
                        return Err("supported USB functions claim the same endpoint");
                    }
                    endpoints.push(endpoint.address);
                }
                count += 1;
            }
        }
        active_settings(&all, &claimed)?;
        if count > maximum {
            maximum = count;
            best = Some(index);
            ambiguous = false;
        } else if count != 0 && count == maximum {
            ambiguous = true;
        }
    }
    if ambiguous {
        device.configuration.clear();
        return Err("ambiguous equally supported USB configurations");
    }
    if maximum == 0 && device.descriptor[4] == HUB_CLASS {
        return Err("USB hub has no supported configuration");
    }
    device.configuration = device
        .configurations
        .get(best.unwrap_or(0))
        .ok_or("USB device has no configuration descriptors")?
        .clone();
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(crate) fn vendor(value: u8) -> Vec<u8> {
        vec![
            9, 2, 18, 0, 1, value, 0, 0x80, 50, 9, 4, 0, 0, 0, 0xff, 0, 0, 0,
        ]
    }

    pub(crate) fn ecm(value: u8) -> Vec<u8> {
        let mut bytes = vec![
            9, 2, 0, 0, 2, value, 0, 0x80, 50, 9, 4, 0, 0, 1, 2, 6, 0, 0, 5, 0x24, 6, 0,
            1, // Union: communications 0, data 1.
            13, 0x24, 0x0f, 1, 0, 0, 0, 0, 0xea, 5, 0, 0, 0, 7, 5, 0x83, 3, 16, 0, 1, 9, 4, 1, 0,
            0, 10, 0, 0, 0, // Inactive data setting.
            9, 4, 1, 3, 2, 10, 0, 0, 0, // Nonsequential alternate value.
            7, 5, 0x81, 2, 64, 0, 0, 7, 5, 0x02, 2, 64, 0, 0,
        ];
        let total = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&total.to_le_bytes());
        bytes
    }

    fn storage(value: u8) -> Vec<u8> {
        vec![
            9, 2, 32, 0, 1, value, 0, 0x80, 50, 9, 4, 0, 0, 2, 8, 6, 0x50, 0, 7, 5, 0x81, 2, 64, 0,
            0, 7, 5, 0x02, 2, 64, 0, 0,
        ]
    }

    pub(crate) fn device(configurations: Vec<Vec<u8>>) -> Device {
        let count = configurations.len() as u8;
        Device {
            slot: 1,
            speed: FULL_SPEED,
            location: "configuration model".into(),
            descriptor: [
                18, 1, 0, 2, 0, 0, 0, 64, 0x34, 0x12, 0x78, 0x56, 0, 1, 0, 0, 0, count,
            ],
            configurations,
            configuration: Vec::new(),
            manufacturer: None,
            product: None,
            serial: None,
        }
    }

    #[test]
    fn supported_binding_beats_standard_but_unsupported_rndis_without_losing_inventory() {
        let mut rndis = vendor(9);
        rndis[14..17].copy_from_slice(&[2, 2, 0xff]);
        let originals = vec![rndis, ecm(42), vendor(5)];
        for bytes in &originals {
            validate(bytes).unwrap();
        }
        let mut device = device(originals.clone());
        select(&mut device).unwrap();
        assert_eq!(device.configuration_value(), 42);
        assert_eq!(device.configuration, originals[1]);
        assert_eq!(device.configurations, originals);
        let all = interfaces(&device.configuration);
        let binding = plan(&device, &all[0], &all).unwrap();
        assert!(matches!(binding, Plan::Ethernet(_)));
        assert_eq!(binding.endpoints().len(), 3);
        let Plan::Ethernet(binding) = binding else {
            unreachable!()
        };
        assert_eq!(binding.data_setting(), (1, 3));
    }

    #[test]
    fn equal_supported_configurations_are_explicitly_ambiguous() {
        let mut device = device(vec![storage(7), ecm(42)]);
        assert_eq!(
            select(&mut device),
            Err("ambiguous equally supported USB configurations")
        );
        assert!(device.configuration.is_empty());
        assert_eq!(device.configuration_value(), 0);
        assert_eq!(device.configurations.len(), 2);
    }

    #[test]
    fn greatest_supported_function_coverage_is_unique_and_descriptor_order_independent() {
        let single = storage(7);
        let mut composite = storage(42);
        composite.extend_from_slice(&[
            9, 4, 1, 0, 2, 8, 6, 0x50, 0, 7, 5, 0x83, 2, 64, 0, 0, 7, 5, 0x04, 2, 64, 0, 0,
        ]);
        composite[4] = 2;
        let total = composite.len() as u16;
        composite[2..4].copy_from_slice(&total.to_le_bytes());
        validate(&composite).unwrap();
        for configurations in [
            vec![single.clone(), composite.clone()],
            vec![composite, single],
        ] {
            let mut device = device(configurations);
            select(&mut device).unwrap();
            assert_eq!(device.configuration_value(), 42);
        }
    }

    #[test]
    fn unsupported_interfaces_never_become_a_successful_plan() {
        let mut device = device(vec![vendor(19), vendor(3)]);
        select(&mut device).unwrap();
        let all = interfaces(&device.configuration);
        assert!(plan(&device, &all[0], &all).is_err());
        assert_eq!(device.configuration_value(), 19);
    }

    #[test]
    fn selected_alternate_cannot_overlap_another_default_active_interface() {
        let mut bytes = ecm(42);
        bytes.extend_from_slice(&[9, 4, 2, 0, 1, 0xff, 0, 0, 0, 7, 5, 0x81, 2, 64, 0, 0]);
        bytes[4] = 3;
        let total = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&total.to_le_bytes());
        validate(&bytes).unwrap(); // Default data setting has no endpoints.
        let mut device = device(vec![bytes]);
        assert_eq!(
            select(&mut device),
            Err("USB alternate settings activate overlapping endpoints")
        );
    }

    #[test]
    fn two_cdc_masters_cannot_claim_one_data_interface() {
        let mut bytes = ecm(42);
        // A second communications interface, naming the original data interface.
        bytes.extend_from_slice(&[
            9, 4, 2, 0, 0, 2, 6, 0, 0, 5, 0x24, 6, 2, 1, 13, 0x24, 0x0f, 1, 0, 0, 0, 0, 0xea, 5, 0,
            0, 0,
        ]);
        bytes[4] = 3;
        let total = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&total.to_le_bytes());
        validate(&bytes).unwrap();
        let mut device = device(vec![bytes]);
        assert_eq!(
            select(&mut device),
            Err("supported USB functions claim the same interface")
        );
    }

    #[test]
    fn configuration_stream_must_be_complete_and_internally_consistent() {
        let valid = ecm(42);
        for length in 0..valid.len() {
            assert!(validate(&valid[..length]).is_err(), "truncation {length}");
        }
        // Length/type/value/interface count/endpoint count/address/alternate zero.
        for (offset, value) in [
            (0, 8),
            (1, 1),
            (2, 9),
            (5, 0),
            (4, 3),
            (13, 2),
            (9, 1),
            (10, 2),
            (45, 0),
            (46, 0x80),
            (53, 2),
        ] {
            let mut malformed = valid.clone();
            malformed[offset] = value;
            assert!(
                validate(&malformed).is_err(),
                "offset {offset}, value {value}"
            );
        }
        let mut duplicate = storage(1);
        duplicate[27] = 0x81;
        assert!(validate(&duplicate).is_err());
        let mut orphan = vendor(1);
        orphan.extend_from_slice(&[7, 5, 0x81, 2, 64, 0, 0]);
        orphan.drain(9..18);
        orphan[2] = orphan.len() as u8;
        assert!(validate(&orphan).is_err());
    }
}
