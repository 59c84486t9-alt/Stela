//! Complete configuration validation and class-driver-based selection. USB 2.0
//! 9.6.3/9.6.5/9.6.6: descriptor indices, values and alternate settings are
//! separate namespaces. Unknown class descriptors remain in the raw inventory.
use super::*;

/// Endpoint types (USB 2.0 Table 9-13) and the largest wMaxPacketSize Linux
/// `usb_parse_endpoint` accepts for each at each speed, indexed by type:
/// control, isochronous, bulk, interrupt.
const ISOCHRONOUS: usize = 1;
const BULK: usize = 2;
const INTERRUPT: usize = 3;
const LOW_SPEED_MAXIMUMS: [u16; 4] = [8, 0, 0, 8];
const FULL_SPEED_MAXIMUMS: [u16; 4] = [64, 1023, 64, 64];
const HIGH_SPEED_MAXIMUMS: [u16; 4] = [64, 1024, 512, 1024];
const SUPER_SPEED_MAXIMUMS: [u16; 4] = [512, 1024, 1024, 1024];
/// wMaxPacketSize's additional-transactions field (high-speed periodic).
const MULTIPLE_TRANSACTIONS: u16 = 3 << 11;
const ENDPOINT_NUMBER: u8 = 0x0f;
const ENDPOINT_TYPE: u8 = 0x03;
/// bInterval replacements: 8 ms in microframe or frame exponents, and the
/// low-speed minimum period.
const HIGH_SPEED_DEFAULT_INTERVAL: u8 = 7;
const FULL_SPEED_ISOCHRONOUS_INTERVAL: u8 = 4;
const SLOW_INTERRUPT_INTERVAL: u8 = 10;
/// SuperSpeed companion limits (Linux `usb_parse_ss_endpoint_companion`).
const MAX_BURST: u8 = 15;
const MAX_STREAMS_EXPONENT: u8 = 16;
const COMPANION_LENGTH: u8 = 6;
const ISOCHRONOUS_MULT: u8 = 0x03;

/// A configuration descriptor as Linux `usb_parse_configuration` reads it:
/// the header must be valid, but a bad descriptor ends the stream, nested
/// configurations, duplicate interface settings and invalid or duplicate
/// endpoints are skipped, endpoint fields are corrected as Linux corrects
/// them, a SuperSpeed endpoint without a companion gets the default one,
/// and the counts and total length describe what remains.
pub(crate) fn sanitize(bytes: &[u8], speed: u8) -> Result<Vec<u8>, &'static str> {
    if bytes.len() < 9 || bytes[0] != 9 || bytes[1] != CONFIGURATION_DESCRIPTOR || bytes[5] == 0 {
        return Err("invalid USB configuration header/value");
    }
    let total = usize::from(u16::from_le_bytes([bytes[2], bytes[3]])).min(bytes.len());
    let mut out = bytes[..9].to_vec();
    let mut settings: Vec<(u8, u8)> = Vec::new();
    let mut owners: Vec<(u8, u8)> = Vec::new();
    // The current interface's number and where its bNumEndpoints is.
    let mut interface: Option<(u8, usize)> = None;
    let mut setting_endpoints: Vec<u8> = Vec::new();
    let mut skipping = false;
    // A SuperSpeed endpoint still waiting for its companion: its type and
    // packet size, and the default companion's bytes per interval.
    let mut companion_due: Option<(usize, u16, u16)> = None;
    let mut at = 9;
    while at + 2 <= total {
        let length = usize::from(bytes[at]);
        if length < 2 || at + length > total {
            break;
        }
        let d = &bytes[at..at + length];
        at += length;
        let kind = d[1];
        if (kind != SS_ENDPOINT_COMPANION || length != usize::from(COMPANION_LENGTH))
            && let Some((_, _, bytes_per_interval)) = companion_due.take()
        {
            out.extend_from_slice(&default_companion(bytes_per_interval));
        }
        match kind {
            CONFIGURATION_DESCRIPTOR => {}
            INTERFACE_DESCRIPTOR => {
                skipping = length < 9 || settings.contains(&(d[2], d[3]));
                if skipping {
                    continue;
                }
                settings.push((d[2], d[3]));
                finish_interface(&mut out, interface, setting_endpoints.len());
                interface = Some((d[2], out.len() + 4));
                setting_endpoints.clear();
                out.extend_from_slice(d);
            }
            ENDPOINT_DESCRIPTOR => {
                let Some((number, _)) = interface.filter(|_| !skipping && length >= 7) else {
                    continue;
                };
                let address = d[2];
                let owned_elsewhere = owners
                    .iter()
                    .any(|(other, owned)| *owned == address && *other != number);
                let maximum = u16::from_le_bytes([d[4], d[5]]);
                if address & ENDPOINT_NUMBER == 0
                    || maximum == 0
                    || setting_endpoints.contains(&address)
                    || owned_elsewhere
                {
                    continue;
                }
                let mut endpoint = d.to_vec();
                fix_endpoint(&mut endpoint, speed);
                setting_endpoints.push(address);
                owners.push((number, address));
                out.extend_from_slice(&endpoint);
                if matches!(speed, SUPER_SPEED | SUPER_SPEED_PLUS) {
                    let kind = usize::from(d[3] & ENDPOINT_TYPE);
                    let packet = u16::from_le_bytes([endpoint[4], endpoint[5]]);
                    let periodic = matches!(kind, ISOCHRONOUS | INTERRUPT);
                    companion_due = Some((kind, packet, if periodic { packet } else { 0 }));
                }
            }
            SS_ENDPOINT_COMPANION => {
                // Only a whole companion right after its endpoint is read.
                let Some((kind, packet, _)) = companion_due.take() else {
                    continue;
                };
                let mut companion = d.to_vec();
                companion[2] = companion[2].min(MAX_BURST);
                if kind == BULK {
                    companion[3] = companion[3].min(MAX_STREAMS_EXPONENT);
                }
                if matches!(kind, ISOCHRONOUS | INTERRUPT) {
                    // A periodic endpoint moves at most its packets per burst
                    // and per isochronous Mult each interval.
                    let mult = match kind {
                        ISOCHRONOUS => u32::from(companion[3] & ISOCHRONOUS_MULT) + 1,
                        _ => 1,
                    };
                    let most = u32::from(packet) * (u32::from(companion[2]) + 1) * mult;
                    let claimed = u16::from_le_bytes([companion[4], companion[5]]);
                    let fixed = u32::from(claimed).min(most) as u16;
                    companion[4..6].copy_from_slice(&fixed.to_le_bytes());
                }
                out.extend_from_slice(&companion);
            }
            _ if skipping => {}
            _ => out.extend_from_slice(d),
        }
    }
    if let Some((_, _, bytes_per_interval)) = companion_due {
        out.extend_from_slice(&default_companion(bytes_per_interval));
    }
    finish_interface(&mut out, interface, setting_endpoints.len());
    let mut numbers: Vec<u8> = settings.iter().map(|(number, _)| *number).collect();
    numbers.sort_unstable();
    numbers.dedup();
    out[4] = numbers.len() as u8;
    let length = u16::try_from(out.len()).map_err(|_| "USB configuration too long")?;
    out[2..4].copy_from_slice(&length.to_le_bytes());
    Ok(out)
}

/// Record the endpoints an interface descriptor really has.
fn finish_interface(out: &mut [u8], interface: Option<(u8, usize)>, endpoints: usize) {
    if let Some((_, count)) = interface {
        out[count] = endpoints as u8;
    }
}

/// Linux's companion for a SuperSpeed endpoint without one: no bursts, no
/// streams, and a periodic endpoint's packet per service interval.
fn default_companion(bytes_per_interval: u16) -> [u8; 6] {
    let [low, high] = bytes_per_interval.to_le_bytes();
    [COMPANION_LENGTH, SS_ENDPOINT_COMPANION, 0, 0, low, high]
}

/// Linux `usb_parse_endpoint`'s corrections of bInterval and wMaxPacketSize.
fn fix_endpoint(endpoint: &mut [u8], speed: u8) {
    let kind = usize::from(endpoint[3] & ENDPOINT_TYPE);
    let interval = endpoint[6];
    let high_speed = matches!(speed, HIGH_SPEED | SUPER_SPEED | SUPER_SPEED_PLUS);
    endpoint[6] = match kind {
        INTERRUPT if high_speed && !(1..=16).contains(&interval) => {
            // Many devices give full-speed periods: convert to microframes.
            match (u32::from(interval) * 8).checked_ilog2() {
                Some(bit) => bit as u8 + 1,
                None => HIGH_SPEED_DEFAULT_INTERVAL,
            }
        }
        INTERRUPT if !high_speed && interval == 0 => SLOW_INTERRUPT_INTERVAL,
        ISOCHRONOUS if !(1..=16).contains(&interval) => match speed {
            HIGH_SPEED => HIGH_SPEED_DEFAULT_INTERVAL,
            _ => FULL_SPEED_ISOCHRONOUS_INTERVAL,
        },
        _ => interval,
    };
    let field = u16::from_le_bytes([endpoint[4], endpoint[5]]);
    let multiple = match speed {
        HIGH_SPEED if matches!(kind, ISOCHRONOUS | INTERRUPT) => field & MULTIPLE_TRANSACTIONS,
        _ => 0,
    };
    let maximums = match speed {
        LOW_SPEED => LOW_SPEED_MAXIMUMS,
        FULL_SPEED => FULL_SPEED_MAXIMUMS,
        SUPER_SPEED | SUPER_SPEED_PLUS => SUPER_SPEED_MAXIMUMS,
        _ => HIGH_SPEED_MAXIMUMS,
    };
    let packet = (field & !multiple).min(maximums[kind]);
    endpoint[4..6].copy_from_slice(&(multiple | packet).to_le_bytes());
}

#[cfg(test)]
pub(super) fn plan(
    device: &Device,
    interface: &Interface,
    all: &[Interface],
) -> Result<Plan, &'static str> {
    plan_with_controller(device, interface, all, None)
}

/// Whether a driver binds through this interface. CDC data and audio streaming
/// interfaces belong to the communications or audio control interface that
/// claims them.
pub(super) fn primary(interface: &Interface) -> bool {
    interface.alternate == 0
        && interface.class != cdc::DATA_CLASS
        && !(interface.class == audio::CLASS && interface.subclass == audio::STREAMING_SUBCLASS)
}

pub(super) fn plan_with_controller(
    device: &Device,
    interface: &Interface,
    all: &[Interface],
    controller: Option<&Controller>,
) -> Result<Plan, &'static str> {
    let binding = match interface.class {
        audio::CLASS => audio::plan(interface, all, &device.configuration, device.speed)
            .map(Plan::Audio)
            .map_err(|_| "unsupported or malformed UAC2 function descriptors"),
        storage::CLASS => storage::plan(device, interface, all, controller),
        hid::CLASS => hid::plan(interface),
        cdc::COMMUNICATIONS => cdc::plan(interface, all),
        bluetooth::CLASS => bluetooth::Binding::new(device, interface).map(Plan::Bluetooth),
        0xff => {
            let mut failure = "no supported vendor Ethernet interface setting";
            let mut chosen = None;
            for candidate in all
                .iter()
                .filter(|candidate| candidate.number == interface.number && candidate.class == 0xff)
            {
                match ethernet::Binding::new(device, candidate)
                    .map(Plan::VendorEthernet)
                    .and_then(|binding| supported(binding, device.speed))
                {
                    Ok(binding) => {
                        chosen = Some(binding);
                        break;
                    }
                    Err(error) if candidate.alternate == 0 => failure = error,
                    Err(_) => {}
                }
            }
            chosen.ok_or(failure)
        }
        _ => Err("no class driver for this interface"),
    }?;
    supported(binding, device.speed)
}

fn supported(binding: Plan, speed: u8) -> Result<Plan, &'static str> {
    for endpoint in binding.endpoints() {
        endpoint::Context::new(&endpoint, speed)
            .map_err(|_| "USB function has an unsupported speed-specific endpoint")?;
    }
    Ok(binding)
}

/// All simultaneously active settings, including interfaces left to other
/// drivers, must have distinct endpoint addresses. Class functions must own
/// disjoint interfaces; two CDC masters cannot both claim one data interface.
pub(super) fn active_settings(
    all: &[Interface],
    selected: &[(u8, u8)],
) -> Result<(), &'static str> {
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
/// functions. At equal coverage, an implemented observed vendor Ethernet mode
/// wins over its generic CDC alternative, as r8152's cfgselector requires.
/// No supported function leaves the first descriptor selected only
/// for unused-interface diagnostics; bind will issue no configuration request.
#[cfg(test)]
pub(crate) fn select(device: &mut Device) -> Result<(), &'static str> {
    select_with_controller(device, None)
}

pub(super) fn select_with_controller(
    device: &mut Device,
    controller: Option<&Controller>,
) -> Result<(), &'static str> {
    let mut candidates = Vec::new();
    for index in 0..device.configurations.len() {
        let Ok(configuration) = sanitize(&device.configurations[index], device.speed) else {
            continue;
        };
        device.configuration = configuration;
        let all = interfaces(&device.configuration);
        let mut count = 0;
        let mut vendor_ethernet = false;
        let mut uas_count = 0;
        let mut asix = false;
        let mut cdc = false;
        let mut endpoints = Vec::new();
        let mut claimed = Vec::new();
        for interface in all.iter().filter(|i| primary(i)) {
            if device.descriptor[4] == HUB_CLASS && interface.class == HUB_CLASS {
                if interface.endpoints.len() == 1
                    && interface.endpoints[0].kind() == 3
                    && interface.endpoints[0].is_in()
                    && device.speed < SUPER_SPEED
                    && endpoint::Context::new(&interface.endpoints[0], device.speed).is_ok()
                {
                    count += 1;
                }
            } else if let Ok(binding) = plan_with_controller(device, interface, &all, controller) {
                if let Plan::VendorEthernet(binding) = &binding {
                    vendor_ethernet |= binding.observed_vendor();
                    asix |= binding.asix_candidate();
                }
                cdc |= matches!(&binding, Plan::Ethernet(_));
                uas_count +=
                    usize::from(matches!(&binding, Plan::Storage(binding) if binding.uas()));
                for (number, alternate) in binding.settings(interface.number) {
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
        candidates.push((index, (count, vendor_ethernet, uas_count), asix, cdc));
    }
    let maximum = candidates
        .iter()
        .map(|candidate| candidate.1)
        .max()
        .unwrap_or((0, false, 0));
    let mut finalists: Vec<_> = candidates
        .iter()
        .filter(|candidate| candidate.1 == maximum)
        .collect();
    // Unlike Realtek cfgselector, ASIX has no source-backed preconfiguration
    // silicon check. At equal supported coverage retain a usable CDC alternative
    // over an ASIX-only candidate; unrelated configurations still tie normally.
    if !maximum.1 && finalists.iter().any(|candidate| candidate.3) {
        finalists.retain(|candidate| !candidate.2 || candidate.3);
    }
    // Linux `usb_choose_configuration` takes the first of equal candidates.
    let best = finalists.first().map(|candidate| candidate.0);
    if maximum.0 == 0 && device.descriptor[4] == HUB_CLASS {
        return Err("USB hub has no supported configuration");
    }
    let chosen = device
        .configurations
        .get(best.unwrap_or(0))
        .ok_or("USB device has no configuration descriptors")?;
    device.configuration = sanitize(chosen, device.speed)?;
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::bus::dma::RegionAllocator;
    use crate::usb::xhci::model::*;

    #[test]
    fn superspeed_companions_associate_only_with_immediately_preceding_endpoint() {
        let mut bytes = vec![
            9, 2, 0, 0, 1, 7, 0, 0x80, 50, 9, 4, 0, 0, 2, 0xff, 0, 0, 0, 7, 5, 0x81, 2, 0, 4, 0, 6,
            0x30, 7, 0, 0, 0, 7, 5, 2, 3, 64, 0, 4, 6, 0x30, 3, 0, 37, 0,
        ];
        let total = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&total.to_le_bytes());
        assert_eq!(sanitize(&bytes, SUPER_SPEED).unwrap(), bytes);
        let all = interfaces(&bytes);
        assert_eq!(
            all[0].endpoints[0].companion,
            Some(SuperSpeedCompanion {
                max_burst: 7,
                attributes: 0,
                bytes_per_interval: 0,
            })
        );
        assert_eq!(
            all[0].endpoints[1].companion,
            Some(SuperSpeedCompanion {
                max_burst: 3,
                attributes: 0,
                bytes_per_interval: 37,
            })
        );
        assert_eq!(
            all[0].extra,
            [vec![6, 0x30, 7, 0, 0, 0], vec![6, 0x30, 3, 0, 37, 0]]
        );
        // A short companion, or one a class descriptor separates from its
        // endpoint, gives way to Linux's default companion.
        let default = Some(SuperSpeedCompanion::default());
        for length in 2..6 {
            let mut bad = bytes.clone();
            bad.splice(
                25..31,
                [length, 0x30, 7, 0, 0, 0][..usize::from(length)]
                    .iter()
                    .copied(),
            );
            let total = bad.len() as u16;
            bad[2..4].copy_from_slice(&total.to_le_bytes());
            let fixed = sanitize(&bad, SUPER_SPEED).unwrap();
            assert_eq!(interfaces(&fixed)[0].endpoints[0].companion, default);
        }
        let mut separated = bytes.clone();
        separated.splice(25..25, [2, 0x25]);
        let total = separated.len() as u16;
        separated[2..4].copy_from_slice(&total.to_le_bytes());
        let fixed = sanitize(&separated, SUPER_SPEED).unwrap();
        assert_eq!(interfaces(&fixed)[0].endpoints[0].companion, default);
        // A periodic companion cannot claim more than its bursts carry.
        let mut greedy = bytes.clone();
        greedy[42..44].copy_from_slice(&1000u16.to_le_bytes());
        let fixed = sanitize(&greedy, SUPER_SPEED).unwrap();
        assert_eq!(
            interfaces(&fixed)[0].endpoints[1]
                .companion
                .unwrap()
                .bytes_per_interval,
            256
        );
        // Orphan and duplicate companions are dropped.
        for at in [18, 31] {
            let mut stray = bytes.clone();
            stray.splice(at..at, [6, 0x30, 9, 0, 0, 0]);
            let total = stray.len() as u16;
            stray[2..4].copy_from_slice(&total.to_le_bytes());
            assert_eq!(sanitize(&stray, SUPER_SPEED).unwrap(), bytes);
        }
    }

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
            vendor_ethernet_revision: None,
            vendor_ethernet_tcr: None,
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
            language: None,
        }
    }

    #[test]
    fn supported_binding_beats_standard_but_unsupported_rndis_without_losing_inventory() {
        let mut rndis = vendor(9);
        rndis[14..17].copy_from_slice(&[2, 2, 0xff]);
        let originals = vec![rndis, ecm(42), vendor(5)];
        for bytes in &originals {
            sanitize(bytes, SUPER_SPEED).unwrap();
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

    fn superspeed(bytes: &[u8]) -> Vec<u8> {
        let mut ss = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let length = usize::from(bytes[at]);
            let mut d = bytes[at..at + length].to_vec();
            if d[1] == ENDPOINT_DESCRIPTOR {
                if d[3] & 3 == 2 {
                    d[4..6].copy_from_slice(&1024u16.to_le_bytes());
                }
                ss.extend_from_slice(&d);
                ss.extend_from_slice(&[
                    6,
                    SS_ENDPOINT_COMPANION,
                    0,
                    0,
                    if d[3] & 3 == 3 { d[4] } else { 0 },
                    0,
                ]);
            } else {
                ss.extend_from_slice(&d);
            }
            at += length;
        }
        let total = ss.len() as u16;
        ss[2..4].copy_from_slice(&total.to_le_bytes());
        sanitize(&ss, SUPER_SPEED).unwrap();
        ss
    }

    #[test]
    fn refused_superspeed_functions_never_tie_or_beat_usable_configuration() {
        let valid = superspeed(&storage(42));
        // Linux fixes a missing companion, a reserved stream count and an
        // oversized burst; each such function then counts.
        let mut missing = storage(7);
        missing[22..24].copy_from_slice(&1024u16.to_le_bytes());
        missing[29..31].copy_from_slice(&1024u16.to_le_bytes());
        let mut streams = superspeed(&storage(7));
        streams[28] = 17;
        let mut burst = superspeed(&storage(7));
        burst[27] = 16;
        for fixed in [missing, streams, burst] {
            let mut dev = device(vec![fixed]);
            dev.speed = SUPER_SPEED;
            select(&mut dev).unwrap();
            let all = interfaces(&dev.configuration);
            assert!(plan(&dev, &all[0], &all).is_ok());
        }
        // A 512-byte SuperSpeed bulk endpoint stays refused.
        let mut small = superspeed(&storage(7));
        small[22..24].copy_from_slice(&512u16.to_le_bytes());
        for refused in [small] {
            for order in [false, true] {
                let mut configurations = vec![refused.clone(), valid.clone()];
                if order {
                    configurations.reverse();
                }
                let mut dev = device(configurations);
                dev.speed = SUPER_SPEED;
                select(&mut dev).unwrap();
                assert_eq!(dev.configuration_value(), 42);
                assert_eq!(dev.configurations.len(), 2);
                let fixed = sanitize(&refused, SUPER_SPEED).unwrap();
                let all = interfaces(&fixed);
                assert!(plan(&dev, &all[0], &all).is_err());
            }
        }
        // Even the supported, observed vendor-mode preference cannot count a
        // vendor function whose transport is explicitly refused by this host.
        let mut vendor = superspeed(&storage(7));
        vendor[14..17].copy_from_slice(&[0xff, 0, 0]);
        vendor[22..24].copy_from_slice(&512u16.to_le_bytes());
        let valid = superspeed(&ecm(42));
        for order in [false, true] {
            let mut configurations = vec![vendor.clone(), valid.clone()];
            if order {
                configurations.reverse();
            }
            let mut dev = device(configurations);
            dev.speed = SUPER_SPEED;
            dev.descriptor[8..12].copy_from_slice(&[0xda, 0x0b, 0x53, 0x81]);
            dev.vendor_ethernet_revision = Some(0x4c10);
            select(&mut dev).unwrap();
            assert_eq!(dev.configuration_value(), 42);
        }
    }

    #[test]
    fn ordinary_bulk_configuration_accepts_a_valid_advertised_stream_capability() {
        for exponent in 1..=16 {
            let mut configuration = superspeed(&storage(42));
            configuration[28] = exponent;
            let mut dev = device(vec![configuration.clone()]);
            dev.speed = SUPER_SPEED;
            select(&mut dev).unwrap();
            assert_eq!(dev.configuration_value(), 42);
            let all = interfaces(&configuration);
            assert!(plan(&dev, &all[0], &all).is_ok());
        }
    }

    #[test]
    fn hub_configuration_coverage_requires_a_usable_interrupt_endpoint() {
        let valid = vec![
            9, 2, 25, 0, 1, 42, 0, 0x80, 50, 9, 4, 0, 0, 1, HUB_CLASS, 0, 0, 0, 7, 5, 0x81, 3, 8,
            0, 1,
        ];
        // An OUT status endpoint cannot report port changes.
        let mut invalid = valid.clone();
        invalid[5] = 7;
        invalid[20] = 0x01;
        for order in [false, true] {
            let mut configurations = vec![invalid.clone(), valid.clone()];
            if order {
                configurations.reverse();
            }
            let mut dev = device(configurations);
            dev.descriptor[4] = HUB_CLASS;
            select(&mut dev).unwrap();
            assert_eq!(dev.configuration_value(), 42);
        }
    }

    #[test]
    fn equal_supported_configurations_choose_the_first_like_linux() {
        let mut device = device(vec![storage(7), ecm(42)]);
        select(&mut device).unwrap();
        assert_eq!(device.configuration_value(), 7);
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
        sanitize(&composite, HIGH_SPEED).unwrap();
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
    fn unsupported_or_unobserved_realtek_revision_preserves_compatible_cdc_choice() {
        let mut vendor = storage(7);
        vendor[14..17].copy_from_slice(&[0xff, 0, 0]);
        for revision in [None, Some(0x4c20), Some(0x7010), Some(0x1030), Some(0x2020)] {
            let mut device = device(vec![vendor.clone(), ecm(42)]);
            device.descriptor[8..12].copy_from_slice(&[0xda, 0x0b, 0x56, 0x81]);
            device.vendor_ethernet_revision = revision;
            select(&mut device).unwrap();
            assert_eq!(device.configuration_value(), 42);
            assert_eq!(device.configurations.len(), 2);
        }
        let mut device = device(vec![vendor]);
        device.descriptor[8..12].copy_from_slice(&[0xda, 0x0b, 0x52, 0x81]);
        device.vendor_ethernet_revision = Some(0x4c10);
        select(&mut device).unwrap();
        let all = interfaces(&device.configuration);
        assert!(matches!(
            plan(&device, &all[0], &all),
            Ok(Plan::VendorEthernet(_))
        ));
    }

    #[test]
    fn implemented_realtek_vendor_mode_wins_equal_cdc_coverage_independent_of_order() {
        let mut vendor = storage(7);
        vendor[14..17].copy_from_slice(&[0xff, 0, 0]);
        for revision in [0x4c00, 0x4c10, 0x4800] {
            for configurations in [vec![vendor.clone(), ecm(42)], vec![ecm(42), vendor.clone()]] {
                let mut device = device(configurations);
                device.descriptor[8..12].copy_from_slice(&[0xda, 0x0b, 0x52, 0x81]);
                device.vendor_ethernet_revision = Some(revision);
                select(&mut device).unwrap();
                assert_eq!(device.configuration_value(), 7);
            }
        }
        let mut other = vendor.clone();
        other[5] = 9;
        let mut device = device(vec![vendor, other, ecm(42)]);
        device.descriptor[8..12].copy_from_slice(&[0xda, 0x0b, 0x52, 0x81]);
        device.vendor_ethernet_revision = Some(0x4c10);
        // Linux takes the first of equally good configurations.
        select(&mut device).unwrap();
        assert_eq!(device.configuration_value(), 7);
    }

    #[test]
    fn exact_oem_candidates_need_observed_supported_chip_and_fixed_bulk_pipes() {
        for &(vid, pid) in ethernet::USB_IDS {
            for revision in [None, Some(0x4c20), Some(0x1030), Some(0x2020), Some(0x5c10)] {
                for variant in 0..4 {
                    let mut vendor = storage(7);
                    vendor[14..17].copy_from_slice(&[0xff, 0, 0]);
                    match variant {
                        1 => vendor[20] = 0x83,
                        2 => vendor[27] = 0x01,
                        3 => vendor[14] = 0x02,
                        _ => {}
                    }
                    for configurations in
                        [vec![vendor.clone(), ecm(42)], vec![ecm(42), vendor.clone()]]
                    {
                        let mut device = device(configurations);
                        device.descriptor[8..10].copy_from_slice(&vid.to_le_bytes());
                        device.descriptor[10..12].copy_from_slice(&pid.to_le_bytes());
                        device.vendor_ethernet_revision = revision;
                        select(&mut device).unwrap();
                        assert_eq!(
                            device.configuration_value(),
                            if revision == Some(0x5c10) && variant == 0 {
                                7
                            } else {
                                42
                            },
                            "{vid:04x}:{pid:04x} {revision:?}/{variant}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn asix_exact_interface_candidates_preserve_cdc_and_select_supported_alternate() {
        for (vid, pid) in ethernet::asix_ids() {
            for mismatch in 0..4 {
                let mut vendor = storage(7);
                vendor[14..17].copy_from_slice(&[0xff, 0xff, 0]);
                match mismatch {
                    1 => vendor[15] = 0,
                    2 => vendor[16] = 1,
                    3 => vendor[14] = 2,
                    _ => {}
                }
                for configurations in [vec![vendor.clone(), ecm(42)], vec![ecm(42), vendor.clone()]]
                {
                    let mut dev = device(configurations);
                    dev.descriptor[8..10].copy_from_slice(&vid.to_le_bytes());
                    dev.descriptor[10..12].copy_from_slice(&pid.to_le_bytes());
                    select(&mut dev).unwrap();
                    assert_eq!(dev.configuration_value(), 42);
                    let all = interfaces(&vendor);
                    assert_eq!(plan(&dev, &all[0], &all).is_ok(), mismatch == 0);
                }
            }
        }
        let mut bytes = storage(7);
        bytes.truncate(18);
        bytes[13] = 0;
        bytes[14..17].copy_from_slice(&[0xff, 0xff, 0]);
        bytes.extend_from_slice(&[
            9, 4, 0, 2, 2, 0xff, 0xff, 0, 0, 7, 5, 0x81, 2, 64, 0, 0, 7, 5, 2, 2, 64, 0, 0,
        ]);
        let total = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&total.to_le_bytes());
        let mut dev = device(vec![bytes]);
        dev.descriptor[8..12].copy_from_slice(&[0x95, 0x0b, 0x90, 0x17]);
        select(&mut dev).unwrap();
        let all = interfaces(&dev.configuration);
        let Plan::VendorEthernet(binding) = plan(&dev, &all[0], &all).unwrap() else {
            panic!()
        };
        assert_eq!(binding.setting(), (0, 2));
        assert!(binding.asix_candidate() && !binding.observed_vendor());
    }

    #[test]
    fn ax88772_exact_candidates_keep_cdc_and_refuse_superspeed_before_binding() {
        for (vid, pid) in ethernet::asix_legacy_ids() {
            for (speed, packet) in [(FULL_SPEED, 64u16), (HIGH_SPEED, 512), (SUPER_SPEED, 1024)] {
                let mut vendor = storage(7);
                vendor[14..17].copy_from_slice(&[0xff, 0, 0]);
                vendor[22..24].copy_from_slice(&packet.to_le_bytes());
                vendor[29..31].copy_from_slice(&packet.to_le_bytes());
                let vendor = if speed == SUPER_SPEED {
                    superspeed(&vendor)
                } else {
                    vendor
                };
                let mut compatible = ecm(42);
                if speed != FULL_SPEED {
                    let mut at = 0;
                    while at < compatible.len() {
                        let n = compatible[at] as usize;
                        if compatible[at + 1] == ENDPOINT_DESCRIPTOR && compatible[at + 3] & 3 == 2
                        {
                            compatible[at + 4..at + 6].copy_from_slice(&packet.to_le_bytes());
                        }
                        at += n;
                    }
                }
                if speed == SUPER_SPEED {
                    compatible = superspeed(&compatible);
                }
                for configurations in [
                    vec![vendor.clone(), compatible.clone()],
                    vec![compatible.clone(), vendor.clone()],
                ] {
                    let mut dev = device(configurations);
                    dev.speed = speed;
                    dev.descriptor[8..10].copy_from_slice(&vid.to_le_bytes());
                    dev.descriptor[10..12].copy_from_slice(&pid.to_le_bytes());
                    select(&mut dev).unwrap();
                    assert_eq!(dev.configuration_value(), 42);
                    let all = interfaces(&vendor);
                    assert_eq!(plan(&dev, &all[0], &all).is_ok(), speed != SUPER_SPEED);
                }
            }
        }
    }

    #[test]
    fn asix_alternate_search_validates_superspeed_contexts_before_claiming() {
        let mut vendor = superspeed(&storage(7));
        vendor[14..17].copy_from_slice(&[0xff, 0xff, 0]);
        let mut alternate = vendor.clone();
        alternate[12] = 2;
        // A 512-byte SuperSpeed bulk endpoint invalidates the default setting.
        vendor[22..24].copy_from_slice(&512u16.to_le_bytes());
        vendor.extend_from_slice(&alternate[9..]);
        let length = vendor.len() as u16;
        vendor[2..4].copy_from_slice(&length.to_le_bytes());
        let mut dev = device(vec![vendor.clone()]);
        dev.speed = SUPER_SPEED;
        dev.descriptor[8..12].copy_from_slice(&[0x95, 0x0b, 0x90, 0x17]);
        select(&mut dev).unwrap();
        let all = interfaces(&dev.configuration);
        let Plan::VendorEthernet(binding) = plan(&dev, &all[0], &all).unwrap() else {
            panic!()
        };
        assert_eq!(binding.setting(), (0, 2));
        for configurations in [
            vec![vendor.clone(), superspeed(&ecm(42))],
            vec![superspeed(&ecm(42)), vendor.clone()],
        ] {
            dev.configurations = configurations;
            select(&mut dev).unwrap();
            assert_eq!(dev.configuration_value(), 42);
        }
        let mut other = vendor.clone();
        other[5] = 9;
        dev.configurations = vec![vendor, other];
        // Linux takes the first of equally good configurations.
        select(&mut dev).unwrap();
        assert_eq!(dev.configuration_value(), 7);
    }

    #[test]
    fn an_endpoint_another_interface_owns_is_skipped_like_linux() {
        let mut bytes = ecm(42);
        bytes.extend_from_slice(&[9, 4, 2, 0, 1, 0xff, 0, 0, 0, 7, 5, 0x81, 2, 64, 0, 0]);
        bytes[4] = 3;
        let total = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&total.to_le_bytes());
        let mut device = device(vec![bytes]);
        select(&mut device).unwrap();
        let all = interfaces(&device.configuration);
        let vendor = all.iter().find(|interface| interface.number == 2).unwrap();
        assert!(vendor.endpoints.is_empty());
        assert!(active_settings(&all, &[(1, 1)]).is_ok());
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
        sanitize(&bytes, HIGH_SPEED).unwrap();
        let mut device = device(vec![bytes]);
        assert_eq!(
            select(&mut device),
            Err("supported USB functions claim the same interface")
        );
    }

    #[test]
    fn malformed_configurations_are_read_as_linux_reads_them() {
        let valid = ecm(42);
        assert_eq!(sanitize(&valid, HIGH_SPEED).unwrap(), valid);
        // Only the header is fatal.
        for (offset, value) in [(0, 8), (1, 1), (5, 0)] {
            let mut malformed = valid.clone();
            malformed[offset] = value;
            assert!(sanitize(&malformed, HIGH_SPEED).is_err(), "offset {offset}");
        }
        assert!(sanitize(&valid[..8], HIGH_SPEED).is_err());
        // A truncated stream keeps every whole descriptor and fixes counts.
        let truncated = sanitize(&valid[..valid.len() - 3], HIGH_SPEED).unwrap();
        assert_eq!(usize::from(truncated[2]), truncated.len());
        // Wrong interface and endpoint counts are corrected.
        let mut miscounted = valid.clone();
        miscounted[4] = 7;
        assert_eq!(sanitize(&miscounted, HIGH_SPEED).unwrap(), valid);
        // Duplicate endpoints in one setting, endpoint zero and empty packets
        // are skipped; the device keeps the rest.
        let mut duplicate = storage(1);
        duplicate[27] = 0x81;
        let fixed = sanitize(&duplicate, HIGH_SPEED).unwrap();
        assert_eq!(interfaces(&fixed)[0].endpoints.len(), 1);
        let mut orphan = vendor(1);
        orphan.extend_from_slice(&[7, 5, 0x81, 2, 64, 0, 0]);
        orphan.drain(9..18);
        orphan[2] = orphan.len() as u8;
        assert!(interfaces(&sanitize(&orphan, HIGH_SPEED).unwrap()).is_empty());
    }

    #[test]
    fn endpoint_intervals_and_packet_sizes_are_corrected_like_linux() {
        let fix = |bytes: [u8; 7], speed| {
            let mut endpoint = bytes.to_vec();
            fix_endpoint(&mut endpoint, speed);
            (u16::from_le_bytes([endpoint[4], endpoint[5]]), endpoint[6])
        };
        // A full-speed period in a high-speed interrupt endpoint: 32 frames.
        assert_eq!(fix([7, 5, 0x81, 3, 8, 0, 32], HIGH_SPEED), (8, 9));
        assert_eq!(fix([7, 5, 0x81, 3, 8, 0, 0], HIGH_SPEED), (8, 7));
        assert_eq!(fix([7, 5, 0x81, 3, 8, 0, 0], FULL_SPEED), (8, 10));
        assert_eq!(fix([7, 5, 0x81, 1, 0, 2, 0], FULL_SPEED), (512, 4));
        // Oversized packets are clamped; high-speed periodic keeps its
        // additional transactions.
        assert_eq!(fix([7, 5, 0x81, 2, 0, 4, 0], HIGH_SPEED), (512, 0));
        assert_eq!(fix([7, 5, 0x81, 3, 0, 0x14, 1], HIGH_SPEED), (0x1400, 1));
        assert_eq!(fix([7, 5, 0x81, 3, 64, 0, 1], LOW_SPEED), (8, 1));
        // Linux only warns about a high-speed bulk endpoint below 512.
        assert_eq!(fix([7, 5, 0x81, 2, 64, 0, 0], HIGH_SPEED), (64, 0));
    }

    #[test]
    fn uac2_selection_keeps_zero_bandwidth_until_explicit_pcm_start() {
        let configuration = audio::test_configuration();
        sanitize(&configuration, HIGH_SPEED).unwrap();
        let mut device = device(vec![configuration]);
        device.speed = 3;
        select(&mut device).unwrap();
        let all = interfaces(&device.configuration);
        let selected = plan(&device, &all[0], &all).unwrap();
        assert!(matches!(selected, Plan::Audio(_)));
        assert!(selected.endpoints().is_empty());
        assert_eq!(selected.settings(0), vec![(0, 0), (1, 0), (2, 0)]);
        active_settings(&all, &selected.settings(0)).unwrap();
    }

    fn storage_modes(value: u8, superspeed: bool, bot: bool, uas: bool) -> Vec<u8> {
        let mut bytes = vec![9, 2, 0, 0, 1, value, 0, 0x80, 50];
        let packet = if superspeed { 1024u16 } else { 512u16 };
        for (enabled, alternate, protocol, pipes) in [
            (bot, 0, 0x50, vec![(0x81u8, 0u8), (2, 0)]),
            (
                uas,
                u8::from(bot),
                0x62,
                vec![(3u8, 1u8), (0x84, 2), (0x85, 3), (6, 4)],
            ),
        ] {
            if !enabled {
                continue;
            }
            bytes.extend_from_slice(&[9, 4, 0, alternate, pipes.len() as u8, 8, 6, protocol, 0]);
            for (address, pipe) in pipes {
                bytes.extend_from_slice(&[7, 5, address, 2, packet as u8, (packet >> 8) as u8, 0]);
                if superspeed {
                    bytes.extend_from_slice(&[
                        6,
                        SS_ENDPOINT_COMPANION,
                        0,
                        if pipe > 1 { 4 } else { 0 },
                        0,
                        0,
                    ]);
                }
                if protocol == 0x62 {
                    bytes.extend_from_slice(&[4, 0x24, pipe, 0]);
                }
            }
        }
        let length = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&length.to_le_bytes());
        configuration::sanitize(&bytes, SUPER_SPEED).unwrap();
        bytes
    }

    #[test]
    fn storage_selector_uses_actual_stream_policy_before_configuration_and_bot_fallback() {
        let mut memory = vec![0u64; 128 * 1024];
        let start = memory.as_mut_ptr() as u64;
        // SAFETY: backing storage outlives the controller and its modeled DMA.
        let mut dma = unsafe { RegionAllocator::new(start..start + memory.len() as u64 * 8) };
        let (mut controller, model) = unconfigured_cancellation_controller(&mut dma);
        controller.max_primary_streams = 16;
        controller.slots[1].as_mut().unwrap().speed = SUPER_SPEED;
        let mut dev = configuration::tests::device(vec![storage_modes(7, true, true, true)]);
        dev.speed = SUPER_SPEED;
        for (policy, expected) in [
            (streams::Policy::Unknown, (0, 0)),
            (streams::Policy::Broken, (0, 0)),
            (streams::Policy::Standard, (0, 1)),
            (streams::Policy::Cadence, (0, 1)),
        ] {
            controller.stream_policy = policy;
            configuration::select_with_controller(&mut dev, Some(&controller)).unwrap();
            let all = interfaces(&dev.configuration);
            let Plan::Storage(binding) =
                configuration::plan_with_controller(&dev, &all[0], &all, Some(&controller))
                    .unwrap()
            else {
                panic!()
            };
            assert_eq!(binding.setting(), expected);
            assert_eq!(binding.uas(), expected.1 == 1);
        }
        controller.stream_policy = streams::Policy::Standard;
        controller.max_primary_streams = 0;
        let all = interfaces(&dev.configuration);
        let Plan::Storage(binding) =
            configuration::plan_with_controller(&dev, &all[0], &all, Some(&controller)).unwrap()
        else {
            panic!()
        };
        assert!(!binding.uas());
        assert_eq!(model.borrow().configuration_value, 0);
        assert!(
            model
                .borrow()
                .configuration_seen_before_endpoints
                .is_empty()
        );
        assert!(model.borrow().active.iter().skip(2).all(Option::is_none));
    }

    #[test]
    fn storage_configuration_prefers_usable_uas_and_preserves_quirk_bot_fallback() {
        for superspeed in [false, true] {
            let mut memory = vec![0u64; 128 * 1024];
            let start = memory.as_mut_ptr() as u64;
            // SAFETY: backing storage outlives the controller and its modeled DMA.
            let mut dma = unsafe { RegionAllocator::new(start..start + memory.len() as u64 * 8) };
            let (mut controller, _) = unconfigured_cancellation_controller(&mut dma);
            let speed = if superspeed { SUPER_SPEED } else { HIGH_SPEED };
            controller.slots[1].as_mut().unwrap().speed = speed;
            controller.stream_policy = streams::Policy::Standard;
            controller.max_primary_streams = 16;
            for reverse in [false, true] {
                let mut configs = vec![
                    storage_modes(7, superspeed, true, false),
                    storage_modes(9, superspeed, false, true),
                ];
                if reverse {
                    configs.reverse();
                }
                let mut dev = configuration::tests::device(configs);
                dev.speed = speed;
                configuration::select_with_controller(&mut dev, Some(&controller)).unwrap();
                assert_eq!(dev.configuration_value(), 9);
                // This exact source-listed SanDisk enclosure refuses UAS even
                // on a capable stream host; retain the usable BOT alternative.
                dev.descriptor[8..12].copy_from_slice(&[0x81, 0x07, 0xe8, 0x55]);
                configuration::select_with_controller(&mut dev, Some(&controller)).unwrap();
                assert_eq!(dev.configuration_value(), 7);
            }
        }
    }
}
