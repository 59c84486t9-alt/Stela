// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Stela contributors
//! The polled bring-up against the device model, which answers every host
//! command, completes ALIVE and NVM init, reports its beacons per scan, and
//! plays the AP: it reads frames from the queues the scheduler added.
use super::*;
use crate::wifi::connection::keeper::{Radio, Stage as Standing};
use crate::wifi::connection::security::Security;
use crate::wifi::intel::{
    link::{Inputs, Phase, Station},
    nvm::Request as NvmRequest,
    policy::{WORLD, tests::regdb},
};
use crate::wifi::network::{Network, Secret};
use crate::wifi::station::Phase as Peering;
use crate::wifi::supplicant::tests::Authenticator;
use crate::{Link, Mac};
use alloc::{boxed::Box, sync::Arc};
use stela_driver_base::entropy::{Entropy, EntropyError};
use zeroize::Zeroizing;

const AP: [u8; 6] = [2, 3, 4, 5, 6, 7];
const RSN: [u8; 22] = [
    48, 20, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 2, 0, 0,
];
/// An AP's HT capabilities and operation on channel 1, one stream at 20 MHz.
const HT: [u8; 52] = [
    45, 26, 0x2c, 1, 0x17, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    61, 22, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
/// A WMM parameter element: best effort at the defaults of each class.
const WMM: [u8; 26] = [
    221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0, 0, 3, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43, 0x5e, 0,
    0x62, 0x32, 0x2f, 0,
];

struct FixedEntropy;

impl Entropy for FixedEntropy {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), EntropyError> {
        bytes.fill(0x5a);
        Ok(())
    }
}

/// The model's view of the function: the next RX entry it completes, the
/// last command sequence it answered, the SSID each scan's beacon carries
/// (the last repeating), the MCC channel word of channels 1 and 2 and the
/// countries MCC requests named.
struct Device<'n> {
    native: &'n Native,
    entry: u16,
    answered: Option<u16>,
    beacons: Vec<&'static [u8]>,
    channel: u32,
    countries: Vec<[u8; 2]>,
    /// Every command the firmware answered, as group and opcode.
    commands: Vec<(u8, u8)>,
    /// Each scheduler queue: its TID, identity, descriptors and next index.
    queues: Vec<(u8, u16, u64, u16)>,
    /// Each frame the air carried, by the station's queues.
    air: Vec<Vec<u8>>,
    /// Whether the AP advertises WMM.
    quality: bool,
}

impl Device<'_> {
    fn inject(&mut self, rom: &RomBoot<'_, Model>, packet: &[u8]) {
        let slot = self.entry & (rom.entries - 1);
        let raw = device_read(
            &self.native.domain,
            rom.free.region().address,
            usize::from(slot) * 8,
            8,
        );
        let vid = (u64::from_le_bytes(raw.try_into().unwrap()) & 0xfff) as u16;
        assert!(vid > 0 && rom.buffers[usize::from(vid - 1)].device_owned);
        complete_from_free_slot(rom, &self.native.domain, slot, vid, slot, packet);
        self.entry += 1;
    }

    /// Answer the command awaiting a response, once.
    fn respond(&mut self, rom: &RomBoot<'_, Model>) {
        let Some(slot) = rom.hcmd.awaiting() else {
            return;
        };
        let tfd = device_read(
            &self.native.domain,
            rom.command.region().address,
            usize::from(slot) * 256,
            256,
        );
        let first = u64::from_le_bytes(tfd[4..12].try_into().unwrap());
        let header = device_read(&self.native.domain, first, 0, 20);
        let sequence = u16::from_le_bytes(header[2..4].try_into().unwrap());
        if self.answered == Some(sequence) {
            return;
        }
        self.answered = Some(sequence);
        let id = Id {
            group: header[1],
            opcode: header[0],
            version: 0,
        };
        self.commands.push((id.group, id.opcode));
        let rest = u64::from_le_bytes(tfd[14..22].try_into().unwrap());
        let more = usize::from(u16::from_le_bytes([tfd[12], tfd[13]]));
        let mut request = header[8..].to_vec();
        if tfd[0] > 1 {
            request.extend(device_read(&self.native.domain, rest, 0, more));
        }
        let request = &request[..];
        let payload = match (id.group, id.opcode) {
            _ if id == NvmRequest::GetInformation.id().wire() => nvm_response(),
            (_, 0xc8) => {
                let country = u16::from_le_bytes([request[0], request[1]]).to_be_bytes();
                self.countries.push(country);
                // GET_CURRENT reports US; the world code comes back as 0.
                let country = match &country {
                    b"ZZ" => *b"US",
                    b"00" => [0; 2],
                    _ => country,
                };
                let mut payload = mcc_payload(country, request[2], 51);
                payload[20..24].copy_from_slice(&self.channel.to_le_bytes());
                payload[24..28].copy_from_slice(&self.channel.to_le_bytes());
                payload
            }
            (1 | 5, 0x08) => vec![0x9b],
            (_, 0x9f) => vec![0xaa],
            (5, 0x17) if request[0] == 0 => {
                let queue = 511 - self.queues.len() as u16;
                let descriptors = u64::from_le_bytes(request[28..36].try_into().unwrap());
                self.queues.push((request[8], queue, descriptors, 0));
                let mut answer = reply(queue);
                answer[4..6].fill(0);
                answer.to_vec()
            }
            (5, 0x17) => {
                self.queues.retain(|known| known.0 != request[8]);
                reply(511).to_vec()
            }
            (_, 0x1e) => vec![0; 132],
            _ => Vec::new(),
        };
        self.inject(rom, &command_packet(id, sequence, &payload));
        if id == NvmRequest::AccessComplete.id().wire() {
            let complete = Id {
                group: 0,
                opcode: 4,
                version: 0,
            };
            self.inject(rom, &command_packet(complete, 0x8000, &[0x76]));
        }
        if (id.group, id.opcode) == (1, 0x0d) {
            for ssid in self.beacons.clone() {
                self.inject(rom, &beacon(ssid, self.quality));
            }
            let mut body = [0; 16];
            body[6] = 1;
            body[7] = 3;
            let done = Id {
                group: 0,
                opcode: 0x0f,
                version: 0,
            };
            self.inject(rom, &command_packet(done, 0x8000, &body));
        }
        if (id.group, id.opcode) == (3, 5) && request[4] == 1 {
            let notification = Id {
                group: 3,
                opcode: 0xfb,
                version: 0,
            };
            let mut body = [0; 16];
            body[4] = 1;
            body[8] = 1;
            self.inject(rom, &command_packet(notification, 0x8000, &body));
        }
    }

    /// Carry what the queues hold to the AP, answering each frame.
    fn transmit(&mut self, rom: &RomBoot<'_, Model>) {
        for at in 0..self.queues.len() {
            loop {
                let (_, queue, descriptors, index) = self.queues[at];
                let tfd = device_read(
                    &self.native.domain,
                    descriptors,
                    usize::from(index) * 256,
                    64,
                );
                // A finished slot holds one buffer, the invalid one.
                if tfd[0] < 2 {
                    break;
                }
                self.queues[at].3 += 1;
                let mut bytes = Vec::new();
                for tb in 0..usize::from(tfd[0]) {
                    let at = 2 + tb * 10;
                    let length = usize::from(u16::from_le_bytes([tfd[at], tfd[at + 1]]));
                    let address = u64::from_le_bytes(tfd[at + 2..at + 10].try_into().unwrap());
                    bytes.extend(device_read(&self.native.domain, address, 0, length));
                }
                let mut response = vec![0; 56];
                response[0] = 1;
                response[36..38].copy_from_slice(&queue.to_le_bytes());
                response[40] = 1;
                response[44..48].copy_from_slice(&u32::from(index + 1).to_le_bytes());
                let done = Id {
                    group: 0,
                    opcode: 0x1c,
                    version: 0,
                };
                let sequence = (queue & 31) << 8 | index;
                self.inject(rom, &command_packet(done, sequence, &response));
                // The command header, then the 20-byte body's rest.
                let mut frame = bytes[24..].to_vec();
                if frame[0] & 0x88 == 0x88 {
                    // The dword pad after the QoS header.
                    frame.drain(26..28);
                }
                match u16::from_le_bytes([frame[0], frame[1]]) & 0xfc {
                    0xb0 => self.inject(rom, &answer(0xb0, &[0, 0, 2, 0, 0, 0])),
                    0x00 => {
                        let mut body = vec![1, 0, 0, 0, 1, 0xc0, 1, 2, 0x82, 0x0c];
                        if self.quality {
                            body.extend(HT);
                            body.extend(WMM);
                        }
                        self.inject(rom, &answer(0x10, &body));
                    }
                    _ => {}
                }
                self.air.push(frame);
            }
        }
    }
}

/// A frame from the AP to the station.
fn answer(subtype: u16, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 24];
    frame[..2].copy_from_slice(&subtype.to_le_bytes());
    frame[4..10].copy_from_slice(&LOCAL);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame.extend(body);
    mpdu(frame, 3)
}

/// The station address `nvm_response` holds.
const LOCAL: [u8; 6] = [0x02, 0x12, 0x34, 0x56, 0x78, 0x9a];

/// A channel 1 ESS beacon from 02:03:04:05:06:07 carrying `ssid` and the 1
/// and 6 Mb/s rates.
fn beacon(ssid: &[u8], quality: bool) -> Vec<u8> {
    let mut frame = vec![0; 36];
    frame[..2].copy_from_slice(&0x80u16.to_le_bytes());
    frame[4..10].fill(0xff);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame[32..34].copy_from_slice(&100u16.to_le_bytes());
    frame[34] = 0x11;
    frame.extend([0, ssid.len() as u8]);
    frame.extend(ssid);
    frame.extend([1, 2, 0x82, 0x0c, 3, 1, 1, 5, 4, 0, 2, 0, 0]);
    frame.extend(RSN);
    if quality {
        frame.extend(HT);
        frame.extend(WMM);
    }
    mpdu(frame, 3)
}

/// `frame` as the firmware's RX packet, at `status` and the beacon's signal.
fn mpdu(frame: Vec<u8>, status: u32) -> Vec<u8> {
    let mut payload = vec![0; 48];
    payload[..2].copy_from_slice(&(frame.len() as u16).to_le_bytes());
    payload[7] = 1 << 6;
    payload[12..16].copy_from_slice(&status.to_le_bytes());
    payload[16..20].copy_from_slice(&(127u32 << 24).to_le_bytes());
    payload[28..32].copy_from_slice(&(3u32 << 14).to_le_bytes());
    payload[32..35].copy_from_slice(&[44, 56, 1]);
    payload.extend(frame);
    let mpdu = Id {
        group: 0,
        opcode: 0xc1,
        version: 0,
    };
    command_packet(mpdu, 0x8000, &payload)
}

/// Bring the modeled function up for the network "test" until it is ready
/// to authenticate or fails, with `flags` on the US 2.4 GHz rule and
/// `channel` as the firmware's channel word.
fn bring_up<'n>(
    native: &'n Native,
    country: Option<[u8; 2]>,
    beacons: Vec<&'static [u8]>,
    flags: u8,
    channel: u32,
) -> (Station<Model, ClockBios>, Phase, Device<'n>) {
    raise(native, country, beacons, flags, channel, false)
}

/// [`bring_up`] with an AP that does or does not advertise WMM.
fn raise<'n>(
    native: &'n Native,
    country: Option<[u8; 2]>,
    beacons: Vec<&'static [u8]>,
    flags: u8,
    channel: u32,
    quality: bool,
) -> (Station<Model, ClockBios>, Phase, Device<'n>) {
    let catalog: &'static resources::Catalog = Box::leak(Box::new(catalog_for(
        &profile(),
        Family::Ax200.firmware_name(),
        &coex_image(2),
    )));
    let source: &'static Source = Box::leak(Box::new(Source::default()));
    native
        .state
        .lock()
        .unwrap()
        .registers
        .extend([(0x388, 0x02123456), (0x38c, 0x789a)]);
    let mut boot = start(
        catalog,
        source,
        &native.domain,
        &native.state,
        &native.drops,
    );
    event(&native.state, 1);
    boot.poll().unwrap();
    let mut alive = rx_packet(1, 0xcafe, 0);
    set_sku(&mut alive, [0; 3]);
    let mut device = Device {
        native,
        entry: 0,
        answered: None,
        beacons,
        channel,
        countries: Vec::new(),
        commands: Vec::new(),
        queues: Vec::new(),
        air: Vec::new(),
        quality,
    };
    device.inject(&boot, &alive);
    let inputs = Inputs {
        firmware: catalog,
        observations: Observations::default(),
        pages: source,
        clock: Clock {
            ticks_per_microsecond: 1_000_000,
        },
        bios: clock_bios(&native.bios_drops, Some(1)),
        database: regdb(&[
            (*b"00", &[(2_402_000, 2_472_000, 0, 2000)]),
            (*b"US", &[(2_402_000, 2_472_000, flags, 3000)]),
        ]),
        network: Network {
            ssid: b"test".to_vec(),
            secret: Secret::Psk(Zeroizing::new([0; 32])),
            country,
        },
        entropy: Arc::new(FixedEntropy),
    };
    // SAFETY: the model owns its pages and nothing else reaches the function.
    let mut wifi = unsafe { crate::wifi::intel::link::Wifi::new(boot, inputs) };
    let mut phase = Phase::Booting;
    for _ in 0..600 {
        wifi.carrier();
        phase = wifi.radio().phase();
        if matches!(phase, Phase::AuthenticationRequired | Phase::Failed) {
            break;
        }
        device.respond(wifi.radio().rom().unwrap());
    }
    (wifi, phase, device)
}

/// Serve the modeled air until `done`.
fn run(
    wifi: &mut Station<Model, ClockBios>,
    device: &mut Device<'_>,
    mut done: impl FnMut(&Station<Model, ClockBios>, &Device<'_>, bool) -> bool,
) -> bool {
    for _ in 0..600 {
        let up = wifi.carrier();
        if done(wifi, device, up) {
            return true;
        }
        let Some(rom) = wifi.radio().rom() else {
            panic!("{:?} {:?}", wifi.radio().phase(), wifi.radio().error());
        };
        device.respond(rom);
        device.transmit(rom);
    }
    false
}

/// A data frame from the AP to `receiver`, with `key` the index and packet
/// number the firmware decrypted it under.
fn data(
    receiver: [u8; 6],
    quality: bool,
    kind: [u8; 2],
    body: &[u8],
    key: Option<(u8, u8)>,
) -> Vec<u8> {
    let mut frame = vec![0; if quality { 26 } else { 24 }];
    frame[0] = if quality { 0x88 } else { 0x08 };
    frame[1] = if key.is_some() { 0x42 } else { 0x02 };
    frame[4..10].copy_from_slice(&receiver);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    if let Some((index, number)) = key {
        frame.extend([number, 0, 0, 0x20 | index << 6, 0, 0, 0, 0]);
    }
    frame.extend([0xaa, 0xaa, 3, 0, 0, 0]);
    frame.extend(kind);
    frame.extend(body);
    mpdu(
        frame,
        if key.is_some() {
            3 | 2 << 8 | 1 << 6
        } else {
            3
        },
    )
}

/// What `frame` from the station carries past its header and LLC.
fn eapol(frame: &[u8]) -> &[u8] {
    let header = if frame[0] & 0x88 == 0x88 { 26 } else { 24 };
    assert_eq!(frame[header + 6..header + 8], [0x88, 0x8e]);
    &frame[header + 8..]
}

/// Join the model's AP through its handshake to an open port.
fn connect<'n>(native: &'n Native, quality: bool) -> (Station<Model, ClockBios>, Device<'n>) {
    let (mut wifi, phase, mut device) =
        raise(native, Some(*b"US"), vec![b"test"], 0, OPEN, quality);
    assert_eq!(phase, Phase::AuthenticationRequired);
    let associated = run(&mut wifi, &mut device, |wifi, _, _| {
        wifi.radio().station().phase() == Peering::Associated
    });
    assert!(associated, "{:?}", wifi.radio().station().phase());
    let security = Security::select(&RSN, true).unwrap();
    let pmk = Zeroizing::new([0; 32]);
    let mut ap = Authenticator::between(
        security.suites(),
        pmk,
        Mac(AP),
        Mac(LOCAL),
        security.element(),
    );
    let local = data(LOCAL, false, [0x88, 0x8e], &ap.message_1(), None);
    device.inject(wifi.radio().rom().unwrap(), &local);
    let answered = run(&mut wifi, &mut device, |_, device, _| device.air.len() > 2);
    assert!(answered, "{:?}", wifi.radio().error());
    ap.message_2(eapol(&device.air[2]));
    let local = data(LOCAL, false, [0x88, 0x8e], &ap.message_3(&RSN), None);
    device.inject(wifi.radio().rom().unwrap(), &local);
    let up = run(&mut wifi, &mut device, |_, _, up| up);
    assert!(
        up,
        "{:?} {:?}",
        wifi.radio().error(),
        device.commands.last()
    );
    // Message 4: pairwise, MIC and secure.
    let answered = run(&mut wifi, &mut device, |_, device, _| device.air.len() > 3);
    assert!(answered, "{:?}", wifi.radio().error());
    ap.signed_reply(eapol(&device.air[3]), 0x308);
    (wifi, device)
}

/// A valid channel that allows initiated radiation.
const OPEN: u32 = 0x0f09;

#[test]
fn bring_up_scans_for_the_network_and_readies_its_station() {
    let native = Native::default();
    let (wifi, phase, device) = bring_up(&native, Some(*b"US"), vec![b"test"], 0, OPEN);
    let wifi = wifi.radio();
    assert_eq!(wifi.error(), None);
    assert_eq!(device.countries.last(), Some(b"US"));
    assert_eq!(phase, Phase::AuthenticationRequired);
    let selected = wifi.selected().unwrap();
    assert_eq!(selected.bss.bssid, Mac(AP));
    assert_eq!(selected.bss.channel.number, 1);
    assert_eq!(selected.rates, 0b1_0001);
    assert_ne!(wifi.address(), Mac::default());
}

#[test]
fn without_a_country_world_rules_apply_and_only_the_networks_bss_is_joined() {
    let native = Native::default();
    let (wifi, phase, device) = bring_up(&native, None, vec![b"other", b"test"], 0, OPEN);
    let wifi = wifi.radio();
    assert_eq!(wifi.error(), None);
    assert_eq!(phase, Phase::AuthenticationRequired);
    // The BIOS country, CN, is not in the database.
    assert_eq!(device.countries.last(), Some(&WORLD));
    assert_eq!(
        wifi.selected().unwrap().bss.ssid.as_deref(),
        Some(b"test".as_slice())
    );
}

#[test]
fn a_station_joins_an_ap_on_a_dfs_no_ir_indoor_only_channel() {
    let native = Native::default();
    // Valid, without ACTIVE, with RADAR and INDOOR_ONLY.
    let restricted = 0x0f31;
    let (wifi, phase, _) = bring_up(&native, Some(*b"US"), vec![b"test"], 2 | 4 | 8, restricted);
    let wifi = wifi.radio();
    assert_eq!(wifi.error(), None);
    assert_eq!(phase, Phase::AuthenticationRequired);
    assert_eq!(wifi.selected().unwrap().bss.channel.number, 1);
}

#[test]
fn a_station_associates_answers_the_handshake_and_leaves_with_its_ap() {
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, false);
    // Session protection before the exchange, then the MAC, link, rates and
    // station of the association, in mvm's order, and the power update.
    let mut commands = device.commands.iter();
    for command in [(3, 5), (3, 9), (5, 0x0f), (3, 0x0a), (3, 8), (1, 0xa9)] {
        assert!(commands.any(|known| *known == command), "{command:?}");
    }
    assert_eq!(device.air[0][0], 0xb0);
    assert_eq!(device.air[1][0], 0x00);
    // The pairwise key, then the group key; the port opens over both.
    let keys = |device: &Device<'_>| device.commands.iter().filter(|c| **c == (5, 0x18)).count();
    assert_eq!(keys(&device), 2);

    let ethernet = [&[9; 6][..], &LOCAL, &[8, 0], &[0xab; 46]].concat();
    wifi.transmit(&ethernet).unwrap();
    let sent = run(&mut wifi, &mut device, |_, device, _| device.air.len() > 4);
    assert!(sent, "{:?}", wifi.radio().error());
    let frame = &device.air[4];
    assert_eq!(frame[..2], [0x08, 0x41]);
    assert_eq!(frame[16..22], [9; 6]);
    // The firmware encrypts, and writes the CCMP header it needs.
    assert_eq!(frame[24 + 8..], ethernet[14..]);

    device.inject(
        wifi.radio().rom().unwrap(),
        &data(LOCAL, false, [8, 0], &[1; 46], Some((0, 1))),
    );
    // Message 3's group counter is 7.
    let group = [1, 0, 0x5e, 0, 0, 1];
    device.inject(
        wifi.radio().rom().unwrap(),
        &data(group, false, [8, 0], &[2; 46], Some((1, 8))),
    );
    run(&mut wifi, &mut device, |_, _, _| false);
    let unicast = wifi.receive().unwrap().expect("the pairwise frame");
    assert_eq!(unicast[..6], LOCAL);
    assert_eq!(unicast[14..], [1; 46]);
    let multicast = wifi.receive().unwrap().expect("the group frame");
    assert_eq!(multicast[..6], group);

    let deauthentication = answer(0xc0, &[3, 0]);
    device.inject(wifi.radio().rom().unwrap(), &deauthentication);
    assert!(
        run(&mut wifi, &mut device, |wifi, _, _| {
            wifi.radio().stage() == Standing::Idle
        }),
        "{:?} {:?} {:?}",
        wifi.radio().stage(),
        wifi.radio().error(),
        device.commands.last(),
    );
    assert!(device.commands.contains(&(3, 0x0c)));
    assert_eq!(keys(&device), 4);
    assert_eq!(wifi.radio().station().phase(), Peering::Idle);
}

#[test]
fn a_leaving_station_tells_its_ap_before_its_station_goes() {
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, false);
    let commands = device.commands.len();
    wifi.radio_mut().deauthenticate(3).unwrap();
    let left = run(&mut wifi, &mut device, |wifi, _, _| {
        wifi.radio().stage() == Standing::Idle
    });
    assert!(left, "{:?}", wifi.radio().error());
    let farewell = device.air.last().unwrap();
    assert_eq!(farewell[0], 0xc0);
    // Protected or not, its reason survives.
    assert_eq!(farewell[24..26], [3, 0]);
    assert!(device.commands[commands..].contains(&(3, 0x0c)));
}

#[test]
fn a_country_the_air_tells_an_associated_station_changes_nothing() {
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, false);
    let update = Id {
        group: 0,
        opcode: 0xc9,
        version: 0,
    };
    device.inject(
        wifi.radio().rom().unwrap(),
        &command_packet(update, 0x8000, &[b'E', b'D', 5, 0]),
    );
    let ethernet = [&[9; 6][..], &LOCAL, &[8, 0], &[0xab; 46]].concat();
    wifi.transmit(&ethernet).unwrap();
    let sent = run(&mut wifi, &mut device, |_, device, _| device.air.len() > 4);
    assert!(sent, "{:?}", wifi.radio().error());
}

#[test]
fn a_wmm_ap_gets_each_class_on_its_tids_queue() {
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, true);
    // The handshake's voice-class frames took their TID's queue.
    let queues = device.queues.len();
    assert!(queues >= 2, "{:?}", device.queues);
    let ethernet = [&[9; 6][..], &LOCAL, &[8, 0], &[0x45], &[0; 45]].concat();
    wifi.transmit(&ethernet).unwrap();
    let sent = run(&mut wifi, &mut device, |_, device, _| device.air.len() > 4);
    assert!(sent, "{:?}", wifi.radio().error());
    // Best effort, a TID of its own.
    assert_eq!(device.air[4][0], 0x88);
    assert_eq!(device.air[4][24], 0);
    assert_eq!(device.queues.len(), queues + 1);
}
