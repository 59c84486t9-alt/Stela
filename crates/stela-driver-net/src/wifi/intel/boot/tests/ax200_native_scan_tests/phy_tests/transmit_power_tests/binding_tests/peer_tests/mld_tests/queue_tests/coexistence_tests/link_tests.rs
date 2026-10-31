// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Stela contributors
//! The polled bring-up against the device model, which answers every host
//! command, completes ALIVE and NVM init, reports its beacons per scan, and
//! plays the AP: it reads frames from the queues the scheduler added.
use super::*;
use crate::wifi::connection::keeper::{Radio, Stage as Standing};
use crate::wifi::connection::security::Security;
use crate::wifi::intel::{
    identity::EhtLimits,
    link::{Inputs, Phase, Station},
    nvm::Request as NvmRequest,
    policy::{WORLD, tests::regdb},
};
use crate::wifi::network::{Network, Secret};
use crate::wifi::sae::{Derivation, Exchange, Frame, H2E_RSNXE, Template};
use crate::wifi::station::{Phase as Peering, wire::multi_link::Basic};
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
    /// What else the AP's beacons and association response carry.
    elements: &'static [u8],
    /// Each link and station command.
    configuration: Vec<(u8, Vec<u8>)>,
    /// Each receive Block Ack command.
    block_acks: Vec<Vec<u8>>,
    /// Each scan request.
    scans: Vec<Vec<u8>>,
    /// The second channel's rules, when they differ from the first's, and the
    /// AP then only heard from the first scan.
    second: Option<u32>,
    /// Whether frames are acknowledged in Block Ack notifications alone, as
    /// the firmware reports those it aggregated.
    aggregating: bool,
    /// The address the AP answers.
    receiver: [u8; 6],
    /// The AP's RSN element.
    rsn: &'static [u8],
    /// Each MAC command.
    macs: Vec<Vec<u8>>,
    /// The AP MLD's side of SAE, and the confirm it holds back.
    sae: Option<Exchange>,
    confirm: Option<Frame>,
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
                let second = self.second.unwrap_or(self.channel);
                payload[24..28].copy_from_slice(&second.to_le_bytes());
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
            (5, 0x16) => {
                self.block_acks.push(request.to_vec());
                u32::from(SESSION).to_le_bytes().to_vec()
            }
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
        if (id.group, id.opcode) == (3, 8) {
            self.macs.push(request.to_vec());
        }
        if id.group == 3 && matches!(id.opcode, 9 | 0x0a) {
            self.configuration.push((id.opcode, request.to_vec()));
        }
        if (id.group, id.opcode) == (1, 0x0d) {
            self.scans.push(request.to_vec());
            if self.second.is_none() || self.scans.len() == 1 {
                for ssid in self.beacons.clone() {
                    self.inject(rom, &beacon(ssid, self.rsn, self.quality, self.elements));
                }
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

    /// Answer the station MLD's SAE `frame`: its commit, or its confirm.
    fn exchange(&mut self, rom: &RomBoot<'_, Model>, frame: &[u8]) {
        let field = |at: usize| u16::from_le_bytes([frame[at], frame[at + 1]]);
        let (transaction, status) = (field(26), field(28));
        let own = Basic {
            address: Mac(LOCAL),
            ..Basic::default()
        };
        let data = &frame[30..frame.len() - own.encode().len()];
        let sae = self.sae.as_mut().unwrap();
        let reply = if transaction == 1 {
            self.confirm = sae.receive(1, status, data).unwrap();
            sae.commit()
        } else {
            assert_eq!(sae.receive(2, status, data).unwrap(), None);
            self.confirm.take().unwrap()
        };
        let mut body = [3, 0].to_vec();
        body.extend(reply.transaction.to_le_bytes());
        body.extend(reply.status.to_le_bytes());
        body.extend(reply.data);
        let ap = Basic {
            address: Mac(AP_MLD),
            ..Basic::default()
        };
        body.extend(ap.encode());
        self.inject(rom, &answer(self.receiver, 0xb0, &body));
    }

    /// Carry what the queues hold to the AP, answering each frame, as much
    /// as the receive buffers keep up with.
    fn transmit(&mut self, rom: &RomBoot<'_, Model>) {
        let mut room = 4;
        for at in 0..self.queues.len() {
            loop {
                if room == 0 {
                    return;
                }
                room -= 1;
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
                let next = (index + 1) % 256;
                self.queues[at].3 = next;
                let mut bytes = Vec::new();
                for tb in 0..usize::from(tfd[0]) {
                    let at = 2 + tb * 10;
                    let length = usize::from(u16::from_le_bytes([tfd[at], tfd[at + 1]]));
                    let address = u64::from_le_bytes(tfd[at + 2..at + 10].try_into().unwrap());
                    bytes.extend(device_read(&self.native.domain, address, 0, length));
                }
                if self.aggregating {
                    let mut body = vec![0; 40];
                    body[28] = 1;
                    body[32..34].copy_from_slice(&queue.to_le_bytes());
                    body[34..36].copy_from_slice(&next.to_le_bytes());
                    let acknowledged = Id {
                        group: 0,
                        opcode: 0xc5,
                        version: 0,
                    };
                    self.inject(rom, &command_packet(acknowledged, 0x8000, &body));
                } else {
                    let mut response = vec![0; 56];
                    response[0] = 1;
                    response[36..38].copy_from_slice(&queue.to_le_bytes());
                    response[40] = 1;
                    response[44..48].copy_from_slice(&u32::from(next).to_le_bytes());
                    let done = Id {
                        group: 0,
                        opcode: 0x1c,
                        version: 0,
                    };
                    let sequence = (queue & 31) << 8 | index;
                    self.inject(rom, &command_packet(done, sequence, &response));
                }
                // The command header, then the 20-byte body's rest.
                let mut frame = bytes[24..].to_vec();
                if frame[0] & 0x88 == 0x88 {
                    // The dword pad after the QoS header.
                    frame.drain(26..28);
                }
                match u16::from_le_bytes([frame[0], frame[1]]) & 0xfc {
                    0xb0 if self.sae.is_some() => self.exchange(rom, &frame),
                    0xb0 => self.inject(rom, &answer(self.receiver, 0xb0, &[0, 0, 2, 0, 0, 0])),
                    0x00 => {
                        let mut body = vec![0x11, 0, 0, 0, 1, 0xc0, 1, 2, 0x82, 0x0c];
                        if self.quality {
                            body.extend(HT);
                            body.extend(WMM);
                        }
                        body.extend(self.elements);
                        self.inject(rom, &answer(self.receiver, 0x10, &body));
                    }
                    _ => {}
                }
                self.air.push(frame);
            }
        }
    }
}

/// A frame from the AP to the station.
fn answer(receiver: [u8; 6], subtype: u16, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 24];
    frame[..2].copy_from_slice(&subtype.to_le_bytes());
    frame[4..10].copy_from_slice(&receiver);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame.extend(body);
    mpdu(frame, 3)
}

/// The station address `nvm_response` holds.
const LOCAL: [u8; 6] = [0x02, 0x12, 0x34, 0x56, 0x78, 0x9a];

/// A channel 1 ESS beacon from 02:03:04:05:06:07 carrying `ssid` and the 1
/// and 6 Mb/s rates.
fn beacon(ssid: &[u8], rsn: &[u8], quality: bool, elements: &[u8]) -> Vec<u8> {
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
    frame.extend(rsn);
    if quality {
        frame.extend(HT);
        frame.extend(WMM);
    }
    frame.extend(elements);
    mpdu(frame, 3)
}

/// `frame` as the firmware's RX packet, at `status` and the beacon's signal.
fn mpdu(frame: Vec<u8>, status: u32) -> Vec<u8> {
    placed(frame, status, None, 127 << 24)
}

/// [`mpdu`], as an A-MSDU's record at its index and whether it is the last,
/// with `reorder` the descriptor's reorder word.
fn placed(frame: Vec<u8>, status: u32, record: Option<(u8, bool)>, reorder: u32) -> Vec<u8> {
    let mut payload = vec![0; 48];
    payload[..2].copy_from_slice(&(frame.len() as u16).to_le_bytes());
    if let Some((index, last)) = record {
        payload[3] = 0x40;
        payload[4] = index | u8::from(last) << 7;
    }
    payload[7] = 1 << 6;
    payload[12..16].copy_from_slice(&status.to_le_bytes());
    payload[16..20].copy_from_slice(&reorder.to_le_bytes());
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
    raise_beside(native, country, beacons, flags, channel, quality, &[])
}

/// [`raise`], with `elements` on the AP's frames.
fn raise_beside<'n>(
    native: &'n Native,
    country: Option<[u8; 2]>,
    beacons: Vec<&'static [u8]>,
    flags: u8,
    channel: u32,
    quality: bool,
    elements: &'static [u8],
) -> (Station<Model, ClockBios>, Phase, Device<'n>) {
    raise_split(
        native, country, beacons, flags, channel, quality, elements, None,
    )
}

/// [`raise_beside`], with [`Device::second`].
#[expect(clippy::too_many_arguments, reason = "each is a fixture's own knob")]
fn raise_split<'n>(
    native: &'n Native,
    country: Option<[u8; 2]>,
    beacons: Vec<&'static [u8]>,
    flags: u8,
    channel: u32,
    quality: bool,
    elements: &'static [u8],
    second: Option<u32>,
) -> (Station<Model, ClockBios>, Phase, Device<'n>) {
    let secret = Secret::Psk(Zeroizing::new([0; 32]));
    raise_as(
        native, country, beacons, flags, channel, quality, elements, second, &RSN, None, secret,
    )
}

/// [`raise_split`], with [`Device::rsn`] and a radio standing in for `eht`.
#[expect(clippy::too_many_arguments, reason = "each is a fixture's own knob")]
fn raise_as<'n>(
    native: &'n Native,
    country: Option<[u8; 2]>,
    beacons: Vec<&'static [u8]>,
    flags: u8,
    channel: u32,
    quality: bool,
    elements: &'static [u8],
    second: Option<u32>,
    rsn: &'static [u8],
    eht: Option<EhtLimits>,
    secret: Secret,
) -> (Station<Model, ClockBios>, Phase, Device<'n>) {
    let catalog: &'static resources::Catalog = Box::leak(Box::new(catalog_for(
        &profile(),
        Family::Ax200.firmware_name(),
        &feature(feature(coex_image(2), 30, 63, true), 30, 21, true),
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
        elements,
        configuration: Vec::new(),
        block_acks: Vec::new(),
        scans: Vec::new(),
        second,
        aggregating: false,
        receiver: LOCAL,
        rsn,
        macs: Vec::new(),
        sae: None,
        confirm: None,
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
            secret,
            country,
        },
        entropy: Arc::new(FixedEntropy),
    };
    // SAFETY: the model owns its pages and nothing else reaches the function.
    let mut wifi = unsafe { crate::wifi::intel::link::Wifi::new(boot, inputs) };
    wifi.radio_mut().assumed_eht = eht;
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
/// The session the model's firmware allocates.
const SESSION: u8 = 3;

/// A TID 0 frame of a Block Ack session under the pairwise key, at `sequence`
/// with the window at `next`, carrying `value` under packet number `number`.
fn session_frame(sequence: u16, next: u16, number: u8, value: u8) -> Vec<u8> {
    let (frame, reorder) = protected(sequence, next, number, value, false, false);
    placed(frame, 3 | 2 << 8 | 1 << 6, None, reorder)
}

fn protected(
    sequence: u16,
    next: u16,
    number: u8,
    value: u8,
    record: bool,
    retry: bool,
) -> (Vec<u8>, u32) {
    let mut frame = vec![0; 26];
    frame[0] = 0x88;
    frame[1] = 0x42 | u8::from(retry) << 3;
    frame[4..10].copy_from_slice(&LOCAL);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame[21] = value;
    frame[22..24].copy_from_slice(&(sequence << 4).to_le_bytes());
    frame[24] = u8::from(record) << 7;
    frame.extend([number, 0, 0, 0x20, 0, 0, 0, 0]);
    frame.extend([0xaa, 0xaa, 3, 0, 0, 0, 8, 0]);
    frame.extend([value; 46]);
    let reorder = u32::from(next) | u32::from(sequence) << 12 | u32::from(SESSION) << 24;
    (frame, reorder)
}

/// What the station now holds for the network, as payload values.
fn delivered(wifi: &mut Station<Model, ClockBios>) -> Vec<u8> {
    let mut values = Vec::new();
    while let Some(ethernet) = wifi.receive().unwrap() {
        values.push(ethernet[14]);
    }
    values
}

/// Serve the air until nothing more can come of what it holds.
fn settle(wifi: &mut Station<Model, ClockBios>, device: &mut Device<'_>) {
    run(wifi, device, |_, _, _| false);
}

/// Connect to a WMM AP and agree on TID 0's session from sequence 5.
fn agreed<'n>(native: &'n Native) -> (Station<Model, ClockBios>, Device<'n>) {
    let (mut wifi, mut device) = connect(native, true);
    let parameters: u16 = 3 | 8 << 6;
    let mut body = vec![3, 0, 9];
    body.extend(parameters.to_le_bytes());
    body.extend(0u16.to_le_bytes());
    body.extend((5u16 << 4).to_le_bytes());
    device.inject(wifi.radio().rom().unwrap(), &answer(LOCAL, 0xd0, &body));
    let accepted = run(&mut wifi, &mut device, |_, device, _| {
        device
            .air
            .last()
            .is_some_and(|frame| frame[0] == 0xd0 && frame[24..26] == [3, 1])
    });
    assert!(accepted, "{:?} {:?}", wifi.radio().error(), device.commands);
    (wifi, device)
}

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

    let deauthentication = answer(LOCAL, 0xc0, &[3, 0]);
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

#[test]
fn a_block_ack_session_is_agreed_with_the_firmware_first() {
    let native = Native::default();
    let (_, device) = agreed(&native);
    let command = &device.block_acks[0];
    assert_eq!(command[..4], [0, 0, 0, 0]);
    assert_eq!(command[4], 1);
    assert_eq!(command[8], 0);
    assert_eq!(command[12..14], 5u16.to_le_bytes());
    assert_eq!(command[14..16], 8u16.to_le_bytes());
    let response = device.air.last().unwrap();
    // The dialog, success, and the window with A-MSDU permission.
    assert_eq!(response[26], 9);
    assert_eq!(response[27..29], [0, 0]);
    let parameters = u16::from_le_bytes([response[29], response[30]]);
    assert_eq!(parameters >> 6, 8);
    assert_eq!(parameters & 1, 1);
}

#[test]
fn a_session_gives_the_station_its_frames_in_order() {
    let native = Native::default();
    let (mut wifi, mut device) = agreed(&native);
    device.inject(wifi.radio().rom().unwrap(), &session_frame(6, 5, 2, 0x66));
    settle(&mut wifi, &mut device);
    assert_eq!(delivered(&mut wifi), []);
    device.inject(wifi.radio().rom().unwrap(), &session_frame(5, 7, 1, 0x55));
    settle(&mut wifi, &mut device);
    assert_eq!(delivered(&mut wifi), [0x55, 0x66]);
    // The firmware gives up on 7.
    device.inject(wifi.radio().rom().unwrap(), &session_frame(8, 7, 3, 0x88));
    settle(&mut wifi, &mut device);
    assert_eq!(delivered(&mut wifi), []);
    let release = Id {
        group: 0,
        opcode: 0xc3,
        version: 0,
    };
    device.inject(
        wifi.radio().rom().unwrap(),
        &command_packet(release, 0x8000, &[SESSION, 0, 9, 0]),
    );
    settle(&mut wifi, &mut device);
    assert_eq!(delivered(&mut wifi), [0x88]);
}

#[test]
fn a_firmware_split_amsdu_reaches_the_station_whole_under_one_packet_number() {
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, true);
    let status = 3 | 2 << 8 | 1 << 6;
    for (index, value, last) in [(0, 0x11, false), (1, 0x22, false), (2, 0x33, true)] {
        let (frame, _) = protected(5, 6, 1, value, true, false);
        device.inject(
            wifi.radio().rom().unwrap(),
            &placed(frame, status, Some((index, last)), 127 << 24),
        );
    }
    settle(&mut wifi, &mut device);
    let mut sources = Vec::new();
    while let Some(ethernet) = wifi.receive().unwrap() {
        assert_eq!(ethernet[..6], LOCAL);
        sources.push(ethernet[11]);
    }
    assert_eq!(sources, [0x11, 0x22, 0x33]);
    // The same MPDU retried, and one that replays its packet number, go.
    let (frame, _) = protected(5, 6, 1, 0x44, false, true);
    device.inject(
        wifi.radio().rom().unwrap(),
        &placed(frame, status, None, 127 << 24),
    );
    let (frame, _) = protected(6, 7, 1, 0x55, false, false);
    device.inject(
        wifi.radio().rom().unwrap(),
        &placed(frame, status, None, 127 << 24),
    );
    settle(&mut wifi, &mut device);
    assert_eq!(delivered(&mut wifi), []);
}

#[test]
fn an_amsdu_missing_a_record_is_lost_whole() {
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, true);
    let status = 3 | 2 << 8 | 1 << 6;
    for (index, last) in [(0, false), (2, true)] {
        let (frame, _) = protected(5, 6, 1, 0x11, true, false);
        device.inject(
            wifi.radio().rom().unwrap(),
            &placed(frame, status, Some((index, last)), 127 << 24),
        );
    }
    settle(&mut wifi, &mut device);
    assert_eq!(delivered(&mut wifi), []);
}

#[test]
fn a_peer_ending_a_session_releases_what_it_held() {
    let native = Native::default();
    let (mut wifi, mut device) = agreed(&native);
    device.inject(wifi.radio().rom().unwrap(), &session_frame(7, 5, 3, 0x77));
    device.inject(wifi.radio().rom().unwrap(), &session_frame(6, 5, 2, 0x66));
    settle(&mut wifi, &mut device);
    assert_eq!(delivered(&mut wifi), []);
    // DELBA from the initiator of TID 0.
    device.inject(
        wifi.radio().rom().unwrap(),
        &answer(LOCAL, 0xd0, &[3, 2, 0, 0x08, 37, 0]),
    );
    settle(&mut wifi, &mut device);
    assert_eq!(delivered(&mut wifi), [0x66, 0x77]);
    let removal = device.block_acks.last().unwrap();
    assert_eq!(removal[..4], 2u32.to_le_bytes());
    // This firmware's command version names the session.
    assert_eq!(removal[4], SESSION);
    assert!(wifi.radio().station().active_rx_block_ack(0).is_none());
}

#[test]
fn a_departure_takes_its_sessions_down_without_telling_the_peer() {
    let native = Native::default();
    let (mut wifi, mut device) = agreed(&native);
    let sent = device.air.len();
    device.inject(wifi.radio().rom().unwrap(), &answer(LOCAL, 0xc0, &[3, 0]));
    let left = run(&mut wifi, &mut device, |wifi, _, _| {
        wifi.radio().stage() == Standing::Idle
    });
    assert!(left, "{:?}", wifi.radio().error());
    assert_eq!(device.block_acks.len(), 2);
    assert_eq!(device.block_acks[1][..4], 2u32.to_le_bytes());
    assert!(!device.air[sent..].iter().any(|frame| frame[0] == 0xd0));
}

#[test]
fn block_ack_notifications_alone_free_the_queues() {
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, true);
    device.aggregating = true;
    let ethernet = [&[9; 6][..], &LOCAL, &[8, 0], &[0x45], &[0; 45]].concat();
    // More than the ring holds.
    for _ in 0..6 {
        let goal = device.air.len() + 60;
        for _ in 0..60 {
            wifi.transmit(&ethernet).unwrap();
        }
        let sent = run(&mut wifi, &mut device, |_, device, _| {
            device.air.len() >= goal
        });
        assert!(sent, "{} {:?}", device.air.len(), wifi.radio().error());
    }
}

#[test]
fn frames_that_wait_together_leave_as_an_amsdu_the_firmware_allows() {
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, true);
    let rates = Id {
        group: 5,
        opcode: 0xf7,
        version: 0,
    };
    let mut body = [0; 20];
    body[4] = 2;
    body[12..14].copy_from_slice(&2200u16.to_le_bytes());
    body[16] = 1;
    device.inject(
        wifi.radio().rom().unwrap(),
        &command_packet(rates, 0x8000, &body),
    );
    settle(&mut wifi, &mut device);
    let sent = device.air.len();
    // TID 0 has no queue yet, so all three wait; the third does not fit.
    let ethernet = [&[9; 6][..], &LOCAL, &[8, 0], &[0x45], &[0; 999]].concat();
    for _ in 0..3 {
        wifi.transmit(&ethernet).unwrap();
    }
    let gone = run(&mut wifi, &mut device, |_, device, _| {
        device.air.len() >= sent + 2
    });
    assert!(gone, "{:?}", wifi.radio().error());
    settle(&mut wifi, &mut device);
    assert_eq!(device.air.len(), sent + 2);
    let aggregate = &device.air[sent];
    assert_eq!(aggregate[24] & 0x80, 0x80);
    assert_eq!(aggregate[16..22], AP);
    assert_eq!(aggregate[26..32], [9; 6]);
    assert_eq!(aggregate[32..38], LOCAL);
    let length: usize = 1000 + 8;
    assert_eq!(aggregate[38..40], (length as u16).to_be_bytes());
    let second = 26 + (14 + length).next_multiple_of(4);
    assert_eq!(aggregate[second..second + 6], [9; 6]);
    assert_eq!(aggregate.len(), second + 14 + length);
    // The third keeps its one sequence number after theirs.
    let sequence = |frame: &[u8]| u16::from_le_bytes([frame[22], frame[23]]) >> 4;
    assert_eq!(sequence(&device.air[sent + 1]), sequence(aggregate) + 1);
    assert_eq!(device.air[sent + 1][24] & 0x80, 0);
}

/// A protected frame's fragment `index` of sequence 5, under packet number
/// `number`, carrying `body` straight after its header.
fn fragment(index: u8, more: bool, number: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 26];
    frame[0] = 0x88;
    frame[1] = 0x42 | u8::from(more) << 2;
    frame[4..10].copy_from_slice(&LOCAL);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame[22..24].copy_from_slice(&(5u16 << 4 | u16::from(index)).to_le_bytes());
    frame.extend([number, 0, 0, 0x20, 0, 0, 0, 0]);
    frame.extend(body);
    mpdu(frame, 3 | 2 << 8 | 1 << 6)
}

fn first_body() -> Vec<u8> {
    [&[0xaa, 0xaa, 3, 0, 0, 0, 8, 0][..], &[0x11; 40]].concat()
}

#[test]
fn fragments_under_consecutive_packet_numbers_become_one_msdu() {
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, true);
    device.inject(
        wifi.radio().rom().unwrap(),
        &fragment(0, true, 1, &first_body()),
    );
    device.inject(
        wifi.radio().rom().unwrap(),
        &fragment(1, true, 2, &[0x22; 20]),
    );
    settle(&mut wifi, &mut device);
    assert_eq!(wifi.receive().unwrap(), None);
    device.inject(
        wifi.radio().rom().unwrap(),
        &fragment(2, false, 3, &[0x33; 10]),
    );
    settle(&mut wifi, &mut device);
    let ethernet = wifi.receive().unwrap().expect("the whole MSDU");
    assert_eq!(ethernet[12..14], [8, 0]);
    assert_eq!(ethernet.len(), 14 + 40 + 20 + 10);
    assert_eq!(ethernet[14], 0x11);
    assert_eq!(ethernet[14 + 40], 0x22);
    assert_eq!(ethernet[14 + 60], 0x33);
}

#[test]
fn a_fragment_out_of_its_place_or_its_packet_numbers_is_dropped() {
    let native = Native::default();
    let (mut wifi, mut device) = connect(&native, true);
    // With nothing before it.
    device.inject(
        wifi.radio().rom().unwrap(),
        &fragment(1, false, 1, &[0x22; 20]),
    );
    // A packet number skipped.
    device.inject(
        wifi.radio().rom().unwrap(),
        &fragment(0, true, 2, &first_body()),
    );
    device.inject(
        wifi.radio().rom().unwrap(),
        &fragment(1, false, 4, &[0x22; 20]),
    );
    settle(&mut wifi, &mut device);
    assert_eq!(wifi.receive().unwrap(), None);
}

#[test]
fn a_scan_probes_where_a_frame_may_start_and_listens_elsewhere() {
    const FORCE_PASSIVE: u8 = 8;
    let native = Native::default();
    let (_, phase, device) = raise(&native, Some(*b"US"), vec![b"test"], 0, OPEN, true);
    assert_eq!(phase, Phase::AuthenticationRequired);
    let scan = &device.scans[0];
    assert_eq!(scan[9] & FORCE_PASSIVE, 0);
    assert_eq!(scan[48], 1, "the channel probes the wildcard SSID");
    let band = u16::from_le_bytes([scan[602], scan[603]]);
    assert!(usize::from(band) > 26, "rates, DS parameters and HT");

    let native = Native::default();
    let silent = OPEN & !8;
    let (_, phase, device) = raise(&native, Some(*b"US"), vec![b"test"], 0, silent, true);
    assert_eq!(phase, Phase::AuthenticationRequired);
    let scan = &device.scans[0];
    assert_eq!(scan[9] & FORCE_PASSIVE, FORCE_PASSIVE);
    assert_eq!(scan[48], 0);
}

#[test]
fn a_network_one_scan_part_heard_outlives_the_parts_after_it() {
    let native = Native::default();
    let (_, phase, device) = raise_split(
        &native,
        Some(*b"US"),
        vec![b"test"],
        0,
        OPEN,
        true,
        &[],
        Some(OPEN & !8),
    );
    assert_eq!(device.scans.len(), 2);
    assert_eq!(phase, Phase::AuthenticationRequired);
}

/// An AP's HE capabilities, one stream with its ACK and HTC bits, then its
/// operation: 3 us packet extension, RTS threshold 5, color 9. Random access
/// and MU EDCA parameters follow it.
#[rustfmt::skip]
const HE_AP: [u8; 2 + 22 + 2 + 7 + 4 + 16] = [
    255, 22, 35,
    0x01, 0, 0x80, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0xfe, 0xff, 0xfe, 0xff,
    255, 7, 36, 0x53, 0, 0, 9, 0xfc, 0xff,
    255, 2, 37, 0x2b,
    255, 14, 38, 0,
    1, 0x95, 3,
    2, 0xa4, 4,
    3, 0xb3, 5,
    4, 0xc2, 6,
];

#[test]
fn an_he_ap_reaches_the_link_and_the_station_commands() {
    let native = Native::default();
    let (mut wifi, phase, mut device) =
        raise_beside(&native, Some(*b"US"), vec![b"test"], 0, OPEN, true, &HE_AP);
    assert_eq!(phase, Phase::AuthenticationRequired);
    let associated = run(&mut wifi, &mut device, |wifi, _, _| {
        wifi.radio().station().phase() == Peering::Associated
    });
    assert!(associated, "{:?}", wifi.radio().station().phase());
    assert!(run(&mut wifi, &mut device, |_, device, _| {
        device.configuration.len() >= 2
    }));
    let (_, link) = device
        .configuration
        .iter()
        .rfind(|(opcode, _)| *opcode == 9)
        .unwrap();
    assert_eq!(link[100..103], [3, 3, 5], "packet extension and OCW range");
    // The BE record arrives first and the firmware orders BK first.
    assert_eq!(link[104..112], [4, 0, 10, 0, 2, 0, 4, 0]);
    assert_eq!(link[112..120], [5, 0, 9, 0, 1, 0, 3, 0]);
    assert_eq!(link[146], 5, "the RTS threshold");
    assert_eq!(link[148], 2, "MU EDCA, with the color enabled");
    assert_eq!(link[152], 2, "the mask of a firmware that still has one");
    assert_eq!(link[165], 9);
    assert_eq!(link[156..162], [0; 6]);
    let (_, peer) = device
        .configuration
        .iter()
        .rfind(|(opcode, _)| *opcode == 0x0a)
        .unwrap();
    assert_eq!(peer[48], 1, "the AP's HE acknowledgements");
    assert_eq!(peer[52], 1, "random access");
    assert_eq!(peer[72..92], [7; 20], "zero nominal padding");
    assert_eq!(peer[92], 1, "HE-HTC");
}

/// The AP MLD the model's AP is link 3 of.
const AP_MLD: [u8; 6] = [2, 10, 11, 12, 13, 14];
/// The address [`FixedEntropy`] draws for the station's link.
const LINK: [u8; 6] = [0x5a; 6];
/// [`RSN`] under SAE with management frame protection required.
const RSN_SAE: [u8; 22] = [
    48, 20, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 8, 0xc0, 0,
];
/// An AP's EHT capabilities and operation, one stream at every MCS.
#[rustfmt::skip]
const EHT_AP: [u8; 2 + 15 + 2 + 6] = [
    255, 15, 108,
    0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0,
    0x11, 0x11, 0x11,
    255, 6, 106, 0, 0x11, 0, 0, 0,
];

/// [`HE_AP`] and [`EHT_AP`] as link 3 of [`AP_MLD`].
fn mld_ap() -> &'static [u8] {
    let mut elements = HE_AP.to_vec();
    elements.extend(EHT_AP);
    elements.extend(H2E_RSNXE);
    elements.extend(
        Basic {
            address: Mac(AP_MLD),
            link_id: Some(3),
            mld_capabilities: Some(0),
            ..Basic::default()
        }
        .encode(),
    );
    Box::leak(elements.into_boxed_slice())
}

#[test]
fn an_ap_mld_takes_the_station_on_a_link_of_its_own_and_gives_it_back() {
    let native = Native::default();
    let eht = EhtLimits {
        stops_at_160: false,
        reduced: false,
        urm: false,
        slow_bus: false,
    };
    let (mut wifi, phase, mut device) = raise_as(
        &native,
        Some(*b"US"),
        vec![b"test"],
        0,
        OPEN,
        true,
        mld_ap(),
        None,
        &RSN_SAE,
        Some(eht),
        Secret::parse(b"password").unwrap(),
    );
    assert_eq!(phase, Phase::AuthenticationRequired);
    device.receiver = LINK;
    let template = Template::derive(b"test", b"password", None);
    let mut random = 7;
    device.sae = Some(
        Exchange::new(
            Derivation::HashToElement,
            b"password",
            Some(&template),
            None,
            Mac(AP_MLD),
            Mac(LOCAL),
            &mut || {
                random += 1;
                [random; 32]
            },
        )
        .unwrap(),
    );
    let associated = run(&mut wifi, &mut device, |wifi, _, _| {
        wifi.radio().station().phase() == Peering::Associated
    });
    assert!(
        associated,
        "{:?} {:?}",
        wifi.radio().station().phase(),
        wifi.radio().error()
    );
    // The cold link leaves and the MLD's takes its place.
    let added: Vec<&Vec<u8>> = device
        .configuration
        .iter()
        .filter(|(opcode, bytes)| *opcode == 9 && bytes[0] == 1)
        .map(|(_, bytes)| bytes)
        .collect();
    let [cold, link] = &added[..] else {
        panic!("{} links added", added.len());
    };
    assert_eq!(cold[16..22], LOCAL);
    assert_eq!(link[16..22], LINK);
    assert_eq!(link[166], 3);
    // SAE's two frames and the association leave from the link, for the AP's.
    for frame in &device.air[..3] {
        assert_eq!(frame[4..10], AP);
        assert_eq!(frame[10..16], LINK);
    }
    let request = &device.air[2];
    let basic = Basic::find(&request[28..]).unwrap().unwrap();
    assert_eq!(basic.address, Mac(LOCAL));
    assert!(
        device
            .macs
            .iter()
            .any(|mac| mac[24] == 1 && mac[26] | mac[28] == 1),
        "address translation before the AP's capabilities are known"
    );
    assert!(run(&mut wifi, &mut device, |_, device, _| {
        let last = device
            .configuration
            .iter()
            .rfind(|(opcode, _)| *opcode == 9);
        last.is_some_and(|(_, link)| link[24..28] != 3u32.to_le_bytes())
    }));
    let (_, link) = device
        .configuration
        .iter()
        .rfind(|(opcode, _)| *opcode == 9)
        .unwrap();
    assert_eq!(link[16..22], LINK);
    assert_eq!(link[166], 3);
    let (_, peer) = device
        .configuration
        .iter()
        .rfind(|(opcode, _)| *opcode == 0x0a)
        .unwrap();
    assert_eq!(peer[8..14], AP_MLD);
    assert_eq!(peer[16..22], AP);
    // The handshake's frames name the MLDs, which firmware translates.
    let security = Security::select(&RSN_SAE, true).unwrap();
    let mut ap = Authenticator::between(
        security.suites(),
        device.sae.as_ref().unwrap().pmk().unwrap(),
        Mac(AP_MLD),
        Mac(LOCAL),
        security.element(),
    );
    let local = data(LINK, false, [0x88, 0x8e], &ap.message_1(), None);
    device.inject(wifi.radio().rom().unwrap(), &local);
    let answered = run(&mut wifi, &mut device, |_, device, _| device.air.len() > 3);
    assert!(answered, "{:?}", wifi.radio().error());
    assert_eq!(device.air[3][4..10], AP_MLD);
    assert_eq!(device.air[3][10..16], LOCAL);
    let added = device.configuration.len();
    wifi.radio_mut().deauthenticate(3).unwrap();
    let left = run(&mut wifi, &mut device, |wifi, _, _| {
        wifi.radio().stage() == Standing::Idle
    });
    assert!(left, "{:?}", wifi.radio().error());
    let farewell = device.air.last().unwrap();
    assert_eq!(farewell[0], 0xc0);
    assert_eq!(farewell[4..10], AP_MLD);
    assert_eq!(farewell[10..16], LOCAL);
    // The cold link comes back with the station's own address.
    let (_, link) = device.configuration[added..]
        .iter()
        .rfind(|(opcode, bytes)| *opcode == 9 && bytes[0] == 1)
        .unwrap();
    assert_eq!(link[16..22], LOCAL);
    assert_eq!(link[166], 0);
}
