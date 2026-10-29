// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Stela contributors
//! The polled bring-up against the device model, which answers every host
//! command, completes ALIVE and NVM init, and reports one beacon per scan.
use super::*;
use crate::net::wifi::intel::{
    link::{Inputs, Phase, Wifi},
    nvm::Request as NvmRequest,
    policy::{WORLD, tests::regdb},
};
use crate::probe::{WifiConfig, WifiSecret};
use alloc::boxed::Box;
use zeroize::Zeroizing;

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
        let request = &header[8..];
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
            (5, 0x17) => reply(511).to_vec(),
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
            let ssid = if self.beacons.len() > 1 {
                self.beacons.remove(0)
            } else {
                self.beacons[0]
            };
            self.inject(rom, &beacon(ssid));
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
    }
}

/// A channel 1 ESS beacon from 02:03:04:05:06:07 carrying `ssid` and the 1
/// and 6 Mb/s rates.
fn beacon(ssid: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 36];
    frame[..2].copy_from_slice(&0x80u16.to_le_bytes());
    frame[4..10].fill(0xff);
    frame[10..16].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
    frame[16..22].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
    frame[32..34].copy_from_slice(&100u16.to_le_bytes());
    frame[34] = 1;
    frame.extend([0, ssid.len() as u8]);
    frame.extend(ssid);
    frame.extend([1, 2, 0x82, 0x0c, 3, 1, 1]);
    let mut payload = vec![0; 48];
    payload[..2].copy_from_slice(&(frame.len() as u16).to_le_bytes());
    payload[7] = 1 << 6;
    payload[12..16].copy_from_slice(&3u32.to_le_bytes());
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
fn bring_up(
    native: &Native,
    country: Option<[u8; 2]>,
    beacons: Vec<&'static [u8]>,
    flags: u8,
    channel: u32,
) -> (Wifi<Model, ClockBios>, Phase, Vec<[u8; 2]>) {
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
        network: WifiConfig {
            ssid: b"test".to_vec(),
            secret: WifiSecret::Psk(Zeroizing::new([0; 32])),
            country,
        },
    };
    // SAFETY: the model owns its pages and nothing else reaches the function.
    let mut wifi = unsafe { Wifi::new(boot, inputs) };
    let mut phase = Phase::Booting;
    for _ in 0..400 {
        phase = wifi.poll();
        if matches!(phase, Phase::AuthenticationRequired | Phase::Failed) {
            break;
        }
        device.respond(wifi.rom().unwrap());
    }
    (wifi, phase, device.countries)
}

/// A valid channel that allows initiated radiation.
const OPEN: u32 = 0x0f09;

#[test]
fn bring_up_scans_for_the_network_and_readies_its_station() {
    let native = Native::default();
    let (wifi, phase, countries) = bring_up(&native, Some(*b"US"), vec![b"test"], 0, OPEN);
    assert_eq!(wifi.error(), None);
    assert_eq!(countries.last(), Some(b"US"));
    assert_eq!(phase, Phase::AuthenticationRequired);
    let selected = wifi.selected().unwrap();
    assert_eq!(selected.bss.bssid, Mac([2, 3, 4, 5, 6, 7]));
    assert_eq!(selected.bss.channel.number, 1);
    assert_eq!(selected.rates, 0b1_0001);
    assert_ne!(wifi.address(), Mac::default());
}

#[test]
fn without_a_country_world_rules_apply_and_scans_repeat_until_the_ssid_is_heard() {
    let native = Native::default();
    let (wifi, phase, countries) = bring_up(&native, None, vec![b"other", b"test"], 0, OPEN);
    assert_eq!(wifi.error(), None);
    assert_eq!(phase, Phase::AuthenticationRequired);
    // The BIOS country, CN, is not in the database.
    assert_eq!(countries.last(), Some(&WORLD));
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
    assert_eq!(wifi.error(), None);
    assert_eq!(phase, Phase::AuthenticationRequired);
    assert_eq!(wifi.selected().unwrap().bss.channel.number, 1);
}
