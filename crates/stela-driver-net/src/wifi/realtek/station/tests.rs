// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Stela contributors
//! The station against a model of the chip, which plays the AP over the frames
//! it is handed.
use super::*;
use crate::wifi::connection::security::Security;
use crate::wifi::intel::policy::tests::regdb;
use crate::wifi::network::{Network, Secret};
use crate::wifi::supplicant::tests::Authenticator;
use alloc::{rc::Rc, vec};
use core::cell::RefCell;
use core::sync::atomic::{AtomicU8, Ordering};
use stela_driver_base::entropy::EntropyError;

const CLOCK: Clock = Clock {
    ticks_per_microsecond: 1,
};
const LOCAL: [u8; 6] = [2, 0x12, 0x34, 0x56, 0x78, 0x9a];
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
const SSID: &[u8] = b"test";

/// Each read one byte over the last, from 0x5a.
#[derive(Default)]
struct FixedEntropy(AtomicU8);

impl Entropy for FixedEntropy {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), EntropyError> {
        bytes.fill(0x5a + self.0.fetch_add(1, Ordering::Relaxed));
        Ok(())
    }
}

/// What the hardware was told, and what it holds for the host.
#[derive(Default)]
struct Air {
    /// The AP's channel, on which each visit hears a beacon.
    channel: u16,
    /// Each channel tuned, with whether a scan tuned it.
    tuned: Vec<(u16, bool)>,
    sent: Vec<(Queue, Packet, Vec<u8>)>,
    /// How many of `sent` the AP has answered.
    answered: usize,
    probed: Vec<u16>,
    incoming: VecDeque<Incoming>,
    commands: Vec<(u32, u32)>,
    prepared: usize,
    ports: Vec<(Mac, u16, bool)>,
    beacon_filters: Vec<bool>,
    edca: Vec<([AccessCategory; 4], bool)>,
    /// Each CAM write: entry, key index, type, group and material.
    keys: Vec<(u8, u8, u8, bool, [u8; 16])>,
    cleared: Vec<u8>,
    /// Queues refuse frames while set.
    full: bool,
    /// Management frames lost to the air before the AP hears them.
    losses: usize,
}

impl Air {
    fn hear(&mut self, bytes: Vec<u8>, decrypted: bool) {
        self.incoming.push_back(Incoming::Frame(Received {
            bytes,
            tsf: 0,
            decrypted,
            icv_error: false,
            signal_dbm: Some(-40),
        }));
    }

    /// The AP's reply to each frame it has not seen, and each frame's report.
    fn serve(&mut self) {
        while let Some((_, packet, bytes)) = self.sent.get(self.answered).cloned() {
            self.answered += 1;
            let lost = bytes[0] & 0x0c == 0 && packet.report.is_some() && self.losses > 0;
            if let Some(number) = packet.report {
                self.incoming
                    .push_back(Incoming::Report(Report::Transmitted {
                        number,
                        acknowledged: !lost,
                    }));
            }
            if lost {
                self.losses -= 1;
                continue;
            }
            match bytes[0] {
                0x40 => self.probed.extend(self.tuned.last().map(|tuned| tuned.0)),
                0xb0 => self.hear(management(0xb0, &[0, 0, 2, 0, 0, 0]), false),
                0x00 => {
                    let mut body = vec![0x11, 0, 0, 0, 1, 0xc0];
                    body.extend(rates(self.channel));
                    if self.channel < 14 {
                        body.extend(HT);
                        body.extend(WMM);
                    }
                    self.hear(management(0x10, &body), false);
                }
                _ => {}
            }
        }
    }
}

#[derive(Clone)]
struct Model(Rc<RefCell<Air>>);

impl Device for Model {
    fn tune(
        &mut self,
        definition: &ChannelDefinition,
        scanning: bool,
        eirp_mbm: i32,
    ) -> Result<(), String> {
        let mut air = self.0.borrow_mut();
        let number = definition.control.number;
        assert_eq!(eirp_mbm, 2000);
        air.tuned.push((number, scanning));
        if scanning && number == air.channel {
            air.hear(beacon(number as u8), false);
        }
        Ok(())
    }
    fn prepare_transmit(&mut self) -> Result<(), String> {
        self.0.borrow_mut().prepared += 1;
        Ok(())
    }
    fn transmit(&mut self, queue: Queue, packet: &Packet, mpdu: &[u8]) -> Result<bool, String> {
        let mut air = self.0.borrow_mut();
        if air.full {
            return Ok(false);
        }
        air.sent.push((queue, *packet, mpdu.to_vec()));
        Ok(true)
    }
    fn receive(&mut self, sink: &mut dyn FnMut(Incoming)) -> Result<(), String> {
        self.0.borrow_mut().incoming.drain(..).for_each(sink);
        Ok(())
    }
    fn command(&mut self, command: (u32, u32)) -> Result<(), String> {
        self.0.borrow_mut().commands.push(command);
        Ok(())
    }
    fn set_port(&mut self, bssid: Mac, aid: u16, linked: bool) -> Result<(), String> {
        self.0.borrow_mut().ports.push((bssid, aid, linked));
        Ok(())
    }
    fn filter_beacons(&mut self, own_only: bool) -> Result<(), String> {
        self.0.borrow_mut().beacon_filters.push(own_only);
        Ok(())
    }
    fn set_edca(&mut self, edca: &[AccessCategory; 4], short_slot: bool) -> Result<(), String> {
        self.0.borrow_mut().edca.push((*edca, short_slot));
        Ok(())
    }
    fn write_key(&mut self, key: &CamKey<'_>) -> Result<(), String> {
        self.0
            .borrow_mut()
            .keys
            .push((key.entry, key.index, key.kind, key.group, *key.material));
        Ok(())
    }
    fn clear_key(&mut self, entry: u8) -> Result<(), String> {
        self.0.borrow_mut().cleared.push(entry);
        Ok(())
    }
}

/// The AP's rates on `channel`: 1 and 6 Mb/s, or 6 and 9.
fn rates(channel: u16) -> [u8; 4] {
    if channel < 14 {
        [1, 2, 0x82, 0x0c]
    } else {
        [1, 2, 0x8c, 0x12]
    }
}

/// An AP's management frame to the station.
fn management(subtype: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 24];
    frame[0] = subtype;
    frame[4..10].copy_from_slice(&LOCAL);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame.extend(body);
    frame
}

/// The AP's beacon on `channel`.
fn beacon(channel: u8) -> Vec<u8> {
    let mut frame = vec![0; 36];
    frame[0] = 0x80;
    frame[4..10].fill(0xff);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame[32..34].copy_from_slice(&100u16.to_le_bytes());
    frame[34] = 0x11;
    frame.extend([0, SSID.len() as u8]);
    frame.extend(SSID);
    frame.extend(rates(u16::from(channel)));
    frame.extend([3, 1, channel, 5, 4, 0, 2, 0, 0]);
    frame.extend(RSN);
    if channel < 14 {
        frame.extend(HT);
        frame.extend(WMM);
    }
    frame
}

/// A data frame from the AP to `receiver`, with `key` its index and packet
/// number.
fn data(
    receiver: [u8; 6],
    sequence: u16,
    kind: [u8; 2],
    body: &[u8],
    key: Option<(u8, u8)>,
) -> Vec<u8> {
    let mut frame = vec![0; 26];
    frame[0] = 0x88;
    frame[1] = if key.is_some() { 0x42 } else { 0x02 };
    frame[4..10].copy_from_slice(&receiver);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame[22..24].copy_from_slice(&(sequence << 4).to_le_bytes());
    if let Some((index, number)) = key {
        frame.extend([number, 0, 0, 0x20 | index << 6, 0, 0, 0, 0]);
    }
    frame.extend([0xaa, 0xaa, 3, 0, 0, 0]);
    frame.extend(kind);
    frame.extend(body);
    if key.is_some() {
        frame.extend([0; 8]);
    }
    frame
}

/// What the station sent past `frame`'s header, IV and LLC when it is EAPOL.
fn eapol(frame: &[u8]) -> Option<&[u8]> {
    if frame[0] & 0x0c != 8 {
        return None;
    }
    let header = if frame[0] & 0x80 != 0 { 26 } else { 24 };
    let header = header + if frame[1] & 0x40 != 0 { 8 } else { 0 };
    (frame.get(header + 6..header + 8)? == [0x88, 0x8e]).then(|| &frame[header + 8..])
}

fn wifi(rules: &[(u32, u32, u8, u16)], channel: u16) -> (Wifi<Model>, Model) {
    core::mem::forget(crate::test_clock::virtualize());
    let database = regdb(&[(*b"US", rules)]);
    let model = Model(Rc::new(RefCell::new(Air {
        channel,
        ..Air::default()
    })));
    let country = database.select(*b"US").unwrap();
    let network = Network {
        ssid: SSID.to_vec(),
        secret: Secret::Psk(Zeroizing::new([0; 32])),
        country: None,
    };
    let radio = Rtl8822c::new(model.clone(), Mac(LOCAL), country, CLOCK).unwrap();
    (
        radio.keep(network, Arc::new(FixedEntropy::default())),
        model,
    )
}

/// Serve the air until `done`, with five milliseconds passing each round.
fn run(
    wifi: &mut Wifi<Model>,
    model: &Model,
    mut done: impl FnMut(&mut Wifi<Model>, &Air) -> bool,
) -> bool {
    for _ in 0..4000 {
        wifi.carrier();
        model.0.borrow_mut().serve();
        if done(wifi, &model.0.borrow()) {
            return true;
        }
        crate::test_clock::advance(CLOCK, 5_000);
    }
    false
}

const OPEN: [(u32, u32, u8, u16); 1] = [(2_402_000, 2_472_000, 0, 2000)];

/// Join the model's AP on channel 1 through its handshake to an open port.
fn connected() -> (Wifi<Model>, Model) {
    let (mut wifi, model) = wifi(&OPEN, 1);
    assert!(run(&mut wifi, &model, |wifi, _| {
        wifi.radio().station().phase() == Peering::Associated
    }));
    let security = Security::select(&RSN, true).unwrap();
    let mut ap = Authenticator::between(
        security.suites(),
        Zeroizing::new([0; 32]),
        Mac(AP),
        Mac(LOCAL),
        security.element(),
    );
    let answers = |air: &Air| {
        air.sent
            .iter()
            .filter_map(|(_, _, bytes)| eapol(bytes).map(<[u8]>::to_vec))
            .collect::<Vec<_>>()
    };
    let frame = data(LOCAL, 0, [0x88, 0x8e], &ap.message_1(), None);
    model.0.borrow_mut().hear(frame, false);
    assert!(run(&mut wifi, &model, |_, air| !answers(air).is_empty()));
    ap.message_2(&answers(&model.0.borrow())[0]);
    let frame = data(LOCAL, 1, [0x88, 0x8e], &ap.message_3(&RSN), None);
    model.0.borrow_mut().hear(frame, false);
    assert!(run(&mut wifi, &model, |_, air| answers(air).len() > 1));
    assert!(wifi.carrier());
    ap.signed_reply(&answers(&model.0.borrow())[1], 0x308);
    (wifi, model)
}

/// What the station holds for the network, as each frame's first payload byte.
fn delivered(wifi: &mut Wifi<Model>) -> Vec<u8> {
    let mut values = Vec::new();
    while let Some(ethernet) = wifi.receive().unwrap() {
        values.push(ethernet[14]);
    }
    values
}

#[test]
fn a_scan_probes_where_it_may_and_only_listens_where_it_may_not() {
    let rules = [
        (2_402_000, 2_472_000, 0, 2000),
        // NL80211_RRF_NO_IR, as regdb writes it.
        (5_170_000, 5_250_000, 8, 2000),
    ];
    let (mut wifi, model) = wifi(&rules, 36);
    assert!(run(&mut wifi, &model, |wifi, _| {
        wifi.radio().station().phase() == Peering::Associated
    }));
    let air = model.0.borrow();
    assert!(air.probed.contains(&1) && air.probed.contains(&11));
    assert!(!air.probed.contains(&36) && !air.probed.contains(&48));
    assert!(air.tuned.contains(&(36, true)) && air.tuned.contains(&(48, true)));
    assert_eq!(air.tuned.last(), Some(&(36, false)));
    assert_eq!(air.beacon_filters.first(), Some(&false));
}

#[test]
fn a_join_programs_the_port_and_the_handshake_fills_the_cam() {
    let (_, model) = connected();
    let air = model.0.borrow();
    assert_eq!(air.ports, [(Mac(AP), 0, false), (Mac(AP), 1, true)]);
    assert_eq!(air.prepared, 2);
    assert!(air.commands.contains(&commands::media_status(0, true)));
    assert!(air.commands.contains(&commands::default_port(0, 0)));
    // The AP's best effort: AIFSN 3, ECW 4 to 10, on a 2.4 GHz long slot.
    let (edca, short_slot) = air.edca[0];
    assert_eq!(
        (edca[0].aifsn, edca[0].ecw_min, edca[0].ecw_max),
        (3, 4, 10)
    );
    assert!(!short_slot);
    // The GTK sits at its index, the PTK past the default keys.
    let cam: Vec<_> = air.keys.iter().map(|key| key.0).collect();
    assert_eq!(cam.len(), 2);
    assert!(cam.contains(&PAIRWISE_CAM) && cam.contains(&1));
    assert!(air.keys.iter().all(|key| key.2 == CAM_AES));
    assert!(
        air.keys
            .iter()
            .any(|key| key.3 && key.0 == 1 && key.4[0] == 0x50)
    );
}

#[test]
fn a_lost_authentication_goes_again() {
    let (mut wifi, model) = self::wifi(&OPEN, 1);
    model.0.borrow_mut().losses = 1;
    assert!(run(&mut wifi, &model, |wifi, _| {
        wifi.radio().station().phase() == Peering::Associated
    }));
    let air = model.0.borrow();
    let tries = air.sent.iter().filter(|sent| sent.2[0] == 0xb0).count();
    assert_eq!(tries, 2);
}

#[test]
fn data_leaves_with_its_packet_number_and_waits_out_a_full_queue() {
    let (mut wifi, model) = connected();
    let before = model.0.borrow().sent.len();
    model.0.borrow_mut().full = true;
    let mut ethernet = vec![0; 14];
    ethernet[..6].copy_from_slice(&AP);
    ethernet[6..12].copy_from_slice(&LOCAL);
    ethernet[12..14].copy_from_slice(&[8, 0]);
    ethernet.extend([0x45, 0]);
    ethernet.extend([0; 44]);
    wifi.transmit(&ethernet).unwrap();
    wifi.transmit(&ethernet).unwrap();
    wifi.carrier();
    assert_eq!(model.0.borrow().sent.len(), before);
    model.0.borrow_mut().full = false;
    assert!(run(&mut wifi, &model, |_, air| air.sent.len() == before + 2));
    let air = model.0.borrow();
    let (first, second) = (&air.sent[before], &air.sent[before + 1]);
    for (queue, packet, mpdu) in [first, second] {
        assert_eq!(*queue, Queue::BestEffort);
        assert_eq!(packet.security, SECURITY_CCMP);
        assert_eq!(usize::from(packet.size), mpdu.len());
        assert_ne!(mpdu[1] & 0x40, 0);
        assert_eq!(mpdu[26 + 3] & 0x20, 0x20);
    }
    assert_eq!(first.2[26] + 1, second.2[26]);
    assert_eq!(first.1.sequence + 1, second.1.sequence);
}

#[test]
fn received_data_passes_its_replay_and_integrity_checks() {
    let (mut wifi, model) = connected();
    let body = [0x45; 46];
    let frame = |sequence, key| data(LOCAL, sequence, [8, 0], &body, Some(key));
    model.0.borrow_mut().hear(frame(10, (0, 1)), true);
    wifi.carrier();
    assert_eq!(delivered(&mut wifi), [0x45]);
    // Replayed, and then failing the hardware's integrity check.
    model.0.borrow_mut().hear(frame(10, (0, 1)), true);
    model
        .0
        .borrow_mut()
        .incoming
        .push_back(Incoming::Frame(Received {
            bytes: frame(11, (0, 2)),
            tsf: 0,
            decrypted: true,
            icv_error: true,
            signal_dbm: None,
        }));
    wifi.carrier();
    assert_eq!(delivered(&mut wifi), []);
    // A group frame under the key the handshake gave.
    let group = data([0xff; 6], 12, [8, 0], &body, Some((1, 200)));
    model.0.borrow_mut().hear(group, true);
    wifi.carrier();
    assert_eq!(delivered(&mut wifi), [0x45]);
}

#[test]
fn an_a_msdu_gives_up_each_of_its_frames() {
    let (mut wifi, model) = connected();
    let mut frame = data(LOCAL, 20, [8, 0], &[], Some((0, 1)));
    frame.truncate(34);
    frame[24] = 0x80;
    for value in [0x31, 0x32] {
        let padding = (4 - frame[34..].len() % 4) % 4;
        frame.extend(vec![0; padding]);
        frame.extend(LOCAL);
        frame.extend(AP);
        frame.extend(54u16.to_be_bytes());
        frame.extend([0xaa, 0xaa, 3, 0, 0, 0, 8, 0]);
        frame.extend([value; 46]);
    }
    frame.extend([0; 8]);
    model.0.borrow_mut().hear(frame, true);
    wifi.carrier();
    assert_eq!(delivered(&mut wifi), [0x31, 0x32]);
}

#[test]
fn a_block_ack_agreement_orders_what_it_holds() {
    let (mut wifi, model) = connected();
    // ADDBA request: dialog 7, TID 0, immediate, 64 frames, starting at 100.
    let parameters = 2u16 | 64 << 6;
    let mut body = vec![3, 0, 7];
    body.extend(parameters.to_le_bytes());
    body.extend([0, 0]);
    body.extend((100u16 << 4).to_le_bytes());
    let before = model.0.borrow().sent.len();
    model.0.borrow_mut().hear(management(0xd0, &body), false);
    assert!(run(&mut wifi, &model, |_, air| air.sent.len() > before));
    {
        let air = model.0.borrow();
        let answer = &air.sent[before].2;
        assert_eq!(answer[0], 0xd0);
        assert_eq!(answer[24..27], [3, 1, 7]);
        assert_eq!(answer[27..29], [0, 0]);
    }
    let frame = |sequence: u16, number: u8, value| {
        data(LOCAL, sequence, [8, 0], &[value; 46], Some((0, number)))
    };
    model.0.borrow_mut().hear(frame(101, 2, 0x21), true);
    wifi.carrier();
    assert_eq!(delivered(&mut wifi), []);
    model.0.borrow_mut().hear(frame(100, 1, 0x20), true);
    wifi.carrier();
    assert_eq!(delivered(&mut wifi), [0x20, 0x21]);
    // A gap the sender never fills gives way after the reorder timeout.
    model.0.borrow_mut().hear(frame(103, 3, 0x23), true);
    wifi.carrier();
    assert_eq!(delivered(&mut wifi), []);
    let mut released = Vec::new();
    for _ in 0..30 {
        crate::test_clock::advance(CLOCK, 5_000);
        wifi.carrier();
        released.extend(delivered(&mut wifi));
    }
    assert_eq!(released, [0x23]);
}

#[test]
fn a_deauthentication_clears_the_port_and_the_cam() {
    let (mut wifi, model) = connected();
    model.0.borrow_mut().hear(management(0xc0, &[1, 0]), false);
    assert!(run(&mut wifi, &model, |_, air| air.cleared.len() == 2));
    assert!(!wifi.carrier());
    let air = model.0.borrow();
    assert_eq!(air.ports.last(), Some(&(Mac([0; 6]), 0, false)));
    assert!(air.cleared.contains(&PAIRWISE_CAM) && air.cleared.contains(&1));
    assert!(air.commands.contains(&commands::media_status(0, false)));
}
