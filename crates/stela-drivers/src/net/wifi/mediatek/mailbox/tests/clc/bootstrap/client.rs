use super::*;
mod modern;
use crate::net::{
    Mac,
    wifi::{
        self,
        mediatek::{
            bootstrap::client::{Client, Error as ClientError, Event, Phase as ClientPhase},
            mcu::{client::Profile, device::Context},
        },
        scan,
        security::ReplaySeed,
        station::{self, Join, PortPolicy, data::TxClass, wire::AssociationRequest},
    },
};
const LOCAL: Mac = Mac([2, 1, 2, 3, 4, 5]);
const AP: Mac = Mac([2, 6, 7, 8, 9, 10]);
const CHANNEL: wifi::Channel = wifi::Channel {
    band: Band::Ghz5,
    number: 36,
    frequency_mhz: 5180,
};
struct Policy(bool);
impl station::RegulatoryPolicy for Policy {
    fn allow_management_tx(&mut self, _: wifi::Channel) -> bool {
        self.0
    }
    fn allow_data_tx(&mut self, _: wifi::Channel) -> bool {
        self.0
    }
}
impl scan::Policy for Policy {
    fn allow_receive(&mut self, _: wifi::Channel) -> bool {
        self.0
    }
    fn allow_probe(&mut self, _: wifi::Channel) -> bool {
        self.0
    }
    fn lookup_channel(&mut self, b: Band, n: u16) -> Option<wifi::Channel> {
        if self.0 && b == Band::Ghz5 && n == 36 {
            Some(CHANNEL)
        } else {
            None
        }
    }
}
fn profile() -> Profile {
    Profile {
        interface: Context {
            bss_index: 0,
            omac_index: 0,
            band_index: 255,
            wmm_index: 0,
            link_index: 0,
            broadcast_wcid: 19,
            address: LOCAL,
        },
        peer: AP,
        wcid: 1,
        channel: CHANNEL,
        aid: 0,
        basic_rates: 0x15,
        supported_rates: 0xff,
        beacon_interval: 100,
        dtim_period: 2,
        slot_time: 9,
        antenna_mask: 3,
        cipher: 0,
    }
}
fn join() -> Join {
    Join {
        bssid: AP,
        channel: CHANNEL,
        policy: PortPolicy::Controlled,
        request: AssociationRequest::new(
            0x11,
            10,
            vec![
                0, 1, b'x', 1, 8, 0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108, 48, 18, 1, 0, 0, 15, 172,
                4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2,
            ],
        )
        .unwrap(),
    }
}
struct Model {
    response: Arc<Mutex<Response>>,
    bar: Bar,
    queues: BTreeMap<u32, ModelState>,
    memory: Arc<Mutex<Memory>>,
    drops: Arc<AtomicUsize>,
}
fn setup() -> (Client<Bar, Q, NativeGuard>, Model) {
    let mut f = NativeFixture::new(Chip::Mt7925);
    f.install().unwrap();
    f.boot(Chip::Mt7925);
    f.policy(Chip::Mt7925);
    unsafe { f.controller.initialize_mac() }.unwrap();
    unsafe { f.controller.start(Band::Ghz5, 36, 5180) }.unwrap();
    let interface = unsafe { f.controller.register_interface(profile().interface) }.unwrap();
    f.model.lock().unwrap().client_execution = true;
    f.model.lock().unwrap().key_execution = true;
    let NativeFixture {
        controller,
        model,
        bar,
        queues,
        memory,
        drops,
        ..
    } = f;
    let driver = unsafe { Client::new(controller, interface) }.unwrap();
    (
        driver,
        Model {
            response: model,
            bar,
            queues,
            memory,
            drops,
        },
    )
}
fn pointer(memory: &Memory, address: u64, bytes: usize) -> *const u8 {
    let (&base, (pages, pointer, direction)) =
        memory.mappings.range(..=address).next_back().unwrap();
    let offset = (address - base) as usize;
    assert!(offset + bytes <= pages.bytes());
    assert_ne!(*direction, crate::bus::dma::mapping::Direction::FromDevice);
    (*pointer + offset) as *const u8
}
// Actual model device fetches the published descriptor, then TXWI/TXP and
// payload via the same requester's registry. It retains no CPU-address alias.
fn finish_tx(model: &Model) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut queue = model.queues[&0xd4300].lock().unwrap();
    while queue.index != queue.head {
        {
            let r = model.response.lock().unwrap();
            assert_eq!(r.roc_channel.or(r.home_channel), Some(36));
        }
        let memory = model.memory.lock().unwrap();
        let desc = unsafe {
            core::slice::from_raw_parts(
                pointer(&memory, queue.base + u64::from(queue.index) * 16, 16),
                16,
            )
        };
        let address = u32::from_le_bytes(desc[..4].try_into().unwrap()) as u64;
        assert_eq!(
            u32::from_le_bytes(desc[4..8].try_into().unwrap()),
            (64 << 16) | (1 << 30)
        );
        let txwi = unsafe { core::slice::from_raw_parts(pointer(&memory, address, 64), 64) };
        let token = u16::from_le_bytes(txwi[32..34].try_into().unwrap()) & 0x7fff;
        let wcid = u32::from_le_bytes(txwi[4..8].try_into().unwrap()) & 0xfff;
        assert!(
            model
                .response
                .lock()
                .unwrap()
                .raw_disabled
                .contains(&(wcid as u16))
        );
        let payload_addr = u32::from_le_bytes(txwi[40..44].try_into().unwrap()) as u64;
        let length = u16::from_le_bytes(txwi[44..46].try_into().unwrap());
        assert_ne!(length & 0x8000, 0);
        let payload = unsafe {
            core::slice::from_raw_parts(
                pointer(&memory, payload_addr, usize::from(length & 0xfff)),
                usize::from(length & 0xfff),
            )
        }
        .to_vec();
        out.push(payload);
        let words = [
            (6u32 << 27) | (1 << 16),
            4 << 16,
            (1 << 31) | (wcid << 12),
            (1 << 30) | (3 << 24),
            u32::from(token) | (0x7fff << 15),
        ];
        let free = words
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        drop(memory);
        queue.index = (queue.index + 1) % queue.count;
        device_receive(&model.queues[&0xd4500], &free, true, 0);
    }
    out
}
fn incoming_bytes(mpdu: &[u8], protected: Option<(u16, u8, u64)>, translated: bool) -> Vec<u8> {
    let mut b = vec![0; 32 + if protected.is_some() { 16 } else { 0 }];
    let mut r1 = 0u32;
    let mut r2 = 1u32 << 30;
    if translated {
        r2 |= 1 << 7;
    }
    if let Some((slot, index, pn)) = protected {
        r1 = u32::from(slot) | (u32::from(index) << 21) | (1 << 16) | (1 << 31);
        r2 |= 4 << 16;
        for i in 0..6 {
            b[32 + i] = (pn >> (i * 8)) as u8;
        }
    }
    b[4..8].copy_from_slice(&r1.to_le_bytes());
    b[8..12].copy_from_slice(&r2.to_le_bytes());
    b[12..16].copy_from_slice(
        &((36u32 << 8) | if mpdu[4] & 1 == 0 { 1 << 16 } else { 0 }).to_le_bytes(),
    );
    b.extend_from_slice(mpdu);
    let len = b.len() as u32;
    b[..4].copy_from_slice(&((2 << 27) | len).to_le_bytes());
    b
}
fn incoming(model: &Model, mpdu: &[u8], protected: Option<(u16, u8, u64)>, translated: bool) {
    let bytes = incoming_bytes(mpdu, protected, translated);
    device_receive(&model.queues[&0xd4520], &bytes, true, 0);
}
fn response(subtype: u16, body: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 24];
    b[..2].copy_from_slice(&subtype.to_le_bytes());
    b[4..10].copy_from_slice(&LOCAL.0);
    b[10..16].copy_from_slice(&AP.0);
    b[16..22].copy_from_slice(&AP.0);
    b.extend_from_slice(body);
    b
}
// Native firmware commands use real elapsed time; these frontend model steps
// are100ms, leaving auth/assoc within500ms and the next operation beyond an
// accepted Configure's500ms bound. The old microsecond ordinal fixture hid
// real native execution time and was not a coherent frontend clock.
fn frontend_tick(step: u64) -> u64 {
    step * 100_000
}
fn associated(driver: &mut Client<Bar, Q, NativeGuard>, model: &Model, now: u64) {
    associated_with_configuration_delay(driver, model, now, 0).unwrap();
}
fn associated_with_configuration_delay(
    driver: &mut Client<Bar, Q, NativeGuard>,
    model: &Model,
    now: u64,
    delay: u64,
) -> Result<(), ClientError> {
    driver
        .join(
            join(),
            profile(),
            frontend_tick(now),
            &Source,
            &mut Policy(true),
        )
        .unwrap();
    assert_eq!(driver.phase(), ClientPhase::Joining);
    assert_eq!(finish_tx(model)[0][..2], [0xb0, 0]);
    driver
        .poll(frontend_tick(now + 1), &Source, &mut Policy(true))
        .unwrap();
    driver.poll_released().unwrap();
    incoming(model, &response(0xb0, &[0, 0, 2, 0, 0, 0]), None, false);
    driver
        .poll(frontend_tick(now + 2), &Source, &mut Policy(true))
        .unwrap();
    assert_eq!(finish_tx(model)[0][..2], [0, 0]);
    driver
        .poll(frontend_tick(now + 3), &Source, &mut Policy(true))
        .unwrap();
    driver.poll_released().unwrap();
    incoming(
        model,
        &response(
            0x10,
            &[
                0x11, 0, 0, 0, 1, 0xc0, 1, 8, 0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108,
            ],
        ),
        None,
        false,
    );
    model.response.lock().unwrap().pause_next_index_us = delay;
    driver.poll(frontend_tick(now + 4), &Source, &mut Policy(true))?;
    assert_eq!(driver.phase(), ClientPhase::Associated);
    Ok(())
}
fn eth(protocol: u16) -> Vec<u8> {
    let mut b = vec![4, 1, 2, 3, 4, 5];
    b.extend_from_slice(&LOCAL.0);
    b.extend_from_slice(&protocol.to_be_bytes());
    b.extend_from_slice(&[1, 2, 3]);
    b
}
#[test]
fn actual_late_legacy_configuration_ack_cannot_reuse_cached_poll_time() {
    let (mut driver, model) = setup();
    assert!(matches!(
        associated_with_configuration_delay(&mut driver, &model, 0, 600_000),
        Err(ClientError::Station(station::Error::Timeout))
    ));
    assert_eq!(driver.phase(), ClientPhase::Quarantined);
    assert_eq!(driver.station().phase(), station::Phase::Quarantined);
    drop(driver);
    assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    assert!(!model.memory.lock().unwrap().mappings.is_empty());
}
fn data(group: bool) -> Vec<u8> {
    let mut b = response(0x4208, &[0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 1, 2, 3]);
    if group {
        b[4..10].fill(255)
    }
    b[16..22].copy_from_slice(&[4, 1, 2, 3, 4, 5]);
    b
}
#[test]
fn actual_mt7925_init_scan_secure_client_reconnect_and_stop() {
    let (mut driver, model) = setup();
    let request = scan::Request::new(vec![CHANNEL], vec![], vec![]).unwrap();
    driver
        .begin_scan(request, 0, 1_000_000, &mut Policy(true))
        .unwrap();
    assert_eq!(driver.phase(), ClientPhase::Scanning);
    // Generic scan command response has no status/scan completion authority.
    assert!(matches!(
        driver.transport_facts().last(),
        Some(crate::net::wifi::mediatek::mailbox::bootstrap::Fact::GenericResponse(_))
    ));
    let mut beacon = response(
        0x80,
        &[
            0, 0, 0, 0, 0, 0, 0, 0, 100, 0, 0x11, 0, 0, 1, b'x', 1, 1, 0x8c, 5, 4, 0, 2, 0, 0,
        ],
    );
    beacon[4..10].fill(255);
    incoming(&model, &beacon, None, false);
    assert!(matches!(
        driver
            .poll(frontend_tick(1), &Source, &mut Policy(true))
            .unwrap()
            .as_slice(),
        [Event::Bss(_)]
    ));
    let mut done = vec![0; 52];
    done[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
    done[36] = 14;
    done[38] = 6;
    done[50] = 4;
    device_receive(&model.queues[&0xd4500], &done, true, 0);
    driver
        .poll(frontend_tick(2), &Source, &mut Policy(true))
        .unwrap();
    assert_eq!(driver.phase(), ClientPhase::ScanCompleted);
    unsafe { driver.retire_scan_after_drain() }.unwrap();
    associated(&mut driver, &model, 10);
    let epoch = driver.station().association_epoch().unwrap();
    assert!(matches!(
        driver.transmit(
            epoch,
            &eth(0x0800),
            TxClass::Data,
            &Source,
            &mut Policy(true)
        ),
        Err(ClientError::Data(station::data::Error::ClosedPort))
    ));
    driver
        .install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
        .unwrap();
    driver
        .install_key(false, 2, &[2; 16], ReplaySeed::ZERO)
        .unwrap();
    driver.authorize_port(epoch).unwrap();
    let receipt = driver
        .transmit(
            epoch,
            &eth(0x0800),
            TxClass::Data,
            &Source,
            &mut Policy(true),
        )
        .unwrap();
    assert!(driver.poll_released().unwrap().is_empty());
    let transmitted = finish_tx(&model);
    assert_eq!(&transmitted[0][..2], &[8, 0x41]);
    assert_eq!(&transmitted[0][24..30], &[0xaa, 0xaa, 3, 0, 0, 0]);
    driver
        .poll(frontend_tick(20), &Source, &mut Policy(true))
        .unwrap();
    let released = driver.poll_released().unwrap();
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].receipt, receipt);
    assert_eq!(released[0].context.association_epoch(), epoch);
    assert!(released[0].context.key().is_some());
    drop(released);
    incoming(&model, &data(false), Some((1, 0, 1)), false);
    assert!(matches!(
        driver
            .poll(frontend_tick(21), &Source, &mut Policy(true))
            .unwrap()
            .as_slice(),
        [Event::Ingress(station::data::Ingress::Data(_))]
    ));
    incoming(&model, &data(false), Some((1, 0, 1)), false);
    assert!(matches!(
        driver.poll(frontend_tick(22), &Source, &mut Policy(true)),
        Err(ClientError::Data(station::data::Error::Crypto(
            wifi::security::Error::Replay
        )))
    ));
    incoming(&model, &data(true), Some((1, 2, 1)), false);
    driver
        .poll(frontend_tick(23), &Source, &mut Policy(true))
        .unwrap();
    incoming(&model, &data(false), Some((1, 0, 2)), true);
    assert!(matches!(
        driver.poll(frontend_tick(24), &Source, &mut Policy(true)),
        Err(ClientError::Rx(
            crate::net::wifi::mediatek::rx::Error::UnsupportedTranslation
        ))
    ));
    driver.disconnect().unwrap();
    assert_eq!(driver.phase(), ClientPhase::NeedsDrain);
    unsafe { driver.retire_peer_after_drain() }.unwrap();
    associated(&mut driver, &model, 30);
    assert_ne!(driver.station().association_epoch().unwrap(), epoch);
    assert!(matches!(
        driver.install_key(true, 0, &[1; 16], ReplaySeed::ZERO),
        Err(ClientError::Key(
            crate::net::wifi::mediatek::mailbox::key::Error::Security(
                wifi::security::Error::Reinstallation
            )
        ))
    ));
    // Confirmed history rejects repeated temporal material without submitting
    // another key command. A fresh candidate remains the allowed recovery.
    driver
        .install_key(true, 0, &[3; 16], ReplaySeed::ZERO)
        .unwrap();
    // Ordinary fresh-key installation cannot silently reset the old GTK.
    assert!(matches!(
        driver.install_key(false, 2, &[2; 16], ReplaySeed::ZERO),
        Err(ClientError::Key(
            crate::net::wifi::mediatek::mailbox::key::Error::Security(
                wifi::security::Error::Reinstallation
            )
        ))
    ));
    // Actual modeled OS exchange authenticates the same AP GTK and RSC0;
    // previous delivered PN1 remains authoritative in the original slot.
    unsafe { driver.resume_group_key(2, &[2; 16], ReplaySeed::ZERO) }.unwrap();
    let next = driver.station().association_epoch().unwrap();
    driver.authorize_port(next).unwrap();
    incoming(&model, &data(true), Some((1, 2, 1)), false);
    assert!(matches!(
        driver.poll(frontend_tick(41), &Source, &mut Policy(true)),
        Err(ClientError::Data(station::data::Error::Crypto(
            wifi::security::Error::Replay
        )))
    ));
    incoming(&model, &data(true), Some((1, 2, 2)), false);
    assert!(matches!(
        driver
            .poll(frontend_tick(42), &Source, &mut Policy(true))
            .unwrap()
            .as_slice(),
        [Event::Ingress(station::data::Ingress::Data(_))]
    ));
    assert!(matches!(
        driver.transmit(
            epoch,
            &eth(0x0800),
            TxClass::Data,
            &Source,
            &mut Policy(true)
        ),
        Err(ClientError::Data(station::data::Error::Stale))
    ));
    driver.disconnect().unwrap();
    unsafe { driver.retire_peer_after_drain() }.unwrap();
    driver.stop().unwrap();
    assert_eq!(driver.phase(), ClientPhase::ControllerDrain);
    model.response.lock().unwrap().clc_processing = false;
    model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
    unsafe { driver.stop_after_quiesce() }.unwrap();
    assert_eq!(driver.phase(), ClientPhase::Stopped);
    drop(driver);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
    assert!(model.memory.lock().unwrap().mappings.is_empty());
}

#[test]
fn combo_initial_boot_is_consumed_once_on_success_or_uncertainty() {
    for failed in [false, true] {
        let mut f = NativeFixture::new(Chip::Mt7925);
        f.install().unwrap();
        if failed {
            f.model.lock().unwrap().initial_fail_at = Some(1);
        }
        let requests = Requests::new(&identity(Chip::Mt7925));
        let provider = catalog(&requests, patch_bytes(), ram(&clc_bytes(Chip::Mt7925)));
        let prepared = requests.load(&provider).unwrap();
        assert_eq!(f.controller.boot(&prepared).is_err(), failed);
        let count = f.model.lock().unwrap().initial_commands.len();
        assert_eq!(count, 1);
        assert!(matches!(
            f.controller.boot(&prepared),
            Err(BootError::WrongPhase)
        ));
        assert_eq!(f.model.lock().unwrap().initial_commands.len(), count);
        if !failed {
            f.retire();
        } else {
            drop(f.controller);
            assert_eq!(f.drops.load(Ordering::Relaxed), 0);
        }
    }
}

#[test]
fn failed_actual_peer_ack_retains_programmed_peer_without_packet_admission() {
    let (mut driver, model) = setup();
    model.response.lock().unwrap().status = 0xdeadbeef;
    assert!(matches!(
        driver.join(join(), profile(), 0, &Source, &mut Policy(true)),
        Err(ClientError::Firmware(0xdeadbeef))
    ));
    // Actual device already consumed and programmed the full peer command;
    // response failure cannot become a clean rollback, nor format permission.
    assert!(model.response.lock().unwrap().peers.contains_key(&1));
    assert_eq!(driver.phase(), ClientPhase::Quarantined);
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, 0);
    drop(driver);
    assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    assert!(!model.memory.lock().unwrap().mappings.is_empty());
}

#[test]
fn wrong_actual_roc_token_never_publishes_authentication_or_reuses_owner() {
    let (mut driver, model) = setup();
    model.response.lock().unwrap().wrong_roc_token = true;
    assert!(matches!(
        driver.join(join(), profile(), 0, &Source, &mut Policy(true)),
        Err(ClientError::GrantTimeout)
    ));
    assert_eq!(driver.phase(), ClientPhase::Quarantined);
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, 0);
    // The generic response and foreign grant do not authorize channel use.
    assert!(model.response.lock().unwrap().roc_channel.is_none());
    assert!(
        model
            .response
            .lock()
            .unwrap()
            .initial_commands
            .iter()
            .any(|p| p[34] == 0x27 && p[52] == 1)
    );
    drop(driver);
    assert_eq!(model.drops.load(Ordering::Relaxed), 0);
}

#[test]
fn peer_removal_cannot_retire_outstanding_actual_packet_owners() {
    let (mut driver, model) = setup();
    associated(&mut driver, &model, 0);
    let epoch = driver.station().association_epoch().unwrap();
    driver
        .install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
        .unwrap();
    driver
        .install_key(false, 2, &[2; 16], ReplaySeed::ZERO)
        .unwrap();
    driver.authorize_port(epoch).unwrap();
    driver
        .transmit(
            epoch,
            &eth(0x0800),
            TxClass::Data,
            &Source,
            &mut Policy(true),
        )
        .unwrap();
    driver.disconnect().unwrap();
    assert!(matches!(
        unsafe { driver.retire_peer_after_drain() },
        Err(ClientError::NeedsDrain)
    ));
    // Even real remove ACKs cannot release still-reachable data mappings/key
    // owners. Complete actual hardware users before independent RX/work drain.
    finish_tx(&model);
    driver
        .poll(frontend_tick(10), &Source, &mut Policy(true))
        .unwrap();
    driver.poll_released().unwrap();
    unsafe { driver.retire_peer_after_drain() }.unwrap();
    driver.stop().unwrap();
    model.response.lock().unwrap().clc_processing = false;
    model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
    unsafe { driver.stop_after_quiesce() }.unwrap();
    drop(driver);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn partial_actual_receive_chain_blocks_peer_generation_retirement() {
    let (mut driver, model) = setup();
    associated(&mut driver, &model, 0);
    driver
        .install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
        .unwrap();
    driver
        .install_key(false, 2, &[2; 16], ReplaySeed::ZERO)
        .unwrap();
    let bytes = incoming_bytes(&data(false), Some((1, 0, 9)), false);
    device_receive(&model.queues[&0xd4520], &bytes[..40], false, 0);
    driver
        .poll(frontend_tick(10), &Source, &mut Policy(true))
        .unwrap();
    driver.disconnect().unwrap();
    assert!(matches!(
        unsafe { driver.retire_peer_after_drain() },
        Err(ClientError::NeedsDrain)
    ));
    // End and consume the actual old chain before the independent old-user
    // drain can qualify a new key/peer generation. No old bytes are retagged.
    device_receive(&model.queues[&0xd4520], &bytes[40..], true, 0);
    assert!(
        driver
            .poll(frontend_tick(11), &Source, &mut Policy(true))
            .is_err()
    );
    unsafe { driver.retire_peer_after_drain() }.unwrap();
    driver.stop().unwrap();
    model.response.lock().unwrap().clc_processing = false;
    model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
    unsafe { driver.stop_after_quiesce() }.unwrap();
    drop(driver);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn actual_roc_expiring_during_native_packet_preparation_never_publishes() {
    use crate::bus::dma::memory::{CacheAttribute, MemoryError, PageSource, PinnedPages};
    struct DelayedSource(AtomicUsize);
    impl PageSource for DelayedSource {
        fn allocate(
            &self,
            bytes: usize,
            alignment: usize,
            attribute: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
                // The actual source grant is1000ms. Delay only the first real
                // post-grant payload allocation; firmware/ROC processing and
                // mailbox allocations use their original source unchanged.
                std::thread::sleep(std::time::Duration::from_millis(1100));
            }
            Source.allocate(bytes, alignment, attribute)
        }
    }
    let (mut driver, model) = setup();
    let before = model.memory.lock().unwrap().mappings.len();
    let source = DelayedSource(AtomicUsize::new(0));
    assert!(matches!(
        driver.join(join(), profile(), 0, &source, &mut Policy(true)),
        Err(ClientError::GrantTimeout)
    ));
    assert_eq!(source.0.load(Ordering::Relaxed), 2);
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, 0);
    assert_eq!(model.memory.lock().unwrap().mappings.len(), before);
    assert_eq!(driver.phase(), ClientPhase::Quarantined);
    // This never-published packet may unmap, but the real programmed peer,
    // actual grant and all controller/IRQ resources remain retained.
    assert!(model.response.lock().unwrap().peers.contains_key(&1));
    assert_eq!(model.response.lock().unwrap().roc_channel, Some(36));
    drop(driver);
    assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    assert!(!model.memory.lock().unwrap().mappings.is_empty());
}

fn retired_group_for_authenticated_resume() -> (
    Client<Bar, Q, NativeGuard>,
    Model,
    wifi::security::KeyIdentity,
) {
    let (mut driver, model) = setup();
    associated(&mut driver, &model, 0);
    driver
        .install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
        .unwrap();
    let old = driver
        .install_key(false, 2, &[2; 16], ReplaySeed::ZERO)
        .unwrap();
    driver
        .authorize_port(driver.station().association_epoch().unwrap())
        .unwrap();
    incoming(&model, &data(true), Some((1, 2, 7)), false);
    driver
        .poll(frontend_tick(12), &Source, &mut Policy(true))
        .unwrap();
    driver.disconnect().unwrap();
    unsafe { driver.retire_peer_after_drain() }.unwrap();
    associated(&mut driver, &model, 30);
    driver
        .install_key(true, 0, &[3; 16], ReplaySeed::ZERO)
        .unwrap();
    (driver, model, old)
}
#[test]
fn actual_authenticated_gtk_resume_retains_old_identity_history_and_higher_os_rsc() {
    for rsc in [3, 9] {
        let (mut driver, model, old) = retired_group_for_authenticated_resume();
        let seed = ReplaySeed::uniform(wifi::security::PacketNumber::new(rsc).unwrap());
        let key = unsafe { driver.resume_group_key(2, &[2; 16], seed) }.unwrap();
        assert_eq!(key.slot(), old.slot());
        assert_eq!(key.native_epoch(), old.native_epoch());
        assert_ne!(key.generation(), old.generation());
        driver
            .authorize_port(driver.station().association_epoch().unwrap())
            .unwrap();
        let floor = rsc.max(7);
        incoming(&model, &data(true), Some((1, 2, floor)), false);
        assert!(matches!(
            driver.poll(frontend_tick(41), &Source, &mut Policy(true)),
            Err(ClientError::Data(station::data::Error::Crypto(
                wifi::security::Error::Replay
            )))
        ));
        incoming(&model, &data(true), Some((1, 2, floor + 1)), false);
        assert!(matches!(
            driver
                .poll(frontend_tick(42), &Source, &mut Policy(true))
                .unwrap()
                .as_slice(),
            [Event::Ingress(station::data::Ingress::Data(_))]
        ));
        driver.disconnect().unwrap();
        unsafe { driver.retire_peer_after_drain() }.unwrap();
        driver.stop().unwrap();
        model.response.lock().unwrap().clc_processing = false;
        model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
        unsafe { driver.stop_after_quiesce() }.unwrap();
        drop(driver);
        assert_eq!(model.drops.load(Ordering::Relaxed), 1);
    }
}
#[test]
fn uncertain_actual_gtk_resume_never_authorizes_port_or_drops_real_peer_owner() {
    let (mut driver, model, _) = retired_group_for_authenticated_resume();
    model.response.lock().unwrap().status = 0xdead;
    assert!(matches!(
        unsafe { driver.resume_group_key(2, &[2; 16], ReplaySeed::ZERO) },
        Err(ClientError::Key(
            crate::net::wifi::mediatek::mailbox::key::Error::Firmware(0xdead)
        ))
    ));
    assert_eq!(driver.phase(), ClientPhase::Quarantined);
    assert!(matches!(
        driver.authorize_port(driver.station().association_epoch().unwrap()),
        Err(ClientError::WrongPhase)
    ));
    assert!(matches!(
        unsafe { driver.resume_group_key(2, &[2; 16], ReplaySeed::ZERO) },
        Err(ClientError::WrongPhase)
    ));
    // Model processes the actual install before returning its nonzero status;
    // no RejectedAndEmpty claim can release the programmed GTK or old floors.
    assert!(
        model
            .response
            .lock()
            .unwrap()
            .keys
            .contains_key(&(profile().interface.broadcast_wcid as u8))
    );
    drop(driver);
    assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    assert!(!model.memory.lock().unwrap().mappings.is_empty());
}

#[test]
fn local_advertisement_uses_retained_real_report_image_eeprom_and_policy_inputs() {
    let (driver, model) = setup();
    let count = model.response.lock().unwrap().client_commands.len();
    for band in [Band::Ghz2, Band::Ghz5] {
        let a = driver.local_advertisement(band).unwrap();
        assert_eq!(a.antenna_mask(), 3);
        assert_eq!(a.source_country(), *b"US");
        assert_eq!(a.capabilities().he().unwrap().mcs_80.rx_nss(), 2);
        assert_eq!(a.validate_capabilities(a.capabilities()), Ok(()));
        assert_eq!(a.he_source_maps()[0].rx, 0xfffa);
        assert_eq!(a.he_source_maps()[1].tx, 0xfffa);
        assert_eq!(a.he_source_maps()[2].rx, 0);
        assert_eq!(a.he_source_maps()[2].tx, 0);
        if band == Band::Ghz2 {
            assert_eq!(a.capabilities().he().unwrap().mcs_160, None);
        }
        assert!(a.capabilities().eht().unwrap().mcs.bw320.is_none());
        assert_eq!(a.capabilities().he().unwrap().phy[0] & 16, 0);
    }
    assert!(matches!(
        driver.local_advertisement(Band::Ghz6),
        Err(crate::net::wifi::mediatek::bootstrap::client::LocalError::UnsupportedBand)
    ));
    // A new unqueried model reply is not a current bound hardware observation.
    model.response.lock().unwrap().capability_payload = Some(vec![0xff; 100]);
    assert_eq!(
        driver
            .local_advertisement(Band::Ghz5)
            .unwrap()
            .antenna_mask(),
        3
    );
    assert_eq!(model.response.lock().unwrap().client_commands.len(), count);
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, 0);
    assert_eq!(driver.phase(), ClientPhase::Idle);
    drop(driver);
    assert_eq!(model.drops.load(Ordering::Relaxed), 0);
}
