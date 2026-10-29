use super::*;

const BASE: u64 = 0x2_3fe0_0000;
/// The keys the J473AP DeviceTree's `pKW4` functions name.
const J473_GPIO_KEYS: [&[u8; 4]; 8] = [
    b"gP09", b"gP0d", b"gP0f", b"gP10", b"gP15", b"gP16", b"gP18", b"pmVC",
];

fn request(kind: u8, id: u8, size: u8, write_size: u8, key: u32) -> u64 {
    u64::from(kind)
        | u64::from(id) << 12
        | u64::from(size) << 16
        | u64::from(write_size) << 24
        | u64::from(key) << 32
}

fn smc() -> (Smc, Sram) {
    let sram = Sram::default();
    let keys = J473_GPIO_KEYS
        .iter()
        .map(|name| (code(name), Key::gpio()))
        .collect();
    (Smc::new(sram.clone(), BASE, keys).unwrap(), sram)
}

fn send(smc: &mut Smc, payload: u64) -> u64 {
    let mut outbox = Vec::new();
    smc.receive(payload, &mut outbox).unwrap();
    assert_eq!(outbox.len(), 1);
    outbox[0]
}

#[test]
fn rtc_key_requires_owner_and_publication_without_reply_or_sram_fabrication() {
    use crate::platform::apple::pmu::{RtcClock, RtcEpoch};
    let (mut smc, sram) = smc();
    let clock = RtcClock::new(RtcEpoch {
        counter: 100,
        ticks: 12345,
    })
    .unwrap();
    let key = rtc::KEY;
    let before = smc.keys.get(&KEY_COUNT).unwrap().value.clone();
    assert_eq!(
        send(&mut smc, request(READ, 1, 6, 0, key)) as u8,
        KEY_NOT_FOUND
    );
    smc.bind_rtc(clock.clone(), RtcKeyProfile::Hex48Little)
        .unwrap();
    assert!(
        smc.bind_rtc(clock.clone(), RtcKeyProfile::Hex48Little)
            .is_err()
    );
    assert_eq!(
        u32::from_be_bytes(
            smc.keys.get(&KEY_COUNT).unwrap().value[..]
                .try_into()
                .unwrap()
        ),
        u32::from_be_bytes(before[..].try_into().unwrap()) + 1
    );
    let names: Vec<_> = (0..smc.keys.len() + 1)
        .map(|index| smc.key_by_index(index).unwrap())
        .collect();
    assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(names.iter().filter(|&&name| name == key).count(), 1);
    assert_eq!(smc.key_by_index(names.len()), None);
    assert_eq!(send(&mut smc, request(KEY_INFO, 2, 0, 0, key)) & 0xff, 0);
    assert_eq!(sram.get(6), [6, b'h', b'e', b'x', b'_', 0x94]);
    sram.put(&[0xa5; 16]);
    let mut output = Vec::new();
    assert!(
        smc.receive(request(READ, 3, 6, 0, key), &mut output)
            .is_err()
    );
    assert!(output.is_empty());
    assert_eq!(sram.get(16), [0xa5; 16]);
    assert_eq!(
        send(&mut smc, request(READ, 4, 5, 0, key)) as u8,
        SIZE_MISMATCH
    );
    assert_eq!(
        send(&mut smc, request(WRITE, 5, 6, 0, key)) as u8,
        NOT_WRITABLE
    );
    assert_eq!(
        send(&mut smc, request(READ_WRITE, 6, 6, 6, key)) as u8,
        NOT_WRITABLE
    );
    assert_eq!(sram.get(16), [0xa5; 16]);
    clock.publish(100).unwrap();
    let reply = send(&mut smc, request(READ, 7, 8, 0, key));
    assert_eq!((reply as u8, (reply >> 16) & 0xff), (SUCCESS, 6));
    let mut expected = [0u8; 8];
    expected.copy_from_slice(&12345u64.to_le_bytes());
    assert_eq!(sram.get(6), expected[..6]);
    assert_eq!(sram.get(8)[6..], [0xa5; 2]);
    assert!(clock.publish(99).is_err());
    assert_eq!(clock.published_ticks(), Ok(12345));
    let mut conflict = Smc::new(
        Sram::default(),
        BASE,
        vec![(key, Key::new(b"hex_", READABLE, 6))],
    )
    .unwrap();
    let count = conflict.value(KEY_COUNT).unwrap().to_vec();
    assert!(
        conflict
            .bind_rtc(clock, RtcKeyProfile::Hex48Little)
            .is_err()
    );
    assert_eq!(conflict.value(KEY_COUNT).unwrap(), count);
}

#[test]
fn original_rtc_helper_profile_requires_full_keyr_clkm_and_resolved_provider() {
    let cells = [0xb6, code(b"keyR"), code(b"CLKM")];
    assert_eq!(
        RtcKeyProfile::from_function(&cells, 0xb6),
        Ok(RtcKeyProfile::Hex48Little)
    );
    assert!(RtcKeyProfile::from_function(&cells, 0).is_err());
    assert!(RtcKeyProfile::from_function(&cells, 0xb7).is_err());
    assert!(RtcKeyProfile::from_function(&cells[..2], 0xb6).is_err());
    assert!(RtcKeyProfile::from_function(&[0xb6, code(b"keyW"), code(b"CLKM")], 0xb6).is_err());
    assert!(RtcKeyProfile::from_function(&[0xb6, code(b"keyR"), code(b"CLKH")], 0xb6).is_err());
}

#[test]
fn smc_and_spmi_sample_one_epoch_while_calendar_offset_has_one_pmu_owner() {
    use {
        crate::platform::apple::counter::FREQUENCY_HZ, crate::platform::apple::pmu::Pmu,
        crate::platform::apple::pmu::RTC_HZ, crate::platform::apple::pmu::RtcClock,
        crate::platform::apple::pmu::RtcEpoch, crate::platform::apple::spmi::SpmiSlave,
        stela_soc_data::pmu::ClockOffset, stela_soc_data::pmu::Configuration,
        stela_soc_data::pmu::Rtc, stela_soc_data::pmu::WallClock,
    };
    let rtc = Rtc {
        upcount: 0x1406,
        clock_offset: ClockOffset::Register(0x1411),
        alarm_control: 0x1401,
        alarm_enable: 0x40,
        alarm_offset: 0x140c,
        alarm_event: 0x14c0,
        irq_mask: 0x14c2,
        event_mask: 1,
        interrupt_mask: 1,
    };
    let clock = RtcClock::new(RtcEpoch {
        counter: 100,
        ticks: 987654321,
    })
    .unwrap();
    let config = Configuration::new(Vec::new(), Some(rtc), 1).unwrap();
    let mut pmu = Pmu::with_clock(
        config,
        clock.clone(),
        Some(WallClock {
            unix_seconds: 1_792_000_000,
            counter: 100,
        }),
    )
    .unwrap();
    let (mut smc, sram) = smc();
    smc.bind_rtc(pmu.rtc_clock().unwrap(), RtcKeyProfile::Hex48Little)
        .unwrap();
    let now = 100 + 3 * FREQUENCY_HZ;
    clock.publish(now).unwrap(); // same service boundary as the root adapter
    send(&mut smc, request(READ, 0, 6, 0, rtc::KEY));
    let mut raw = [0; 8];
    raw[..6].copy_from_slice(&sram.get(6));
    let logical = u64::from_le_bytes(raw);
    assert_eq!(logical, 987654321 + 3 * RTC_HZ);
    pmu.read(rtc.upcount, &mut raw[..6], now).unwrap();
    assert_eq!(u64::from_le_bytes(raw) >> 1, logical);
    pmu.write(0x1411, &[9, 8, 7, 6, 5, 4], now).unwrap();
    send(&mut smc, request(READ, 1, 6, 0, rtc::KEY));
    raw[..6].copy_from_slice(&sram.get(6));
    assert_eq!(u64::from_le_bytes(raw), logical);
    assert!(pmu.read(rtc.upcount, &mut raw[..6], now - 1).is_err());
    assert_eq!(clock.published_ticks(), Ok(logical));
}

#[test]
fn write_observations_preserve_zero_replies_and_request_id_wrap() {
    let (mut smc, sram) = smc();
    sram.put(&PANIC_BEGIN.to_le_bytes());
    for number in 0..=16 {
        let id = (number & 15) as u8;
        let payload = request(WRITE, id, 4, 0, SYSTEM_EVENT);
        let reply = send(&mut smc, payload);
        assert_eq!(reply, u64::from(id) << 12);
        assert_eq!(
            smc.take_log(),
            Some(WriteLog {
                request: payload,
                system_event: Some(PANIC_BEGIN),
                reply: Ok(reply),
                dropped_before: 0,
            })
        );
    }
    assert_eq!(smc.notice(), Some(PANIC_BEGIN));
    assert_eq!(smc.take_log(), None);
}

#[test]
fn write_observations_report_losses() {
    let (mut smc, sram) = smc();
    sram.put(&[0]);
    for number in 0..WRITE_LOG_LIMIT + 3 {
        send(
            &mut smc,
            request(WRITE, (number & 15) as u8, 1, 0, NOTIFICATIONS),
        );
    }
    assert_eq!(smc.write_log.len(), WRITE_LOG_LIMIT);
    let first = smc.take_log().unwrap();
    assert_eq!(first.request, request(WRITE, 3, 1, 0, NOTIFICATIONS));
    assert_eq!(first.dropped_before, 3);
    assert_eq!(smc.take_log().unwrap().dropped_before, 0);
    while smc.take_log().is_some() {}

    sram.put(&0u32.to_le_bytes());
    let payload = request(WRITE, 0, 4, 0, SYSTEM_EVENT);
    let mut replies = Vec::new();
    assert_eq!(
        smc.receive(payload, &mut replies),
        Err("SMC MBSE command is not modeled")
    );
    assert!(replies.is_empty());
    assert_eq!(
        smc.take_log(),
        Some(WriteLog {
            request: payload,
            system_event: Some(0),
            reply: Err("SMC MBSE command is not modeled"),
            dropped_before: 0,
        })
    );
}

#[test]
fn initialize_names_the_shared_page_and_key_count_reads_big_endian() {
    let (mut smc, _) = smc();
    assert_eq!(send(&mut smc, u64::from(INITIALIZE)), BASE);
    let reply = send(&mut smc, request(READ, 3, 4, 0, code(b"#KEY")));
    assert_eq!(reply & 0xff, u64::from(SUCCESS));
    assert_eq!(reply >> 12 & 0xf, 3);
    assert_eq!(reply >> 16 & 0xff, 4);
    assert_eq!((reply >> 32) as u32, u32::from_be(17));
    // Unknown keys, short reads and bad sizes answer SMC errors.
    assert_eq!(
        send(&mut smc, request(READ, 0, 4, 0, code(b"RGEN"))) & 0xff,
        u64::from(KEY_NOT_FOUND)
    );
    assert_eq!(
        send(&mut smc, request(READ, 0, 2, 0, code(b"#KEY"))) & 0xff,
        u64::from(SIZE_MISMATCH)
    );
    assert_eq!(
        send(&mut smc, request(READ, 0, 121, 0, code(b"#KEY"))) & 0xff,
        u64::from(BAD_ARGUMENT)
    );
    assert!(smc.receive(0x55, &mut Vec::new()).is_err());
}

#[test]
fn fourcc_key_indices_decode_at_the_consumer_boundary() {
    let (mut smc, _) = smc();
    let expected: Vec<u32> = smc.keys.keys().copied().collect();
    for (index, key) in expected.into_iter().enumerate() {
        let reply = send(&mut smc, request(KEY_BY_INDEX, 3, 0, 0, index as u32));
        assert_eq!(reply as u8, SUCCESS);
        // Linux swab32 and Apple's LDR/REV interpret the four raw
        // response bytes as a most-significant-byte-first FourCC.
        let wire = ((reply >> 32) as u32).to_le_bytes();
        assert_eq!(u32::from_be_bytes(wire), key);
    }
}

#[test]
fn fourcc_key_information_decodes_at_the_consumer_boundary() {
    let (mut smc, sram) = smc();
    let reply = send(&mut smc, request(KEY_INFO, 4, 0, 0, code(b"gP16")));
    assert_eq!(reply as u8, SUCCESS);
    let info = sram.get(6);
    // Linux get_unaligned_be32 and Apple's LDUR/REV decode this field.
    assert_eq!(
        u32::from_be_bytes(info[1..5].try_into().unwrap()),
        code(b"ui32")
    );
    assert_eq!(info[0], 4);
    assert_eq!(info[5], READABLE | WRITABLE | FUNCTION);
}

#[test]
fn keys_enumerate_sorted_with_their_information() {
    let (mut smc, sram) = smc();
    let first = send(&mut smc, request(KEY_BY_INDEX, 0, 0, 0, 0));
    assert_eq!(((first >> 32) as u32).to_le_bytes(), *b"#KEY");
    // Byte order: `D1Vn` before `MBSE`, `aDC#` before `bHLD` and `gP09`.
    let second = send(&mut smc, request(KEY_BY_INDEX, 0, 0, 0, 1));
    assert_eq!(((second >> 32) as u32).to_le_bytes(), *b"D1Vn");
    let third = send(&mut smc, request(KEY_BY_INDEX, 0, 0, 0, 2));
    assert_eq!(((third >> 32) as u32).to_le_bytes(), *b"MBSE");
    let eighth = send(&mut smc, request(KEY_BY_INDEX, 0, 0, 0, 7));
    assert_eq!(((eighth >> 32) as u32).to_le_bytes(), *b"aDC#");
    let tenth = send(&mut smc, request(KEY_BY_INDEX, 0, 0, 0, 9));
    assert_eq!(((tenth >> 32) as u32).to_le_bytes(), *b"gP09");
    assert_eq!(
        send(&mut smc, request(KEY_BY_INDEX, 0, 0, 0, 17)) & 0xff,
        u64::from(INDEX_RANGE)
    );
    send(&mut smc, request(KEY_INFO, 0, 0, 0, code(b"gP16")));
    assert_eq!(sram.get(6), [4, b'u', b'i', b'3', b'2', 0xd0]);
}

#[test]
fn the_ap_enables_notifications_with_the_ntap_flag() {
    let (mut smc, sram) = smc();
    assert!(!smc.notifications_enabled());
    sram.put(&[1]);
    let reply = send(&mut smc, request(WRITE, 0, 1, 0, code(b"NTAP")));
    assert_eq!(reply & 0xff, u64::from(SUCCESS));
    assert!(smc.notifications_enabled());
    assert!(Smc::new(Sram::default(), BASE, vec![(code(b"NTAP"), Key::gpio())]).is_err());
}

#[test]
fn gpio_keys_latch_writes_from_the_shared_page() {
    let (mut smc, sram) = smc();
    sram.put(&0x0100_8000u32.to_le_bytes());
    let reply = send(&mut smc, request(WRITE, 5, 4, 0, code(b"gP16")));
    assert_eq!((reply & 0xff, reply >> 12 & 0xf), (u64::from(SUCCESS), 5));
    assert_eq!(smc.value(code(b"gP16")), Some(&[0, 0x80, 0, 1][..]));
    let read = send(&mut smc, request(READ, 0, 4, 0, code(b"gP16")));
    assert_eq!((read >> 32) as u32, 0x0100_8000);
    assert_eq!(
        send(&mut smc, request(WRITE, 0, 4, 0, code(b"#KEY"))) & 0xff,
        u64::from(NOT_WRITABLE)
    );
    assert_eq!(
        send(&mut smc, request(WRITE, 0, 2, 0, code(b"gP16"))) & 0xff,
        u64::from(SIZE_MISMATCH)
    );
    // RW writes then reads back.
    sram.put(&7u32.to_le_bytes());
    let both = send(&mut smc, request(READ_WRITE, 0, 4, 4, code(b"gP09")));
    assert_eq!((both >> 32) as u32, 7);
    assert_eq!(sram.read(0, 4), Some(7));
    assert!(sram.read(SRAM_BYTES - 2, 4).is_none());
}

fn write_key(smc: &mut Smc, sram: &Sram, name: &[u8; 4], value: &[u8]) -> Vec<u64> {
    sram.put(value);
    let mut outbox = Vec::new();
    smc.receive(
        request(WRITE, 2, value.len() as u8, 0, code(name)),
        &mut outbox,
    )
    .unwrap();
    outbox
}

#[test]
fn system_event_notices_are_recorded_and_commands_request_transitions() {
    let (mut smc, sram) = smc();
    // AppleSMCPMU takes the system-event path only for a 4-byte MBSE.
    send(&mut smc, request(KEY_INFO, 0, 0, 0, code(b"MBSE")));
    assert_eq!(sram.get(1), [4]);
    for notice in [b"offw", b"rest", b"slpw", b"waka", b"panb", b"pane"] {
        let reply = write_key(&mut smc, &sram, b"MBSE", &code(notice).to_le_bytes());
        assert_eq!(reply, [request(SUCCESS, 2, 0, 0, 0) & 0xffff]);
        assert_eq!(smc.notice(), Some(code(notice)));
        assert!(smc.take_transition().is_none());
    }
    write_key(&mut smc, &sram, b"MBSE", &code(b"phra").to_le_bytes());
    let restart = smc.take_transition().unwrap();
    assert_eq!(
        (restart.device, restart.transition),
        ("smc", Transition::Restart)
    );
    assert!(smc.take_transition().is_none());
    write_key(&mut smc, &sram, b"MBSE", &code(b"sysr").to_le_bytes());
    assert_eq!(
        smc.take_transition().unwrap().transition,
        Transition::Restart
    );
    write_key(&mut smc, &sram, b"MBSE", &code(b"susp").to_le_bytes());
    assert_eq!(
        smc.take_transition().unwrap().transition,
        Transition::PowerOff
    );
    // Low-power emergency mode, hibernation and unknown commands refuse.
    for command in [b"lpem", b"hiba", b"zzzz"] {
        sram.put(&code(command).to_le_bytes());
        assert!(
            smc.receive(request(WRITE, 0, 4, 0, code(b"MBSE")), &mut Vec::new())
                .is_err()
        );
    }
    assert_eq!(
        send(&mut smc, request(READ, 0, 4, 0, code(b"MBSE"))) & 0xff,
        u64::from(NOT_READABLE)
    );
}

#[test]
fn sleep_waits_for_the_ap_and_a_wake_reports_its_source_in_mbsw() {
    let (smc, sram) = smc();
    let mut smc = smc.with_wake_bits(WakeBits {
        power_button: Some(0),
        rtc: Some(48),
    });
    write_key(&mut smc, &sram, b"NTAP", &[1]);
    // `slpa` makes the sleep pending; `waka` before the SoC slept
    // cancels it.
    write_key(&mut smc, &sram, b"MBSE", &code(b"slpa").to_le_bytes());
    assert!(smc.sleep_pending() && !smc.asleep());
    write_key(&mut smc, &sram, b"MBSE", &code(b"waka").to_le_bytes());
    assert!(!smc.sleep_pending());
    // Asleep, a press reports nothing and asks for the wake.
    write_key(&mut smc, &sram, b"MBSE", &code(b"slpa").to_le_bytes());
    smc.enter_sleep();
    assert!(smc.asleep());
    assert!(!smc.power_button(false));
    assert!(smc.power_button(true));
    smc.wake(WakeSource::PowerButton);
    assert!(!smc.asleep());
    send(&mut smc, request(READ, 0, 8, 0, code(b"MBSW")));
    assert_eq!(sram.get(8), 1u64.to_le_bytes());
    // Its release is not reported; the next press and release are.
    assert!(!smc.power_button(false));
    let mut outbox = Vec::new();
    smc.poll(&mut outbox).unwrap();
    assert!(outbox.is_empty());
    smc.power_button(true);
    smc.power_button(false);
    smc.poll(&mut outbox).unwrap();
    assert_eq!(outbox, [0x18 | 0x7201_0101 << 32, 0x18 | 0x7201_0100 << 32]);
    // An RTC wake reports bit 48 alone.
    write_key(&mut smc, &sram, b"MBSE", &code(b"slpa").to_le_bytes());
    smc.enter_sleep();
    smc.wake(WakeSource::Rtc);
    send(&mut smc, request(READ, 0, 8, 0, code(b"MBSW")));
    assert_eq!(sram.get(8), (1u64 << 48).to_le_bytes());
    // Without a named bit a wake reports no source.
    let (mut smc, sram) = self::smc();
    write_key(&mut smc, &sram, b"MBSE", &code(b"slpa").to_le_bytes());
    smc.enter_sleep();
    smc.wake(WakeSource::Rtc);
    send(&mut smc, request(READ, 0, 8, 0, code(b"MBSW")));
    assert_eq!(sram.get(8), [0; 8]);
}

#[test]
fn an_ap_panic_notification_is_answered_with_panic_done() {
    let (mut smc, sram) = smc();
    let outbox = write_key(&mut smc, &sram, b"NESN", &[0x70, 0x8a, 0, 0]);
    assert_eq!(outbox.len(), 2);
    assert_eq!(outbox[0] & 0xff, u64::from(SUCCESS));
    assert_eq!(outbox[1], 0x18 | 0x700a_0000 << 32);
    sram.put(&[0x75, 1, 0, 0]);
    assert!(
        smc.receive(request(WRITE, 0, 4, 0, code(b"NESN")), &mut Vec::new())
            .is_err()
    );
}

#[test]
fn the_power_button_is_held_in_bhld_and_notified_once_enabled() {
    let (mut smc, sram) = smc();
    smc.power_button(true);
    let held = send(&mut smc, request(READ, 0, 1, 0, code(b"bHLD")));
    assert_eq!((held >> 16 & 0xff, held >> 32), (1, 1));
    // Nothing is sent before the AP sets NTAP; the event waits.
    let mut outbox = Vec::new();
    smc.poll(&mut outbox).unwrap();
    assert!(outbox.is_empty());
    write_key(&mut smc, &sram, b"NTAP", &[1]);
    smc.poll(&mut outbox).unwrap();
    assert_eq!(outbox, [0x18 | 0x7201_0101 << 32]);
    smc.power_button(false);
    outbox.clear();
    smc.poll(&mut outbox).unwrap();
    assert_eq!(outbox, [0x18 | 0x7201_0100 << 32]);
    let released = send(&mut smc, request(READ, 0, 1, 0, code(b"bHLD")));
    assert_eq!(released >> 32, 0);
}

#[test]
fn boot_records_report_no_wake_source_and_an_unknown_shutdown() {
    let (mut smc, sram) = smc();
    sram.put(&[0xff; 8]);
    let wake = send(&mut smc, request(READ, 0, 8, 0, code(b"MBSW")));
    assert_eq!((wake & 0xff, wake >> 16 & 0xff), (u64::from(SUCCESS), 8));
    assert_eq!(sram.get(8), [0; 8]);
    let cause = send(&mut smc, request(READ, 0, 1, 0, code(b"MESS")));
    assert_eq!((cause & 0xff, cause >> 16 & 0xff, cause >> 32), (0, 1, 0));
    assert_eq!(
        send(&mut smc, request(READ, 0, 8, 0, code(b"MEST"))) & 0xff,
        u64::from(KEY_NOT_FOUND)
    );
    assert_eq!(
        send(&mut smc, request(WRITE, 0, 1, 0, code(b"MESS"))) & 0xff,
        u64::from(NOT_WRITABLE)
    );
}

/// `AppleHPM::atomic4CC`'s sequence: read free, take, read held, issue
/// the 4CC command, release.
#[test]
fn the_port_controller_lock_is_granted_to_the_ap_at_once() {
    let (mut smc, sram) = smc();
    let lock = code(b"D1Vn");
    let status = |smc: &mut Smc| send(smc, request(READ, 0, 1, 0, lock)) >> 32;
    assert_eq!(status(&mut smc), u64::from(LOCK_RELEASED));
    let taken = write_key(&mut smc, &sram, b"D1Vn", &[LOCK_HELD]);
    assert_eq!(taken[0] & 0xff, u64::from(SUCCESS));
    assert_eq!(status(&mut smc), u64::from(LOCK_HELD));
    write_key(&mut smc, &sram, b"D1Vn", &[LOCK_RELEASED]);
    assert_eq!(status(&mut smc), u64::from(LOCK_RELEASED));
    // Only release and take have a meaning.
    sram.put(&[2]);
    assert!(
        smc.receive(request(WRITE, 0, 1, 0, lock), &mut Vec::new())
            .is_err()
    );
    assert_eq!(smc.value(lock), Some(&[LOCK_RELEASED][..]));
    send(&mut smc, request(KEY_INFO, 0, 0, 0, lock));
    assert_eq!(
        sram.get(6),
        [1, b'f', b'l', b'a', b'g', READABLE | WRITABLE]
    );
}

#[test]
fn the_smc_exports_no_adc_sensors() {
    let (mut smc, _) = smc();
    let count = send(&mut smc, request(READ, 0, 4, 0, code(b"aDC#")));
    assert_eq!((count & 0xff, count >> 16 & 0xff), (u64::from(SUCCESS), 4));
    assert_eq!(count >> 32, 0);
    assert_eq!(
        send(&mut smc, request(WRITE, 0, 4, 0, code(b"aDC#"))) & 0xff,
        u64::from(NOT_WRITABLE)
    );
    // Without a channel there is no per-index sensor key.
    assert_eq!(
        send(&mut smc, request(KEY_INFO, 0, 0, 0, code(b"aDC0"))) & 0xff,
        u64::from(KEY_NOT_FOUND)
    );
}

#[test]
fn the_watchdog_reads_disarmed_and_refuses_arming() {
    let mut sink = super::super::interrupt::InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    let mut watchdog = Watchdog;
    let control = watchdog
        .read(WATCHDOG_CONTROL, Width::Word, &mut access)
        .unwrap();
    assert_eq!(control, 0);
    // `_disableSmcHwWatchdog`'s read-modify-write.
    watchdog
        .write(WATCHDOG_CONTROL, Width::Word, control & !1, &mut access)
        .unwrap();
    assert!(
        watchdog
            .write(WATCHDOG_CONTROL, Width::Word, 1, &mut access)
            .is_err()
    );
    assert!(watchdog.read(0, Width::Word, &mut access).is_err());
}
