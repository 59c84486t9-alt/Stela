// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8822C channel state phase fixtures and source comparisons.
use super::*;

#[test]
fn channel_geometry_and_failure_retention() {
    let (mut bus, phy, report, g) = channel_setup();
    // SAFETY: Bus retains its BB/MAC/RF model while the channel geometry and phase
    // inputs are borrowed. No packet or other channel-control client runs concurrently.
    let state = unsafe { phy.set_channel(&mut bus, &report, g) }.unwrap();
    assert_eq!(state.geometry(), g);
    assert_eq!(state.primary_index(), 4);
    assert_eq!(state.programmed_rf18() & 255, 42);
    assert_eq!(
        state.initial_igi(),
        bus.model.lock().unwrap().get(0x1d70, 4) as u8 & 127
    );
    let total = bus.model.lock().unwrap().calls;
    let plan = state
        .phy()
        .factory_power()
        .plan_channel_power(g, power_limits())
        .unwrap();
    // SAFETY: Bus retains the register/TXAGC model and the live plan/phase values.
    // The fixture has no concurrent transmit or power-control client, including rejected-plan cases.
    unsafe { state.program_channel_power(&mut bus, &report, plan) }.unwrap();
    for at in 1..=total {
        let (mut bus, phy, report, g) = channel_setup();
        bus.model.lock().unwrap().fail = Some(at);
        assert!(
            // SAFETY: Bus retains its BB/MAC/RF model while the channel geometry and phase
            // inputs are borrowed. No packet or other channel-control client runs concurrently.
            unsafe { phy.set_channel(&mut bus, &report, g) }.is_err(),
            "{at}"
        );
        assert!(bus.model.lock().unwrap().quarantined >= 1, "{at}");
    }
    let (mut bus, phy, report, g) = channel_setup();
    // SAFETY: Bus retains its BB/MAC/RF model while the channel geometry and phase
    // inputs are borrowed. No packet or other channel-control client runs concurrently.
    let state = unsafe { phy.set_channel(&mut bus, &report, g) }.unwrap();
    let bad = channel_power::Geometry::new(1, channel_power::Width::Mhz20, None, None).unwrap();
    let plan = state
        .phy()
        .factory_power()
        .plan_channel_power(bad, power_limits())
        .unwrap();
    bus.model.lock().unwrap().calls = 0;
    assert!(matches!(
        // SAFETY: Bus retains the register/TXAGC model and the live plan/phase values.
        // The fixture has no concurrent transmit or power-control client, including rejected-plan cases.
        unsafe { state.program_channel_power(&mut bus, &report, plan) },
        Err(Error::ChannelPower(channel_power::Error::Geometry))
    ));
    assert_eq!(bus.model.lock().unwrap().calls, 0);
}

#[test]
fn channel_domain_loss_quarantines() {
    let (mut bus, phy, report, g) = channel_setup();
    // SAFETY: Bus retains its BB/MAC/RF model while the channel geometry and phase
    // inputs are borrowed. No packet or other channel-control client runs concurrently.
    unsafe { phy.set_channel(&mut bus, &report, g) }.unwrap();
    let total = bus.model.lock().unwrap().calls;
    for (r, w, v, at) in [
        (0xf0, 4, 0, total - 4),
        (0x80, 2, 0xffff, total - 3),
        (2, 1, 0, total - 2),
        (0x1f, 1, 0, total - 1),
        (0xec, 4, 0, total),
    ] {
        let (mut bus, phy, report, g) = channel_setup();
        bus.model.lock().unwrap().mutate = Some((at, r, w, v));
        // SAFETY: Bus retains its BB/MAC/RF model while the channel geometry and phase
        // inputs are borrowed. No packet or other channel-control client runs concurrently.
        assert!(unsafe { phy.set_channel(&mut bus, &report, g) }.is_err());
        assert!(bus.model.lock().unwrap().quarantined >= 1);
    }
    let (mut bus, phy, report, g) = channel_setup();
    bus.panic_register = Some(0x3fb8);
    assert!(
        // SAFETY: Bus retains its BB/MAC/RF model while the channel geometry and phase
        // inputs are borrowed. No packet or other channel-control client runs concurrently.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            phy.set_channel(&mut bus, &report, g)
        }))
        .is_err()
    );
    let m = bus.model.lock().unwrap();
    assert!(m.events.iter().any(|e| e[0] == 1 && e[1] == 0x1c90));
    assert!(m.quarantined >= 1);
}

#[test]
#[ignore = "requires unchanged complete source BB/MAC/RF channel oracle"]
fn rtl8822c_channel_matches_linux() {
    let trace = std::fs::read(std::env::var("STELA_REALTEK_WIFI_CHANNEL_ORACLE").unwrap()).unwrap();
    let mut offset = 0;
    let mut cases = 0;
    while offset < trace.len() {
        let h: [u32; 8] = core::array::from_fn(|i| {
            u32::from_le_bytes(
                trace[offset + i * 4..offset + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            )
        });
        offset += 32;
        let width = match h[1] {
            0 => channel_power::Width::Mhz20,
            1 => channel_power::Width::Mhz40,
            _ => channel_power::Width::Mhz80,
        };
        let g = channel_power::Geometry::new(
            h[0] as u8,
            width,
            if h[2] == 0 { None } else { Some(h[2] as u8) },
            if h[3] == 0 { None } else { Some(h[3] as u8) },
        )
        .unwrap();
        assert_eq!(u32::from(channel::primary_index(g)), h[6]);
        let (mut bus, _, report) = setup(1, 0, 63, h[4] as usize, false, false);
        {
            let mut m = bus.model.lock().unwrap();
            let v = m.get(2, 1) | 3;
            m.set(2, 1, v);
            let v = m.get(0x1f, 1) | 7;
            m.set(0x1f, 1, v);
            let v = m.get(0xec, 4) | 0x07000000;
            m.set(0xec, 4, v);
            let v = (m.get(0x1d70, 4) & !127) | h[5];
            m.set(0x1d70, 4, v);
        }
        let mut a = Attempt {
            profile: bus.profile(),
            io: &mut bus,
            done: false,
        };
        channel::set(&mut a, &report, g, h[6] as u8).unwrap();
        a.done = true;
        drop(a);
        let events = &trace[offset..offset + h[7] as usize * 16];
        offset += events.len();
        let bar = &trace[offset..offset + 0x5000];
        offset += bar.len();
        let m = bus.model.lock().unwrap();
        assert_eq!(source_events(&m.events), events, "source IO {cases}");
        assert!(
            m.bytes == bar,
            "BAR {cases}: {:?}",
            m.bytes.iter().zip(bar).position(|(a, b)| a != b)
        );
        assert_eq!(m.quarantined, 0);
        cases += 1;
    }
    assert_eq!(cases, 360);
}
