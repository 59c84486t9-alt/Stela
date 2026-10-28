// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8822C power phase fixtures and source comparisons.
use super::*;

#[test]
fn power_programming_failure_retention() {
    let (mut bus, phy, report, plan) = power_setup();
    // SAFETY: Bus retains the register/TXAGC model and the live plan/phase values.
    // The fixture has no concurrent transmit or power-control client, including rejected-plan cases.
    let programmed = unsafe { phy.program_channel_power(&mut bus, &report, plan) }.unwrap();
    assert_eq!(programmed.plan().geometry().primary(), 1);
    assert_eq!(programmed.phy().factory_power().rfe(), 0);
    let _phy = programmed.into_phy();
    let total = bus.model.lock().unwrap().calls;
    for at in 1..=total {
        let (mut bus, phy, report, plan) = power_setup();
        bus.model.lock().unwrap().fail = Some(at);
        assert!(
            // SAFETY: Bus retains the register/TXAGC model and the live plan/phase values.
            // The fixture has no concurrent transmit or power-control client, including rejected-plan cases.
            unsafe { phy.program_channel_power(&mut bus, &report, plan) }.is_err(),
            "{at}"
        );
        assert_eq!(bus.model.lock().unwrap().quarantined, 1, "{at}");
    }
    for (r, w, v, at) in [
        (0xf0, 4, 0, total - 4),
        (0x80, 2, 0xffff, total - 3),
        (2, 1, 0, total - 2),
        (0x1f, 1, 0, total - 1),
        (0xec, 4, 0, total),
    ] {
        let (mut bus, phy, report, plan) = power_setup();
        bus.model.lock().unwrap().mutate = Some((at, r, w, v));
        // SAFETY: Bus retains the register/TXAGC model and the live plan/phase values.
        // The fixture has no concurrent transmit or power-control client, including rejected-plan cases.
        assert!(unsafe { phy.program_channel_power(&mut bus, &report, plan) }.is_err());
        assert_eq!(bus.model.lock().unwrap().quarantined, 1);
    }
    let (mut bus, phy, report, plan) = power_setup();
    bus.panic_register = Some(0x3a00);
    assert!(
        // SAFETY: Bus retains the register/TXAGC model and the live plan/phase values.
        // The fixture has no concurrent transmit or power-control client, including rejected-plan cases.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            phy.program_channel_power(&mut bus, &report, plan)
        }))
        .is_err()
    );
    let m = bus.model.lock().unwrap();
    assert!(m.events.iter().any(|e| e[0] == 1 && e[1] == 0x18e8));
    assert_eq!(m.quarantined, 1);
}

#[test]
fn power_limits_preflight() {
    let (mut bus, phy, report, _) = power_setup();
    let g = channel_power::Geometry::new(1, channel_power::Width::Mhz20, None, None).unwrap();
    let other = board_power::channel_fixture(5, [255; 168])
        .plan_channel_power(g, power_limits())
        .unwrap();
    assert!(matches!(
        // SAFETY: Bus retains the register/TXAGC model and the live plan/phase values.
        // The fixture has no concurrent transmit or power-control client, including rejected-plan cases.
        unsafe { phy.program_channel_power(&mut bus, &report, other) },
        Err(Error::ChannelPower(channel_power::Error::WrongBoard))
    ));
    assert_eq!(bus.model.lock().unwrap().calls, 0);
    let (bus, phy, _, _) = power_setup();
    let mut l = power_limits();
    l.sar_quarter_dbm = Some([i32::MIN; 2]);
    assert!(phy.factory_power().plan_channel_power(g, l).is_err());
    assert_eq!(bus.model.lock().unwrap().calls, 0);
}

#[test]
#[ignore = "oracle: STELA_REALTEK_WIFI_CHANNEL_POWER_ORACLE"]
fn rtl8822c_power_matches_linux() {
    let trace =
        std::fs::read(std::env::var("STELA_REALTEK_WIFI_CHANNEL_POWER_ORACLE").unwrap()).unwrap();
    let mut offset = 0;
    for c in 0..512u32 {
        let h: [u32; 9] = core::array::from_fn(|i| {
            u32::from_le_bytes(
                trace[offset + i * 4..offset + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            )
        });
        offset += 36;
        assert_eq!(h[0], c);
        let nvm: [u8; 168] = trace[offset..offset + 168].try_into().unwrap();
        offset += 168;
        let table = &trace[offset..offset + 336];
        offset += 336;
        let events = &trace[offset..offset + h[7] as usize * 16];
        offset += events.len();
        let bar = &trace[offset..offset + h[8] as usize];
        offset += bar.len();
        let width = match h[2] {
            0 => channel_power::Width::Mhz20,
            1 => channel_power::Width::Mhz40,
            _ => channel_power::Width::Mhz80,
        };
        let g = channel_power::Geometry::new(
            h[1] as u8,
            width,
            if h[3] == 0 { None } else { Some(h[3] as u8) },
            if h[4] == 0 { None } else { Some(h[4] as u8) },
        )
        .unwrap();
        let limits = channel_power::Limits {
            factory_sheet: FactorySheet::try_from(h[5] as u8).unwrap(),
            max_eirp_mbm: (h[6] as i32 + 2) * 25,
            antenna_and_combining_mbm: [50, 75],
            sar_quarter_dbm: Some([h[6] as i32 + 4, h[6] as i32 - 1]),
            remnant_cck: (c % 3) as i8,
            remnant_ofdm: [(c % 3) as i8, (c % 2) as i8],
        };
        let power = board_power::channel_fixture((c % 7) as u8, nvm);
        let plan = power
            .plan_channel_power(g, limits)
            .unwrap_or_else(|e| panic!("case {c}: {e:?}"));
        for path in 0..2 {
            for rate in 0..84 {
                if let Some(gain) = plan.gain(path, rate) {
                    assert_eq!(
                        gain,
                        table[path as usize * 84 + rate as usize],
                        "case {c} path {path} rate {rate}"
                    );
                }
            }
        }
        let (mut bus, _, _) = setup(1, (c % 7) as u8, 63, c as usize, false, false);
        let mut a = Attempt {
            profile: bus.profile(),
            io: &mut bus,
            done: false,
        };
        channel_power::program_registers(&mut a, &plan).unwrap();
        a.done = true;
        drop(a);
        let m = bus.model.lock().unwrap();
        assert_eq!(source_events(&m.events), events, "events {c}");
        assert!(
            m.bytes == bar,
            "BAR {c}: first mismatch {:?}",
            m.bytes.iter().zip(bar).position(|(a, b)| a != b)
        );
        assert_eq!(m.quarantined, 0);
    }
    assert_eq!(trace.len() - offset, 65536 + 384 * 2);
}
