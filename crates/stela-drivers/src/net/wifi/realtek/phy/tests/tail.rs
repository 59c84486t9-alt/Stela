// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8822C tail phase fixtures and source comparisons.
use super::*;

#[test]
fn phy_tail_disables_mu_validity_keeps_source_widths_and_raw_thermal_reference() {
    let (mut bus, factory, report) = tail_setup(3, 255, 255);
    let before = bus.model.lock().unwrap().get(0x14c0, 4);
    let initialized = unsafe { factory.finish_initial_phy(&mut bus, &report) }.unwrap();
    let power = initialized
        .factory()
        .calibration()
        .initial()
        .factory_power();
    assert_eq!(power.profile(), bus.profile());
    assert_eq!(power.rfe(), 0);
    assert_eq!(power.limit_sheet_type(), 0);
    let t = initialized.tracking();
    assert_eq!(t.delta_power_index, [0; 4]);
    assert_eq!(t.averages, [None; 4]);
    assert_eq!(t.filter_state, [0; 4]);
    assert!(!t.triggered);
    assert_eq!(t.thermal_reference, 255);
    assert_eq!(t.lck_reference, 255);
    assert_eq!(initialized.factory().raw().thermal, [255; 2]);
    let m = bus.model.lock().unwrap();
    assert_eq!(
        m.get(0x14c0, 4),
        ((before | 0x10000) & !(0xf000 | 0x80 | 0x3f)) | 0xa000
    );
    assert_eq!(m.get(0x14c0, 4) & 0xbf, 0);
    let writes: Vec<_> = m
        .events
        .iter()
        .filter(|e| e[0] == 1)
        .map(|e| (e[1], e[2]))
        .collect();
    assert_eq!(
        writes,
        [
            (0x14c0, 4),
            (0x167c, 1),
            (0x1680, 2),
            (0x42c, 4),
            (0x45f, 1),
            (0x6dc, 4)
        ]
    );
    assert_eq!(m.quarantined, 0);
}

#[test]
fn phy_tail_every_io_failure_late_reset_and_partial_write_unwind_quarantines() {
    let (mut bus, factory, report) = tail_setup(0, 5, 6);
    unsafe { factory.finish_initial_phy(&mut bus, &report) }.unwrap();
    let total = bus.model.lock().unwrap().calls;
    for at in 1..=total {
        let (mut bus, factory, report) = tail_setup(0, 5, 6);
        bus.model.lock().unwrap().fail = Some(at);
        assert!(
            unsafe { factory.finish_initial_phy(&mut bus, &report) }.is_err(),
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
        let (mut bus, factory, report) = tail_setup(0, 5, 6);
        bus.model.lock().unwrap().mutate = Some((at, r, w, v));
        assert!(unsafe { factory.finish_initial_phy(&mut bus, &report) }.is_err());
        assert_eq!(bus.model.lock().unwrap().quarantined, 1);
    }
    let (mut bus, factory, report) = tail_setup(0, 5, 6);
    bus.panic_register = Some(0x42c);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            factory.finish_initial_phy(&mut bus, &report)
        }))
        .is_err()
    );
    let m = bus.model.lock().unwrap();
    assert!(m.events.iter().any(|e| e[0] == 1 && e[1] == 0x1680));
    assert_eq!(m.quarantined, 1);
}

#[test]
fn phy_tail_rejects_mismatched_profile_layout_and_initial_domain_without_programming() {
    let (mut bus, factory, _) = tail_setup(0, 0, 0);
    let (_, _, other) = setup(2, 0, 0, 0, false, false);
    assert!(matches!(
        unsafe { factory.finish_initial_phy(&mut bus, &other) },
        Err(Error::WrongProfile)
    ));
    assert_eq!(bus.model.lock().unwrap().calls, 0);
    let (mut bus, factory, _) = tail_setup(0, 0, 0);
    let (_, _, one) = setup(1, 0, 0, 0, true, false);
    assert!(matches!(
        unsafe { factory.finish_initial_phy(&mut bus, &one) },
        Err(Error::UnsupportedRfLayout)
    ));
    assert_eq!(bus.model.lock().unwrap().calls, 0);
    for (r, w) in [(2, 1), (0x1f, 1), (0xec, 4)] {
        let (mut bus, factory, report) = tail_setup(0, 0, 0);
        bus.model.lock().unwrap().set(r, w, 0);
        assert!(matches!(
            unsafe { factory.finish_initial_phy(&mut bus, &report) },
            Err(Error::DomainOff)
        ));
        let m = bus.model.lock().unwrap();
        assert!(!m.events.iter().any(|e| e[0] == 1));
        assert_eq!(m.quarantined, 1);
    }
}

#[test]
#[ignore = "requires unchanged source thermal reset/EWMA initialization and complete beamforming IO/BAR oracle"]
fn phy_tail_whole_source_io_tracking_and_bar_match() {
    let trace =
        std::fs::read(std::env::var("STELA_REALTEK_WIFI_PHY_TAIL_ORACLE").unwrap()).unwrap();
    let mut offset = 0;
    for case in 0..1024 {
        let head: [u32; 5] = core::array::from_fn(|i| {
            u32::from_le_bytes(
                trace[offset + i * 4..offset + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            )
        });
        offset += 20;
        let [pattern, a, b, reference, events] = head;
        let (mut bus, factory, report) = tail_setup(pattern as usize, a as u8, b as u8);
        let initialized = unsafe { factory.finish_initial_phy(&mut bus, &report) }.unwrap();
        let t = initialized.tracking();
        assert_eq!(u32::from(t.thermal_reference), reference);
        let m = bus.model.lock().unwrap();
        let native = source_events(&m.events);
        assert_eq!(native.len(), events as usize * 16, "{case}");
        assert_eq!(&native, &trace[offset..offset + native.len()], "{case}");
        offset += native.len();
        let mut words = Vec::new();
        words.extend(t.delta_power_index.map(|v| v as u32));
        words.extend(t.filter_state.map(|v| u32::try_from(v).unwrap()));
        words.extend(t.averages.map(|v| u32::from(v.unwrap_or(255))));
        words.extend([
            u32::from(t.triggered),
            u32::from(t.thermal_reference),
            u32::from(t.lck_reference),
        ]);
        let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        assert_eq!(bytes.len(), 60);
        assert_eq!(&bytes, &trace[offset..offset + 60], "{case}");
        offset += 60;
        assert_eq!(&m.bytes, &trace[offset..offset + 0x5000], "{case}");
        offset += 0x5000;
        assert_eq!(m.quarantined, 0);
    }
    assert_eq!(offset, trace.len());
}
