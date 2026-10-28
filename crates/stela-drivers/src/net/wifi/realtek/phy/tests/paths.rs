// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8822C paths phase fixtures and source comparisons.
use super::*;

#[test]
fn initial_paths_preserve_source_reset_width_and_igi_wrap_latch_effects() {
    for igi in [0u32, 1, 2, 63, 127] {
        let (mut bus, loaded, report) = paths_setup(3, igi);
        let original = bus.model.lock().unwrap().get(2, 2);
        let configured = unsafe { loaded.configure_paths(&mut bus, &report) }.unwrap();
        assert_eq!(configured.profile(), bus.profile());
        assert_eq!(u32::from(configured.initial_igi()), igi);
        let m = bus.model.lock().unwrap();
        let resets: Vec<_> = m
            .events
            .iter()
            .filter(|e| e[0] == 1 && e[1] == 2)
            .copied()
            .collect();
        assert_eq!(resets.len(), 9);
        for pulse in resets.as_chunks::<3>().0 {
            assert_eq!(
                *pulse,
                [
                    [1, 2, 2, original | 1],
                    [1, 2, 2, original & !1],
                    [1, 2, 2, original | 1]
                ]
            );
        }
        let latches: Vec<_> = m
            .events
            .iter()
            .filter(|e| e[0] == 1 && e[1] == 0x1d70)
            .map(|e| e[3])
            .collect();
        assert_eq!(latches.len(), 4);
        assert_eq!(latches[0] & 127, igi.wrapping_sub(2) & 127);
        assert_eq!((latches[1] >> 8) & 127, igi.wrapping_sub(2) & 127);
        assert_eq!(latches[2] & 127, igi);
        assert_eq!((latches[3] >> 8) & 127, igi);
        assert_eq!(m.quarantined, 0);
    }
}

#[test]
fn every_path_io_failure_and_late_reset_retains_actual_owner_without_configured_state() {
    let (mut bus, loaded, report) = paths_setup(0, 0);
    unsafe { loaded.configure_paths(&mut bus, &report) }.unwrap();
    let total = bus.model.lock().unwrap().calls;
    for at in 1..=total {
        let (mut bus, loaded, report) = paths_setup(0, 0);
        bus.model.lock().unwrap().fail = Some(at);
        assert!(
            unsafe { loaded.configure_paths(&mut bus, &report) }.is_err(),
            "operation {at}"
        );
        assert!(bus.model.lock().unwrap().quarantined >= 1, "operation {at}");
    }
    for (r, w, value, at) in [(0xf0, 4, 0, total - 4), (0x80, 2, 0xffff, total - 3)] {
        let (mut bus, loaded, report) = paths_setup(0, 0);
        bus.model.lock().unwrap().mutate = Some((at, r, w, value));
        assert!(unsafe { loaded.configure_paths(&mut bus, &report) }.is_err());
        let m = bus.model.lock().unwrap();
        assert!(m.events.iter().any(|e| e[0] == 1 && e[1] == 2 && e[2] == 2));
        assert!(m.quarantined >= 1);
    }
}

#[test]
fn path_profile_report_and_actual_domain_mismatches_do_not_program_bb() {
    let (mut bus, loaded, _) = paths_setup(0, 63);
    let (_, _, other) = setup(2, 0, 0, 0, false, false);
    assert!(matches!(
        unsafe { loaded.configure_paths(&mut bus, &other) },
        Err(Error::WrongProfile)
    ));
    assert_eq!(bus.model.lock().unwrap().calls, 0);
    let (mut bus, loaded, _) = paths_setup(0, 63);
    let (_, _, one) = setup(1, 0, 0, 0, true, false);
    assert!(matches!(
        unsafe { loaded.configure_paths(&mut bus, &one) },
        Err(Error::UnsupportedRfLayout)
    ));
    assert_eq!(bus.model.lock().unwrap().calls, 0);
    for (r, w) in [(2, 1), (0x1f, 1), (0xec, 4)] {
        let (mut bus, loaded, report) = paths_setup(0, 63);
        bus.model.lock().unwrap().set(r, w, 0);
        assert!(matches!(
            unsafe { loaded.configure_paths(&mut bus, &report) },
            Err(Error::DomainOff)
        ));
        let m = bus.model.lock().unwrap();
        assert!(!m.events.iter().any(|e| e[0] == 1));
        assert_eq!(m.quarantined, 1);
    }
}

#[test]
#[ignore = "requires unchanged pinned C initial AB/AB/false TRX oracle"]
fn every_igi_and_complete_source_trx_trace_and_bar_matches() {
    let trace = std::fs::read(std::env::var("STELA_REALTEK_WIFI_TRX_ORACLE").unwrap()).unwrap();
    let mut offset = 0;
    for case in 0..512 {
        let mut header = [0; 3];
        for (i, v) in header.iter_mut().enumerate() {
            *v = u32::from_le_bytes(
                trace[offset + i * 4..offset + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
        }
        offset += 12;
        let [pattern, igi, events] = header;
        let (mut bus, loaded, report) = paths_setup(pattern as usize, igi);
        let configured = unsafe { loaded.configure_paths(&mut bus, &report) }.unwrap();
        assert_eq!(u32::from(configured.initial_igi()), igi);
        let m = bus.model.lock().unwrap();
        let native = source_events(&m.events);
        assert_eq!(native.len(), events as usize * 16, "case {case}");
        assert_eq!(
            &native,
            &trace[offset..offset + native.len()],
            "case {case}"
        );
        offset += native.len();
        assert_eq!(&m.bytes, &trace[offset..offset + 0x5000], "case {case}");
        offset += 0x5000;
        assert_eq!(m.quarantined, 0);
    }
    assert_eq!(offset, trace.len());
}
