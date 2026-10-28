// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8822C dynamic phase fixtures and source comparisons.
use super::*;

#[test]
fn dynamic_igi_and_edcca_bits() {
    let (mut bus, paths, report) = dynamic_setup(3, 127, 0x7f, 63, 0);
    let old = bus.model.lock().unwrap().get(0x84c, 4);
    // SAFETY: Bus retains the modeled IGI/CCK/EDCCA registers and phase arguments.
    // Reads, writes and injected failures occur sequentially without another RF client.
    let state = unsafe { paths.initialize_dynamic(&mut bus, &report) }.unwrap();
    assert_eq!(state.profile(), bus.profile());
    assert_eq!(state.igi_history(), [127, 0, 0, 0]);
    assert_eq!(state.cck_bounds(), [63, 0]);
    assert_eq!(state.crystal_cap(), 127);
    let t = state.tracking();
    assert_eq!(t.fa_history, [0; 4]);
    assert_eq!(t.igi_bitmap, 0);
    assert_eq!(t.cck_pd_levels, [[0; 4]; 2]);
    assert_eq!(t.cck_fa_average, None);
    assert!(!t.iqk_done);
    assert!(t.cfo_adjusting);
    assert_eq!(t.current_tx_path, Path::A);
    assert_eq!(t.path_counts, [0; 2]);
    assert_eq!(t.path_sums, [0; 2]);
    let m = bus.model.lock().unwrap();
    assert_eq!(m.get(0x84c, 4), (old & 0xffff) | 0xffff0000);
    let writes: Vec<_> = m
        .events
        .iter()
        .filter(|e| e[0] == 1)
        .map(|e| (e[1], e[2]))
        .collect();
    assert_eq!(
        writes,
        [(0x84c, 4), (0x84c, 4), (0x520, 4), (0x524, 4), (0x844, 4)]
    );
    assert_eq!(m.quarantined, 0);
}

#[test]
fn dynamic_domain_loss_quarantines() {
    let (mut bus, paths, report) = dynamic_setup(0, 0, 63, 0, 63);
    // SAFETY: Bus retains the modeled IGI/CCK/EDCCA registers and phase arguments.
    // Reads, writes and injected failures occur sequentially without another RF client.
    unsafe { paths.initialize_dynamic(&mut bus, &report) }.unwrap();
    let total = bus.model.lock().unwrap().calls;
    for at in 1..=total {
        let (mut bus, paths, report) = dynamic_setup(0, 0, 63, 0, 63);
        bus.model.lock().unwrap().fail = Some(at);
        assert!(
            // SAFETY: Bus retains the modeled IGI/CCK/EDCCA registers and phase arguments.
            // Reads, writes and injected failures occur sequentially without another RF client.
            unsafe { paths.initialize_dynamic(&mut bus, &report) }.is_err(),
            "{at}"
        );
        assert_eq!(bus.model.lock().unwrap().quarantined, 1, "{at}");
    }
    for (r, w, value, at) in [
        (0xf0, 4, 0, total - 4),
        (0x80, 2, 0xffff, total - 3),
        (2, 1, 0, total - 2),
        (0x1f, 1, 0, total - 1),
        (0xec, 4, 0, total),
    ] {
        let (mut bus, paths, report) = dynamic_setup(0, 0, 63, 0, 63);
        bus.model.lock().unwrap().mutate = Some((at, r, w, value));
        // SAFETY: Bus retains the modeled IGI/CCK/EDCCA registers and phase arguments.
        // Reads, writes and injected failures occur sequentially without another RF client.
        assert!(unsafe { paths.initialize_dynamic(&mut bus, &report) }.is_err());
        let m = bus.model.lock().unwrap();
        assert!(m.events.iter().any(|e| e[0] == 1));
        assert_eq!(m.quarantined, 1);
    }
}

#[test]
fn dynamic_partial_write_unwind() {
    let (mut bus, paths, report) = dynamic_setup(0, 0, 0, 0, 0);
    bus.panic_register = Some(0x524);
    // SAFETY: Bus retains the modeled IGI/CCK/EDCCA registers and phase arguments.
    // Reads, writes and injected failures occur sequentially without another RF client.
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        paths.initialize_dynamic(&mut bus, &report)
    }));
    assert!(caught.is_err());
    let m = bus.model.lock().unwrap();
    assert!(m.events.iter().any(|e| e[0] == 1 && e[1] == 0x520));
    assert_eq!(m.quarantined, 1);
}

#[test]
fn dynamic_profile_preflight() {
    let (mut bus, paths, _) = dynamic_setup(0, 0, 0, 0, 0);
    let (_, _, other) = setup(2, 0, 0, 0, false, false);
    assert!(matches!(
        // SAFETY: Bus retains the modeled IGI/CCK/EDCCA registers and phase arguments.
        // Reads, writes and injected failures occur sequentially without another RF client.
        unsafe { paths.initialize_dynamic(&mut bus, &other) },
        Err(Error::WrongProfile)
    ));
    assert_eq!(bus.model.lock().unwrap().calls, 0);
    let (mut bus, paths, _) = dynamic_setup(0, 0, 0, 0, 0);
    let (_, _, one) = setup(1, 0, 0, 0, true, false);
    assert!(matches!(
        // SAFETY: Bus retains the modeled IGI/CCK/EDCCA registers and phase arguments.
        // Reads, writes and injected failures occur sequentially without another RF client.
        unsafe { paths.initialize_dynamic(&mut bus, &one) },
        Err(Error::UnsupportedRfLayout)
    ));
    assert_eq!(bus.model.lock().unwrap().calls, 0);
    for (r, w) in [(2, 1), (0x1f, 1), (0xec, 4)] {
        let (mut bus, paths, report) = dynamic_setup(0, 0, 0, 0, 0);
        bus.model.lock().unwrap().set(r, w, 0);
        assert!(matches!(
            // SAFETY: Bus retains the modeled IGI/CCK/EDCCA registers and phase arguments.
            // Reads, writes and injected failures occur sequentially without another RF client.
            unsafe { paths.initialize_dynamic(&mut bus, &report) },
            Err(Error::DomainOff)
        ));
        let m = bus.model.lock().unwrap();
        assert!(!m.events.iter().any(|e| e[0] == 1));
        assert_eq!(m.quarantined, 1);
    }
}

#[test]
#[ignore = "oracle: STELA_REALTEK_WIFI_DYNAMIC_ORACLE"]
fn rtl8822c_dynamic_matches_linux() {
    let trace = std::fs::read(std::env::var("STELA_REALTEK_WIFI_DYNAMIC_ORACLE").unwrap()).unwrap();
    let mut offset = 0;
    for case in 0..512 {
        let mut header = [0; 6];
        for (i, v) in header.iter_mut().enumerate() {
            *v = u32::from_le_bytes(
                trace[offset + i * 4..offset + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
        }
        offset += 24;
        let [pattern, igi, crystal, upper, lower, events] = header;
        let (mut bus, paths, report) =
            dynamic_setup(pattern as usize, igi, crystal as u8, upper, lower);
        // SAFETY: Bus retains the modeled IGI/CCK/EDCCA registers and phase arguments.
        // Reads, writes and injected failures occur sequentially without another RF client.
        let state = unsafe { paths.initialize_dynamic(&mut bus, &report) }.unwrap();
        let m = bus.model.lock().unwrap();
        let native = source_events(&m.events);
        assert_eq!(native.len(), events as usize * 16, "{case}");
        assert_eq!(&native, &trace[offset..offset + native.len()], "{case}");
        offset += native.len();
        let mut words = Vec::new();
        for word in dynamic_words(&state) {
            words.extend(word.to_le_bytes());
        }
        assert_eq!(words.len(), 28 * 4);
        assert_eq!(&words, &trace[offset..offset + words.len()], "{case}");
        offset += words.len();
        assert_eq!(&m.bytes, &trace[offset..offset + 0x5000], "{case}");
        offset += 0x5000;
        assert_eq!(m.quarantined, 0);
    }
    assert_eq!(offset, trace.len());
}
