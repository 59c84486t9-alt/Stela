// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8822C mac phase fixtures and source comparisons.
use super::*;

#[test]
fn source_mac_executes_real_fifo_protocol_driver_info_interface_and_all_error_retention() {
    let (mut bus, report) = source_mac_setup(3);
    let state = unsafe { source_mac::initialize(&mut bus, &report) }.unwrap();
    assert_eq!(state.rx_filter_map1(), 0xffff);
    assert_eq!(state.fifo().profile(), bus.profile());
    let total = bus.model.lock().unwrap().calls;
    {
        let m = bus.model.lock().unwrap();
        assert!(m.events.iter().any(|e| e[0] == 1 && e[1] == 0x208));
        assert!(
            m.events
                .iter()
                .any(|e| e[..3] == [1, 0x522, 2] && e[3] == 0)
        );
        assert_eq!(m.get(0x3fc, 4) & (1 << 26), 1 << 26);
        assert_eq!(m.get(0x60f, 1), 4);
        assert_ne!(m.get(0x608, 4) & (1 << 28), 0);
    }
    for at in 1..=total {
        let (mut bus, report) = source_mac_setup(3);
        bus.model.lock().unwrap().fail = Some(at);
        assert!(
            unsafe { source_mac::initialize(&mut bus, &report) }.is_err(),
            "{at}"
        );
        assert!(bus.model.lock().unwrap().quarantined >= 1, "{at}");
    }
    for (r, w, v, at) in [(0xf0, 4, 0, total - 1), (0x80, 2, 0xffff, total)] {
        let (mut bus, report) = source_mac_setup(3);
        bus.model.lock().unwrap().mutate = Some((at, r, w, v));
        assert!(unsafe { source_mac::initialize(&mut bus, &report) }.is_err());
        assert!(bus.model.lock().unwrap().quarantined >= 1);
    }
    let (mut bus, report) = source_mac_setup(3);
    bus.panic_register = Some(0x1664);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            source_mac::initialize(&mut bus, &report)
        }))
        .is_err()
    );
    assert!(bus.model.lock().unwrap().quarantined >= 1);
}

#[test]
fn source_mac_rejects_unrecognized_cut_or_foreign_report_before_fifo_io() {
    let (mut bus, report) = source_mac_setup(7);
    assert!(matches!(
        unsafe { source_mac::initialize(&mut bus, &report) },
        Err(Error::UnsupportedCut(7))
    ));
    assert_eq!(bus.model.lock().unwrap().calls, 0);
    let (mut bus, _) = source_mac_setup(1);
    let (_, other) = source_mac_setup(2);
    assert!(matches!(
        unsafe { source_mac::initialize(&mut bus, &other) },
        Err(Error::WrongProfile)
    ));
    assert_eq!(bus.model.lock().unwrap().calls, 0);
}

#[test]
#[ignore = "requires unchanged whole MAC protocol/driver-info/PCI interface source oracle"]
fn source_mac_all_cut_register_patterns_widths_io_and_bar_match() {
    let path =
        std::path::PathBuf::from(std::env::var("STELA_REALTEK_WIFI_SOURCE_MAC_ORACLE").unwrap());
    assert_eq!(
        std::fs::read(path.parent().unwrap().join("data.rs")).unwrap(),
        include_bytes!("../source_mac/data.rs")
    );
    let trace = std::fs::read(path).unwrap();
    let mut offset = 0;
    let mut cases = 0;
    while offset < trace.len() {
        let h: [u32; 4] = core::array::from_fn(|i| {
            u32::from_le_bytes(
                trace[offset + i * 4..offset + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            )
        });
        offset += 16;
        let (mut bus, _, _) = setup(h[0] as u8, 0, 63, h[1] as usize, false, false);
        let mut a = Attempt {
            profile: bus.profile(),
            io: &mut bus,
            done: false,
        };
        let rx = source_mac::protocol(&mut a).unwrap();
        a.done = true;
        drop(a);
        assert_eq!(u32::from(rx), h[3]);
        let events = &trace[offset..offset + h[2] as usize * 16];
        offset += events.len();
        let bar = &trace[offset..offset + 0x5000];
        offset += bar.len();
        let m = bus.model.lock().unwrap();
        assert_eq!(source_events(&m.events), events, "MAC IO {cases}");
        assert!(
            m.bytes == bar,
            "MAC BAR {cases}: {:?}",
            m.bytes.iter().zip(bar).position(|(a, b)| a != b)
        );
        assert_eq!(m.quarantined, 0);
        cases += 1;
    }
    assert_eq!(cases, 896);
}
