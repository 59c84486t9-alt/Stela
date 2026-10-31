extern crate std;

use super::{fabric::*, *};
use crate::bus::thunderbolt::config::Space;
use crate::bus::thunderbolt::drom;

/// A host router with two USB4 ports and adapters for each.
fn host() -> Fabric {
    let fabric = Fabric::new();
    fabric.lock().connect(
        0,
        router(
            1,
            0,
            &[
                LANE, LANE, LANE, LANE, DP_IN, DP_IN, PCIE_DOWN, PCIE_DOWN, USB3_DOWN, USB3_DOWN,
            ],
        ),
    );
    fabric
}

/// A dock: upstream lanes 1 and 2, downstream lanes 3 and 4.
fn dock(version: u32) -> Model {
    router(
        version,
        1,
        &[
            LANE, LANE, LANE, LANE, DP_OUT, PCIE_UP, PCIE_DOWN, USB3_UP, USB3_DOWN,
        ],
    )
}

/// Poll until the clock has passed `milliseconds`, in 1 ms steps.
fn run(fabric: &Fabric, manager: &mut Manager, milliseconds: u64) {
    for _ in 0..milliseconds {
        for _ in 0..64 {
            assert!(manager.poll(), "stopped: {:?}", fabric.lock().reports);
        }
        fabric.lock().now += 1;
    }
}

fn routers_added(fabric: &Fabric) -> usize {
    fabric
        .lock()
        .reports
        .iter()
        .filter(|report| matches!(report, Report::RouterAdded { .. }))
        .count()
}

#[test]
fn route_arithmetic_matches_linux() {
    assert_eq!(depth(0), 0);
    assert_eq!(depth(0x1), 1);
    assert_eq!(depth(0x301), 2);
    assert_eq!(parent(0x301), 1);
    assert_eq!(parent(1), 0);
    assert_eq!(port_at(0x301, 0), 1);
    assert_eq!(port_at(0x301, 1), 3);
    assert_eq!(downstream(1, 3), 0x301);
    assert!(beneath(0x301, 1));
    assert!(beneath(1, 0));
    assert!(!beneath(0x302, 1));
    assert!(!beneath(1, 0x301));
}

#[test]
fn uuid_round_trips_its_canonical_form() {
    let uuid = Uuid::of([0x1122_3344, 0x5566_7788, !0, !0]);
    let text = alloc::format!("{uuid}");
    assert_eq!(text, "44332211-8877-6655-ffff-ffffffffffff");
    assert_eq!(Uuid::parse(&text), Some(uuid));
    assert_eq!(Uuid::parse("44332211-8877-6655-ffff-fffffffffff"), None);
    assert_eq!(Uuid::parse("443322118877-6655-ffff-ffffffffffffff"), None);
    assert_eq!(Uuid::parse("g4332211-8877-6655-ffff-ffffffffffff"), None);
}

#[test]
fn the_host_starts_with_ports_reset_and_time_running() {
    let fabric = host();
    let mut manager = fabric.manager();
    run(&fabric, &mut manager, 100);
    let state = fabric.lock();
    assert!(
        state.reports.contains(&Report::Ready),
        "{:?}",
        state.reports
    );
    let resets = state
        .writes
        .iter()
        .filter(|write| write.3 == USB4 + PORT_CS_19 && write.4 & PORT_CS_19_DPR != 0)
        .count();
    assert_eq!(resets, 2, "both USB4 ports, not their second lanes");
    // Enumerated, with a CM version and a 255 ms notification timeout.
    assert_eq!(state.routers[&0].header[3] >> 31, 1);
    assert_eq!(state.routers[&0].header[4] & 0xffff, CMUV_V1 << 8 | 0xff);
    assert_eq!(
        state.word(0, 0, Space::Router, 0x30 + TMU_RTR_CS_3) >> TMU_RTR_CS_3_INTERVAL_SHIFT,
        1000
    );
}

#[test]
fn a_dock_gets_every_tunnel_it_can_carry() {
    let fabric = host();
    fabric.lock().connect(1, dock(1));
    let mut manager = fabric.manager();
    run(&fabric, &mut manager, 200);
    assert_eq!(routers_added(&fabric), 1, "{:?}", fabric.lock().reports);
    assert!(
        fabric.lock().reports.iter().any(
            |report| matches!(report, Report::RouterAdded { width, .. } if *width == WIDTH_DUAL)
        )
    );
    assert_eq!(fabric.tunnels_up(Protocol::Usb3), 1);
    assert_eq!(fabric.tunnels_up(Protocol::Pcie), 1);
    let state = fabric.lock();
    // Router 1: configured, valid and bonded with its parent.
    let cs5 = state.word(1, 0, Space::Router, ROUTER_CS_5);
    assert_eq!(
        cs5 & (ROUTER_CS_5_PTO | ROUTER_CS_5_UTO),
        ROUTER_CS_5_PTO | ROUTER_CS_5_UTO
    );
    assert_ne!(cs5 & ROUTER_CS_5_CV, 0);
    assert_ne!(
        state.word(1, 1, Space::Port, USB4 + PORT_CS_19) & PORT_CS_19_PC,
        0
    );
    assert_ne!(
        state.word(0, 1, Space::Port, USB4 + PORT_CS_19) & PORT_CS_19_PC,
        0
    );
    assert_ne!(
        state.word(0, 1, Space::Port, PHY + LANE_ADP_CS_1) & LANE_ADP_CS_1_LB,
        0
    );
    // PCIe down adapter 7 goes to up adapter 6 through both routers.
    assert_ne!(state.word(0, 7, Space::Port, ADAPTER) & ADP_PCIE_CS_0_PE, 0);
    assert_ne!(state.word(1, 6, Space::Port, ADAPTER) & ADP_PCIE_CS_0_PE, 0);
    let first = state.word(0, 7, Space::Hops, 16);
    assert_eq!(first & HOP_ENABLE, HOP_ENABLE);
    assert_eq!((first >> 11) & 63, 1);
    let lane = state.word(1, 1, Space::Hops, 2 * (first as u16 & 0x7ff));
    assert_eq!(lane & 0x7ff, 8);
    assert_eq!((lane >> 11) & 63, 6);
    // Time runs bi-directional HiFi on the link.
    assert_eq!(
        state.word(1, 0, Space::Router, 0x30 + TMU_RTR_CS_3) >> TMU_RTR_CS_3_INTERVAL_SHIFT,
        16
    );
    // The USB3 adapter reserved bandwidth and finished its request.
    assert_eq!(
        state.word(0, 9, Space::Port, ADAPTER + ADP_USB3_CS_2) & ADP_USB3_CS_2_CMR,
        0
    );
    assert_ne!(
        state.word(0, 9, Space::Port, ADAPTER + ADP_USB3_CS_2) & ADP_USB3_CS_2_ADBW,
        0
    );
}

#[test]
fn a_device_behind_a_dock_tunnels_across_both_links() {
    let fabric = host();
    {
        let mut state = fabric.lock();
        state.connect(1, dock(1));
        state.connect(0x301, dock(1));
    }
    let mut manager = fabric.manager();
    run(&fabric, &mut manager, 200);
    assert_eq!(routers_added(&fabric), 2);
    assert_eq!(fabric.tunnels_up(Protocol::Pcie), 2);
    assert_eq!(fabric.tunnels_up(Protocol::Usb3), 2);
    let state = fabric.lock();
    // Each router's second tunnel takes its own HopID on the shared link: the
    // host's USB3 path ends at router 1; router 1's PCIe path leaves by lane 3.
    let first = state.word(1, 7, Space::Hops, 16);
    assert_eq!(first & HOP_ENABLE, HOP_ENABLE);
    assert_eq!((first >> 11) & 63, 3);
    assert_ne!(
        state.word(0x301, 6, Space::Port, ADAPTER) & ADP_PCIE_CS_0_PE,
        0
    );
}

#[test]
fn pcie_waits_for_admission_while_usb3_does_not() {
    let fabric = host();
    {
        let mut state = fabric.lock();
        state.admitted = false;
        state.connect(1, dock(1));
    }
    let mut manager = fabric.manager();
    run(&fabric, &mut manager, 200);
    assert_eq!(fabric.tunnels_up(Protocol::Usb3), 1);
    assert_eq!(fabric.tunnels_up(Protocol::Pcie), 0);
    let state = fabric.lock();
    assert!(state.reports.iter().any(|report| matches!(
        report,
        Report::Admission {
            admission: Admission::Refused,
            ..
        }
    )));
    assert_eq!(state.word(0, 7, Space::Port, ADAPTER) & ADP_PCIE_CS_0_PE, 0);
}

#[test]
fn a_refused_router_authorizes_nothing_behind_it() {
    let fabric = host();
    {
        let mut state = fabric.lock();
        state.admitted = false;
        state.connect(1, dock(1));
    }
    let mut manager = fabric.manager();
    run(&fabric, &mut manager, 200);
    {
        let mut state = fabric.lock();
        state.admitted = true;
        state.connect(0x301, dock(1));
        state.event(1, 3, false);
    }
    run(&fabric, &mut manager, 100);
    assert_eq!(routers_added(&fabric), 2);
    assert_eq!(fabric.tunnels_up(Protocol::Pcie), 0);
}

#[test]
fn displayport_pairs_a_host_input_with_a_hot_plugged_output() {
    let fabric = host();
    fabric.lock().connect(1, dock(1));
    let mut manager = fabric.manager();
    run(&fabric, &mut manager, 200);
    assert_eq!(fabric.tunnels_up(Protocol::DisplayPort), 0);
    {
        let mut state = fabric.lock();
        let dock = state.routers.get_mut(&1).unwrap();
        dock.words.insert(
            (5, Space::Port as u8, ADAPTER + DP_LOCAL_CAP),
            3 << 8 | 2 << 12,
        );
        let host = state.routers.get_mut(&0).unwrap();
        host.words.insert(
            (5, Space::Port as u8, ADAPTER + DP_LOCAL_CAP),
            3 << 8 | 2 << 12,
        );
        state.event(1, 5, false);
    }
    run(&fabric, &mut manager, 20);
    {
        let state = fabric.lock();
        assert_ne!(state.word(0, 5, Space::Port, ADAPTER) & ADP_DP_CS_0_VE, 0);
        assert_ne!(state.word(1, 5, Space::Port, ADAPTER) & ADP_DP_CS_0_VE, 0);
        // The video path's NFC credits are held on the lanes.
        assert_ne!(
            state.word(1, 1, Space::Port, ADP_CS_4) & ADP_CS_4_NFC_BUFFERS,
            0
        );
    }
    assert_eq!(
        fabric.tunnels_up(Protocol::DisplayPort),
        0,
        "DPRX is not done"
    );
    {
        let mut state = fabric.lock();
        let host = state.routers.get_mut(&0).unwrap();
        host.words.insert(
            (5, Space::Port as u8, ADAPTER + DP_COMMON_CAP),
            DP_COMMON_CAP_DPRX_DONE | 3 << 8 | 2 << 12,
        );
    }
    run(&fabric, &mut manager, 60);
    assert_eq!(fabric.tunnels_up(Protocol::DisplayPort), 1);
}

#[test]
fn a_dprx_that_never_finishes_gives_up_the_input() {
    let fabric = host();
    fabric.lock().connect(1, dock(1));
    let mut manager = fabric.manager();
    run(&fabric, &mut manager, 200);
    fabric.lock().event(1, 5, false);
    run(&fabric, &mut manager, 12_200);
    let state = fabric.lock();
    assert!(state.reports.iter().any(|report| matches!(
        report,
        Report::Failed {
            what: "DPRX negotiation",
            ..
        }
    )));
    assert!(state.reports.iter().any(|report| matches!(
        report,
        Report::TunnelDown {
            protocol: Protocol::DisplayPort,
            ..
        }
    )));
    assert_eq!(state.word(0, 5, Space::Port, ADAPTER) & ADP_DP_CS_0_VE, 0);
}

#[test]
fn unplugging_removes_the_subtree_and_frees_its_hops() {
    let fabric = host();
    {
        let mut state = fabric.lock();
        state.connect(1, dock(1));
        state.connect(0x301, dock(1));
    }
    let mut manager = fabric.manager();
    run(&fabric, &mut manager, 200);
    fabric.lock().disconnect(1);
    run(&fabric, &mut manager, 50);
    {
        let state = fabric.lock();
        let removed: Vec<u64> = state
            .reports
            .iter()
            .filter_map(|report| match report {
                Report::RouterRemoved { route } => Some(*route),
                _ => None,
            })
            .collect();
        assert_eq!(removed, [0x301, 1], "deepest first");
        assert_eq!(state.word(0, 7, Space::Port, ADAPTER) & ADP_PCIE_CS_0_PE, 0);
        assert_eq!(state.word(0, 9, Space::Port, ADAPTER) & ADP_USB3_CS_0_PE, 0);
        assert_eq!(state.word(0, 7, Space::Hops, 16) & HOP_ENABLE, 0);
        assert_eq!(
            state.word(0, 1, Space::Port, USB4 + PORT_CS_19) & PORT_CS_19_PC,
            0
        );
    }
    // The same HopIDs, adapters and link serve the next device.
    {
        let mut state = fabric.lock();
        state.connect(1, dock(1));
        state.event(0, 1, false);
    }
    run(&fabric, &mut manager, 100);
    assert_eq!(routers_added(&fabric), 3);
    assert_eq!(fabric.tunnels_up(Protocol::Pcie), 3);
}

#[test]
fn a_router_that_vanishes_mid_scan_leaves_the_domain_serving() {
    let fabric = host();
    let mut manager = fabric.manager();
    run(&fabric, &mut manager, 50);
    {
        let mut state = fabric.lock();
        state.connect(1, dock(1));
        state.silent = Some(1);
        state.event(0, 1, false);
    }
    run(&fabric, &mut manager, 100);
    assert_eq!(routers_added(&fabric), 0);
    {
        let mut state = fabric.lock();
        state.silent = None;
        state.event(0, 1, false);
    }
    run(&fabric, &mut manager, 100);
    assert_eq!(routers_added(&fabric), 1);
}

const TITAN_RIDGE: u16 = 0x15e7;
const ALPINE_RIDGE: u16 = 0x1578;

fn image(revision: u8) -> Vec<u8> {
    let mut bytes = alloc::vec![0; if revision == 1 { 22 } else { 16 }];
    bytes[1..9].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    bytes[13] = revision;
    bytes.extend_from_slice(&[7, 1, b'A', b'c', b'm', b'e', 0]);
    bytes.extend_from_slice(&[6, 2, b'D', b'o', b'c', 0]);
    // Lane 3 and 4 are not wired up.
    bytes.extend_from_slice(&[2, 0xc3, 2, 0xc4]);
    drom::seal(&mut bytes);
    bytes
}

fn thunderbolt_dock(device: u16) -> Model {
    legacy(
        device,
        1,
        &[LANE, LANE, LANE, LANE, DP_OUT, PCIE_UP, PCIE_DOWN],
    )
}

fn added(fabric: &Fabric, route: u64) -> Report {
    fabric
        .lock()
        .reports
        .iter()
        .find(
            |report| matches!(report, Report::RouterAdded { route: found, .. } if *found == route),
        )
        .unwrap_or_else(|| panic!("{:?}", fabric.lock().reports))
        .clone()
}

#[test]
fn a_usb4_router_is_named_by_its_drom() {
    let fabric = host();
    {
        let mut state = fabric.lock();
        let mut model = dock(1);
        model.drom = image(3);
        state.connect(1, model);
        state.connect(0x301, dock(1));
    }
    let mut manager = fabric.manager();
    run(&fabric, &mut manager, 200);
    let Report::RouterAdded { name, .. } = added(&fabric, 1) else {
        unreachable!();
    };
    assert_eq!(name.as_deref(), Some("Acme Doc"));
    assert_eq!(routers_added(&fabric), 1, "port 3 is disabled by the DROM");
}

#[test]
fn a_thunderbolt_3_dock_comes_up_through_its_link_controller() {
    let fabric = host();
    {
        let mut state = fabric.lock();
        let mut model = thunderbolt_dock(TITAN_RIDGE);
        model.drom = image(1);
        state.connect(1, model);
    }
    let mut manager = fabric.manager();
    run(&fabric, &mut manager, 200);
    let Report::RouterAdded {
        name,
        generation,
        version,
        uuid,
        width,
        ..
    } = added(&fabric, 1)
    else {
        unreachable!();
    };
    assert_eq!(name.as_deref(), Some("Acme Doc"));
    assert_eq!((generation, version, width), (3, 0, WIDTH_DUAL));
    assert_eq!(uuid, Uuid::of([0xa1a2, 0xb1b2, 0xc1c2, 0xd1d2]));
    assert_eq!(fabric.tunnels_up(Protocol::Pcie), 1);
    assert_eq!(fabric.tunnels_up(Protocol::Usb3), 0);
    let state = fabric.lock();
    let failed = state
        .reports
        .iter()
        .find(|report| matches!(report, Report::Failed { .. }));
    assert_eq!(failed, None);
    // Plug events are on, the USB one off, and the EEPROM given back.
    let events = state.word(1, 0, Space::Router, PLUG_EVENTS + 1);
    assert_eq!(events & PLUG_EVENTS_DISABLE, PLUG_EVENTS_USB_DISABLE);
    let control = state.word(1, 0, Space::Router, PLUG_EVENTS + EEPROM_CTL);
    assert_eq!(control & (EEPROM_ENABLE | EEPROM_CS), EEPROM_CS);
    // Its upstream lane is configured through the link controller, the
    // host's through USB4 registers.
    let lanes = state.word(1, 0, Space::Router, lane_controller(1) + LC_SX_CTRL);
    assert_eq!(lanes, LC_SX_CTRL_L1C | LC_SX_CTRL_UPSTREAM);
    assert_ne!(
        state.word(0, 1, Space::Port, USB4 + PORT_CS_19) & PORT_CS_19_PC,
        0
    );
    assert_eq!(state.routers[&1].header[4] & 0xff00, 0, "no CM version");
    // The xHCI is connected on both Type-C ports.
    for number in [1, 3] {
        let requests = state.word(1, 0, Space::Router, lane_controller(number) + LC_LINK_REQ);
        assert_eq!(requests, LC_LINK_REQ_XHCI_CONNECT);
    }
    // Time synchronization went through the vendor capability, without a
    // USB4 time post.
    assert_eq!(
        state.word(1, 0, Space::Router, 0x30 + TMU_RTR_CS_3) >> TMU_RTR_CS_3_INTERVAL_SHIFT,
        16
    );
    assert!(state.writes.iter().any(|write| {
        (write.0, write.3) == (1, 0x70 + TIME_VSEC_CS_26) && write.4 & TIME_VSEC_CS_26_TD != 0
    }));
    assert!(!state.writes.iter().any(|write| {
        write.0 == 1 && write.2 == Space::Router as u8 && write.3 == 0x30 + TMU_RTR_CS_24
    }));
}

#[test]
fn alpine_ridge_gets_its_xhci_only_where_usb_is_plugged() {
    let fabric = host();
    {
        let mut state = fabric.lock();
        let mut model = thunderbolt_dock(ALPINE_RIDGE);
        model.words.insert(
            (0, Space::Router as u8, lane_controller(3) + LC_CS_42),
            LC_CS_42_USB_PLUGGED,
        );
        state.connect(1, model);
    }
    let mut manager = fabric.manager();
    run(&fabric, &mut manager, 200);
    let state = fabric.lock();
    assert_eq!(
        state.word(1, 0, Space::Router, lane_controller(1) + LC_LINK_REQ),
        0
    );
    assert_eq!(
        state.word(1, 0, Space::Router, lane_controller(3) + LC_LINK_REQ),
        LC_LINK_REQ_XHCI_CONNECT
    );
    // Alpine Ridge keeps its USB plug events.
    assert_eq!(
        state.word(1, 0, Space::Router, PLUG_EVENTS + 1) & PLUG_EVENTS_DISABLE,
        0
    );
}

#[test]
fn a_chain_runs_through_a_thunderbolt_3_router() {
    let fabric = host();
    {
        let mut state = fabric.lock();
        state.connect(1, thunderbolt_dock(TITAN_RIDGE));
        state.connect(0x301, dock(1));
    }
    let mut manager = fabric.manager();
    run(&fabric, &mut manager, 200);
    assert_eq!(routers_added(&fabric), 2, "{:?}", fabric.lock().reports);
    assert_eq!(fabric.tunnels_up(Protocol::Pcie), 2);
    assert_eq!(
        fabric.tunnels_up(Protocol::Usb3),
        0,
        "no USB3 through Thunderbolt 3"
    );
    let state = fabric.lock();
    // The legacy parent has no USB4 ports to map, and takes any free adapter.
    assert_ne!(state.word(1, 7, Space::Port, ADAPTER) & ADP_PCIE_CS_0_PE, 0);
    // A protocol adapter's credits are the CM's to set before USB4.
    assert_eq!(
        (state.word(1, 7, Space::Hops, 16) >> HOP_INITIAL_CREDITS_SHIFT) & 0x7f,
        7
    );
}

#[test]
fn a_router_without_plug_events_is_reported_once_and_left_alone() {
    let fabric = host();
    {
        let mut state = fabric.lock();
        let mut model = thunderbolt_dock(TITAN_RIDGE);
        let header = 0x30;
        let word = u32::from(CAP_TIME) << 8;
        model.words.insert((0, Space::Router as u8, header), word);
        state.connect(1, model);
    }
    let mut manager = fabric.manager();
    run(&fabric, &mut manager, 100);
    fabric.lock().event(0, 1, false);
    run(&fabric, &mut manager, 100);
    let state = fabric.lock();
    let reports = state
        .reports
        .iter()
        .filter(|report| matches!(report, Report::Unsupported { .. }))
        .count();
    assert_eq!(reports, 1, "{:?}", state.reports);
    assert_eq!(state.routers[&1].header[3] >> 31, 0, "not enumerated");
}

#[test]
fn idle_says_when_the_domain_has_nothing_going_on() {
    let fabric = host();
    let mut manager = fabric.manager();
    assert!(!manager.idle());
    // The ports' resets take the clock some time.
    manager.poll();
    assert!(!manager.idle());
    run(&fabric, &mut manager, 50);
    assert!(manager.idle());
}

#[test]
fn usb4_v2_links_keep_time_in_enhanced_mode() {
    let fabric = Fabric::new();
    {
        let mut state = fabric.lock();
        state.connect(0, router(2, 0, &[LANE, LANE, PCIE_DOWN, USB3_DOWN]));
        state.connect(1, dock(2));
    }
    let mut manager = fabric.manager();
    run(&fabric, &mut manager, 100);
    let state = fabric.lock();
    assert_ne!(
        state.word(1, 1, Space::Port, TIME + TMU_ADP_CS_8) & TMU_ADP_CS_8_EUDM,
        0
    );
    assert_ne!(
        state.word(0, 1, Space::Port, TIME + TMU_ADP_CS_8) & TMU_ADP_CS_8_EUDM,
        0
    );
    assert_eq!(state.routers[&1].header[4] & 0xff00, CMUV_V2 << 8);
}
