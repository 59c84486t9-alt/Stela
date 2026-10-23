extern crate std;
use super::{model::*, *};
use crate::bus::dma::RegionAllocator;
use alloc::collections::BTreeMap;

fn controller(
    dma: &mut dyn DmaAllocator,
    context: usize,
    nodes: BTreeMap<u32, Node>,
) -> (Controller, Rc<RefCell<Hardware>>) {
    let model = Rc::new(RefCell::new(Hardware::new(context, nodes)));
    let controller = Controller::new(
        Box::new(RegistersModel(model.clone())),
        Clock {
            ticks_per_microsecond: 1,
        },
        dma,
        "hub model".into(),
    )
    .unwrap();
    (controller, model)
}
fn nodes() -> BTreeMap<u32, Node> {
    BTreeMap::from([(0, Node::hub(SUPER_SPEED, 1)), (1, Node::leaf(SUPER_SPEED))])
}
fn bos() -> Vec<u8> {
    let mut bytes = vec![5, 15, 25, 0, 1, 20, 16, 10, 0, 1, 0, 0, 0, 1, 0, 0, 0];
    for ty in [0u32, 2] {
        bytes.extend_from_slice(&(1 | 3 << 4 | ty << 6 | 1 << 14 | 10 << 16).to_le_bytes());
    }
    bytes
}
fn fault_node(fault: Fault) -> Node {
    let mut node = Node::hub(SUPER_SPEED, 1);
    let port = &mut node.ports.as_mut().unwrap()[0];
    port.fault = fault;
    match fault {
        Fault::Suspended => port.status |= 3 << 5,
        Fault::Inactive => port.status |= 6 << 5,
        Fault::WarmForever => port.status |= 10 << 5,
        Fault::UnknownSpeed => {
            node.bos = Some(bos());
            node.speed = SUPER_SPEED_PLUS;
            node.ports.as_mut().unwrap()[0].extended = 0x22;
        }
        _ => {}
    }
    node
}

#[test]
fn superspeed_cold_hub_uses_actual_contexts_depth_power_routes_and_bulk_io() {
    for context in [32, 64] {
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: exclusive live backing remains retained through all DMA.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, context, nodes());
        let mut failures = Vec::new();
        let devices = controller.enumerate(&mut dma, &mut failures);
        assert!(failures.is_empty(), "{failures:?}");
        assert_eq!(devices.len(), 2);
        let child = devices
            .iter()
            .find(|d| d.descriptor[4] != HUB_CLASS)
            .unwrap();
        assert_eq!(child.speed, SUPER_SPEED);
        assert_eq!(child.location, "hub model port 1.1");
        let actual = controller.slots[usize::from(child.slot)].as_ref().unwrap();
        assert_eq!(actual.attachment.route, 1);
        assert_eq!(actual.attachment.translator, None);
        assert!(!actual.retiring);
        let endpoints = interfaces(&child.configuration)[0].endpoints.clone();
        controller.set_configuration(child.slot, 1).unwrap();
        controller
            .configure(child.slot, &endpoints, None, &mut dma)
            .unwrap();
        let mut payload = dma.allocate(64, 64).unwrap();
        payload.bytes_mut().fill(0xee);
        assert_eq!(
            controller.transfer(child.slot, 3, payload.physical(), 64, 1000),
            Ok(64)
        );
        assert_eq!(payload.bytes(), &[child.slot; 64]);
        assert_eq!(
            controller.transfer(child.slot, 4, payload.physical(), 64, 1000),
            Ok(64)
        );
        assert_eq!(model.borrow().outgoing, [vec![child.slot; 64]]);
        let state = model.borrow();
        let hub = state
            .contexts
            .iter()
            .find(|(slot, kind, _)| *slot == 1 && *kind == CONFIGURE_ENDPOINT)
            .unwrap()
            .2;
        assert_ne!(hub[0] & 1 << 26, 0);
        assert_eq!(hub[0] & 1 << 25, 0);
        assert_eq!(hub[1] >> 24, 1);
        assert_eq!(hub[2], 0);
        let requests = &state.requests;
        let config = requests
            .iter()
            .position(|(_, _, q)| q[1] == SET_CONFIGURATION)
            .unwrap();
        let depth = requests
            .iter()
            .position(|(_, _, q)| q[0] == 0x20 && q[1] == 12)
            .unwrap();
        let power = requests
            .iter()
            .position(|(_, _, q)| q[0] == 0x23 && q[1] == SET_FEATURE && q[2] == 8)
            .unwrap();
        let reset = requests
            .iter()
            .position(|(_, _, q)| q[0] == 0x23 && q[1] == SET_FEATURE && q[2] == 4)
            .unwrap();
        assert!(config < depth && depth < power && power < reset);
        assert!(
            requests
                .iter()
                .any(|(_, _, q)| q[0] == 0xa0 && q[2..4] == [0, 0x2a] && q[6] == 12)
        );
        assert!(requests.iter().all(|(_, _, q)| !(q[0] == 0x23
            && q[1] == CLEAR_FEATURE
            && [17, 18, 23].contains(&q[2]))));
    }
}

#[test]
fn nested_superspeed_hubs_preserve_five_route_nibbles_and_no_usb2_tt() {
    let mut nodes = BTreeMap::new();
    for tier in 0..5 {
        nodes.insert(
            (0..tier).fold(0, |r, t| r | 15 << (4 * t)),
            Node::hub(SUPER_SPEED, 15),
        );
    }
    nodes.insert(0xfffff, Node::leaf(SUPER_SPEED));
    for node in nodes.values_mut().filter(|node| node.ports.is_some()) {
        for port in &mut node.ports.as_mut().unwrap()[..14] {
            port.status = 0;
            port.change = 0;
        }
    }
    let mut backing = vec![0u64; 512 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: exclusive backing retains every ancestor/child context and TD.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut controller, model) = controller(&mut dma, 64, nodes);
    let mut failures = Vec::new();
    let devices = controller.enumerate(&mut dma, &mut failures);
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(devices.len(), 6);
    let leaf = devices
        .iter()
        .find(|d| d.descriptor[4] != HUB_CLASS)
        .unwrap();
    assert_eq!(
        controller.slots[usize::from(leaf.slot)]
            .as_ref()
            .unwrap()
            .attachment
            .route,
        0xfffff
    );
    let state = model.borrow();
    for tier in 0..5 {
        let route = (0..tier).fold(0, |r, t| r | 15 << (4 * t));
        assert_eq!(state.nodes[&route].depth, Some(tier));
    }
    assert!(state.contexts.iter().all(|(_, _, ctx)| ctx[2] == 0));
}

#[test]
fn superspeedplus_uses_actual_bos_speed_ids_and_extended_status() {
    for lanes in [1, 2] {
        let mut nodes = nodes();
        let root = nodes.get_mut(&0).unwrap();
        root.speed = SUPER_SPEED_PLUS;
        root.bos = Some(bos());
        root.ports.as_mut().unwrap()[0].extended = 0x11 | (lanes - 1) << 8 | (lanes - 1) << 12;
        nodes.get_mut(&1).unwrap().speed = SUPER_SPEED_PLUS;
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: all native model DMA remains live and exclusively owned.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, 32, nodes);
        let mut failures = Vec::new();
        let devices = controller.enumerate(&mut dma, &mut failures);
        assert!(failures.is_empty(), "{failures:?}");
        assert_eq!(devices.len(), 2);
        let child = devices
            .iter()
            .find(|d| d.descriptor[4] != HUB_CLASS)
            .unwrap();
        assert_eq!(child.speed, SUPER_SPEED_PLUS);
        assert!(
            model
                .borrow()
                .requests
                .iter()
                .any(|(_, _, q)| q[0] == 0xa3 && q[2] == 2 && q[6] == 8)
        );
    }
}

#[test]
fn asymmetric_or_unknown_actual_ssp_port_status_never_inherits_upstream_speed() {
    for extended in [0x21, 0x111, 0x10011] {
        let mut nodes = nodes();
        let root = nodes.get_mut(&0).unwrap();
        root.speed = SUPER_SPEED_PLUS;
        root.bos = Some(bos());
        root.ports.as_mut().unwrap()[0].extended = extended;
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: rejected child links cannot release or reuse retained DMA.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, 32, nodes);
        let mut failures = Vec::new();
        let devices = controller.enumerate(&mut dma, &mut failures);
        assert_eq!(devices.len(), 1);
        assert_eq!(failures.len(), 1);
        assert!(
            model
                .borrow()
                .requests
                .iter()
                .any(|(_, _, q)| q[0] == 0xa3 && q[2] == 2 && q[6] == 8)
        );
        assert_eq!(
            model
                .borrow()
                .commands
                .iter()
                .filter(|(k, _)| *k == ENABLE_SLOT)
                .count(),
            1
        );
    }
}

#[test]
fn actual_hub_power_and_overcurrent_health_gate_all_downstream_admission() {
    for (self_powered, status, change, after) in [
        (false, 0, 0, None),
        (true, 1, 0, None),
        (true, 2, 0, None),
        (true, 4, 0, None),
        (true, 0, 2, None),
        (true, 0, 4, None),
        (true, 0, 0, Some(2)),
        (true, 0, 0, Some(1)),
    ] {
        let mut nodes = nodes();
        let root = nodes.get_mut(&0).unwrap();
        root.self_powered = self_powered;
        root.hub_status = status;
        root.hub_change = change;
        root.after_power_status = after;
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: failed power admission retains every controller/hub allocation.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, 32, nodes);
        let mut failures = Vec::new();
        let devices = controller.enumerate(&mut dma, &mut failures);
        assert_eq!(devices.len(), 1);
        assert_eq!(failures.len(), 1);
        assert_eq!(
            model
                .borrow()
                .commands
                .iter()
                .filter(|(kind, _)| *kind == ENABLE_SLOT)
                .count(),
            1
        );
        assert!(
            !model
                .borrow()
                .requests
                .iter()
                .any(|(_, _, q)| q[0] == 0x23 && q[1] == SET_FEATURE && q[2] == 4)
        );
    }
}

#[test]
fn historical_local_power_change_is_acknowledged_and_health_rechecked() {
    let mut nodes = nodes();
    nodes.get_mut(&0).unwrap().hub_change = 1;
    let mut backing = vec![0u64; 256 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: all hub and child DMA is retained by the fixture's actual owners.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut controller, model) = controller(&mut dma, 32, nodes);
    let mut failures = Vec::new();
    let devices = controller.enumerate(&mut dma, &mut failures);
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(devices.len(), 2);
    assert!(
        model
            .borrow()
            .requests
            .iter()
            .any(|(_, _, q)| q[0] == 0x20 && q[1] == CLEAR_FEATURE && q[2..6] == [0; 4])
    );
}

#[test]
fn port_admission_refuses_power_lifecycle_reset_and_status_failures() {
    for fault in [
        Fault::Power,
        Fault::PowerAbsent,
        Fault::Reset,
        Fault::ResetForever,
        Fault::NoEnable,
        Fault::Suspended,
        Fault::UnknownSpeed,
        Fault::WarmForever,
        Fault::ShortStatus,
        Fault::ClearChange,
        Fault::LinkNotU0,
        Fault::ConfigError,
        Fault::OverCurrentChange,
    ] {
        let mut nodes = nodes();
        nodes.insert(0, fault_node(fault));
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: allocations remain retained even after uncertain operations.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, 32, nodes);
        let mut failures = Vec::new();
        let devices = controller.enumerate(&mut dma, &mut failures);
        assert_eq!(devices.len(), 1, "{fault:?}: {failures:?}");
        assert_eq!(failures.len(), 1, "{fault:?}");
        assert_eq!(
            model
                .borrow()
                .commands
                .iter()
                .filter(|(kind, _)| *kind == ENABLE_SLOT)
                .count(),
            1,
            "{fault:?}"
        );
        if fault == Fault::NoEnable {
            assert_eq!(
                model.borrow().nodes[&0].ports.as_ref().unwrap()[0].reset_count,
                5
            );
        }
        let hub = controller.slots[1].as_ref().unwrap();
        assert!(hub.endpoints[1].is_some());
        assert_eq!(controller.slot_ownership[1], reset::Ownership::Enabled);
    }
}

#[test]
fn inactive_and_failed_hot_reset_require_real_bounded_warm_reset() {
    for fault in [Fault::Inactive, Fault::HotThenWarm] {
        let mut nodes = nodes();
        nodes.insert(0, fault_node(fault));
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: fixture retains complete DMA ownership through every reset.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, 32, nodes);
        let mut failures = Vec::new();
        let devices = controller.enumerate(&mut dma, &mut failures);
        assert!(failures.is_empty(), "{fault:?}: {failures:?}");
        assert_eq!(devices.len(), 2);
        let state = model.borrow();
        assert!(
            state
                .requests
                .iter()
                .any(|(_, _, q)| q[0] == 0x23 && q[1] == SET_FEATURE && q[2] == 28)
        );
        assert!(
            state
                .requests
                .iter()
                .any(|(_, _, q)| q[0] == 0x23 && q[1] == CLEAR_FEATURE && q[2] == 29)
        );
    }
}

#[test]
fn disconnect_during_reset_does_not_publish_a_child_or_recycle_hub_owners() {
    let mut nodes = nodes();
    nodes.insert(0, fault_node(Fault::Disconnect));
    let mut backing = vec![0u64; 256 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: the disconnected hub's original DMA remains retained.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut controller, model) = controller(&mut dma, 32, nodes);
    let mut failures = Vec::new();
    let devices = controller.enumerate(&mut dma, &mut failures);
    assert!(failures.is_empty());
    assert_eq!(devices.len(), 1);
    assert_eq!(
        model
            .borrow()
            .commands
            .iter()
            .filter(|(k, _)| *k == ENABLE_SLOT)
            .count(),
        1
    );
    assert!(
        controller.slots[1].as_ref().unwrap().endpoints[3]
            .as_ref()
            .unwrap()
            .enabled
    );
}

#[test]
fn failed_or_uncertain_hub_configuration_never_sends_depth_or_power() {
    for silent in [false, true] {
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: all rings/contexts remain retained after failed Configure.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, 32, nodes());
        if silent {
            model.borrow_mut().silent = Some((CONFIGURE_ENDPOINT, 1));
        } else {
            model.borrow_mut().fail = Some((CONFIGURE_ENDPOINT, 1));
        }
        let mut failures = Vec::new();
        let devices = controller.enumerate(&mut dma, &mut failures);
        assert_eq!(devices.len(), 1);
        assert_eq!(failures.len(), 1);
        assert!(
            !model
                .borrow()
                .requests
                .iter()
                .any(|(_, _, q)| q[0] == 0x20 || q[0] == 0x23)
        );
        let endpoint = controller.slots[1].as_ref().unwrap().endpoints[3]
            .as_ref()
            .unwrap();
        assert!(!endpoint.enabled && endpoint.poisoned);
        assert_eq!(controller.command_poisoned, silent);
    }
}

#[test]
fn usb2_hub_refactor_preserves_full_speed_child_transaction_translator() {
    let mut nodes = BTreeMap::from([(0, Node::hub(HIGH_SPEED, 1)), (1, Node::leaf(FULL_SPEED))]);
    nodes.get_mut(&0).unwrap().ports.as_mut().unwrap()[0].child_speed = FULL_SPEED;
    let mut backing = vec![0u64; 256 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: complete USB2 parent/child contexts remain live and exclusive.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut controller, model) = controller(&mut dma, 32, nodes);
    let mut failures = Vec::new();
    let devices = controller.enumerate(&mut dma, &mut failures);
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(devices.len(), 2);
    let child = devices
        .iter()
        .find(|d| d.descriptor[4] != HUB_CLASS)
        .unwrap();
    assert_eq!(
        controller.slots[usize::from(child.slot)]
            .as_ref()
            .unwrap()
            .attachment
            .translator,
        Some((1, 1))
    );
    let state = model.borrow();
    let hub = state
        .contexts
        .iter()
        .find(|(s, k, _)| *s == 1 && *k == CONFIGURE_ENDPOINT)
        .unwrap()
        .2;
    assert_eq!(hub[2] >> 16 & 3, 3);
    let child = state
        .contexts
        .iter()
        .find(|(s, k, _)| *s == 2 && *k == ADDRESS_DEVICE)
        .unwrap()
        .2;
    assert_eq!(child[0] & 0xfffff, 1);
    assert_eq!(child[2], 1 | 1 << 8);
}

#[test]
fn malformed_hub_descriptors_and_bos_never_reach_configuration_or_child_allocation() {
    let valid = Node::hub(SUPER_SPEED, 1)
        .descriptor
        .unwrap_or_else(|| vec![12, 0x2a, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
    let mut variants = Vec::new();
    for (at, value) in [
        (0, 11),
        (1, 0x29),
        (2, 0),
        (2, 16),
        (3, 3),
        (3, 0x18),
        (3, 0x20),
    ] {
        let mut bytes = valid.clone();
        bytes[at] = value;
        variants.push((Some(bytes), None));
    }
    let mut short = valid.clone();
    short.pop();
    variants.push((Some(short), None));
    for (at, value) in [
        (0, 4),
        (2, 24),
        (4, 2),
        (5, 19),
        (6, 15),
        (8, 1),
        (9, 2),
        (16, 0x41),
        (17, 0x71),
    ] {
        let mut bytes = bos();
        bytes[at] = value;
        variants.push((None, Some(bytes)));
    }
    for (descriptor, bos) in variants {
        let mut nodes = nodes();
        let root = nodes.get_mut(&0).unwrap();
        root.descriptor = descriptor;
        root.bos = bos;
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: even malformed wire inputs only access retained fixture DMA.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, 32, nodes);
        let mut failures = Vec::new();
        let devices = controller.enumerate(&mut dma, &mut failures);
        assert_eq!(devices.len(), 1);
        assert_eq!(
            failures.len(),
            1,
            "wire case {:?}",
            model.borrow().nodes[&0].bos
        );
        assert!(
            !model
                .borrow()
                .requests
                .iter()
                .any(|(_, _, q)| q[1] == SET_CONFIGURATION)
        );
        assert!(controller.slots[1].as_ref().unwrap().endpoints[3].is_none());
    }
}

#[test]
fn failed_later_port_preserves_prior_child_dma_and_does_not_authorize_behind_hub_reset() {
    let mut nodes = nodes();
    nodes
        .get_mut(&0)
        .unwrap()
        .ports
        .as_mut()
        .unwrap()
        .push(PortModel::connected());
    nodes.get_mut(&0).unwrap().ports.as_mut().unwrap()[1].fault = Fault::Reset;
    let mut backing = vec![0u64; 256 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: the already admitted child and failed port's hub retain owners.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut controller, model) = controller(&mut dma, 32, nodes);
    let mut failures = Vec::new();
    let devices = controller.enumerate(&mut dma, &mut failures);
    assert_eq!(devices.len(), 2);
    assert_eq!(failures.len(), 1);
    let child = devices
        .iter()
        .find(|d| d.descriptor[4] != HUB_CLASS)
        .unwrap();
    let endpoints = interfaces(&child.configuration)[0].endpoints.clone();
    controller.set_configuration(child.slot, 1).unwrap();
    controller
        .configure(child.slot, &endpoints, None, &mut dma)
        .unwrap();
    let payload = dma.allocate(64, 64).unwrap();
    assert_eq!(
        controller.transfer(child.slot, 3, payload.physical(), 64, 1000),
        Ok(64)
    );
    let commands = model.borrow().commands.len();
    // SAFETY: this test owns the class endpoint set. The real service must
    // nevertheless refuse resetting an unsupported non-root topology.
    assert!(unsafe { controller.reset_and_identify(child, &endpoints, &mut dma) }.is_err());
    assert_eq!(model.borrow().commands.len(), commands);
    assert!(controller.live_slot(child.slot).is_ok());
}

#[test]
fn invalid_route_and_retired_or_foreign_hub_owner_refuse_before_transport_effects() {
    use descriptor::{child, topology};
    let root = Attachment {
        root_port: 1,
        route: 0,
        tier: 0,
        speed: SUPER_SPEED,
        translator: None,
    };
    assert!(topology(root).is_ok());
    for invalid in [
        Attachment { route: 1, ..root },
        Attachment { tier: 5, ..root },
        Attachment { tier: 1, ..root },
        Attachment {
            translator: Some((1, 1)),
            ..root
        },
    ] {
        assert!(topology(invalid).is_err());
    }
    assert!(child(root, 0, SUPER_SPEED).is_err());
    assert!(child(root, 16, SUPER_SPEED).is_err());
    assert!(child(root, 1, HIGH_SPEED).is_err());
    let mut backing = vec![0u64; 256 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: all addressed but unconfigured state remains retained.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut controller, model) = controller(&mut dma, 32, nodes());
    let mut device = controller
        .identify(root, "hub model port 1".into(), &mut dma)
        .unwrap();
    configuration::select_with_controller(&mut device, Some(&controller)).unwrap();
    let before = model.borrow().requests.len();
    let mut devices = Vec::new();
    let mut failures = Vec::new();
    assert!(
        controller
            .hub(
                &device,
                Attachment { route: 1, ..root },
                &mut dma,
                &mut devices,
                &mut failures
            )
            .is_err()
    );
    controller.quarantine_slot(device.slot);
    assert!(
        controller
            .hub(&device, root, &mut dma, &mut devices, &mut failures)
            .is_err()
    );
    assert_eq!(model.borrow().requests.len(), before);
}

#[test]
#[ignore = "requires pinned unchanged-source SuperSpeed hub oracle"]
fn unchanged_linux_hub_requests_power_warm_reset_and_sublink_rates() {
    use descriptor::{Descriptor, Ssp};
    use sha2::{Digest, Sha256};
    use superspeed::{Port, depth_request, status_request};
    let raw =
        std::fs::read(std::env::var("STELA_XHCI_HUB_ORACLE").expect("set STELA_XHCI_HUB_ORACLE"))
            .unwrap();
    assert_eq!(raw.len(), 5400);
    assert_eq!(
        format!("{:x}", Sha256::digest(&raw)),
        "6c311188681264c2f7decb6072e1802fc18635f23bdd29afc7f970b28d4281dd"
    );
    let node = Node::hub(SUPER_SPEED, 1);
    let config = node.configuration();
    let endpoint = interfaces(&config)[0].endpoints[0];
    let mut counts = [0usize; 6];
    for line in core::str::from_utf8(&raw).unwrap().lines() {
        let mut fields = line.split_whitespace();
        let tag = fields.next().unwrap();
        let n: Vec<u32> = fields.map(|f| f.parse().unwrap()).collect();
        match tag {
            "D" => {
                let desc = [12, 0x2a, 1, 1, 0, n[0] as u8, 0, 0, 0, 0, 0, 0];
                assert_eq!(
                    Descriptor::new(&desc, &endpoint).unwrap().power_good_us,
                    u64::from(n[1]) * 1000
                );
                counts[0] += 1;
            }
            "W" => {
                let status = 0x203u16 | (n[0] as u16) << 5;
                let bytes = [status as u8, (status >> 8) as u8, 0, 0];
                assert_eq!(Port::decode(&bytes, false).unwrap().warm(), n[1] != 0);
                counts[1] += 1;
            }
            "G" | "P" | "H" => {
                let expected = setup(
                    n[0] as u8,
                    n[1] as u8,
                    n[2] as u16,
                    n[3] as u16,
                    n[4] as u16,
                );
                match tag {
                    "G" => {
                        assert_eq!(expected, setup(0xa0, GET_DESCRIPTOR, 0x2a00, 0, 12));
                        counts[2] += 1;
                    }
                    "P" => {
                        assert_eq!(expected, status_request(n[3] as u8, n[2] == 2));
                        counts[3] += 1;
                    }
                    _ => {
                        assert_eq!(expected, depth_request(n[2] as u8));
                        counts[4] += 1;
                    }
                }
            }
            "S" => {
                let mut capability = bos();
                for (at, ty) in [(17usize, n[3]), (21, n[3] + 2)] {
                    let attr = 1 | n[1] << 4 | ty << 6 | 1 << 14 | n[0] << 16;
                    capability[at..at + 4].copy_from_slice(&attr.to_le_bytes());
                }
                let status = 0x11 | (n[2] - 1) << 8 | (n[2] - 1) << 12;
                let qualified = Ssp::bos(&capability)
                    .ok()
                    .flatten()
                    .and_then(|s| s.speed(status).ok());
                assert_eq!(qualified == Some(SUPER_SPEED_PLUS), n[4] != 0, "{line}");
                counts[5] += 1;
            }
            _ => panic!("unexpected donor row {tag}"),
        }
    }
    assert_eq!(counts, [256, 11, 1, 4, 5, 216]);
}

#[test]
fn superspeed_port_connection_is_debounced_before_any_reset_or_child_publication() {
    let mut nodes = nodes();
    let port = &mut nodes.get_mut(&0).unwrap().ports.as_mut().unwrap()[0];
    port.connection_samples = [
        (true, true),
        (false, true),
        (true, true),
        (true, false),
        (true, false),
        (true, false),
        (true, false),
    ]
    .into();
    let mut backing = vec![0u64; 256 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: exclusive fixture RAM remains live until all controller owners drop.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut controller, model) = controller(&mut dma, 64, nodes);
    let mut failures = Vec::new();
    let devices = controller.enumerate(&mut dma, &mut failures);
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(devices.len(), 2);
    let state = model.borrow();
    let reset = state
        .requests
        .iter()
        .position(|(_, _, q)| q[0] == 0x23 && q[1] == SET_FEATURE && q[2] == PORT_RESET as u8)
        .unwrap();
    assert!(
        state.requests[..reset]
            .iter()
            .filter(|(_, _, q)| q[0] == 0xa3 && q[1] == GET_STATUS)
            .count()
            >= 7
    );
}

#[test]
fn superspeed_unsettled_connection_or_repeated_csc_never_resets_or_addresses_child() {
    for toggles in [false, true] {
        let mut nodes = nodes();
        let port = &mut nodes.get_mut(&0).unwrap().ports.as_mut().unwrap()[0];
        port.connection_samples = (0..200).map(|i| (!toggles || i % 2 == 0, true)).collect();
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: exclusive fixture RAM remains live until all controller owners drop.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, 32, nodes);
        let mut failures = Vec::new();
        let devices = controller.enumerate(&mut dma, &mut failures);
        assert_eq!(devices.len(), 1);
        assert_eq!(failures.len(), 1);
        let state = model.borrow();
        assert_eq!(
            state
                .commands
                .iter()
                .filter(|(kind, _)| *kind == ADDRESS_DEVICE)
                .count(),
            1
        );
        assert!(
            !state
                .requests
                .iter()
                .any(|(_, _, q)| q[0] == 0x23 && q[1] == SET_FEATURE && [4, 28].contains(&q[2]))
        );
    }
}

#[test]
fn superspeed_reset_waits_for_reconnection_and_ignores_reset_connection_change() {
    for fault in [
        Fault::ResetConnectionBounce,
        Fault::ConnectionChange,
        Fault::NoResetChange,
    ] {
        let mut nodes = nodes();
        nodes.insert(0, fault_node(fault));
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: fixture RAM and all contexts remain retained through completion.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, 64, nodes);
        let mut failures = Vec::new();
        let devices = controller.enumerate(&mut dma, &mut failures);
        assert!(failures.is_empty(), "{fault:?}: {failures:?}");
        assert_eq!(devices.len(), 2, "{fault:?}");
        let state = model.borrow();
        let resets: Vec<_> = state
            .requests
            .iter()
            .filter(|(_, _, q)| q[0] == 0x23 && q[1] == SET_FEATURE && q[2] == PORT_RESET as u8)
            .collect();
        assert_eq!(resets.len(), 1);
        assert_eq!(state.nodes[&0].ports.as_ref().unwrap()[0].change, 0);
    }
}

#[test]
fn observed_hub_power_loss_quarantines_all_previous_children_without_releasing_dma() {
    let nodes = BTreeMap::from([
        (0, Node::hub(SUPER_SPEED, 2)),
        (1, Node::leaf(SUPER_SPEED)),
        (2, Node::leaf(SUPER_SPEED)),
    ]);
    let mut backing = vec![0u64; 256 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: all fixture DMA owners remain retained until the controller drops.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (mut controller, model) = controller(&mut dma, 64, nodes);
    model.borrow_mut().loss_after_child_route = Some(1);
    let mut failures = Vec::new();
    let devices = controller.enumerate(&mut dma, &mut failures);
    assert_eq!(devices.len(), 2);
    assert_eq!(failures.len(), 1);
    assert!(controller.slots[1].as_ref().unwrap().retiring);
    assert!(controller.slots[2].as_ref().unwrap().retiring);
    let pointers: Vec<_> = controller
        .slots
        .iter()
        .flatten()
        .map(|state| (state.input.physical(), state._output.physical()))
        .collect();
    let before = (
        model.borrow().requests.len(),
        model.borrow().commands.len(),
        model.borrow().mmio_reads,
        model.borrow().mmio_writes,
    );
    let memory = backing.clone();
    // Restoring observed power cannot revive either retained old handle.
    model.borrow_mut().nodes.get_mut(&0).unwrap().hub_status = 0;
    for device in &devices {
        assert!(controller.endpoint_ready(device.slot, 3).is_err());
        assert!(controller.submit(device.slot, 3, 0, 1).is_err());
        assert!(
            controller
                .control(device.slot, setup(0x80, GET_STATUS, 0, 0, 2), &[])
                .is_err()
        );
    }
    assert_eq!(
        (
            model.borrow().requests.len(),
            model.borrow().commands.len(),
            model.borrow().mmio_reads,
            model.borrow().mmio_writes
        ),
        before
    );
    assert_eq!(backing, memory);
    assert_eq!(
        controller
            .slots
            .iter()
            .flatten()
            .map(|state| (state.input.physical(), state._output.physical()))
            .collect::<Vec<_>>(),
        pointers
    );
}

#[test]
fn superspeed_retries_ordinary_disabled_or_not_ready_hot_resets() {
    for fault in [Fault::FirstResetDisabled, Fault::FirstResetNotU0] {
        let mut nodes = nodes();
        nodes.insert(0, fault_node(fault));
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: fixture RAM remains exclusively owned through all reset attempts.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (mut controller, model) = controller(&mut dma, 32, nodes);
        let mut failures = Vec::new();
        let devices = controller.enumerate(&mut dma, &mut failures);
        assert!(failures.is_empty(), "{fault:?}: {failures:?}");
        assert_eq!(devices.len(), 2);
        let state = model.borrow();
        assert_eq!(state.nodes[&0].ports.as_ref().unwrap()[0].reset_count, 2);
        assert_eq!(
            state
                .requests
                .iter()
                .filter(|(_, _, q)| q[0] == 0x23 && q[1] == SET_FEATURE && q[2] == PORT_RESET as u8)
                .count(),
            2
        );
        assert!(
            !state
                .requests
                .iter()
                .any(|(_, _, q)| q[0] == 0x23 && q[1] == SET_FEATURE && q[2] == 28)
        );
    }
}
