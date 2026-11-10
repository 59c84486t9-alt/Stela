//! Devices behind a hub on root 1, as behind the rate-matching hub of an
//! Intel 5 to 8 series EHCI controller: hub enumeration, high-speed devices
//! through it, and split transactions for a low-speed keyboard.
use super::*;
use crate::{
    Clock,
    usb::ehci::{host::enumerate, input},
};
use alloc::rc::Rc;
use core::cell::RefCell;

/// A low-speed boot keyboard: EP0 packet 8, one 8-byte interrupt IN
/// endpoint polled every 10 frames.
const KEYBOARD: [u8; 18] = [
    18, 1, 0x10, 1, 0, 0, 0, 8, 0x6d, 0x04, 0x1c, 0xc3, 0, 1, 0, 0, 0, 1,
];
const KEYBOARD_DESCRIPTION: [u8; 34] = [
    9, 2, 34, 0, 1, 1, 0, 0xa0, 50, 9, 4, 0, 0, 1, 3, 1, 1, 0, 9, 0x21, 0x11, 1, 0, 1, 0x22, 63, 0,
    7, 5, 0x81, 3, 8, 0, 10,
];
const LOW_SPEED: u16 = 1 << 9;
const HIGH_SPEED: u16 = 1 << 10;

fn clock() -> Clock {
    Clock {
        ticks_per_microsecond: 1_000,
    }
}

/// A controller whose root 1 holds a hub with `ports`.
fn behind_hub(ports: Vec<Child>) -> Arc<Mutex<Shared>> {
    let m = Arc::new(Mutex::new(Shared::new()));
    m.lock().unwrap().hub_ports = ports;
    m
}

/// Root 1's hub, addressed, configured and with `port` powered.
fn hub(c: &mut Controller, port: u8) -> DeviceId {
    let hub = c.reset_port(1).unwrap();
    c.set_address(&hub, 1).unwrap();
    c.configure(&hub, 0).unwrap();
    c.power_hub_port(&hub, port).unwrap();
    hub
}

#[test]
fn a_high_speed_stick_behind_the_root_hub_is_addressed_and_bound() {
    let _time = crate::test_clock::virtualize();
    let m = behind_hub(vec![
        Child::empty(),
        Child::new(HIGH_SPEED, DEVICE, &DESCRIPTION),
    ]);
    let controller = Rc::new(RefCell::new(controller(m.clone())));
    let found = enumerate(&controller, "ehci", clock());
    let m = m.lock().unwrap();
    assert_eq!(m.addresses[0], Some(1), "the hub takes the lowest address");
    assert_eq!(m.configurations[0], 1);
    assert!(m.hub_ports.iter().all(|port| port.powered));
    assert_eq!(m.hub_ports[0].resets, 0, "an empty port is not reset");
    assert_eq!(m.hub_ports[1].resets, 1);
    assert_eq!(
        m.hub_ports[1].change, 0,
        "connection and reset changes acknowledged"
    );
    assert_eq!(m.hub_ports[1].address, Some(2));
    assert_eq!(m.hub_ports[1].configured, 1);
    // The peer answers bulk IN with a pattern, so the INQUIRY's CSW is
    // malformed; its CBW still went out on the child's OUT pipe.
    assert_eq!(m.received.get(..4), Some(&b"USBC"[..]));
    assert!(found.unused.is_empty());
    assert!(
        found
            .failures
            .iter()
            .all(|(at, _)| at.starts_with("ehci port 1 hub port 2")),
        "{:?}",
        found.failures
    );
}

#[test]
fn a_low_speed_keyboard_behind_the_hub_runs_split_transactions() {
    let _time = crate::test_clock::virtualize();
    let m = behind_hub(vec![Child::new(LOW_SPEED, KEYBOARD, &KEYBOARD_DESCRIPTION)]);
    let mut c = controller(m.clone());
    let hub = hub(&mut c, 1);
    let keyboard = c.reset_hub_port(&hub, 1).unwrap().unwrap();
    assert_eq!(c.speed(&keyboard), Ok(Speed::Low));
    assert!(!keyboard.is_root());
    assert_eq!(c.unused_address(), Some(2));
    c.set_address(&keyboard, 2).unwrap();
    c.set_control_packet(&keyboard, KEYBOARD[7]).unwrap();
    assert!(c.configure(&keyboard, 0).unwrap().is_empty());
    let pipes = c.interrupt_pipes(&keyboard).unwrap();
    // bInterval 10 rounds down to 8 frames.
    assert_eq!(pipes[0].interval_microframes(), 64);
    let report = c.submit_interrupt_in(&pipes[0], 8, 1_000_000).unwrap();
    let completion = c.poll(&report).unwrap().unwrap();
    assert_eq!(completion.actual, 8);
    let m = m.lock().unwrap();
    assert_eq!(m.hub_ports[0].address, Some(2));
    assert_eq!(m.hub_ports[0].configured, 1);
    assert!(!m.periodic_services.is_empty());
    assert!(m.periodic_services.iter().all(|tick| tick % 64 == 0));
}

#[test]
fn enumeration_reads_a_low_speed_ep0_packet_before_the_whole_descriptor() {
    let _time = crate::test_clock::virtualize();
    let m = behind_hub(vec![Child::new(LOW_SPEED, KEYBOARD, &KEYBOARD_DESCRIPTION)]);
    let controller = Rc::new(RefCell::new(controller(m.clone())));
    let found = enumerate(&controller, "ehci", clock());
    assert_eq!(found.inputs.len(), 1);
    let m = m.lock().unwrap();
    assert_eq!(m.hub_ports[0].address, Some(2));
    let reads: Vec<u16> = m
        .setup_trace
        .iter()
        .filter(|setup| setup[..4] == [0x80, 6, 0, 1])
        .map(|setup| u16::from_le_bytes([setup[6], setup[7]]))
        .collect();
    assert_eq!(
        reads,
        [18, 8, 18],
        "the hub's, then the keyboard's two reads"
    );
}

#[test]
fn a_failed_child_disables_its_hub_port_and_frees_address0() {
    let _time = crate::test_clock::virtualize();
    let mut broken = DEVICE;
    broken[17] = 0; // No configuration.
    let m = behind_hub(vec![
        Child::new(HIGH_SPEED, broken, &DESCRIPTION),
        Child::new(HIGH_SPEED, DEVICE, &DESCRIPTION),
    ]);
    let controller = Rc::new(RefCell::new(controller(m.clone())));
    let found = enumerate(&controller, "ehci", clock());
    assert!(
        found
            .failures
            .iter()
            .any(|(at, _)| at == "ehci port 1 hub port 1")
    );
    let m = m.lock().unwrap();
    assert!(
        !m.hub_ports[0].enabled,
        "the failed device's port is disabled"
    );
    // Address 0 went free again, so the next port was enumerated, and the
    // disabled port's address was reused.
    assert_eq!(m.hub_ports[1].address, Some(2));
    assert_eq!(m.hub_ports[1].configured, 1);
}

#[test]
fn a_root_reset_retires_the_devices_behind_its_hub() {
    let _time = crate::test_clock::virtualize();
    let m = behind_hub(vec![Child::new(HIGH_SPEED, DEVICE, &DESCRIPTION)]);
    let mut c = controller(m.clone());
    let hub = hub(&mut c, 1);
    let child = c.reset_hub_port(&hub, 1).unwrap().unwrap();
    c.set_address(&child, 2).unwrap();
    assert_eq!(c.hub_port_of(&child).unwrap().unwrap().1, 1);
    // A second reset of the same hub port retires the old handle.
    let again = c.reset_hub_port(&hub, 1).unwrap().unwrap();
    assert_eq!(c.validate(&child), Err(Error::Stale));
    c.set_address(&again, 2).unwrap();
    let root = c.reset_port(1).unwrap();
    assert_eq!(c.validate(&again), Err(Error::Stale));
    assert_eq!(c.validate(&hub), Err(Error::Stale));
    // Every address behind the root is free again.
    c.set_address(&root, 1).unwrap();
    assert_eq!(c.unused_address(), Some(2));
}

#[test]
fn hub_port_requests_need_the_hub_owner_and_a_free_address0() {
    let _time = crate::test_clock::virtualize();
    let m = behind_hub(vec![
        Child::new(HIGH_SPEED, DEVICE, &DESCRIPTION),
        Child::new(HIGH_SPEED, DEVICE, &DESCRIPTION),
    ]);
    let mut c = controller(m.clone());
    let hub = hub(&mut c, 1);
    c.power_hub_port(&hub, 2).unwrap();
    // Ordinary control cannot reach a hub port.
    assert!(matches!(
        c.control_out(&hub, [0x23, 3, 4, 0, 1, 0, 0, 0], &[]),
        Err(Error::Unsupported(_))
    ));
    let first = c.reset_hub_port(&hub, 1).unwrap().unwrap();
    assert_eq!(c.reset_hub_port(&hub, 2).map(|_| ()), Err(Error::Busy));
    c.set_address(&first, 2).unwrap();
    assert!(c.reset_hub_port(&hub, 2).unwrap().is_some());
    assert_eq!(c.hub_port_status(&hub, 0), Err(Error::Invalid));
}

/// Root 1's hub with the low-speed keyboard on its port 1, addressed and
/// configured, and the keyboard's boot interface bound.
fn keyboard(m: &Arc<Mutex<Shared>>) -> (Rc<RefCell<Controller>>, DeviceId, input::BootInput) {
    let mut c = controller(m.clone());
    let hub = hub(&mut c, 1);
    let keyboard = c.reset_hub_port(&hub, 1).unwrap().unwrap();
    c.set_address(&keyboard, 2).unwrap();
    c.set_control_packet(&keyboard, 8).unwrap();
    c.configure(&keyboard, 0).unwrap();
    let shared = Rc::new(RefCell::new(c));
    let interface = &crate::usb::descriptor::interfaces(&KEYBOARD_DESCRIPTION)[0];
    assert!(input::is_boot(interface));
    let bound = input::BootInput::new(
        "keyboard".into(),
        shared.clone(),
        keyboard,
        interface,
        clock(),
    )
    .unwrap();
    (shared, hub, bound)
}

#[test]
fn a_boot_keyboard_behind_the_hub_is_bound_and_read() {
    let _time = crate::test_clock::virtualize();
    let m = behind_hub(vec![Child::new(LOW_SPEED, KEYBOARD, &KEYBOARD_DESCRIPTION)]);
    let controller = Rc::new(RefCell::new(controller(m.clone())));
    let mut found = enumerate(&controller, "ehci", clock());
    assert!(found.unused.is_empty() && found.failures.is_empty());
    assert_eq!(found.inputs.len(), 1);
    assert_eq!(found.inputs[0].name, "ehci port 1 hub port 1 interface 0");
    {
        let m = m.lock().unwrap();
        // SET_PROTOCOL(boot) and SET_IDLE(0) to interface 0.
        assert!(m.setup_trace.contains(&[0x21, 0x0b, 0, 0, 0, 0, 0, 0]));
        assert!(m.setup_trace.contains(&[0x21, 0x0a, 0, 0, 0, 0, 0, 0]));
    }
    // Left Shift and `a` held.
    m.lock().unwrap().report = Some(vec![2, 0, 4, 0, 0, 0, 0, 0]);
    let inputs = found.inputs[0].poll();
    for usage in [0xe1, 4] {
        assert!(inputs.contains(&crate::input::Input::Key {
            usage,
            pressed: true
        }));
    }
    assert!(!found.inputs[0].failed());
}

#[test]
fn another_transfer_preempts_the_waiting_keyboard_read() {
    let _time = crate::test_clock::virtualize();
    let m = behind_hub(vec![Child::new(LOW_SPEED, KEYBOARD, &KEYBOARD_DESCRIPTION)]);
    {
        let mut m = m.lock().unwrap();
        m.periodic_auto = false;
        m.report = Some(vec![0, 0, 4, 0, 0, 0, 0, 0]);
    }
    let (shared, hub, mut keyboard) = keyboard(&m);
    // The read is submitted and waits: no frame was serviced.
    assert!(keyboard.poll().is_empty());
    // A hub request still runs; it preempts the waiting read.
    let status = shared.borrow_mut().hub_port_status(&hub, 1).unwrap();
    assert_ne!(status.status & 1, 0);
    assert!(keyboard.poll().is_empty());
    assert!(!keyboard.failed(), "a preempted read is submitted again");
    m.lock().unwrap().periodic_auto = true;
    let inputs = keyboard.poll();
    assert!(!inputs.is_empty());
    assert!(!keyboard.failed());
}
