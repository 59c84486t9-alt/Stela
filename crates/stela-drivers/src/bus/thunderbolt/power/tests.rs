use super::*;
use crate::bus::thunderbolt::{
    config::{Encoded, PacketType},
    ring::{Direction, TX_DESCRIPTOR, model::*},
};
use core::sync::atomic::{AtomicBool, AtomicUsize};

struct Reservation {
    inventory: Inventory,
    operation: Operation,
    current: AtomicBool,
    dropped: Arc<AtomicUsize>,
}
// SAFETY: exact synthetic requester/reset epoch, with retained modeled power,
// serialized CM state and no independent hardware/firmware configuration actor.
unsafe impl Owner for Reservation {
    fn inventory(&self) -> &Inventory {
        &self.inventory
    }
    fn operation(&self) -> Operation {
        self.operation
    }
    fn port_may_wakeup(&self, port: u8) -> bool {
        port == 2
    }
    fn is_current(&self) -> bool {
        self.current.load(Ordering::Relaxed)
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}
fn owner(route: u64, operation: Operation) -> Arc<Reservation> {
    let mut inventory = router_owner(route, 1, 0).target.clone();
    inventory.header.raw[1] = (3 << 14) | (u32::from(inventory.upstream_port) << 8);
    inventory.adapters = vec![
        router_adapter(3, 1, Some(0x50)),
        router_adapter(1, 1, Some(0x30)),
        router_adapter(2, 1, Some(0x40)),
    ];
    Arc::new(Reservation {
        inventory,
        operation,
        current: AtomicBool::new(true),
        dropped: Arc::new(AtomicUsize::new(0)),
    })
}
fn response(
    domain: &Domain,
    model: &Model,
    index: usize,
    space: Space,
    port: u8,
    offset: u16,
    data: &[u32],
) -> Encoded {
    let index = index % 10;
    let descriptor = domain.read32(model.descriptor_address(Direction::Tx, index) + 8);
    let kind = PacketType::try_from(((descriptor >> 12) & 15) as u8).unwrap();
    let frame = domain.data(
        model.frame_address(Direction::Tx, index),
        (descriptor & 0xfff) as usize,
    );
    let address = u32::from_be_bytes(frame[8..12].try_into().unwrap());
    assert_eq!((address & 0x1fff) as u16, offset);
    assert_eq!((address >> 25) & 3, space as u32);
    assert_eq!((address >> 19) & 63, u32::from(port));
    assert_eq!((address >> 13) & 63, 1);
    let mut words = vec![
        u32::from_be_bytes(frame[..4].try_into().unwrap()) | (1 << 31),
        u32::from_be_bytes(frame[4..8].try_into().unwrap()),
        address & !(63 << 19),
    ];
    words.extend_from_slice(data);
    incoming(kind, &words)
}
fn exchange(
    control: &mut Control<Model>,
    domain: &Domain,
    model: &Model,
    index: usize,
    address: Address,
    data: &[u32],
    now: u64,
) -> Result<Option<Event>, Error> {
    let reply = response(
        domain,
        model,
        index,
        address.space,
        address.port,
        address.offset,
        data,
    );
    model.finish(Direction::Tx, index % 10, &[], None);
    finish_rx(model, index % 10, &reply);
    control.poll(now)
}

#[test]
fn wake_source_policy_distinguishes_configured_runtime_and_upstream_ports() {
    for configured in [false, true] {
        for may_wakeup in [false, true] {
            for runtime in [false, true] {
                let wake = Wake {
                    connect: true,
                    disconnect: true,
                    usb4: true,
                    runtime,
                    ..Wake::default()
                };
                let before = 0xa5f100f7 | (u32::from(configured) << 3);
                let (after, mask) = change(
                    Kind::PortWake {
                        upstream: false,
                        may_wakeup,
                    },
                    Operation::Wake(wake),
                    before,
                );
                let bits = if configured {
                    (u32::from(runtime || may_wakeup) << 17) | (1 << 18)
                } else {
                    u32::from(runtime || may_wakeup) << 16
                };
                assert_eq!(after & PORT_WAKE, bits);
                assert_eq!(after & !mask, before & !mask);
                let (upstream, _) = change(
                    Kind::PortWake {
                        upstream: true,
                        may_wakeup,
                    },
                    Operation::Wake(Wake::default()),
                    before,
                );
                assert_eq!(
                    upstream & PORT_WAKE,
                    1 << 18,
                    "device upstream always forwards USB4 wake"
                );
            }
        }
    }
}

#[test]
fn wake_programs_sorted_real_ports_then_device_router_with_ack_and_readback() {
    let wake = Wake {
        connect: true,
        disconnect: true,
        usb4: true,
        usb3: true,
        displayport: true,
        ..Wake::default()
    };
    for route in [0, 1] {
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let owner = owner(route, Operation::Wake(wake));
        let dropped = owner.dropped.clone();
        let steps = plan(&*owner).unwrap();
        assert_eq!(steps.len(), if route == 0 { 3 } else { 4 });
        // SAFETY: exact same modeled NHI, retained router and idle CM channel.
        let mut control = unsafe { Control::new(channel, owner.clone(), 0) }.unwrap();
        control.poll(0).unwrap();
        let mut index = 0;
        let mut receipt = None;
        for (ordinal, step) in steps.iter().enumerate() {
            let before = 0xb0080080 | if ordinal % 2 == 0 { 1 << 3 } else { 0 };
            let (after, _) = change(step.kind, Operation::Wake(wake), before);
            for data in [vec![before], vec![], vec![after]] {
                if data.is_empty() {
                    let frame = domain.data(model.frame_address(Direction::Tx, index % 10), 20);
                    assert_eq!(u32::from_be_bytes(frame[12..16].try_into().unwrap()), after);
                }
                let event = exchange(
                    &mut control,
                    &domain,
                    &model,
                    index,
                    step.address,
                    &data,
                    index as u64 + 1,
                )
                .unwrap();
                if let Some(Event::Applied(value)) = event {
                    receipt = Some(value);
                }
                index += 1;
            }
        }
        let applied = receipt.unwrap();
        assert_eq!(applied.words.len(), steps.len());
        assert_eq!(applied.sleep_status, None);
        let mut channel = control.into_channel();
        drop(owner);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        // SAFETY: independent synthetic CM retains the programmed state.
        unsafe { applied.retire() };
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        channel_release(&mut channel);
    }
}

#[test]
fn sleep_requires_actual_ack_then_ready_status_without_extending_deadline() {
    for ready in [false, true] {
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let owner = owner(1, Operation::Sleep);
        let dropped = owner.dropped.clone();
        let address = plan(&*owner).unwrap()[0].address;
        // SAFETY: same modeled powered router with quiesced dependent endpoints.
        let mut control = unsafe { Control::new(channel, owner.clone(), 0) }.unwrap();
        control.poll(0).unwrap();
        exchange(&mut control, &domain, &model, 0, address, &[0xa0000008], 1).unwrap();
        let frame = domain.data(model.frame_address(Direction::Tx, 1), 20);
        assert_eq!(
            u32::from_be_bytes(frame[12..16].try_into().unwrap()),
            0xa0000009
        );
        exchange(&mut control, &domain, &model, 1, address, &[], 2).unwrap();
        let status_address = Address {
            offset: 6,
            ..address
        };
        assert!(
            exchange(
                &mut control,
                &domain,
                &model,
                2,
                status_address,
                &[0x100],
                400
            )
            .unwrap()
            .is_none()
        );
        let result = exchange(
            &mut control,
            &domain,
            &model,
            3,
            status_address,
            &[0x100 | u32::from(ready)],
            501,
        )
        .unwrap();
        let mut receipt = None;
        if ready {
            let Some(Event::Applied(value)) = result else {
                panic!("sleep ready receipt")
            };
            assert_eq!(value.sleep_status, Some(0x101));
            receipt = Some(value);
        } else {
            assert!(result.is_none());
            assert!(matches!(control.poll(502), Err(Error::Timeout)));
            assert!(matches!(control.poll(503), Err(Error::Poisoned)));
        }
        let mut channel = control.into_channel();
        drop(owner);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        if let Some(value) = receipt {
            // SAFETY: actual modeled power ownership transferred to native PM.
            unsafe { value.retire() };
            assert_eq!(dropped.load(Ordering::Relaxed), 1);
        }
        channel_release(&mut channel);
    }
}

#[test]
fn uncertain_wake_write_failures_and_revocation_quarantine_original_owner() {
    for fault in 0..7 {
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let owner = owner(1, Operation::Wake(Wake::default()));
        let dropped = owner.dropped.clone();
        let address = plan(&*owner).unwrap()[0].address;
        // SAFETY: exact modeled router/epoch, exclusive retained wake resources.
        let mut control = unsafe { Control::new(channel, owner.clone(), 0) }.unwrap();
        control.poll(0).unwrap();
        exchange(&mut control, &domain, &model, 0, address, &[0], 1).unwrap();
        match fault {
            0 => assert!(matches!(control.poll(501), Err(Error::Timeout))),
            1 => {
                exchange(&mut control, &domain, &model, 1, address, &[], 2).unwrap();
                assert!(matches!(
                    exchange(&mut control, &domain, &model, 2, address, &[0], 3),
                    Err(Error::Readback)
                ));
            }
            2 => {
                owner.current.store(false, Ordering::Relaxed);
                assert!(matches!(control.poll(2), Err(Error::Revoked)));
            }
            3 => assert_eq!(control.cancel(), Err(Error::Cancelled)),
            4 => assert!(matches!(control.poll(0), Err(Error::ClockRegressed))),
            5 => {
                let reply = controller_error(
                    &domain,
                    &model,
                    &NativeCursor {
                        tx: 1,
                        rx: 1,
                        now: 2,
                    },
                );
                finish_rx(&model, 1, &reply);
                assert!(matches!(
                    control.poll(2),
                    Err(Error::Controller { code: 2, .. })
                ));
            }
            6 => {
                finish_rx(&model, 1, &incoming(PacketType::Event, &[0, 1, 2]));
                assert!(matches!(control.poll(2), Err(Error::Hotplug(_))));
            }
            _ => unreachable!(),
        }
        let writes = model.state.lock().unwrap().writes.len();
        owner.current.store(true, Ordering::Relaxed);
        assert!(matches!(control.poll(502), Err(Error::Poisoned)));
        assert_eq!(writes, model.state.lock().unwrap().writes.len());
        let mut channel = control.into_channel();
        drop(owner);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        channel_release(&mut channel);
    }
}

#[test]
fn unconsumed_sleep_completion_keeps_live_native_power_reservation() {
    let (_source, domain, model, mut channel) = channel();
    channel.start(0).unwrap();
    let owner = owner(1, Operation::Sleep);
    let dropped = owner.dropped.clone();
    let address = plan(&*owner).unwrap()[0].address;
    // SAFETY: same modeled router and actual retained power/tunnel lifetime.
    let mut control = unsafe { Control::new(channel, owner.clone(), 0) }.unwrap();
    control.poll(0).unwrap();
    exchange(&mut control, &domain, &model, 0, address, &[0], 1).unwrap();
    exchange(&mut control, &domain, &model, 1, address, &[], 2).unwrap();
    let result = exchange(
        &mut control,
        &domain,
        &model,
        2,
        Address {
            offset: 6,
            ..address
        },
        &[1],
        3,
    )
    .unwrap();
    assert!(matches!(result, Some(Event::Applied(_))));
    drop(result);
    let mut channel = control.into_channel();
    drop(owner);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    channel_release(&mut channel);
}

#[test]
fn wake_admission_rejects_malformed_inventory_capabilities_and_stale_ownership() {
    for fault in 0..5 {
        let (_source, _domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let mut owner = owner(1, Operation::Wake(Wake::default()));
        let value = Arc::get_mut(&mut owner).unwrap();
        match fault {
            0 => value.current.store(false, Ordering::Relaxed),
            1 => value.inventory.header.raw[4] = 0,
            2 => value.inventory.adapters[0] = value.inventory.adapters[1].clone(),
            3 | 4 => {
                let AdapterObservation::Present { capabilities, .. } =
                    &mut value.inventory.adapters[0]
                else {
                    unreachable!()
                };
                if fault == 3 {
                    capabilities[0].offset = 8191;
                } else {
                    capabilities.push(capabilities[0].clone());
                }
            }
            _ => unreachable!(),
        }
        let writes = model.state.lock().unwrap().writes.len();
        // SAFETY: same modeled channel; intentionally invalid inputs refuse.
        let result = unsafe { Control::new(channel, owner, 0) };
        assert!(matches!(
            result,
            Err(Error::Revoked | Error::Unsupported | Error::Inventory | Error::Capability)
        ));
        assert_eq!(writes, model.state.lock().unwrap().writes.len());
    }
}

#[test]
fn wake_tx_backpressure_has_fixed_publication_deadline_without_fake_writes() {
    let (_source, domain, model, mut channel) = channel();
    channel.start(0).unwrap();
    let owner = owner(1, Operation::Wake(Wake::default()));
    let dropped = owner.dropped.clone();
    let address = plan(&*owner).unwrap()[0].address;
    for index in 0..8 {
        channel
            .read(Route::new(1).unwrap(), address, 0, 1000)
            .unwrap();
        let reply = response(
            &domain,
            &model,
            index,
            address.space,
            address.port,
            address.offset,
            &[0],
        );
        finish_rx(&model, index, &reply);
        channel.poll(0).unwrap();
    }
    // SAFETY: same modeled exclusive router and idle channel, TX DMA is full.
    let mut control = unsafe { Control::new(channel, owner.clone(), 0) }.unwrap();
    control.poll(0).unwrap();
    let reply = response(
        &domain,
        &model,
        8,
        address.space,
        address.port,
        address.offset,
        &[0],
    );
    finish_rx(&model, 8, &reply);
    control.poll(1).unwrap();
    assert_eq!(model.read32(TX_DESCRIPTOR + 8) >> 16, 9);
    for now in [2, 400, 500] {
        assert!(control.poll(now).unwrap().is_none());
    }
    assert!(matches!(control.poll(501), Err(Error::Timeout)));
    let mut channel = control.into_channel();
    drop(owner);
    assert_eq!(
        dropped.load(Ordering::Relaxed),
        1,
        "no wake write published"
    );
    channel_release(&mut channel);
}

#[test]
#[ignore = "requires pinned unchanged Linux USB4 wake/sleep trace"]
fn unchanged_linux_usb4_power_register_effects_match() {
    extern crate std;
    let trace = std::fs::read_to_string(
        std::env::var("STELA_THUNDERBOLT_POWER_ORACLE").expect("set pinned power trace"),
    )
    .unwrap();
    let mut wake_cases = 0;
    let mut sleep_cases = 0;
    for line in trace.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        let n = |i: usize| fields[i].parse::<u32>().unwrap();
        if fields[0] == "S" {
            assert_eq!(fields.len(), 5);
            assert_eq!(change(Kind::Sleep, Operation::Sleep, n(1)).0, n(2));
            assert_eq!((n(3), n(4)), (1, 1));
            sleep_cases += 1;
            continue;
        }
        assert_eq!((fields[0], fields.len()), ("W", 11));
        let shape = n(1);
        let flags = n(2);
        let wake = Wake {
            connect: flags & 1 != 0,
            disconnect: flags & 2 != 0,
            usb4: flags & 4 != 0,
            usb3: flags & 8 != 0,
            pcie: flags & 16 != 0,
            displayport: flags & 32 != 0,
            runtime: n(3) != 0,
        };
        if shape == 2 {
            assert_eq!((n(6), n(7)), (n(5), 0), "root upstream is skipped");
        } else {
            assert_eq!(
                change(
                    Kind::PortWake {
                        upstream: shape >= 2,
                        may_wakeup: n(4) != 0
                    },
                    Operation::Wake(wake),
                    n(5),
                )
                .0,
                n(6),
            );
            assert_eq!(n(7), 1);
        }
        if shape % 2 == 0 {
            assert_eq!(
                (n(9), n(10)),
                (n(8), 0),
                "root has no protocol wake register write"
            );
        } else {
            assert_eq!(
                change(Kind::RouterWake, Operation::Wake(wake), n(8)).0,
                n(9)
            );
            assert_eq!(n(10), 1);
        }
        wake_cases += 1;
    }
    assert_eq!((wake_cases, sleep_cases), (8192, 256));
}

#[test]
fn deadline_overflow_after_real_writes_permanently_poison_continued_publication() {
    let (_source, domain, model, mut channel) = channel();
    let start = u64::MAX - JOB_MS;
    channel.start(start).unwrap();
    let mut owner = owner(1, Operation::Wake(Wake::default()));
    let value = Arc::get_mut(&mut owner).unwrap();
    value.inventory.header.raw[1] = (14 << 14) | (1 << 8);
    value.inventory.adapters = (1..=14)
        .map(|port| router_adapter(port, 1, Some(0x30)))
        .collect();
    let dropped = owner.dropped.clone();
    let steps = plan(&*owner).unwrap();
    // SAFETY: same modeled router/CM lifetime; clock genuinely advances near its limit.
    let mut control = unsafe { Control::new(channel, owner.clone(), start) }.unwrap();
    control.poll(start).unwrap();
    for index in 0..40 {
        let step = steps[index / 3];
        let data = match index % 3 {
            0 => vec![0],
            1 => vec![],
            _ => vec![change(step.kind, Operation::Wake(Wake::default()), 0).0],
        };
        let result = exchange(
            &mut control,
            &domain,
            &model,
            index,
            step.address,
            &data,
            start + (index as u64 + 1) * 499,
        );
        if index == 39 {
            assert!(matches!(result, Err(Error::ClockOverflow)));
        } else {
            assert!(result.unwrap().is_none());
        }
    }
    let writes = model.state.lock().unwrap().writes.len();
    assert!(matches!(control.poll(u64::MAX - 1), Err(Error::Poisoned)));
    assert_eq!(writes, model.state.lock().unwrap().writes.len());
    let mut channel = control.into_channel();
    drop(owner);
    assert_eq!(
        dropped.load(Ordering::Relaxed),
        0,
        "previous wake writes retain the real owner"
    );
    channel_release(&mut channel);
}
