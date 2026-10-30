extern crate std;
use super::*;

use crate::bus::thunderbolt::config::PacketType;
use crate::bus::thunderbolt::ring::{Direction, TX_DESCRIPTOR, model::*};

use core::sync::atomic::Ordering;

#[test]
fn routes_enforce_adapter_and_depth_limits() {
    for raw in [0x100, 0x010002, 64, 255, 1 << 48] {
        assert!(Path::new(Route::new(raw).unwrap()).is_err());
    }
    let root = Path::new(Route::new(0).unwrap()).unwrap();
    let mut path = root;
    for port in 1..=6 {
        path = path.downstream(port, false).unwrap();
        assert_eq!(path.depth(), port);
        assert!(path.is_descendant_of(root));
    }
    assert_eq!(path.downstream(1, false), Err(Error::Depth));
    let usb4 = Path::new(Route::new(0x0504030201).unwrap()).unwrap();
    assert_eq!(usb4.downstream(1, true), Err(Error::Depth));
    assert!(path.is_descendant_of(usb4));
    assert!(!usb4.is_descendant_of(usb4));
    assert!(!usb4.is_descendant_of(Path::new(Route::new(2).unwrap()).unwrap()));
}
#[test]
fn capability_long_short_bounds_and_raw_unknown_adapter_are_explicit() {
    let cap = Capability::parse(0x100, &[0x00060500, 2 << 16 | 0x200], true).unwrap();
    assert_eq!(
        (cap.id, cap.vendor_specific, cap.length, cap.next),
        (5, Some(6), Some(2), 0x200)
    );
    assert_eq!(
        Capability::parse(0x100, &[0x00060500, 2 << 16 | 0xffff], true)
            .unwrap()
            .next,
        0
    );
    assert_eq!(
        Capability::parse(0x100, &[0x00060500, 1 << 16], true),
        Err(Error::CapabilityHeader)
    );
    assert_eq!(
        Capability::parse(0x100, &[0x00060501, 2 << 16], true),
        Err(Error::CapabilityHeader)
    );
    assert_eq!(
        Capability::parse(0x100, &[0x00060500, 2 << 16 | 8192], true),
        Err(Error::CapabilityOffset(8192))
    );
    assert_eq!(
        Capability::parse(8191, &[0x02010500, 0], true),
        Err(Error::CapabilityHeader)
    );
    assert_eq!(
        Capability::parse(8, &[0x7e00, 0], true),
        Err(Error::CapabilityHeader)
    );
    assert_eq!(Capability::parse(8, &[0x7e00], false).unwrap().id, 0x7e);
    let mut job = Job {
        path: Path::new(Route::new(0).unwrap()).unwrap(),
        expected: None,
        publication_deadline: None,
        stage: Stage::Router,
        inventory: None,
        seen: Vec::new(),
        invalidated: false,
    };
    Inspector::<super::super::ring::Mmio>::set_capability(
        &mut job,
        Stage::RouterCapability(32),
        32,
        1,
    )
    .unwrap();
    assert_eq!(
        Inspector::<super::super::ring::Mmio>::set_capability(
            &mut job,
            Stage::RouterCapability(33),
            33,
            1
        ),
        Err(Error::CapabilityBudget)
    );
    assert_eq!(
        Inspector::<super::super::ring::Mmio>::set_capability(
            &mut job,
            Stage::RouterCapability(32),
            32,
            1
        ),
        Err(Error::CapabilityLoop(32))
    );
}
#[test]
#[ignore = "oracle: STELA_THUNDERBOLT_TOPOLOGY_ORACLE"]
fn unchanged_linux_router_adapter_bitfields_and_helpers_match() {
    extern crate std;
    use std::{env, fs};
    let trace = fs::read_to_string(
        env::var("STELA_THUNDERBOLT_TOPOLOGY_ORACLE").expect("set topology trace"),
    )
    .unwrap();
    let mut count = 0;
    for line in trace.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        assert_eq!(fields[0], "H");
        let values: Vec<u64> = fields[1..]
            .iter()
            .map(|field| field.parse().unwrap())
            .collect();
        assert_eq!(values.len(), 30);
        let raw: Vec<u32> = values[..13].iter().map(|value| *value as u32).collect();
        let router = RouterHeader::parse(&raw[..5]).unwrap();
        let adapter = AdapterHeader::parse(&raw[5..]).unwrap();
        let kind = match adapter.kind() {
            AdapterKind::Inactive => 0,
            AdapterKind::Lane => 1,
            AdapterKind::Nhi => 2,
            AdapterKind::PcieDown => 0x100101,
            AdapterKind::PcieUp => 0x100102,
            AdapterKind::Usb3Down => 0x200101,
            AdapterKind::Usb3Up => 0x200102,
            AdapterKind::DisplayIn => 0x0e0101,
            AdapterKind::DisplayOut => 0x0e0102,
            AdapterKind::Unknown(raw) => raw,
        };
        assert_eq!(
            &values[13..],
            &[
                u64::from(router.vendor()),
                u64::from(router.device()),
                u64::from(router.first_capability()),
                u64::from(router.reported_upstream()),
                u64::from(router.max_port()),
                u64::from(router.reported_depth()),
                u64::from(router.revision()),
                router.reported_route(),
                u64::from(router.enabled()),
                u64::from(router.usb4_version()),
                u64::from(kind),
                u64::from(adapter.first_capability()),
                u64::from(adapter.reported_port()),
                u64::from(adapter.max_in_hop()),
                u64::from(adapter.max_out_hop()),
                u64::from(adapter.nonflow_buffers()),
                u64::from(adapter.total_buffers()),
            ],
            "{line}"
        );
        count += 1;
    }
    assert_eq!(count, 4096);
}

#[test]
fn inspector_reads_router_adapter_and_capability_dma_without_control_adapter_zero() {
    use super::super::{
        config::Route,
        topology::{AdapterKind, AdapterObservation, Event, Inspector},
    };
    let (source, domain, model, mut channel) = channel();
    channel.start(0).unwrap();
    let mut inspector = Inspector::new(channel, 100, 64).unwrap();
    assert_eq!(
        inspector.begin(Route::new(1).unwrap(), 0),
        Err(super::super::topology::Error::RootRequired)
    );
    inspector.begin(Route::new(0).unwrap(), 0).unwrap();
    let mut adapter1 = vec![0; 8];
    adapter1[1] = 0x10;
    adapter1[2] = 1;
    adapter1[3] = 1 << 20;
    adapter1[4] = 19 | (67 << 20);
    adapter1[5] = 31 | (63 << 11);
    let mut adapter3 = vec![0; 8];
    adapter3[2] = 0xabcdef;
    adapter3[3] = 3 << 20;
    // (space,port,offset,words,reply-data/error). Every expected request is
    // decoded from the driver's mapped TX frame, not a mock RPC.
    type InspectStep = (u32, u32, u32, u32, Result<Vec<u32>, u32>);
    let steps: Vec<InspectStep> = vec![
        (
            2,
            0,
            0,
            5,
            Ok(vec![0x12348086, 0x20 | (3 << 14), 0, 0, 1 << 29]),
        ),
        (2, 0, 0x20, 2, Ok(vec![0x330, 0x12345678])),
        (2, 0, 0x30, 2, Ok(vec![0x02010500, 0xabcd])),
        (1, 1, 0, 8, Ok(adapter1)),
        (1, 1, 0x10, 1, Ok(vec![0x120])),
        (1, 1, 0x20, 1, Ok(vec![0x600])),
        (1, 2, 0, 8, Err(2)),
        (1, 3, 0, 8, Ok(adapter3)),
    ];
    let mut result = None;
    for (index, (space, port, offset, words, data)) in steps.into_iter().enumerate() {
        let sent = domain.data(model.frame_address(Direction::Tx, index % 10), 16);
        let address = u32::from_be_bytes(sent[8..12].try_into().unwrap());
        assert_eq!((address >> 25) & 3, space);
        assert_eq!((address >> 19) & 63, port);
        assert_eq!(address & 0x1fff, offset);
        assert_eq!((address >> 13) & 63, words);
        assert!(!(space == 1 && port == 0));
        model.finish(Direction::Tx, index % 10, &[], None);
        let response = match data {
            Ok(data) => {
                let mut words = vec![1 << 31, 0, address & !(63 << 19)];
                words.extend(data);
                incoming(PacketType::Read, &words)
            }
            Err(code) => incoming(PacketType::Error, &[1 << 31, 0, code]),
        };
        finish_rx(&model, index % 10, &response);
        result = inspector.poll(index as u64 + 1).unwrap();
        if index < 7 {
            assert_eq!(result, None);
        }
    }
    let Some(Event::Inventory(inventory)) = result else {
        panic!("inventory")
    };
    assert_eq!(inventory.header.vendor(), 0x8086);
    assert_eq!(inventory.header.device(), 0x1234);
    assert_eq!(inventory.header.usb4_version(), 1);
    assert_eq!(inventory.capabilities.len(), 2);
    assert_eq!(inventory.capabilities[1].vendor_specific, Some(1));
    assert_eq!(inventory.capabilities[0].raw, vec![0x330, 0x12345678]);
    assert_eq!(inventory.adapters.len(), 3);
    let AdapterObservation::Present {
        header,
        capabilities,
        ..
    } = &inventory.adapters[0]
    else {
        panic!("adapter1")
    };
    assert_eq!(header.kind(), AdapterKind::Lane);
    assert_eq!((header.max_in_hop(), header.max_out_hop()), (31, 63));
    assert_eq!((header.nonflow_buffers(), header.total_buffers()), (19, 67));
    assert_eq!(
        capabilities.iter().map(|cap| cap.id).collect::<Vec<_>>(),
        vec![1, 6]
    );
    assert!(matches!(
        inventory.adapters[1],
        AdapterObservation::Unimplemented {
            port: 2,
            raw: 2,
            ..
        }
    ));
    assert!(
        matches!(&inventory.adapters[2],AdapterObservation::Present { header,.. } if header.kind()==AdapterKind::Unknown(0xabcdef))
    );
    let mut channel = inspector.into_channel();
    channel_release(&mut channel);
    drop(channel);
    assert!(domain.state.lock().unwrap().maps.is_empty());
    assert_eq!(
        source.allocated.load(Ordering::Relaxed),
        source.released.load(Ordering::Relaxed)
    );
}

#[test]
fn inspector_rejects_capability_cycles_and_hotplug_stale_snapshot_before_new_reads() {
    use super::super::{
        config::Route,
        topology::{Error as InspectError, Event, Inspector},
    };
    for case in 0..3 {
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let mut inspector = Inspector::new(channel, 100, 64).unwrap();
        inspector.begin(Route::new(0).unwrap(), 0).unwrap();
        if case == 2 {
            let event = incoming(PacketType::Event, &[0, 0, 1]);
            finish_rx(&model, 0, &event);
            assert!(matches!(inspector.poll(1).unwrap(), Some(Event::Plug(_))));
        }
        let sent = domain.data(model.frame_address(Direction::Tx, 0), 16);
        let address = u32::from_be_bytes(sent[8..12].try_into().unwrap());
        model.finish(Direction::Tx, 0, &[], None);
        let response = incoming(
            PacketType::Read,
            &[
                1 << 31,
                0,
                address,
                0x12348086,
                if case == 1 { 4 } else { 0x20 },
                0,
                0,
                1 << 29,
            ],
        );
        finish_rx(&model, if case == 2 { 1 } else { 0 }, &response);
        if case == 2 {
            assert_eq!(inspector.poll(2), Err(InspectError::TopologyChanged));
        } else if case == 1 {
            assert_eq!(inspector.poll(2), Err(InspectError::CapabilityOffset(4)));
        } else {
            assert_eq!(inspector.poll(2).unwrap(), None);
            let sent = domain.data(model.frame_address(Direction::Tx, 1), 16);
            let address = u32::from_be_bytes(sent[8..12].try_into().unwrap());
            model.finish(Direction::Tx, 1, &[], None);
            let response = incoming(PacketType::Read, &[1 << 31, 0, address, 0x320, 0]);
            finish_rx(&model, 1, &response);
            assert_eq!(inspector.poll(3), Err(InspectError::CapabilityLoop(0x20)));
        }
        let writes = model.state.lock().unwrap().writes.len();
        assert_eq!(inspector.poll(4).unwrap(), None);
        assert_eq!(writes, model.state.lock().unwrap().writes.len());
        let mut channel = inspector.into_channel();
        channel_release(&mut channel);
    }
}

#[test]
fn inspector_refuses_exact_legacy_tmu_quirks_before_any_capability_or_adapter_access() {
    use super::super::{
        config::Route,
        topology::{Error as InspectError, Inspector},
    };
    for device in [0x1513u16, 0x151a] {
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let mut inspector = Inspector::new(channel, 100, 64).unwrap();
        inspector.begin(Route::new(0).unwrap(), 0).unwrap();
        let sent = domain.data(model.frame_address(Direction::Tx, 0), 16);
        let address = u32::from_be_bytes(sent[8..12].try_into().unwrap());
        model.finish(Direction::Tx, 0, &[], None);
        let reply = incoming(
            PacketType::Read,
            &[
                1 << 31,
                0,
                address,
                0x8086 | (u32::from(device) << 16),
                0x20 | (3 << 14),
                0,
                0,
                0,
            ],
        );
        finish_rx(&model, 0, &reply);
        assert_eq!(
            inspector.poll(1),
            Err(InspectError::LegacyTmuAccess {
                vendor: 0x8086,
                device
            })
        );
        assert_eq!(
            model.read32(TX_DESCRIPTOR + 8) >> 16,
            1,
            "no second request may be published"
        );
        let writes = model.state.lock().unwrap().writes.len();
        assert_eq!(inspector.poll(2).unwrap(), None);
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        let mut channel = inspector.into_channel();
        channel_release(&mut channel);
    }
}

#[test]
fn inventory_tx_publication_deadline_does_not_move_when_dma_consumer_stalls() {
    use super::super::{
        channel::Error as ChannelError,
        config::Route,
        topology::{Error as InspectError, Inspector},
    };
    let (_source, domain, model, mut channel) = channel();
    channel.start(0).unwrap();
    let mut inspector = Inspector::new(channel, 10, 64).unwrap();
    inspector.begin(Route::new(0).unwrap(), 0).unwrap();
    for index in 0..9 {
        let sent = domain.data(model.frame_address(Direction::Tx, index), 16);
        let address = u32::from_be_bytes(sent[8..12].try_into().unwrap());
        // The synthetic wire peer replies, but NHI never acknowledges any
        // TX DMA descriptor. Nine real transmitted slots fill the ring.
        let mut words = vec![1 << 31, 0, address & !(63 << 19)];
        if index == 0 {
            words.extend([0x12348086, 10 << 14, 0, 0, 1 << 29]);
        } else {
            words.extend([0; 8]);
        }
        finish_rx(&model, index, &incoming(PacketType::Read, &words));
        assert_eq!(inspector.poll(index as u64).unwrap(), None);
    }
    assert_eq!(model.read32(TX_DESCRIPTOR + 8) >> 16, 9);
    let writes = model.state.lock().unwrap().writes.len();
    for now in 9..18 {
        assert_eq!(inspector.poll(now).unwrap(), None);
    }
    assert_eq!(
        inspector.poll(18),
        Err(InspectError::PublicationTimeout {
            route: Route::new(0).unwrap(),
            port: 9,
            offset: 0
        })
    );
    assert_eq!(
        inspector.poll(19),
        Err(InspectError::Channel(ChannelError::Poisoned))
    );
    assert_eq!(
        inspector.begin(Route::new(0).unwrap(), 19),
        Err(InspectError::Channel(ChannelError::Poisoned))
    );
    assert_eq!(model.state.lock().unwrap().writes.len(), writes);
    let mut channel = inspector.into_channel();
    channel_release(&mut channel);
}
