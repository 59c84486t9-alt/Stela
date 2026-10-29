// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

pub(super) fn exercise_rx_recycling(oracle: Option<&str>) {
    for ax210 in [false, true] {
        let mut reference = Vec::new();
        if let Some(oracle) = oracle {
            for line in oracle.lines() {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields[1].parse::<u8>().unwrap() != u8::from(ax210) {
                    continue;
                }
                if fields[0] == "initial" {
                    assert_eq!(&fields[2..], ["31", "24"]);
                } else {
                    assert_eq!(fields[0], "recycle");
                    let row: Vec<u16> = fields[2..].iter().map(|v| v.parse().unwrap()).collect();
                    reference.push(row);
                }
            }
            assert_eq!(reference.len(), 521);
            assert_eq!(reference[0], [0, 0, 1, 0, 0]);
        }
        let p = if ax210 { ax210_profile() } else { profile() };
        let bytes = if ax210 {
            ax210_bytes()
        } else {
            firmware_bytes()
        };
        let catalog = catalog_for(&p, p.family().firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let (observation, step_catalog) = step_fixture();
        let source = Source::default();
        let domain = Arc::new(Domain::default());
        let state = if ax210 {
            ax210_state()
        } else {
            Arc::new(Mutex::new(ModelState::default()))
        };
        let drops = Arc::new(AtomicUsize::new(0));
        let boot = if ax210 {
            start_ax210(
                &catalog,
                crate::net::wifi::intel::platform::load_step(observation, &step_catalog).unwrap(),
                &source,
                &domain,
                &state,
                &drops,
            )
        } else {
            start(&catalog, &source, &domain, &state, &drops)
        };
        let mut boot = command_ready(boot, &empty, &source, &domain, &state);
        let calls = source.calls.load(Ordering::Relaxed);
        let maps = domain.records.lock().unwrap().maps;
        assert_eq!(
            boot.replenish_completed_receive().unwrap(),
            Replenished {
                returned: 1,
                published: 8,
                device_credits: 31,
                waiting_for_completed_slot: false
            }
        );
        assert_eq!(state.lock().unwrap().registers.get(&0x1c80), Some(&0));
        let mut preserved = None;
        for n in 0..520u16 {
            let ticket = unsafe { boot.submit_command(command_id(), &[n as u8], &source) }.unwrap();
            let slot = (n + 1) & 31;
            let stride = if ax210 { 16 } else { 8 };
            let free = device_read(
                &domain,
                boot.free.region().address,
                usize::from(slot) * stride,
                stride,
            );
            let (vid, address) = if ax210 {
                (
                    u16::from_le_bytes(free[..2].try_into().unwrap()),
                    u64::from_le_bytes(free[8..16].try_into().unwrap()),
                )
            } else {
                let word = u64::from_le_bytes(free.try_into().unwrap());
                ((word & 0xfff) as u16, word & !0xfff)
            };
            assert_eq!(
                address,
                boot.buffers[usize::from(vid - 1)]
                    .allocation
                    .region()
                    .address
            );
            if oracle.is_some() {
                assert_eq!(
                    (
                        reference[usize::from(n) + 1][0],
                        reference[usize::from(n) + 1][1],
                        reference[usize::from(n) + 1][2]
                    ),
                    (n + 1, slot, vid)
                );
            }
            complete_from_free_slot(
                &boot,
                &domain,
                slot,
                vid,
                slot,
                &command_packet(command_id(), ticket.sequence(), &[n as u8]),
            );
            let response = match boot.poll_command(&ticket).unwrap() {
                CommandProgress::Completed(r) => r,
                _ => panic!("no completion"),
            };
            assert_eq!(response.raw, [n as u8]);
            if n == 0 {
                preserved = Some(response.raw);
            }
            let replenished = boot.replenish_completed_receive().unwrap();
            assert_eq!(replenished.returned, 1);
            assert!(!replenished.waiting_for_completed_slot);
            assert!(matches!(replenished.published, 0 | 8));
            let expected = ((32 + n + 1) & 31) & !7;
            assert_eq!(
                state.lock().unwrap().registers.get(&0x1c80),
                Some(&u32::from(expected))
            );
            if oracle.is_some() {
                assert_eq!(reference[usize::from(n) + 1][4], expected);
            }
        }
        assert_eq!(preserved.unwrap(), [0]);
        assert_eq!(source.calls.load(Ordering::Relaxed), calls);
        assert_eq!(domain.records.lock().unwrap().maps, maps);
        boot.stop().unwrap();
        assert!(domain.records.lock().unwrap().live.is_empty());
    }
}
