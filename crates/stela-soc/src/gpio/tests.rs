use super::*;
use stela_contracts::interrupt::InterruptLatch;
fn lines() -> Vec<AicInput> {
    (199..206).map(|irq| AicInput::new(0, irq)).collect()
}
#[test]
fn plain_input_samples_real_net_without_arming_or_clearing_interrupts() {
    for profile in [Profile::T8101, Profile::S5l8960x] {
        let net = Net::new();
        let driver = net.open_drain().unwrap();
        let mut bank = Gpio::with_profile(profile, 32, lines(), &[], vec![(3, net)]).unwrap();
        let mut latch = InterruptLatch::new();
        {
            let mut access = Access::new(0, 0, &mut latch);
            // Source safe-reconfiguration order: old receiver0,
            // intermediate plain-input0, then receiver9. Do not sample an
            // invented DATA value from the intermediate hardware state.
            bank.write(12, Width::Word, 0, &mut access).unwrap();
            assert!(bank.read(12, Width::Word, &mut access).is_err());
            bank.write(12, Width::Word, INPUT_ENABLE.into(), &mut access)
                .unwrap();
            assert_eq!(
                bank.read(12, Width::Word, &mut access),
                Ok(u64::from(INPUT_ENABLE | DATA))
            );
            driver.pull_low(true);
            bank.advance(&mut access).unwrap();
            assert_eq!(
                bank.read(12, Width::Word, &mut access),
                Ok(u64::from(INPUT_ENABLE))
            );
            assert!(bank.armed.is_empty());
            assert!(bank.pending.iter().all(|word| *word == 0));
        }
        assert!(latch.take_aic_inputs().is_empty());
        let mut access = Access::new(0, 0, &mut latch);
        // Changing to plain input removes edge capture but does not
        // surrender an existing pending interrupt owned by software.
        bank.write(
            12,
            Width::Word,
            (EDGE_RISING | INPUT_ENABLE).into(),
            &mut access,
        )
        .unwrap();
        driver.pull_low(false);
        bank.advance(&mut access).unwrap();
        assert_eq!(bank.pending[0], 1 << 3);
        bank.write(12, Width::Word, INPUT_ENABLE.into(), &mut access)
            .unwrap();
        assert_eq!(bank.pending[0], 1 << 3);
        bank.write(IRQ_BASE, Width::Word, 1 << 3, &mut access)
            .unwrap();
        assert_eq!(bank.pending[0], 0);
    }
}

#[test]
fn plain_input_uses_pulls_and_refuses_floating_data_for_both_profiles() {
    for profile in [Profile::T8101, Profile::S5l8960x] {
        let mut bank = Gpio::with_profile(profile, 32, lines(), &[], vec![]).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        bank.write(4, Width::Word, INPUT_ENABLE.into(), &mut access)
            .unwrap();
        assert!(bank.read(4, Width::Word, &mut access).is_err());
        for (pull, level) in [(1 << 7, false), (2 << 7, true)] {
            let value = INPUT_ENABLE | pull;
            bank.write(4, Width::Word, value.into(), &mut access)
                .unwrap();
            assert_eq!(
                bank.read(4, Width::Word, &mut access),
                Ok(u64::from(value | u32::from(level)))
            );
        }
        assert!(bank.armed.is_empty());
    }
}

#[test]
fn s5l_lock_refuses_before_effects_while_t8101_lock_stays_monotonic() {
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut bank = Gpio::with_profile(Profile::S5l8960x, 32, lines(), &[3], vec![]).unwrap();
    let before = bank.pins.clone();
    for value in [
        OUTPUT | LOCK,
        INPUT_ENABLE | LOCK,
        EDGE_RISING | INPUT_ENABLE | LOCK,
    ] {
        assert!(
            bank.write(12, Width::Word, value.into(), &mut access)
                .is_err()
        );
        assert_eq!(bank.pins, before);
        assert!(bank.armed.is_empty());
        assert!(bank.pending.iter().all(|word| *word == 0));
    }
    for value in [0, u32::MAX] {
        assert!(
            bank.write(0xc48, Width::Word, value.into(), &mut access)
                .is_err()
        );
        assert_eq!(bank.pins, before);
    }
    assert!(bank.read(0xc48, Width::Word, &mut access).is_err());
    let mut old = Gpio::new(32, lines(), &[3], vec![]).unwrap();
    old.write(12, Width::Word, (OUTPUT | LOCK).into(), &mut access)
        .unwrap();
    old.write(12, Width::Word, (OUTPUT | DATA).into(), &mut access)
        .unwrap();
    assert_eq!(old.pins[3], OUTPUT | DATA | LOCK);
    assert!(
        old.write(12, Width::Word, INPUT_ENABLE.into(), &mut access)
            .is_err()
    );
}

#[test]
fn kept_clock_and_quiesce_preserve_pad_ownership_independently() {
    let net = Net::new();
    let input = net.open_drain().unwrap();
    let mut bank = Gpio::new(64, lines(), &[49], vec![(8, net)]).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    bank.write(49 * 4, Width::Word, u64::from(OUTPUT | LOCK), &mut access)
        .unwrap();
    bank.write(
        8 * 4,
        Width::Word,
        u64::from(INPUT_OFF | INPUT_ENABLE),
        &mut access,
    )
    .unwrap();
    let active = bank.lifecycle;
    let quiesced = LifecycleState {
        quiesced: true,
        ..active
    };
    bank.check_lifecycle(quiesced).unwrap();
    bank.set_lifecycle(quiesced, &mut access);
    assert_eq!(bank.output(49), Some(false));
    assert!(
        bank.write(49 * 4, Width::Word, u64::from(OUTPUT | DATA), &mut access)
            .is_err()
    );
    assert_eq!(bank.output(49), Some(false));
    let stopped = LifecycleState {
        clocked: false,
        ..quiesced
    };
    bank.check_lifecycle(stopped).unwrap();
    bank.set_lifecycle(stopped, &mut access);
    assert!(bank.read(49 * 4, Width::Word, &mut access).is_err());
    input.pull_low(true);
    bank.advance(&mut access).unwrap();
    assert_eq!(bank.output(49), Some(false));
    bank.check_lifecycle(quiesced).unwrap();
    bank.set_lifecycle(quiesced, &mut access);
    assert!(
        bank.lifecycle.quiesced,
        "clock restart does not resume service"
    );
    assert_eq!(
        bank.read(49 * 4, Width::Word, &mut access),
        Ok(u64::from(OUTPUT | LOCK))
    );
    bank.check_lifecycle(active).unwrap();
    bank.set_lifecycle(active, &mut access);
    assert_eq!(
        bank.read(8 * 4, Width::Word, &mut access),
        Ok(u64::from(INPUT_OFF | INPUT_ENABLE))
    );
    assert!(bank.pending.iter().all(|word| *word == 0));
    assert!(latch.take_aic_inputs().is_empty());
}

#[test]
fn armed_edge_or_owned_pending_interrupt_prevents_pause_without_losing_events() {
    let net = Net::new();
    let input = net.open_drain().unwrap();
    let mut bank = Gpio::new(64, lines(), &[], vec![(8, net)]).unwrap();
    let mut latch = InterruptLatch::new();
    let active = bank.lifecycle;
    let stopped = LifecycleState {
        clocked: false,
        ..active
    };
    let mut access = Access::new(0, 0, &mut latch);
    bank.write(
        8 * 4,
        Width::Word,
        u64::from(EDGE_FALLING | INPUT_ENABLE),
        &mut access,
    )
    .unwrap();
    assert!(bank.check_lifecycle(stopped).is_err());
    assert_eq!(bank.lifecycle, active);
    input.pull_low(true);
    bank.advance(&mut access).unwrap();
    input.pull_low(false);
    bank.advance(&mut access).unwrap();
    assert_eq!(
        bank.pending[0],
        1 << 8,
        "refused pause leaves edge capture active"
    );
    // Removing the trigger does not surrender an already-owned latch.
    bank.write(8 * 4, Width::Word, u64::from(INPUT_OFF), &mut access)
        .unwrap();
    assert!(bank.armed.is_empty());
    assert!(bank.check_lifecycle(stopped).is_err());
    assert!(
        bank.check_lifecycle(LifecycleState {
            quiesced: true,
            ..active
        })
        .is_err()
    );
    bank.write(IRQ_BASE, Width::Word, 1 << 8, &mut access)
        .unwrap();
    bank.check_lifecycle(stopped).unwrap();
    bank.set_lifecycle(stopped, &mut access);
    for proposed in [
        LifecycleState {
            reset: true,
            ..active
        },
        LifecycleState {
            powered: false,
            retention: true,
            ..active
        },
        LifecycleState {
            powered: false,
            retention: false,
            ..active
        },
    ] {
        assert!(bank.check_lifecycle(proposed).is_err());
        assert_eq!(bank.lifecycle, stopped);
        assert_eq!(bank.pending[0], 0);
    }
    assert_eq!(
        latch.take_aic_inputs(),
        [(lines()[0], true), (lines()[0], false)]
    );
}

#[test]
fn mounted_gpio_refusal_keeps_real_aic_delivery_owned() {
    use {
        crate::aic::Aic2, stela_contracts::bus::Bus, stela_soc_data::aic::AIC2_IRQ_CFG,
        stela_soc_data::aic::AIC2_TIMESTAMPS, stela_soc_data::aic::Aic2Config,
    };
    let net = Net::new();
    let input = net.open_drain().unwrap();
    let gpio = Gpio::new(32, vec![AicInput::new(0, 3)], &[], vec![(8, net)]).unwrap();
    let aic = Aic2::new(Aic2Config {
        version: 2,
        nr_irq: 32,
        max_irq: 32,
        irq_config: AIC2_IRQ_CFG,
        event_offset: 0x4000,
        timestamps: 0,
        timestamp_base: AIC2_TIMESTAMPS,
        cpus: 1,
        default_cpus: 1,
    })
    .unwrap();
    let mut bus = Bus::new();
    let gpio_id = bus.add(Box::new(gpio));
    let aic_id = bus.add(Box::new(aic));
    bus.map(gpio_id, 0x10000, 0x1000, 0).unwrap();
    bus.map(aic_id, 0x20000, 0x4004, 0).unwrap();
    let mut latch = InterruptLatch::new();
    bus.write(
        0x10020,
        Width::Word,
        u64::from(LEVEL_LOW | INPUT_ENABLE),
        &mut Access::new(0, 0, &mut latch),
    )
    .unwrap();
    // An aggregate preflight must check every real bank before committing
    // either one. AIC is idle, but the GPIO wake/edge path is unchecked.
    let paused = LifecycleState {
        powered: true,
        clocked: false,
        quiesced: false,
        reset: false,
        retention: true,
    };
    bus.lifecycle(aic_id)
        .unwrap()
        .check_lifecycle(paused)
        .unwrap();
    assert!(
        bus.lifecycle(gpio_id)
            .unwrap()
            .check_lifecycle(paused)
            .is_err()
    );
    input.pull_low(true);
    bus.advance(&mut Access::new(0, 1, &mut latch)).unwrap();
    for (line, level) in latch.take_aic_inputs() {
        bus.device_mut::<Aic2>(aic_id)
            .unwrap()
            .set_input(line, level, &mut Access::new(0, 1, &mut latch))
            .unwrap();
    }
    // Unmask source 3 and enable the mapped AIC. The earlier
    // refused lifecycle preflight changed neither bank or input level.
    bus.write(
        0x20000 + AIC2_IRQ_CFG + 4 * 32 + 12,
        Width::Word,
        1 << 3,
        &mut Access::new(0, 2, &mut latch),
    )
    .unwrap();
    bus.write(0x20014, Width::Word, 1, &mut Access::new(0, 2, &mut latch))
        .unwrap();
    assert!(latch.pins(0).irq);
    assert_eq!(
        bus.read(0x24000, Width::Word, &mut Access::new(0, 3, &mut latch)),
        Ok(1 << 16 | 3)
    );
    assert!(!latch.pins(0).irq);
    assert_eq!(
        bus.read(0x10800, Width::Word, &mut Access::new(0, 3, &mut latch)),
        Ok(1 << 8)
    );
}
#[test]
#[ignore = "oracle: STELA_TEST_PMGR_KERNELCACHE"]
fn original_drivers_keep_wake_claim_and_timestamp_disarm_explicit() {
    use sha2::{Digest, Sha256};
    let path = std::env::var("STELA_TEST_PMGR_KERNELCACHE")
        .expect("pinned original J473 kernelcache path");
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        "06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d"
    );
    // GPIO setPowerState claims separate wake ownership; this is not
    // evidence for resetting pads or dropping pending edges on suspend.
    // AIC stopInterruptTimestamping separately disarms its slot.
    for (offset, opcode) in [
        (0x24d9480, 0xf900b401),
        (0x24d9484, 0xf100043f),
        (0x24d9498, 0x97fffded),
        (0x24dd7a0, 0x528041c9),
        (0x24dd7a8, 0xb9000308),
        (0x24dd7f8, 0xb9000128),
        (0x24dd91c, 0x321f0922),
        (0x24dd920, 0xb9000102),
        (0x24dd9b8, 0xb9000128),
        (0x28232e0, 0x52830009),
        (0x28232e4, 0x0b081121),
        (0x2823308, 0x52800002),
        (0x2823310, 0xd73f0910),
    ] {
        assert_eq!(
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()),
            opcode,
            "original IRQ lifecycle source at {offset:#x}"
        );
    }
}
#[test]
fn enabling_an_undriven_receiver_does_not_invent_a_sample() {
    let mut bank = Gpio::new(213, lines(), &[], vec![]).unwrap();
    let mut latch = InterruptLatch::new();
    let mut a = Access::new(0, 0, &mut latch);
    let input = INPUT_OFF | INPUT_ENABLE | 2 << 16;
    bank.write(4 * 84, Width::Word, input.into(), &mut a)
        .unwrap();
    assert_eq!(bank.pins[84], input);
    assert!(bank.read(4 * 84, Width::Word, &mut a).is_err());
    assert_eq!(bank.pins[84], input);
    bank.write(4 * 84, Width::Word, (input | 1 << 7).into(), &mut a)
        .unwrap();
    assert_eq!(
        bank.read(4 * 84, Width::Word, &mut a),
        Ok(u64::from(input | 1 << 7))
    );
    bank.write(4 * 84, Width::Word, (input | 2 << 7).into(), &mut a)
        .unwrap();
    assert_eq!(
        bank.read(4 * 84, Width::Word, &mut a),
        Ok(u64::from(input | 2 << 7 | DATA))
    );
    bank.write(4 * 84, Width::Word, input.into(), &mut a)
        .unwrap();
    bank.write(4 * 84, Width::Word, u64::from(INPUT_OFF), &mut a)
        .unwrap();
    assert_eq!(
        bank.read(4 * 84, Width::Word, &mut a),
        Ok(u64::from(INPUT_OFF))
    );
}
#[test]
fn level_interrupts_follow_their_net_until_acknowledged_inactive() {
    let net = Net::new();
    let hpm = net.open_drain().unwrap();
    let mut bank = Gpio::new(213, lines(), &[], vec![(8, net.clone())]).unwrap();
    let mut latch = InterruptLatch::new();
    let level_low = LEVEL_LOW | INPUT_ENABLE | 1 << 16;
    let status = 0x800 + 0x40;
    let wire = Wire::Aic(AicInput::new(0, 200));
    {
        let mut a = Access::new(0, 0, &mut latch);
        bank.write(4 * 8, Width::Word, level_low.into(), &mut a)
            .unwrap();
        assert_eq!(bank.read(status, Width::Word, &mut a), Ok(0));
        hpm.pull_low(true);
        bank.advance(&mut a).unwrap();
        assert_eq!(bank.read(status, Width::Word, &mut a), Ok(1 << 8));
        assert_eq!(bank.read(4 * 8, Width::Word, &mut a), Ok(level_low.into()));
        // Acknowledging an active level relatches it at once.
        bank.write(status, Width::Word, 1 << 8, &mut a).unwrap();
        assert_eq!(bank.read(status, Width::Word, &mut a), Ok(1 << 8));
    }
    assert!(latch.is_asserted(wire));
    {
        let mut a = Access::new(0, 0, &mut latch);
        hpm.pull_low(false);
        bank.write(status, Width::Word, 1 << 8, &mut a).unwrap();
        assert_eq!(bank.read(status, Width::Word, &mut a), Ok(0));
    }
    assert!(!latch.is_asserted(wire));
    assert_eq!(
        latch.take_aic_inputs(),
        [
            (AicInput::new(0, 200), true),
            (AicInput::new(0, 200), false)
        ]
    );
    // A floating level input cannot be armed.
    let mut a = Access::new(0, 0, &mut latch);
    assert!(
        bank.write(4 * 9, Width::Word, level_low.into(), &mut a)
            .is_err()
    );
    assert!(
        bank.write(4 * 8, Width::Word, (level_low | 7 << 16).into(), &mut a)
            .is_err()
    );
}
#[test]
fn edges_latch_on_sampled_transitions_and_masking_keeps_the_latch() {
    let net = Net::new();
    let line = net.open_drain().unwrap();
    let mut bank = Gpio::new(213, lines(), &[], vec![(84, net)]).unwrap();
    let mut latch = InterruptLatch::new();
    let mut a = Access::new(0, 0, &mut latch);
    let status = 0x800 + 2 * 0x40 + 8;
    for (mode, falls, rises) in [
        (EDGE_RISING, 0, 1 << 20),
        (EDGE_FALLING, 1 << 20, 0),
        (EDGE_ANY, 1 << 20, 1 << 20),
    ] {
        let word = mode | INPUT_ENABLE | 2 << 16;
        bank.write(4 * 84, Width::Word, word.into(), &mut a)
            .unwrap();
        assert_eq!(bank.read(status, Width::Word, &mut a), Ok(0));
        line.pull_low(true);
        bank.advance(&mut a).unwrap();
        assert_eq!(bank.read(status, Width::Word, &mut a), Ok(falls));
        bank.write(status, Width::Word, u64::MAX >> 32, &mut a)
            .unwrap();
        line.pull_low(false);
        bank.advance(&mut a).unwrap();
        assert_eq!(bank.read(status, Width::Word, &mut a), Ok(rises));
        if rises != 0 {
            bank.write(4 * 84, Width::Word, u64::from(INPUT_OFF), &mut a)
                .unwrap();
            assert_eq!(bank.read(status, Width::Word, &mut a), Ok(rises));
        }
        bank.write(status, Width::Word, u64::MAX >> 32, &mut a)
            .unwrap();
    }
}
#[test]
fn i2c_lines_sample_their_board_pull_up() {
    let mut bank = Gpio::new(213, lines(), &[49], vec![(86, Net::new())]).unwrap();
    let mut latch = InterruptLatch::new();
    let mut a = Access::new(0, 0, &mut latch);
    let sda = INPUT_OFF | INPUT_ENABLE | 1 << 5;
    bank.write(4 * 86, Width::Word, sda.into(), &mut a).unwrap();
    assert_eq!(
        bank.read(4 * 86, Width::Word, &mut a),
        Ok(u64::from(sda | DATA))
    );
    // Even an internal pull-down loses to the external pull-up.
    bank.write(4 * 86, Width::Word, (sda | 1 << 7).into(), &mut a)
        .unwrap();
    assert_eq!(
        bank.read(4 * 86, Width::Word, &mut a),
        Ok(u64::from(sda | 1 << 7 | DATA))
    );
    assert!(Gpio::new(213, lines(), &[49], vec![(49, Net::new())]).is_err());
    assert!(Gpio::new(213, vec![], &[], vec![]).is_err());
}
#[test]
fn an_eighth_group_without_a_line_has_status_but_takes_no_interrupt() {
    // J414sAP `gpio0`: `#gpio-int-groups` 8, seven `interrupts`.
    let mut bank = Gpio::new(255, lines(), &[], vec![(8, Net::new())])
        .unwrap()
        .with_groups(GROUPS)
        .unwrap();
    let mut latch = InterruptLatch::new();
    let mut a = Access::new(0, 0, &mut latch);
    let last = IRQ_BASE + (GROUPS as u64 - 1) * IRQ_STRIDE;
    bank.write(last, Width::Word, u64::from(u32::MAX), &mut a)
        .unwrap();
    assert_eq!(bank.read(last, Width::Word, &mut a), Ok(0));
    let unwired = EDGE_RISING | (GROUPS as u32 - 1) << GROUP_SHIFT;
    assert!(
        bank.write(4 * 8, Width::Word, u64::from(unwired), &mut a)
            .is_err()
    );
    let wired = EDGE_RISING | 6 << GROUP_SHIFT;
    bank.write(4 * 8, Width::Word, u64::from(wired), &mut a)
        .unwrap();
    assert!(
        Gpio::new(255, lines(), &[], vec![])
            .unwrap()
            .with_groups(GROUPS + 1)
            .is_err()
    );
    assert!(
        Gpio::new(255, lines(), &[], vec![])
            .unwrap()
            .with_groups(1)
            .is_err()
    );
}
#[test]
fn peripheral_functions_record_the_mux_without_a_gpio_level() {
    let mut bank = Gpio::new(213, lines(), &[49], vec![]).unwrap();
    let mut latch = InterruptLatch::new();
    let mut a = Access::new(0, 0, &mut latch);
    let sda = INPUT_OFF | INPUT_ENABLE | 1 << 5;
    bank.write(4 * 110, Width::Word, sda.into(), &mut a)
        .unwrap();
    assert_eq!(bank.pins[110], sda);
    assert!(
        bank.write(49 * 4, Width::Word, u64::from(OUTPUT | 1 << 5), &mut a)
            .is_err()
    );
    assert!(
        bank.write(
            4 * 110,
            Width::Word,
            u64::from(EDGE_RISING | 1 << 5),
            &mut a
        )
        .is_err()
    );
    assert_eq!(bank.output(110), None);
}
#[test]
fn cs_registers_are_explicit() {
    let mut bank = Gpio::new(213, lines(), &[49], vec![]).unwrap();
    let mut latch = InterruptLatch::new();
    let mut a = Access::new(0, 0, &mut latch);
    assert_eq!(bank.output(49), Some(true));
    bank.write(49 * 4, Width::Word, 2, &mut a).unwrap();
    assert_eq!(bank.output(49), Some(false));
    bank.write(49 * 4, Width::Word, u64::from(2 | LOCK), &mut a)
        .unwrap();
    assert!(bank.write(49 * 4, Width::Word, 0x202, &mut a).is_err());
    bank.write(0, Width::Word, 0, &mut a).unwrap();
    assert!(bank.read(0, Width::Word, &mut a).is_err());
    assert!(bank.read(0xc48, Width::Word, &mut a).is_err());
    assert_eq!(bank.read(0x800, Width::Word, &mut a), Ok(0));
}
