use super::*;
use stela_contracts::interrupt::InterruptLatch;
use stela_contracts::refuse;
use stela_soc_data::aic::layout::Aic2DieLayout;

const NR_IRQ: u16 = 0x3a0;
const MAX_IRQ: u16 = 0x400;
const IRQ_CFG: u64 = AIC2_IRQ_CFG;
const MASK_SET: u64 = IRQ_CFG + 4 * MAX_IRQ as u64 + 2 * 4 * (MAX_IRQ as u64 / 32);
const MASK_CLR: u64 = MASK_SET + 4 * (MAX_IRQ as u64 / 32);
const SW_SET: u64 = IRQ_CFG + 4 * MAX_IRQ as u64;
const SW_CLR: u64 = SW_SET + 4 * (MAX_IRQ as u64 / 32);
const EVENT: u64 = 0x8000;
const UART: AicInput = AicInput::new(0, 739);

fn aic(cpus: usize) -> Aic2 {
    Aic2::new(Aic2Config {
        version: 2,
        nr_irq: NR_IRQ,
        max_irq: MAX_IRQ,
        irq_config: IRQ_CFG,
        event_offset: EVENT,
        timestamps: 16,
        timestamp_base: AIC2_TIMESTAMPS,
        cpus,
        default_cpus: 1,
    })
    .unwrap()
}
fn read(aic: &mut Aic2, latch: &mut InterruptLatch, cpu: CpuIndex, offset: u64) -> u32 {
    aic.read(offset, Width::Word, &mut Access::new(cpu, 0, latch))
        .unwrap() as u32
}
fn write(aic: &mut Aic2, latch: &mut InterruptLatch, offset: u64, value: u32) {
    aic.write(
        offset,
        Width::Word,
        value.into(),
        &mut Access::new(0, 0, latch),
    )
    .unwrap();
}
#[test]
fn kept_clock_pause_preserves_pending_levels_masks_and_timestamp_history() {
    let mut aic = aic(2);
    let mut latch = InterruptLatch::new();
    let (word, bit) = position(usize::from(UART.irq));
    write(&mut aic, &mut latch, MASK_CLR + 4 * word as u64, bit);
    write(&mut aic, &mut latch, SW_SET + 4 * word as u64, bit);
    write(
        &mut aic,
        &mut latch,
        AIC2_TIMESTAMPS,
        TIMESTAMP_ENABLE | u32::from(UART.irq),
    );
    aic.set_input(UART, true, &mut Access::new(0, 123, &mut latch))
        .unwrap();
    write(&mut aic, &mut latch, AIC2_TIMESTAMPS, 0);
    let active = aic.lifecycle;
    let paused = LifecycleState {
        clocked: false,
        ..active
    };
    aic.check_lifecycle(paused).unwrap();
    aic.set_lifecycle(paused, &mut Access::new(0, 124, &mut latch));
    assert!(
        aic.read(VERSION, Width::Word, &mut Access::new(0, 125, &mut latch))
            .is_err()
    );
    // External lines remain levels. No enabled timestamp or delivery
    // engine was suspended, so no pulse/wake behavior is invented.
    aic.set_input(UART, false, &mut Access::new(0, 126, &mut latch))
        .unwrap();
    aic.set_input(UART, true, &mut Access::new(0, 127, &mut latch))
        .unwrap();
    assert!(!latch.pins(0).irq);
    assert_eq!(aic.software[word] & bit, bit);
    assert_eq!(aic.hardware[word] & bit, bit);
    assert_eq!(aic.mask[word] & bit, 0);
    assert_eq!(aic.timestamps[0].counter, 123);
    aic.check_lifecycle(active).unwrap();
    aic.set_lifecycle(active, &mut Access::new(0, 128, &mut latch));
    write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
    assert!(latch.pins(0).irq);
    assert_eq!(read(&mut aic, &mut latch, 0, EVENT), EVENT_TYPE_IRQ | 739);
    assert!(!latch.pins(0).irq);
    // Claim masks the source without consuming software or wire state.
    assert_eq!(aic.software[word] & bit, bit);
    assert_eq!(aic.hardware[word] & bit, bit);
}

#[test]
fn quiesce_is_independent_of_clock_and_cannot_arm_new_delivery() {
    let mut aic = aic(2);
    let mut latch = InterruptLatch::new();
    let active = aic.lifecycle;
    let quiesced = LifecycleState {
        quiesced: true,
        ..active
    };
    aic.check_lifecycle(quiesced).unwrap();
    aic.set_lifecycle(quiesced, &mut Access::new(0, 0, &mut latch));
    assert_eq!(read(&mut aic, &mut latch, 0, CONFIG), 0);
    assert!(
        aic.write(
            CONFIG,
            Width::Word,
            CONFIG_ENABLE.into(),
            &mut Access::new(0, 1, &mut latch),
        )
        .is_err()
    );
    assert!(!aic.enabled);
    let clock_stopped = LifecycleState {
        clocked: false,
        ..quiesced
    };
    aic.check_lifecycle(clock_stopped).unwrap();
    aic.set_lifecycle(clock_stopped, &mut Access::new(0, 2, &mut latch));
    aic.check_lifecycle(quiesced).unwrap();
    aic.set_lifecycle(quiesced, &mut Access::new(0, 3, &mut latch));
    assert!(
        aic.lifecycle.quiesced,
        "clock restart cannot resume service"
    );
    aic.check_lifecycle(active).unwrap();
    aic.set_lifecycle(active, &mut Access::new(0, 4, &mut latch));
    write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
}

#[test]
fn armed_delivery_capture_and_destructive_edges_refuse_without_effects() {
    let mut aic = aic(2);
    let mut latch = InterruptLatch::new();
    let active = aic.lifecycle;
    write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
    for proposed in [
        LifecycleState {
            clocked: false,
            ..active
        },
        LifecycleState {
            quiesced: true,
            ..active
        },
        LifecycleState {
            reset: true,
            ..active
        },
        LifecycleState {
            powered: false,
            retention: false,
            ..active
        },
        LifecycleState {
            powered: false,
            retention: true,
            ..active
        },
    ] {
        assert!(aic.check_lifecycle(proposed).is_err());
        assert_eq!(aic.lifecycle, active);
        assert!(aic.enabled);
    }
    write(&mut aic, &mut latch, CONFIG, 0);
    write(&mut aic, &mut latch, AIC2_TIMESTAMPS, TIMESTAMP_ENABLE | 5);
    assert!(
        aic.check_lifecycle(LifecycleState {
            clocked: false,
            ..active
        })
        .is_err()
    );
    aic.set_input(
        AicInput::new(0, 5),
        true,
        &mut Access::new(0, 99, &mut latch),
    )
    .unwrap();
    assert_eq!(
        aic.timestamps[0].counter, 99,
        "refused pause still captures"
    );
}
/// Linux `aic_of_ic_init`: read INFO1/INFO3, mask and clear every IRQ,
/// then set CONFIG.ENABLE with a read-modify-write.
fn linux_init(aic: &mut Aic2, latch: &mut InterruptLatch) {
    let info1 = read(aic, latch, 0, INFO1);
    let info3 = read(aic, latch, 0, INFO3);
    assert_eq!(info1 & 0xffff, u32::from(NR_IRQ));
    assert_eq!(info1 >> 24 & 0xf, 0, "LAST_DIE");
    assert_eq!(info3 & 0xffff, u32::from(MAX_IRQ));
    assert_eq!(info3 >> 24 & 0xf, 1, "MAX_DIE");
    for word in 0..u64::from(NR_IRQ).div_ceil(32) {
        write(aic, latch, MASK_SET + 4 * word, u32::MAX);
        write(aic, latch, SW_CLR + 4 * word, u32::MAX);
    }
    let config = read(aic, latch, 0, CONFIG);
    write(aic, latch, CONFIG, config | CONFIG_ENABLE);
}

/// Linux `aic_irq_unmask`, `aic_handle_irq` (event read with auto-mask)
/// and `aic_irq_eoi` (unmask again) for the UART line.
#[test]
fn linux_hardware_irq_cycle() {
    let mut latch = InterruptLatch::new();
    let mut aic = aic(2);
    linux_init(&mut aic, &mut latch);
    let (word, bit) = position(UART.irq.into());
    write(&mut aic, &mut latch, MASK_CLR + 4 * word as u64, bit);
    aic.set_input(UART, true, &mut Access::new(0, 0, &mut latch))
        .unwrap();
    assert!(latch.pins(0).irq);
    assert_eq!(read(&mut aic, &mut latch, 0, EVENT), 1 << 16 | 739);
    assert!(!latch.pins(0).irq, "the event read masked the IRQ");
    assert_eq!(read(&mut aic, &mut latch, 0, EVENT), 0);
    aic.set_input(UART, false, &mut Access::new(0, 0, &mut latch))
        .unwrap();
    write(&mut aic, &mut latch, MASK_CLR + 4 * word as u64, bit);
    assert!(!latch.pins(0).irq);
    aic.set_input(UART, true, &mut Access::new(0, 0, &mut latch))
        .unwrap();
    assert!(latch.pins(0).irq);
}

/// The 26A434 kernel's `AppleInterruptControllerV2::start` on a T8112:
/// VERSION, INFO1 and INFO3, then masks at its fixed 0x6400 and reads
/// back through 0x6600 and HW_STATE at 0x6800.
#[test]
fn xnu_aic2_layout_is_that_of_4096_irqs() {
    let mut latch = InterruptLatch::new();
    let mut aic = Aic2::new(Aic2Config {
        version: 2,
        nr_irq: 740,
        max_irq: AIC2_MAX_IRQ,
        irq_config: AIC2_IRQ_CFG,
        event_offset: 0x8000,
        timestamps: 16,
        timestamp_base: AIC2_TIMESTAMPS,
        cpus: 1,
        default_cpus: 1,
    })
    .unwrap();
    assert_eq!(read(&mut aic, &mut latch, 0, VERSION) & 0xff, 2);
    assert_eq!(read(&mut aic, &mut latch, 0, INFO1) & 0x7ff, 740);
    assert_eq!(read(&mut aic, &mut latch, 0, INFO3), 1 << 24 | 0x1000);
    for word in 0..740u64.div_ceil(32) {
        write(&mut aic, &mut latch, 0x6400 + 4 * word, u32::MAX);
    }
    assert_eq!(read(&mut aic, &mut latch, 0, 0x6600), u32::MAX);
    assert_eq!(read(&mut aic, &mut latch, 0, 0x6600 + 4 * 23), 0xf);
    assert_eq!(read(&mut aic, &mut latch, 0, 0x6800), 0);
}

/// `startInterruptTimestamping` enables slot 0 for IRQ 0xc9 and
/// `getTimestamp` reads the high word, then the low one.
#[test]
fn timestamp_slots_latch_the_counter_at_their_irqs_rising_edge() {
    let mut latch = InterruptLatch::new();
    let mut aic = aic(2);
    let irq = AicInput::new(0, 0xc9);
    write(&mut aic, &mut latch, 0x1800, 0x8000_00c9);
    assert_eq!(read(&mut aic, &mut latch, 0, 0x1800), 0x8000_00c9);
    let stamp = 0x1_2345_6789;
    aic.set_input(irq, true, &mut Access::new(0, stamp, &mut latch))
        .unwrap();
    aic.set_input(irq, true, &mut Access::new(0, stamp + 5, &mut latch))
        .unwrap();
    assert_eq!(read(&mut aic, &mut latch, 0, 0x180c), 1);
    assert_eq!(read(&mut aic, &mut latch, 0, 0x1808), 0x2345_6789);
    // Slot 1 is idle; slots past `#shared-timestamps` do not exist.
    assert_eq!(read(&mut aic, &mut latch, 0, 0x1818), 0);
    let mut access = Access::new(0, 0, &mut latch);
    assert!(aic.read(0x1900, Width::Word, &mut access).is_err());
    assert!(aic.read(0x1804, Width::Word, &mut access).is_err());
    assert!(aic.write(0x1808, Width::Word, 0, &mut access).is_err());
    assert!(
        aic.write(
            0x1810,
            Width::Word,
            0x8000_0000 | u64::from(NR_IRQ),
            &mut access
        )
        .is_err()
    );
    assert!(
        aic.write(0x1810, Width::Word, 0x4000_0000, &mut access)
            .is_err()
    );
}

#[test]
fn software_triggers_and_priority() {
    let mut latch = InterruptLatch::new();
    let mut aic = aic(2);
    linux_init(&mut aic, &mut latch);
    write(&mut aic, &mut latch, MASK_CLR, 0b1010);
    write(&mut aic, &mut latch, SW_SET, 0b1110);
    assert_eq!(read(&mut aic, &mut latch, 0, SW_SET), 0b1110);
    assert_eq!(read(&mut aic, &mut latch, 0, EVENT), 1 << 16 | 1);
    assert_eq!(read(&mut aic, &mut latch, 0, EVENT), 1 << 16 | 3);
    assert_eq!(
        read(&mut aic, &mut latch, 0, EVENT),
        0,
        "IRQ 2 stays masked"
    );
    write(&mut aic, &mut latch, SW_CLR, 0b1110);
    write(&mut aic, &mut latch, MASK_CLR, 0b1010);
    assert!(!latch.pins(0).irq);
}

#[test]
fn disabled_controller_gates_default_ap_delivery() {
    let mut latch = InterruptLatch::new();
    let mut aic = aic(2);
    write(&mut aic, &mut latch, MASK_CLR, 1);
    aic.set_input(
        AicInput::new(0, 0),
        true,
        &mut Access::new(0, 0, &mut latch),
    )
    .unwrap();
    assert!(!latch.pins(0).irq, "CONFIG.ENABLE is clear");
    write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
    assert!(latch.pins(0).irq && !latch.pins(1).irq);
    assert_eq!(read(&mut aic, &mut latch, 1, EVENT), 0);
    assert_eq!(read(&mut aic, &mut latch, 0, EVENT), EVENT_TYPE_IRQ);
    assert!(!latch.pins(0).irq);
}

/// TARGET0 uses the explicit AP roster; SIQ filters each PE independently.
#[test]
fn a_cpu_refusing_irqs_through_siq_cfg_is_sent_none() {
    let mut latch = InterruptLatch::new();
    let mut aic = aic(2);
    aic.config.default_cpus = 0b11;
    write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
    write(&mut aic, &mut latch, MASK_CLR, 1);
    aic.set_input(
        AicInput::new(0, 0),
        true,
        &mut Access::new(0, 0, &mut latch),
    )
    .unwrap();
    assert!(latch.pins(0).irq && latch.pins(1).irq);
    aic.steer(0, true, &mut Access::new(0, 0, &mut latch));
    assert!(!latch.pins(0).irq && latch.pins(1).irq);
    assert_eq!(read(&mut aic, &mut latch, 0, EVENT), 0);
    aic.steer(1, true, &mut Access::new(0, 0, &mut latch));
    assert!(!latch.pins(0).irq && !latch.pins(1).irq);
    aic.steer(0, false, &mut Access::new(0, 0, &mut latch));
    assert!(latch.pins(0).irq && !latch.pins(1).irq);
    // A CPU the AIC does not serve changes nothing.
    aic.steer(5, true, &mut Access::new(0, 0, &mut latch));
    assert_eq!(read(&mut aic, &mut latch, 0, EVENT), EVENT_TYPE_IRQ);
}

#[test]
fn ext_intr_cfg_and_refusals() {
    let mut latch = InterruptLatch::new();
    let mut aic = aic(2);
    // IRQ 0x2e3 (739) keeps the supported AP selector0.
    aic.apply_ext_intr_cfg(&[0xe3, 0x02, 0x00]).unwrap();
    assert_eq!(read(&mut aic, &mut latch, 0, IRQ_CFG + 4 * 739), 0);
    assert!(
        aic.apply_ext_intr_cfg(&[0xe3, 0x12, 0x01]).is_err(),
        "die 1"
    );
    let mut access = Access::new(0, 0, &mut latch);
    for offset in [
        INFO2,
        RESET,
        0x28,
        IRQ_CFG + 4 * u64::from(NR_IRQ),
        EVENT + 4,
    ] {
        assert!(
            aic.read(offset, Width::Word, &mut access).is_err(),
            "{offset:#x}"
        );
    }
    assert!(
        aic.write(CONFIG, Width::Word, 1 << 28, &mut access)
            .is_err()
    );
    assert!(aic.write(EVENT, Width::Word, 0, &mut access).is_err());
    assert!(aic.read(EVENT, Width::Double, &mut access).is_err());
    assert!(
        aic.set_input(AicInput::new(0, NR_IRQ), true, &mut access)
            .is_err()
    );
}

fn two_dies() -> (Aic2Config, Aic2Layout) {
    let config = Aic2Config {
        version: 3,
        nr_irq: 33,
        max_irq: 64,
        irq_config: IRQ_CFG,
        event_offset: EVENT,
        timestamps: 16,
        timestamp_base: AIC2_TIMESTAMPS,
        cpus: 2,
        default_cpus: 1,
    };
    let first = Aic2DieLayout::contiguous(IRQ_CFG, config.max_irq).unwrap();
    let mut second = Aic2DieLayout::contiguous(0x4000, config.max_irq).unwrap();
    // Later firmware may supply distinct mask strides. Every other
    // array is explicit too; none aliases the corresponding die0 bank.
    second.mask_set = 0x6000;
    second.mask_clear = 0x7000;
    let layout = Aic2Layout {
        info1: 0x100,
        info3: 0x108,
        max_dies: 4,
        dies: vec![first, second],
    };
    (config, layout)
}

#[test]
fn two_eligible_cpus_claim_valid_words_in_die_priority_order() {
    let (mut config, layout) = two_dies();
    config.cpus = 64;
    config.default_cpus = 1 | 1 << 63;
    let (first, second) = (layout.dies[0], layout.dies[1]);
    let mut aic = Aic2::new_with_layout(config, layout).unwrap();
    let mut latch = InterruptLatch::new();
    write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
    write(&mut aic, &mut latch, first.mask_clear + 4, u32::MAX);
    write(&mut aic, &mut latch, first.software_set + 4, u32::MAX);
    write(&mut aic, &mut latch, second.mask_clear, 1);
    write(&mut aic, &mut latch, second.software_set, 1);

    assert!(latch.pins(0).irq && latch.pins(63).irq);
    assert!(!latch.pins(1).irq);
    assert_eq!(read(&mut aic, &mut latch, 63, EVENT), EVENT_TYPE_IRQ | 32);
    assert!(latch.pins(0).irq && latch.pins(63).irq);
    aic.steer(63, true, &mut Access::new(0, 0, &mut latch));
    assert!(latch.pins(0).irq && !latch.pins(63).irq);
    assert_eq!(read(&mut aic, &mut latch, 63, EVENT), 0);
    assert_eq!(
        read(&mut aic, &mut latch, 0, EVENT),
        1 << 24 | EVENT_TYPE_IRQ
    );
    assert_eq!(
        read(&mut aic, &mut latch, 0, EVENT),
        0,
        "padding stays masked"
    );
    assert!(!latch.pins(0).irq && !latch.pins(63).irq);
}

#[test]
fn explicit_layout_routes_claims_masks_and_timestamps_independently_per_die() {
    let (config, layout) = two_dies();
    let (first, second) = (layout.dies[0], layout.dies[1]);
    let mut aic = Aic2::new_with_layout(config, layout).unwrap();
    let mut latch = InterruptLatch::new();
    assert_eq!(read(&mut aic, &mut latch, 0, 0x100), 1 << 24 | 33);
    assert_eq!(read(&mut aic, &mut latch, 0, 0x108), 4 << 24 | 64);
    assert_eq!(aic.span(), EVENT + 4);
    write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
    write(&mut aic, &mut latch, first.mask_clear + 4, 1);
    write(&mut aic, &mut latch, second.mask_clear + 4, 1);
    write(
        &mut aic,
        &mut latch,
        AIC2_TIMESTAMPS,
        TIMESTAMP_ENABLE | 1 << 24 | 32,
    );
    let input = AicInput::new(1, 32);
    aic.set_input(
        input,
        true,
        &mut Access::new(0, 0x1234_5678_9abc_def0, &mut latch),
    )
    .unwrap();
    assert_eq!(
        read(&mut aic, &mut latch, 0, AIC2_TIMESTAMPS + TIMESTAMP_LOW),
        0x9abc_def0
    );
    assert_eq!(
        read(&mut aic, &mut latch, 0, AIC2_TIMESTAMPS + TIMESTAMP_HIGH),
        0x1234_5678
    );
    assert_eq!(read(&mut aic, &mut latch, 0, first.hardware_state + 4), 0);
    assert_eq!(read(&mut aic, &mut latch, 0, second.hardware_state + 4), 1);
    write(&mut aic, &mut latch, first.software_set + 4, 1);
    assert!(latch.pins(0).irq);
    assert_eq!(read(&mut aic, &mut latch, 0, EVENT), EVENT_TYPE_IRQ | 32);
    assert!(latch.pins(0).irq, "die1 remains independently pending");
    assert_eq!(
        read(&mut aic, &mut latch, 0, EVENT),
        1 << 24 | EVENT_TYPE_IRQ | 32
    );
    assert!(!latch.pins(0).irq);
    // A held level fires again only after that die is unmasked.
    write(&mut aic, &mut latch, first.mask_clear + 4, 1);
    write(&mut aic, &mut latch, first.software_clear + 4, 1);
    assert!(!latch.pins(0).irq);
    write(&mut aic, &mut latch, second.mask_clear + 4, u32::MAX);
    assert!(latch.pins(0).irq);
    assert_eq!(read(&mut aic, &mut latch, 0, second.mask_set + 4), 0);
    // Invalid tail bits are ignored independently in each die.
    assert_eq!(read(&mut aic, &mut latch, 0, first.mask_set + 4), 0);
    let mut access = Access::new(0, 0, &mut latch);
    for offset in [
        INFO1,
        INFO3,
        second.mask_set + 8,
        second.irq_config + 4 * 33,
        second.mask_set + 1,
    ] {
        assert!(aic.read(offset, Width::Word, &mut access).is_err());
    }
    assert!(
        aic.set_input(AicInput::new(2, 0), true, &mut access)
            .is_err()
    );
}

#[test]
fn firmware_routing_refusals_are_atomic_across_dies() {
    let (mut config, layout) = two_dies();
    config.default_cpus = 0b10;
    let second = layout.dies[1];
    let mut aic = Aic2::new_with_layout(config, layout).unwrap();
    let first_index = aic.input_index(AicInput::new(0, 3));
    let second_index = aic.input_index(AicInput::new(1, 3));
    // Seed an unadmitted selector so applying the valid prefix
    // would visibly change it. Production never accepts this selector.
    aic.irq_cfg[first_index] = 5;
    let before = aic.irq_cfg.clone();
    for suffix in [[3, 0x10, 2], [0, 0x20, 0], [3, 0x10, 0x20]] {
        let property = [3, 0, 0, suffix[0], suffix[1], suffix[2]];
        assert!(aic.apply_ext_intr_cfg(&property).is_err());
        assert_eq!(aic.irq_cfg, before);
    }
    // A firmware target replacement must also validate the whole word:
    // it cannot preserve an unchecked nonzero delay field.
    aic.irq_cfg[second_index] = 1 << 5;
    let before = aic.irq_cfg.clone();
    assert_eq!(
        aic.apply_ext_intr_cfg(&[3, 0, 0, 3, 0x10, 0]),
        Err(Aic2Error::InvalidConfig(refuse!(
            "nonzero IRQ_CFG DELAY_IDX delay/priority effects are unqualified"
        )))
    );
    assert_eq!(aic.irq_cfg, before);
    aic.irq_cfg[second_index] = 0;
    aic.apply_ext_intr_cfg(&[3, 0, 0, 3, 0x10, 0]).unwrap();
    assert_eq!(aic.irq_cfg[first_index], 0);
    assert_eq!(aic.irq_cfg[second_index], 0);
    let mut latch = InterruptLatch::new();
    write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
    write(&mut aic, &mut latch, second.mask_clear, 1 << 3);
    write(&mut aic, &mut latch, second.software_set, 1 << 3);
    assert!(!latch.pins(0).irq && latch.pins(1).irq);
    assert_eq!(read(&mut aic, &mut latch, 0, EVENT), 0);
    assert_eq!(
        read(&mut aic, &mut latch, 1, EVENT),
        1 << 24 | EVENT_TYPE_IRQ | 3
    );
}

#[test]
fn unqualified_irq_cfg_selectors_and_delays_refuse_without_effects() {
    for version in [2, 3] {
        let (mut config, layout) = two_dies();
        config.version = version;
        config.default_cpus = 0b10;
        for die in 0..2 {
            let bank = layout.dies[die];
            let mut aic = Aic2::new_with_layout(config.clone(), layout.clone()).unwrap();
            let mut latch = InterruptLatch::new();
            write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
            write(&mut aic, &mut latch, bank.mask_clear, 1 << 3);
            write(&mut aic, &mut latch, bank.software_set, 1 << 3);
            write(
                &mut aic,
                &mut latch,
                AIC2_TIMESTAMPS,
                TIMESTAMP_ENABLE | (die as u32) << 24 | 3,
            );
            aic.set_input(
                AicInput::new(die as u8, 3),
                true,
                &mut Access::new(0, 123, &mut latch),
            )
            .unwrap();
            assert!(!latch.pins(0).irq && latch.pins(1).irq);
            let before = (
                aic.irq_cfg.clone(),
                aic.software.clone(),
                aic.hardware.clone(),
                aic.mask.clone(),
                aic.irq_level,
                aic.refusing,
                aic.timestamps
                    .iter()
                    .map(|t| (t.config, t.counter))
                    .collect::<Vec<_>>(),
            );
            let pins = [latch.pins(0), latch.pins(1)];
            for value in (1..=15).chain((1..=7).map(|index| index << 5)) {
                let reason = if value & IRQ_CFG_TARGET != 0 {
                    "nonzero IRQ_CFG TARGET destination selectors are unqualified"
                } else {
                    "nonzero IRQ_CFG DELAY_IDX delay/priority effects are unqualified"
                };
                assert!(matches!(
                    aic.write(bank.irq_config + 12, Width::Word, u64::from(value),
                              &mut Access::new(0, 456, &mut latch)),
                    Err(MmioError::Unsupported { reason: actual, .. }) if actual == reason.into()
                ));
                assert_eq!(
                    (
                        aic.irq_cfg.clone(),
                        aic.software.clone(),
                        aic.hardware.clone(),
                        aic.mask.clone(),
                        aic.irq_level,
                        aic.refusing,
                        aic.timestamps
                            .iter()
                            .map(|t| (t.config, t.counter))
                            .collect::<Vec<_>>()
                    ),
                    before
                );
                assert_eq!([latch.pins(0), latch.pins(1)], pins);
            }
            write(&mut aic, &mut latch, bank.irq_config + 12, 0);
            assert_eq!(read(&mut aic, &mut latch, 0, bank.irq_config + 12), 0);
            assert_eq!(
                read(&mut aic, &mut latch, 1, EVENT),
                (die as u32) << 24 | EVENT_TYPE_IRQ | 3
            );
            assert!(!latch.pins(1).irq);
        }
    }
}

#[test]
fn explicit_layout_refuses_missing_overlapping_unaligned_and_overflowing_banks() {
    let (config, layout) = two_dies();
    for invalid in [
        Aic2Layout {
            max_dies: 1,
            ..layout.clone()
        },
        Aic2Layout {
            max_dies: 16,
            ..layout.clone()
        },
        Aic2Layout {
            dies: vec![],
            ..layout.clone()
        },
        Aic2Layout {
            info1: VERSION,
            ..layout.clone()
        },
        Aic2Layout {
            info3: 0x101,
            ..layout.clone()
        },
        Aic2Layout {
            info1: AIC2_TIMESTAMPS,
            ..layout.clone()
        },
        Aic2Layout {
            info3: u64::MAX - 3,
            ..layout.clone()
        },
    ] {
        assert!(Aic2::new_with_layout(config.clone(), invalid).is_err());
    }
    for offset in [layout.dies[0].mask_set, EVENT, 0x6001, u64::MAX - 3] {
        let mut invalid = layout.clone();
        invalid.dies[1].mask_set = offset;
        assert!(Aic2::new_with_layout(config.clone(), invalid).is_err());
    }
    let mut invalid = layout.clone();
    invalid.dies[0].irq_config += 4;
    assert!(Aic2::new_with_layout(config, invalid).is_err());
    assert!(Aic2DieLayout::contiguous(u64::MAX - 3, 64).is_none());
}

/// AICv3 as the 26A434 `aic,3` driver addresses it: the AICv2's
/// 4096-IRQ arrays at 0x10000, `MASK_CLR` at 0x14600, the event register
/// at the +0x40000 iBoot publishes and the timestamp slots at 0x1000.
#[test]
fn aic3_moves_the_per_die_arrays() {
    let v3 = |irq_config, event_offset| {
        Aic2::new(Aic2Config {
            version: 3,
            nr_irq: NR_IRQ,
            max_irq: AIC2_MAX_IRQ,
            irq_config,
            event_offset,
            timestamps: 16,
            timestamp_base: AIC3_TIMESTAMPS,
            cpus: 1,
            default_cpus: 1,
        })
    };
    let mut aic = v3(AIC3_IRQ_CFG, 0x40000).unwrap();
    assert_eq!(aic.span(), 0x40004);
    let mut latch = InterruptLatch::new();
    write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
    write(&mut aic, &mut latch, 0x14600, 1 << 3);
    write(&mut aic, &mut latch, AIC3_IRQ_CFG + 4 * 3, 0);
    write(&mut aic, &mut latch, AIC3_TIMESTAMPS, TIMESTAMP_ENABLE | 3);
    aic.set_input(
        AicInput::new(0, 3),
        true,
        &mut Access::new(0, 77, &mut latch),
    )
    .unwrap();
    assert_eq!(read(&mut aic, &mut latch, 0, 0x40000), 1 << 16 | 3);
    assert_eq!(
        read(&mut aic, &mut latch, 0, AIC3_TIMESTAMPS + TIMESTAMP_LOW),
        77
    );
    let mut access = Access::new(0, 0, &mut latch);
    assert!(
        aic.read(AIC2_IRQ_CFG, Width::Word, &mut access).is_err(),
        "AICv2's array offset is unallocated"
    );
    assert!(
        aic.read(AIC2_TIMESTAMPS, Width::Word, &mut access).is_err(),
        "AICv2's timestamp offset is unallocated"
    );
    assert!(
        v3(AIC3_IRQ_CFG, EVENT).is_err(),
        "the event overlaps the arrays"
    );
    assert!(v3(CONFIG, 0x40000).is_err());
    assert!(v3(AIC3_IRQ_CFG + 2, 0x40000).is_err());
}

/// An M3 Ultra's AICv3 as the 26A434 driver reads it: CAP0 counts two
/// dies (LAST_DIE 1) of NR_IRQ inputs, MAXNUMIRQ 4096 IRQs per die and
/// MAX_DIE 2, and die 1's arrays follow die 0's at 0x4a00, so its
/// vector 0x15bf is die 1's `MASK_CLR` word at 0x14600 + 0x4a00 + 4 * 45.
#[test]
fn stacked_dies_follow_one_another_at_the_die_stride() {
    let config = Aic2Config {
        version: 3,
        nr_irq: 0x93f,
        max_irq: AIC2_MAX_IRQ,
        irq_config: AIC3_IRQ_CFG,
        event_offset: 0x40000,
        timestamps: 16,
        timestamp_base: AIC3_TIMESTAMPS,
        cpus: 1,
        default_cpus: 1,
    };
    let mut aic = Aic2::stacked(config.clone(), 2).unwrap();
    let mut latch = InterruptLatch::new();
    assert_eq!(read(&mut aic, &mut latch, 0, INFO1), 1 << 24 | 0x93f);
    assert_eq!(read(&mut aic, &mut latch, 0, INFO3), 2 << 24 | 0x1000);
    let (word, bit) = position(0x5bf);
    let die1 = AIC3_IRQ_CFG + AIC2_DIE_STRIDE;
    assert_eq!(die1 + 0x4600, 0x14600 + 0x4a00);
    write(&mut aic, &mut latch, CONFIG, CONFIG_ENABLE);
    write(&mut aic, &mut latch, die1 + 0x4600 + 4 * word as u64, bit);
    write(&mut aic, &mut latch, die1 + 4 * 0x5bf, 0);
    aic.set_input(
        AicInput::new(1, 0x5bf),
        true,
        &mut Access::new(0, 0, &mut latch),
    )
    .unwrap();
    assert_eq!(
        read(&mut aic, &mut latch, 0, 0x40000),
        1 << 24 | EVENT_TYPE_IRQ | 0x5bf
    );
    // A third die, at 0x19400, is not populated: it has no inputs and
    // no registers.
    assert!(
        aic.set_input(
            AicInput::new(2, 0),
            true,
            &mut Access::new(0, 0, &mut latch)
        )
        .is_err()
    );
    let mut access = Access::new(0, 0, &mut latch);
    assert!(
        aic.read(die1 + AIC2_DIE_STRIDE, Width::Word, &mut access)
            .is_err()
    );
    // The event register must follow the last die's arrays.
    let crowded = Aic2Config {
        event_offset: die1 + AIC2_DIE_STRIDE - 4,
        ..config
    };
    assert!(Aic2::stacked(crowded, 2).is_err());
}
