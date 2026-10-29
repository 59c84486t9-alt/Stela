use super::super::super::{
    Packets,
    counters::{Claim, CopyStep},
    power::DeviceTable,
};
use super::super::ingestion::{Call, Request, Value};
use super::super::owner::Completion;
use super::*;
use alloc::{rc::Rc, vec::Vec};
use core::cell::Cell;
use stela_contracts::refuse;
use {
    crate::ptd::Ptd, crate::ptd::transport::notifications::LocalNotifications,
    crate::ptd::transport::notifications::NativeProfile, stela_contracts::bus::LifecycleState,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::Width,
    stela_contracts::interrupt::InterruptLatch, stela_soc_data::ptd::Geometry,
    stela_soc_data::ptd::Range, stela_soc_data::ptd::UPDATE_OFFSET,
};

struct NoProviders;
impl Backend for NoProviders {
    fn call(&mut self, _: &Request, _: &Call, _: &mut Access<'_>) -> Completion<Value> {
        Completion::Refused(refuse!("authored actual provider absent"))
    }
}
fn d() -> Descriptor {
    super::super::profile::tests::fixture().descriptors()[1].clone()
}
fn ctx(selected: u128) -> CounterContext {
    CounterContext {
        selected,
        evaluation_tick: 480,
        current_packet: Packets([0x43, 0, 0, 0, 0, 0]),
        activity: 1,
        buffer_index: 0,
        state_index: 0,
        previous_state_index: 0,
        evaluated: 1,
        pending: 0,
    }
}
fn setup() -> (Frames, LocalNotifications, InterruptLatch) {
    let range = Range {
        id: 9,
        start: 16,
        count: 144,
        name: "authored AMCC range".into(),
    };
    let live = LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: true,
    };
    let local = Ptd::initialized_local_profile(
        NativeProfile::T8112,
        Geometry::new((0x23b3c0000, 0x20000), (0x23b3d0000, 0x4000)).unwrap(),
        core::slice::from_ref(&range),
        live,
    )
    .unwrap()
    .1;
    let ids = [
        1, 2, 16, 17, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 18,
    ];
    let bytes: Vec<_> = ids
        .into_iter()
        .enumerate()
        .flat_map(|(i, id)| {
            let mut row = [0u32; 31];
            row[0] = id;
            row[3] = if i == 1 {
                14
            } else if (4..=7).contains(&i) {
                1
            } else {
                0
            };
            row.into_iter().flat_map(u32::to_le_bytes)
        })
        .collect();
    let table = DeviceTable::from_properties(&bytes, &[0; 8], None).unwrap();
    let frames = Frames::initialized(
        Claim::new(local.clone(), range, Rc::new(Cell::new(true))),
        &table,
        &[0xa5; 144],
    )
    .unwrap();
    (frames, local, InterruptLatch::new())
}
fn publish(local: &LocalNotifications, entry: u32, value: u64, latch: &mut InterruptLatch) {
    local
        .bank()
        .clone()
        .write(
            UPDATE_OFFSET + u64::from(entry) * 8,
            Width::Double,
            value,
            &mut Access::new(0, 24, latch),
        )
        .unwrap();
}
fn copied(
    frames: &mut Frames,
    local: &LocalNotifications,
    latch: &mut InterruptLatch,
) -> (Captured, Copied, u128) {
    for (entry, value) in [(16, 70 | (100 << 32)), (32, 0x1234), (124, 0x9876)] {
        publish(local, entry, value, latch);
    }
    let captured = frames.capture_pending(&Access::new(0, 48, latch)).unwrap();
    let selected = captured.bits(16, 112).unwrap() & d().selection().bits();
    frames
        .begin_copy(&captured, 1, d().selection().bits())
        .unwrap();
    while frames.step(&mut Access::new(0, 49, latch)).unwrap() != CopyStep::Complete {}
    (captured, frames.finish_copy().unwrap(), selected)
}
fn run(
    o: &mut Owner<NoProviders>,
    frames: &Frames,
    latch: &mut InterruptLatch,
) -> Result<EffectValue, Error> {
    match o.advance(frames, &mut Access::new(0, 50, latch))? {
        Progress::Complete(value) => Ok(value),
        _ => panic!("unexpected authored asynchronous AMCC provider"),
    }
}
#[test]
fn generic_capture_precedes_absent_special_descriptors_and_arrival() {
    let (mut frames, local, mut latch) = setup();
    let (capture, copy, selected) = copied(&mut frames, &local, &mut latch);
    let mut o =
        Owner::initialized_software(Configuration::t8112(&d()).unwrap(), NoProviders).unwrap();
    o.begin_capture(
        &frames,
        &capture,
        Input::Copied(copy),
        &d(),
        ctx(selected),
        1,
    )
    .unwrap();
    assert_eq!(o.arrivals(), 0);
    assert!(o.statistics().iter().flatten().all(Option::is_none));
    let value = run(&mut o, &frames, &mut latch).unwrap();
    assert!(matches!(
        value,
        EffectValue::Hook {
            buffer_index: 1,
            ..
        }
    ));
    assert_eq!(frames.progress().consumed, 3);
    assert_eq!(o.packet_low(), 3);
    assert_eq!(o.arrivals(), (1u128 << 0) | (1u128 << 92));
    assert_eq!(o.generic().metrics(), [[0; 3]; 2]); // Generic Postprocess has not run.
    let mut context = ctx(selected);
    products(&mut context, value).unwrap();
    o.begin_postprocess(&frames, &d(), context, 1).unwrap();
    run(&mut o, &frames, &mut latch).unwrap();
    assert_eq!(o.generic().metrics()[1], [560, 800, 1360]);
    assert_eq!(o.query(Query::Slot50, 1, 1, 0).unwrap(), 560);
    assert_eq!(
        o.query(Query::Slot58, 1, 1, 0).unwrap(),
        o.generic().rates()[1][0]
    );
    assert!(o.begin_postprocess(&frames, &d(), context, 1).is_err());
    assert_eq!(frames.progress().consumed, 3);
}
#[test]
fn prior_pending_only_capture_allows_the_next_cycle_without_optional_post() {
    let (mut frames, local, mut latch) = setup();
    let (first, copy, selected) = copied(&mut frames, &local, &mut latch);
    let mut o =
        Owner::initialized_software(Configuration::t8112(&d()).unwrap(), NoProviders).unwrap();
    let mut pending = ctx(selected);
    pending.evaluated = 0;
    pending.pending = 1;
    o.begin_capture(&frames, &first, Input::Copied(copy), &d(), pending, 1)
        .unwrap();
    let first_products = run(&mut o, &frames, &mut latch).unwrap();
    products(&mut pending, first_products).unwrap();
    assert_eq!(pending.buffer_index, 0);
    assert_eq!(o.generic().metrics(), [[0; 3]; 2]);
    assert_eq!(frames.progress().consumed, 3);

    let (second, copy, selected) = copied(&mut frames, &local, &mut latch);
    let retained = frames.retain_cells(1).unwrap();
    let mut bad = ctx(0);
    bad.activity = 0;
    assert!(
        o.begin_capture(&frames, &second, Input::Retained(retained), &d(), bad, 1)
            .is_err()
    );
    assert_eq!(o.awaiting_post.as_ref().unwrap().context, pending);
    assert!(o.batch.is_none());

    o.begin_capture(
        &frames,
        &second,
        Input::Copied(copy),
        &d(),
        ctx(selected),
        1,
    )
    .unwrap();
    let mut current = ctx(selected);
    products(&mut current, run(&mut o, &frames, &mut latch).unwrap()).unwrap();
    assert_eq!(current.buffer_index, 1);
    assert_eq!(frames.progress().consumed, 6);
    let retained = frames.retain_cells(1).unwrap();
    assert!(
        o.begin_capture(
            &frames,
            &second,
            Input::Retained(retained),
            &d(),
            current,
            1,
        )
        .is_err()
    ); // Evaluated Capture still requires its post hook.
    assert!(o.begin_postprocess(&frames, &d(), pending, 1).is_err());
    o.begin_postprocess(&frames, &d(), current, 1).unwrap();
    run(&mut o, &frames, &mut latch).unwrap();
    assert_eq!(frames.progress().consumed, 6);
}
#[test]
fn empty_mc_event_mask_reads_no_frames_and_preserves_initialized_samples() {
    let (frames, _, _) = setup();
    let mut o =
        Owner::initialized_software(Configuration::t8112(&d()).unwrap(), NoProviders).unwrap();
    assert!(o.generic.cells(&frames).is_err());
    let mut destination = [[0x55; GROUP_BYTES]; GROUPS];
    assert_eq!(
        o.copy_completed_groups(&frames, 0, &mut destination),
        Ok(Some(0))
    );
    assert_eq!(destination, [[0x55; GROUP_BYTES]; GROUPS]);
    assert_eq!(o.arrivals(), 0);
}
#[test]
fn mc_event_copy_preflights_storage_and_clears_only_low96_arrivals() {
    let (mut frames, local, mut latch) = setup();
    let (capture, copy, selected) = copied(&mut frames, &local, &mut latch);
    let mut o =
        Owner::initialized_software(Configuration::t8112(&d()).unwrap(), NoProviders).unwrap();
    let mut context = ctx(selected);
    o.begin_capture(&frames, &capture, Input::Copied(copy), &d(), context, 1)
        .unwrap();
    products(&mut context, run(&mut o, &frames, &mut latch).unwrap()).unwrap();
    let mut destination = [[0x55; GROUP_BYTES]; GROUPS];
    assert!(
        o.copy_completed_groups(&frames, o.arrivals(), &mut destination)
            .is_err()
    );
    assert_eq!(destination, [[0x55; GROUP_BYTES]; GROUPS]);
    o.begin_postprocess(&frames, &d(), context, 1).unwrap();
    run(&mut o, &frames, &mut latch).unwrap();
    // Authored high-bit state checks the clear width, not a new producer.
    o.arrived = (1 << 100) | 1 | (1 << 92);
    let expected = o.arrivals();
    assert_eq!(
        o.copy_completed_groups(&frames, 1, &mut destination),
        Ok(None)
    );
    assert_eq!(destination, [[0x55; GROUP_BYTES]; GROUPS]);
    let (foreign, _, _) = setup();
    assert!(
        o.copy_completed_groups(&foreign, expected, &mut destination)
            .is_err()
    );
    assert_eq!(destination, [[0x55; GROUP_BYTES]; GROUPS]);
    assert_eq!(o.arrivals(), expected);
    assert_eq!(
        o.copy_completed_groups(&frames, expected, &mut destination),
        Ok(Some(1 | (1 << 23)))
    );
    assert_eq!(o.arrivals(), 1 << 100);
    assert_eq!(
        u64::from_le_bytes(destination[0][..8].try_into().unwrap()),
        0x1234
    );
    assert_eq!(
        u64::from_le_bytes(destination[23][..8].try_into().unwrap()),
        0x9876
    );
    assert_eq!(destination[1], [0x55; GROUP_BYTES]);
    assert_eq!(frames.progress().consumed, 3);
}
#[test]
fn group_views_copy_kept_value_metadata_without_reconsume_or_early_copy() {
    let (mut frames, local, mut latch) = setup();
    let (capture, copy, selected) = copied(&mut frames, &local, &mut latch);
    let mut o =
        Owner::initialized_software(Configuration::t8112(&d()).unwrap(), NoProviders).unwrap();
    o.begin_capture(
        &frames,
        &capture,
        Input::Copied(copy),
        &d(),
        ctx(selected),
        1,
    )
    .unwrap();
    run(&mut o, &frames, &mut latch).unwrap();
    let mut destination = [0x55; 64];
    assert!(o.group(&frames, 24).is_err());
    assert!(
        o.group(&frames, 0)
            .unwrap()
            .copy_into_existing(&mut destination[..63])
            .is_err()
    );
    assert_eq!(destination, [0x55; 64]);
    o.group(&frames, 0)
        .unwrap()
        .copy_into_existing(&mut destination)
        .unwrap();
    assert_eq!(
        u64::from_le_bytes(destination[..8].try_into().unwrap()),
        0x1234
    );
    assert_eq!(
        u64::from_le_bytes(destination[8..16].try_into().unwrap()),
        (0xa5u64 << 56) | (1 << 54) | 24
    );
    assert_eq!(
        u64::from_le_bytes(destination[24..32].try_into().unwrap()),
        0xa5u64 << 56
    );
    o.group(&frames, 23)
        .unwrap()
        .copy_into_existing(&mut destination)
        .unwrap();
    assert_eq!(
        u64::from_le_bytes(destination[..8].try_into().unwrap()),
        0x9876
    );
    assert_eq!(frames.progress().consumed, 3);
    let (foreign, _, _) = setup();
    assert!(o.group(&foreign, 0).is_err());
    let next = frames
        .capture_pending(&Access::new(0, 51, &mut latch))
        .unwrap();
    frames.begin_copy(&next, 1, 0).unwrap();
    frames.finish_copy().unwrap();
    assert!(o.group(&frames, 0).is_err());
}
#[test]
fn unknown_special_provider_keeps_generic_and_local_prefix_without_arrival() {
    let (mut frames, local, mut latch) = setup();
    let (capture, copy, selected) = copied(&mut frames, &local, &mut latch);
    let mut refs = [CounterReference::default(); 12];
    refs[0] = CounterReference {
        kind: 2,
        provider: 7,
        start: 0,
        width: 32,
        flags: 1,
        scale: 0,
    };
    refs[1] = CounterReference {
        kind: 3,
        ..CounterReference::default()
    };
    let mut o = Owner::initialized_software(
        Configuration::declared_t8112(&d(), refs).unwrap(),
        NoProviders,
    )
    .unwrap();
    o.begin_capture(
        &frames,
        &capture,
        Input::Copied(copy),
        &d(),
        ctx(selected),
        1,
    )
    .unwrap();
    assert!(matches!(
        run(&mut o, &frames, &mut latch),
        Err(Error::Refused(_))
    ));
    assert_eq!(
        o.pairs[0][0],
        Pair {
            value: 70,
            tick: 480
        }
    );
    let before = o.pairs;
    assert_eq!(o.packet_low(), 0);
    assert_eq!(o.arrivals(), 0);
    assert!(run(&mut o, &frames, &mut latch).is_err());
    assert_eq!(o.pairs, before);
    assert_eq!(frames.progress().consumed, 3);
    frames
        .capture_pending(&Access::new(0, 53, &mut latch))
        .unwrap();
    assert!(matches!(
        run(&mut o, &frames, &mut latch),
        Err(Error::Contract(_))
    ));
    assert_eq!(o.arrivals(), 0);
}
#[test]
fn kept_activity_zero_does_not_copy_again_or_derive_arrival_from_expected() {
    let (mut frames, local, mut latch) = setup();
    publish(&local, 32, 777, &mut latch);
    let capture = frames
        .capture_pending(&Access::new(0, 48, &mut latch))
        .unwrap();
    let selected = capture.bits(16, 112).unwrap() & d().selection().bits();
    frames.begin_discard(&capture, 1, selected).unwrap();
    while frames.step(&mut Access::new(0, 49, &mut latch)).unwrap() != CopyStep::Complete {}
    frames.finish_discard().unwrap();
    let before = frames.progress();
    let retained = frames.retain_cells(1).unwrap();
    let mut context = ctx(selected);
    context.activity = 0;
    let mut o =
        Owner::initialized_software(Configuration::t8112(&d()).unwrap(), NoProviders).unwrap();
    o.begin_capture(
        &frames,
        &capture,
        Input::Retained(retained),
        &d(),
        context,
        1,
    )
    .unwrap();
    run(&mut o, &frames, &mut latch).unwrap();
    assert_eq!(frames.progress(), before);
    assert_eq!(o.arrivals(), 1);
    let mut out = [0xff; 64];
    o.group(&frames, 0)
        .unwrap()
        .copy_into_existing(&mut out)
        .unwrap();
    assert_eq!(u64::from_le_bytes(out[..8].try_into().unwrap()), 0); // Declared software cell, not published777.
    assert_eq!(
        u64::from_le_bytes(out[8..16].try_into().unwrap()),
        0xa5u64 << 56
    );
}
#[test]
fn foreign_capture_expected_masks_and_wrong_ordinal_refuse_before_source_mutation() {
    let (mut frames, local, mut latch) = setup();
    let (capture, copy, selected) = copied(&mut frames, &local, &mut latch);
    let (mut foreign, _, mut fl) = setup();
    let forged = foreign
        .capture_pending(&Access::new(0, 48, &mut fl))
        .unwrap();
    let mut o =
        Owner::initialized_software(Configuration::t8112(&d()).unwrap(), NoProviders).unwrap();
    assert!(
        o.begin_capture(
            &frames,
            &forged,
            Input::Copied(copy),
            &d(),
            ctx(selected),
            1
        )
        .is_err()
    );
    assert_eq!(o.arrivals(), 0);
    assert!(o.batch.is_none());
    let retained = frames.retain_cells(1).unwrap();
    let mut context = ctx(u128::MAX);
    context.activity = 0;
    assert!(
        o.begin_capture(
            &frames,
            &capture,
            Input::Retained(retained),
            &d(),
            context,
            1
        )
        .is_err()
    );
    let other = super::super::profile::tests::fixture().descriptors()[0].clone();
    assert!(Configuration::t8112(&other).is_err());
    assert!(o.batch.is_none());
}
#[test]
fn source_special_postprocess_scaling_low32_rates_fallback_and_histograms() {
    let mut refs = [CounterReference::default(); 12];
    refs[0] = CounterReference {
        kind: 2,
        provider: 0,
        start: 0,
        width: 32,
        flags: 1,
        scale: 3,
    };
    refs[1] = CounterReference {
        kind: 2,
        provider: 0,
        start: 32,
        width: 32,
        flags: 1,
        scale: 0,
    };
    let mut o = Owner::initialized_software(
        Configuration::declared_t8112(&d(), refs).unwrap(),
        NoProviders,
    )
    .unwrap();
    o.pairs[0] = [
        Pair {
            value: u64::MAX - 7,
            tick: 0,
        },
        Pair::default(),
    ];
    o.pairs[1] = [
        Pair {
            value: 100,
            tick: 0,
        },
        Pair::default(),
    ];
    let mut context = ctx(0);
    context.buffer_index = 1;
    for i in 0..3 {
        o.post_metric(i, context).unwrap();
    }
    let delta = (u64::MAX - 7).wrapping_mul(3);
    let micros = o.config.generic.periods().1;
    let rate = ((delta.wrapping_mul(1_000_000) / micros) >> 20) as u32;
    assert_eq!(
        o.metrics[0],
        [delta as u32, 100, (delta as u32).wrapping_add(100)]
    );
    assert_eq!(o.rates[0][0], rate);
    assert_eq!(o.rates[0][2], o.rates[0][0].wrapping_add(o.rates[0][1]));
    let stat = o.statistics[0][0].as_ref().unwrap();
    assert_eq!(stat.bins().len(), 32);
    assert_eq!(stat.retained_run(), ((rate >> 12).min(31), 1));
    assert_eq!(o.query(Query::Slot50, 1, 2, 0).unwrap(), rate);
    assert_eq!(o.query(Query::Slot58, 1, 2, 0).unwrap(), delta as u32);
}
#[test]
fn query_slot50_uses_source_fallback_sum_instead_of_generic_rate_alias() {
    let mut o =
        Owner::initialized_software(Configuration::t8112(&d()).unwrap(), NoProviders).unwrap();
    o.rates = [[u32::MAX, 7, 9], [5, 8, 10], [6, 9, 11], [7, 10, 12]];
    o.metrics = [[1, 2, 3], [4, 5, 6], [7, 8, 9], [10, 11, 12]];
    assert_eq!(o.query(Query::Slot50, 1, 0, 0).unwrap(), 17);
    assert_eq!(o.query(Query::Slot58, 1, 0, 0).unwrap(), 22);
    assert_eq!(o.query(Query::Slot50, 1, 1, 0).unwrap(), 0); // Configured generic cell, not sum.
    assert_eq!(o.query(Query::Slot50, 0, u32::MAX, u32::MAX), Ok(0));
    assert!(o.query(Query::Slot50, 1, 6, 0).is_err());
    assert!(o.query(Query::Slot58, 1, 0, 3).is_err());
}
#[test]
fn old_copy_cannot_claim_a_new_equal_timestamp_capture_with_equal_selection() {
    let (mut frames, local, mut latch) = setup();
    let (_first, copy, selected) = copied(&mut frames, &local, &mut latch);
    for (entry, value) in [(16, 9), (32, 8), (124, 7)] {
        publish(&local, entry, value, &mut latch);
    }
    let second = frames
        .capture_pending(&Access::new(0, 48, &mut latch))
        .unwrap();
    assert_eq!(
        second.bits(16, 112).unwrap() & d().selection().bits(),
        selected
    );
    assert!(frames.cells(&copy).is_ok());
    let mut o =
        Owner::initialized_software(Configuration::t8112(&d()).unwrap(), NoProviders).unwrap();
    assert!(
        o.begin_capture(
            &frames,
            &second,
            Input::Copied(copy),
            &d(),
            ctx(selected),
            1
        )
        .is_err()
    );
    assert!(o.batch.is_none());
    assert_eq!(o.arrivals(), 0);
    assert_eq!(frames.progress().consumed, 3);
}
#[test]
fn special_delta_wrap_and_zero_microsecond_rate_keep_source_products() {
    let mut refs = [CounterReference::default(); 12];
    refs[0] = CounterReference {
        kind: 2,
        width: 64,
        ..CounterReference::default()
    };
    let mut o = Owner::initialized_software(
        Configuration::declared_t8112(&d(), refs).unwrap(),
        NoProviders,
    )
    .unwrap();
    o.pairs[0] = [
        Pair {
            value: u64::MAX - 3,
            tick: u64::MAX - 47,
        },
        Pair { value: 5, tick: 48 },
    ];
    let mut context = ctx(0);
    context.buffer_index = 2;
    o.post_metric(0, context).unwrap();
    assert_eq!(o.metrics[0][0], 9);
    assert_eq!(o.rates[0][0], 2);
    o.pairs[0] = [
        Pair {
            value: 10,
            tick: 96,
        },
        Pair {
            value: 20,
            tick: 96,
        },
    ];
    o.post_metric(0, context).unwrap();
    assert_eq!(o.metrics[0][0], 10);
    assert_eq!(o.rates[0][0], 0);
}
#[test]
fn arrival_register_shifts_preserve_zero_prefix_and_high_word_modulo_behavior() {
    let value = 0x778899aabbccddee0011223344556677u128;
    assert_eq!(shift_arrival(value, 2), value >> 16);
    assert_eq!(shift_arrival(value, 8), value >> 64);
    assert_eq!(shift_arrival(value, 16), 0);
    let low = value as u64 | (value >> 64) as u64;
    assert_eq!(
        shift_arrival(value, 0),
        u128::from(low) | (value & (!0u128 << 64))
    );
}
#[test]
#[cfg(feature = "std")]
#[ignore = "oracle: STELA_TEST_MCC_J473_DT, STELA_TEST_PMP_T8112"]
fn original_t8112_amcc_specialized_descriptors_query_and_histogram_operands() {
    use sha2::{Digest, Sha256};
    let p = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&p)),
        "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
    );
    let word =
        |va: usize| u32::from_le_bytes(p[va - 0xfff000..va - 0xfff000 + 4].try_into().unwrap());
    let config = Configuration::t8112(&d()).unwrap();
    for (i, r) in config.references().iter().enumerate() {
        let raw = [r.kind, r.provider, r.start, r.width, r.flags, r.scale];
        assert_eq!(
            raw,
            core::array::from_fn(|j| word(0x1046ab8 + 0x27c + 24 * i + 4 * j))
        );
    }
    assert_eq!(word(0x1046ab8 + 0x278), 2);
    assert_eq!((word(0x1004cdc) >> 10) & 0xfff, 0x3b0 / 4);
    assert_eq!((word(0x1004d14) >> 10) & 0xfff, 0x3c8 / 4);
    assert_eq!((word(0x101c1d4) >> 5) & 0xffff, 32);
    let dt = std::fs::read(std::env::var("STELA_TEST_MCC_J473_DT").unwrap()).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&dt)),
        "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
    );
    let root = stela_contracts::adt::Node::root(&dt).unwrap();
    let nub = root
        .child("arm-io")
        .unwrap()
        .child("pmp")
        .unwrap()
        .child("iop-pmp-nub")
        .unwrap();
    assert_eq!(
        u32::from_le_bytes(
            nub.property("soc-device").unwrap()[124 + 12..124 + 16]
                .try_into()
                .unwrap()
        ),
        14
    );
}
