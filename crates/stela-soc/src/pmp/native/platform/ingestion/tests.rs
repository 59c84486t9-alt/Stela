use super::super::super::counters::{Claim, CopyStep};
use super::super::super::power::DeviceTable;
use super::*;
use core::cell::Cell;
use stela_contracts::refuse;
use {
    crate::ptd::Ptd, crate::ptd::transport::notifications::LocalNotifications,
    crate::ptd::transport::notifications::NativeProfile, stela_contracts::bus::LifecycleState,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::Width,
    stela_contracts::interrupt::InterruptLatch, stela_soc_data::ptd::Geometry,
    stela_soc_data::ptd::Range, stela_soc_data::ptd::UPDATE_OFFSET,
};
struct TestBackend {
    calls: Vec<(Request, Call)>,
    busy: bool,
    refuse_tail: bool,
    retired_tail: bool,
    bad: bool,
}
impl TestBackend {
    fn new() -> Self {
        Self {
            calls: Vec::new(),
            busy: false,
            refuse_tail: false,
            retired_tail: false,
            bad: false,
        }
    }
}
impl Backend for TestBackend {
    fn call(&mut self, r: &Request, c: &Call, _: &mut Access<'_>) -> Completion<Value> {
        self.calls.push((r.clone(), c.clone()));
        if self.busy {
            self.busy = false;
            return Completion::Busy { deadline: Some(9) };
        }
        if matches!(c, Call::ControlTail { .. }) && self.refuse_tail {
            self.refuse_tail = false;
            return Completion::Refused(refuse!("authored missing auxiliary effect"));
        }
        let value = if self.bad {
            Value::Complete
        } else {
            match c {
                Call::ProviderTuple { index, .. } => Value::Pair(Pair {
                    value: u64::from(100 + index),
                    tick: 2000 + u64::from(*index),
                }),
                Call::ProviderValue { index, .. } => Value::Word(300 + u64::from(*index)),
                Call::ExtendedFrame { index, .. } => Value::Pair(Pair {
                    value: 400 + u64::from(*index),
                    tick: 3000 + u64::from(*index),
                }),
                Call::ExtendedCount { .. } => Value::Word(24),
                Call::Clock => Value::Word(700),
                Call::State => Value::Word(2),
                Call::InitializedScale { .. } => Value::Word(0),
                Call::Coefficients { .. } => Value::Coefficients {
                    active: vec![2; 3],
                    inactive: vec![3; 3],
                    extra: vec![4; 3],
                },
                Call::OutputLayout { .. } => Value::Layout {
                    start: 240,
                    count: 1,
                },
                _ => Value::Complete,
            }
        };
        let refusal = if matches!(c, Call::ControlTail { .. }) && self.retired_tail {
            self.retired_tail = false;
            Some(refuse!("authored retired auxiliary refusal"))
        } else {
            None
        };
        Completion::Retired { value, refusal }
    }
}
fn setup() -> (Frames, LocalNotifications, InterruptLatch) {
    let range = Range {
        id: 9,
        start: 16,
        count: 144,
        name: "authored generic source packet".into(),
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
    let counts = [0, 14, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let raw: Vec<_> = ids
        .into_iter()
        .zip(counts)
        .flat_map(|(id, count)| {
            let mut w = [0u32; 31];
            w[0] = id;
            w[3] = count;
            w.into_iter().flat_map(u32::to_le_bytes)
        })
        .collect();
    let table = DeviceTable::from_properties(&raw, &[0; 8], None).unwrap();
    let frames = Frames::initialized(
        Claim::new(local.clone(), range, Rc::new(Cell::new(true))),
        &table,
        &[0xa5; 144],
    )
    .unwrap();
    (frames, local, InterruptLatch::new())
}
fn copied(
    frames: &mut Frames,
    local: &LocalNotifications,
    ordinal: u32,
    value: u64,
    latch: &mut InterruptLatch,
) -> Copied {
    let layout = frames.layout(ordinal).unwrap();
    if layout.count != 0 {
        local
            .bank()
            .clone()
            .write(
                UPDATE_OFFSET + u64::from(layout.start) * 8,
                Width::Double,
                value,
                &mut Access::new(0, 77, latch),
            )
            .unwrap();
    }
    let capture = frames.capture_pending(&Access::new(0, 99, latch)).unwrap();
    frames.begin_copy(&capture, ordinal, u128::MAX).unwrap();
    while frames.step(&mut Access::new(0, 100, latch)).unwrap() != CopyStep::Complete {}
    frames.finish_copy().unwrap()
}
fn context() -> CounterContext {
    CounterContext {
        selected: 1,
        evaluation_tick: 500,
        current_packet: super::super::super::Packets([0x403, 0, 0x403, 0, 0, 0]),
        activity: 1,
        buffer_index: 0,
        state_index: 0,
        previous_state_index: 0,
        evaluated: 1,
        pending: 0,
    }
}
fn descriptor(i: usize) -> Descriptor {
    super::super::profile::tests::fixture().descriptors[i].clone()
}
fn run(
    owner: &mut Owner<TestBackend>,
    frames: &Frames,
    latch: &mut InterruptLatch,
) -> Result<Progress, Error> {
    owner.advance(frames, &mut Access::new(0, 100, latch))
}
#[test]
fn copied_frames_drive_bitfields_buffers_rates_and_query() {
    let (mut frames, local, mut latch) = setup();
    let d = descriptor(1);
    let receipt = copied(&mut frames, &local, 1, 70 | (100 << 32), &mut latch);
    let mut o = Owner::initialized_software(Configuration::t8112(&d).unwrap(), TestBackend::new());
    let mut c = context();
    o.begin_capture(&frames, receipt, &d, c, 1).unwrap();
    assert_eq!(
        run(&mut o, &frames, &mut latch),
        Ok(Progress::Complete(EffectValue::Hook {
            buffer_index: 1,
            state_index: 0,
            previous_state_index: 0
        }))
    );
    assert_eq!(
        o.base[3][0],
        Pair {
            value: 70,
            tick: 500
        }
    );
    assert_eq!(o.base[4][0].value, 100);
    assert_eq!(o.cells(&frames).unwrap()[0].value, 70 | (100 << 32));
    c.buffer_index = 1;
    o.begin_postprocess(&frames, &d, c, 1).unwrap();
    run(&mut o, &frames, &mut latch).unwrap();
    assert_eq!(o.metrics()[1], [560, 800, 1360]);
    assert_eq!(o.query(1, 1, 0), Ok(76));
    assert_eq!(o.query(0, 1, 0), Ok(0));
    assert!(o.query(1, 2, 0).is_err());
    assert_eq!(o.backend.calls.len(), 0);
    assert!(o.begin_postprocess(&frames, &d, c, 1).is_err());
}
#[test]
fn source_zero_activity_reads_kept_storage_without_copying_or_consuming_pending_entries() {
    let (mut frames, local, mut latch) = setup();
    let d = descriptor(1);
    let mut o = Owner::initialized_software(Configuration::t8112(&d).unwrap(), TestBackend::new());
    let c = CounterContext {
        activity: 0,
        ..context()
    };
    let before = frames.progress();
    local
        .bank()
        .clone()
        .write(
            UPDATE_OFFSET + 16 * 8,
            Width::Double,
            123,
            &mut Access::new(0, 1, &mut latch),
        )
        .unwrap();
    o.begin_retained_capture(&frames, frames.retain_cells(1).unwrap(), &d, c, 1)
        .unwrap();
    assert!(matches!(
        run(&mut o, &frames, &mut latch),
        Ok(Progress::Complete(_))
    ));
    assert_eq!(frames.progress(), before);
    assert!(
        o.cells(&frames)
            .unwrap()
            .iter()
            .all(|f| !f.copied && f.value == 0)
    );
    assert_eq!(
        o.base[3][0],
        Pair {
            value: 0,
            tick: c.evaluation_tick
        }
    );
    assert_eq!(
        local
            .bank()
            .clone()
            .consume_entry(16, &mut Access::new(0, 2, &mut latch))
            .unwrap()
            .value,
        123
    );
    let products = o.products();
    let next = CounterContext {
        buffer_index: products.0,
        ..c
    };
    copied(&mut frames, &local, 1, 456, &mut latch);
    assert!(o.cells(&frames).is_err());
    assert!(o.begin_postprocess(&frames, &d, next, 1).is_err());
    assert_eq!(o.products(), products);
}
#[test]
fn source_no_counter_slice_skips_bulk_and_invalid_kept_constructors_preserve_state() {
    let (frames, _, _) = setup();
    let d = descriptor(2);
    let mut o = Owner::initialized_software(Configuration::t8112(&d).unwrap(), TestBackend::new());
    let c = context();
    o.begin_retained_capture(&frames, frames.retain_cells(2).unwrap(), &d, c, 1)
        .unwrap();
    assert!(o.cells(&frames).unwrap().is_empty());
    assert_eq!(frames.progress().completed_copies, 0);
    let (frames, _, _) = setup();
    let d = descriptor(1);
    let mut o = Owner::initialized_software(Configuration::t8112(&d).unwrap(), TestBackend::new());
    assert!(
        o.begin_retained_capture(&frames, frames.retain_cells(1).unwrap(), &d, context(), 1)
            .is_err()
    );
    assert!(o.receipt.is_none());
    assert!(!o.awaiting_post);
    assert_eq!(o.products().0, 0);
    o.serial = u64::MAX;
    assert!(
        o.begin_retained_capture(
            &frames,
            frames.retain_cells(1).unwrap(),
            &d,
            CounterContext {
                activity: 0,
                ..context()
            },
            1
        )
        .is_err()
    );
    assert!(o.receipt.is_none());
    assert_eq!(frames.progress().consumed, 0);
}
#[test]
fn provider_tuple_sums_and_auxiliary_refusal_keep_exact_prefix() {
    let (mut frames, local, mut latch) = setup();
    let d = descriptor(4);
    let receipt = copied(&mut frames, &local, 4, 0, &mut latch);
    let mut cfg = Configuration::t8112(&d).unwrap();
    cfg.references[0].flags = 6;
    let mut backend = TestBackend::new();
    backend.refuse_tail = true;
    let mut o = Owner::initialized_software(cfg, backend);
    o.begin_capture(&frames, receipt, &d, context(), 1).unwrap();
    assert_eq!(
        run(&mut o, &frames, &mut latch),
        Err(Error::Refused(refuse!("authored missing auxiliary effect")))
    );
    assert_eq!(
        o.base[0][0],
        Pair {
            value: 102 + 103 + 104,
            tick: 2002
        }
    );
    let n = o.backend.calls.len();
    let request = o.backend.calls.last().unwrap().0.clone();
    assert_eq!(o.products().0, 0);
    run(&mut o, &frames, &mut latch).unwrap();
    assert_eq!(o.products().0, 1);
    assert_eq!(o.backend.calls.len(), n + 1);
    assert!(request.same_operation(&o.backend.calls[n].0));
}
#[test]
fn auxiliary_tail_keeps_activation_distinct_from_activity() {
    let (mut frames, local, mut latch) = setup();
    let d = descriptor(4);
    let receipt = copied(&mut frames, &local, 4, 0, &mut latch);
    let mut backend = TestBackend::new();
    backend.refuse_tail = true;
    let mut o = Owner::initialized_software(Configuration::t8112(&d).unwrap(), backend);
    o.begin_capture(&frames, receipt, &d, context(), 7).unwrap();
    assert!(matches!(
        run(&mut o, &frames, &mut latch),
        Err(Error::Refused(_))
    ));
    let Call::ControlTail {
        context,
        activation,
        ..
    } = &o.backend.calls.last().unwrap().1
    else {
        panic!("the actual auxiliary tail was not reached");
    };
    assert_eq!((*activation, context.activity), (7, 1));
}
#[test]
fn retired_callback_refusal_never_replays_and_stale_receipts_never_read() {
    let (mut frames, local, mut latch) = setup();
    let d = descriptor(4);
    let receipt = copied(&mut frames, &local, 4, 0, &mut latch);
    let mut backend = TestBackend::new();
    backend.retired_tail = true;
    let mut o = Owner::initialized_software(Configuration::t8112(&d).unwrap(), backend);
    o.begin_capture(&frames, receipt, &d, context(), 1).unwrap();
    assert!(run(&mut o, &frames, &mut latch).is_err());
    let n = o.backend.calls.len();
    run(&mut o, &frames, &mut latch).unwrap();
    assert_eq!(o.backend.calls.len(), n);
    let c = CounterContext {
        buffer_index: 1,
        ..context()
    };
    o.begin_postprocess(&frames, &d, c, 1).unwrap();
    let _new = copied(&mut frames, &local, 4, 1, &mut latch);
    assert!(matches!(
        run(&mut o, &frames, &mut latch),
        Err(Error::Contract(_))
    ));
    assert_eq!(o.backend.calls.len(), n);
    assert!(o.cells(&frames).is_err());
}
#[test]
fn tuple_callback_shape_and_cursor_exhaustion_fail_before_fabrication() {
    let (mut frames, local, mut latch) = setup();
    let d = descriptor(4);
    let receipt = copied(&mut frames, &local, 4, 0, &mut latch);
    let mut backend = TestBackend::new();
    backend.bad = true;
    let mut o = Owner::initialized_software(Configuration::t8112(&d).unwrap(), backend);
    o.begin_capture(&frames, receipt, &d, context(), 1).unwrap();
    assert_eq!(
        run(&mut o, &frames, &mut latch),
        Err(Error::Contract(refuse!(
            "generic actual callback result shape mismatch"
        )))
    );
    assert_eq!(o.products().0, 0);
    let receipt = copied(&mut frames, &local, 4, 0, &mut latch);
    let mut o = Owner::initialized_software(Configuration::t8112(&d).unwrap(), TestBackend::new());
    o.begin_capture(&frames, receipt, &d, context(), 1).unwrap();
    o.batch.as_mut().unwrap().cursor = u64::MAX;
    assert!(matches!(
        run(&mut o, &frames, &mut latch),
        Err(Error::Contract(_))
    ));
    assert!(o.backend.calls.is_empty());
}
#[test]
fn inactive_primary_timestamp_uses_kept_frame_metadata() {
    let (mut frames, local, mut latch) = setup();
    let d = descriptor(1);
    let receipt = copied(&mut frames, &local, 1, 41, &mut latch);
    let expected = frames.cells(&receipt).unwrap()[0].metadata & TIME_MASK;
    let mut o = Owner::initialized_software(Configuration::t8112(&d).unwrap(), TestBackend::new());
    let mut c = context();
    c.evaluated = 0;
    c.evaluation_tick = 9999;
    o.begin_capture(&frames, receipt, &d, c, 1).unwrap();
    run(&mut o, &frames, &mut latch).unwrap();
    assert_eq!(o.base[3][0].tick, expected);
    assert_ne!(expected, 9999);
}
#[test]
fn constructor_preflight_keeps_receipt_products_and_pending_post_intact() {
    let (mut frames, local, mut latch) = setup();
    let mut d = descriptor(1);
    let receipt = copied(&mut frames, &local, 1, 42, &mut latch);
    let mut o = Owner::initialized_software(Configuration::t8112(&d).unwrap(), TestBackend::new());
    d.counters = None;
    assert_eq!(
        o.begin_capture(&frames, receipt, &d, context(), 1),
        Err(Error::Contract(refuse!(
            "generic no-counter descriptor received a nonempty frame slice"
        )))
    );
    assert!(o.receipt.is_none());
    assert!(!o.awaiting_post);
    assert_eq!(o.products().0, 0);
    d = descriptor(1);
    let receipt = copied(&mut frames, &local, 1, 43, &mut latch);
    o.serial = u64::MAX;
    assert_eq!(
        o.begin_capture(&frames, receipt, &d, context(), 1),
        Err(Error::Contract(refuse!(
            "generic ingestion serial exhausted"
        )))
    );
    assert!(o.receipt.is_none());
    assert!(!o.awaiting_post);
    assert_eq!(o.products().0, 0);
    o.serial = 0;
    let receipt = copied(&mut frames, &local, 1, 44, &mut latch);
    o.begin_capture(&frames, receipt, &d, context(), 1).unwrap();
    run(&mut o, &frames, &mut latch).unwrap();
    o.serial = u64::MAX;
    let products = o.products();
    let c = CounterContext {
        buffer_index: 1,
        ..context()
    };
    assert_eq!(
        o.begin_postprocess(&frames, &d, c, 1),
        Err(Error::Contract(refuse!(
            "generic ingestion serial exhausted"
        )))
    );
    assert_eq!(o.products(), products);
    assert!(o.awaiting_post);
    assert!(o.cells(&frames).is_ok());
}
#[test]
fn type4_coefficients_and_output_range_precede_duration_publication() {
    let (mut frames, local, mut latch) = setup();
    let mut d = descriptor(2);
    d.raw[4] = 18;
    let receipt = copied(&mut frames, &local, 2, 0, &mut latch);
    let mut o = Owner::initialized_software(Configuration::t8112(&d).unwrap(), TestBackend::new());
    let c = context();
    o.begin_capture(&frames, receipt, &d, c, 1).unwrap();
    run(&mut o, &frames, &mut latch).unwrap();
    let (_, state, previous) = o.products();
    let c = CounterContext {
        buffer_index: 1,
        state_index: state,
        previous_state_index: previous,
        ..c
    };
    o.begin_postprocess(&frames, &d, c, 1).unwrap();
    run(&mut o, &frames, &mut latch).unwrap();
    assert!(o.config.frequencies[0].qualified);
    let calls = &o.backend.calls;
    let coefficients = calls
        .iter()
        .position(|(_, c)| matches!(c, Call::Coefficients { .. }))
        .unwrap();
    let layout = calls
        .iter()
        .position(|(_, c)| matches!(c, Call::OutputLayout { source: 18 }))
        .unwrap();
    let publish = calls
        .iter()
        .position(|(_, c)| matches!(c, Call::PublishInteger { entry: 240, .. }))
        .unwrap();
    assert!(coefficients < layout && layout < publish);
}
#[test]
fn source_activation_store_resets_only_capture_index_without_frame_permission() {
    let (mut frames, local, mut latch) = setup();
    let d = descriptor(1);
    let receipt = copied(&mut frames, &local, 1, 42, &mut latch);
    let mut o = Owner::initialized_software(Configuration::t8112(&d).unwrap(), TestBackend::new());
    o.begin_capture(&frames, receipt, &d, context(), 1).unwrap();
    run(&mut o, &frames, &mut latch).unwrap();
    let old = o.base;
    assert_eq!(o.ordinal(), d.ordinal());
    o.apply_source_activation_reset().unwrap();
    assert_eq!(o.products().0, 0);
    assert_eq!(o.base, old);
    assert_eq!(o.cells(&frames).unwrap()[0].value, 42);
    assert!(!o.awaiting_post);
    assert_eq!(extract_field(o.cells(&frames).unwrap(), 0, 0).unwrap(), 42);
    assert!(o.backend.calls.is_empty());
}
#[test]
fn extended_integer_source_preserves_sum_and_timestamp() {
    let (mut frames, local, mut latch) = setup();
    let d = descriptor(1);
    let receipt = copied(&mut frames, &local, 1, 1, &mut latch);
    let mut config = Configuration::t8112(&d).unwrap();
    config.references[6] = CounterReference {
        kind: 2,
        provider: 3,
        start: 0,
        width: 0,
        flags: 0,
        scale: 0,
    };
    let mut o = Owner::initialized_software(config, TestBackend::new());
    let c = CounterContext {
        evaluated: 0,
        ..context()
    };
    o.begin_capture(&frames, receipt, &d, c, 1).unwrap();
    run(&mut o, &frames, &mut latch).unwrap();
    assert_eq!(
        o.integer[0][0],
        Pair {
            value: 400 + 408 + 416,
            tick: 3000
        }
    );
    let calls: Vec<_> = o
        .backend
        .calls
        .iter()
        .filter_map(|(_, c)| {
            if let Call::ExtendedFrame { index, .. } = c {
                Some(*index)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(calls, vec![0, 8, 16, 0]);
}
#[test]
fn provider_busy_and_foreign_frame_owner_preserve_identity() {
    let (mut frames, local, mut latch) = setup();
    let d = descriptor(4);
    let receipt = copied(&mut frames, &local, 4, 0, &mut latch);
    let (mut foreign, local2, mut latch2) = setup();
    let other = copied(&mut foreign, &local2, 4, 0, &mut latch2);
    let mut backend = TestBackend::new();
    backend.busy = true;
    let mut o = Owner::initialized_software(Configuration::t8112(&d).unwrap(), backend);
    assert!(o.begin_capture(&frames, other, &d, context(), 1).is_err());
    o.begin_capture(&frames, receipt, &d, context(), 1).unwrap();
    assert_eq!(
        run(&mut o, &frames, &mut latch),
        Ok(Progress::Busy { deadline: Some(9) })
    );
    let request = o.backend.calls[0].0.clone();
    run(&mut o, &frames, &mut latch).unwrap();
    assert!(request.same_operation(&o.backend.calls[1].0));
}
