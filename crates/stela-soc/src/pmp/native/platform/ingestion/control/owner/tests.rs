use super::super::super::super::super::{
    Packets,
    counters::{Claim, CopyStep},
    power::DeviceTable,
};
use super::super::super::{Auxiliary, Pair};
use super::*;
use alloc::{vec, vec::Vec};
use core::cell::Cell;
use stela_contracts::refuse;
use {
    crate::ptd::Ptd, crate::ptd::transport::notifications::LocalNotifications,
    crate::ptd::transport::notifications::NativeProfile, stela_contracts::bus::LifecycleState,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::Width,
    stela_contracts::interrupt::InterruptLatch, stela_soc_data::ptd::Geometry,
    stela_soc_data::ptd::Range, stela_soc_data::ptd::UPDATE_OFFSET,
};

fn descriptor(ordinal: usize) -> super::super::super::Descriptor {
    super::super::super::super::profile::tests::fixture().descriptors()[ordinal].clone()
}
fn request(serial: u64) -> Request {
    Request {
        owner: Rc::new(()),
        serial,
        cursor: 17,
    }
}
fn call(configuration: &Configuration) -> Call {
    Call::ControlTail {
        ordinal: configuration.ordinal,
        context: super::super::super::super::owner::CounterContext {
            selected: 8,
            evaluation_tick: 100,
            current_packet: Packets([0; 6]),
            activity: 1,
            buffer_index: 1,
            state_index: 0,
            previous_state_index: 0,
            evaluated: 1,
            pending: 0,
        },
        descriptors: configuration.rows.clone(),
        activation: 0,
    }
}
fn setup() -> (Frames, LocalNotifications, InterruptLatch) {
    let range = Range {
        id: 9,
        start: 16,
        count: 144,
        name: "authored source frames".into(),
    };
    let extra = Range {
        id: 30,
        start: 200,
        count: 8,
        name: "authored shared bank2".into(),
    };
    let live = LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: true,
    };
    let (_, local) = Ptd::initialized_local_profile(
        NativeProfile::T8112,
        Geometry::new((0x23b3c0000, 0x20000), (0x23b3d0000, 0x4000)).unwrap(),
        &[range.clone(), extra],
        live,
    )
    .unwrap();
    let ids = [
        1, 2, 16, 17, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 18,
    ];
    let counts = [0, 14, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let bytes: Vec<_> = ids
        .into_iter()
        .zip(counts)
        .flat_map(|(id, count)| {
            let mut words = [0u32; 31];
            words[0] = id;
            words[3] = count;
            words.into_iter().flat_map(u32::to_le_bytes)
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
            &mut Access::new(0, 101, latch),
        )
        .unwrap();
}
fn capture(
    frames: &mut Frames,
    local: &LocalNotifications,
    ordinal: u32,
    value: u64,
    latch: &mut InterruptLatch,
) -> Captured {
    publish(
        local,
        frames.layout(ordinal).unwrap().start + 3,
        value,
        latch,
    );
    let captured = frames.capture_pending(&Access::new(0, 102, latch)).unwrap();
    frames.begin_copy(&captured, ordinal, u128::MAX).unwrap();
    while frames.step(&mut Access::new(0, 103, latch)).unwrap() != CopyStep::Complete {}
    let _actual_copy = frames.finish_copy().unwrap();
    captured
}
struct Actual {
    identity: Identity,
    local: LocalNotifications,
    calls: Vec<(ResourceRequest, Operation)>,
    busy: bool,
    retired_error: bool,
    malformed: bool,
    cache: [Option<Pair>; 8],
    consumes: u32,
}
impl Actual {
    fn new(local: LocalNotifications) -> Self {
        Self {
            identity: Identity::new(),
            local,
            calls: Vec::new(),
            busy: false,
            retired_error: false,
            malformed: false,
            cache: [None; 8],
            consumes: 0,
        }
    }
}
impl Resources for Actual {
    fn identity(&self) -> &Identity {
        &self.identity
    }
    fn notifications(&self) -> &LocalNotifications {
        &self.local
    }
    fn call(
        &mut self,
        request: &ResourceRequest,
        operation: Operation,
        access: &mut Access<'_>,
    ) -> Completion<ResourceValue> {
        self.calls.push((request.clone(), operation));
        if core::mem::take(&mut self.busy) {
            return Completion::Busy {
                deadline: Some(200),
            };
        }
        let value = if self.malformed {
            ResourceValue::Pair(Pair::default())
        } else {
            match operation {
                Operation::Flags70 { .. } => ResourceValue::Word(0x101),
                Operation::Member28 { .. } => ResourceValue::Word(0x8000_ffff),
                Operation::Packed400 { .. } => ResourceValue::Word(0x800a_7ffe),
                Operation::ExtendedFrame { bank, index } => {
                    assert_eq!(bank, 2);
                    let slot = &mut self.cache[index as usize];
                    if slot.is_none() {
                        let entry = self
                            .local
                            .bank()
                            .consume_entry(200 + index, access)
                            .unwrap();
                        *slot = Some(Pair {
                            value: entry.value,
                            tick: entry.metadata >> 10,
                        });
                        self.consumes += 1;
                    }
                    ResourceValue::Pair(slot.unwrap())
                }
                _ => ResourceValue::Complete,
            }
        };
        Completion::Retired {
            value,
            refusal: if core::mem::take(&mut self.retired_error) {
                Some(refuse!("authored retirement with refusal"))
            } else {
                None
            },
        }
    }
}
fn invoke(
    owner: &mut Owner,
    request: &Request,
    call: &Call,
    frames: &Frames,
    captured: &Captured,
    resources: &mut Actual,
    latch: &mut InterruptLatch,
) -> Completion<Value> {
    owner.call(
        request,
        call,
        frames,
        captured,
        resources,
        &mut Access::new(0, 104, latch),
    )
}
fn complete(result: Completion<Value>) {
    assert_eq!(
        result,
        Completion::Retired {
            value: Value::Complete,
            refusal: None
        }
    );
}
#[test]
fn selected_t8112_local_tails_preserve_frames_without_another_consume() {
    for ordinal in 4..=7 {
        let (mut frames, local, mut latch) = setup();
        let captured = capture(
            &mut frames,
            &local,
            ordinal,
            0x8aa3_8bb2_8cc1_8dd0,
            &mut latch,
        );
        let configuration = Configuration::t8112(&descriptor(ordinal as usize)).unwrap();
        let input = call(&configuration);
        let mut owner = Owner::initialized_software(
            configuration.clone(),
            SoftwareImage::zeroed(&configuration),
        )
        .unwrap();
        let mut resources = Actual::new(local);
        let before = frames.progress();
        let req = request(1);
        complete(invoke(
            &mut owner,
            &req,
            &input,
            &frames,
            &captured,
            &mut resources,
            &mut latch,
        ));
        assert_eq!(word(&owner.image.slots[0].raw, 12), 0x0010_0dd0);
        if ordinal == 5 {
            assert_eq!(word(&owner.image.slots[1].raw, 12), 0x0011_0cc0);
            assert_eq!(word(&owner.image.slots[2].raw, 12), 0x0012_0bb0);
        }
        assert!(resources.calls.is_empty()); // Timer limits are explicit software0, not hardware readiness.
        assert_eq!(frames.progress(), before);
        complete(invoke(
            &mut owner,
            &req,
            &input,
            &frames,
            &captured,
            &mut resources,
            &mut latch,
        ));
        assert_eq!(frames.progress(), before);
    }
}
#[test]
fn retired_member_flag_read_is_not_replayed_before_masked_write_and_period_read() {
    let (mut frames, local, mut latch) = setup();
    let captured = capture(&mut frames, &local, 4, 0x8ab3, &mut latch);
    let configuration = Configuration::t8112(&descriptor(4)).unwrap();
    let input = call(&configuration);
    let mut image = SoftwareImage::zeroed(&configuration);
    image.slots[0].raw[0] = 1;
    image.slots[0].timer[2] = 1;
    let mut owner = Owner::initialized_software(configuration, image).unwrap();
    let mut resources = Actual::new(local);
    resources.retired_error = true;
    let req = request(1);
    assert!(matches!(
        invoke(
            &mut owner,
            &req,
            &input,
            &frames,
            &captured,
            &mut resources,
            &mut latch
        ),
        Completion::Refused(_)
    ));
    assert_eq!(resources.calls.len(), 1);
    assert_eq!(
        resources.calls[0].1,
        Operation::Flags70 {
            provider: 0,
            member: 8
        }
    );
    assert_eq!(owner.image.slots[0].members[8][20..22], [1, 1]);
    complete(invoke(
        &mut owner,
        &req,
        &input,
        &frames,
        &captured,
        &mut resources,
        &mut latch,
    ));
    assert_eq!(
        resources
            .calls
            .iter()
            .map(|(_, op)| *op)
            .collect::<Vec<_>>(),
        vec![
            Operation::Flags70 {
                provider: 0,
                member: 8
            },
            Operation::Flags {
                provider: 0,
                member: 8,
                method: FlagsMethod::Store58,
                value: 0x101
            },
            Operation::Member28 {
                provider: 0,
                member: 8
            },
        ]
    );
    assert_eq!(owner.image.slots[0].raw[0], 0);
    assert_eq!(word(&owner.image.slots[0].raw, 8), 1);
    assert_eq!(half(&owner.image.slots[0].members[8], 16), 0xffff);
    assert_eq!(owner.image.slots[0].timer, [0, 1, 1]);
}
#[test]
fn busy_keeps_identity_and_rejects_new_capture_foreign_bank_or_changed_call() {
    let (mut frames, local, mut latch) = setup();
    let captured = capture(&mut frames, &local, 4, 0x8ab3, &mut latch);
    let cfg = Configuration::t8112(&descriptor(4)).unwrap();
    let input = call(&cfg);
    let mut image = SoftwareImage::zeroed(&cfg);
    image.slots[0].raw[0] = 1;
    let mut owner = Owner::initialized_software(cfg, image).unwrap();
    let mut resources = Actual::new(local.clone());
    resources.busy = true;
    let req = request(1);
    assert_eq!(
        invoke(
            &mut owner,
            &req,
            &input,
            &frames,
            &captured,
            &mut resources,
            &mut latch
        ),
        Completion::Busy {
            deadline: Some(200)
        }
    );
    let first = resources.calls[0].0.clone();
    let mut changed = input.clone();
    if let Call::ControlTail { context, .. } = &mut changed {
        context.activity = 0;
    }
    assert!(matches!(
        invoke(
            &mut owner,
            &req,
            &changed,
            &frames,
            &captured,
            &mut resources,
            &mut latch
        ),
        Completion::Refused(_)
    ));
    assert_eq!(resources.calls.len(), 1);
    complete(invoke(
        &mut owner,
        &req,
        &input,
        &frames,
        &captured,
        &mut resources,
        &mut latch,
    ));
    assert!(first.same_operation(&resources.calls[1].0));
    let (_, foreign, _) = setup();
    let mut foreign_resources = Actual::new(foreign);
    assert!(matches!(
        invoke(
            &mut owner,
            &req,
            &input,
            &frames,
            &captured,
            &mut foreign_resources,
            &mut latch
        ),
        Completion::Refused(_)
    ));

    let mut next = req.clone();
    next.serial = 2;
    let captured2 = frames
        .capture_pending(&Access::new(0, 105, &mut latch))
        .unwrap();
    complete(invoke(
        &mut owner,
        &next,
        &input,
        &frames,
        &captured2,
        &mut resources,
        &mut latch,
    ));
    assert!(matches!(
        invoke(
            &mut owner,
            &req,
            &input,
            &frames,
            &captured2,
            &mut resources,
            &mut latch
        ),
        Completion::Refused(_)
    ));
}
fn extended_configuration() -> Configuration {
    let mut rows = vec![
        Auxiliary {
            words: [0; 14],
            members: Vec::new()
        };
        4
    ];
    rows[0].words[2] = 2;
    rows[0].words[3] = 4;
    rows[0].words[4] = 192;
    rows[0].words[5] = 16;
    rows[0].words[7] = 1;
    rows[0].members.push([2, 0, 192, 16, 0]);
    Configuration::declared(&descriptor(4), &rows).unwrap()
}
#[test]
fn packed_and_member_reads_share_one_bank2_consumption() {
    let (mut frames, local, mut latch) = setup();
    let captured = capture(&mut frames, &local, 4, 0x1234, &mut latch);
    publish(&local, 203, 0x8001, &mut latch);
    let configuration = extended_configuration();
    let input = call(&configuration);
    let mut image = SoftwareImage::zeroed(&configuration);
    image.slots[0].timer = [0, 1, 1];
    put_word(&mut image.slots[0].members[0], 12, 1);
    let mut owner = Owner::initialized_software(configuration, image).unwrap();
    let mut resources = Actual::new(local);
    let req = request(1);
    let progress = frames.progress();
    complete(invoke(
        &mut owner,
        &req,
        &input,
        &frames,
        &captured,
        &mut resources,
        &mut latch,
    ));
    assert_eq!(resources.consumes, 1);
    assert_eq!(resources.calls.len(), 2);
    assert_eq!(half(&owner.image.slots[0].members[0], 16), 0x8001);
    assert_eq!(half(&owner.image.slots[0].members[0], 18), 0x8001);
    assert_eq!(owner.image.slots[0].members[0][20..22], [1, 0]);
    assert_eq!(word(&owner.image.slots[0].raw, 12), 0x0011_0001);
    assert_eq!(frames.progress(), progress);
}
#[test]
fn unknown_correction_pointer_refuses_after_its_read_without_reconsumption() {
    let (mut frames, local, mut latch) = setup();
    let captured = capture(&mut frames, &local, 4, 1, &mut latch);
    publish(&local, 203, 0x8001, &mut latch);
    let mut cfg = extended_configuration();
    cfg.rows[0].words[10] = 0x1234;
    let input = call(&cfg);
    let mut image = SoftwareImage::zeroed(&cfg);
    image.slots[0].timer = [0, 1, 1];
    let mut owner = Owner::initialized_software(cfg, image).unwrap();
    let mut resources = Actual::new(local);
    let req = request(1);
    for _ in 0..2 {
        assert!(matches!(
            invoke(
                &mut owner,
                &req,
                &input,
                &frames,
                &captured,
                &mut resources,
                &mut latch
            ),
            Completion::Refused(reason) if reason == refuse!("auxiliary correction list requires actual paired scalar owners")
        ));
    }
    assert_eq!(resources.calls.len(), 2);
    assert_eq!(resources.consumes, 1);
    assert_eq!(half(&owner.image.slots[0].members[0], 16), 0x8001);
    assert_eq!(owner.image.slots[0].timer[0], 1); // The later timer clear was not reached.
}
#[test]
fn malformed_retired_resource_result_is_latched_without_replay() {
    let (mut frames, local, mut latch) = setup();
    let captured = capture(&mut frames, &local, 4, 0, &mut latch);
    let cfg = Configuration::t8112(&descriptor(4)).unwrap();
    let input = call(&cfg);
    let mut image = SoftwareImage::zeroed(&cfg);
    image.slots[0].raw[0] = 1;
    let mut owner = Owner::initialized_software(cfg, image).unwrap();
    let mut resources = Actual::new(local);
    resources.malformed = true;
    let req = request(1);
    for _ in 0..2 {
        assert!(matches!(
            invoke(
                &mut owner,
                &req,
                &input,
                &frames,
                &captured,
                &mut resources,
                &mut latch
            ),
            Completion::Refused(_)
        ));
    }
    assert_eq!(resources.calls.len(), 1);
    assert_eq!(
        owner.refusal().map(Refusal::what),
        Some("auxiliary actual resource result shape mismatch")
    );
}
#[test]
fn activation_transitions_fan_out_flags_then_signal_in_source_order() {
    let (_, local, mut latch) = setup();
    let cfg = Configuration::t8112(&descriptor(4)).unwrap();
    let mut image = SoftwareImage::zeroed(&cfg);
    image.slots[0].raw[1] = 1;
    image.slots[0].raw[3] = 1;
    image.slots[0].timer[2] = 3;
    for member in &mut image.slots[0].members {
        member[2] = 1;
    }
    image.slots[0].members[8][0] = 1;
    let mut owner = Owner::initialized_software(cfg, image).unwrap();
    let mut resources = Actual::new(local);
    let req = request(1);
    owner
        .begin(
            Caller::Tail(req.clone()),
            Signature::Transition {
                slot: 0,
                mode: 1,
                activation: 1,
            },
            1,
            None,
            Some(Step::Transition(0, 1)),
        )
        .unwrap();
    complete(owner.advance(None, &mut resources, &mut Access::new(0, 1, &mut latch)));
    assert_eq!(
        resources
            .calls
            .iter()
            .map(|(_, op)| *op)
            .collect::<Vec<_>>(),
        vec![
            Operation::Flags {
                provider: 0,
                member: 8,
                method: FlagsMethod::Enable60,
                value: 1
            },
            Operation::Signal {
                source: 64,
                enable: true
            },
            Operation::Flags {
                provider: 0,
                member: 8,
                method: FlagsMethod::Disable68,
                value: 0x100
            },
        ]
    );
    assert!(
        owner.image.slots[0]
            .members
            .iter()
            .all(|member| member[1..3] == [1, 0])
    );
    assert_eq!(owner.image.slots[0].timer, [3, 3, 3]);
    owner
        .begin(
            Caller::Tail(req),
            Signature::Transition {
                slot: 0,
                mode: 0,
                activation: 1,
            },
            1,
            None,
            Some(Step::Transition(0, 0)),
        )
        .unwrap();
    complete(owner.advance(None, &mut resources, &mut Access::new(0, 2, &mut latch)));
    assert_eq!(
        resources.calls[3].1,
        Operation::Flags {
            provider: 0,
            member: 8,
            method: FlagsMethod::Disable68,
            value: 1
        }
    );
    assert_eq!(
        resources.calls[4].1,
        Operation::Signal {
            source: 64,
            enable: false
        }
    );
    assert_eq!(word(&owner.image.slots[0].raw, 8), 0);
    assert_eq!(owner.image.slots[0].timer, [0, 0, 3]);
}
#[test]
fn compiled_empty_amcc_still_performs_reached_state_and_timer_transitions() {
    let (_, local, mut latch) = setup();
    let cfg = Configuration::t8112(&descriptor(1)).unwrap();
    let mut image = SoftwareImage::zeroed(&cfg);
    image.slots[2].timer[2] = 9;
    let mut owner = Owner::initialized_software(cfg, image).unwrap();
    let mut resources = Actual::new(local);
    let req = request(1);
    owner
        .begin(
            Caller::Tail(req.clone()),
            Signature::Transition {
                slot: 2,
                mode: 1,
                activation: 1,
            },
            1,
            None,
            Some(Step::Transition(2, 1)),
        )
        .unwrap();
    complete(owner.advance(None, &mut resources, &mut Access::new(0, 1, &mut latch)));
    assert_eq!(word(&owner.image.slots[2].raw, 8), 1);
    assert_eq!(owner.image.slots[2].timer, [9, 9, 9]);
    owner
        .begin(
            Caller::Tail(req),
            Signature::Transition {
                slot: 2,
                mode: 2,
                activation: 1,
            },
            1,
            None,
            Some(Step::Transition(2, 2)),
        )
        .unwrap();
    complete(owner.advance(None, &mut resources, &mut Access::new(0, 2, &mut latch)));
    assert_eq!(word(&owner.image.slots[2].raw, 8), 2);
    assert_eq!(owner.image.slots[2].timer, [0, 0, 9]);
    assert!(resources.calls.is_empty());
}
#[test]
fn captured_identity_is_kept_across_busy_and_does_not_follow_new_observation() {
    let (mut frames, local, mut latch) = setup();
    let captured = capture(&mut frames, &local, 4, 1, &mut latch);
    let cfg = Configuration::t8112(&descriptor(4)).unwrap();
    let input = call(&cfg);
    let mut image = SoftwareImage::zeroed(&cfg);
    image.slots[0].raw[0] = 1;
    let mut owner = Owner::initialized_software(cfg, image).unwrap();
    let mut resources = Actual::new(local);
    resources.busy = true;
    let req = request(1);
    assert!(matches!(
        invoke(
            &mut owner,
            &req,
            &input,
            &frames,
            &captured,
            &mut resources,
            &mut latch
        ),
        Completion::Busy { .. }
    ));
    let next = frames
        .capture_pending(&Access::new(0, 105, &mut latch))
        .unwrap();
    assert!(matches!(
        invoke(
            &mut owner,
            &req,
            &input,
            &frames,
            &next,
            &mut resources,
            &mut latch
        ),
        Completion::Refused(_)
    ));
    assert_eq!(resources.calls.len(), 1);
}
#[test]
fn source_configure_keeps_registration_prefix_and_does_not_register_thresholds_alone() {
    let (_, local, mut latch) = setup();
    let cfg = Configuration::t8112(&descriptor(4)).unwrap();
    let mut image = SoftwareImage::zeroed(&cfg);
    put_word(&mut image.slots[0].raw, 8, 1);
    image.slots[0].members[8][..5].fill(7);
    let mut owner = Owner::initialized_software(cfg, image).unwrap();
    let mut resources = Actual::new(local);
    let req = request(1);
    owner
        .begin(
            Caller::Tail(req.clone()),
            Signature::ConfigureAuxiliary {
                slot: 0,
                flags: 0,
                thresholds: 0xffff,
                period: 7,
                activation: 1,
            },
            1,
            None,
            Some(Step::ConfigureAuxiliary(0, 0, 0xffff, 7)),
        )
        .unwrap();
    complete(owner.advance(None, &mut resources, &mut Access::new(0, 1, &mut latch)));
    assert!(resources.calls.is_empty());
    assert_eq!(owner.image.slots[0].raw[1..5], [0, 0, 255, 255]);
    assert_eq!(owner.image.slots[0].members[8][..5], [1, 0, 0, 0, 0]);
    assert_eq!(owner.image.slots[0].timer[2], 7);
    assert!(owner.registered_auxiliary(0).unwrap().is_none());
    owner
        .begin(
            Caller::Tail(req),
            Signature::ConfigureAuxiliary {
                slot: 0,
                flags: 0x200,
                thresholds: 0,
                period: 0,
                activation: 1,
            },
            1,
            None,
            Some(Step::ConfigureAuxiliary(0, 0x200, 0, 0)),
        )
        .unwrap();
    resources.busy = true;
    assert!(matches!(
        owner.advance(None, &mut resources, &mut Access::new(0, 2, &mut latch)),
        Completion::Busy { .. }
    ));
    assert!(!owner.auxiliary_binding(0).unwrap().registered());
    assert_eq!(word(&owner.image.slots[0].raw, 8), 1);
    resources.retired_error = true;
    assert!(matches!(
        owner.advance(None, &mut resources, &mut Access::new(0, 3, &mut latch)),
        Completion::Refused(_)
    ));
    assert!(owner.registered_auxiliary(0).unwrap().unwrap().registered());
    assert_eq!(word(&owner.image.slots[0].raw, 8), 1); // Transition is still owed.
    complete(owner.advance(None, &mut resources, &mut Access::new(0, 4, &mut latch)));
    assert_eq!(word(&owner.image.slots[0].raw, 8), 0);
    assert_eq!(owner.image.slots[0].timer[2], 7); // Input0 preserves source period.
    assert_eq!(
        resources.calls[0].1,
        Operation::RegisterAuxiliary {
            slot: 0,
            source: 64
        }
    );
    assert!(resources.calls[0].0.same_operation(&resources.calls[1].0));
    assert_eq!(
        resources
            .calls
            .iter()
            .filter(|(_, op)| matches!(op, Operation::RegisterAuxiliary { .. }))
            .count(),
        2
    ); // Busy then one retirement.
}

#[test]
fn auxiliary_callback_binds_the_same_control() {
    use super::super::super::super::super::interrupts as irq;
    use alloc::boxed::Box;
    use core::cell::RefCell;
    struct Device(irq::Placement);
    impl irq::Device for Device {
        fn placement(&self) -> irq::Placement {
            self.0
        }
        fn read(&mut self, offset: u64, _: &mut Access<'_>) -> Result<u32, irq::Error> {
            Ok(match offset {
                4 => 512,
                0x14 => 0xa4,
                0xc000 => 0x10040,
                _ => panic!("unexpected authored IRQ read"),
            })
        }
        fn write(&mut self, offset: u64, _: u32, _: &mut Access<'_>) -> Result<(), irq::Error> {
            assert_eq!(offset, 0x14);
            Ok(()) // Current-source disable has no extra MMIO.
        }
        fn order(&mut self, _: &mut Access<'_>) -> Result<(), irq::Error> {
            Ok(())
        }
        fn irq_pending(&mut self, _: &mut Access<'_>) -> Result<bool, irq::Error> {
            Ok(false)
        }
    }
    struct Target(
        Rc<RefCell<Owner>>,
        Rc<RefCell<Vec<irq::AuxiliaryReset>>>,
        bool,
    );
    impl irq::AuxiliaryTarget for Target {
        fn reset_slot(
            &mut self,
            reset: &irq::AuxiliaryReset,
            _: &mut Access<'_>,
        ) -> Completion<()> {
            self.1.borrow_mut().push(reset.clone());
            if core::mem::take(&mut self.2) {
                return Completion::Busy { deadline: None };
            }
            self.0.borrow_mut().reset_slot(reset)
        }
    }
    let (_, local, mut latch) = setup();
    let d = descriptor(4);
    let cfg = Configuration::t8112(&d).unwrap();
    let control = Rc::new(RefCell::new(
        Owner::initialized_software(cfg.clone(), SoftwareImage::zeroed(&cfg)).unwrap(),
    ));
    let binding = control.borrow().auxiliary_binding(0).unwrap();
    let receipts = Rc::new(RefCell::new(Vec::new()));
    let p = irq::Placement::t8112(0).unwrap();
    let mut irq = irq::Owner::t8112(
        p,
        Box::new(Device(p)),
        irq::SoftwareConfiguration::default(),
    )
    .unwrap();
    irq.initialize(&mut Access::new(0, 1, &mut latch)).unwrap();
    // Keep native registration in the typed source resource.
    struct Register<'a> {
        actual: Actual,
        native: &'a mut irq::Owner,
        handler: Option<Box<dyn irq::Handler>>,
    }
    impl Resources for Register<'_> {
        fn identity(&self) -> &Identity {
            self.actual.identity()
        }
        fn notifications(&self) -> &LocalNotifications {
            self.actual.notifications()
        }
        fn call(
            &mut self,
            req: &ResourceRequest,
            op: Operation,
            a: &mut Access<'_>,
        ) -> Completion<ResourceValue> {
            if let Operation::RegisterAuxiliary { source, .. } = op {
                self.native
                    .register(source, self.handler.take().unwrap())
                    .unwrap();
                Completion::Retired {
                    value: ResourceValue::Complete,
                    refusal: None,
                }
            } else {
                self.actual.call(req, op, a)
            }
        }
    }
    let handler = irq::AuxiliaryHandler::t8112(
        &d,
        0,
        binding.clone(),
        Target(control.clone(), receipts.clone(), true),
    )
    .unwrap();
    let mut resource = Register {
        actual: Actual::new(local),
        native: &mut irq,
        handler: Some(Box::new(handler)),
    };
    control
        .borrow_mut()
        .begin(
            Caller::Tail(request(1)),
            Signature::ConfigureAuxiliary {
                slot: 0,
                flags: 1,
                thresholds: 0,
                period: 3,
                activation: 0,
            },
            0,
            None,
            Some(Step::ConfigureAuxiliary(0, 1, 0, 3)),
        )
        .unwrap();
    complete(
        control
            .borrow_mut()
            .advance(None, &mut resource, &mut Access::new(0, 2, &mut latch)),
    );
    assert!(binding.registered());
    drop(resource);
    irq.begin_dispatch(false).unwrap();
    assert!(matches!(
        irq.advance_dispatch(&mut Access::new(0, 3, &mut latch)),
        Completion::Busy { .. }
    ));
    assert_eq!(irq.snapshot().current_enabled, 0);
    assert_eq!(control.borrow().image.slots[0].raw[0], 0);
    assert!(matches!(
        irq.advance_dispatch(&mut Access::new(0, 4, &mut latch)),
        Completion::Retired {
            value: irq::Outcome::Dispatched {
                registered: true,
                ..
            },
            refusal: None
        }
    ));
    assert_eq!(control.borrow().image.slots[0].raw[0], 1);
    assert_eq!(receipts.borrow().len(), 2);
    let reset = receipts.borrow()[1].clone();
    let mut foreign =
        Owner::initialized_software(cfg.clone(), SoftwareImage::zeroed(&cfg)).unwrap();
    assert!(matches!(foreign.reset_slot(&reset), Completion::Refused(_)));
    control
        .borrow_mut()
        .software(Step::ResetFlag(0), None)
        .unwrap();
    assert!(matches!(
        control.borrow_mut().reset_slot(&reset),
        Completion::Retired { .. }
    ));
    assert_eq!(control.borrow().image.slots[0].raw[0], 0); // Replay cannot reassert consumed flag.
    irq.begin_dispatch(false).unwrap();
    assert!(matches!(
        control.borrow_mut().reset_slot(&reset),
        Completion::Refused(_)
    ));
    assert_eq!(control.borrow().image.slots[0].timer[2], 3);
}

#[test]
#[cfg(feature = "std")]
#[ignore = "oracle: STELA_TEST_PMP_T8112"]
fn original_selected_control_rows_and_call_operands_match_immutable_pmp() {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
    );
    let read =
        |va: usize| u32::from_le_bytes(bytes[va - 0xfff000..va - 0xfff000 + 4].try_into().unwrap());
    for (ordinal, base) in [
        (1, 0x1046ab8usize),
        (4, 0x10477d0),
        (5, 0x1047b08),
        (6, 0x1047e18),
        (7, 0x1048410),
    ] {
        let cfg = Configuration::t8112(&descriptor(ordinal)).unwrap();
        for (i, row) in cfg.rows().iter().enumerate() {
            assert_eq!(
                row.words,
                core::array::from_fn(|j| read(base + 0x160 + 56 * i + 4 * j))
            );
            let pointer = u64::from(row.words[8]) | (u64::from(row.words[9]) << 32);
            for (m, member) in row.members.iter().enumerate() {
                assert_eq!(
                    *member,
                    core::array::from_fn(|j| read(pointer as usize + 20 * m + 4 * j))
                );
            }
        }
    }
    assert_eq!(read(0x101b518), 0xf9403908); // Provider+70, not PMGR state.
    assert_eq!(read(0x101b548), 0xf9402d48); // Provider+58.
    assert_eq!(read(0x101bb90), 0xf900011f); // Zero two timers, preserve third.
    assert_eq!(read(0x101bc88), 0xb9000a93); // Commit mode after reached effects.
}
