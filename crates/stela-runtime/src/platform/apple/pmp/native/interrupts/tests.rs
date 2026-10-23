use super::*;
use crate::platform::apple::interrupt::InterruptLatch;
use alloc::{boxed::Box, collections::VecDeque, rc::Rc, vec, vec::Vec};
use core::cell::RefCell;

#[derive(Default)]
struct State {
    effects: Vec<(u64, Option<u32>)>,
    pending: VecDeque<u32>,
    count: u32,
    refuse_write_once: Option<u64>,
    uncertain_once: Option<u64>,
    line: bool,
}
struct Actual(Rc<RefCell<State>>, Placement);
impl Device for Actual {
    fn placement(&self) -> Placement {
        self.1
    }
    fn read(&mut self, offset: u64, _: &mut Access<'_>) -> Result<u32, Error> {
        let mut s = self.0.borrow_mut();
        s.effects.push((offset, None));
        if s.uncertain_once == Some(offset) {
            s.uncertain_once = None;
            return Err(Error::Uncertain(MmioError::Unmapped {
                address: self.1.address + offset,
                width: Width::Word,
            }));
        }
        Ok(match offset {
            4 => s.count,
            0x14 => 0xa4,
            0xc000 => s.pending.pop_front().unwrap(),
            _ => 0,
        })
    }
    fn write(&mut self, offset: u64, value: u32, _: &mut Access<'_>) -> Result<(), Error> {
        let mut s = self.0.borrow_mut();
        if s.refuse_write_once == Some(offset) {
            s.refuse_write_once = None;
            return Err(Error::Refused("authored effect-free unavailable write"));
        }
        s.effects.push((offset, Some(value)));
        Ok(())
    }
    fn order(&mut self, _: &mut Access<'_>) -> Result<(), Error> {
        self.0.borrow_mut().effects.push((u64::MAX, None));
        Ok(())
    }
    fn irq_pending(&mut self, _: &mut Access<'_>) -> Result<bool, Error> {
        self.0.borrow_mut().effects.push((u64::MAX - 1, None));
        Ok(self.0.borrow().line)
    }
}
fn owner(count: u32) -> (Owner, Rc<RefCell<State>>) {
    let s = Rc::new(RefCell::new(State {
        count,
        ..State::default()
    }));
    let p = Placement::t8112(0x1000).unwrap();
    let o = Owner::t8112(
        p,
        Box::new(Actual(s.clone(), p)),
        SoftwareConfiguration::default(),
    )
    .unwrap();
    (o, s)
}
fn retired(result: Completion<Outcome>) -> Outcome {
    match result {
        Completion::Retired {
            value,
            refusal: None,
        } => value,
        other => panic!("{other:?}"),
    }
}
#[test]
fn initialization_uses_actual_count_and_enable_reads_and_retains_no_reset_image() {
    let (mut o, s) = owner(0xf234);
    let mut l = InterruptLatch::new();
    let mut a = Access::new(0, 1, &mut l);
    assert!(o.begin_signal(64, true).is_err());
    assert_eq!(o.initialize(&mut a), Ok(0x234));
    assert_eq!(o.initialize(&mut a), Ok(0x234));
    assert_eq!(
        s.borrow().effects,
        vec![(0x14, None), (0x14, Some(0xa5)), (4, None)]
    );
    assert_eq!(o.snapshot().source_count, Some(0x234));
    assert_eq!(o.snapshot().current, u32::MAX);
    assert!(o.registrations().next().is_none());
    assert!(Placement::t8112(u64::MAX).is_err());
    let p = Placement::t8112(0).unwrap();
    assert!(
        Owner::t8112(
            p,
            Box::new(Actual(s, Placement::t8112(1).unwrap())),
            SoftwareConfiguration::default()
        )
        .is_err()
    );
}
#[test]
fn signals_retain_target_read_write_prefix_tokens_and_actual_source_bound() {
    let (mut o, s) = owner(512);
    let (mut foreign, _) = owner(512);
    let mut l = InterruptLatch::new();
    let mut a = Access::new(0, 2, &mut l);
    o.initialize(&mut a).unwrap();
    foreign.initialize(&mut a).unwrap();
    s.borrow_mut().effects.clear();
    let signal = o.begin_signal(509, true).unwrap();
    s.borrow_mut().refuse_write_once = Some(0x663c);
    assert!(matches!(
        o.advance_signal(&signal, &mut a),
        Completion::Refused(_)
    ));
    assert!(o.begin_signal(64, false).is_err());
    assert_eq!(
        retired(o.advance_signal(&signal, &mut a)),
        Outcome::Signal { previous: true }
    );
    assert_eq!(
        retired(o.advance_signal(&signal, &mut a)),
        Outcome::Signal { previous: true }
    );
    assert_eq!(
        s.borrow().effects,
        vec![(0x27f4, Some(1)), (0x663c, None), (0x663c, Some(1 << 29))]
    );
    assert!(matches!(
        foreign.advance_signal(&signal, &mut a),
        Completion::Refused(_)
    ));
    let invalid = o.begin_signal(512, true).unwrap();
    assert_eq!(
        retired(o.advance_signal(&invalid, &mut a)),
        Outcome::Signal { previous: false }
    );
    assert!(matches!(
        o.advance_signal(&signal, &mut a),
        Completion::Refused(_)
    ));
    assert_eq!(s.borrow().effects.len(), 3);
}
#[test]
fn uncertain_read_latches_after_target_write_without_replay() {
    let (mut o, s) = owner(512);
    let mut l = InterruptLatch::new();
    let mut a = Access::new(0, 3, &mut l);
    o.initialize(&mut a).unwrap();
    s.borrow_mut().effects.clear();
    s.borrow_mut().uncertain_once = Some(0x6608);
    let r = o.begin_signal(64, true).unwrap();
    for _ in 0..2 {
        assert!(matches!(
            o.advance_signal(&r, &mut a),
            Completion::Refused(_)
        ));
    }
    assert_eq!(s.borrow().effects, vec![(0x2100, Some(1)), (0x6608, None)]);
    assert!(matches!(o.snapshot().fault, Some(Error::Uncertain(_))));
}
struct Callback {
    events: Rc<RefCell<Vec<Event>>>,
    busy: bool,
    disable: bool,
    retired_refusal: bool,
}
impl Handler for Callback {
    fn call(&mut self, e: Event, s: &mut Signals<'_>, a: &mut Access<'_>) -> Completion<()> {
        self.events.borrow_mut().push(e);
        if core::mem::take(&mut self.busy) {
            return Completion::Busy { deadline: Some(50) };
        }
        if self.disable {
            assert_eq!(s.current(), e.source);
            assert!(s.set(0, e.source, false, a).unwrap());
        }
        Completion::Retired {
            value: (),
            refusal: if core::mem::take(&mut self.retired_refusal) {
                Some("authored callback retired")
            } else {
                None
            },
        }
    }
}
#[test]
fn actual_pending_read_and_registry_flag_clear_precede_busy_callback_and_disable() {
    let (mut o, s) = owner(512);
    let mut l = InterruptLatch::new();
    let mut a = Access::new(0, 4, &mut l);
    o.initialize(&mut a).unwrap();
    let events = Rc::new(RefCell::new(Vec::new()));
    o.register(
        64,
        Box::new(Callback {
            events: events.clone(),
            busy: true,
            disable: true,
            retired_refusal: true,
        }),
    )
    .unwrap();
    o.configure_registration(64, 0x200).unwrap();
    s.borrow_mut().pending.push_back(0x10040);
    s.borrow_mut().effects.clear();
    s.borrow_mut().line = true;
    o.begin_dispatch(false).unwrap();
    assert_eq!(
        o.advance_dispatch(&mut a),
        Completion::Busy { deadline: Some(50) }
    );
    assert_eq!(o.snapshot().current, 64);
    assert!(o.begin_dispatch(false).is_err());
    assert!(o.configure_registration(64, 0x100).is_err());
    assert!(matches!(
        o.advance_dispatch(&mut a),
        Completion::Refused("authored callback retired")
    ));
    assert_eq!(
        retired(o.advance_dispatch(&mut a)),
        Outcome::Dispatched {
            source: 64,
            registered: true,
            more: true
        }
    );
    assert_eq!(events.borrow().len(), 2);
    assert_eq!(events.borrow()[0], events.borrow()[1]);
    assert_eq!(
        s.borrow().effects,
        vec![
            (0xc000, None),
            (0x6208, Some(1)),
            (u64::MAX, None),
            (u64::MAX - 1, None)
        ]
    );
    assert_eq!(o.snapshot().current, u32::MAX);
    assert_eq!(o.snapshot().current_enabled, 0);
}
#[test]
fn ordinary_callback_reenable_uses_actual_source_words_without_old_mask_read() {
    let (mut o, s) = owner(512);
    let mut l = InterruptLatch::new();
    let mut a = Access::new(0, 5, &mut l);
    o.initialize(&mut a).unwrap();
    let events = Rc::new(RefCell::new(Vec::new()));
    o.register(
        87,
        Box::new(Callback {
            events,
            busy: false,
            disable: false,
            retired_refusal: false,
        }),
    )
    .unwrap();
    s.borrow_mut().pending.push_back(0x10057);
    s.borrow_mut().effects.clear();
    o.begin_dispatch(false).unwrap();
    assert_eq!(
        retired(o.advance_dispatch(&mut a)),
        Outcome::Dispatched {
            source: 87,
            registered: true,
            more: false
        }
    );
    assert_eq!(
        s.borrow().effects,
        vec![
            (0xc000, None),
            (0x215c, Some(1)),
            (0x6608, Some(1 << 23)),
            (u64::MAX, None),
            (u64::MAX - 1, None)
        ]
    );
}
#[test]
fn special_and_unregistered_routes_never_become_invented_callback_completions() {
    let (mut o, s) = owner(512);
    let mut l = InterruptLatch::new();
    let mut a = Access::new(0, 6, &mut l);
    o.initialize(&mut a).unwrap();
    s.borrow_mut().effects.clear();
    o.begin_dispatch(true).unwrap();
    assert_eq!(
        retired(o.advance_dispatch(&mut a)),
        Outcome::Special { registered: false }
    );
    assert!(s.borrow().effects.is_empty());
    assert_eq!(o.configure_registration(SPECIAL, 0x200), Ok(0x8000_0001));
    assert_eq!(o.configure_registration(90, 0), Ok(0));
    o.configure_registration(90, 0x200).unwrap();
    assert_eq!(
        o.registrations().collect::<Vec<_>>(),
        vec![Registration {
            source: 90,
            flag: true,
            has_handler: false
        }]
    );
    s.borrow_mut().pending.push_back(0x1005a);
    o.begin_dispatch(false).unwrap();
    assert_eq!(
        retired(o.advance_dispatch(&mut a)),
        Outcome::Dispatched {
            source: 90,
            registered: false,
            more: false
        }
    );
    assert_eq!(
        s.borrow().effects,
        vec![
            (0xc000, None),
            (0x6208, Some(1 << 26)),
            (u64::MAX, None),
            (u64::MAX - 1, None)
        ]
    );
    s.borrow_mut().effects.clear();
    s.borrow_mut().pending.push_back(0x20040);
    o.begin_dispatch(false).unwrap();
    assert_eq!(
        retired(o.advance_dispatch(&mut a)),
        Outcome::OtherEvent { word: 0x20040 }
    );
    assert_eq!(s.borrow().effects, vec![(0xc000, None)]);
    assert!(o.snapshot_lifecycle_requirement().is_err());
}
struct Reset(Rc<RefCell<Vec<(Event, usize)>>>, bool);
impl AuxiliaryTarget for Reset {
    fn reset_slot(&mut self, event: Event, slot: usize, _: &mut Access<'_>) -> Completion<()> {
        self.0.borrow_mut().push((event, slot));
        if core::mem::take(&mut self.1) {
            return Completion::Busy { deadline: None };
        }
        Completion::Retired {
            value: (),
            refusal: None,
        }
    }
}
#[test]
fn source_auxiliary_handler_disables_current_then_retains_actual_reset_prefix() {
    let (mut o, s) = owner(512);
    let mut l = InterruptLatch::new();
    let mut a = Access::new(0, 7, &mut l);
    o.initialize(&mut a).unwrap();
    let descriptor = super::super::platform::authored_profile().descriptors()[4].clone();
    let effects = Rc::new(RefCell::new(Vec::new()));
    let handler = AuxiliaryHandler::t8112(&descriptor, 0, Reset(effects.clone(), true)).unwrap();
    assert_eq!(handler.source(), 64);
    o.register(64, Box::new(handler)).unwrap();
    s.borrow_mut().pending.push_back(0x10040);
    s.borrow_mut().effects.clear();
    o.begin_dispatch(false).unwrap();
    assert_eq!(
        o.advance_dispatch(&mut a),
        Completion::Busy { deadline: None }
    );
    assert_eq!(o.snapshot().current_enabled, 0);
    assert_eq!(
        retired(o.advance_dispatch(&mut a)),
        Outcome::Dispatched {
            source: 64,
            registered: true,
            more: false
        }
    );
    assert_eq!(effects.borrow().len(), 2);
    assert_eq!(effects.borrow()[0], effects.borrow()[1]);
    assert_eq!(
        s.borrow().effects,
        vec![(0xc000, None), (u64::MAX, None), (u64::MAX - 1, None)]
    );
}

#[test]
fn registration_status_preserves_reached_flag_prefix_and_source_noop() {
    let (mut o, _) = owner(512);
    let mut l = InterruptLatch::new();
    let mut a = Access::new(0, 8, &mut l);
    o.initialize(&mut a).unwrap();
    assert_eq!(o.configure_registration(64, 1), Ok(0x8000_000b));
    assert!(o.registrations().next().is_none());
    assert_eq!(o.configure_registration(64, 0x201), Ok(0x8000_000b));
    assert_eq!(
        o.registrations().next(),
        Some(Registration {
            source: 64,
            flag: true,
            has_handler: false
        })
    );
    assert_eq!(o.configure_registration(64, 0), Ok(0));
    assert!(o.registrations().next().unwrap().flag);
    assert_eq!(o.configure_registration(64, 0x100), Ok(0));
    assert!(!o.registrations().next().unwrap().flag);
}

#[test]
fn out_of_range_actual_iack_does_not_invent_source_completion_tail() {
    let (mut o, s) = owner(32);
    let mut l = InterruptLatch::new();
    let mut a = Access::new(0, 9, &mut l);
    o.initialize(&mut a).unwrap();
    s.borrow_mut().effects.clear();
    s.borrow_mut().pending.push_back(0x10040);
    o.begin_dispatch(false).unwrap();
    assert_eq!(
        retired(o.advance_dispatch(&mut a)),
        Outcome::Dispatched {
            source: 64,
            registered: false,
            more: false
        }
    );
    assert_eq!(o.snapshot().current, 64);
    assert_eq!(
        s.borrow().effects,
        vec![(0xc000, None), (u64::MAX - 1, None)]
    );
}

#[test]
#[cfg(feature = "std")]
#[ignore = "requires original26A434 T8112 PMP via STELA_TEST_PMP_T8112"]
fn original_native_irq_selection_mapping_and_control_operands_match() {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
    );
    let word =
        |va: usize| u32::from_le_bytes(bytes[va - 0xfff000..va - 0xfff000 + 4].try_into().unwrap());
    let wide =
        |va: usize| u64::from_le_bytes(bytes[va - 0xfff000..va - 0xfff000 + 8].try_into().unwrap());
    assert_eq!(wide(0x1044650), 0x23b0c0000);
    assert_eq!(wide(0x1044658), 0x20000);
    assert_eq!(word(0x1044660), 1); // Actual relocation is mandatory.
    assert_eq!(word(0x1044680), 1);
    assert_eq!(word(0x1044684), 2); // target1,type2.
    assert_eq!(wide(0x1035608 + 0x28), 0x1026280);
    assert_eq!(wide(0x1035608 + 0x38), 0x10262b4);
    assert_eq!(word(0x1026470), 0x1140094a);
    assert_eq!(word(0x1026478), 0x528cc008);
    assert_eq!(word(0x1026480), 0x528c8008);
    assert_eq!(word(0x10264b4), 0xb829694b);
    assert_eq!(word(0x101cff0), 0xd63f0100);
    assert_eq!(word(0x101d070), 0x390c0268);
}
