//! Native coprocessor interrupt owner, distinct from AP AIC and PTD transport.
//!
//! Original26A434 T8112 PMP SHA256
//! b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//! constructor10066f0..10067b8, selected vtable1035608, initialize1026008,
//! dispatch1026194, signal1026280/10263f8, registry10262b4/1026328.
//! Fresh static evidence: memory/native-interrupts-r1. Firmware is never
//! executed. Required device/line/callback owners have no defaults.
mod auxiliary;
pub mod device;
mod owner;

use super::platform::owner::Completion;
pub use auxiliary::{AuxiliaryHandler, AuxiliaryReset, AuxiliaryTarget};
pub use owner::{Event, Handler, Owner, Registration, Signal, Signals, Snapshot};
use {
    stela_contracts::bus::Access, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::bus::Width,
};

pub const SPECIAL: u32 = 0x0800_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No effect retired. A missing required owner must return this variant.
    Refused(&'static str),
    /// MMIO may have retired; the owner permanently prevents access replay.
    Uncertain(MmioError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    pub address: u64,
    pub bytes: u64,
    pub relocation: u64,
}
impl Placement {
    ///1044650 is relocatable:1006714..28 adds actual1079fb0. Zero is allowed
    /// only when it is the declared runtime relocation, never a default.
    pub fn t8112(relocation: u64) -> Result<Self, Error> {
        let address = 0x23b0c0000u64
            .checked_add(relocation)
            .ok_or(Error::Refused(
                "native interrupt mapping relocation overflow",
            ))?;
        address
            .checked_add(0x20000)
            .ok_or(Error::Refused("native interrupt aperture overflow"))?;
        Ok(Self {
            address,
            bytes: 0x20000,
            relocation,
        })
    }
}

/// Source software configuration or an observation of it, not
/// controller reset/enable state. The original global BSS image has zero bytes
/// at P28/P8c; runtime overrides require their producers. Only bit0 is
/// interpreted. Snapshot-enabled lifecycle paths require real saved words.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SoftwareConfiguration {
    pub routing_flags: u8,
    pub save_flags: u8,
}

/// Required native device, ordering and CPU IRQ route. Numeric aperture
/// matching alone does not check an independently copied register bank.
/// Refused must be effect-free; every ambiguous MMIO error is Uncertain.
pub trait Device {
    fn placement(&self) -> Placement;
    fn read(&mut self, offset: u64, access: &mut Access<'_>) -> Result<u32, Error>;
    fn write(&mut self, offset: u64, value: u32, access: &mut Access<'_>) -> Result<(), Error>;
    fn order(&mut self, access: &mut Access<'_>) -> Result<(), Error>;
    /// Native ISR_EL1 bit7 route after one dispatched event. Never an
    /// expected mask, AP IRQ, queued request or guessed cache-counter event.
    fn irq_pending(&mut self, access: &mut Access<'_>) -> Result<bool, Error>;
}
pub trait Route {
    fn order(&mut self, access: &mut Access<'_>) -> Result<(), Error>;
    fn irq_pending(&mut self, access: &mut Access<'_>) -> Result<bool, Error>;
}

/// Adapter keeping MMIO and native line/order owners. `new` stores a
/// declared placement; it grants no mapped-borrow capability. Root must
/// check the same bus-owned view and native route when composing the owner.
/// Bounds checks below establish only the declared aperture, never identity.
pub struct Mapped<M, R> {
    placement: Placement,
    device: M,
    route: R,
}
impl<M, R> Mapped<M, R> {
    pub fn new(placement: Placement, device: M, route: R) -> Self {
        Self {
            placement,
            device,
            route,
        }
    }
}
impl<M: MmioDevice, R: Route> Device for Mapped<M, R> {
    fn placement(&self) -> Placement {
        self.placement
    }
    fn read(&mut self, offset: u64, access: &mut Access<'_>) -> Result<u32, Error> {
        if offset & 3 != 0
            || offset
                .checked_add(4)
                .is_none_or(|end| end > self.placement.bytes)
        {
            return Err(Error::Refused(
                "native interrupt word read exceeds declared mapped aperture",
            ));
        }
        self.device
            .read(offset, Width::Word, access)
            .map(|v| v as u32)
            .map_err(Error::Uncertain)
    }
    fn write(&mut self, offset: u64, value: u32, access: &mut Access<'_>) -> Result<(), Error> {
        if offset & 3 != 0
            || offset
                .checked_add(4)
                .is_none_or(|end| end > self.placement.bytes)
        {
            return Err(Error::Refused(
                "native interrupt word write exceeds declared mapped aperture",
            ));
        }
        self.device
            .write(offset, Width::Word, u64::from(value), access)
            .map_err(Error::Uncertain)
    }
    fn order(&mut self, access: &mut Access<'_>) -> Result<(), Error> {
        self.route.order(access)
    }
    fn irq_pending(&mut self, access: &mut Access<'_>) -> Result<bool, Error> {
        self.route.irq_pending(access)
    }
}

/// Retired source return or event outcome; none denotes native command
/// ACK, a device event producer, controller readiness or whole boot admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Signal {
        previous: bool,
    },
    Dispatched {
        source: u32,
        registered: bool,
        more: bool,
    },
    OtherEvent {
        word: u32,
    },
    Special {
        registered: bool,
    },
}
pub(super) fn refused(error: Error) -> Completion<Outcome> {
    Completion::Refused(match error {
        Error::Refused(reason) => reason,
        Error::Uncertain(_) => "native interrupt device retirement uncertain; replay refused",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, collections::VecDeque, rc::Rc, vec, vec::Vec};
    use core::cell::RefCell;
    use stela_contracts::interrupt::InterruptLatch;

    #[test]
    fn mapped_bounds_refuse_before_borrowing_the_supplied_actual_view() {
        struct View;
        impl MmioDevice for View {
            fn name(&self) -> &'static str {
                "authored unborrowed view"
            }
            fn read(&mut self, _: u64, _: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
                panic!("out of bounds actual read")
            }
            fn write(
                &mut self,
                _: u64,
                _: Width,
                _: u64,
                _: &mut Access<'_>,
            ) -> Result<(), MmioError> {
                panic!("out of bounds actual write")
            }
        }
        struct ActualRoute;
        impl Route for ActualRoute {
            fn order(&mut self, _: &mut Access<'_>) -> Result<(), Error> {
                panic!("no reached ordering")
            }
            fn irq_pending(&mut self, _: &mut Access<'_>) -> Result<bool, Error> {
                panic!("no reached line read")
            }
        }
        let p = Placement::t8112(0).unwrap();
        let mut mapped = Mapped::new(p, View, ActualRoute);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 1, &mut latch);
        for offset in [1, p.bytes, u64::MAX] {
            assert!(matches!(
                mapped.read(offset, &mut access),
                Err(Error::Refused(_))
            ));
            assert!(matches!(
                mapped.write(offset, 1, &mut access),
                Err(Error::Refused(_))
            ));
        }
    }

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
        fn reset_slot(&mut self, reset: &AuxiliaryReset, _: &mut Access<'_>) -> Completion<()> {
            self.0.borrow_mut().push((reset.event(), reset.slot()));
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
    fn unretired_source_producer_cannot_turn_image_flags_into_callback_reset() {
        let (mut o, s) = owner(512);
        let mut l = InterruptLatch::new();
        let mut a = Access::new(0, 7, &mut l);
        o.initialize(&mut a).unwrap();
        let descriptor = super::super::platform::authored_profile().descriptors()[4].clone();
        use super::super::platform::ingestion::control;
        let cfg = control::Configuration::t8112(&descriptor).unwrap();
        let mut image = control::SoftwareImage::zeroed(&cfg);
        image.slots[0].raw[1] = 1;
        let control = control::Owner::initialized_software(cfg, image).unwrap();
        let binding = control.auxiliary_binding(0).unwrap();
        assert!(!binding.registered());
        assert!(control.registered_auxiliary(0).unwrap().is_none());
        let effects = Rc::new(RefCell::new(Vec::new()));
        let handler =
            AuxiliaryHandler::t8112(&descriptor, 0, binding, Reset(effects.clone(), true)).unwrap();
        o.register(64, Box::new(handler)).unwrap();
        s.borrow_mut().pending.push_back(0x10040);
        s.borrow_mut().effects.clear();
        o.begin_dispatch(false).unwrap();
        for _ in 0..2 {
            assert!(matches!(
                o.advance_dispatch(&mut a),
                Completion::Refused("auxiliary IRQ registration producer has not retired")
            ));
        }
        assert!(effects.borrow().is_empty());
        assert_eq!(o.snapshot().current_enabled, 1);
        assert_eq!(s.borrow().effects, vec![(0xc000, None)]);
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
    #[ignore = "oracle: STELA_TEST_PMP_T8112"]
    fn original_native_irq_selection_mapping_and_control_operands_match() {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
        );
        let word = |va: usize| {
            u32::from_le_bytes(bytes[va - 0xfff000..va - 0xfff000 + 4].try_into().unwrap())
        };
        let wide = |va: usize| {
            u64::from_le_bytes(bytes[va - 0xfff000..va - 0xfff000 + 8].try_into().unwrap())
        };
        assert_eq!(wide(0x1044650), 0x23b0c0000);
        assert_eq!(wide(0x1044658), 0x20000);
        assert_eq!(word(0x1044660), 1); // Relocation is mandatory.
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
}
