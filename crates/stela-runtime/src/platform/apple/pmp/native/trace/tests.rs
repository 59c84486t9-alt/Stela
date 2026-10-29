use super::*;
use alloc::collections::VecDeque;
use core::cell::RefCell;
use stela_contracts::interrupt::InterruptLatch;
use stela_contracts::refuse;

type WriteLog = Rc<RefCell<Vec<(Request, u64, Vec<u8>)>>>;
#[derive(Clone)]
struct Bytes {
    geometry: Geometry,
    data: Rc<RefCell<Vec<u8>>>,
    writes: WriteLog,
    busy_timestamp: Rc<core::cell::Cell<bool>>,
    refuse_body: Rc<core::cell::Cell<bool>>,
    retired_body: Rc<core::cell::Cell<bool>>,
}
fn done<T>(value: T) -> Completion<T> {
    Completion::Retired {
        value,
        refusal: None,
    }
}
impl Mapping for Bytes {
    fn geometry(&self) -> Geometry {
        self.geometry
    }
    fn read(
        &mut self,
        _: &Request,
        offset: u64,
        out: &mut [u8],
        _: &mut Access<'_>,
    ) -> Completion<()> {
        let data = self.data.borrow();
        out.copy_from_slice(&data[offset as usize..offset as usize + out.len()]);
        done(())
    }
    fn write(
        &mut self,
        r: &Request,
        offset: u64,
        input: &[u8],
        _: &mut Access<'_>,
    ) -> Completion<()> {
        self.writes
            .borrow_mut()
            .push((r.clone(), offset, input.to_vec()));
        if input.len() == 24 && self.refuse_body.replace(false) {
            return Completion::Refused(refuse!("actual test body destination refused"));
        }
        if input.len() == 8 && input != [0u8; 8].as_slice() && self.busy_timestamp.replace(false) {
            return Completion::Busy { deadline: Some(7) };
        }
        self.data.borrow_mut()[offset as usize..offset as usize + input.len()]
            .copy_from_slice(input);
        if input.len() == 24 && self.retired_body.replace(false) {
            return Completion::Retired {
                value: (),
                refusal: Some(refuse!("actual test body committed before diagnostic")),
            };
        }
        done(())
    }
    fn synchronize(
        &mut self,
        _: &Request,
        _: Synchronization,
        _: &mut Access<'_>,
    ) -> Completion<()> {
        done(())
    }
}
struct Resources {
    messages: VecDeque<u64>,
    effects: Vec<(Request, Effect)>,
    views: Vec<Bytes>,
    busy_timestamp: Rc<core::cell::Cell<bool>>,
    refuse_body: Rc<core::cell::Cell<bool>>,
    retired_body: Rc<core::cell::Cell<bool>>,
    reads: u32,
    waits: bool,
}
impl Resources {
    fn new() -> Self {
        Self {
            messages: VecDeque::new(),
            effects: Vec::new(),
            views: Vec::new(),
            busy_timestamp: Rc::new(core::cell::Cell::new(false)),
            refuse_body: Rc::new(core::cell::Cell::new(false)),
            retired_body: Rc::new(core::cell::Cell::new(false)),
            reads: 0,
            waits: false,
        }
    }
}
impl Backend for Resources {
    type Mapping = Bytes;
    fn effect(&mut self, r: &Request, e: Effect, _: &mut Access<'_>) -> Completion<()> {
        self.effects.push((r.clone(), e));
        if e == Effect::NotifyWaiters {
            self.waits = false;
        }
        if e == Effect::DrainWait && self.waits {
            return Completion::Busy { deadline: Some(8) };
        }
        done(())
    }
    fn map(
        &mut self,
        _: &Request,
        _: Buffer,
        g: Geometry,
        _: &mut Access<'_>,
    ) -> Completion<Bytes> {
        let b = Bytes {
            geometry: g,
            data: Rc::new(RefCell::new(vec![0; g.bytes as usize])),
            writes: Rc::new(RefCell::new(Vec::new())),
            busy_timestamp: self.busy_timestamp.clone(),
            refuse_body: self.refuse_body.clone(),
            retired_body: self.retired_body.clone(),
        };
        self.views.push(b.clone());
        done(b)
    }
    fn receive(&mut self, _: &Request, _: &mut Access<'_>) -> Completion<Option<u64>> {
        done(self.messages.pop_front())
    }
    fn clock(&mut self, _: &Request, _: &mut Access<'_>) -> Completion<u64> {
        self.reads += 1;
        done(0x0102_0304_0506_0708)
    }
    fn thread_id(&mut self, _: &Request, _: &mut Access<'_>) -> Completion<u32> {
        done(19)
    }
    fn flush_context(&mut self, _: &Request, _: &mut Access<'_>) -> Completion<FlushContext> {
        done(FlushContext {
            on_thread_stack: false,
            irq_masked: false,
            scheduler_flag: 0,
        })
    }
}
fn advance(o: &mut Owner<Resources>) -> Result<Progress, Error> {
    let mut latch = InterruptLatch::new();
    o.advance(&mut Access::new(0, 999, &mut latch))
}
fn until(o: &mut Owner<Resources>, expected: Progress) {
    for _ in 0..256 {
        let p = advance(o).unwrap();
        if p == expected {
            return;
        }
        assert!(matches!(p, Progress::Busy { .. }), "{p:?}");
    }
    panic!("trace operation did not retire");
}
fn owner(capacity: u32) -> Owner<Resources> {
    let mut o = Owner::initialized(
        Configuration::from_source_capacity(capacity).unwrap(),
        Resources::new(),
    );
    o.begin_initialize().unwrap();
    until(&mut o, Progress::Initialized);
    o
}
fn command(o: &mut Owner<Resources>, raw: u64) {
    o.backend.messages.push_back(raw);
    o.begin_dispatch().unwrap();
    until(
        o,
        Progress::Dispatched {
            consumed: true,
            kind: Some((raw >> 48) as u8),
        },
    );
}
fn bound() -> Owner<Resources> {
    let mut o = owner(7);
    command(&mut o, (1u64 << 48) | 0x4000);
    command(&mut o, 6u64 << 48);
    o
}
#[test]
fn source_initialization_is_distinct_from_buffer_and_no_record_return() {
    let mut o = owner(7);
    assert_eq!(o.trace_control(), 1);
    assert!(!o.enabled());
    assert_eq!(Configuration::t8112().slots(), 0x8001);
    assert_eq!(Configuration::t8112().threshold(), 0x4000);
    assert_eq!(Configuration::t8112().ring_bytes(), 0x101000);
    let effects = o.backend.effects.len();
    o.begin_emit(12, [u64::MAX; 4]).unwrap();
    until(
        &mut o,
        Progress::Emitted(Emission {
            source_return: NO_BUFFER,
            record: None,
        }),
    );
    assert_eq!(o.backend.effects.len(), effects);
    assert_eq!(o.backend.reads, 0);
    assert!(o.backend.views.is_empty());
    command(&mut o, (1u64 << 48) | 0x4000);
    o.begin_emit(12, [0; 4]).unwrap();
    until(
        &mut o,
        Progress::Emitted(Emission {
            source_return: DISABLED,
            record: None,
        }),
    );
    assert_eq!(o.backend.reads, 0);
}
#[test]
fn body_then_ordering_then_timestamp_retry_keeps_same_request() {
    let mut o = bound();
    o.backend.busy_timestamp.set(true);
    o.begin_emit(0x1234_5678, [0xaaaa_ffff_1234_5678, 2, 3, 4])
        .unwrap();
    let mut saw = false;
    for _ in 0..64 {
        if advance(&mut o).unwrap() == (Progress::Busy { deadline: Some(7) }) {
            saw = true;
            break;
        }
    }
    assert!(saw);
    assert_eq!(o.indices(), (0, 1));
    let view = o.backend.views[0].clone();
    assert_eq!(&view.data.borrow()[..8], &[0; 8]);
    assert_eq!(&view.data.borrow()[16..20], &0x1234_5678u32.to_le_bytes());
    until(
        &mut o,
        Progress::Emitted(Emission {
            source_return: 0,
            record: Some(RecordKind::Requested),
        }),
    );
    assert_eq!(
        &view.data.borrow()[..8],
        &0x0102_0304_0506_0708u64.to_le_bytes()
    );
    let writes = view.writes.borrow();
    assert_eq!(writes.len(), 3);
    assert_eq!(writes[0].1, 8);
    assert_eq!(writes[1].1, 0);
    assert_eq!(writes[2].1, 0);
    assert!(writes[1].0.same_operation(&writes[2].0));
    assert!(
        o.backend
            .effects
            .iter()
            .any(|(_, e)| *e == Effect::Ordering(Ordering::TimestampRelease))
    );
}
#[test]
fn before_write_refusal_keeps_reservation_and_prefix_without_new_clock() {
    let mut o = bound();
    o.backend.refuse_body.set(true);
    o.begin_emit(8, [0; 4]).unwrap();
    let mut saw = false;
    for _ in 0..64 {
        if matches!(advance(&mut o), Err(Error::Backend(_))) {
            saw = true;
            break;
        }
    }
    assert!(saw);
    assert_eq!(o.indices(), (0, 1));
    assert_eq!(o.backend.reads, 1);
    assert!(o.begin_emit(9, [0; 4]).is_err());
    until(
        &mut o,
        Progress::Emitted(Emission {
            source_return: 0,
            record: Some(RecordKind::Requested),
        }),
    );
    let writes = o.backend.views[0].writes.borrow();
    assert!(writes[0].0.same_operation(&writes[1].0));
    assert_eq!(o.backend.reads, 1);
}
#[test]
fn filter_reads_mapping_and_refresh_precedes_new_observation() {
    let mut o = bound();
    command(&mut o, (2u64 << 48) | 0x8000);
    o.begin_emit(0x860b_b000, [1; 4]).unwrap();
    until(
        &mut o,
        Progress::Emitted(Emission {
            source_return: FILTERED,
            record: None,
        }),
    );
    assert_eq!(o.backend.reads, 0);
    assert_eq!(o.indices(), (0, 0));
    let event = 0x860b_b000u32;
    o.backend.views[1].data.borrow_mut()[(event >> 19) as usize] = 1 << ((event >> 16) & 7);
    command(&mut o, 9u64 << 48);
    o.begin_emit(event, [1; 4]).unwrap();
    until(
        &mut o,
        Progress::Emitted(Emission {
            source_return: 0,
            record: Some(RecordKind::Requested),
        }),
    );
    assert_eq!(o.backend.reads, 1);
}
#[test]
fn full_ring_notifies_and_returns_error_without_overwriting_slot() {
    let mut o = owner(1);
    command(&mut o, (1u64 << 48) | 0x4000);
    command(&mut o, 6u64 << 48);
    o.begin_emit(5, [1; 4]).unwrap();
    until(
        &mut o,
        Progress::Emitted(Emission {
            source_return: OVERFLOW,
            record: Some(RecordKind::OverflowMarker),
        }),
    );
    assert_eq!(
        &o.backend.views[0].data.borrow()[8..12],
        &OVERFLOW_EVENT.to_le_bytes()
    );
    assert_eq!(&o.backend.views[0].data.borrow()[16..32], &[0; 16]);
    let bytes = o.backend.views[0].data.borrow().clone();
    o.begin_emit(6, [2; 4]).unwrap();
    until(
        &mut o,
        Progress::Emitted(Emission {
            source_return: OVERFLOW,
            record: None,
        }),
    );
    assert_eq!(*o.backend.views[0].data.borrow(), bytes);
    assert_eq!(o.indices(), (0, 1));
}
#[test]
fn consumed_callback_can_retire_while_real_lifecycle_wait_is_kept() {
    let mut o = bound();
    o.begin_emit(1, [0; 4]).unwrap();
    until(
        &mut o,
        Progress::Emitted(Emission {
            source_return: 0,
            record: Some(RecordKind::Requested),
        }),
    );
    // AP flush request is read; next dispatch performs real flush.
    command(&mut o, 7u64 << 48);
    o.begin_dispatch().unwrap();
    until(
        &mut o,
        Progress::Dispatched {
            consumed: false,
            kind: None,
        },
    );
    assert!(o.flush_busy());
    o.backend.waits = true;
    o.begin_lifecycle(0x21, 0).unwrap();
    assert!(matches!(advance(&mut o).unwrap(), Progress::Busy { .. }));
    assert_eq!(
        advance(&mut o).unwrap(),
        Progress::Busy { deadline: Some(8) }
    );
    command(&mut o, (3u64 << 48) | 1);
    assert!(!o.flush_busy());
    // Notification now allows the already-entered wait to retire.
    until(&mut o, Progress::Paused);
    assert_eq!(o.indices(), (1, 1));
    assert_eq!(&o.backend.views[0].data.borrow()[..8], &[0; 8]);
    assert!(
        o.backend
            .effects
            .iter()
            .any(|(_, e)| *e == Effect::NotifyWaiters)
    );
    let waits: Vec<_> = o
        .backend
        .effects
        .iter()
        .filter(|(_, e)| *e == Effect::DrainWait)
        .collect();
    assert_eq!(waits.len(), 2);
    assert!(waits[0].0.same_operation(&waits[1].0));
    o.begin_lifecycle(0, 0x21).unwrap();
    until(&mut o, Progress::Resumed);
}
#[test]
fn source_unsigned_wrap_and_preflight_exhaustion_are_preserved() {
    // Source101f72c wraps W subtraction before modulo; do not replace with
    // an intuitive free-space expression. Original count is not power2.
    let count = Configuration::t8112().slots();
    assert_eq!(0u32.wrapping_sub(0).wrapping_sub(1) % count, 3);
    let mut o = bound();
    o.serial = u64::MAX;
    let before = o.backend.effects.len();
    assert!(o.begin_emit(1, [0; 4]).is_err());
    assert!(o.foreground.is_none());
    assert_eq!(o.backend.effects.len(), before);
    o.serial = 8;
    o.begin_emit(1, [0; 4]).unwrap();
    o.foreground.as_mut().unwrap().cursor = u64::MAX;
    assert!(advance(&mut o).is_err());
    assert_eq!(o.backend.reads, 0);
    assert_eq!(o.indices(), (0, 0));
}
#[test]
fn retired_body_diagnostic_never_replays_committed_bytes_or_reservation() {
    let mut o = bound();
    o.backend.retired_body.set(true);
    o.begin_emit(8, [5; 4]).unwrap();
    let mut saw = false;
    for _ in 0..64 {
        if matches!(advance(&mut o), Err(Error::Backend(_))) {
            saw = true;
            break;
        }
    }
    assert!(saw);
    assert_eq!(o.indices(), (0, 1));
    assert_eq!(&o.backend.views[0].data.borrow()[..8], &[0; 8]);
    assert_eq!(o.backend.views[0].writes.borrow().len(), 1);
    until(
        &mut o,
        Progress::Emitted(Emission {
            source_return: 0,
            record: Some(RecordKind::Requested),
        }),
    );
    let writes = o.backend.views[0].writes.borrow();
    assert_eq!(writes.len(), 2);
    assert_eq!(writes[0].1, 8);
    assert_eq!(writes[1].1, 0);
    assert_eq!(o.backend.reads, 1);
}
