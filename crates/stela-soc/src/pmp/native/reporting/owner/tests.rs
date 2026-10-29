use super::super::{getter, resources::Wake};
use super::*;
use crate::Result;
use alloc::vec;
use core::cell::Cell;
use stela_contracts::interrupt::InterruptLatch;
use stela_contracts::refuse;

fn done<T>(value: T) -> Completion<T> {
    Completion::Retired {
        value,
        refusal: None,
    }
}
struct Ram {
    bytes: Rc<RefCell<Vec<u8>>>,
    events: Rc<RefCell<Vec<&'static str>>>,
    fail_kind: Rc<Cell<bool>>,
}
impl Mapping for Ram {
    fn geometry(&self) -> wire::Buffer {
        wire::Buffer {
            bus: 0x100000,
            bytes: wire::REQUEST_BYTES,
        }
    }
    fn synchronization_granule(&self) -> Result<u64> {
        Ok(64)
    }
    fn write(
        &mut self,
        _: &Request,
        offset: u64,
        bytes: &[u8],
        _: &mut Access<'_>,
    ) -> Completion<usize> {
        self.bytes.borrow_mut()[offset as usize..offset as usize + bytes.len()]
            .copy_from_slice(bytes);
        self.events.borrow_mut().push("write");
        let refusal = if offset == 24 && self.fail_kind.replace(false) {
            Some(refuse!("authored post-kind-store diagnostic"))
        } else {
            None
        };
        Completion::Retired {
            value: bytes.len(),
            refusal,
        }
    }
    fn read(
        &mut self,
        _: &Request,
        offset: u64,
        bytes: usize,
        _: &mut Access<'_>,
    ) -> Completion<Vec<u8>> {
        done(self.bytes.borrow()[offset as usize..offset as usize + bytes].to_vec())
    }
    fn synchronize(
        &mut self,
        _: &Request,
        offset: u64,
        bytes: u64,
        _: &mut Access<'_>,
    ) -> Completion<()> {
        assert!(offset.is_multiple_of(64) && bytes.is_multiple_of(64));
        self.events.borrow_mut().push("sync");
        done(())
    }
}
struct Host {
    bytes: Rc<RefCell<Vec<u8>>>,
    events: Rc<RefCell<Vec<&'static str>>>,
    fail_kind: Rc<Cell<bool>>,
    sent: Vec<u64>,
}
impl Host {
    fn new() -> Self {
        Self {
            bytes: Rc::new(RefCell::new(vec![0xa5; wire::REQUEST_BYTES as usize])),
            events: Rc::new(RefCell::new(Vec::new())),
            fail_kind: Rc::new(Cell::new(false)),
            sent: Vec::new(),
        }
    }
}
impl Resources for Host {
    type Mapping = Ram;
    fn claim(&mut self, _: &Request, _: &mut Access<'_>) -> Completion<()> {
        self.events.borrow_mut().push("claim");
        done(())
    }
    fn map(
        &mut self,
        _: &Request,
        buffer: wire::Buffer,
        flags: u32,
        _: &mut Access<'_>,
    ) -> Completion<MapResult<Ram>> {
        assert_eq!(flags, 0x202);
        assert_eq!(buffer.bus, 0x100000);
        self.events.borrow_mut().push("map");
        done(MapResult::Mapped(Ram {
            bytes: self.bytes.clone(),
            events: self.events.clone(),
            fail_kind: self.fail_kind.clone(),
        }))
    }
    fn dsb_sy(&mut self, _: &Request, _: &mut Access<'_>) -> Completion<()> {
        self.events.borrow_mut().push("dsb");
        done(())
    }
    fn converted_clock(&mut self, _: &Request, _: &mut Access<'_>) -> Completion<u64> {
        self.events.borrow_mut().push("clock");
        done(1234)
    }
    fn send(
        &mut self,
        _: &Request,
        endpoint: u8,
        payload: u64,
        _: &mut Access<'_>,
    ) -> Completion<()> {
        assert_eq!(endpoint, 4);
        self.sent.push(payload);
        self.events.borrow_mut().push("send");
        done(())
    }
    fn arm_wait(&mut self, _: &Request, _: &WaitKey, _: &mut Access<'_>) -> Completion<()> {
        self.events.borrow_mut().push("arm");
        done(())
    }
    fn wait(&mut self, _: &Request, _: &WaitKey, _: &mut Access<'_>) -> Completion<()> {
        self.events.borrow_mut().push("wait");
        done(())
    }
    fn unmap(&mut self, _: &Request, _: &mut Ram, _: &mut Access<'_>) -> Completion<()> {
        self.events.borrow_mut().push("unmap");
        done(())
    }
    fn release(&mut self, _: &Request, _: &mut Ram, _: &mut Access<'_>) -> Completion<()> {
        self.events.borrow_mut().push("release");
        done(())
    }
}
struct Immediate {
    events: Rc<RefCell<Vec<&'static str>>>,
}
impl Wake for Immediate {
    fn publication_ack(&mut self, _: &WaitKey, _: &mut Access<'_>) -> Completion<()> {
        self.events.borrow_mut().push("ack");
        done(())
    }
    fn queue_refresh(&mut self, _: &mut Access<'_>) -> Completion<()> {
        self.events.borrow_mut().push("queue");
        done(())
    }
}
fn step(owner: &mut Owner<Host>) -> Result<Progress> {
    owner.advance(&mut Access::new(0, 1, &mut InterruptLatch::new()))
}
fn receive(owner: &Owner<Host>, payload: u64) -> Completion<()> {
    let mut wake = Immediate {
        events: owner.resources.events.clone(),
    };
    owner.receiver().receive(
        payload,
        &mut wake,
        &mut Access::new(0, 1, &mut InterruptLatch::new()),
    )
}
fn until(owner: &mut Owner<Host>, result: Finished) {
    for _ in 0..1024 {
        if step(owner).unwrap() == Progress::Finished(result.clone()) {
            return;
        }
    }
    panic!("authored reporting work failed to retire");
}
fn entered() -> Owner<Host> {
    let mut owner = Owner::new(Host::new());
    owner.enter(false).unwrap();
    for _ in 0..8 {
        step(&mut owner).unwrap();
        if owner.resources.sent == [wire::BUFFER_REQUEST] {
            break;
        }
    }
    assert!(matches!(
        receive(&owner, wire::BUFFER_REQUEST | 0x100000),
        Completion::Retired { .. }
    ));
    until(&mut owner, Finished::Ready);
    assert_eq!(owner.resources.sent, [wire::BUFFER_REQUEST, wire::READY]);
    assert_eq!(owner.used_bytes(), 16);
    assert_eq!(owner.record_count(), 0);
    assert_eq!(
        &owner.resources.bytes.borrow()[..4],
        &record::MAGIC.to_le_bytes()
    );
    assert!(owner.resources.bytes.borrow()[16..].iter().all(|b| *b == 0));
    assert!(matches!(
        receive(&owner, wire::BUFFER_REQUEST | 0x100000),
        Completion::Refused(_)
    ));
    owner
}
struct Live {
    value: Rc<Cell<u64>>,
    calls: Rc<Cell<u32>>,
}
impl getter::Scalar for Live {
    fn get(&mut self, _: &Request, _: &mut Access<'_>) -> Completion<u64> {
        self.calls.set(self.calls.get() + 1);
        done(self.value.get())
    }
}
impl getter::Pair for Live {
    fn get(&mut self, _: &Request, index: u32, _: &mut Access<'_>) -> Completion<(u64, u64)> {
        self.calls.set(self.calls.get() + 1);
        done((self.value.get() + u64::from(index), 17))
    }
}
impl getter::Indexed for Live {
    fn get(&mut self, _: &Request, index: u32, _: &mut Access<'_>) -> Completion<u64> {
        self.calls.set(self.calls.get() + 1);
        done(self.value.get() + u64::from(index))
    }
}
impl getter::State for Live {
    fn get(&mut self, _: &Request, index: u32, _: &mut Access<'_>) -> Completion<[u64; 4]> {
        self.calls.set(self.calls.get() + 1);
        done([self.value.get() + u64::from(index), 2, 3, 4])
    }
}
fn metadata(channel: u64, layout: Layout) -> Metadata {
    Metadata {
        channel,
        category: 2,
        name: record::Name::new(b"Live"),
        group: record::Name::new(b"Authored"),
        unit: 1,
        layout,
        descriptions: if let Layout::States { descriptions, .. } = layout {
            vec![[9; 16]; descriptions as usize]
        } else {
            Vec::new()
        },
    }
}
fn registered(
    owner: &mut Owner<Host>,
    token: Registration,
    metadata: Metadata,
    getter: LiveGetter,
) {
    let channel = metadata.channel;
    let prior = owner.resources.sent.len();
    owner.register(token, metadata, getter).unwrap();
    for _ in 0..128 {
        step(owner).unwrap();
        if owner.resources.sent.len() > prior
            && owner.resources.sent.last() == Some(&wire::REGISTERED)
        {
            break;
        }
    }
    assert_eq!(step(owner).unwrap(), Progress::Busy { deadline: None });
    assert!(matches!(
        receive(owner, wire::REGISTERED),
        Completion::Retired { .. }
    ));
    until(
        owner,
        Finished::Registered(RegistrationResult::Published { epoch: 1, channel }),
    );
}
#[test]
fn ap_owned_ready_independent_ack_and_retired_kind_prefix_are_real() {
    let mut owner = entered();
    let token = Registration::new();
    let value = Rc::new(Cell::new(71));
    let calls = Rc::new(Cell::new(0));
    owner.resources.fail_kind.set(true);
    owner
        .register(
            token.clone(),
            metadata(1, Layout::Scalar),
            LiveGetter::Scalar(Box::new(Live {
                value: value.clone(),
                calls: calls.clone(),
            })),
        )
        .unwrap();
    assert_eq!(
        step(&mut owner),
        Err(refuse!("authored post-kind-store diagnostic"))
    );
    assert_eq!(owner.used_bytes(), 0x68);
    assert_eq!(owner.record_count(), 0);
    assert_eq!(calls.get(), 0);
    for _ in 0..64 {
        step(&mut owner).unwrap();
        if owner.resources.sent.last() == Some(&wire::REGISTERED) {
            break;
        }
    }
    assert_eq!(owner.record_count(), 1);
    assert_eq!(calls.get(), 1);
    assert_eq!(owner.registration_result(&token), None);
    assert_eq!(step(&mut owner).unwrap(), Progress::Busy { deadline: None });
    // Update is queued while the synchronous registration waits.
    assert!(matches!(
        receive(&owner, wire::UPDATE),
        Completion::Retired { .. }
    ));
    assert_eq!(calls.get(), 1);
    assert!(matches!(
        receive(&owner, wire::REGISTERED),
        Completion::Retired { .. }
    ));
    until(
        &mut owner,
        Finished::Registered(RegistrationResult::Published {
            epoch: 1,
            channel: 1,
        }),
    );
    value.set(90);
    until(&mut owner, Finished::Refreshed);
    assert_eq!(calls.get(), 2);
    assert_eq!(
        &owner.resources.bytes.borrow()[0x60..0x68],
        &90u64.to_le_bytes()
    );
    let events = owner.resources.events.borrow();
    let dsb = events.iter().position(|e| *e == "dsb").unwrap();
    assert_eq!(events[dsb - 1], "sync");
    assert_eq!(events[dsb + 1], "clock");
}
#[test]
fn all_getter_kinds_preserve_live_labels_and_once_registration_across_mapping_loss() {
    let mut owner = entered();
    let value = Rc::new(Cell::new(10));
    let calls = Rc::new(Cell::new(0));
    for (channel, layout) in [
        (1, Layout::Pairs(2)),
        (2, Layout::Scalars(2)),
        (
            3,
            Layout::States {
                count: 2,
                descriptions: 1,
            },
        ),
    ] {
        let live = Box::new(Live {
            value: value.clone(),
            calls: calls.clone(),
        });
        let getter = match layout {
            Layout::Pairs(count) => LiveGetter::Pairs {
                count,
                getter: live,
            },
            Layout::Scalars(count) => LiveGetter::Scalars {
                count,
                getter: live,
            },
            Layout::States {
                count,
                descriptions,
            } => LiveGetter::States {
                count,
                descriptions,
                getter: live,
            },
            _ => unreachable!(),
        };
        registered(
            &mut owner,
            Registration::new(),
            metadata(channel, layout),
            getter,
        );
        owner.labels(channel, &[(1, 0xfeed)]).unwrap();
        until(&mut owner, Finished::LabelsChanged);
    }
    let before = owner.resources.bytes.borrow().clone();
    value.set(40);
    assert!(matches!(
        receive(&owner, wire::UPDATE),
        Completion::Retired { .. }
    ));
    until(&mut owner, Finished::Refreshed);
    for row in &owner.records {
        let lane = match row.metadata.layout {
            Layout::Pairs(_) => 16,
            Layout::Scalars(_) => 8,
            _ => 32,
        };
        let offset = (row.offset + 0x50 + row.metadata.layout.stride() + lane) as usize;
        assert_eq!(
            &owner.resources.bytes.borrow()[offset..offset + 8],
            &before[offset..offset + 8]
        );
        assert_eq!(
            &owner.resources.bytes.borrow()[row.offset as usize + 0x38..row.offset as usize + 0x48],
            &[0; 16]
        );
    }
    let token = Registration::new();
    registered(
        &mut owner,
        token.clone(),
        metadata(4, Layout::Scalar),
        LiveGetter::Scalar(Box::new(Live {
            value: value.clone(),
            calls: calls.clone(),
        })),
    );
    owner.sleep().unwrap();
    owner.exit(0).unwrap();
    until(&mut owner, Finished::Released);
    assert_eq!(
        owner.registration_result(&token),
        Some(RegistrationResult::Published {
            epoch: 1,
            channel: 4
        })
    );
    assert_eq!(owner.record_count(), 0);
    let events = owner.resources.events.borrow();
    assert_eq!(&events[events.len() - 2..], &["unmap", "release"]);
}
#[test]
fn retired_getter_diagnostic_keeps_the_observed_value_without_a_second_call() {
    struct Diagnosed {
        value: Rc<Cell<u64>>,
        calls: Rc<Cell<u32>>,
    }
    impl getter::Scalar for Diagnosed {
        fn get(&mut self, _: &Request, _: &mut Access<'_>) -> Completion<u64> {
            self.calls.set(self.calls.get() + 1);
            Completion::Retired {
                value: self.value.get(),
                refusal: Some(refuse!("authored retired getter diagnostic")),
            }
        }
    }
    let mut owner = entered();
    let value = Rc::new(Cell::new(55));
    let calls = Rc::new(Cell::new(0));
    owner
        .register(
            Registration::new(),
            metadata(1, Layout::Scalar),
            LiveGetter::Scalar(Box::new(Diagnosed {
                value: value.clone(),
                calls: calls.clone(),
            })),
        )
        .unwrap();
    let mut reached = false;
    for _ in 0..32 {
        if step(&mut owner) == Err(refuse!("authored retired getter diagnostic")) {
            reached = true;
            break;
        }
    }
    assert!(reached);
    assert_eq!(calls.get(), 1);
    assert_eq!(owner.record_count(), 0);
    value.set(99);
    for _ in 0..64 {
        step(&mut owner).unwrap();
        if owner.resources.sent.last() == Some(&wire::REGISTERED) {
            break;
        }
    }
    assert_eq!(
        &owner.resources.bytes.borrow()[0x60..0x68],
        &55u64.to_le_bytes()
    );
    assert_eq!(calls.get(), 1);
    assert!(matches!(
        receive(&owner, wire::REGISTERED),
        Completion::Retired { .. }
    ));
    until(
        &mut owner,
        Finished::Registered(RegistrationResult::Published {
            epoch: 1,
            channel: 1,
        }),
    );
}
#[test]
fn backend_identities_refuse_exhaustion_before_any_resource_effect() {
    let mut owner = Owner::new(Host::new());
    owner.serial = u64::MAX;
    assert_eq!(
        owner.enter(false),
        Err(refuse!("IOReporting job identity exhausted"))
    );
    assert!(owner.resources.events.borrow().is_empty());
    assert!(owner.job.is_none());
    assert_eq!(owner.state, 0);
    owner.serial = 0;
    owner.epoch = u64::MAX;
    assert_eq!(
        owner.enter(false),
        Err(refuse!("IOReporting lifecycle epoch exhausted"))
    );
    assert!(owner.resources.events.borrow().is_empty());
    owner.epoch = 0;
    owner.enter(false).unwrap();
    owner.job.as_mut().unwrap().request.operation = u64::MAX;
    assert_eq!(
        step(&mut owner),
        Err(refuse!("IOReporting backend operation identity exhausted"))
    );
    assert!(owner.resources.events.borrow().is_empty());
    assert_eq!(owner.job.as_ref().unwrap().request.operation, u64::MAX);
    assert_eq!(
        step(&mut owner),
        Err(refuse!("IOReporting backend operation identity exhausted"))
    );
}
#[test]
fn absent_database_is_a_kept_source_failure_without_getter_or_publication() {
    let mut owner = Owner::new(Host::new());
    let token = Registration::new();
    let calls = Rc::new(Cell::new(0));
    for _ in 0..2 {
        let result = owner
            .register(
                token.clone(),
                metadata(1, Layout::Scalar),
                LiveGetter::Scalar(Box::new(Live {
                    value: Rc::new(Cell::new(0)),
                    calls: calls.clone(),
                })),
            )
            .unwrap();
        assert_eq!(result, Some(RegistrationResult::SourceError(NO_DATABASE)));
    }
    assert!(owner.resources.sent.is_empty());
    assert_eq!(calls.get(), 0);
    assert_eq!(owner.returned.len(), 1);
    assert!(owner.enter(true).is_err());
}
