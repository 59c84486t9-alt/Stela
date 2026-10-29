use super::*;
use crate::Result;
use alloc::{collections::VecDeque, vec};
use stela_contracts::interrupt::InterruptLatch;
use stela_contracts::refuse;
struct Mapped {
    geometry: MapRequest,
    bytes: Vec<u8>,
    fail_read: bool,
}
impl Mapping for Mapped {
    fn geometry(&self) -> MapRequest {
        self.geometry
    }
    fn read(&mut self, offset: u64, output: &mut [u8], _: &mut Access<'_>) -> Result<()> {
        if self.fail_read {
            self.fail_read = false;
            return Err(refuse!("actual RAM read fault"));
        }
        let at = usize::try_from(offset).unwrap();
        output.copy_from_slice(&self.bytes[at..at + output.len()]);
        Ok(())
    }
    fn write(&mut self, offset: u64, input: &[u8], _: &mut Access<'_>) -> Result<()> {
        let at = usize::try_from(offset).unwrap();
        self.bytes[at..at + input.len()].copy_from_slice(input);
        Ok(())
    }
}
#[derive(Clone, Copy)]
enum Outcome {
    Busy,
    Refuse,
    Retire,
    RetireRefuse,
}
struct Backing {
    maps: Vec<Request>,
    unmaps: Vec<Request>,
    map_steps: VecDeque<Outcome>,
    unmap_steps: VecDeque<Outcome>,
    table: Vec<u8>,
    fail_read: bool,
    bad_geometry: bool,
}
impl Backing {
    fn new() -> Self {
        Self {
            maps: Vec::new(),
            unmaps: Vec::new(),
            map_steps: VecDeque::new(),
            unmap_steps: VecDeque::new(),
            table: vec![0; 4096],
            fail_read: false,
            bad_geometry: false,
        }
    }
}
impl Backend for Backing {
    type Mapping = Mapped;
    fn map(
        &mut self,
        request: &Request,
        mut geometry: MapRequest,
        _: &mut Access<'_>,
    ) -> MapStep<Mapped> {
        self.maps.push(request.clone());
        match self.map_steps.pop_front().unwrap_or(Outcome::Retire) {
            Outcome::Busy => MapStep::Busy { deadline: Some(11) },
            Outcome::Refuse => MapStep::Refused(refuse!("actual mapping unavailable")),
            value => {
                if self.bad_geometry {
                    geometry.bus += PAGE;
                }
                let mut bytes = vec![0; usize::try_from(geometry.bytes).unwrap()];
                if bytes.len() >= self.table.len() {
                    bytes[..self.table.len()].copy_from_slice(&self.table);
                }
                MapStep::Retired {
                    mapping: Mapped {
                        geometry,
                        bytes,
                        fail_read: core::mem::take(&mut self.fail_read),
                    },
                    refusal: matches!(value, Outcome::RetireRefuse)
                        .then_some(refuse!("post-map refusal")),
                }
            }
        }
    }
    fn unmap(&mut self, request: &Request, _: &mut Mapped, _: &mut Access<'_>) -> Step {
        self.unmaps.push(request.clone());
        match self.unmap_steps.pop_front().unwrap_or(Outcome::Retire) {
            Outcome::Busy => Step::Busy { deadline: Some(12) },
            Outcome::Refuse => Step::Refused(refuse!("actual unmap unavailable")),
            value => Step::Retired {
                refusal: matches!(value, Outcome::RetireRefuse)
                    .then_some(refuse!("post-unmap refusal")),
            },
        }
    }
}
fn client(backing: Backing) -> Client<Backing> {
    Client::new(Claim::new(Rc::new(()), Rc::new(Cell::new(true))), backing).unwrap()
}
fn advance(c: &mut Client<Backing>) -> Result<Progress> {
    c.advance(&mut Access::new(0, 5, &mut InterruptLatch::new()))
}
fn allocated(c: &mut Client<Backing>, bus: u64) -> Allocation {
    c.begin_allocate(5000).unwrap();
    let mut out = Vec::new();
    assert!(c.emit(&mut out).unwrap());
    assert_eq!(out, [0x0012_0000_0000_2000]);
    c.receive(0x0013_0000_0000_0000 | bus).unwrap();
    advance(c).unwrap();
    match c.take_completion().unwrap().unwrap() {
        Completion::Allocated(Some(a)) => a,
        _ => panic!("expected actual mapping"),
    }
}
#[test]
fn shared_slot_reply_survives_busy_and_refusal() {
    let mut backend = Backing::new();
    backend.map_steps = VecDeque::from([Outcome::Busy, Outcome::Refuse, Outcome::RetireRefuse]);
    let mut c = client(backend);
    c.begin_allocate(5000).unwrap();
    assert!(c.begin_init().is_err());
    assert!(c.receive(0x0013_0000_0000_4000).is_err());
    let mut out = Vec::new();
    c.emit(&mut out).unwrap();
    for wrong in [
        0x0011_0000_0000_4000,
        0x0015_0000_0000_0000,
        0x0113_0000_0000_4000,
        0x0013_0000_0000_4001,
    ] {
        assert!(c.receive(wrong).is_err());
    }
    c.receive(0x0013_0000_0000_4000).unwrap();
    for duplicate in [0x0013_0000_0000_4000, 0x0013_0000_0000_8000] {
        assert!(c.receive(duplicate).is_err());
    }
    assert_eq!(advance(&mut c), Ok(Progress::Busy { deadline: Some(11) }));
    assert!(advance(&mut c).is_err());
    assert_eq!(advance(&mut c), Err(refuse!("post-map refusal")));
    assert!(!c.emit(&mut out).unwrap());
    assert_eq!(out.len(), 1);
    assert_eq!(c.backend.maps.len(), 3);
    assert!(
        c.backend
            .maps
            .windows(2)
            .all(|r| r[0].same_operation(&r[1]))
    );
    advance(&mut c).unwrap();
    assert_eq!(c.backend.maps.len(), 3);
    assert!(c.begin_allocate(1).is_err());
    let allocation = match c.take_completion().unwrap().unwrap() {
        Completion::Allocated(Some(a)) => a,
        _ => panic!(),
    };
    let mut latch = InterruptLatch::new();
    let mut a = Access::new(0, 6, &mut latch);
    c.write(&allocation, 4999, &[0x72], &mut a).unwrap();
    let mut value = [0];
    c.read(&allocation, 4999, &mut value, &mut a).unwrap();
    assert_eq!(value, [0x72]);
    assert!(c.write(&allocation, 5000, &[1], &mut a).is_err());
    assert!(c.read(&allocation, u64::MAX, &mut value, &mut a).is_err());
    assert!(c.receive(0x0013_0000_0000_4000).is_err());
}
#[test]
fn local_unmap_retires_before_wire_free_and_equal_bus_reuse_has_new_identity() {
    let mut backing = Backing::new();
    backing.unmap_steps = VecDeque::from([Outcome::Busy, Outcome::Refuse, Outcome::RetireRefuse]);
    let mut c = client(backing);
    let first = allocated(&mut c, 0x4000);
    c.begin_free(&first).unwrap();
    let mut out = Vec::new();
    assert!(!c.emit(&mut out).unwrap());
    assert_eq!(advance(&mut c), Ok(Progress::Busy { deadline: Some(12) }));
    assert!(advance(&mut c).is_err());
    assert!(!c.emit(&mut out).unwrap());
    assert_eq!(advance(&mut c), Err(refuse!("post-unmap refusal")));
    assert!(c.emit(&mut out).unwrap());
    assert_eq!(out, [0x0014_0000_0000_4000]);
    assert!(!c.emit(&mut out).unwrap());
    assert!(
        c.read(
            &first,
            0,
            &mut [0],
            &mut Access::new(0, 0, &mut InterruptLatch::new())
        )
        .is_err()
    );
    assert!(
        c.backend
            .unmaps
            .windows(2)
            .all(|r| r[0].same_operation(&r[1]))
    );
    assert_eq!(c.backend.unmaps[0].effect(), Effect::Unmap);
    assert!(!c.backend.maps[0].same_operation(&c.backend.unmaps[0]));
    assert!(c.receive(0x0015_0000_0000_4000).is_err());
    c.receive(0x0015_0000_0000_0000).unwrap();
    advance(&mut c).unwrap();
    assert_eq!(c.backend.unmaps.len(), 3);
    assert!(matches!(
        c.take_completion().unwrap(),
        Some(Completion::Freed(_))
    ));
    let second = allocated(&mut c, 0x4000);
    assert!(!Rc::ptr_eq(&first.object, &second.object));
    c.begin_free(&first).unwrap();
    assert!(!c.emit(&mut out).unwrap());
    assert!(matches!(
        c.take_completion().unwrap(),
        Some(Completion::Freed(_))
    ));
    let mut foreign = client(Backing::new());
    assert!(foreign.begin_free(&second).is_err());
    assert!(
        c.read(
            &first,
            0,
            &mut [0],
            &mut Access::new(0, 0, &mut InterruptLatch::new())
        )
        .is_err()
    );
    c.read(
        &second,
        0,
        &mut [0],
        &mut Access::new(0, 0, &mut InterruptLatch::new()),
    )
    .unwrap();
}
#[test]
fn static_table_is_actual_read_prefix_not_mapping_permission_or_dynamic_allocation() {
    let mut backing = Backing::new();
    backing.fail_read = true;
    backing.table[..8].copy_from_slice(&0x8000_0000u64.to_le_bytes());
    backing.table[8..16].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
    backing.table[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
    let mut c = client(backing);
    c.begin_init().unwrap();
    let mut out = Vec::new();
    c.emit(&mut out).unwrap();
    assert_eq!(out, [0x0010_0000_0000_0000]);
    c.receive(0x0011_0000_0000_1000).unwrap();
    assert_eq!(advance(&mut c), Err(refuse!("actual RAM read fault")));
    assert!(c.table.is_none());
    advance(&mut c).unwrap();
    assert_eq!(c.backend.maps.len(), 1);
    assert_eq!(c.backend.unmaps.len(), 0);
    assert!(c.table.is_some());
    let regions = match c.take_completion().unwrap().unwrap() {
        Completion::Initialized(Some(r)) => r,
        _ => panic!(),
    };
    assert_eq!(
        regions,
        [Region {
            physical: 0x8000_0000,
            bus: 0x1_8000_0000,
            bytes: 0x2000
        }]
    );
    assert!(c.begin_init().is_err());
    assert_eq!(c.allocations.len(), 0);
    assert_eq!(
        c.table.as_ref().unwrap().geometry(),
        MapRequest {
            bus: 0x1000,
            bytes: 4096,
            source_mode: 2
        }
    );
}
#[test]
fn zero_reply_and_empty_table_are_distinct() {
    for bus in [0, 0x1000] {
        let mut c = client(Backing::new());
        c.begin_init().unwrap();
        c.emit(&mut Vec::new()).unwrap();
        c.receive(0x0011_0000_0000_0000 | bus).unwrap();
        advance(&mut c).unwrap();
        match c.take_completion().unwrap().unwrap() {
            Completion::Initialized(value) => {
                assert_eq!(value, if bus == 0 { None } else { Some(Vec::new()) })
            }
            _ => panic!(),
        }
        assert_eq!(c.backend.maps.len(), usize::from(bus != 0));
    }
    let mut c = client(Backing::new());
    c.begin_allocate(0).unwrap();
    c.emit(&mut Vec::new()).unwrap();
    c.receive(0x0013_0000_0000_0000).unwrap();
    advance(&mut c).unwrap();
    assert!(matches!(
        c.take_completion().unwrap(),
        Some(Completion::Allocated(None))
    ));
    assert!(c.backend.maps.is_empty());
}

#[test]
fn abandoned_client_does_not_clean_up() {
    let mut c = client(Backing::new());
    let allocation = allocated(&mut c, 0x4000);
    c.claim.alive.set(false);
    assert!(c.begin_free(&allocation).is_err());
    assert!(c.emit(&mut Vec::new()).is_err());
    assert!(advance(&mut c).is_err());
    assert!(c.receive(0x0015_0000_0000_0000).is_err());
    assert!(c.take_completion().is_err());
    assert!(c.allocations[0].mapping.is_some());
    assert!(c.backend.unmaps.is_empty());
}
#[test]
fn bad_backend_geometry_is_kept_and_never_credited_or_replayed() {
    let mut backing = Backing::new();
    backing.bad_geometry = true;
    let mut c = client(backing);
    c.begin_allocate(1).unwrap();
    c.emit(&mut Vec::new()).unwrap();
    c.receive(0x0013_0000_0000_4000).unwrap();
    for _ in 0..2 {
        assert!(advance(&mut c).is_err());
    }
    assert_eq!(c.backend.maps.len(), 1);
    assert!(c.pending.as_ref().unwrap().mapping.is_some());
    assert!(c.take_completion().unwrap().is_none());
    assert!(
        c.begin_free(&Allocation {
            owner: c.claim.owner.clone(),
            object: Rc::new(())
        })
        .is_err()
    );
}
