use super::*;
use crate::Result;
use crate::asc::{Asc, Firmware, Lines, Message};
use alloc::{boxed::Box, vec::Vec};
use stela_contracts::bus::Lifecycle;
use stela_contracts::refuse;
use {stela_contracts::dma::Memory, stela_contracts::dma::test_support::Ram};
use {stela_contracts::interrupt::AicInput, stela_contracts::interrupt::InterruptLatch};

struct FetchOwner {
    ram: Ram,
    mapping: Option<(u64, u64, u64)>,
    allocated: bool,
}
struct Peer(Rc<RefCell<FetchOwner>>);
impl Firmware for Peer {
    fn fetch_entry(&mut self, iop: u64) -> Result<EntryFetch> {
        let mut owner = self.0.borrow_mut();
        if !owner.allocated {
            return Err(refuse!("test allocation owner released"));
        }
        let (base, physical, bytes) = owner.mapping.ok_or(refuse!("test IOP mapping is absent"))?;
        let offset = iop
            .checked_sub(base)
            .ok_or(refuse!("test fetch precedes mapping"))?;
        if offset.checked_add(4).is_none_or(|end| end > bytes) {
            return Err(refuse!("test complete fetch exceeds mapping"));
        }
        let physical = physical
            .checked_add(offset)
            .ok_or(refuse!("test fetch physical overflow"))?;
        let mut raw = [0; 4];
        if !owner.ram.read(physical, &mut raw) {
            return Err(refuse!("test fetch is not owned RAM"));
        }
        Ok(EntryFetch {
            physical,
            instruction: u32::from_le_bytes(raw),
        })
    }

    fn start(&mut self, _: &mut Vec<Message>) -> Result<()> {
        Ok(())
    }
    fn receive(&mut self, _: Message, _: &mut Vec<Message>) -> Result<()> {
        Ok(())
    }
    fn check_reset(&self) -> Result<()> {
        Ok(())
    }
    fn reset(&mut self) -> Result<()> {
        Ok(())
    }
    fn stop(&mut self) -> Result<()> {
        Ok(())
    }
    fn resume(&mut self, _: &mut Vec<Message>) -> Result<()> {
        Ok(())
    }
}
const ENTRY: u64 = 0x20_0000;
const PHYSICAL: u64 = 0x8000_0000;
const INSTRUCTION: u32 = 0x1400_0081;

fn mapping(iop_base: u64) -> EntryMapping {
    EntryMapping {
        linked_base: 0,
        physical_base: PHYSICAL,
        iop_base,
        bytes: 0x4000,
    }
}
fn handoff(word: u64) -> EntryHandoff {
    EntryHandoff::from_mapping(
        mapping(ENTRY),
        0,
        INSTRUCTION,
        word,
        Origin::NativeBootResource,
    )
    .unwrap()
}
fn owner_with_mapping(running: bool, iop: u64) -> (Asc, Rc<RefCell<FetchOwner>>) {
    let mut ram = Ram::new(PHYSICAL, 0x4000);
    assert!(ram.write(PHYSICAL, &INSTRUCTION.to_le_bytes()));
    let owned = Rc::new(RefCell::new(FetchOwner {
        ram,
        mapping: Some((iop, PHYSICAL, 0x4000)),
        allocated: true,
    }));
    let asc = Asc::new(
        Box::new(Peer(owned.clone())),
        running,
        Lines::from_interrupts([1, 2, 3, 4].map(|irq| AicInput::new(0, irq))),
    )
    .unwrap();
    (asc, owned)
}
fn owner(running: bool) -> Asc {
    owner_with_mapping(running, ENTRY).0
}

#[test]
fn running_requires_locked_and_fetched_entry() {
    let mut asc = owner(true);
    let mut aux = asc.auxiliary();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    assert!(aux.read(0, Width::Double, &mut access).is_err());
    assert!(
        aux.write(0, Width::Double, ENTRY | LOCK, &mut access)
            .is_err()
    );
    assert!(asc.establish_entry(handoff(0)).is_err());
    assert!(aux.read(0, Width::Double, &mut access).is_err());
    asc.establish_entry(handoff(ENTRY | LOCK)).unwrap();
    assert_eq!(
        aux.read(0, Width::Double, &mut access).unwrap(),
        ENTRY | LOCK
    );
    assert!(asc.establish_entry(handoff(ENTRY | LOCK)).is_err());
}

#[test]
fn authorized_programming_precedes_start_and_locked_writes_refuse() {
    let mut asc = owner(false);
    asc.establish_entry(handoff(0)).unwrap();
    let mut aux = asc.auxiliary();
    let mut second = asc.auxiliary();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    assert!(asc.write(0x44, Width::Word, 0x10, &mut access).is_err());
    assert!(!asc.running);
    for value in [
        ENTRY,
        (ENTRY + 0x800) | LOCK,
        ENTRY | LOCK | 2,
        1 << 63 | ENTRY | LOCK,
    ] {
        assert!(aux.write(0, Width::Double, value, &mut access).is_err());
        assert_eq!(second.read(0, Width::Double, &mut access).unwrap(), 0);
    }
    for (offset, width) in [(8, Width::Double), (0, Width::Word)] {
        assert!(aux.write(offset, width, ENTRY | LOCK, &mut access).is_err());
        assert!(aux.read(offset, width, &mut access).is_err());
    }
    aux.write(0, Width::Double, ENTRY | LOCK, &mut access)
        .unwrap();
    assert_eq!(
        second.read(0, Width::Double, &mut access).unwrap(),
        ENTRY | LOCK
    );
    assert!(
        aux.write(0, Width::Double, ENTRY | LOCK, &mut access)
            .is_err()
    );
    asc.write(0x44, Width::Word, 0x10, &mut access).unwrap();
    assert!(asc.running);
}

#[test]
fn one_owner_keeps_or_invalidates_every_auxiliary_handle() {
    let mut asc = owner(true);
    // Capture may include opaque bits the consumers never decode.
    let opaque = 1 << 63;
    let captured = EntryHandoff::from_mapping(
        mapping(ENTRY),
        0,
        INSTRUCTION,
        ENTRY | LOCK | opaque,
        Origin::PhysicalCapture,
    )
    .unwrap();
    assert_eq!(captured.origin(), Origin::PhysicalCapture);
    asc.establish_entry(captured).unwrap();
    let mut aux = asc.auxiliary();
    let active = asc.lifecycle;
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    asc.write(0x44, Width::Word, 0, &mut access).unwrap();
    assert_eq!(
        aux.read(0, Width::Double, &mut access).unwrap(),
        captured.word
    );
    let retained = LifecycleState {
        powered: false,
        clocked: false,
        retention: true,
        ..active
    };
    asc.check_lifecycle(retained).unwrap();
    asc.set_lifecycle(retained, &mut access);
    assert!(aux.read(0, Width::Double, &mut access).is_err());
    asc.set_lifecycle(active, &mut access);
    assert_eq!(
        aux.read(0, Width::Double, &mut access).unwrap(),
        captured.word
    );
    for destructive in [
        LifecycleState {
            reset: true,
            ..active
        },
        LifecycleState {
            powered: false,
            ..active
        },
    ] {
        asc.check_lifecycle(destructive).unwrap();
        asc.set_lifecycle(destructive, &mut access);
        asc.set_lifecycle(active, &mut access);
        assert!(aux.read(0, Width::Double, &mut access).is_err());
        assert!(
            aux.write(0, Width::Double, ENTRY | LOCK, &mut access)
                .is_err()
        );
        assert!(asc.write(0x44, Width::Word, 0x10, &mut access).is_err());
        assert!(!asc.running);
        asc.establish_entry(captured).unwrap();
    }
}

#[test]
fn resource_geometry_and_locked_identity_are_checked() {
    let origin = Origin::NativeBootResource;
    for (mapping, offset, word) in [
        (mapping(ENTRY + 4), 0, 0),
        (mapping(1 << 42), 0, 0),
        (mapping(ENTRY), 0x4000 - 3, 0),
        (
            EntryMapping {
                bytes: 3,
                ..mapping(ENTRY)
            },
            0,
            0,
        ),
        (
            EntryMapping {
                physical_base: u64::MAX,
                ..mapping(ENTRY)
            },
            0,
            0,
        ),
        (
            EntryMapping {
                linked_base: u64::MAX,
                ..mapping(ENTRY)
            },
            0,
            0,
        ),
        (mapping(ENTRY), 0, (ENTRY + 0x800) | LOCK),
        (mapping(ENTRY), 0, ENTRY | LOCK | (1 << 63)),
    ] {
        assert!(EntryHandoff::from_mapping(mapping, offset, INSTRUCTION, word, origin).is_err());
    }
    let h = handoff(0);
    assert_eq!(h.origin(), origin);
    assert_eq!(
        (h.linked_entry(), h.physical_entry(), h.iop_entry()),
        (0, PHYSICAL, ENTRY)
    );
}

#[test]
fn mapped_iop_zero_requires_current_allocation_mapping_and_instruction() {
    let (mut asc, owned) = owner_with_mapping(false, 0);
    let h =
        EntryHandoff::from_mapping(mapping(0), 0, INSTRUCTION, LOCK, Origin::NativeBootResource)
            .unwrap();
    assert_eq!(
        (h.linked_entry(), h.physical_entry(), h.iop_entry()),
        (0, PHYSICAL, 0)
    );
    asc.establish_entry(h).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut aux = asc.auxiliary();
    assert_eq!(aux.read(0, Width::Double, &mut access).unwrap(), LOCK);
    owned.borrow_mut().mapping = None;
    assert!(asc.write(0x44, Width::Word, 0x10, &mut access).is_err());
    assert!(!asc.running);
    owned.borrow_mut().mapping = Some((0, PHYSICAL, 0x4000));
    owned.borrow_mut().allocated = false;
    assert!(asc.write(0x44, Width::Word, 0x10, &mut access).is_err());
    owned.borrow_mut().allocated = true;
    assert!(
        owned
            .borrow_mut()
            .ram
            .write(PHYSICAL, &0xd503201fu32.to_le_bytes())
    );
    assert!(asc.write(0x44, Width::Word, 0x10, &mut access).is_err());
    assert!(!asc.running);
    assert!(
        owned
            .borrow_mut()
            .ram
            .write(PHYSICAL, &INSTRUCTION.to_le_bytes())
    );
    asc.write(0x44, Width::Word, 0x10, &mut access).unwrap();
    assert!(asc.running);
    asc.write(0x44, Width::Word, 0, &mut access).unwrap();
    owned.borrow_mut().mapping = None;
    assert!(asc.write(0x44, Width::Word, 0x10, &mut access).is_err());
    assert!(!asc.running);
}

#[test]
fn source_instruction_or_resolved_physical_mismatch_refuses_handoff() {
    let (mut asc, owned) = owner_with_mapping(false, ENTRY);
    let wrong = EntryHandoff::from_mapping(
        mapping(ENTRY),
        0,
        INSTRUCTION ^ 1,
        0,
        Origin::NativeBootResource,
    )
    .unwrap();
    assert!(asc.establish_entry(wrong).is_err());
    owned.borrow_mut().mapping = Some((ENTRY, PHYSICAL + 0x800, 0x3800));
    assert!(
        owned
            .borrow_mut()
            .ram
            .write(PHYSICAL + 0x800, &INSTRUCTION.to_le_bytes())
    );
    assert!(asc.establish_entry(handoff(0)).is_err());
    let mut aux = asc.auxiliary();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    assert!(aux.read(0, Width::Double, &mut access).is_err());
}

#[test]
fn protocol_only_peer_cannot_claim_original_entry_ownership() {
    struct Protocol;
    impl Firmware for Protocol {
        fn start(&mut self, _: &mut Vec<Message>) -> Result<()> {
            Ok(())
        }
        fn receive(&mut self, _: Message, _: &mut Vec<Message>) -> Result<()> {
            Ok(())
        }
    }
    let mut asc = Asc::new(
        Box::new(Protocol),
        false,
        Lines::from_interrupts([1, 2, 3, 4].map(|irq| AicInput::new(0, irq))),
    )
    .unwrap();
    assert_eq!(
        asc.establish_entry(handoff(ENTRY | LOCK)),
        Err(refuse!(
            "original coprocessor instruction fetch ownership is not modeled"
        ))
    );
}
