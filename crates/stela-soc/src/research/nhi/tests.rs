use super::*;
use crate::Result;
use alloc::rc::Rc;
use core::cell::RefCell;
use stela_contracts::interrupt::InterruptLatch;
use stela_contracts::refuse;
use {
    stela_contracts::dma::Iommu, stela_contracts::dma::Memory,
    stela_contracts::dma::test_support::Ram,
};

#[derive(Default)]
struct State {
    sent: Vec<(usize, Vec<u8>, u8, u8, bool, u32)>,
    configured: Vec<(usize, Direction, Option<Options>)>,
    notifications: Vec<Frame>,
    deadline: Option<u64>,
    refuse_send: bool,
    refuse_reset: bool,
    refuse_options: bool,
    resets: usize,
}
struct Peer(Rc<RefCell<State>>);
impl Consumer for Peer {
    fn configure(&mut self, hop: usize, dir: Direction, options: Option<Options>) -> Result<()> {
        let mut state = self.0.borrow_mut();
        if state.refuse_options {
            return Err(refuse!("test wire cannot implement requested mode"));
        }
        state.configured.push((hop, dir, options));
        Ok(())
    }
    fn transmit(&mut self, frame: Transmit<'_>) -> Result<Option<Accepted>> {
        let mut state = self.0.borrow_mut();
        if state.refuse_send {
            return Err(refuse!("test wire rejected frame before acceptance"));
        }
        state.sent.push((
            frame.hop,
            frame.bytes.to_vec(),
            frame.sof,
            frame.eof,
            frame.isochronous,
            frame.scheduled_time,
        ));
        Ok(Some(Accepted {
            timestamp: 0x12345678,
            incoming: Vec::new(),
        }))
    }
    fn poll(&mut self, _: u64, _: &[usize]) -> Result<(Vec<Frame>, Option<u64>)> {
        let mut state = self.0.borrow_mut();
        Ok((core::mem::take(&mut state.notifications), state.deadline))
    }
    fn reset(&mut self) -> Result<()> {
        let mut state = self.0.borrow_mut();
        if state.refuse_reset {
            return Err(refuse!("test wire is not quiescent"));
        }
        state.resets += 1;
        state.notifications.clear();
        Ok(())
    }
}
#[derive(Default)]
struct Guard {
    fault: Option<(u64, bool)>,
    writes: Vec<u64>,
}
impl Iommu for Guard {
    fn page(&self) -> u64 {
        16
    }
    fn translate(
        &mut self,
        _: &mut dyn Memory,
        stream: usize,
        iova: u64,
        last: u64,
        write: bool,
        access: &mut Access<'_>,
    ) -> Result<u64, DmaError> {
        assert_eq!(stream, 1);
        assert_eq!(iova / 16, last / 16);
        if self.fault.is_some_and(|(address, direction)| {
            direction == write && (iova..=last).contains(&address)
        }) {
            access
                .interrupts
                .set_level(Wire::Aic(AicInput::new(0, 99)), true);
            return Err(DmaError::Fault(0x80));
        }
        if write {
            self.writes.push(iova);
        }
        Ok(iova)
    }
}
fn profile(count: u32) -> Profile {
    Profile {
        layout: Layout::ACIO,
        capability_words: [count, 0x76543210],
        shared_tx_buffers: 8,
    }
}
fn make(count: u32) -> (Nhi, Rc<RefCell<State>>) {
    let state = Rc::new(RefCell::new(State::default()));
    let tx = (0..count).map(|n| AicInput::new(0, n as u16)).collect();
    let rx = (0..count)
        .map(|n| AicInput::new(0, (n + count) as u16))
        .collect();
    let nhi = Nhi::new(profile(count), tx, rx, Box::new(Peer(state.clone()))).unwrap();
    (nhi, state)
}
fn write(nhi: &mut Nhi, access: &mut Access<'_>, offset: u64, width: Width, value: u64) {
    nhi.write(offset, width, value, access).unwrap();
}
fn read(nhi: &mut Nhi, access: &mut Access<'_>, offset: u64, width: Width) -> u64 {
    nhi.read(offset, width, access).unwrap()
}
fn program(
    nhi: &mut Nhi,
    access: &mut Access<'_>,
    direction: Direction,
    hop: usize,
    flags: u32,
    capacity: u16,
) {
    let base = if direction == Direction::Transmit {
        0x10000
    } else {
        0x80000
    } + hop as u64 * 0x4000;
    let descriptors = if direction == Direction::Transmit {
        0x1000
    } else {
        0x2000
    } + hop as u64 * 0x100;
    write(nhi, access, base, Width::Double, descriptors);
    write(
        nhi,
        access,
        base + 12,
        Width::Word,
        4 | u64::from(capacity) << 16,
    );
    write(
        nhi,
        access,
        base + 20,
        Width::Word,
        if direction == Direction::Transmit {
            2
        } else {
            0x00800400
        },
    );
    write(
        nhi,
        access,
        base + 16,
        Width::Word,
        u64::from(flags | ENABLE),
    );
}
fn descriptor(ram: &mut Ram, at: u64, payload: u64, metadata: u32, time: u32) {
    ram.put_u64(at, payload);
    ram.put_u64(at + 8, u64::from(metadata) | u64::from(time) << 32);
}
fn word(ram: &mut Ram, at: u64) -> u32 {
    let mut bytes = [0; 4];
    assert!(ram.read(at, &mut bytes));
    u32::from_le_bytes(bytes)
}
fn service(
    nhi: &mut Nhi,
    ram: &mut Ram,
    guard: &mut Guard,
    access: &mut Access<'_>,
) -> Result<(), Error> {
    nhi.service_dma(&mut Port {
        memory: ram,
        iommu: guard,
        stream: 1,
        access,
    })
}

#[test]
fn programmed_dma_wraps_and_preserves_owned_index_halves() {
    let (mut nhi, state) = make(1);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 100, &mut latch);
    let mut ram = Ram::new(0, 0x10000);
    let mut guard = Guard::default();
    nhi.set_powered(true, &mut access).unwrap();
    program(
        &mut nhi,
        &mut access,
        Direction::Transmit,
        0,
        RAW | ISOCH,
        0,
    );
    assert!(ram.write(0x3000, b"NHI"));
    for slot in 0..4 {
        descriptor(&mut ram, 0x1000 + slot * 16, 0x3000, 0xd7a003, 0xabcdef);
    }
    write(
        &mut nhi,
        &mut access,
        0x10008,
        Width::Word,
        3 << 16 | 0xffff,
    );
    service(&mut nhi, &mut ram, &mut guard, &mut access).unwrap();
    assert_eq!(read(&mut nhi, &mut access, 0x10008, Width::Word), 0x30003);
    assert_eq!(state.borrow().sent.len(), 3);
    assert_eq!(
        state.borrow().sent[0],
        (0, b"NHI".to_vec(), 7, 10, true, 0xabcdef)
    );
    assert_eq!(word(&mut ram, 0x1008), 0xb7a003);
    assert_eq!(word(&mut ram, 0x100c), 0x12345678);
    write(&mut nhi, &mut access, 0x10008, Width::Half, 0); // Hardware tail is read-only.
    write(&mut nhi, &mut access, 0x1000a, Width::Half, 0);
    service(&mut nhi, &mut ram, &mut guard, &mut access).unwrap();
    assert_eq!(read(&mut nhi, &mut access, 0x10008, Width::Word), 0);
    assert_eq!(state.borrow().sent.len(), 4);
    assert!(!nhi.dma_pending());
}

#[test]
fn completion_fault_keeps_acceptance_and_dart_fault_is_separate() {
    let (mut nhi, state) = make(1);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 100, &mut latch);
    let mut ram = Ram::new(0, 0x10000);
    let mut guard = Guard {
        fault: Some((0x3000, false)),
        ..Guard::default()
    };
    nhi.set_powered(true, &mut access).unwrap();
    program(&mut nhi, &mut access, Direction::Transmit, 0, RAW, 0);
    descriptor(&mut ram, 0x1000, 0x3000, 0xc00001, 0);
    write(&mut nhi, &mut access, 0x1000a, Width::Half, 1);
    write(&mut nhi, &mut access, 0xd0010, Width::Word, 1);
    assert_eq!(
        service(&mut nhi, &mut ram, &mut guard, &mut access),
        Err(Error::Dma(DmaError::Fault(0x80)))
    );
    assert!(state.borrow().sent.is_empty());
    guard.fault = Some((0x1008, true));
    assert_eq!(
        service(&mut nhi, &mut ram, &mut guard, &mut access),
        Err(Error::Dma(DmaError::Fault(0x80)))
    );
    assert_eq!(state.borrow().sent.len(), 1);
    assert_eq!(word(&mut ram, 0x1008), 0xc00001);
    assert_eq!(word(&mut ram, 0x100c), 0x12345678);
    assert_eq!(read(&mut nhi, &mut access, 0x10008, Width::Half), 0);
    assert!(nhi.write(0x10010, Width::Word, 0, &mut access).is_err());
    assert!(!nhi.asserted[0]);
    guard.fault = None;
    service(&mut nhi, &mut ram, &mut guard, &mut access).unwrap();
    assert_eq!(state.borrow().sent.len(), 1);
    assert_eq!(word(&mut ram, 0x1008), 0xa00001);
    assert!(nhi.asserted[0]);
    assert!(latch.is_asserted(Wire::Aic(AicInput::new(0, 99))));
}

#[test]
fn receive_fault_never_publishes_ownership_before_payload_and_time() {
    let (mut nhi, state) = make(1);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut ram = Ram::new(0, 0x10000);
    let mut guard = Guard {
        fault: Some((0x3010, true)),
        ..Guard::default()
    };
    nhi.set_powered(true, &mut access).unwrap();
    program(&mut nhi, &mut access, Direction::Receive, 0, 0, 20);
    descriptor(&mut ram, 0x2000, 0x3008, 0xc00000, 0);
    write(&mut nhi, &mut access, 0x80008, Width::Half, 1);
    state
        .borrow_mut()
        .notifications
        .push(Frame::new(0, (0..24).collect(), 7, 10, 0xfeed, true).unwrap());
    nhi.advance(&mut access).unwrap();
    assert_eq!(
        service(&mut nhi, &mut ram, &mut guard, &mut access),
        Err(Error::Dma(DmaError::Fault(0x80)))
    );
    assert_eq!(&ram.bytes[0x3008..0x3010], &[0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(word(&mut ram, 0x2008), 0xc00000);
    assert_eq!(word(&mut ram, 0x200c), 0);
    assert_eq!(read(&mut nhi, &mut access, 0x8000a, Width::Half), 0);
    guard.fault = None;
    service(&mut nhi, &mut ram, &mut guard, &mut access).unwrap();
    assert_eq!(&ram.bytes[0x3008..0x301c], &(0..20).collect::<Vec<u8>>());
    assert_eq!(word(&mut ram, 0x2008), 0xf7a014); // CRC + overrun alias POSTED.
    assert_eq!(word(&mut ram, 0x200c), 0xfeed);
    assert_eq!(read(&mut nhi, &mut access, 0x80008, Width::Word), 0x10001);
    assert_eq!(&guard.writes[guard.writes.len() - 2..], &[0x200c, 0x2008]);
    assert!(!nhi.dma_pending());
}

#[test]
fn masked_sticky_interrupts_throttle_subsequent_edges_and_merge_deadlines() {
    let (mut nhi, state) = make(1);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 100, &mut latch);
    let mut ram = Ram::new(0, 0x10000);
    let mut guard = Guard::default();
    nhi.set_powered(true, &mut access).unwrap();
    program(&mut nhi, &mut access, Direction::Transmit, 0, RAW, 0);
    for slot in 0..2 {
        descriptor(&mut ram, 0x1000 + slot * 16, 0x3000, 0xc00001, 0);
    }
    write(&mut nhi, &mut access, 0xd004c, Width::Word, 125); // 32us = 768 counter ticks.
    write(&mut nhi, &mut access, 0x1000a, Width::Half, 1);
    service(&mut nhi, &mut ram, &mut guard, &mut access).unwrap();
    assert_eq!(read(&mut nhi, &mut access, 0xd0000, Width::Word), 1);
    assert!(!nhi.asserted[0]);
    write(&mut nhi, &mut access, 0xd0010, Width::Word, 1);
    assert!(nhi.asserted[0]);
    write(&mut nhi, &mut access, 0xd0000, Width::Word, 1);
    assert!(!nhi.asserted[0]);
    write(&mut nhi, &mut access, 0x1000a, Width::Half, 2);
    service(&mut nhi, &mut ram, &mut guard, &mut access).unwrap();
    state.borrow_mut().deadline = Some(500);
    assert_eq!(nhi.advance(&mut access).unwrap(), Some(500));
    state.borrow_mut().deadline = None;
    assert_eq!(nhi.advance(&mut access).unwrap(), Some(868));
    access.now = 867;
    nhi.advance(&mut access).unwrap();
    assert!(!nhi.asserted[0]);
    access.now = 868;
    assert_eq!(nhi.advance(&mut access).unwrap(), None);
    assert!(nhi.asserted[0]);
    write(&mut nhi, &mut access, 0xd0010, Width::Word, 0);
    assert!(!nhi.asserted[0]);
    assert_eq!(read(&mut nhi, &mut access, 0xd0000, Width::Word), 1);
}

#[test]
fn configuration_is_latched_validated_and_requires_native_support() {
    let (mut nhi, state) = make(2);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    nhi.set_powered(true, &mut access).unwrap();
    write(&mut nhi, &mut access, PDF_VIEW, Width::Word, 0x11223344);
    program(
        &mut nhi,
        &mut access,
        Direction::Receive,
        0,
        RAW | E2E | 1 << 12,
        256,
    );
    let configured = state.borrow().configured[0].2.unwrap();
    assert!(configured.raw && configured.e2e);
    assert_eq!(
        (
            configured.pdf,
            configured.e2e_tx_hop,
            configured.receive_capacity
        ),
        (0x11223344, 1, 256)
    );
    assert!(nhi.write(PDF_VIEW, Width::Word, 0, &mut access).is_err());
    assert!(
        nhi.write(0x80010, Width::Word, u64::from(ENABLE | RAW), &mut access)
            .is_err()
    );
    assert!(
        nhi.write(0x80000, Width::Double, 0x4000, &mut access)
            .is_err()
    );
    write(&mut nhi, &mut access, 0x80010, Width::Word, 0);
    state.borrow_mut().refuse_options = true;
    assert!(
        nhi.write(0x80010, Width::Word, u64::from(ENABLE | RAW), &mut access)
            .is_err()
    );
    assert_eq!(read(&mut nhi, &mut access, 0x80010, Width::Word), 0);
    state.borrow_mut().refuse_options = false;
    program(&mut nhi, &mut access, Direction::Transmit, 0, RAW, 0);
    write(&mut nhi, &mut access, 0x14000, Width::Double, 0x1100);
    write(&mut nhi, &mut access, 0x1400c, Width::Word, 4);
    write(&mut nhi, &mut access, 0x14014, Width::Word, 7);
    assert!(
        nhi.write(0x14010, Width::Word, u64::from(ENABLE), &mut access)
            .is_err()
    );
    assert!(nhi.write(0x1000a, Width::Half, 4, &mut access).is_err());
    assert!(nhi.read(0x10000, Width::Byte, &mut access).is_err());
}

#[test]
fn peer_rejection_is_retryable_and_power_loss_requires_quiescence() {
    let (mut nhi, state) = make(1);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut ram = Ram::new(0, 0x10000);
    let mut guard = Guard::default();
    assert!(nhi.read(0, Width::Word, &mut access).is_err());
    assert!(service(&mut nhi, &mut ram, &mut guard, &mut access).is_err());
    nhi.set_powered(true, &mut access).unwrap();
    program(&mut nhi, &mut access, Direction::Transmit, 0, RAW, 0);
    descriptor(&mut ram, 0x1000, 0x3000, 0xc00001, 0);
    write(&mut nhi, &mut access, 0x1000a, Width::Half, 1);
    state.borrow_mut().refuse_send = true;
    assert!(matches!(
        service(&mut nhi, &mut ram, &mut guard, &mut access),
        Err(Error::Unsupported(_))
    ));
    assert_eq!(word(&mut ram, 0x1008), 0xc00001);
    assert_eq!(nhi.pending, 0);
    state.borrow_mut().refuse_reset = true;
    assert!(nhi.set_powered(false, &mut access).is_err());
    assert_eq!(read(&mut nhi, &mut access, 0x1000a, Width::Half), 1);
    state.borrow_mut().refuse_send = false;
    service(&mut nhi, &mut ram, &mut guard, &mut access).unwrap();
    assert_eq!(state.borrow().sent.len(), 1);
    state.borrow_mut().refuse_reset = false;
    nhi.set_powered(false, &mut access).unwrap();
    nhi.set_powered(true, &mut access).unwrap();
    assert_eq!(read(&mut nhi, &mut access, 0x10000, Width::Double), 0);
    assert_eq!(read(&mut nhi, &mut access, 0xd0000, Width::Word), 0);
    assert_eq!(state.borrow().resets, 1);
    assert_eq!(read(&mut nhi, &mut access, 4, Width::Word), 0x76543210);
}

#[test]
fn profile_layout_is_explicit_and_rejects_overflow_overlap_or_irq_aliases() {
    let consumer = || Box::new(Peer(Rc::new(RefCell::new(State::default())))) as Box<dyn Consumer>;
    let line = AicInput::new(0, 1);
    assert!(Nhi::new(profile(1), vec![line], vec![line], consumer()).is_err());
    let mut bad = profile(3);
    bad.layout.stride = u64::MAX - 3;
    assert!(Nhi::new(bad, vec![line; 3], vec![line; 3], consumer()).is_err());
    let mut bad = profile(1);
    bad.layout.rx = bad.layout.tx;
    assert!(Nhi::new(bad, vec![line], vec![AicInput::new(0, 2)], consumer()).is_err());
    let mut reversed = profile(1);
    core::mem::swap(&mut reversed.layout.tx, &mut reversed.layout.rx);
    let mut nhi = Nhi::new(reversed, vec![line], vec![AicInput::new(0, 2)], consumer()).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    nhi.set_powered(true, &mut access).unwrap();
    write(&mut nhi, &mut access, 0x1000c, Width::Half, 4);
    assert_eq!(read(&mut nhi, &mut access, 0x1000c, Width::Half), 4);
}
#[test]
fn native_notifications_require_posted_credit_and_terminal_fault_requires_reset() {
    let (mut nhi, state) = make(1);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    nhi.set_powered(true, &mut access).unwrap();
    state
        .borrow_mut()
        .notifications
        .push(Frame::new(0, vec![1], 0, 0, 0, false).unwrap());
    assert!(nhi.advance(&mut access).is_err());
    assert!(nhi.rx[0].incoming.is_empty());
    assert!(!nhi.dma_pending());
    state
        .borrow_mut()
        .notifications
        .push(Frame::new(0, vec![2], 0, 0, 0, false).unwrap());
    assert!(nhi.advance(&mut access).is_err());
    assert_eq!(state.borrow().notifications.len(), 1); // No second peer action after violation.
    nhi.reset(&mut access).unwrap();
    assert!(nhi.advance(&mut access).is_ok());
    write(&mut nhi, &mut access, 0x80000, Width::Double, 0x2000);
    write(&mut nhi, &mut access, 0x8000c, Width::Word, 4);
    assert!(
        nhi.write(0x80010, Width::Word, u64::from(ENABLE), &mut access)
            .is_err()
    );
    write(&mut nhi, &mut access, 0x8000e, Width::Half, 257);
    assert!(
        nhi.write(0x80010, Width::Word, u64::from(ENABLE), &mut access)
            .is_err()
    );
}

#[test]
fn dma_quantum_is_bounded_and_pending_work_resumes_fairly() {
    let (mut nhi, state) = make(2);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut ram = Ram::new(0, 0x10000);
    let mut guard = Guard::default();
    nhi.set_powered(true, &mut access).unwrap();
    for hop in 0..2 {
        let registers = 0x10000 + hop * 0x4000;
        let descriptors = 0x1000 + hop * 0x1000;
        write(&mut nhi, &mut access, registers, Width::Double, descriptors);
        write(&mut nhi, &mut access, registers + 12, Width::Half, 100);
        write(&mut nhi, &mut access, registers + 20, Width::Word, 2);
        write(
            &mut nhi,
            &mut access,
            registers + 16,
            Width::Word,
            u64::from(ENABLE | RAW),
        );
        for slot in 0..99 {
            descriptor(&mut ram, descriptors + slot * 16, 0x4000, 0x400001, 0);
        }
        write(&mut nhi, &mut access, registers + 10, Width::Half, 99);
    }
    service(&mut nhi, &mut ram, &mut guard, &mut access).unwrap();
    assert_eq!(state.borrow().sent.len(), 64);
    assert_eq!(
        state
            .borrow()
            .sent
            .iter()
            .filter(|frame| frame.0 == 0)
            .count(),
        32
    );
    assert!(nhi.dma_pending());
    for _ in 0..3 {
        service(&mut nhi, &mut ram, &mut guard, &mut access).unwrap();
    }
    assert_eq!(state.borrow().sent.len(), 198);
    assert!(!nhi.dma_pending());
}
#[test]
fn stopped_rings_restart_from_reinitialized_indices_and_new_tables() {
    let (mut nhi, state) = make(1);
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut ram = Ram::new(0, 0x10000);
    let mut guard = Guard::default();
    nhi.set_powered(true, &mut access).unwrap();
    program(&mut nhi, &mut access, Direction::Transmit, 0, RAW, 0);
    program(&mut nhi, &mut access, Direction::Receive, 0, RAW, 256);
    assert!(ram.write(0x3000, b"a"));
    for slot in 0..3 {
        descriptor(&mut ram, 0x1000 + slot * 16, 0x3000, 0x400001, 0);
        descriptor(
            &mut ram,
            0x2000 + slot * 16,
            0x4000 + slot * 0x100,
            0x400000,
            0,
        );
        state
            .borrow_mut()
            .notifications
            .push(Frame::new(0, vec![slot as u8], 0, 0, 42, false).unwrap());
    }
    write(&mut nhi, &mut access, 0x1000a, Width::Half, 3);
    write(&mut nhi, &mut access, 0x80008, Width::Half, 3);
    nhi.advance(&mut access).unwrap();
    service(&mut nhi, &mut ram, &mut guard, &mut access).unwrap();
    assert_eq!(read(&mut nhi, &mut access, 0x10008, Width::Word), 0x30003);
    assert_eq!(read(&mut nhi, &mut access, 0x80008, Width::Word), 0x30003);
    write(&mut nhi, &mut access, 0x10010, Width::Word, 0);
    write(&mut nhi, &mut access, 0x80010, Width::Word, 0);
    assert!(
        nhi.write(0x10008, Width::Word, 4 << 16, &mut access)
            .is_err()
    );
    assert_eq!(read(&mut nhi, &mut access, 0x10008, Width::Word), 0x30003);
    write(&mut nhi, &mut access, 0x10008, Width::Word, 0);
    write(&mut nhi, &mut access, 0x8000a, Width::Half, 0);
    write(&mut nhi, &mut access, 0x80008, Width::Half, 0);
    write(&mut nhi, &mut access, 0x10000, Width::Double, 0x5000);
    write(&mut nhi, &mut access, 0x80000, Width::Double, 0x6000);
    assert_eq!(read(&mut nhi, &mut access, 0x10008, Width::Word), 0);
    assert_eq!(read(&mut nhi, &mut access, 0x80008, Width::Word), 0);
    write(
        &mut nhi,
        &mut access,
        0x10010,
        Width::Word,
        u64::from(ENABLE | RAW),
    );
    write(
        &mut nhi,
        &mut access,
        0x80010,
        Width::Word,
        u64::from(ENABLE | RAW),
    );
    assert!(ram.write(0x7000, b"Z"));
    descriptor(&mut ram, 0x5000, 0x7000, 0x400001, 0);
    descriptor(&mut ram, 0x6000, 0x8000, 0x400000, 0);
    // Running rings ignore the hardware-owned half, for both widths.
    write(&mut nhi, &mut access, 0x10008, Width::Half, 0xffff);
    write(&mut nhi, &mut access, 0x8000a, Width::Half, 0xffff);
    write(&mut nhi, &mut access, 0x10008, Width::Word, 0x1ffff);
    write(&mut nhi, &mut access, 0x80008, Width::Word, 0xffff0001);
    assert_eq!(read(&mut nhi, &mut access, 0x10008, Width::Word), 0x10000);
    assert_eq!(read(&mut nhi, &mut access, 0x80008, Width::Word), 1);
    state
        .borrow_mut()
        .notifications
        .push(Frame::new(0, vec![b'Z'], 0, 0, 43, false).unwrap());
    nhi.advance(&mut access).unwrap();
    service(&mut nhi, &mut ram, &mut guard, &mut access).unwrap();
    assert_eq!(read(&mut nhi, &mut access, 0x10008, Width::Word), 0x10001);
    assert_eq!(read(&mut nhi, &mut access, 0x80008, Width::Word), 0x10001);
    assert_eq!(state.borrow().sent.len(), 4);
    assert_eq!(state.borrow().sent.last().unwrap().1, b"Z");
    assert_eq!(ram.bytes[0x8000], b'Z');
    assert_eq!(word(&mut ram, 0x5008), 0x200001);
    assert_eq!(word(&mut ram, 0x6008), 0x200001);
}
