use super::*;
use crate::bus::dma::{DmaAllocator, RegionAllocator};
use alloc::{boxed::Box, rc::Rc, vec, vec::Vec};
use core::cell::{Cell, RefCell};

#[derive(Clone)]
struct Time(Rc<Cell<u64>>);
impl Timer for Time {
    fn now_us(&self) -> u64 {
        self.0.get()
    }
    fn relax(&self) {
        self.0.set(self.0.get().wrapping_add(1));
    }
}
#[derive(Clone, Debug)]
enum Access {
    Read(usize),
    Write(usize, u32),
    PayloadRead(usize),
    PayloadWrite(Vec<u8>),
}
struct Device {
    time: Time,
    events: [u32; 2],
    enabled: [bool; 2],
    payload: [u8; 32],
    address: u64,
    log: Vec<Access>,
    delay: usize,
    remaining: usize,
    pending: Option<(usize, u32)>,
    corrupt: u32,
    hang: bool,
    fail: Option<(usize, bool)>,
    count: usize,
    late: Option<usize>,
    drops: Rc<Cell<usize>>,
}
impl Device {
    fn before(&mut self, access: Access) -> Result<(), IoError> {
        self.log.push(access);
        self.count += 1;
        if self.late == Some(self.count) {
            self.time.0.set(self.time.0.get().wrapping_add(100));
        }
        if self.fail == Some((self.count, false)) {
            return Err(IoError);
        }
        Ok(())
    }
    fn after(&self) -> Result<(), IoError> {
        if self.fail == Some((self.count, true)) {
            Err(IoError)
        } else {
            Ok(())
        }
    }
    fn complete(&mut self) {
        let Some((bus, word)) = self.pending.take() else {
            return;
        };
        let op = word & 15;
        let length = ((word >> 16) & 4095) as usize;
        let address = (word >> 8) & 255;
        let inline = word >> 31 != 0;
        if op == 2 {
            self.enabled[bus] = true;
        } else if op == 3 {
            self.enabled[bus] = false;
        } else {
            assert!(self.enabled[bus], "native sent data before enable");
            assert_eq!(inline, length <= 32);
            let data = if inline {
                &mut self.payload[..length]
            } else {
                // SAFETY: fixture owns a real region allocation and the
                // firmware command/address selects its bounded payload.
                unsafe { core::slice::from_raw_parts_mut(self.address as *mut u8, length) }
            };
            if op == 0 {
                for (i, byte) in data.iter_mut().enumerate() {
                    *byte = (i as u8).wrapping_mul(31).wrapping_add(address as u8);
                }
            } else {
                for (i, byte) in data.iter().enumerate() {
                    assert_eq!(*byte, (i as u8).wrapping_mul(17).wrapping_add(3));
                }
            }
        }
        self.events[bus] = (1
            | (op * 2) << 2
            | (inline as u32) << 7
            | (bus as u32) << 8
            | (length as u32) << 12
            | address << 24)
            ^ self.corrupt;
    }
}
impl Drop for Device {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
#[derive(Clone)]
struct Model(Rc<RefCell<Device>>);
// SAFETY: one controller serializes this single device model. Clones are
// fixture inspection handles, never another mailbox driver.
unsafe impl Registers for Model {
    fn read32(&mut self, offset: usize) -> Result<u32, IoError> {
        let mut d = self.0.borrow_mut();
        d.before(Access::Read(offset))?;
        if let Some((bus, _)) = d.pending
            && offset == EVENT[bus]
            && !d.hang
        {
            if d.remaining == 0 {
                d.complete();
            } else {
                d.remaining -= 1;
            }
        }
        let value = if let Some(bus) = EVENT.iter().position(|x| *x == offset) {
            d.events[bus]
        } else {
            panic!("unexpected read {offset:x}");
        };
        d.after()?;
        Ok(value)
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), IoError> {
        let mut d = self.0.borrow_mut();
        d.before(Access::Write(offset, value))?;
        if let Some(bus) = COMMAND.iter().position(|x| *x == offset) {
            assert!(d.pending.is_none());
            assert_eq!(d.events, [0; 2]);
            assert_eq!((value >> 4) & 15, bus as u32);
            d.pending = Some((bus, value));
            d.remaining = d.delay;
        } else if let Some(bus) = EVENT.iter().position(|x| *x == offset) {
            assert_eq!(value, 0);
            d.events[bus] = 0;
        } else if offset == INTERRUPT {
            assert_eq!(value, 0);
        } else if offset == PAYLOAD {
            d.address = d.address & (!0u64 << 32) | u64::from(value);
        } else if offset == PAYLOAD + 4 {
            d.address = d.address & u64::from(u32::MAX) | (u64::from(value) << 32);
        } else {
            panic!("unexpected write {offset:x}");
        }
        d.after()
    }
    fn read_payload(&mut self, bytes: &mut [u8]) -> Result<(), IoError> {
        let mut d = self.0.borrow_mut();
        d.before(Access::PayloadRead(bytes.len()))?;
        bytes.copy_from_slice(&d.payload[..bytes.len()]);
        d.after()
    }
    fn write_payload(&mut self, bytes: &[u8]) -> Result<(), IoError> {
        let mut d = self.0.borrow_mut();
        d.before(Access::PayloadWrite(bytes.to_vec()))?;
        d.payload[..bytes.len()].copy_from_slice(bytes);
        d.after()
    }
}
type Host = Controller<Model, Time>;
fn fixture() -> (Host, Model, Rc<Cell<usize>>) {
    let time = Time(Rc::new(Cell::new(u64::MAX - 20)));
    let drops = Rc::new(Cell::new(0));
    let model = Model(Rc::new(RefCell::new(Device {
        time: time.clone(),
        events: [0; 2],
        enabled: [false; 2],
        payload: [0; 32],
        address: 0,
        log: Vec::new(),
        delay: 0,
        remaining: 0,
        pending: None,
        corrupt: 0,
        hang: false,
        fail: None,
        count: 0,
        late: None,
        drops: drops.clone(),
    })));
    // The existing RegionAllocator grants boot-lifetime identity DMA; the
    // fixture keeps its heap allocation for that epoch.
    let raw = Box::leak(vec![0u8; 8192].into_boxed_slice());
    let start = raw.as_mut_ptr() as u64;
    // SAFETY: exclusively kept, mapped native RAM, no other allocator.
    let mut allocator = unsafe { RegionAllocator::new(start..start + 8192) };
    let buffer = allocator.allocate(MAX_LENGTH, 1).unwrap();
    // SAFETY: fixture has an exclusive initially stopped native model and
    // coherent kept payload; bus identity/speeds are explicit fixture facts.
    let host = unsafe {
        Controller::claim(
            model.clone(),
            time,
            buffer,
            [Some(Speed::Khz400), Some(Speed::Mhz1)],
            100,
        )
    }
    .ok()
    .unwrap();
    (host, model, drops)
}
fn bus(id: u64) -> BusId {
    BusId::from_uid(id).unwrap()
}
fn output(length: usize) -> Vec<u8> {
    (0..length)
        .map(|i| (i as u8).wrapping_mul(17).wrapping_add(3))
        .collect()
}
fn assert_read(bytes: &[u8], address: u8) {
    for (i, byte) in bytes.iter().enumerate() {
        assert_eq!(*byte, (i as u8).wrapping_mul(31).wrapping_add(address));
    }
}

#[test]
fn two_buses_all_lengths_inline_dma_and_power_lifecycle() {
    let (mut h, m, drops) = fixture();
    for id in 0..2 {
        h.enable(bus(id)).unwrap();
        for delay in [0, 1, 3] {
            m.0.borrow_mut().delay = delay;
            for length in [1, 2, 3, 7, 31, 32, 33, 39, 255, 4095] {
                h.write(bus(id), Address::SevenBit(0x15), &output(length))
                    .unwrap();
                let mut bytes = vec![0xa5; length];
                h.read(bus(id), Address::SevenBit(0x2c), &mut bytes)
                    .unwrap();
                assert_read(&bytes, 0x2c);
            }
        }
    }
    for access in &m.0.borrow().log {
        match access {
            Access::Write(offset, value) if COMMAND.contains(offset) => {
                assert!((value & 15) <= 3);
                assert_eq!(
                    (value >> 4) & 15,
                    COMMAND.iter().position(|x| x == offset).unwrap() as u32
                );
            }
            Access::PayloadWrite(bytes) => {
                assert!(bytes.len() <= INLINE);
                assert_eq!(bytes, &output(bytes.len()));
            }
            Access::PayloadRead(length) => assert!(*length <= INLINE),
            _ => {}
        }
    }
    h.disable(bus(0)).unwrap();
    assert!(h.is_enabled(bus(1)));
    h.disable(bus(1)).unwrap();
    assert_eq!(m.0.borrow().enabled, [false; 2]);
    let owners = h.release().ok().unwrap();
    drop(owners);
    drop(m);
    assert_eq!(drops.get(), 1);
}
#[test]
fn inputs_refuse_without_io_and_speed_never_exceeds_observed_limit() {
    for id in [2, 255, u64::MAX] {
        assert_eq!(BusId::from_uid(id), Err(ErrorKind::Configuration));
    }
    let speeds = [
        (100_000, Speed::Khz100),
        (399_999, Speed::Khz100),
        (400_000, Speed::Khz400),
        (1_399_999, Speed::Mhz1),
        (1_400_000, Speed::Mhz1_4),
        (3_400_000, Speed::Mhz3_4),
    ];
    for (limit, speed) in speeds {
        assert_eq!(Speed::from_limit(limit), Ok(speed));
    }
    assert_eq!(Speed::from_limit(99_999), Err(ErrorKind::Configuration));
    let (mut h, m, _) = fixture();
    assert_eq!(
        h.write(bus(0), Address::SevenBit(0x15), &[1])
            .unwrap_err()
            .kind,
        ErrorKind::NotEnabled
    );
    for address in [
        Address::SevenBit(0),
        Address::SevenBit(0x78),
        Address::TenBit(0x15),
    ] {
        assert_eq!(
            h.write(bus(0), address, &[1]).unwrap_err().kind,
            ErrorKind::InvalidAddress
        );
    }
    for length in [0, 4096] {
        assert_eq!(
            h.write(bus(0), Address::SevenBit(0x15), &vec![0; length])
                .unwrap_err()
                .kind,
            ErrorKind::Length(length)
        );
    }
    assert!(m.0.borrow().log.is_empty());
    assert!(h.failure().is_none());
}
#[test]
fn every_event_field_is_checked_before_caller_output_and_old_events_are_not_reused() {
    for bit in 0..32 {
        let (mut h, m, _) = fixture();
        h.enable(bus(0)).unwrap();
        m.0.borrow_mut().corrupt = 1 << bit;
        let mut out = [0xa5; 17];
        let error = h
            .read(bus(0), Address::SevenBit(0x2c), &mut out)
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Response, "bit{bit}");
        assert!(error.event.is_some());
        assert!(error.published);
        assert_eq!(out, [0xa5; 17]);
        let count = m.0.borrow().count;
        assert_eq!(h.enable(bus(1)).unwrap_err().kind, ErrorKind::NeedsReset);
        assert_eq!(count, m.0.borrow().count);
    }
    for id in 0..2 {
        let (mut h, m, _) = fixture();
        m.0.borrow_mut().events[id] = 0x1234;
        let error = h.enable(bus(0)).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Pending);
        assert_eq!(error.event, Some(0x1234));
        assert!(!error.published);
        assert!(
            m.0.borrow()
                .log
                .iter()
                .all(|a| matches!(a, Access::Read(_)))
        );
    }
}
#[test]
fn before_and_after_every_register_effect_fail_closed_for_both_buses_and_dma() {
    for length in [17, 33] {
        let (mut baseline, model, _) = fixture();
        baseline.enable(bus(0)).unwrap();
        model.0.borrow_mut().count = 0;
        model.0.borrow_mut().log.clear();
        let mut out = vec![0xa5; length];
        baseline
            .read(bus(0), Address::SevenBit(0x2c), &mut out)
            .unwrap();
        let total = model.0.borrow().count;
        for access in 1..=total {
            for after in [false, true] {
                let (mut h, m, drops) = fixture();
                h.enable(bus(0)).unwrap();
                m.0.borrow_mut().count = 0;
                m.0.borrow_mut().fail = Some((access, after));
                let mut out = vec![0xa5; length];
                let error = h
                    .read(bus(0), Address::SevenBit(0x2c), &mut out)
                    .unwrap_err();
                assert_eq!(error.kind, ErrorKind::Io);
                assert_eq!(out, vec![0xa5; length]);
                let count = m.0.borrow().count;
                assert_eq!(
                    h.write(bus(1), Address::SevenBit(0x15), &[1])
                        .unwrap_err()
                        .kind,
                    ErrorKind::NeedsReset
                );
                assert_eq!(count, m.0.borrow().count);
                assert_eq!(h.failure(), Some(error));
                drop(h);
                drop(m);
                assert_eq!(drops.get(), 0, "uncertain actual owner was freed");
            }
        }
    }
}
#[test]
fn late_reads_keep_the_event_and_timeout_keeps_payload_owners() {
    let (mut baseline, m, _) = fixture();
    baseline.enable(bus(0)).unwrap();
    m.0.borrow_mut().count = 0;
    m.0.borrow_mut().log.clear();
    let mut out = [0xa5; 17];
    baseline
        .read(bus(0), Address::SevenBit(0x2c), &mut out)
        .unwrap();
    let log = m.0.borrow().log.clone();
    for access in 1..=log.len() {
        let (mut h, m, _) = fixture();
        h.enable(bus(0)).unwrap();
        m.0.borrow_mut().count = 0;
        m.0.borrow_mut().late = Some(access);
        let mut out = [0xa5; 17];
        let error = h
            .read(bus(0), Address::SevenBit(0x2c), &mut out)
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Timeout);
        assert_eq!(out, [0xa5; 17]);
        if matches!(log[access-1],Access::Read(offset) if offset==EVENT[0]) && access > 3 {
            assert_ne!(error.event, Some(0));
        }
        assert_eq!(h.failure(), Some(error));
    }
    let (mut h, m, _) = fixture();
    h.enable(bus(0)).unwrap();
    m.0.borrow_mut().hang = true;
    let mut out = [0xa5; 33];
    assert_eq!(
        h.read(bus(0), Address::SevenBit(0x2c), &mut out)
            .unwrap_err()
            .kind,
        ErrorKind::Timeout
    );
    assert_eq!(out, [0xa5; 33]);
}
#[test]
fn enabled_drop_keeps_owner_and_normal_disable_allows_release() {
    let (mut h, m, drops) = fixture();
    h.enable(bus(1)).unwrap();
    drop(h);
    drop(m);
    assert_eq!(drops.get(), 0);
    let (mut h, m, drops) = fixture();
    h.enable(bus(1)).unwrap();
    h.disable(bus(1)).unwrap();
    drop(h);
    drop(m);
    assert_eq!(drops.get(), 1);
}

#[test]
#[ignore = "oracle: STELA_AMD_MP2_ORACLE"]
fn unchanged_linux_source_commands_and_events() {
    extern crate std;
    let path = std::env::var("STELA_AMD_MP2_ORACLE").expect("STELA_AMD_MP2_ORACLE trace path");
    let trace = std::fs::read_to_string(path).unwrap();
    let (mut host, model, _) = fixture();
    let mut cases = 0;
    for line in trace.lines() {
        let fields: Vec<_> = line.split(',').collect();
        let number = |index: usize| fields[index].parse::<usize>().unwrap();
        let hex = |index: usize| u64::from_str_radix(fields[index], 16).unwrap();
        if fields[0] == "E" {
            let (mut h, m, _) = fixture();
            h.enable(bus(0)).unwrap();
            let op = number(1);
            let event = hex(2) as u32;
            let expected = 1 | (op as u32 * 2) << 2 | 1 << 7 | 17 << 12 | 0x2c << 24;
            m.0.borrow_mut().corrupt = expected ^ event;
            let mut out = [0xa5; 17];
            let result = if op == 0 {
                h.read(bus(0), Address::SevenBit(0x2c), &mut out)
            } else {
                h.write(bus(0), Address::SevenBit(0x2c), &output(17))
            };
            let source_accepts = number(3) != 0;
            let correlated = (event >> 8) & 15 == 0 && (event >> 7) & 1 == 1;
            assert_eq!(result.is_ok(), source_accepts && correlated);
            if result.is_err() {
                assert_eq!(out, [0xa5; 17]);
            }
        } else {
            let id = number(1);
            let speed = number(2);
            host.speeds[id] = Some(
                [
                    Speed::Khz100,
                    Speed::Khz400,
                    Speed::Mhz1,
                    Speed::Mhz1_4,
                    Speed::Mhz3_4,
                ][speed],
            );
            if fields[0] == "P" {
                let enable = number(3) != 0;
                if !enable && !host.is_enabled(bus(id as u64)) {
                    host.enable(bus(id as u64)).unwrap();
                }
                model.0.borrow_mut().log.clear();
                if enable {
                    host.enable(bus(id as u64)).unwrap();
                } else {
                    host.disable(bus(id as u64)).unwrap();
                }
                let command = model
                    .0
                    .borrow()
                    .log
                    .iter()
                    .find_map(|access| match access {
                        Access::Write(offset, word) if *offset == COMMAND[id] => Some(*word),
                        _ => None,
                    })
                    .unwrap();
                assert_eq!(u64::from(command), hex(4));
            } else {
                let op = number(3);
                let length = number(4);
                model.0.borrow_mut().log.clear();
                if op == 0 {
                    let mut bytes = vec![0xa5; length];
                    host.read(bus(id as u64), Address::SevenBit(0x2c), &mut bytes)
                        .unwrap();
                    assert_read(&bytes, 0x2c);
                } else {
                    host.write(bus(id as u64), Address::SevenBit(0x2c), &output(length))
                        .unwrap();
                }
                let d = model.0.borrow();
                let command = d
                    .log
                    .iter()
                    .find_map(|access| match access {
                        Access::Write(offset, word) if *offset == COMMAND[id] => Some(*word),
                        _ => None,
                    })
                    .unwrap();
                assert_eq!(u64::from(command), hex(5));
                if length > INLINE {
                    assert_eq!(hex(6), 0x123456789abcdef0);
                    assert_eq!(d.address, host.owners.as_ref().unwrap().2.bus_address());
                } else if op == 1 {
                    let actual = output(length);
                    let mut first = [0; 8];
                    let count = length.min(8);
                    first[..count].copy_from_slice(&actual[..count]);
                    assert_eq!(u64::from_le_bytes(first), hex(6));
                } else {
                    assert_eq!(hex(6), 0);
                }
            }
        }
        cases += 1;
    }
    assert_eq!(cases, 90112);
    for id in 0..2 {
        host.disable(bus(id)).unwrap();
    }
}

#[test]
fn write_and_power_faults_fence_both_buses_and_never_replay_a_command() {
    fn setup(case: usize) -> (Host, Model, Rc<Cell<usize>>) {
        let (mut h, m, drops) = fixture();
        h.enable(bus(1)).unwrap();
        if case != 0 {
            h.enable(bus(0)).unwrap();
        }
        m.0.borrow_mut().count = 0;
        m.0.borrow_mut().log.clear();
        (h, m, drops)
    }
    fn run(h: &mut Host, case: usize) -> Result<(), Error> {
        match case {
            0 => h.enable(bus(0)),
            1 => h.disable(bus(0)),
            2 => h.write(bus(0), Address::SevenBit(0x2c), &output(17)),
            3 => h.write(bus(0), Address::SevenBit(0x2c), &output(33)),
            _ => unreachable!(),
        }
    }
    for case in 0..4 {
        let (mut baseline, m, _) = setup(case);
        run(&mut baseline, case).unwrap();
        let total = m.0.borrow().count;
        for index in 1..=total {
            for after in [false, true] {
                let (mut h, m, drops) = setup(case);
                m.0.borrow_mut().fail = Some((index, after));
                let error = run(&mut h, case).unwrap_err();
                assert_eq!(error.kind, ErrorKind::Io);
                assert_eq!(h.failure(), Some(error));
                let count = m.0.borrow().count;
                assert_eq!(h.disable(bus(1)).unwrap_err().kind, ErrorKind::NeedsReset);
                assert_eq!(m.0.borrow().count, count);
                drop(h);
                drop(m);
                assert_eq!(drops.get(), 0);
            }
        }
    }
}
#[test]
fn invalid_claim_returns_the_owned_resources_without_io() {
    let (host, m, _) = fixture();
    let (r, t, buffer) = host.release().ok().unwrap();
    let physical = buffer.bus_address();
    // SAFETY: same real private stopped model and RAM ownership as fixture;
    // invalid scalar config must be rejected without publication.
    let (kind, (r, _t, buffer)) = unsafe { Controller::claim(r, t, buffer, [None, None], 100) }
        .err()
        .unwrap();
    assert_eq!(kind, ErrorKind::Configuration);
    assert_eq!(buffer.bus_address(), physical);
    assert!(Rc::ptr_eq(&r.0, &m.0));
    assert!(m.0.borrow().log.is_empty());
}
