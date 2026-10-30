//! Independent command link: ordered wire effects, delayed indexed responses,
//! status W1C, separate page state and original-provider retention.
use super::*;
use alloc::{collections::BTreeMap, rc::Rc, vec, vec::Vec};
use core::cell::{Cell, RefCell};
mod oracle;

struct Hardware {
    layout: Layout,
    words: BTreeMap<usize, u32>,
    data: BTreeMap<(u8, u8, u8, u16), u8>,
    pages: [[u8; 2]; 16],
    queued: Vec<u32>,
    responses: Vec<u32>,
    response_index: usize,
    available: bool,
    ready_at: u64,
    time: Rc<Cell<u64>>,
    wire: Vec<u32>,
    watermarks: Vec<u32>,
    reads: usize,
    stores: usize,
    effects: Vec<(usize, u32)>,
    fail_store: Option<usize>,
    fail_after: bool,
    nack: Option<usize>,
    ignored: Option<usize>,
    excess: bool,
    silent: bool,
    ignore_ack: bool,
    drops: usize,
}
struct Port(Rc<RefCell<Hardware>>);
impl Drop for Port {
    fn drop(&mut self) {
        self.0.borrow_mut().drops += 1;
    }
}
impl Hardware {
    fn progress(&mut self) {
        if !self.silent && !self.responses.is_empty() && self.time.get() >= self.ready_at {
            self.available = true;
            *self.words.entry(INTERRUPT).or_default() |= RX_WATERMARK;
        }
    }
    fn command(&mut self, value: u32) {
        assert!(!self.available && self.responses.is_empty());
        self.queued.push(value);
        let expected = self.words[&WATERMARK] as usize;
        assert!(self.queued.len() <= expected && expected <= BATCH);
        if self.queued.len() != expected {
            return;
        }
        for word in core::mem::take(&mut self.queued) {
            let number = self.wire.len();
            self.wire.push(word);
            let device = ((word >> 24) & 15) as u8;
            let at = (word >> 8) as u16;
            let byte = word as u8;
            let page = self.pages[usize::from(device)];
            let key = (device, page[0], page[1], at);
            let mut response = 1;
            if self.nack == Some(number) {
                response = 2;
            } else if self.ignored == Some(number) {
                response = 0;
            } else {
                match (word >> 28) & 7 {
                    2 => response |= u32::from(*self.data.get(&key).unwrap_or(&0)) << 8,
                    3 => {
                        if at == 0x48 || at == 0x49 {
                            self.pages[usize::from(device)][usize::from(at - 0x48)] = byte;
                        } else {
                            self.data.insert(key, byte);
                        }
                    }
                    _ => panic!("unimplemented wire command"),
                }
            }
            self.responses.push(response);
        }
        self.response_index = 0;
        self.ready_at = self.time.get() + 3;
    }
}
// SAFETY: isolated serialized link model; original provider is held and
// implements ordered before/after effects, not a physical ownership grant.
unsafe impl Registers for Port {
    fn layout(&self) -> Layout {
        self.0.borrow().layout
    }
    fn bytes(&self) -> usize {
        self.0.borrow().layout.register_bytes()
    }
    fn read32(&mut self, offset: usize) -> Result<u32, IoError> {
        let mut h = self.0.borrow_mut();
        h.reads += 1;
        h.progress();
        if offset == FIFO {
            return Ok(if h.available {
                h.responses.len() as u32 + u32::from(h.excess)
            } else {
                0
            });
        }
        let base = h.layout.offset() + COMMAND;
        if offset >= base && offset < base + (BATCH + 2) * 4 {
            assert!(h.available);
            assert_eq!(offset, base + h.response_index * 4);
            let value = h.responses[h.response_index];
            h.response_index += 1;
            if h.response_index == h.responses.len() {
                h.responses.clear();
                h.available = false;
            }
            return Ok(value);
        }
        Ok(*h.words.get(&offset).unwrap_or(&0))
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), IoError> {
        let mut h = self.0.borrow_mut();
        h.stores += 1;
        h.effects.push((offset, value));
        let failed = h.fail_store == Some(h.stores);
        if failed && !h.fail_after {
            return Err(IoError);
        }
        let base = h.layout.offset() + COMMAND;
        if offset >= base && offset < base + BATCH * 4 {
            assert_eq!(offset, base + h.queued.len() * 4);
            h.command(value);
        } else if offset == INTERRUPT {
            assert_eq!(value, RX_WATERMARK, "unrelated causes must be preserved");
            if !h.ignore_ack {
                *h.words.entry(offset).or_default() &= !value;
            }
        } else {
            assert_eq!(offset, WATERMARK);
            assert!((1..=BATCH as u32).contains(&value));
            h.watermarks.push(value);
            h.words.insert(offset, value);
        }
        if failed { Err(IoError) } else { Ok(()) }
    }
}
struct Time(Rc<Cell<u64>>);
impl Timer for Time {
    fn now_us(&self) -> u64 {
        (u64::MAX - 15).wrapping_add(self.0.get() * 10) / 10
    }
    fn start(&self) -> u64 {
        !self.0.get()
    }
    fn elapsed_us(&self, marker: u64) -> u64 {
        self.0.get().wrapping_sub(!marker)
    }
    fn relax(&self) {
        self.0.set(self.0.get() + 1);
    }
}
fn setup(layout: Layout) -> (Controller<Port, Time>, Rc<RefCell<Hardware>>) {
    let time = Rc::new(Cell::new(0));
    let mut words = BTreeMap::new();
    words.insert(layout.offset() + CONTROL, 2);
    let h = Rc::new(RefCell::new(Hardware {
        layout,
        words,
        data: BTreeMap::new(),
        pages: [[0; 2]; 16],
        queued: vec![],
        responses: vec![],
        response_index: 0,
        available: false,
        ready_at: 0,
        time: time.clone(),
        wire: vec![],
        watermarks: vec![],
        reads: 0,
        stores: 0,
        effects: vec![],
        fail_store: None,
        fail_after: false,
        nack: None,
        ignored: None,
        excess: false,
        silent: false,
        ignore_ack: false,
        drops: 0,
    }));
    (
        Controller::new(Port(h.clone()), Time(time)).ok().unwrap(),
        h,
    )
}
fn message() -> Message {
    Message {
        device: 3,
        address: 0x9000,
        page: None,
        ssp_sync: false,
    }
}

#[test]
fn paged_multi_batch_commands_change_data_and_preserve_unrelated_causes() {
    for layout in [Layout::Legacy, Layout::Extended] {
        for count in 1..=33 {
            let (mut host, h) = setup(layout);
            h.borrow_mut()
                .words
                .insert(INTERRUPT, (1 << 13) | (1 << 14));
            let m = Message {
                page: Some([0x17, 0x23]),
                ssp_sync: true,
                ..message()
            };
            let tx: Vec<_> = (0..count).map(|i| (i as u8).wrapping_mul(37)).collect();
            host.write_registers(m, &tx).unwrap();
            let mut rx = vec![0xa5; count];
            host.read_registers(m, &mut rx).unwrap();
            assert_eq!(rx, tx);
            assert_eq!(h.borrow().pages[3], [0x17, 0x23]);
            assert_eq!(h.borrow().words[&INTERRUPT], (1 << 13) | (1 << 14));
            assert_eq!(h.borrow().wire.len(), 4 + count * 2);
            assert!(h.borrow().wire[2..2 + count].iter().all(|v| v >> 31 == 1));
            assert_eq!(h.borrow().wire[0], 3 << 28 | 3 << 24 | 0x48 << 8 | 0x17);
            assert_eq!(h.borrow().watermarks.first(), Some(&2));
            assert_eq!(h.borrow().wire[count + 2], h.borrow().wire[0]);
            drop(host.release().ok().unwrap());
            assert_eq!(h.borrow().drops, 1);
        }
    }
}

#[test]
fn every_nack_or_missing_ack_withholds_all_read_output_and_keeps_original_link() {
    for missing in [false, true] {
        for at in 0..17 {
            let (mut host, h) = setup(Layout::Extended);
            if missing {
                h.borrow_mut().ignored = Some(at);
            } else {
                h.borrow_mut().nack = Some(at);
            }
            let mut poison = [0xa5; 17];
            let error = host.read_registers(message(), &mut poison).unwrap_err();
            assert_eq!(
                error.kind,
                if missing {
                    ErrorKind::Ignored
                } else {
                    ErrorKind::Nack
                }
            );
            assert_eq!(error.completed, at / 8 * 8);
            assert_eq!(poison, [0xa5; 17]);
            assert!(h.borrow().responses.is_empty());
            let effects = (h.borrow().reads, h.borrow().stores);
            assert_eq!(
                host.read_registers(message(), &mut poison)
                    .unwrap_err()
                    .kind,
                ErrorKind::Faulted
            );
            drop(host.release().err().unwrap());
            assert_eq!(effects, (h.borrow().reads, h.borrow().stores));
            assert_eq!(h.borrow().drops, 0);
        }
    }
}

#[test]
fn invalid_geometry_is_effect_free_and_preserves_an_unmodified_usable_controller() {
    let (mut host, h) = setup(Layout::Legacy);
    for (m, len) in [
        (
            Message {
                device: 16,
                ..message()
            },
            1,
        ),
        (message(), 0),
        (
            Message {
                address: 65535,
                ..message()
            },
            2,
        ),
    ] {
        let mut bytes = vec![0xa5; len];
        assert_eq!(
            host.read_registers(m, &mut bytes).unwrap_err().kind,
            ErrorKind::Length
        );
        assert_eq!(h.borrow().reads + h.borrow().stores, 0);
    }
    host.write_registers(message(), &[0x5a]).unwrap();
    drop(host.release().ok().unwrap());
    assert_eq!(h.borrow().drops, 1);
}

#[test]
fn uncertain_command_and_watermark_stores_are_never_replayed_or_released() {
    for after in [false, true] {
        for failed in 1..=4 {
            let (mut host, h) = setup(Layout::Legacy);
            h.borrow_mut().fail_store = Some(failed);
            h.borrow_mut().fail_after = after;
            let mut bytes = [0xa5; 3];
            let error = host.read_registers(message(), &mut bytes).unwrap_err();
            assert_eq!(error.kind, ErrorKind::Io);
            assert_eq!(error.issued, failed > 1);
            assert_eq!(bytes, [0xa5; 3]);
            let stores = h.borrow().stores;
            drop(host.release().err().unwrap());
            assert_eq!(h.borrow().stores, stores);
            assert_eq!(h.borrow().drops, 0);
        }
    }
}

#[test]
fn late_missing_extra_or_unacknowledged_responses_cannot_publish_output() {
    for fault in 0..3 {
        let (mut host, h) = setup(Layout::Extended);
        h.borrow_mut().silent = fault == 0;
        h.borrow_mut().excess = fault == 1;
        h.borrow_mut().ignore_ack = fault == 2;
        let mut bytes = [0xa5; 3];
        let error = host.read_registers(message(), &mut bytes).unwrap_err();
        assert_eq!(
            error.kind,
            if fault == 0 {
                ErrorKind::Timeout
            } else {
                ErrorKind::ForeignResponse
            }
        );
        assert_eq!(bytes, [0xa5; 3]);
        assert_eq!(h.borrow().wire.len(), 3);
        drop(host);
        assert_eq!(h.borrow().drops, 0);
    }
}

#[test]
fn foreign_irq_clock_stop_reset_and_response_state_refuse_before_command_effects() {
    for (offset, value) in [
        (INTERRUPT_MASK, 1),
        (STATUS, 1 << 16),
        (CONTROL, 1 << 7),
        (CONFIG, 1 << 5),
        (CONFIG, 1 << 24),
        (INTERRUPT, 1 << 8),
    ] {
        let (mut host, h) = setup(Layout::Legacy);
        h.borrow_mut().words.insert(offset, value);
        assert_eq!(
            host.write_registers(message(), &[0x19]).unwrap_err().kind,
            ErrorKind::Link
        );
        assert_eq!(h.borrow().stores, 0);
        assert!(h.borrow().wire.is_empty());
        drop(host);
        assert_eq!(h.borrow().drops, 0);
    }
}

#[test]
fn native_invalid_clock_returns_original_provider_before_any_callback() {
    struct NoIo(Rc<Cell<usize>>);
    impl Drop for NoIo {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    // SAFETY: isolated inaccessible model; invalid clock must return it intact.
    unsafe impl Registers for NoIo {
        fn layout(&self) -> Layout {
            panic!("layout before timing admission")
        }
        fn bytes(&self) -> usize {
            panic!("extent before timing admission")
        }
        fn read32(&mut self, _: usize) -> Result<u32, IoError> {
            panic!("read before timing admission")
        }
        fn write32(&mut self, _: usize, _: u32) -> Result<(), IoError> {
            panic!("write before timing admission")
        }
    }
    for rate in [0, u64::MAX, u64::MAX / 2 / TIMEOUT_US + 1] {
        let drops = Rc::new(Cell::new(0));
        let failure = Controller::new(
            NoIo(drops.clone()),
            crate::Clock {
                ticks_per_microsecond: rate,
            },
        )
        .err()
        .unwrap();
        assert_eq!(failure.0, ErrorKind::Configuration);
        assert_eq!(failure.2.ticks_per_microsecond, rate);
        assert_eq!(drops.get(), 0);
        drop(failure);
        assert_eq!(drops.get(), 1);
    }
}
