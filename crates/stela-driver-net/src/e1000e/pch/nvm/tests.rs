extern crate std;
use super::*;
use alloc::{rc::Rc, sync::Arc, vec, vec::Vec};
use core::{
    cell::RefCell,
    sync::atomic::{AtomicUsize, Ordering},
};

struct State {
    timing_failure: Option<crate::bus::pci::power::Error>,
    fail_delay_at: Option<usize>,
    delay_calls: usize,
    timer_drops: Arc<AtomicUsize>,

    layout: Layout,
    fw: u32,
    gfpreg: u32,
    strap: u32,
    memory: Vec<u8>,
    status: u16,
    control: u16,
    address: u32,
    data: u32,
    ops: Vec<[u32; 3]>,
    accesses: usize,
    fail_at: Option<usize>,
    errors: usize,
    delay_reads: usize,
    pending: Option<usize>,
    hang: bool,
    record: bool,
    reads: usize,
    waits: usize,
    cycles: usize,
}
impl State {
    fn record(&mut self, kind: u32, address: u32, value: u32) {
        if self.record {
            self.ops.push([kind, address, value]);
        }
    }
    fn enter(&mut self) -> Result<(), Error> {
        let at = self.accesses;
        self.accesses += 1;
        if self.fail_at == Some(at) {
            Err(Error::Access)
        } else {
            Ok(())
        }
    }
    fn status(&mut self) -> u16 {
        self.reads += 1;
        if let Some(left) = self.pending
            && !self.hang
        {
            if left == 0 {
                self.pending = None;
                self.status = (self.status & !IN_PROGRESS) | DONE;
                if self.errors > 0 {
                    self.errors -= 1;
                    self.status |= CYCLE_ERROR;
                }
            } else {
                self.pending = Some(left - 1);
            }
        }
        self.status
    }
    fn status_store(&mut self, value: u16) {
        self.status &= !(value & (DONE | CYCLE_ERROR | ACCESS_ERROR));
    }
    fn control_store(&mut self, value: u16) {
        self.control = value & !GO;
        if value & GO != 0 {
            assert_eq!(
                value & CYCLE_MASK,
                0,
                "persistent flash modification attempted"
            );
            self.cycles += 1;
            self.pending = Some(self.delay_reads);
            self.status = (self.status & !(DONE | CYCLE_ERROR | ACCESS_ERROR)) | IN_PROGRESS;
            let size = usize::from((value & SIZE_MASK) >> 8) + 1;
            let at = self.address as usize;
            let mut bytes = [0xf0u8; 4];
            bytes[..size].copy_from_slice(&self.memory[at..at + size]);
            self.data = u32::from_le_bytes(bytes);
        }
    }
}
struct Io {
    state: Rc<RefCell<State>>,
    released: Arc<AtomicUsize>,
}
impl Drop for Io {
    fn drop(&mut self) {
        self.released.fetch_add(1, Ordering::SeqCst);
    }
}
// SAFETY: one serial deterministic register/flash model with no concurrent
// native producer; flash operations are not performed by this fixture.
unsafe impl Registers for Io {
    fn read_mac32(&mut self, at: u32) -> Result<u32, Error> {
        let mut s = self.state.borrow_mut();
        s.enter()?;
        let value = match at {
            FWSM => s.fw,
            STRAP => s.strap,
            _ => panic!("unknown MAC read"),
        };
        s.record(0x10, at, value);
        Ok(value)
    }
    fn read16(&mut self, at: u32) -> Result<u16, Error> {
        let mut s = self.state.borrow_mut();
        s.enter()?;
        let value = match at {
            HSFSTS => s.status(),
            HSFCTL => {
                assert_ne!(s.layout, Layout::Spt);
                s.control
            }
            _ => panic!("unknown read16"),
        };
        s.record(0, at, u32::from(value));
        Ok(value)
    }
    fn read32(&mut self, at: u32) -> Result<u32, Error> {
        let mut s = self.state.borrow_mut();
        s.enter()?;
        let value = match at {
            GFPREG => s.gfpreg,
            HSFSTS => {
                assert_eq!(s.layout, Layout::Spt);
                u32::from(s.status()) | (u32::from(s.control) << 16)
            }
            FDATA => s.data,
            _ => panic!("unknown read32"),
        };
        s.record(1, at, value);
        Ok(value)
    }
    fn write16(&mut self, at: u32, value: u16) -> Result<(), Error> {
        let mut s = self.state.borrow_mut();
        s.enter()?;
        assert_ne!(s.layout, Layout::Spt);
        s.record(2, at, u32::from(value));
        match at {
            HSFSTS => s.status_store(value),
            HSFCTL => s.control_store(value),
            _ => panic!("unknown write16"),
        };
        Ok(())
    }
    fn write32(&mut self, at: u32, value: u32) -> Result<(), Error> {
        let mut s = self.state.borrow_mut();
        s.enter()?;
        s.record(3, at, value);
        match at {
            HSFSTS => {
                assert_eq!(s.layout, Layout::Spt);
                s.status_store(value as u16);
                s.control_store((value >> 16) as u16)
            }
            FADDR => s.address = value,
            _ => panic!("unknown write32"),
        };
        Ok(())
    }
}
struct Timer(Rc<RefCell<State>>, Arc<AtomicUsize>);
impl Timer {
    fn new(state: Rc<RefCell<State>>) -> Self {
        let drops = state.borrow().timer_drops.clone();
        Self(state, drops)
    }
}
// SAFETY: isolated owned virtual-time model; this grants no native permission.
unsafe impl Delay for Timer {
    fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
        if let Some(error) = self.0.borrow().timing_failure {
            Err(error)
        } else {
            Ok(())
        }
    }
    fn wait_us(&self, us: u64) -> Result<(), crate::bus::pci::power::Error> {
        self.check()?;
        {
            let mut state = self.0.borrow_mut();
            let at = state.delay_calls;
            state.delay_calls += 1;
            if state.fail_delay_at == Some(at) {
                let error = crate::bus::pci::power::Error::Clock;
                state.timing_failure = Some(error);
                return Err(error);
            }
        }
        let mut s = self.0.borrow_mut();
        s.waits += 1;
        s.record(4, us as u32, 0);
        Ok(())
    }
}
impl Drop for Timer {
    fn drop(&mut self) {
        self.1.fetch_add(1, Ordering::Relaxed);
    }
}

fn make_state(layout: Layout, bank: u8) -> State {
    let base = if layout == Layout::Spt { 0 } else { 0x2000 };
    let mut memory = vec![0u8; base + 8192];
    for b in 0..2 {
        let mut words = [0u16; 2048];
        for (i, word) in words.iter_mut().enumerate() {
            *word = (i as u16).wrapping_mul(17) ^ ((b as u16) << 12);
        }
        words[0] = 0x1102;
        words[1] = 0x3322;
        words[2] = 0x5544;
        words[3] |= 1;
        words[0x19] |= 0x40;
        words[0x13] = (words[0x13] & 0x3fff) | if b == usize::from(bank) { 0x8000 } else { 0 };
        words[63] = 0xbabau16.wrapping_sub(words[..63].iter().copied().fold(0, u16::wrapping_add));
        for (i, word) in words.into_iter().enumerate() {
            memory[base + b * 4096 + i * 2..base + b * 4096 + i * 2 + 2]
                .copy_from_slice(&word.to_le_bytes());
        }
    }
    State {
        timing_failure: None,
        fail_delay_at: None,
        delay_calls: 0,
        timer_drops: Arc::new(AtomicUsize::new(0)),
        layout,
        fw: 0x40,
        gfpreg: (3 << 16) | 2,
        strap: 2,
        memory,
        status: DESCRIPTOR_VALID | DONE,
        control: 0x4400,
        address: 0,
        data: 0,
        ops: Vec::new(),
        accesses: 0,
        fail_at: None,
        errors: 0,
        delay_reads: 0,
        pending: None,
        hang: false,
        record: true,
        reads: 0,
        waits: 0,
        cycles: 0,
    }
}
type Fixture = (Nvm<Io, Timer>, Rc<RefCell<State>>, Arc<AtomicUsize>);
fn fixture(layout: Layout, bank: u8) -> Fixture {
    let state = Rc::new(RefCell::new(make_state(layout, bank)));
    let released = Arc::new(AtomicUsize::new(0));
    let io = Io {
        state: state.clone(),
        released: released.clone(),
    };
    // SAFETY: one controlled fresh model matches its selected layout.
    let nvm = unsafe { Nvm::new(layout, io, Timer::new(state.clone())) }.unwrap();
    (nvm, state, released)
}
#[test]
fn geometries_and_banks_supply_validated_factory_station() {
    for layout in [Layout::Pch2, Layout::Lpt, Layout::Spt] {
        for bank in 0..2 {
            let (mut nvm, state, released) = fixture(layout, bank);
            assert_eq!(
                nvm.geometry(),
                Geometry {
                    base: if layout == Layout::Spt { 0 } else { 0x2000 },
                    bank_words: 2048
                }
            );
            nvm.validate().unwrap();
            assert_eq!(nvm.selected_bank(), Some(bank));
            assert_eq!(nvm.station().unwrap().0, [2, 0x11, 0x22, 0x33, 0x44, 0x55]);
            assert!(state.borrow().cycles > 0);
            drop(nvm);
            assert_eq!(released.load(Ordering::SeqCst), 1);
        }
    }
}
#[test]
fn odd_spt_reads_and_erased_data_are_actual_bounded_payloads() {
    for layout in [Layout::Pch2, Layout::Lpt, Layout::Spt] {
        let (mut nvm, state, _) = fixture(layout, 1);
        let base = if layout == Layout::Spt { 0 } else { 0x2000 };
        state.borrow_mut().memory[base + 4096 + 7 * 2..base + 4096 + 7 * 2 + 2].fill(0xff);
        for (offset, length) in [(0, 1), (1, 2), (7, 5), (2046, 2), (2047, 1)] {
            let mut output = vec![0; length];
            nvm.read(offset, &mut output).unwrap();
            let s = state.borrow();
            for (i, word) in output.iter().enumerate() {
                let at = base + 4096 + (usize::from(offset) + i) * 2;
                assert_eq!(
                    *word,
                    u16::from_le_bytes(s.memory[at..at + 2].try_into().unwrap())
                );
            }
        }
        assert!(!nvm.is_poisoned());
        let count = state.borrow().accesses;
        let mut unchanged = [0xdead; 2];
        assert_eq!(nvm.read(2047, &mut unchanged), Err(Error::Bounds));
        assert_eq!(unchanged, [0xdead; 2]);
        assert_eq!(state.borrow().accesses, count);
    }
}
#[test]
fn every_flash_access_failure_preserves_output_and_keeps_owner() {
    for layout in [Layout::Pch2, Layout::Spt] {
        let (mut good, state, _) = fixture(layout, 1);
        let begin = state.borrow().accesses;
        good.read(1, &mut [0u16; 3]).unwrap();
        let end = state.borrow().accesses;
        for fail in begin..end {
            let (mut nvm, state, released) = fixture(layout, 1);
            state.borrow_mut().fail_at = Some(fail);
            let mut output = [0xcafe; 3];
            assert_eq!(nvm.read(1, &mut output), Err(Error::Access));
            assert_eq!(output, [0xcafe; 3]);
            assert!(nvm.is_poisoned());
            let accesses = state.borrow().accesses;
            assert_eq!(nvm.read(0, &mut [0u16]), Err(Error::Poisoned));
            assert_eq!(state.borrow().accesses, accesses);
            drop(nvm);
            assert_eq!(released.load(Ordering::SeqCst), 0);
        }
    }
}
#[test]
fn invalid_bank_checksum_marker_and_descriptor_never_get_fallback_success() {
    for layout in [Layout::Pch2, Layout::Lpt, Layout::Spt] {
        for fault in 0..4 {
            let (mut nvm, state, _) = fixture(layout, 0);
            let base = if layout == Layout::Spt { 0 } else { 0x2000 };
            match fault {
                0 => state.borrow_mut().memory[base + 0x13 * 2 + 1] = 0,
                1 => state.borrow_mut().memory[base + 63 * 2] ^= 1,
                2 => {
                    let at = if layout == Layout::Pch2 {
                        0x19 * 2
                    } else {
                        3 * 2
                    };
                    let mask = if layout == Layout::Pch2 { 0x40 } else { 1 };
                    state.borrow_mut().memory[base + at] &= !mask;
                }
                _ => state.borrow_mut().status &= !DESCRIPTOR_VALID,
            }
            let error = nvm.validate().unwrap_err();
            assert!(matches!(
                (fault, error),
                (0, Error::NoValidBank)
                    | (1, Error::Checksum(_))
                    | (2, Error::RepairRequired)
                    | (3, Error::InvalidDescriptor)
            ));
            assert!(nvm.is_poisoned());
        }
    }
}
#[test]
fn nvm_retries_are_bounded_without_flash_writes() {
    for layout in [Layout::Pch2, Layout::Spt] {
        let (mut nvm, state, _) = fixture(layout, 0);
        state.borrow_mut().errors = 2;
        nvm.read(0, &mut [0u16]).unwrap();
        assert_eq!(state.borrow().cycles, 4);
        let (mut nvm, state, _) = fixture(layout, 0);
        state.borrow_mut().errors = 20;
        assert!(matches!(nvm.read(0, &mut [0u16]), Err(Error::Cycle(_))));
        assert_eq!(state.borrow().cycles, 11);
    }
    let (mut nvm, state, released) = fixture(Layout::Spt, 0);
    state.borrow_mut().hang = true;
    state.borrow_mut().record = false;
    let mut output = [0xaabb];
    assert_eq!(nvm.read(0, &mut output), Err(Error::Timeout));
    assert_eq!(output, [0xaabb]);
    assert_eq!(state.borrow().cycles, 1);
    assert_eq!(state.borrow().waits, POLLS + 2);
    drop(nvm);
    assert_eq!(released.load(Ordering::SeqCst), 0);
}
#[test]
fn a_failed_post_cycle_observation_keeps_the_timeout() {
    let (mut baseline, state, _) = fixture(Layout::Spt, 0);
    state.borrow_mut().hang = true;
    state.borrow_mut().record = false;
    assert_eq!(baseline.read(0, &mut [0u16]), Err(Error::Timeout));
    let final_observation = state.borrow().accesses - 1;
    let (mut nvm, state, released) = fixture(Layout::Spt, 0);
    {
        let mut s = state.borrow_mut();
        s.hang = true;
        s.record = false;
        s.fail_at = Some(final_observation);
    }
    let mut untouched = [0xabcd];
    assert_eq!(
        nvm.read(0, &mut untouched),
        Err(Error::Followup {
            primary: CycleFailure::Timeout,
            observation: Box::new(Error::Access),
        })
    );
    assert_eq!(untouched, [0xabcd]);
    assert_eq!(state.borrow().cycles, 1);
    assert!(nvm.is_poisoned());
    drop(nvm);
    assert_eq!(released.load(Ordering::SeqCst), 0);
}

#[test]
fn geometry_and_me_qualification_refuse_without_sequencer_writes() {
    assert_eq!(
        Geometry::from_register(Layout::Pch2, 0x0001_0003),
        Err(Error::InvalidGeometry)
    );
    assert_eq!(
        Geometry::from_register(Layout::Pch2, u32::MAX),
        Err(Error::Removed)
    );
    for layout in [Layout::Pch2, Layout::Lpt, Layout::Spt] {
        let state = Rc::new(RefCell::new(make_state(layout, 0)));
        state.borrow_mut().fw |= 1 << 15;
        let released = Arc::new(AtomicUsize::new(0));
        let io = Io {
            state: state.clone(),
            released: released.clone(),
        };
        assert!(matches!(
            // SAFETY: sole model reservation, with the chosen layout.
            unsafe { Nvm::new(layout, io, Timer::new(state.clone())) },
            Err(Error::FirmwareOwned)
        ));
        assert!(!state.borrow().ops.iter().any(|op| matches!(op[0], 2 | 3)));
        assert_eq!(released.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn native_separate_and_integrated_windows_enforce_access_widths() {
    use crate::e1000e::pch::io::NvmMmio;
    use core::ptr::NonNull;
    let mut mac = vec![0u32; 0x10000 / 4];
    let macp = NonNull::new(mac.as_mut_ptr().cast()).unwrap();
    let mut flash = vec![0u32; 8];
    let flashp = NonNull::new(flash.as_mut_ptr().cast()).unwrap();
    let owner: Arc<dyn core::any::Any> = Arc::new(());
    // SAFETY: exclusive stable allocations stand in for the two UC
    // windows in this model only; no physical-hardware proof is inferred.
    let mut separate =
        unsafe { NvmMmio::from_separate_windows(macp, 0x10000, flashp, 32, owner.clone()) }
            .unwrap();
    separate.write16(6, 0x1234).unwrap();
    assert_eq!(separate.read16(6).unwrap(), 0x1234);
    assert_eq!(flash[1], 0x1234_0000);
    assert_eq!(separate.write32(6, 0), Err(Error::Bounds));
    assert_eq!(separate.read16(31), Err(Error::Bounds));
    assert_eq!(separate.read32(32), Err(Error::Bounds));
    assert_eq!(flash[2], 0);
    drop(separate);
    // SAFETY: same-allocation +e000 subwindow and complete bounds.
    let mut integrated = unsafe { NvmMmio::from_mac_window(macp, 0x10000, owner) }.unwrap();
    integrated.write32(4, 0x5678_0000).unwrap();
    assert_eq!(integrated.read32(4).unwrap(), 0x5678_0000);
    assert_eq!(mac[(0xe000 + 4) / 4], 0x5678_0000);
    assert_eq!(mac[(0xe000 + 8) / 4], 0);
    assert_eq!(integrated.read16(0x2000), Err(Error::Bounds));
}

#[test]
#[ignore = "oracle: STELA_E1000E_PCH_NVM_ORACLE"]
fn unchanged_linux_pch_nvm_register_effects_and_payloads() {
    let path = std::env::var("STELA_E1000E_PCH_NVM_ORACLE").expect("NVM oracle trace");
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(bytes.len() % 4, 0);
    let words: Vec<u32> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|b| u32::from_le_bytes(*b))
        .collect();
    let mut at = 0;
    let mut cases = 0;
    while at < words.len() {
        let h = &words[at..at + 8];
        at += 8;
        let layout = match h[0] {
            0 => Layout::Pch2,
            1 => Layout::Lpt,
            2 => Layout::Spt,
            _ => panic!("bad layout"),
        };
        let (mut nvm, state, _) = fixture(layout, h[1] as u8);
        {
            let mut s = state.borrow_mut();
            s.errors = h[4] as usize;
            s.delay_reads = h[5] as usize;
            if h[6] != 0 {
                s.pending = Some(s.delay_reads);
                s.status |= IN_PROGRESS;
            }
        }
        let expected = &words[at..at + h[3] as usize];
        at += h[3] as usize;
        let mut output = vec![0u16; h[3] as usize];
        nvm.read(h[2] as u16, &mut output).unwrap();
        assert_eq!(
            output.iter().copied().map(u32::from).collect::<Vec<_>>(),
            expected
        );
        let operations = words[at..at + h[7] as usize * 3].as_chunks::<3>().0;
        at += h[7] as usize * 3;
        assert_eq!(state.borrow().ops, operations, "case {cases}: {h:?}");
        cases += 1;
    }
    assert_eq!(cases, 648);
}

#[test]
fn failed_flash_minimum_keeps_output_and_actual_register_timer_pair() {
    for layout in [Layout::Pch2, Layout::Lpt, Layout::Spt] {
        let (mut nvm, state, released) = fixture(layout, 0);
        {
            let mut model = state.borrow_mut();
            model.delay_reads = 1;
            model.fail_delay_at = Some(model.delay_calls);
        }
        let cause = crate::bus::pci::power::Error::Clock;
        let mut output = [0xa55a; 3];
        assert_eq!(nvm.read(0, &mut output), Err(Error::Minimum(cause)));
        assert_eq!(output, [0xa55a; 3]);
        assert!(nvm.is_poisoned());
        let observed = state.borrow().ops.clone();
        let accesses = state.borrow().accesses;
        state.borrow_mut().timing_failure = None;
        assert_eq!(nvm.read(0, &mut output), Err(Error::Minimum(cause)));
        assert_eq!(state.borrow().ops, observed);
        assert_eq!(state.borrow().accesses, accesses);
        drop(nvm);
        assert_eq!(released.load(Ordering::SeqCst), 0);
        assert_eq!(state.borrow().timer_drops.load(Ordering::SeqCst), 0);
    }
}
