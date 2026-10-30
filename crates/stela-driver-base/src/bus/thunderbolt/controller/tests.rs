extern crate std;
use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use std::sync::Mutex;
struct PciState {
    values: Vec<u32>,
    writes: Vec<(u16, u32)>,
    fail: Option<u16>,
    reject: Option<u16>,
    ready_at: u64,
    ready_delay: u64,
}
struct Pci {
    state: Arc<Mutex<PciState>>,
    clock: Arc<AtomicU64>,
}
impl ConfigSpace for Pci {
    fn read32(&self, offset: u16) -> u32 {
        let state = self.state.lock().unwrap();
        if state.fail == Some(offset) {
            return u32::MAX;
        }
        let mut value = state.values[usize::from(offset) / 4];
        if offset == VS_FW_READY && self.clock.load(Ordering::Relaxed) >= state.ready_at {
            value |= 1 << 31;
        }
        value
    }
    fn write32(&mut self, offset: u16, value: u32) {
        let mut state = self.state.lock().unwrap();
        state.writes.push((offset, value));
        if state.reject != Some(offset) {
            state.values[usize::from(offset) / 4] = value;
            if offset == VS_FORCE && value & FORCE != 0 {
                state.ready_at = self
                    .clock
                    .load(Ordering::Relaxed)
                    .saturating_add(state.ready_delay);
            }
        }
    }
}
struct RegistersState {
    values: BTreeMap<usize, u32>,
    writes: Vec<(usize, u32)>,
    masks: Vec<u32>,
    notify: Vec<u32>,
    reject: Option<usize>,
    fail: Option<usize>,
    reset_delay: u64,
    reset_clear_at: u64,
}
struct Model {
    state: Mutex<RegistersState>,
    clock: Arc<AtomicU64>,
    style: InterruptStyle,
}
// SAFETY: this model owns one synthetic PCI/MMIO requester and reset epoch;
// its mutex preserves real read-clear/write-clear/reset failure effects.
unsafe impl Registers for Model {
    fn bytes(&self) -> usize {
        RESET + 4
    }
    fn read32(&self, offset: usize) -> u32 {
        let mut state = self.state.lock().unwrap();
        if state.fail == Some(offset) {
            return u32::MAX;
        }
        if (INTERRUPT..INTERRUPT + state.masks.len() * 4).contains(&offset) {
            return state.masks[(offset - INTERRUPT) / 4];
        }
        if (NOTIFY..NOTIFY + state.notify.len() * 4).contains(&offset) {
            let index = (offset - NOTIFY) / 4;
            let value = state.notify[index];
            if self.style == InterruptStyle::IntelAutoClear {
                state.notify[index] = 0;
            }
            return value;
        }
        if offset == RESET && self.clock.load(Ordering::Relaxed) >= state.reset_clear_at {
            state.values.insert(RESET, 0);
        }
        *state.values.get(&offset).unwrap_or(&0)
    }
    fn write32(&self, offset: usize, value: u32) {
        let mut state = self.state.lock().unwrap();
        state.writes.push((offset, value));
        if state.reject == Some(offset) {
            return;
        }
        if self.style == InterruptStyle::Usb4MaskClear
            && (MASK_CLEAR..MASK_CLEAR + state.masks.len() * 4).contains(&offset)
        {
            state.masks[(offset - MASK_CLEAR) / 4] &= !value;
            return;
        }
        if self.style == InterruptStyle::IntelAutoClear
            && (INTERRUPT..INTERRUPT + state.masks.len() * 4).contains(&offset)
        {
            state.masks[(offset - INTERRUPT) / 4] = value;
            return;
        }
        if self.style == InterruptStyle::Usb4MaskClear
            && (INT_CLEAR..INT_CLEAR + state.notify.len() * 4).contains(&offset)
        {
            state.notify[(offset - INT_CLEAR) / 4] &= !value;
            return;
        }
        state.values.insert(offset, value);
        if offset == RESET {
            state.reset_clear_at = self
                .clock
                .load(Ordering::Relaxed)
                .saturating_add(state.reset_delay);
        }
    }
}
fn fixture(vendor: u16, device: u16, class: u32, version: u8, hops: u16) -> (Pci, Arc<Model>) {
    let clock = Arc::new(AtomicU64::new(0));
    let mut values = vec![0; 1024];
    values[0] = u32::from(vendor) | (u32::from(device) << 16);
    values[1] = 2;
    values[2] = (class << 8) | 3;
    values[usize::from(VS_FORCE) / 4] = 0x98ab5678;
    values[usize::from(VS_MAX_LTR) / 4] = 0xdead1234;
    let pci = Pci {
        state: Arc::new(Mutex::new(PciState {
            values,
            writes: Vec::new(),
            fail: None,
            reject: None,
            ready_at: u64::MAX,
            ready_delay: 6,
        })),
        clock: clock.clone(),
    };
    let mut registers = BTreeMap::new();
    registers.insert(CAPABILITIES, (u32::from(version) << 16) | u32::from(hops));
    let model = Arc::new(Model {
        state: Mutex::new(RegistersState {
            values: registers,
            writes: Vec::new(),
            masks: vec![u32::MAX; (usize::from(hops) * 2).div_ceil(32)],
            notify: vec![u32::MAX; (usize::from(hops) * 3).div_ceil(32)],
            reject: None,
            fail: None,
            reset_delay: 50,
            reset_clear_at: u64::MAX,
        }),
        clock,
        style: if vendor == 0x8086 {
            InterruptStyle::IntelAutoClear
        } else {
            InterruptStyle::Usb4MaskClear
        },
    });
    (pci, model)
}
fn poll(controller: &mut Controller<'_, Pci, Model>, now: u64) -> Result<Option<Prepared>, Error> {
    controller.registers.clock.store(now, Ordering::Relaxed);
    controller.poll(now)
}
#[test]
fn intel_integrated_force_ready_ltr_reset_and_interrupt_register_effects() {
    let (mut pci, model) = fixture(0x8086, 0x9a1b, 0x0c0340, 0x40, 8);
    let state = pci.state.clone();
    // SAFETY: both surfaces are this same exclusively owned synthetic
    // requester/epoch, real modeled D0/decode, master off, no prior DMA/IRQ.
    let mut controller = unsafe { Controller::new(&mut pci, model.clone()) }.unwrap();
    assert_eq!(poll(&mut controller, 0).unwrap(), None);
    assert!(state.lock().unwrap().writes.is_empty());
    assert_eq!(model.state.lock().unwrap().writes, vec![(RESET, 1)]);
    assert_eq!(poll(&mut controller, 99).unwrap(), None);
    assert_eq!(poll(&mut controller, 100).unwrap(), None);
    assert_eq!(state.lock().unwrap().writes, vec![(VS_FORCE, 0x22ab567a)]);
    for now in [100, 101, 103, 105] {
        assert_eq!(poll(&mut controller, now).unwrap(), None);
    }
    let prepared = poll(&mut controller, 106).unwrap().unwrap();
    assert_eq!(
        state.lock().unwrap().writes,
        vec![(VS_FORCE, 0x22ab567a), (VS_LTR, 0x12341234)]
    );
    assert_eq!(prepared.hop_count, 8);
    assert_eq!(prepared.profile.family(), Family::IntelIntegrated);
    assert_eq!(prepared.version, 0x40);
    assert!(
        model
            .state
            .lock()
            .unwrap()
            .masks
            .iter()
            .all(|value| *value == 0)
    );
    assert!(
        model
            .state
            .lock()
            .unwrap()
            .notify
            .iter()
            .all(|value| *value == 0)
    );
    assert_eq!(poll(&mut controller, 107), Err(Error::Stopped));
    assert!(
        state
            .lock()
            .unwrap()
            .writes
            .iter()
            .all(|(offset, _)| *offset != 4)
    );
}
#[test]
fn generic_usb4_amd_uses_source_mask_clear_banks_and_discrete_skips_icl_power() {
    for (vendor, device, class, version, hops) in [
        (0x1022, 0x1668, 0x0c0340, 0x40, 33),
        (0x8086, 0x1575, 0x088000, 0x20, 16),
    ] {
        let (mut pci, model) = fixture(vendor, device, class, version, hops);
        let state = pci.state.clone();
        // SAFETY: same synthetic physical requester, epoch and stopped
        // resources; all required native ownership grants are modeled.
        let mut controller = unsafe { Controller::new(&mut pci, model.clone()) }.unwrap();
        let result = poll(&mut controller, 0).unwrap();
        let prepared = if version >= 0x40 {
            assert_eq!(result, None);
            poll(&mut controller, 100).unwrap().unwrap()
        } else {
            result.unwrap()
        };
        assert_eq!(prepared.hop_count, hops);
        assert!(state.lock().unwrap().writes.is_empty());
        let model_state = model.state.lock().unwrap();
        assert!(model_state.masks.iter().all(|v| *v == 0));
        assert!(model_state.notify.iter().all(|v| *v == 0));
        if vendor != 0x8086 {
            assert_eq!(prepared.profile.family(), Family::Usb4Compliant);
            for index in 0..(usize::from(hops) * 2).div_ceil(32) {
                assert!(
                    model_state
                        .writes
                        .contains(&(MASK_CLEAR + 4 * index, u32::MAX))
                );
            }
        }
    }
}
#[test]
fn identity_decode_mastering_active_ring_and_mapping_fail_before_mutation() {
    for case in 0..7 {
        let (mut pci, model) = fixture(0x8086, 0x9a1b, 0x0c0340, 0x40, 8);
        let state = pci.state.clone();
        match case {
            0 => state.lock().unwrap().values[1] = 0,
            1 => state.lock().unwrap().values[1] = 6,
            2 => state.lock().unwrap().values[0] = u32::MAX,
            3 => state.lock().unwrap().values[0] = 0x15138086,
            4 => state.lock().unwrap().values[2] = 0x03000000,
            5 => {
                model
                    .state
                    .lock()
                    .unwrap()
                    .values
                    .insert(CAPABILITIES, u32::MAX);
            }
            _ => {
                model.state.lock().unwrap().values.insert(0x19800, 1 << 31);
            }
        }
        // SAFETY: synthetic identity/register faults test
        // validation; no other physical owner or DMA can exist.
        match unsafe { Controller::new(&mut pci, model.clone()) } {
            Ok(mut controller) => assert_eq!(poll(&mut controller, 0), Err(Error::Busy)),
            Err(_) => assert_ne!(case, 6),
        }
        assert!(state.lock().unwrap().writes.is_empty());
        assert!(model.state.lock().unwrap().writes.is_empty());
    }
}
#[test]
fn firmware_timeout_failed_readback_and_reset_failure_quarantine_real_reservation() {
    for case in 0..5 {
        let integrated = case < 3;
        let (mut pci, model) = fixture(
            if integrated { 0x8086 } else { 0x1022 },
            if integrated { 0x9a1b } else { 0x1668 },
            0x0c0340,
            0x40,
            8,
        );
        let state = pci.state.clone();
        match case {
            0 => state.lock().unwrap().ready_delay = u64::MAX,
            1 => state.lock().unwrap().fail = Some(VS_FW_READY),
            2 => state.lock().unwrap().reject = Some(VS_LTR),
            3 => model.state.lock().unwrap().reset_delay = u64::MAX,
            _ => model.state.lock().unwrap().reject = Some(MASK_CLEAR),
        }
        // SAFETY: same stopped synthetic NHI; injected failures preserve
        // physical ownership rather than authorizing fallback startup.
        let mut controller = unsafe { Controller::new(&mut pci, model.clone()) }.unwrap();
        assert_eq!(poll(&mut controller, 0).unwrap(), None);
        if integrated {
            assert_eq!(poll(&mut controller, 100).unwrap(), None);
        }
        let error = match case {
            0 => {
                for step in 0..350 {
                    assert_eq!(poll(&mut controller, 100 + step * 3).unwrap(), None);
                }
                poll(&mut controller, 1150)
            }
            1 => poll(&mut controller, 100),
            2 => poll(&mut controller, 106),
            3 => poll(&mut controller, 600),
            _ => poll(&mut controller, 100),
        };
        assert_eq!(
            error,
            Err(match case {
                0 => Error::FirmwareTimeout,
                1 => Error::PciRead(VS_FW_READY),
                2 => Error::PciRejected(VS_LTR),
                3 => Error::ResetTimeout,
                _ => Error::RegisterRejected(INTERRUPT),
            })
        );
        let pci_writes = state.lock().unwrap().writes.len();
        let mmio_writes = model.state.lock().unwrap().writes.len();
        assert_eq!(poll(&mut controller, 2000), Err(Error::Poisoned));
        assert_eq!(state.lock().unwrap().writes.len(), pci_writes);
        assert_eq!(model.state.lock().unwrap().writes.len(), mmio_writes);
        drop(controller);
        assert!(
            Arc::strong_count(&model) >= 2,
            "uncertain reservation must remain retained"
        );
    }
}
#[test]
fn clock_regression_and_overflow_never_claim_prepared_or_publish_new_work() {
    let (mut pci, model) = fixture(0x8086, 0x9a1b, 0x0c0340, 0x40, 8);
    let state = pci.state.clone();
    // SAFETY: same synthetic requester and epoch contract.
    let mut controller = unsafe { Controller::new(&mut pci, model.clone()) }.unwrap();
    assert_eq!(poll(&mut controller, u64::MAX), Err(Error::ClockOverflow));
    assert!(state.lock().unwrap().writes.is_empty());
    drop(controller);
    let (mut pci, model) = fixture(0x8086, 0x9a1b, 0x0c0340, 0x40, 8);
    let state = pci.state.clone();
    // SAFETY: independent synthetic requester/epoch, no prior work.
    let mut controller = unsafe { Controller::new(&mut pci, model.clone()) }.unwrap();
    poll(&mut controller, 10).unwrap();
    let writes = state.lock().unwrap().writes.len();
    assert_eq!(poll(&mut controller, 9), Err(Error::ClockRegressed));
    assert_eq!(state.lock().unwrap().writes.len(), writes);
}

#[test]
#[ignore = "oracle: STELA_THUNDERBOLT_CONTROLLER_ORACLE"]
fn unchanged_linux_controller_preparation_effects_and_match_table_agree() {
    use std::{env, fs};
    let trace = fs::read_to_string(
        env::var("STELA_THUNDERBOLT_CONTROLLER_ORACLE").expect("set controller trace"),
    )
    .unwrap();
    let mut count = 0;
    for line in trace.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        assert_eq!(fields[0], "C");
        let data: Vec<u32> = fields[1..]
            .iter()
            .map(|word| word.parse().unwrap())
            .collect();
        let (mut pci, model) = fixture(
            data[0] as u16,
            data[1] as u16,
            data[2],
            data[3] as u8,
            data[4] as u16,
        );
        let state = pci.state.clone();
        // SAFETY: this same stopped synthetic requester/epoch is
        // represented by both PCI and MMIO; no independent owner is paired.
        let mut controller = unsafe { Controller::new(&mut pci, model.clone()) }.unwrap();
        let mut prepared = None;
        for now in 0..200 {
            prepared = poll(&mut controller, now).unwrap();
            if prepared.is_some() {
                break;
            }
        }
        let prepared = prepared.expect("bounded source-modeled startup");
        assert_eq!(
            data[5],
            match prepared.profile.family() {
                Family::IntelDiscrete => 0,
                Family::IntelIntegrated => 1,
                Family::Usb4Compliant => 2,
            }
        );
        let pci_count = data[6] as usize;
        let mut at = 7;
        let expected_pci: Vec<(u16, u32)> = (0..pci_count)
            .map(|_| {
                let value = (data[at] as u16, data[at + 1]);
                at += 2;
                value
            })
            .collect();
        let mmio_count = data[at] as usize;
        at += 1;
        let expected_mmio: Vec<(usize, u32)> = (0..mmio_count)
            .map(|_| {
                let value = (data[at] as usize, data[at + 1]);
                at += 2;
                value
            })
            .collect();
        assert_eq!(at, data.len());
        assert_eq!(state.lock().unwrap().writes, expected_pci, "{line}");
        assert_eq!(model.state.lock().unwrap().writes, expected_mmio, "{line}");
        count += 1;
    }
    assert_eq!(count, 350);
}
