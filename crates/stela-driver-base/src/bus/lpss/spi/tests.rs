use super::*;
use alloc::{collections::VecDeque, rc::Rc, vec, vec::Vec};
use core::cell::{Cell, RefCell};
#[derive(Clone)]
struct Time(Rc<Cell<u64>>);
impl crate::bus::i2c::Timer for Time {
    fn now_us(&self) -> u64 {
        self.0.get()
    }
    fn relax(&self) {
        self.0.set(self.0.get().wrapping_add(1));
    }
}
impl Timer for Time {
    fn calibrated(&self) -> bool {
        true
    }
}
#[derive(Clone, Copy, Debug)]
enum Access {
    Identity,
    Read(usize),
    Write(usize, u32),
}
struct Hardware {
    device: u16,
    regs: [u32; 0x300 / 4],
    base: u64,
    rx: VecDeque<u32>,
    wire: Vec<u32>,
    log: Vec<Access>,
    fail: Option<(usize, bool)>,
    reject: Option<usize>,
    drops: usize,
}
impl Hardware {
    fn begin(&mut self, access: Access) -> Result<bool, super::super::Error> {
        self.log.push(access);
        if self.fail == Some((self.log.len(), false)) {
            return Err(super::super::Error::Io);
        }
        Ok(self.fail == Some((self.log.len(), true)))
    }
}
struct Model(Rc<RefCell<Hardware>>);
impl Drop for Model {
    fn drop(&mut self) {
        self.0.borrow_mut().drops += 1;
    }
}
// SAFETY: isolated uniquely owned source-register and peripheral peer, with
// backing and independent before/after effect failures.
unsafe impl Registers for Model {
    fn identity(&mut self) -> Result<Identity, super::super::Error> {
        let mut h = self.0.borrow_mut();
        let late = h.begin(Access::Identity)?;
        if late {
            return Err(super::super::Error::Io);
        }
        Ok(Identity {
            vendor: 0x8086,
            device: h.device,
            subsystem_vendor: 1,
            subsystem_device: 2,
        })
    }
    fn physical_base(&self) -> u64 {
        self.0.borrow().base
    }
    fn read32(&mut self, offset: usize) -> Result<u32, super::super::Error> {
        let mut h = self.0.borrow_mut();
        let late = h.begin(Access::Read(offset))?;
        let value = match offset {
            8 => 4 | if h.rx.is_empty() { 0 } else { 8 },
            0x10 => h.rx.pop_front().expect("read beyond actual device RX"),
            _ => h.regs[offset / 4],
        };
        if late {
            Err(super::super::Error::Io)
        } else {
            Ok(value)
        }
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), super::super::Error> {
        let mut h = self.0.borrow_mut();
        let late = h.begin(Access::Write(offset, value))?;
        if h.reject != Some(offset) {
            match offset {
                8 => {}
                0x10 => {
                    assert_eq!(h.regs[0x204 / 4], 7);
                    assert_eq!(h.regs[0x200 / 4] & 0x8000_0001, 0x8000_0001);
                    assert_ne!(h.regs[0] & 128, 0);
                    assert_eq!(h.regs[0x224 / 4] & 3, 1);
                    assert_eq!(h.regs[1] & (3 | 1 << 19 | 3 << 20), 0);
                    h.wire.push(value);
                    h.rx.push_back(value ^ 0xa5);
                }
                0x204 => {
                    h.regs[offset / 4] = value;
                    if value == 0 {
                        h.regs[..0x200 / 4].fill(0);
                        h.rx.clear();
                    }
                }
                _ => h.regs[offset / 4] = value,
            }
        }
        if late {
            Err(super::super::Error::Io)
        } else {
            Ok(())
        }
    }
}
fn model(device: u16, clock: u32) -> (Model, Time, Rc<RefCell<Hardware>>) {
    let mut regs = [0; 0x300 / 4];
    regs[0x200 / 4] = clock;
    regs[0x2fc / 4] = 15 << 9 | 2 << 4;
    let h = Rc::new(RefCell::new(Hardware {
        device,
        regs,
        base: 0x1234_5000_0000,
        rx: VecDeque::new(),
        wire: vec![],
        log: vec![],
        fail: None,
        reject: None,
        drops: 0,
    }));
    (Model(h.clone()), Time(Rc::new(Cell::new(0))), h)
}
#[test]
fn spi_ids_select_source_clock_and_not_i2c_profiles() {
    let profile = Profile::select(Identity {
        vendor: 0x8086,
        device: 0xa0aa,
        subsystem_vendor: 0,
        subsystem_device: 0,
    })
    .unwrap();
    assert_eq!(profile.family(), pxa2xx::Profile::CannonLake);
    assert_eq!(profile.root_clock_hz(), 120_000_000);
    assert!(
        Profile::select(Identity {
            vendor: 0x8086,
            device: 0x9d60,
            subsystem_vendor: 0,
            subsystem_device: 0
        })
        .is_err()
    );
}

#[test]
fn kept_private_reset_remap_fractional_clock_and_real_pio_compose_before_retirement() {
    for (device, root) in [
        (0x9d29, 120_000_000),
        (0x31c2, 100_000_000),
        (0xa0aa, 120_000_000),
        (0x51aa, 100_000_000),
    ] {
        for clock in [0, 1 << 1 | 2 << 16, 1 << 1 | 3 << 16] {
            let (registers, time, h) = model(device, clock);
            // SAFETY: same isolated source-register owner, stopped before attach.
            let mut spi = match unsafe { Spi::attach(registers, time, 1, 10_000) } {
                Ok(s) => s,
                Err((e, _)) => panic!("attach: {e:?}"),
            };
            let mut rx = [0xe7; 3];
            spi.message(
                pxa2xx::Device {
                    chip_select: 0,
                    mode: pxa2xx::Mode::Mode0,
                    active_high: false,
                    loopback: false,
                },
                &mut [pxa2xx::Transfer {
                    tx: Some(&[1, 2, 3]),
                    rx: Some(&mut rx),
                    words: 3,
                    bits_per_word: 8,
                    max_hz: 20_000_000,
                    delay_us: 0,
                    cs_change: false,
                    cs_change_delay_us: 0,
                }],
            )
            .unwrap();
            assert_eq!(rx, [0xa4, 0xa7, 0xa6]);
            let actual = if clock == 0 {
                root
            } else {
                root / ((clock >> 16) & 32767)
            };
            assert_eq!(
                ((h.borrow().regs[0] >> 8) & 4095) + 1,
                actual.div_ceil(20_000_000)
            );
            assert_eq!(h.borrow().regs[0x240 / 4], 0x5000_0000);
            assert_eq!(h.borrow().regs[0x244 / 4], 0x1234);
            assert_eq!(h.borrow().regs[0x220 / 4], 1);
            let writes: Vec<_> = h
                .borrow()
                .log
                .iter()
                .filter_map(|access| {
                    if let Access::Write(offset, value) = access {
                        Some((*offset, *value))
                    } else {
                        None
                    }
                })
                .collect();
            assert_eq!(
                &writes[..5],
                &[
                    (0x204, 0),
                    (0x204, 7),
                    (0x240, 0x5000_0000),
                    (0x244, 0x1234),
                    (0x220, 1)
                ]
            );
            assert!(
                h.borrow()
                    .log
                    .iter()
                    .any(|access| matches!(access, Access::Read(0x240)))
            );
            assert!(
                h.borrow()
                    .log
                    .iter()
                    .any(|access| matches!(access, Access::Read(0x244)))
            );
            let (retired, _) = spi.shutdown().unwrap();
            assert_eq!(h.borrow().regs[0x204 / 4], 0);
            assert_eq!(h.borrow().regs[0x200 / 4], clock);
            assert_eq!(h.borrow().wire, [1, 2, 3]);
            drop(retired);
            assert_eq!(h.borrow().drops, 1);
        }
    }
}
#[test]
fn each_preparation_effect_failure_preserves_original_owner_and_unmodified_boundary() {
    let (r, t, h) = model(0xa0aa, 0);
    // SAFETY: isolated real peer ownership; no prior users.
    let spi = unsafe { Spi::attach(r, t, 1, 10_000) }.ok().unwrap();
    let accesses = h.borrow().log.len();
    drop(spi);
    for ordinal in 1..=accesses {
        for after in [false, true] {
            let (r, t, h) = model(0xa0aa, 0);
            h.borrow_mut().fail = Some((ordinal, after));
            // SAFETY: same isolated model, injecting uncertain register effects.
            let (error, returned) = unsafe { Spi::attach(r, t, 1, 10_000) }.err().unwrap();
            assert!(matches!(error, Error::Platform(_) | Error::Spi(_)));
            assert_eq!(h.borrow().log.len(), ordinal);
            let modified = h
                .borrow()
                .log
                .iter()
                .any(|a| matches!(a, Access::Write(_, _)));
            if !modified {
                assert!(returned.is_some());
                drop(returned);
                assert_eq!(h.borrow().drops, 1);
            } else {
                assert!(returned.is_none());
                assert_eq!(h.borrow().drops, 0);
            }
        }
    }
}
#[test]
fn unknown_identity_caps_clock_and_bad_native_time_never_program_hardware() {
    for fault in 0..4 {
        let (r, t, h) = model(
            if fault == 0 { 0x9d60 } else { 0xa0aa },
            if fault == 2 { 32767 << 1 | 1 << 16 } else { 0 },
        );
        if fault == 1 {
            h.borrow_mut().regs[0x2fc / 4] = 0;
        }
        let result = if fault == 3 {
            // SAFETY: same peer, unusable native timer must be refused.
            unsafe {
                Spi::attach(
                    r,
                    crate::Clock {
                        ticks_per_microsecond: 0,
                    },
                    1,
                    10_000,
                )
            }
            .map(|_| ())
        } else {
            // SAFETY: same peer, unsupported observed metadata is rejected before effects.
            unsafe { Spi::attach(r, t, 1, 10_000) }.map(|_| ())
        };
        let (_, returned) = result.err().unwrap();
        assert!(returned.is_some());
        assert!(
            !h.borrow()
                .log
                .iter()
                .any(|a| matches!(a, Access::Write(_, _)))
        );
        drop(returned);
        assert_eq!(h.borrow().drops, 1);
    }
}

#[test]
fn every_shutdown_access_failure_and_refused_gate_reset_keeps_original_owners() {
    let (r, t, h) = model(0xa0aa, 1 << 1 | 2 << 16);
    // SAFETY: original isolated kept controller, no prior user.
    let spi = unsafe { Spi::attach(r, t, 1, 10_000) }.ok().unwrap();
    h.borrow_mut().log.clear();
    drop(spi.shutdown().unwrap());
    let accesses = h.borrow().log.len();
    for ordinal in 1..=accesses {
        for after in [false, true] {
            let (r, t, h) = model(0xa0aa, 1 << 1 | 2 << 16);
            // SAFETY: independent original peer, effects injected after admission.
            let spi = unsafe { Spi::attach(r, t, 1, 10_000) }.ok().unwrap();
            h.borrow_mut().log.clear();
            h.borrow_mut().fail = Some((ordinal, after));
            assert!(spi.shutdown().is_err());
            assert_eq!(h.borrow().log.len(), ordinal);
            assert_eq!(h.borrow().drops, 0);
        }
    }
    for offset in [0x200, 0x204] {
        let (r, t, h) = model(0xa0aa, 1 << 1 | 2 << 16);
        // SAFETY: same source peer and successful preparation.
        let spi = unsafe { Spi::attach(r, t, 1, 10_000) }.ok().unwrap();
        h.borrow_mut().reject = Some(offset);
        assert!(
            matches!(spi.shutdown(),Err(Error::Platform(super::super::Error::Register{offset:observed,..}))if observed==offset)
        );
        assert_eq!(h.borrow().drops, 0);
    }
}
#[test]
fn native_original_function_mapping_prepare_and_acknowledged_retirement() {
    use crate::bus::lpss::tests::{native_fixture_for, release_native, stop_fixture};
    let (function, mapping, config_counts, bar_counts) = native_fixture_for(0xa0aa);
    let pointer = mapping.address(0, 0x300).unwrap().cast::<u32>();
    // SAFETY: original owned isolated RAM mapping, no hardware/IRQ/other users.
    unsafe {
        pointer
            .as_ptr()
            .add(0x2fc / 4)
            .write_volatile(15 << 9 | 2 << 4);
        pointer
            .as_ptr()
            .add(0x200 / 4)
            .write_volatile(1 << 1 | 2 << 16);
    }
    // SAFETY: same original stopped fixture/resource and source clock epoch.
    let registers = match unsafe { NativeRegisters::claim(stop_fixture(function), mapping) } {
        Ok(registers) => registers,
        Err((error, _)) => panic!("native claim: {error:?}"),
    };
    let mut owner = match Owner::prepare(registers, 1) {
        Ok(owner) => owner,
        Err((error, _)) => panic!("native prepare: {error:?}"),
    };
    assert_eq!(owner.description.input_clock_hz, 60_000_000);
    assert_eq!(owner.read(0x204), Ok(7));
    assert_eq!(owner.read(0x200), Ok(1 << 31 | 1 << 1 | 2 << 16 | 1));
    // This concrete RAM mapping checks the native resource and
    // private reset/remap/clock accesses. RAM has no SSP FIFO/W1C semantics,
    // so no child is published here. Separate independent serial peers execute
    // the full same composed PIO engine instead of inventing RAM-side ACKs.
    let retired = owner.retire().unwrap();
    release_native(retired.into_resources(), &config_counts, &bar_counts);
}

#[test]
#[ignore = "oracle: STELA_LPSS_SPI_TRACE"]
fn unchanged_linux_spi_pci_inventory_reset_remap_and_clock_functions_match_native_owner() {
    extern crate std;
    let trace = std::fs::read_to_string(
        std::env::var("STELA_LPSS_SPI_TRACE").expect("pinned source trace"),
    )
    .unwrap();
    let mut count = 0;
    let mut profiles = 0;
    for line in trace.lines() {
        let fields: Vec<_> = line.split(',').collect();
        let num = |i: usize| fields[i].parse::<u64>().unwrap();
        match fields[0] {
            "P" => {
                let device = num(1) as u16;
                let profile = Profile::select(Identity {
                    vendor: 0x8086,
                    device,
                    subsystem_vendor: 0,
                    subsystem_device: 0,
                })
                .unwrap();
                assert_eq!(u64::from(profile.root_clock_hz()), num(2));
                assert_eq!(
                    profile.family(),
                    match num(3) {
                        14 => pxa2xx::Profile::Sunrisepoint,
                        15 => pxa2xx::Profile::Broxton,
                        16 => pxa2xx::Profile::CannonLake,
                        _ => panic!("source SSP type"),
                    }
                );
                let (r, t, h) = model(device, 0);
                // SAFETY: every source profile drives the same kept
                // private/PXA/card peer rather than gaining credit from its ID.
                let mut spi = unsafe { Spi::attach(r, t, 1, 10_000) }.ok().unwrap();
                let mut output = [0xe7];
                spi.message(
                    pxa2xx::Device {
                        chip_select: 0,
                        mode: pxa2xx::Mode::Mode0,
                        active_high: false,
                        loopback: false,
                    },
                    &mut [pxa2xx::Transfer {
                        tx: Some(&[0x71]),
                        rx: Some(&mut output),
                        words: 1,
                        bits_per_word: 8,
                        max_hz: 4_000_000,
                        delay_us: 0,
                        cs_change: false,
                        cs_change_delay_us: 0,
                    }],
                )
                .unwrap();
                assert_eq!(output, [0xd4]);
                assert_eq!(h.borrow().wire, [0x71]);
                drop(spi.shutdown().unwrap());
                assert_eq!(h.borrow().drops, 1);
                profiles += 1;
            }
            "R" => {
                let (r, _, h) = model(0xa0aa, 0);
                {
                    let mut h = h.borrow_mut();
                    h.base = num(2);
                    h.regs[0x2fc / 4] |= if num(1) != 0 { 1 << 8 } else { 0 };
                }
                let owner = Owner::prepare(r, 1).ok().unwrap();
                let expected: Vec<_> = fields[3..]
                    .iter()
                    .map(|pair| {
                        let (at, value) = pair.split_once(':').unwrap();
                        (at.parse::<usize>().unwrap(), value.parse::<u32>().unwrap())
                    })
                    .collect();
                let actual: Vec<_> = h
                    .borrow()
                    .log
                    .iter()
                    .filter_map(|access| {
                        if let Access::Write(at, value) = access {
                            Some((*at, *value))
                        } else {
                            None
                        }
                    })
                    .take(expected.len())
                    .collect();
                assert_eq!(actual, expected);
                drop(owner.retire().unwrap());
                assert_eq!(h.borrow().drops, 1);
            }
            "C" => {
                let (r, _, h) = model(
                    if num(1) == 100_000_000 {
                        0x31c2
                    } else {
                        0xa0aa
                    },
                    num(2) as u32,
                );
                let owner = Owner::prepare(r, 1);
                if num(3) > u64::from(u32::MAX) {
                    let (error, returned) = owner.err().unwrap();
                    assert_eq!(error, Error::Configuration);
                    assert!(returned.is_some());
                    drop(returned);
                    assert_eq!(h.borrow().drops, 1);
                } else {
                    let owner = owner.ok().unwrap();
                    assert_eq!(u64::from(owner.description.input_clock_hz), num(3));
                    let on: Vec<_> = h
                        .borrow()
                        .log
                        .iter()
                        .filter_map(|access| {
                            if let Access::Write(0x200, value) = access {
                                Some(u64::from(*value))
                            } else {
                                None
                            }
                        })
                        .collect();
                    assert_eq!(on, [num(4), num(5)]);
                    drop(owner.retire().unwrap());
                    let all: Vec<_> = h
                        .borrow()
                        .log
                        .iter()
                        .filter_map(|access| {
                            if let Access::Write(0x200, value) = access {
                                Some(u64::from(*value))
                            } else {
                                None
                            }
                        })
                        .collect();
                    assert_eq!(&all[2..], &[num(6), num(7)]);
                    assert_eq!(h.borrow().drops, 1);
                }
            }
            _ => panic!("unknown source record"),
        }
        count += 1;
    }
    assert_eq!(profiles, 95);
    assert_eq!(count, 143);
}
