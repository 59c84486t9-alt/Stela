extern crate std;
use super::*;
use crate::bus::dma::{RegionAllocator, TestRegion};

#[test]
fn only_intel_controllers_settle_after_reset() {
    assert_eq!(
        Profile::pci(INTEL, 0xa36d).reset_settle_us(),
        INTEL_RESET_SETTLE_US
    );
    assert_eq!(Profile::pci(0x1022, 0x15b6).reset_settle_us(), 0);
    // Vendor quirks combine: an aperture limit keeps its own settle rule.
    let asmedia = Profile::pci(0x1b21, 0x1242);
    assert_eq!((asmedia.bits, asmedia.reset_settle_us()), (32, 0));
}

#[derive(Default)]
struct State {
    running: bool,
    ac64: bool,
    writes: Vec<(usize, u32)>,
    size: Option<usize>,
    /// xECP, in dwords.
    extended: u32,
}
struct RegistersModel(Rc<RefCell<State>>);
impl Registers for RegistersModel {
    fn read32(&mut self, at: usize) -> u32 {
        let state = self.0.borrow();
        match at {
            0 => 0x0110_0040,
            HCSPARAMS1 => 1 << 24 | 8,
            HCSPARAMS2 => 2 << 27,
            HCCPARAMS1 => u32::from(state.ac64) | 2 << 12 | state.extended << 16,
            DBOFF => 0x1000,
            RTSOFF => 0x800,
            0x44 => {
                if state.running {
                    0
                } else {
                    HCH
                }
            }
            0x40 => {
                if state.running {
                    RUN
                } else {
                    0
                }
            }
            0x48 => 1,
            _ => 0,
        }
    }
    fn write32(&mut self, at: usize, value: u32) {
        let mut state = self.0.borrow_mut();
        state.writes.push((at, value));
        if at == 0x40 {
            state.running = value & RUN != 0;
        }
    }
    fn size(&self) -> Option<usize> {
        self.0.borrow().size
    }
}

struct Allocator<'a> {
    inner: &'a mut dyn DmaAllocator,
    requests: Vec<(usize, usize, u64)>,
    fail: Option<usize>,
}
impl DmaAllocator for Allocator<'_> {
    fn allocate(&mut self, bytes: usize, align: usize) -> Result<DmaBuffer, BlockError> {
        if self.fail == Some(self.requests.len()) {
            return Err(BlockError::NoDmaMemory);
        }
        let buffer = self.inner.allocate(bytes, align)?;
        self.requests.push((bytes, align, buffer.physical()));
        Ok(buffer)
    }
}

fn clock() -> Clock {
    Clock {
        ticks_per_microsecond: 1,
    }
}

#[test]
fn register_offsets_outside_the_bar_refuse_the_controller() {
    let mut dma = TestRegion::new(64 * 1024 * 8);
    // Doorbells for eight slots end at 0x1024; xECP 0x800 is at 0x2000.
    for (size, extended, fits) in [
        (0x1024, 0, true),
        (0x1020, 0, false),
        (0x1024, 0x800, false),
        (0x2004, 0x800, true),
    ] {
        let state = Rc::new(RefCell::new(State {
            ac64: true,
            size: Some(size),
            extended,
            ..State::default()
        }));
        let registers = Box::new(RegistersModel(state.clone()));
        let result = Controller::new(
            registers,
            clock(),
            &mut dma,
            String::from("bar"),
            crate::minimum_model::owned(clock()),
        );
        assert_eq!(result.is_ok(), fits, "{size:#x} {extended:#x}");
        if !fits {
            assert!(state.borrow().writes.is_empty());
        }
    }
}

#[test]
fn constructor_pads_command_and_event_segments_without_extra_trbs() {
    for overfetch in [false, true] {
        let mut region = TestRegion::new(64 * 1024 * 8);
        let mut dma = Allocator {
            inner: &mut region,
            requests: Vec::new(),
            fail: None,
        };
        let state = Rc::new(RefCell::new(State {
            ac64: true,
            ..State::default()
        }));
        let registers = Box::new(RegistersModel(state.clone()));
        let controller = if overfetch {
            Controller::with_dma_profile(
                registers,
                clock(),
                &mut dma,
                String::from("overfetch"),
                Profile::pci(0x1d17, 0x9202),
                crate::usb::xhci::minimum::fixture(clock()),
            )
            .unwrap()
        } else {
            Controller::new(
                registers,
                clock(),
                &mut dma,
                String::from("ordinary"),
                crate::minimum_model::owned(clock()),
            )
            .unwrap()
        };
        let segment = if overfetch { 8192 } else { 4096 };
        assert_eq!(
            dma.requests.iter().map(|r| (r.0, r.1)).collect::<Vec<_>>(),
            [
                (72, 64),
                (16, 64),
                (4096, 4096),
                (4096, 4096),
                (segment, segment),
                (segment, segment),
                (16, 64)
            ]
        );
        assert_eq!(controller.commands.buffer.len(), segment);
        assert_eq!(controller.events.len(), segment);
        assert!(
            controller.commands.buffer.bytes()[4096..]
                .iter()
                .all(|b| *b == 0)
        );
        assert!(controller.events.bytes().iter().all(|b| *b == 0));
        assert_eq!(
            controller
                .commands
                .buffer
                .read::<u64>((RING_TRBS - 1) * TRB),
            controller.commands.buffer.physical()
        );
        assert_eq!(controller._event_table.read::<u32>(8), 256);
        assert_eq!(controller.dma_profile.overfetch, overfetch);
        assert!(state.borrow().running);
        assert!(dma.requests.iter().all(|(bytes, align, address)| {
            address.is_multiple_of(*align as u64)
                && controller.dma_profile.check(*address, *bytes).is_ok()
        }));
    }
}

#[test]
fn every_initial_allocation_failure_precedes_all_pointer_publication_and_run() {
    for overfetch in [false, true] {
        for fail in 0..7 {
            let mut region = TestRegion::new(64 * 1024 * 8);
            let mut dma = Allocator {
                inner: &mut region,
                requests: Vec::new(),
                fail: Some(fail),
            };
            let state = Rc::new(RefCell::new(State {
                ac64: true,
                ..State::default()
            }));
            assert!(matches!(
                Controller::with_dma_profile(
                    Box::new(RegistersModel(state.clone())),
                    clock(),
                    &mut dma,
                    String::new(),
                    Profile {
                        overfetch,
                        ..Profile::SPEC
                    },
                    crate::usb::xhci::minimum::fixture(clock())
                ),
                Err(BlockError::NoDmaMemory)
            ));
            assert_eq!(dma.requests.len(), fail);
            let state = state.borrow();
            assert!(!state.running);
            assert!(state.writes.iter().all(|(at, _)| {
                ![
                    0x40 + DCBAAP,
                    0x40 + DCBAAP + 4,
                    0x40 + CRCR,
                    0x40 + CRCR + 4,
                    0x800 + ERDP,
                    0x800 + ERDP + 4,
                    0x800 + ERSTBA,
                    0x800 + ERSTBA + 4,
                ]
                .contains(at)
            }));
        }
    }
}

#[test]
fn controller_applies_ac64_and_pci_masks_before_pointer_publication() {
    for (ac64, profile) in [
        (false, Profile::SPEC),
        (true, Profile::pci(0x1b21, 0x3242)),
        (true, Profile::pci(0x1106, 0x3483)),
    ] {
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // A hosted identity pointer lies beyond these apertures;
        // keep this conditional for unusual low-address test processes.
        if start < 1 << 36 {
            continue;
        }
        // SAFETY: exclusive test backing outlives every attempted allocation.
        let mut region = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let state = Rc::new(RefCell::new(State {
            ac64,
            ..State::default()
        }));
        assert!(
            Controller::with_dma_profile(
                Box::new(RegistersModel(state.clone())),
                clock(),
                &mut region,
                String::new(),
                profile,
                crate::usb::xhci::minimum::fixture(clock())
            )
            .is_err()
        );
        let state = state.borrow();
        assert!(!state.running);
        assert!(
            state
                .writes
                .iter()
                .all(|(at, _)| *at == 0x40 || *at == 0x40 + CONFIG)
        );
    }
}

#[test]
fn pci_profiles_match_exact_aperture_and_segment_quirks() {
    for (vendor, device, bits, overfetch) in [
        (0x1b21, 0x1142, 32, false),
        (0x1b21, 0x1242, 32, false),
        (0x1b21, 0x2142, 32, false),
        (0x1b21, 0x3242, 32, false),
        (0x1106, 0x3483, 36, true),
        (0x1d17, 0x9202, 64, true),
        (0x1d17, 0x9203, 64, true),
        (0x8086, 0x1e31, 64, false),
        (0x1b21, 0x1042, 64, false),
        (0x1106, 0x3432, 64, false),
        (0x17cd, 0x0200, 64, false),
        (0x1b21, 0x3042, 64, false),
        (0xffff, 0x3483, 64, false),
        (0x1d17, 0x9201, 64, false),
    ] {
        let profile = Profile::pci(vendor, device);
        assert_eq!((profile.bits, profile.overfetch), (bits, overfetch));
        assert_eq!(profile.segment_bytes(), if overfetch { 8192 } else { 4096 });
        assert_eq!(profile.capabilities(false).bits, 32);
        assert_eq!(profile.capabilities(true), profile);
    }
}

#[test]
fn complete_extents_cannot_wrap_or_cross_apertures() {
    for bits in [32, 36, 64] {
        let profile = Profile {
            bits,
            ..Profile::SPEC
        };
        let maximum = if bits == 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        assert!(profile.check(maximum - 4095, 4096).is_ok());
        assert!(profile.check(maximum - 4094, 4096).is_err());
        assert!(profile.check(maximum, 1).is_ok());
        assert!(profile.check(maximum, 0).is_ok());
        assert!(profile.check(maximum, 2).is_err());
        assert!(profile.check(0, 4096).is_ok());
        if bits != 64 {
            assert!(profile.check(maximum + 1, 0).is_err());
        }
    }
    assert!(Profile::SPEC.check(u64::MAX - 7, 16).is_err());
}

#[test]
#[ignore = "oracle: STELA_XHCI_DMA_ORACLE"]
fn unchanged_linux_pci_mask_and_segment_branches_match_every_profile() {
    use sha2::{Digest, Sha256};
    let path = std::env::var("STELA_XHCI_DMA_ORACLE").expect("set STELA_XHCI_DMA_ORACLE");
    let raw = std::fs::read(path).unwrap();
    assert_eq!(raw.len(), 3704);
    assert_eq!(
        format!("{:x}", Sha256::digest(&raw)),
        "ddb6d37cc2cdb7320c8730ead3ed8f63c5bf34ba37ea3eb5f3eb87c4c775e30c"
    );
    let mut count = 0;
    for line in std::str::from_utf8(&raw).unwrap().lines() {
        let row: Vec<u64> = line
            .split_whitespace()
            .map(|v| v.parse().unwrap())
            .collect();
        assert_eq!(row.len(), 8);
        let profile = Profile::pci(row[0] as u16, row[1] as u16).capabilities(row[2] != 0);
        assert_eq!(u64::from(profile.bits), row[3]);
        assert_eq!(u64::from(profile.bits), row[4]);
        assert_eq!(profile.segment_bytes() as u64, row[5]);
        assert_eq!(profile.segment_bytes() as u64, row[6]);
        // The pinned backend's 4 KiB page is our explicitly required size.
        assert_eq!(profile.segment_bytes() as u64, row[7]);
        count += 1;
    }
    assert_eq!(count, 110);
}
