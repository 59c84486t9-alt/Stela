//! Private AHCI model time, transition order and actual retained-object checks.
use super::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
extern crate std;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn timing() -> BlockError {
    BlockError::PciPower(crate::bus::pci::power::Error::Clock)
}

/// Raw AHCI register fixture deliberately reports DET ready immediately. The
/// actual constructor must finish its physical resume minimum before it can
/// request even its first DMA allocation.
#[test]
fn initial_constructor_waits_for_resume_before_setup_and_keeps_failed_port() {
    struct AllocationBoundary {
        timer: Rc<MinimumModel>,
        calls: usize,
    }
    impl DmaAllocator for AllocationBoundary {
        fn allocate(&mut self, _: usize, _: usize) -> Result<DmaBuffer, BlockError> {
            self.calls += 1;
            assert!(self.timer.now.get() >= COMRESET_HOLD_US + RESUME_SETTLE_US);
            Err(BlockError::Protocol("constructor allocation boundary"))
        }
    }
    for fail_resume in [false, true] {
        let _clock = crate::test_clock::virtualize();
        let timer = Rc::new(MinimumModel::default());
        if fail_resume {
            timer.fail_wait.set(Some(2));
        }
        let control = Control::model(timer.clone());
        let mut registers = Box::new([0u32; 32]);
        registers[PORT_SATA_STATUS / 4] = DEVICE_PRESENT;
        registers[PORT_SIGNATURE / 4] = SIGNATURE_ATA;
        // SAFETY: this isolated device-model allocation outlives the call and
        // inspection. No hardware, native timing service or factory is used.
        let port = unsafe { Mmio::new(registers.as_mut_ptr() as u64) };
        let mut dma = AllocationBoundary {
            timer: timer.clone(),
            calls: 0,
        };
        let owner = Rc::downgrade(&control);
        {
            let result = AhciDisk::start(
                port,
                CAP_64BIT,
                0,
                Clock {
                    ticks_per_microsecond: 1,
                },
                &mut dma,
                control.clone(),
            );
            let Err(refusal) = result else {
                panic!("allocation boundary must refuse");
            };
            assert_eq!(
                &*timer.waits.borrow(),
                &[COMRESET_HOLD_US, RESUME_SETTLE_US]
            );
            assert_eq!(
                registers[PORT_COMMAND / 4] & (COMMAND_START | COMMAND_FIS_RECEIVE),
                0
            );
            if fail_resume {
                assert_eq!(refusal.error, timing());
                assert_eq!(dma.calls, 0);
                assert_eq!(control.ready(), Err(timing()));
            } else {
                assert_eq!(
                    refusal.error,
                    BlockError::Protocol("constructor allocation boundary")
                );
                assert_eq!(dma.calls, 1);
            }
        }
        drop(control);
        assert!(owner.upgrade().is_some());
    }
}
#[test]
fn comreset_and_resume_use_the_same_real_model_minima() {
    let _clock = crate::test_clock::virtualize();
    let timer = Rc::new(MinimumModel::default());
    let mut fixture = Fixture::with_control(0, Control::model(timer.clone()));
    fixture.disk.clock = Clock {
        ticks_per_microsecond: 1,
    };
    let link = Link::new(&[]);
    assert_eq!(fixture.disk.hardreset(&link, 10_000_000, false), Ok(true));
    let waits = timer.waits.borrow();
    assert_eq!(waits[0], COMRESET_HOLD_US);
    assert_eq!(waits[1], RESUME_SETTLE_US);
    assert!(waits[2..].iter().all(|us| *us == DEBOUNCE_NORMAL[0]));
    assert!(waits[2..].iter().sum::<u64>() > DEBOUNCE_NORMAL[1]);
    assert!(timer.now.get() >= COMRESET_HOLD_US + RESUME_SETTLE_US + DEBOUNCE_NORMAL[1]);
}
#[test]
fn failed_hold_or_resume_never_deasserts_early_restarts_or_retries() {
    for ordinal in [1, 2] {
        let _clock = crate::test_clock::virtualize();
        let timer = Rc::new(MinimumModel::default());
        timer.fail_wait.set(Some(ordinal));
        let control = Control::model(timer.clone());
        let mut fixture = Fixture::with_control(0, control.clone());
        fixture.disk.clock = Clock {
            ticks_per_microsecond: 1,
        };
        let link = Link::new(&[]);
        assert_eq!(
            fixture.disk.hardreset(&link, 10_000_000, false),
            Err(timing())
        );
        let controls = link.writes_to(PORT_SATA_CONTROL);
        if ordinal == 1 {
            assert_eq!(controls, vec![SATA_CONTROL_COMRESET]);
        } else {
            assert_eq!(controls, vec![SATA_CONTROL_COMRESET, SATA_CONTROL_RESUMED]);
        }
        assert!(
            !link
                .writes_to(PORT_COMMAND)
                .iter()
                .any(|v| v & COMMAND_START != 0)
        );
        let before = (link.reads.get(), link.writes.borrow().len());
        assert_eq!(
            fixture
                .disk
                .reconfigure(&link, true, false, BlockError::Timeout, DEVICE_TRIES),
            Err(timing())
        );
        assert_eq!(fixture.disk.apply_lpm(&link, LPM_MAX_POWER), Err(timing()));
        assert_eq!((link.reads.get(), link.writes.borrow().len()), before);
        assert!(!fixture.disk.room());
        assert_eq!(fixture.disk.depth(), 0);
        // Same controller timing failure also refuses another port's hardware.
        let mut peer = Fixture::with_control(0, control);
        assert_eq!(peer.disk.hardreset(&link, 10_000_000, false), Err(timing()));
        assert_eq!((link.reads.get(), link.writes.borrow().len()), before);
    }
}
#[test]
fn failed_precheck_prevents_the_minimum_transition_and_lpm_followup() {
    let timer = Rc::new(MinimumModel::default());
    timer.fail_check.set(Some(2));
    let mut fixture = Fixture::with_control(0, Control::model(timer.clone()));
    let link = Link::new(&[]);
    assert_eq!(
        fixture.disk.hardreset(&link, 10_000_000, false),
        Err(timing())
    );
    assert!(link.writes_to(PORT_SATA_CONTROL).is_empty());
    assert!(timer.waits.borrow().is_empty());
    let timer = Rc::new(MinimumModel::default());
    timer.fail_wait.set(Some(1));
    let mut fixture = Fixture::with_control(0, Control::model(timer));
    fixture.disk.lpm.capabilities = CAP_AGGRESSIVE_LPM;
    let link = Link::new(&[]);
    assert_eq!(fixture.disk.apply_lpm(&link, LPM_MAX_POWER), Err(timing()));
    assert!(!link.writes_to(PORT_COMMAND).is_empty());
    assert!(link.writes_to(PORT_DEVICE_SLEEP).is_empty());
    assert!(link.writes_to(PORT_SATA_CONTROL).is_empty());
}

struct OwnedBytes {
    _bytes: Box<[u8; 4096]>,
    dropped: Arc<AtomicUsize>,
}
#[test]
fn healthy_unexposed_resource_release_is_observable() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let timer = Rc::new(MinimumModel::default());
    let control = Control::model(timer.clone());
    let observer = Rc::downgrade(&timer);
    let resource = DmaResource::new(
        OwnedBytes {
            _bytes: Box::new([0; 4096]),
            dropped: dropped.clone(),
        },
        control.clone(),
        Rc::new(Cell::new(false)),
    );
    drop(resource);
    drop(control);
    drop(timer);
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
    assert!(observer.upgrade().is_none());
}
impl Drop for OwnedBytes {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}
#[test]
fn failure_and_callback_unwind_keep_actual_allocations_and_controller_timer() {
    for unwind in [false, true] {
        let dropped = Arc::new(AtomicUsize::new(0));
        let timer = Rc::new(MinimumModel::default());
        if unwind {
            timer.panic_wait.set(Some(1));
        } else {
            timer.fail_wait.set(Some(1));
        }
        let observer = Rc::downgrade(&timer);
        let control = Control::model(timer);
        let resource = DmaResource::new(
            OwnedBytes {
                _bytes: Box::new([0; 4096]),
                dropped: dropped.clone(),
            },
            control.clone(),
            Rc::new(Cell::new(false)),
        );
        if unwind {
            assert!(catch_unwind(AssertUnwindSafe(|| control.wait_after(1000, || {}))).is_err());
            assert_eq!(
                control.ready(),
                Err(BlockError::PciPower(
                    crate::bus::pci::power::Error::Interrupted
                ))
            );
        } else {
            assert_eq!(control.wait_after(1000, || {}), Err(timing()));
        }
        drop(resource);
        drop(control);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        assert!(observer.upgrade().is_some());
    }
}
#[test]
fn whole_controller_refusal_keeps_prior_disks_and_partial_port() {
    let timer = Rc::new(MinimumModel::default());
    let control = Control::model(timer.clone());
    let observer = Rc::downgrade(&timer);
    let owner = Rc::downgrade(&control);
    let fixture = Fixture::with_control(0, control.clone());
    let Fixture {
        disk,
        _registers,
        _memory,
    } = fixture;
    let port = disk.port;
    {
        let partial = minimum::PortRefusal::new(
            timing(),
            crate::Retained::new(Box::new(minimum::PortBuild {
                owner: control.clone(),
                port,
                commands: None,
                table: None,
                bounce: None,
                disk: None,
            })),
        );
        let failure = AttachRefusal::new(
            timing(),
            crate::Retained::new(Box::new(minimum::Build {
                host: Host {
                    control: control.clone(),
                    retained_ports: vec![partial],
                },
                hba: Some(port),
                disks: vec![disk],
                failures: Vec::new(),
            })),
        );
        assert_eq!(failure.error, timing());
    }
    drop(control);
    drop(timer);
    assert!(observer.upgrade().is_some() && owner.upgrade().is_some());
    // Those fixture backing objects are still held throughout this observation;
    // the carrier owns the actual disk/partial state, not just its error label.
    assert!(!_registers.is_empty() && !_memory.is_empty());
}
