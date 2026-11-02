// SPDX-License-Identifier: GPL-2.0-only
extern crate std;
use super::*;
use alloc::{sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Mutex,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Effect {
    Read(u32),
    Write(u32, u32),
}
struct State {
    effects: Vec<Effect>,
    mask: u32,
    host: u32,
    gate: u32,
    dma: u32,
    idle_after: usize,
    reads: usize,
    fault: usize,
    accesses: usize,
    panic_gate: bool,
    sentinel: Option<u32>,
    backing: Vec<u8>,
    fw_read_delay: u64,
}
struct Model {
    state: Arc<Mutex<State>>,
    now: Arc<AtomicU64>,
}
struct Clock(Arc<AtomicU64>);
// SAFETY: the monotonic model clock advances for every operation and spin observation.
unsafe impl Time for Clock {
    fn now_us(&self) -> u64 {
        self.0.fetch_add(100, Ordering::Relaxed)
    }
}
impl Model {
    fn access(&self, effect: Effect) -> Result<()> {
        self.now.fetch_add(20, Ordering::Relaxed);
        let mut s = self.state.lock().unwrap();
        s.effects.push(effect);
        s.accesses += 1;
        if s.accesses == s.fault {
            Err(super::super::Error::Access(match effect {
                Effect::Read(at) | Effect::Write(at, _) => at,
            }))
        } else {
            Ok(())
        }
    }
}
// SAFETY: serial isolated BAR peer, no native hardware or reset/assignment alias.
unsafe impl Registers for Model {
    fn span(&self) -> crate::bus::mmio::owned::PhysicalSpan {
        crate::bus::mmio::owned::PhysicalSpan::new(0x1_9000_0000, 0x400).unwrap()
    }
    fn read32(&self, at: u32) -> Result<u32> {
        self.access(Effect::Read(at))?;
        let mut s = self.state.lock().unwrap();
        if at == FWSTS {
            self.now.fetch_add(s.fw_read_delay, Ordering::Relaxed);
        }
        if s.sentinel == Some(at) {
            return Ok(u32::MAX);
        }
        Ok(match at {
            PIMR => s.mask,
            HOST_COMM => s.host,
            RMP2 => s.gate,
            FWSTS => {
                s.reads += 1;
                if s.reads >= s.idle_after {
                    s.dma = 0;
                }
                s.dma | 3
            }
            _ => panic!("cold stop touched protocol mailbox {at:x}"),
        })
    }
    fn write32(&self, at: u32, value: u32) -> Result<()> {
        self.access(Effect::Write(at, value))?;
        let mut s = self.state.lock().unwrap();
        match at {
            PIMR => s.mask = value,
            HOST_COMM => s.host = value,
            RMP2 => {
                s.gate = value;
                if s.panic_gate {
                    drop(s);
                    panic!("uncertain DMA gate publication");
                }
            }
            _ => panic!("cold stop touched protocol mailbox {at:x}"),
        }
        Ok(())
    }
}
fn fixture(dma: u32) -> (Model, Clock, Arc<Mutex<State>>) {
    let state = Arc::new(Mutex::new(State {
        effects: Vec::new(),
        mask: 0x8101,
        host: 0x185,
        gate: 1,
        dma,
        idle_after: 3,
        reads: 0,
        fault: usize::MAX,
        accesses: 0,
        panic_gate: false,
        sentinel: None,
        backing: vec![0x6d; 16384],
        fw_read_delay: 0,
    }));
    let now = Arc::new(AtomicU64::new(0));
    (
        Model {
            state: state.clone(),
            now: now.clone(),
        },
        Clock(now),
        state,
    )
}
#[test]
fn all_inherited_dma_channels_idle_under_original_gate_without_mailbox_or_buffer_effects() {
    for dma in [1 << 16, 1 << 17, 1 << 18, 1 << 19, IN_DMA] {
        let (r, t, s) = fixture(dma);
        StopAttempt::new().stop(&r, &t).unwrap();
        let s = s.lock().unwrap();
        assert_eq!((s.mask, s.host, s.gate, s.dma), (0x8000, 0x105, 0, 0));
        assert_eq!(s.backing, vec![0x6d; 16384]);
        assert_eq!(
            s.effects
                .iter()
                .filter(|e| matches!(e, Effect::Write(..)))
                .copied()
                .collect::<Vec<_>>(),
            vec![
                Effect::Write(PIMR, 0x8000),
                Effect::Write(HOST_COMM, 0x105),
                Effect::Write(RMP2, 0)
            ]
        );
        assert!(s.reads >= 3);
    }
}
#[test]
fn already_clear_host_ready_stays_clear_and_no_xor_reopens_firmware() {
    let (r, t, s) = fixture(0);
    s.lock().unwrap().host = 0x105;
    StopAttempt::new().stop(&r, &t).unwrap();
    assert_eq!(s.lock().unwrap().host, 0x105);
}
#[test]
fn dma_zero_observed_after_deadline_and_unrepresentable_deadline_are_refused() {
    let (r, t, s) = fixture(IN_DMA);
    {
        let mut state = s.lock().unwrap();
        state.idle_after = 1;
        state.fw_read_delay = 20_001;
    }
    assert_eq!(
        StopAttempt::new().stop(&r, &t).err(),
        Some(super::super::Error::Timeout("inherited DMA inactive"))
    );
    let (r, t, s) = fixture(IN_DMA);
    t.0.store(u64::MAX - 100, Ordering::Relaxed);
    assert_eq!(
        StopAttempt::new().stop(&r, &t).err(),
        Some(super::super::Error::Requirement(
            "bounded original ISH clock"
        ))
    );
    assert!(s.lock().unwrap().effects.is_empty());
}
#[test]
fn no_dma_ack_and_removed_registers_are_terminal_not_config_only_quiescence() {
    let (r, t, s) = fixture(IN_DMA);
    s.lock().unwrap().idle_after = usize::MAX;
    let mut a = StopAttempt::new();
    let error = a.stop(&r, &t).err().unwrap();
    assert_eq!(
        error,
        super::super::Error::Timeout("inherited DMA inactive")
    );
    let effects = s.lock().unwrap().effects.clone();
    assert_eq!(a.stop(&r, &t).err(), Some(error));
    assert_eq!(s.lock().unwrap().effects, effects);
    for at in [PIMR, HOST_COMM, RMP2, FWSTS] {
        let (r, t, s) = fixture(IN_DMA);
        s.lock().unwrap().sentinel = Some(at);
        assert_eq!(
            StopAttempt::new().stop(&r, &t).err(),
            Some(super::super::Error::Removed)
        );
    }
}
#[test]
fn every_register_failure_and_caught_gate_unwind_close_admission_without_retry_or_drop_effects() {
    let (r, t, s) = fixture(IN_DMA);
    StopAttempt::new().stop(&r, &t).unwrap();
    let accesses = s.lock().unwrap().accesses;
    for fault in 1..=accesses {
        let (r, t, s) = fixture(IN_DMA);
        s.lock().unwrap().fault = fault;
        let mut a = StopAttempt::new();
        let error = a.stop(&r, &t).err().unwrap();
        let effects = s.lock().unwrap().effects.clone();
        assert_eq!(a.stop(&r, &t).err(), Some(error));

        assert_eq!(s.lock().unwrap().effects, effects);
        assert_eq!(s.lock().unwrap().backing, vec![0x6d; 16384]);
    }
    let (r, t, s) = fixture(IN_DMA);
    s.lock().unwrap().panic_gate = true;
    let mut a = StopAttempt::new();
    assert!(catch_unwind(AssertUnwindSafe(|| a.stop(&r, &t))).is_err());
    let effects = s.lock().unwrap().effects.clone();
    assert_eq!(a.stop(&r, &t).err(), Some(super::super::Error::Terminal));

    assert_eq!(s.lock().unwrap().effects, effects);
    assert_eq!(s.lock().unwrap().backing, vec![0x6d; 16384]);
}
struct OriginalRoot(Arc<core::sync::atomic::AtomicUsize>);
impl Drop for OriginalRoot {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: explicit isolated original-root peer. No drain/bind receipt exists;
// invoking either is a failure of the tested admission boundary.
unsafe impl crate::bus::pci::requester::preparation::Root for OriginalRoot {
    fn drain(&self) -> core::result::Result<(), crate::bus::dma::mapping::DmaError> {
        panic!("no original root receipt")
    }
    unsafe fn bind(
        &self,
        _: crate::bus::pci::requester::RequesterBinding,
    ) -> core::result::Result<
        alloc::boxed::Box<dyn crate::bus::pci::requester::preparation::AttachmentBackend>,
        crate::bus::dma::mapping::DmaError,
    > {
        panic!("no private bind before reset/notification prerequisites")
    }
}
#[test]
fn actual_original_config_root_and_register_graph_survives_active_drop_failure_and_unwind() {
    use crate::bus::pci::{
        Address, ConfigSpace, Function,
        owned::test_support::fixture as config_fixture,
        requester::{FunctionRole, preparation::PreparingRequester},
    };
    use alloc::boxed::Box;
    use core::sync::atomic::AtomicUsize;
    for mode in 0..5 {
        let address = Address {
            segment: 0x4567,
            bus: 0xb3,
            device: 3,
            function: 6,
        };
        let (mut config, counters) = config_fixture(address);
        config.write32(0, 0x9d35_8086).unwrap();
        config.write32(8, 0x1180_0001).unwrap();
        config.write16(4, 0x402).unwrap();
        config.write32(0x10, 0x9000_0004).unwrap();
        config.write32(0x14, 1).unwrap();
        let function = Function::new(address, config).unwrap();
        let roots = Arc::new(AtomicUsize::new(0));
        // SAFETY: isolated actual config allocation paired with original root.
        let requester = match unsafe {
            PreparingRequester::new(
                function,
                FunctionRole::Physical,
                Box::new(OriginalRoot(roots.clone())),
            )
        } {
            Ok(r) => r,
            Err(_) => panic!("original model requester"),
        };
        let (r, t, s) = fixture(IN_DMA);
        if mode == 2 {
            s.lock().unwrap().fault = 1;
        }
        if mode == 3 {
            s.lock().unwrap().panic_gate = true;
        }
        if mode == 4 {
            counters.fail_context_at.store(
                counters.contexts.load(Ordering::Relaxed) + 1,
                Ordering::Relaxed,
            );
        }
        // SAFETY: exclusive register peer models the same symbolic original BAR.
        let mut original = unsafe { native::Original::new(requester, r, t) };
        if mode != 0 {
            let result = catch_unwind(AssertUnwindSafe(|| original.prepare()));
            if mode == 1 {
                assert_eq!(result.unwrap(), Ok(()));
            } else if mode == 2 {
                assert!(result.unwrap().is_err());
            } else if mode == 4 {
                let error = native::Error::Controller(crate::input::ish::Error::ConfigAccess(
                    crate::bus::pci::ConfigError::before_effect(
                        crate::bus::pci::ConfigFailure::Mapping(
                            crate::bus::mmio::owned::Error::Unavailable,
                        ),
                    ),
                ));
                assert_eq!(result.unwrap(), Err(error.clone()));
                assert_eq!(original.prepare(), Err(error));
                assert!(s.lock().unwrap().effects.is_empty());
            } else {
                assert!(result.is_err());
            }
            let effects = s.lock().unwrap().effects.clone();
            assert!(original.prepare().is_err());
            assert_eq!(s.lock().unwrap().effects, effects);
        }
        drop(original);
        assert_eq!(roots.load(Ordering::Relaxed), 0);
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
        assert_eq!(
            Arc::strong_count(&s),
            2,
            "original register owner must remain kept"
        );
        assert_eq!(s.lock().unwrap().backing, vec![0x6d; 16384]);
    }
}
