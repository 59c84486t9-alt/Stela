// SPDX-License-Identifier: GPL-2.0-only
//! Shared Renoir PDM register, DMA and clock fixtures.
extern crate std;
use super::super::{PcmFormat, acp_pdm::check_dma_range};
use super::*;
use crate::audio::acp_pdm::test_support::Source;
use crate::bus::dma::{
    mapping::{Direction as DmaDirection, DmaError, DomainMapping},
    memory::{CacheAttribute, CpuMapping},
    pages::DmaPages,
};
use alloc::vec::Vec;
use core::{
    ops::Range,
    sync::atomic::{AtomicU64, Ordering},
};
use std::sync::Mutex;

const IOVA: u64 = 0x1_8000_0000;
/// The revisions this profile admits; single-revision cases use the first.
const REVISIONS: &[u8] = &[1];
const REVISION: u8 = REVISIONS[0];
struct Translation {
    token: DomainMapping,
    cpu: CpuMapping,
    pages: DmaPages,
}
struct Device {
    words: Vec<u32>,
    identity: Identity,
    master: bool,
    count: u64,
    cursor: usize,
    frames: u64,
    translation: Option<Translation>,
    atu_readback: u32,
    atu_reads: usize,
    resets: usize,
    published_reset: Option<usize>,
    maps: usize,
    unmaps: usize,
    cpu_syncs: usize,
    device_syncs: usize,
    device_owns: bool,
    start_never: bool,
    stop_never: bool,
    reset_never: bool,
    power_never: bool,
    power_off_never: bool,
    unmap_fail: bool,
    sync_fail: bool,
    drain_fail: bool,
    drain_unavailable: bool,
    drains: usize,
    coherent_reads: usize,
    coherence_unavailable: bool,
    advance_on_coherent: Option<(usize, usize)>,
    accesses: Vec<(usize, bool)>,
    defer_payload: bool,
    posted: Vec<(usize, i32)>,
    lost_read: Option<usize>,
    fail_after_write: Option<usize>,
    ignore_write: Option<usize>,
    rollover: bool,
    unstable: bool,
    writes: Vec<(usize, u32)>,
    clock: Arc<AtomicU64>,
    jump_write: Option<(usize, u32, u64)>,
    jump_read: Option<(usize, u32, u64)>,
}

fn sample(frame: u64, channel: usize) -> i32 {
    (frame.wrapping_mul(101) as i32)
        ^ if channel == 0 {
            0x1234_5600
        } else {
            -0x2345_6700
        }
}
struct Model(Arc<Mutex<Device>>);
impl Registers for Model {
    fn region_bytes(&self) -> usize {
        0x11000
    }
    fn identity(&mut self) -> Result<Identity, Error> {
        Ok(self.0.lock().unwrap().identity)
    }
    fn set_bus_master(&mut self, enabled: bool) -> Result<(), Error> {
        self.0.lock().unwrap().master = enabled;
        Ok(())
    }
    fn read32(&mut self, offset: usize) -> u32 {
        self.0.lock().unwrap().read(offset)
    }
    fn write32(&mut self, offset: usize, value: u32) {
        self.0.lock().unwrap().write(offset, value)
    }
}
struct Domain(Arc<Mutex<Device>>);

struct Time(Arc<AtomicU64>);
impl Timer for Time {
    fn now_us(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
    fn relax(&self) {
        self.0.fetch_add(10, Ordering::Relaxed);
    }
}
fn config() -> Config<'static> {
    Config {
        ownership: Ownership::ExclusiveDirect,
        wov: Some(1),
        board: Some(BoardIdentity {
            board_vendor: "Observed vendor",
            product_name: "Observed product",
            board_name: "Observed board",
        }),
        acp_config: Some(0),
        dma_address_bits: 40,
        gain: 3,
    }
}
fn fixture(revision: u8) -> (Controller<Model, Time>, Arc<Mutex<Device>>, Source) {
    let device = Arc::new(Mutex::new(Device::new(revision)));
    let clock = device.lock().unwrap().clock.clone();
    // SAFETY: this isolated model supplies every source/ownership boundary;
    // the modeled domain is tied to exactly this modeled PCI function.
    let controller = unsafe {
        Controller::claim(
            Model(device.clone()),
            Time(clock),
            config(),
            Arc::new(Domain(device.clone())),
        )
    }
    .unwrap();
    (controller, device, Source::new())
}
fn ready(revision: u8, period: usize) -> (Controller<Model, Time>, Arc<Mutex<Device>>, Source) {
    let (mut controller, device, source) = fixture(revision);
    controller.initialize().unwrap();
    controller
        .prepare_capture(&source, CAPTURE_FORMAT, period)
        .unwrap();
    (controller, device, source)
}

impl Device {
    fn new(revision: u8) -> Self {
        let mut words = vec![0; 0x11000 / 4];
        words[0x1420 / 4] = 2;
        words[0x2c5c / 4] = 0x6000;
        Self {
            words,
            identity: Identity {
                vendor: 0x1022,
                device: 0x15e2,
                revision,
            },
            master: false,
            count: 0,
            cursor: 0,
            frames: 0,
            translation: None,
            atu_readback: 0,
            atu_reads: 0,
            resets: 0,
            published_reset: None,
            maps: 0,
            unmaps: 0,
            cpu_syncs: 0,
            device_syncs: 0,
            device_owns: false,
            start_never: false,
            stop_never: false,
            reset_never: false,
            power_never: false,
            power_off_never: false,
            unmap_fail: false,
            sync_fail: false,
            drain_fail: false,
            drain_unavailable: false,
            drains: 0,
            coherent_reads: 0,
            coherence_unavailable: false,
            advance_on_coherent: None,
            accesses: Vec::new(),
            defer_payload: false,
            posted: Vec::new(),
            lost_read: None,
            fail_after_write: None,
            ignore_write: None,
            rollover: false,
            unstable: false,
            writes: Vec::new(),
            clock: Arc::new(AtomicU64::new(0)),
            jump_write: None,
            jump_read: None,
        }
    }
}

fn assert_claim_refuses(cfg: Config<'_>) {
    let device = Arc::new(Mutex::new(Device::new(1)));
    assert!(
        // SAFETY: Model and Domain keep the same mutex-serialized Device
        // and its owned fixture registers. There is no physical PCI or
        // firmware actor, and no DMA mapping has been published.
        unsafe {
            Controller::claim(
                Model(device.clone()),
                Time(Arc::new(AtomicU64::new(0))),
                cfg,
                Arc::new(Domain(device.clone())),
            )
        }
        .is_err()
    );
    assert!(device.lock().unwrap().writes.is_empty());
    assert_eq!(device.lock().unwrap().maps, 0);
}

mod admission;
#[expect(
    clippy::duplicate_mod,
    reason = "every family runs these against its own model"
)]
#[path = "../acp_pdm/family_tests/clocked.rs"]
mod clocked;
#[expect(
    clippy::duplicate_mod,
    reason = "every family runs these against its own model"
)]
#[path = "../acp_pdm/family_tests/common.rs"]
mod common;
mod device;
mod domain;
mod interrupts;
#[expect(
    clippy::duplicate_mod,
    reason = "every family runs these against its own model"
)]
#[path = "../acp_pdm/family_tests/period_delivery.rs"]
mod period_delivery;
mod power;
mod recovery;
mod suspend_resume;
