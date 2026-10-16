//! Explicit 1 GHz guest clock profile, backed by a coherent host or replay sample.
//!
//! `counter` is continuous time; subtracting cumulative sleep gives absolute
//! (awake) time. Clock publication changes only the declared time fields; the
//! commpage owner preserves any separately declared static configuration.
//! This is not a complete commpage, hardware counter, or Darwin service layer.
//! Publication and translated reads must be serialized by the address-space
//! owner; the read-only guest alias never grants guest write permission.
//!
//! Host contract: XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea,
//! osfmk/i386/cpu_capabilities.h and libsyscall/wrappers/mach_continuous_time.c.
//! The internal x86 commpage contract is validated, not assumed on other hosts.
pub use crate::commpage::legacy::{
    CONT_HW_TIMEBASE, CONT_HWCLOCK, CONT_TIMEBASE, GUEST_BASE, GUEST_BYTES, TIMEBASE_OFFSET,
    USER_TIMEBASE,
};
use crate::{
    commpage::legacy::{self, CLOCK_FIELD_END as FIELD_END, CLOCK_FIELD_START as FIELD_START},
    memory::MemoryRegion,
};
use alloc::collections::VecDeque;
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};
use anyhow::{Result, bail, ensure};
use serde::Serialize;

#[cfg(test)]
pub(crate) static TEST_CONTEXT_LOCK: crate::platform::sync::Mutex<()> =
    crate::platform::sync::Mutex::new(());

pub const PROFILE_ID: &str = "stela-continuous-ns-arm-commpage-clock-v1";
pub const FREQUENCY: u64 = 1_000_000_000;
/// Bounded diagnostic history for this initial execution profile.
pub const MAX_COUNTER_EVENTS: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    /// Continuous nanoseconds, including sleep.
    pub counter: u64,
    /// Cumulative sleep nanoseconds in the same epoch.
    pub sleep_ticks: u64,
}
impl Snapshot {
    pub fn awake_ticks(self) -> Result<u64> {
        self.counter
            .checked_sub(self.sleep_ticks)
            .ok_or_else(|| anyhow::anyhow!("clock sleep exceeds continuous counter"))
    }
}

/// Explicit process clock provider. Implementations must use the same 1 GHz
/// epoch for continuous and sleep ticks. Context checks all three monotonicities.
pub trait ClockSource {
    fn sample(&mut self) -> Result<Snapshot>;
    fn source_id(&self) -> &'static str;
}

/// Finite, caller-provided test input; exhaustion never invents another tick.
#[derive(Debug)]
pub struct ReplaySource {
    samples: VecDeque<Snapshot>,
}
impl ReplaySource {
    pub fn new(samples: Vec<Snapshot>) -> Result<Self> {
        ensure!(!samples.is_empty(), "clock replay has no samples");
        let mut previous = None;
        for sample in &samples {
            validate(*sample, previous)?;
            previous = Some(*sample);
        }
        Ok(Self {
            samples: samples.into(),
        })
    }
}
impl ClockSource for ReplaySource {
    fn sample(&mut self) -> Result<Snapshot> {
        self.samples
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("clock replay exhausted"))
    }
    fn source_id(&self) -> &'static str {
        "explicit-finite-replay-v1"
    }
}

/// Ordered successful samples; sequence zero is the construction sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CounterEvent {
    pub sequence: u64,
    pub snapshot: Snapshot,
}

pub struct Context {
    address_space: u64,
    source: Box<dyn ClockSource>,
    page: legacy::Page,
    events: Vec<CounterEvent>,
}
impl Context {
    /// Consumes and publishes the first source sample. Further samples are
    /// obtained only by read_counter, not by inspecting snapshot/region/events.
    pub fn new(address_space: u64, source: Box<dyn ClockSource>) -> Result<Self> {
        Self::new_with_commpage(address_space, source, legacy::Configuration::default())
    }

    /// Declare additional legacy fields without mixing their meaning into the
    /// clock source. The commpage owner restricts publication to clock bytes.
    pub fn new_with_commpage(
        address_space: u64,
        mut source: Box<dyn ClockSource>,
        configuration: legacy::Configuration,
    ) -> Result<Self> {
        let first = source.sample()?;
        validate(first, None)?;
        let page = legacy::Page::map(&fields(first), configuration)?;
        let mut events = Vec::with_capacity(64);
        events.push(CounterEvent {
            sequence: 0,
            snapshot: first,
        });
        Ok(Self {
            address_space,
            source,
            page,
            events,
        })
    }
    pub fn native(address_space: u64) -> Result<Self> {
        Self::new(address_space, Box::new(NativeDarwinSource::new()?))
    }
    /// Register the existing writable publication alias, retaining this clock.
    pub fn shared_memory_participant(&mut self) -> crate::memory::SharedMemoryParticipant<'_> {
        self.page.shared_memory_participant(self.address_space)
    }

    pub fn check_execution_thread<P: crate::memory::domain::DataPolicy>(
        &self,
        thread: &crate::memory::domain::MemoryThread<P>,
    ) -> Result<(), stela_compiler::context::memory::MemoryStatus> {
        self.page.check_execution_thread(thread)
    }

    pub fn address_space(&self) -> u64 {
        self.address_space
    }
    pub fn profile_id(&self) -> &'static str {
        PROFILE_ID
    }
    pub fn legacy_configuration(&self) -> legacy::Configuration {
        self.page.configuration()
    }
    pub fn source_id(&self) -> &'static str {
        self.source.source_id()
    }
    pub fn frequency(&self) -> u64 {
        FREQUENCY
    }
    pub fn region(&self) -> &MemoryRegion {
        self.page.region()
    }
    pub fn snapshot(&self) -> Snapshot {
        self.events.last().expect("initial clock event").snapshot
    }
    pub fn snapshot_bytes(&self, offset: usize, bytes: usize) -> Result<Vec<u8>> {
        self.page.read_snapshot(offset, bytes)
    }
    pub fn events(&self) -> &[CounterEvent] {
        &self.events
    }

    /// Publish one coherent sample before returning its continuous counter.
    /// Validation/publication failures leave the published snapshot and event
    /// accounting unchanged (a source may have consumed its failed sample).
    /// The caller must exclude concurrent translated execution during this call.
    pub fn read_counter(&mut self) -> Result<u64> {
        ensure!(
            self.events.len() < MAX_COUNTER_EVENTS,
            "clock diagnostic event budget exhausted"
        );
        // Reserve before sampling/publication so failure cannot publish a sample
        // without its record. Typical bounded probes need only two records.
        self.events.try_reserve(1)?;
        let sample = self.source.sample()?;
        validate(sample, Some(self.snapshot()))?;
        self.page.publish_clock(&fields(sample))?;
        self.events.push(CounterEvent {
            sequence: self.events.len() as u64,
            snapshot: sample,
        });
        Ok(sample.counter)
    }
}

fn validate(sample: Snapshot, previous: Option<Snapshot>) -> Result<()> {
    let awake = sample.awake_ticks()?;
    if let Some(previous) = previous {
        ensure!(
            sample.counter >= previous.counter,
            "continuous clock moved backwards"
        );
        ensure!(
            sample.sleep_ticks >= previous.sleep_ticks,
            "cumulative sleep moved backwards"
        );
        ensure!(
            awake >= previous.awake_ticks()?,
            "absolute clock moved backwards"
        );
    }
    Ok(())
}

fn fields(sample: Snapshot) -> [u8; FIELD_END - FIELD_START] {
    let mut fields = [0; FIELD_END - FIELD_START];
    fields[..8].copy_from_slice(&sample.sleep_ticks.wrapping_neg().to_le_bytes());
    fields[USER_TIMEBASE - FIELD_START] = 1;
    fields[CONT_HWCLOCK - FIELD_START] = 1;
    fields[CONT_TIMEBASE - FIELD_START..CONT_TIMEBASE - FIELD_START + 8]
        .copy_from_slice(&sample.sleep_ticks.to_le_bytes());
    // CONT_HW_TIMEBASE=0: the supplied virtual counter is already continuous.
    fields
}

/// Native source exists only for the validated x86-64 Darwin internal ABI.
/// There is deliberately no guessed Linux or Apple-silicon host fallback.
pub struct NativeDarwinSource {
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    previous: Option<Snapshot>,
}
impl NativeDarwinSource {
    pub fn new() -> Result<Self> {
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        {
            darwin::validate_host()?;
            Ok(Self { previous: None })
        }
        #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
        bail!("native clock requires the reviewed x86-64 Darwin commpage ABI")
    }
}
impl ClockSource for NativeDarwinSource {
    fn sample(&mut self) -> Result<Snapshot> {
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        {
            let sample = darwin::sample()?;
            validate(sample, self.previous)?;
            self.previous = Some(sample);
            Ok(sample)
        }
        #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
        bail!("native clock requires the reviewed x86-64 Darwin commpage ABI")
    }
    fn source_id(&self) -> &'static str {
        "darwin-x86_64-absolute-plus-commpage-sleep-v1"
    }
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod darwin {
    use super::*;
    const HOST_BASE: u64 = 0x00007fffffe00000;
    const SLEEP: usize = 0xc0;
    const MAX_RETRIES: usize = 64;
    #[repr(C)]
    struct Timebase {
        numer: u32,
        denom: u32,
    }
    unsafe extern "C" {
        static mach_task_self_: u32;
        fn mach_absolute_time() -> u64;
        fn mach_timebase_info(info: *mut Timebase) -> i32;
        fn mach_vm_region(
            task: u32,
            address: *mut u64,
            size: *mut u64,
            flavor: i32,
            info: *mut i32,
            count: *mut u32,
            object: *mut u32,
        ) -> i32;
        fn mach_port_deallocate(task: u32, name: u32) -> i32;
    }
    pub(super) fn validate_host() -> Result<()> {
        let mut address = HOST_BASE;
        let mut size = 0;
        let mut info = [0i32; 9];
        let mut count = 9;
        let mut object = 0;
        // SAFETY: Current task and initialized buffers for BASIC_INFO_64/count9.
        let status = unsafe {
            mach_vm_region(
                mach_task_self_,
                &mut address,
                &mut size,
                9,
                info.as_mut_ptr(),
                &mut count,
                &mut object,
            )
        };
        if object != 0 {
            // SAFETY: Release only the object send right returned by this query.
            unsafe { mach_port_deallocate(mach_task_self_, object) };
        }
        ensure!(
            status == 0
                && count == 9
                && address <= HOST_BASE
                && address
                    .checked_add(size)
                    .is_some_and(|end| end >= HOST_BASE + SLEEP as u64 + 8)
                && info[0] & libc::VM_PROT_READ != 0
                && info[0] & libc::VM_PROT_WRITE == 0,
            "host commpage mapping is unavailable or outside the reviewed read-only profile"
        );
        // SAFETY: The checked fixed Darwin kernel commpage is process-lifetime,
        // readable, and not user writable. These fixed offsets are aligned and
        // within the validated extent. Host code must not dismantle system maps.
        let signature = unsafe {
            core::slice::from_raw_parts(HOST_BASE as *const u8, b"commpage 64-bit".len())
        };
        ensure!(
            signature == b"commpage 64-bit",
            "unrecognized host commpage signature"
        );
        let version = unsafe { core::ptr::read_volatile((HOST_BASE + 0x1e) as *const u16) };
        ensure!(version == 14, "unsupported host commpage version {version}");
        let mut timebase = Timebase { numer: 0, denom: 0 };
        // SAFETY: The public API receives its exact initialized C structure.
        let result = unsafe { mach_timebase_info(&mut timebase) };
        ensure!(
            result == 0 && timebase.numer == 1 && timebase.denom == 1,
            "host absolute time is not the reviewed 1:1 nanosecond timebase"
        );
        Ok(())
    }
    pub(super) fn sample() -> Result<Snapshot> {
        for _ in 0..MAX_RETRIES {
            // SAFETY: Construction validated this process-lifetime Darwin
            // commpage. Aligned x86-64 volatile loads observe atomic sleep ticks;
            // the public call and compiler fences preserve the sampling bracket.
            let before =
                unsafe { core::ptr::read_volatile((HOST_BASE + SLEEP as u64) as *const u64) };
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            let awake = unsafe { mach_absolute_time() };
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            let after =
                unsafe { core::ptr::read_volatile((HOST_BASE + SLEEP as u64) as *const u64) };
            if before == after {
                let counter = awake
                    .checked_add(before)
                    .ok_or_else(|| anyhow::anyhow!("host continuous time overflow"))?;
                return Ok(Snapshot {
                    counter,
                    sleep_ticks: before,
                });
            }
        }
        bail!("host cumulative sleep changed during all {MAX_RETRIES} clock samples")
    }
}

#[cfg(test)]
mod tests;
