//! Child of the canonical single-authority test in a separate generated CPU
//! harness. Only the existing original C MM leaf is instrumented, never a
//! production provider. No physical PCI/GPU services are exercised.
use super::*;
use crate::{discovery, pci};

unsafe extern "C" {
    fn stela_amd_tmr_fixture(bytes: &mut usize) -> *const u8;
    fn stela_amd_tmr_model_begin(registers: *mut u32, bytes: *const u8, size: usize);
    fn stela_amd_tmr_model_accesses() -> u32;
    fn stela_amd_tmr_model_end();
    fn stela_amd_ip_oracle(
        source: *const u8,
        bytes: usize,
        counts: &mut discovery::IpCounts,
        hwips: &mut u32,
        instances: &mut u32,
    );
    fn stela_amd_ip_oracle_fact(hwip: u32, instance: u32, segment: u32, kind: u32) -> u64;
}
struct FixtureConfig;
impl ConfigSpace for FixtureConfig {
    fn read32(&self, offset: u16) -> u32 {
        match offset {
            0 => 0xffff_1002,
            8 => 0x1200_0045,
            12 => 0,
            44 => 0x5678_abcd,
            _ => panic!("unexpected config read"),
        }
    }
    fn write32(&mut self, _: u16, _: u32) {
        panic!("no config writes")
    }
    fn write16(&mut self, _: u16, _: u16) {
        panic!("no config writes")
    }
    fn write8(&mut self, _: u16, _: u8) {
        panic!("no config writes")
    }
}
pub(super) fn acquire_observed(authority: &Authority) {
    let mut function = Function::new(
        Address {
            segment: 4,
            bus: 0x81,
            device: 2,
            function: 0,
        },
        FixtureConfig,
    )
    .unwrap();
    let policy = pci::Policy {
        si_built: true,
        cik_built: true,
        radeon_built: false,
        si_support: -1,
        cik_support: -1,
        experimental: 0,
        discovery: -1,
        force_asic: -1,
        memory_encrypted: false,
        firmware_drivers_only: false,
        modeset: -1,
    };
    // SAFETY: actual public Function observes only immutable synthetic config.
    let matched = unsafe { pci::identify(&mut function, policy) }.unwrap();
    assert_eq!(matched.ip_path(), pci::IpPath::Dynamic);
    assert_eq!(matched.source(), pci::Source::Hardware);
    let (resource, drops) = resource(0x1300_0000, 0x60000, ResourceKind::Registers);
    // SAFETY: exact canonical RAM model resource, no physical admission claim.
    let mut bars = unsafe {
        AttachedBars::attach_matched(
            authority,
            &matched,
            RegisterBar { index: 5, resource },
            None,
        )
    }
    .unwrap();
    let window = bars.registers().unwrap();
    let clock = Clock {
        ticks_per_microsecond: 1,
    };
    let mut bytes = 0;
    // SAFETY: original-format immutable static CPU fixture, no firmware payload.
    let source = unsafe { stela_amd_tmr_fixture(&mut bytes) };
    let begin = || unsafe {
        stela_amd_tmr_model_begin(window.direct_dword(0).unwrap().as_ptr(), source, bytes)
    };
    begin();
    // SAFETY: instrumented original MM query/copy runs only the bounded RAM
    // fixture. The real production admission and ownership APIs are unchanged.
    let observed = unsafe { discovery::acquire_dynamic_ip(&bars, &clock) }.unwrap();
    assert_eq!(observed.source_bytes(), unsafe {
        core::slice::from_raw_parts(source, bytes)
    });
    assert_eq!(observed.identity(), bars.identity());
    let mut counts = discovery::IpCounts::default();
    let (mut hwips, mut instances) = (0, 0);
    // SAFETY: exact checked C/Rust ABI; independent frozen original consumer
    // owns its distinct work copy and returns only scalar expected values.
    unsafe { stela_amd_ip_oracle(source, bytes, &mut counts, &mut hwips, &mut instances) };
    assert_eq!(observed.counts(), counts);
    let mut bound = 0;
    for hwip in 0..hwips {
        for instance in 0..instances {
            let version = unsafe { stela_amd_ip_oracle_fact(hwip, instance, 0, 0) };
            assert_eq!(observed.version(hwip, instance), Some(version as u32));
            let count = unsafe { stela_amd_ip_oracle_fact(hwip, instance, 0, 1) };
            if count == u64::MAX {
                assert_eq!(observed.register_count(hwip, instance), None);
            } else {
                bound += 1;
                assert_eq!(observed.register_count(hwip, instance), Some(count as u32));
                for segment in 0..count as u32 {
                    let expected = unsafe { stela_amd_ip_oracle_fact(hwip, instance, segment, 2) };
                    assert_eq!(
                        observed.register_base(hwip, instance, segment),
                        Some(expected as u32)
                    );
                }
                assert_eq!(observed.register_base(hwip, instance, count as u32), None);
            }
        }
    }
    assert!(bound > 0);
    assert_eq!(observed.version(hwips, 0), None);
    assert_eq!(observed.version(0, instances), None);
    assert_eq!(observed.register_base(u32::MAX, u32::MAX, u32::MAX), None);
    assert!(unsafe { stela_amd_tmr_model_accesses() } > bytes as u32 / 4);
    drop(observed);
    // Each of four fallible production allocations is independently refused.
    // Query/index effects remain real in this model, never falsely rolled back.
    for allocation in 0..4 {
        begin();
        allocation_failure::arm(allocation);
        let failed = unsafe { discovery::acquire_dynamic_ip(&bars, &clock) };
        let consumed = allocation_failure::disarm();
        assert!(consumed);
        assert!(matches!(
            (allocation, failed),
            (0, Err(discovery::Error::PostQueryAllocation))
                | (1..=3, Err(discovery::Error::PostAcquireAllocation))
        ));
        assert!(unsafe { stela_amd_tmr_model_accesses() } > 0);
    }
    begin();
    assert!(matches!(
        unsafe {
            discovery::acquire_dynamic_ip(
                &bars,
                &Clock {
                    ticks_per_microsecond: 0,
                },
            )
        },
        Err(discovery::Error::ClockUnavailable)
    ));
    assert_eq!(unsafe { stela_amd_tmr_model_accesses() }, 0);
    unsafe { stela_amd_tmr_model_end() };
    drop(window);
    // SAFETY: all model consumers drained; failed unpublished copies dropped.
    unsafe { bars.retire() }.unwrap();
    drop(bars);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    println!(
        "AMD dynamic IP Rust/C: same admitted source owner; immutable raw bytes; every original version/binding/base/count; four allocation failures; CPU leaf-I/O model only"
    );
}

pub(super) mod allocation_failure {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    thread_local! { static REMAINING: Cell<Option<usize>> = const { Cell::new(None) }; }
    thread_local! { static CONSUMED: Cell<bool> = const { Cell::new(false) }; }
    struct FaultAllocator;
    #[global_allocator]
    static ALLOCATOR: FaultAllocator = FaultAllocator;
    // SAFETY: exact System delegation except one explicit valid null response;
    // TLS is allocation-free and limited to this single harness thread.
    unsafe impl GlobalAlloc for FaultAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let fail = REMAINING
                .try_with(|value| match value.get() {
                    Some(0) => {
                        value.set(None);
                        true
                    }
                    Some(n) => {
                        value.set(Some(n - 1));
                        false
                    }
                    None => false,
                })
                .unwrap_or(false);
            if fail {
                let _ = CONSUMED.try_with(|v| v.set(true));
                core::ptr::null_mut()
            } else {
                unsafe { System.alloc(layout) }
            }
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            // SAFETY: unmodified System allocation/layout from Rust.
            unsafe { System.dealloc(pointer, layout) }
        }
    }
    pub fn arm(before: usize) {
        CONSUMED.with(|v| v.set(false));
        REMAINING.with(|v| v.set(Some(before)));
    }
    pub fn disarm() -> bool {
        REMAINING.with(|v| v.set(None));
        CONSUMED.with(Cell::get)
    }
}
