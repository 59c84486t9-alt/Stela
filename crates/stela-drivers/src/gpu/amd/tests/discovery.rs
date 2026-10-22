//! Child of the single-authority canonical test, with bounded generated C
//! leaf-I/O instrumentation. No physical GPU or production provider is used.
use super::native_mmio;
use super::*;
#[path = "../discovery.rs"]
mod discovery;
#[path = "../vram.rs"]
mod vram;
unsafe extern "C" {
    fn stela_amd_tmr_fixture(size: &mut usize) -> *const u8;
    fn stela_amd_tmr_model_begin(registers: *mut u32, bytes: *const u8, size: usize);
    fn stela_amd_tmr_model_accesses() -> u32;
    fn stela_amd_tmr_model_delay();
    fn stela_amd_tmr_model_vf();
    fn stela_amd_tmr_model_system();
    fn stela_amd_tmr_model_corrupt();
    fn stela_amd_tmr_model_end();
}
pub(super) fn acquire_snapshot(authority: &Authority, pci: &Function<Config>) {
    let (resource, drops) = resource(0x1200_0000, 0x60000, ResourceKind::Registers);
    // SAFETY: isolated canonical RAM-only model, no physical state asserted.
    let mut bars = unsafe {
        AttachedBars::attach(
            authority,
            pci,
            asic(2),
            asic(2),
            RegisterBar { index: 5, resource },
            None,
        )
    }
    .unwrap();
    let window = bars.registers().unwrap();
    let clock = stela_drivers::Clock {
        ticks_per_microsecond: 1,
    };
    let mut bytes = 0;
    // SAFETY: actual immutable static CPU fixture, existing bounded generator.
    let source = unsafe { stela_amd_tmr_fixture(&mut bytes) };
    let begin = || unsafe {
        stela_amd_tmr_model_begin(window.direct_dword(0).unwrap().as_ptr(), source, bytes)
    };
    begin();
    // Exercise the actual C-to-Rust elapsed-time callback once. This CPU
    // model does not qualify calibration, scheduler sleep or physical timing.
    unsafe { stela_amd_tmr_model_delay() };
    // SAFETY: production acquisition runs only the instrumented CPU fixture path;
    // actual original algorithms execute with canonical model ownership/lifetime.
    let snapshot = unsafe { discovery::acquire(&bars, &clock) }.unwrap();
    assert_eq!(snapshot.bytes(), unsafe {
        core::slice::from_raw_parts(source, bytes)
    });
    assert_eq!(snapshot.identity(), bars.identity());
    assert_eq!(snapshot.vram_bytes(), 64 << 20);
    assert_eq!(snapshot.vram_offset(), (64 << 20) - 65536);
    assert!(unsafe { stela_amd_tmr_model_accesses() } > bytes as u32 / 4);
    drop(snapshot);
    begin();
    unsafe { stela_amd_tmr_model_corrupt() };
    assert!(matches!(
        unsafe { discovery::acquire(&bars, &clock) },
        Err(discovery::Error::Validation(_))
    ));
    begin();
    allocation_failure::arm();
    // SAFETY: same controlled CPU fixture; only snapshot Vec allocation fails.
    let failed = unsafe { discovery::acquire(&bars, &clock) };
    let consumed = allocation_failure::disarm();
    assert!(consumed);
    assert!(matches!(failed, Err(discovery::Error::PostQueryAllocation)));
    assert!(unsafe { stela_amd_tmr_model_accesses() } > 0);
    begin();
    // SAFETY: zero clock is rejected before the actual query sees any register.
    assert!(matches!(
        unsafe {
            discovery::acquire(
                &bars,
                &stela_drivers::Clock {
                    ticks_per_microsecond: 0,
                },
            )
        },
        Err(discovery::Error::ClockUnavailable)
    ));
    assert_eq!(unsafe { stela_amd_tmr_model_accesses() }, 0);
    unsafe { stela_amd_tmr_model_vf() };
    assert!(matches!(
        unsafe { discovery::acquire(&bars, &clock) },
        Err(discovery::Error::VfOwnerUnavailable)
    ));
    begin();
    unsafe { stela_amd_tmr_model_system() };
    assert!(matches!(
        unsafe { discovery::acquire(&bars, &clock) },
        Err(discovery::Error::SystemFirmwareOwnerUnavailable)
    ));
    unsafe { stela_amd_tmr_model_end() };
    drop(window);
    // SAFETY: all CPU-only fixture accesses/views have ended before retirement.
    unsafe { bars.retire() }.unwrap();
    drop(bars);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    println!(
        "AMD TMR Rust/C: full retained validated snapshot equality, actual identity/extent, pre-I/O clock refusal, missing VF/sysmem owners; generated leaf-I/O RAM model only"
    );
}

// Test-only System wrapper: arm exactly the current test thread's next
// allocation. It does not replace any production allocator/service.
mod allocation_failure {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    thread_local! { static ARMED: Cell<bool> = const { Cell::new(false) }; }
    thread_local! { static CONSUMED: Cell<bool> = const { Cell::new(false) }; }
    struct FaultAllocator;
    #[global_allocator]
    static ALLOCATOR: FaultAllocator = FaultAllocator;
    // SAFETY: exact System delegation except the explicit valid null OOM
    // response; TLS access is allocation-free and bounded to this test thread.
    unsafe impl GlobalAlloc for FaultAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if ARMED.try_with(|v| v.replace(false)).unwrap_or(false) {
                let _ = CONSUMED.try_with(|v| v.set(true));
                core::ptr::null_mut()
            } else {
                // SAFETY: unchanged allocator request supplied by Rust.
                unsafe { System.alloc(layout) }
            }
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            // SAFETY: exact System allocation and original layout from Rust.
            unsafe { System.dealloc(pointer, layout) }
        }
    }
    pub fn arm() {
        CONSUMED.with(|v| v.set(false));
        ARMED.with(|v| v.set(true));
    }
    pub fn disarm() -> bool {
        ARMED.with(|v| v.set(false));
        CONSUMED.with(Cell::get)
    }
}
