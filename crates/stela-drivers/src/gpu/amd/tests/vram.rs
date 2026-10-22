//! Child of the existing one-authority native_mmio test process. The actual C
//! entry accesses only this model's owned host RAM, never physical registers.
use super::*;
use stela_drivers::gpu::amd::vram;

pub(super) fn original_read(authority: &Authority, pci: &Function<Config>) {
    let (resource, drops) = resource(0x1100_0000, 16384, ResourceKind::Registers);
    // SAFETY: genuine canonical ownership of this isolated RAM-only model;
    // no physical device, D0/reset guard or hardware readiness is asserted.
    let mut bars = unsafe {
        AttachedBars::attach(
            authority,
            pci,
            asic(0),
            asic(0),
            RegisterBar { index: 2, resource },
            None,
        )
    }
    .unwrap();
    let window = bars.registers().unwrap();
    let data = window.direct_dword(1).unwrap();
    // SAFETY: exclusively held real host-RAM allocation returned by the model
    // mapping platform; seed its MM_DATA word, with no active Rust reference.
    unsafe { data.as_ptr().write_volatile(0x5634_1234) };
    let mut output = [0x55aa_55aa; 4];
    // SAFETY: explicitly CPU-only register model, synchronized single test
    // thread. C must reject the complete overflowing read before any access.
    assert_eq!(
        unsafe { vram::read(&window, 256, 252, &mut output) },
        Err(vram::Error::Preflight(2))
    );
    assert_eq!(output, [0x55aa_55aa; 4]);
    // SAFETY: same exclusive RAM model. Native MM-index operations are real C
    // volatile accesses to this allocation, not an emulated VRAM device.
    unsafe { vram::read(&window, 0x8000_000c, 0x7fff_fffc, &mut output) }.unwrap();
    assert_eq!(output, [0x5634_1234; 4]);
    // SAFETY: no other model accessor exists or runs concurrently.
    assert_eq!(
        unsafe { window.direct_dword(0).unwrap().as_ptr().read_volatile() },
        0x8000_0008
    );
    // SAFETY: same bounded exclusively owned RAM words, no live references.
    assert_eq!(
        unsafe { window.direct_dword(6).unwrap().as_ptr().read_volatile() },
        1
    );
    // All accesses have stopped. A borrowed view still prevents retirement;
    // no platform unmap occurs until that exact lease is released.
    // SAFETY: model accesses drained; this attempt must refuse as Busy.
    assert_eq!(
        unsafe { bars.retire() },
        Err(Error::Mapping(MmioError::Busy))
    );
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    drop(window);
    // SAFETY: no view/pointer users remain and the same exact model owner is
    // retained through the acknowledged canonical retirement retry.
    unsafe { bars.retire() }.unwrap();
    drop(bars);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    println!(
        "AMD VRAM Rust/C: same canonical window lease, atomic preflight and original low-register binding; CPU RAM only"
    );
}
