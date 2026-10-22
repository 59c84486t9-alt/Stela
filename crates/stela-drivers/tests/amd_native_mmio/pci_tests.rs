//! CPU-only original matching with actual public PCI/canonical ownership types.
use super::*;
use crate::pci::{Error as MatchError, IpPath, Policy, Source};
use std::cell::Cell;

struct ObservedConfig {
    words: [u32; 16],
    reads: Cell<u64>,
}
impl ConfigSpace for ObservedConfig {
    fn read32(&self, offset: u16) -> u32 {
        assert!(offset.is_multiple_of(4));
        self.reads.set(self.reads.get() | (1 << (offset / 4)));
        self.words[usize::from(offset / 4)]
    }
    fn write32(&mut self, _: u16, _: u32) {
        panic!("original admission performs no config writes")
    }
    fn write16(&mut self, _: u16, _: u16) {
        panic!("original admission performs no config writes")
    }
    fn write8(&mut self, _: u16, _: u8) {
        panic!("original admission performs no config writes")
    }
}
fn observed(device: u16, class: u32, revision: u8) -> Function<ObservedConfig> {
    let mut words = [0; 16];
    words[0] = (u32::from(device) << 16) | 0x1002;
    words[2] = (class << 8) | u32::from(revision);
    words[11] = 0x5678_abcd;
    Function::new(
        Address {
            segment: 4,
            bus: 0x81,
            device: 2,
            function: 0,
        },
        ObservedConfig {
            words,
            reads: Cell::new(0),
        },
    )
    .unwrap()
}
fn policy() -> Policy {
    Policy {
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
    }
}

pub fn original_match(authority: &Authority, model: &Arc<Model>) {
    let mut function = observed(0xffff, 0x120000, 0x45);
    // SAFETY: immutable synthetic config/build inputs, no physical hardware.
    let matched = unsafe { crate::pci::identify(&mut function, policy()) }.unwrap();
    assert_eq!(matched.address().segment, 4);
    assert_eq!(matched.revision(), 0x45);
    assert_eq!(matched.subsystem_ids(), (0xabcd, 0x5678));
    assert_eq!(matched.ip_path(), IpPath::Dynamic);
    assert_eq!(matched.source(), Source::Hardware);
    assert_eq!(matched.initial_apu_flags(), 0); // Not proof of discrete hardware.
    assert_eq!(matched.matched_row(), 310); // Exact third original wildcard.
    // SAFETY: canonical model resources belong to this immutable function.
    let mut bars =
        unsafe { AttachedBars::attach_matched(authority, &matched, registers(0x1100000, 5), None) }
            .unwrap();
    assert!(matches!(
        unsafe {
            crate::discovery::acquire_dynamic_ip(
                &bars,
                &Clock {
                    ticks_per_microsecond: 0,
                },
            )
        },
        Err(crate::discovery::Error::ClockUnavailable)
    ));
    assert_eq!(bars.identity().asic_type, matched.asic_type());
    assert_eq!(bars.identity().original_flags, matched.original_flags());
    assert_eq!(
        bars.original_plan(),
        Some((IpPath::Dynamic, Source::Hardware))
    );
    // SAFETY: no real effects/consumers, exact model mapping can retire.
    unsafe { bars.retire() }.unwrap();
    drop(bars);
    // Failed matched attachment retains the original truthful rollback behavior.
    let calls = model.0.lock().unwrap().calls;
    let error =
        unsafe { AttachedBars::attach_matched(authority, &matched, registers(0x1200000, 2), None) }
            .err()
            .unwrap();
    assert_eq!(error.stage, Stage::Preflight);
    assert_eq!(model.0.lock().unwrap().calls, calls);
    {
        let mut state = model.0.lock().unwrap();
        state.fail_map = state.calls + 1;
    }
    // SAFETY: explicit unchanged model map failure, no hardware resources.
    let error =
        unsafe { AttachedBars::attach_matched(authority, &matched, registers(0x1200000, 5), None) }
            .err()
            .unwrap();
    assert_eq!(error.stage, Stage::Registers);
    assert_eq!(error.rollback, Rollback::NotAttempted);
    model.0.lock().unwrap().fail_map = 0;
    assert_eq!(authority.status().unwrap().live, 0);
    assert_eq!(
        function.config().reads.get(),
        (1 << 0) | (1 << 2) | (1 << 3) | (1 << 11)
    );

    for (id, class, path, source) in [
        (0x6780, 0x020000, IpPath::SiStatic, Source::NotUsed), // class_mask0
        (
            0x6860,
            0x120000,
            IpPath::SocStatic,
            Source::Firmware(c"amdgpu/vega10_ip_discovery.bin"),
        ),
        (0x13db, 0x020000, IpPath::SocStatic, Source::NotUsed),
        (0x13fe, 0x020000, IpPath::Dynamic, Source::Hardware),
    ] {
        let mut function = observed(id, class, 0);
        // SAFETY: immutable model corresponds to original initial probe stage.
        let matched = unsafe { crate::pci::identify(&mut function, policy()) }.unwrap();
        assert_eq!(matched.ip_path(), path);
        assert_eq!(matched.source(), source);
        if path != IpPath::Dynamic {
            let index = if path == IpPath::SiStatic { 2 } else { 5 };
            let mut bars = unsafe {
                AttachedBars::attach_matched(authority, &matched, registers(0x1300000, index), None)
            }
            .unwrap();
            assert!(matches!(
                unsafe {
                    crate::discovery::acquire_dynamic_ip(
                        &bars,
                        &Clock {
                            ticks_per_microsecond: 0,
                        },
                    )
                },
                Err(crate::discovery::Error::Window(
                    Error::StaticInitializationRequired
                ))
            ));
            unsafe { bars.retire() }.unwrap();
        }
    }
    let mut function = observed(0xffff, 0x120000, 0);
    let mut selected_file = policy();
    selected_file.discovery = 2;
    // SAFETY: selected original file option on immutable CPU config model.
    let matched = unsafe { crate::pci::identify(&mut function, selected_file) }.unwrap();
    assert_eq!(
        matched.source(),
        Source::Firmware(c"amdgpu/ip_discovery.bin")
    );
    let mut bars =
        unsafe { AttachedBars::attach_matched(authority, &matched, registers(0x1400000, 5), None) }
            .unwrap();
    assert!(matches!(
        unsafe {
            crate::discovery::acquire_dynamic_ip(
                &bars,
                &Clock {
                    ticks_per_microsecond: 0,
                },
            )
        },
        Err(crate::discovery::Error::Window(
            Error::FirmwareSourceRequired
        ))
    ));
    unsafe { bars.retire() }.unwrap();
    drop(bars);
    // Matching creates no file, TMR reservation, hardware fallback or GPU state.

    let mut changed = observed(0xffff, 0x120000, 0);
    changed.device = 0x6780;
    // SAFETY: model deliberately corrupts public labels; actual config refuses it.
    assert_eq!(
        unsafe { crate::pci::identify(&mut changed, policy()) }.err(),
        Some(MatchError::IdentityChanged)
    );
    let mut bridge = observed(0xffff, 0x120000, 0);
    bridge.config().words[3] = 1 << 16;
    assert_eq!(
        unsafe { crate::pci::identify(&mut bridge, policy()) }.err(),
        Some(MatchError::UnsupportedHeader)
    );
    assert_eq!(bridge.config().reads.get() & (1 << 11), 0); // Never wrong header subsystem layout.
    let mut absent = observed(0xffff, 0x120000, 0);
    absent.config().words[0] = u32::MAX;
    assert_eq!(
        unsafe { crate::pci::identify(&mut absent, policy()) }.err(),
        Some(MatchError::Absent)
    );
    let mut nonmatch = observed(0xffff, 0x020000, 0);
    assert_eq!(
        unsafe { crate::pci::identify(&mut nonmatch, policy()) }.err(),
        Some(MatchError::Native(2))
    );
    println!(
        "AMD matched attachment: real public types, accelerator/class0/file/static/refusals/rollback; CPU model only"
    );
}
