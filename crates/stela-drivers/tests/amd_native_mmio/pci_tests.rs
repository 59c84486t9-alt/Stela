//! CPU-only probe admission and IP discovery with the public PCI and canonical
//! ownership types.
use super::*;
use crate::pci::{Error as MatchError, IpPath, Policy};
use firmware::{Catalog, HandoffProvider, Provenance, Resource, Target};
use sha2::{Digest, Sha256};
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
        panic!("admission performs no config writes")
    }
    fn write16(&mut self, _: u16, _: u16) {
        panic!("admission performs no config writes")
    }
    fn write8(&mut self, _: u16, _: u8) {
        panic!("admission performs no config writes")
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
/// A 512 KiB register BAR, which holds every register discovery reads.
fn full_registers(base: u64) -> RegisterBar {
    RegisterBar {
        index: 5,
        resource: resource(base, 512 * 1024, ResourceKind::Registers).0,
    }
}
fn catalog(name: &str, target: Target<'_>, bytes: Vec<u8>) -> Catalog {
    Catalog::from_handoff(vec![Resource {
        name,
        target,
        provenance: Provenance {
            source: "synthetic-amd-discovery-fixture",
            revision: "stela-tests",
            member: "synthetic/ip_discovery.bin",
            license: "MIT test data",
        },
        expected_length: bytes.len(),
        expected_sha256: Sha256::digest(&bytes).into(),
        bytes,
    }])
    .unwrap()
}

pub fn original_match(authority: &Authority, model: &Arc<Model>) {
    let mut function = observed(0xffff, 0x120000, 0x45);
    // SAFETY: immutable synthetic config, no physical hardware.
    let matched = unsafe { crate::pci::identify(&mut function, Policy::default()) }.unwrap();
    assert_eq!(matched.address().segment, 4);
    assert_eq!(matched.revision(), 0x45);
    assert_eq!(matched.subsystem_ids(), (0xabcd, 0x5678));
    assert_eq!(matched.asic_type(), asic(3));
    assert_eq!(matched.ip_path(), IpPath::Dynamic);
    assert_eq!(matched.apu_flags(), 0);
    // SAFETY: canonical model resources belong to this immutable function.
    let mut bars =
        unsafe { AttachedBars::attach_matched(authority, &matched, registers(0x1100000, 5), None) }
            .unwrap();
    assert_eq!(bars.identity().asic_type, matched.asic_type());
    assert_eq!(bars.identity().original_flags, matched.flags());
    assert_eq!(bars.ip_path(), Some(IpPath::Dynamic));
    // Discovery's first register is beyond this 16 KiB window.
    let empty = HandoffProvider::new(None);
    // Invalid timing metadata refuses before the original C owner, provider
    // or even the first out-of-window register can be consulted. Do not make
    // a required delay silently expire with zero calibration.
    for (rate, error) in [
        (0, stela_drivers::ClockError::Uncalibrated),
        (
            u64::MAX / 1000 + 1,
            stela_drivers::ClockError::DurationOverflow,
        ),
        (
            (u64::MAX / 2) / 1000 + 1,
            stela_drivers::ClockError::DurationTooLong,
        ),
    ] {
        let invalid = Clock {
            ticks_per_microsecond: rate,
        };
        // SAFETY: canonical model resources, no physical hardware; invalid
        // calibration must fail before any register operation.
        assert_eq!(
            unsafe { crate::discovery::discover(&bars, &invalid, &empty) }.err(),
            Some(crate::discovery::Error::Clock(error))
        );
    }
    // SAFETY: the zeroed model mapping stands in for the device.
    let refused = unsafe { crate::discovery::discover(&bars, &CLOCK, &empty) };
    assert_eq!(
        refused.err(),
        Some(crate::discovery::Error::Unsupported(
            c"indirect register access"
        ))
    );
    // SAFETY: no real effects or consumers; the model mapping can retire.
    unsafe { bars.retire() }.unwrap();
    drop(bars);
    // Failed matched attachment keeps attach's rollback behavior.
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

    // Fixed-table ASICs have no discovery to run.
    for (id, path) in [(0x67df, IpPath::ViStatic), (0x6860, IpPath::SocStatic)] {
        let mut function = observed(id, 0x030000, 0);
        // SAFETY: immutable synthetic config.
        let matched = unsafe { crate::pci::identify(&mut function, Policy::default()) }.unwrap();
        assert_eq!(matched.ip_path(), path);
        let mut bars = unsafe {
            AttachedBars::attach_matched(authority, &matched, registers(0x1300000, 5), None)
        }
        .unwrap();
        // SAFETY: refused before any access.
        let refused = unsafe { crate::discovery::discover(&bars, &CLOCK, &empty) };
        assert_eq!(
            refused.err(),
            Some(crate::discovery::Error::Window(
                Error::StaticInitializationRequired
            ))
        );
        unsafe { bars.retire() }.unwrap();
    }

    // The discovery parameter selects the firmware file. The model reports
    // 16 MiB of VRAM and completed IFWI; Linux then does not use its zeroed
    // discovery table. This fixture does not test the independent IFWI wait.
    let mut function = observed(0x7550, 0x030000, 0xc1);
    let file = Policy {
        discovery: 2,
        ..Policy::default()
    };
    // SAFETY: immutable synthetic config.
    let matched = unsafe { crate::pci::identify(&mut function, file) }.unwrap();
    let mut bars = unsafe {
        AttachedBars::attach_matched(authority, &matched, full_registers(0x1400000), None)
    }
    .unwrap();
    {
        let memsize = bars.registers().unwrap().direct_dword(0xde3).unwrap();
        let ready = bars.registers().unwrap().direct_dword(0x16061).unwrap();
        // SAFETY: the model's own register memory, with no device behind it.
        unsafe {
            memsize.write_volatile(16);
            ready.write_volatile(0x8000_0000);
        }
    }
    // SAFETY: the zeroed model mapping stands in for the device.
    let missing = unsafe { crate::discovery::discover(&bars, &CLOCK, &empty) };
    assert!(matches!(
        missing.err(),
        Some(crate::discovery::Error::Firmware(error))
            if error.name == "amdgpu/ip_discovery.bin"
    ));
    let images = catalog(
        "amdgpu/ip_discovery.bin",
        Target {
            driver: "amd-amdgpu-ip-discovery",
            hardware: "pci-1002-7550",
            revision: "pci-c1;subsys-abcd-5678",
            board: None,
        },
        discovery_binary(),
    );
    // SAFETY: as above.
    let found = unsafe { crate::discovery::discover(&bars, &CLOCK, &images) }.unwrap();
    // Linux's enum amd_hw_ip_block_type: GC 1, SDMA0 3, MP1 16, UVD 17, UMC 29.
    assert_eq!(found.version(1, 0), Some(0x0a03_0001));
    assert_eq!(found.version(3, 0), Some(0x0502_0000));
    assert_eq!(found.version(17, 0), Some(0x0300_0000));
    assert_eq!(found.version(16, 0), None);
    assert_eq!(found.register_count(1, 0), Some(2));
    assert_eq!(found.register_base(1, 0, 1), Some(0xa000));
    assert_eq!(found.register_base(1, 0, 2), None);
    assert_eq!(found.register_base(29, 1, 0), Some(0x54000));
    assert_eq!(found.register_count(16, 0), None);
    let facts = found.facts();
    assert_eq!(
        (facts.xcc_mask, facts.sdma_count, facts.vcn_count),
        (1, 1, 1)
    );
    assert_eq!((facts.vcn_config[0], facts.vcn_codec_disable[0]), (0x80, 5));
    assert_eq!(
        (facts.umc_nodes, facts.umc_count, facts.umc_active_mask),
        (2, 1, 1)
    );
    assert_eq!(facts.mall_size, 2 << 20);
    assert_eq!(facts.gfx(crate::discovery::GfxField::MaxCuPerSh), 10);
    assert_eq!(facts.gfx(crate::discovery::GfxField::GcTccSize), 0);
    drop(found);
    // SAFETY: discovery has released its accesses; the model mapping retires.
    unsafe { bars.retire() }.unwrap();
    drop(bars);

    // Refusals: a changed identity, a bridge header, an absent function, a
    // class Linux does not claim, and SI, which Stela builds without.
    let mut changed = observed(0xffff, 0x120000, 0);
    changed.device = 0x6780;
    // SAFETY: the model corrupts the public labels; config refuses it.
    assert_eq!(
        unsafe { crate::pci::identify(&mut changed, Policy::default()) }.err(),
        Some(MatchError::IdentityChanged)
    );
    let mut bridge = observed(0xffff, 0x120000, 0);
    bridge.config().words[3] = 1 << 16;
    assert_eq!(
        unsafe { crate::pci::identify(&mut bridge, Policy::default()) }.err(),
        Some(MatchError::UnsupportedHeader)
    );
    assert_eq!(bridge.config().reads.get() & (1 << 11), 0);
    let mut absent = observed(0xffff, 0x120000, 0);
    absent.config().words[0] = u32::MAX;
    assert_eq!(
        unsafe { crate::pci::identify(&mut absent, Policy::default()) }.err(),
        Some(MatchError::Absent)
    );
    const ENODEV: i32 = 19;
    for (device, class) in [(0xffff, 0x020000), (0x6780, 0x030000)] {
        let mut refused = observed(device, class, 0);
        assert_eq!(
            unsafe { crate::pci::identify(&mut refused, Policy::default()) }.err(),
            Some(MatchError::Native(-ENODEV))
        );
    }
    println!(
        "AMD probe admission and discovery: matches, paths, firmware and refusals; CPU model only"
    );
}
