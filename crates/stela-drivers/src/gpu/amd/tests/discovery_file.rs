//! Separate generated same-authority CPU harness, using actual production Rust,
//! canonical Catalog/Image and existing original MM leaf-I/O instrumentation.
use super::*;
use crate::{discovery, dynamic_ip_tests::allocation_failure, firmware, pci};
use firmware::{Catalog, Provider};
use sha2::{Digest, Sha256};
use std::cell::Cell;

unsafe extern "C" {
    fn stela_amd_info_oracle(
        source: *const u8,
        bytes: usize,
        device: u16,
        revision: u8,
        out: &mut discovery::Information,
    );
    fn stela_amd_file_fixture_declared(source: *const u8, bytes: usize) -> usize;
    fn stela_amd_tmr_fixture(bytes: &mut usize) -> *const u8;
    fn stela_amd_tmr_model_begin(registers: *mut u32, bytes: *const u8, size: usize);
    fn stela_amd_tmr_model_accesses() -> u32;
    fn stela_amd_tmr_model_vf();
    fn stela_amd_tmr_model_system();
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
struct FileConfig(u16);
impl ConfigSpace for FileConfig {
    fn read32(&self, offset: u16) -> u32 {
        match offset {
            0 => (u32::from(self.0) << 16) | 0x1002,
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
fn policy(discovery: i32) -> pci::Policy {
    pci::Policy {
        si_built: true,
        cik_built: true,
        radeon_built: false,
        si_support: -1,
        cik_support: -1,
        experimental: 0,
        discovery,
        force_asic: -1,
        memory_encrypted: false,
        firmware_drivers_only: false,
        modeset: -1,
    }
}
fn file_function(device: u16) -> Function<FileConfig> {
    Function::new(
        Address {
            segment: 4,
            bus: 0x81,
            device: 3,
            function: 0,
        },
        FileConfig(device),
    )
    .unwrap()
}
fn make_catalog(request: &discovery::FileRequest<'_>, bytes: &[u8], member: &str) -> Catalog {
    Catalog::from_handoff(vec![firmware::Resource {
        name: request.name(),
        target: request.target(),
        provenance: firmware::Provenance {
            source: "original CPU fixture",
            revision: "immutable-input",
            member,
            license: "test-only",
        },
        expected_length: bytes.len(),
        expected_sha256: Sha256::digest(bytes).into(),
        bytes: bytes.to_vec(),
    }])
    .unwrap()
}
struct ObservedProvider<'a> {
    catalog: &'a Catalog,
    calls: Cell<u32>,
    alternate: Option<firmware::Requirement<'a>>,
}
impl Provider for ObservedProvider<'_> {
    fn load(
        &self,
        requirement: firmware::Requirement<'_>,
    ) -> Result<firmware::Image<'_>, firmware::Error> {
        assert!(
            unsafe { stela_amd_tmr_model_accesses() } > 0,
            "provider before original TMR query"
        );
        self.calls.set(self.calls.get() + 1);
        self.catalog.load(self.alternate.unwrap_or(requirement))
    }
}
fn make_provider(catalog: &Catalog) -> ObservedProvider<'_> {
    ObservedProvider {
        catalog,
        calls: Cell::new(0),
        alternate: None,
    }
}
fn facts(ip: &discovery::FileIp<'_, '_>, bytes: &[u8]) {
    assert_eq!(&ip.acquired_bytes()[..bytes.len()], bytes);
    assert!(ip.acquired_bytes()[bytes.len()..].iter().all(|&v| v == 0));
    let mut expected = discovery::IpCounts::default();
    let (mut hwips, mut instances) = (0, 0);
    unsafe {
        stela_amd_ip_oracle(
            ip.acquired_bytes().as_ptr(),
            ip.acquired_bytes().len(),
            &mut expected,
            &mut hwips,
            &mut instances,
        )
    };
    assert_eq!(ip.counts(), expected);
    for hwip in 0..hwips {
        for instance in 0..instances {
            assert_eq!(
                ip.version(hwip, instance),
                Some(unsafe { stela_amd_ip_oracle_fact(hwip, instance, 0, 0) } as u32)
            );
            let count = unsafe { stela_amd_ip_oracle_fact(hwip, instance, 0, 1) };
            if count == u64::MAX {
                assert_eq!(ip.register_count(hwip, instance), None);
            } else {
                assert_eq!(ip.register_count(hwip, instance), Some(count as u32));
                for segment in 0..count as u32 {
                    assert_eq!(
                        ip.register_base(hwip, instance, segment),
                        Some(
                            unsafe { stela_amd_ip_oracle_fact(hwip, instance, segment, 2) } as u32
                        )
                    );
                }
                assert_eq!(ip.register_base(hwip, instance, count as u32), None);
            }
        }
    }
}
pub(super) fn selected_files(authority: &Authority) {
    let mut function = file_function(0xffff);
    // SAFETY: actual public Function observes immutable synthetic config only.
    let matched = unsafe { pci::identify(&mut function, policy(2)) }.unwrap();
    assert_eq!(matched.ip_path(), pci::IpPath::Dynamic);
    let (resource, drops) = super::resource(0x1400_0000, 0x60000, ResourceKind::Registers);
    // SAFETY: canonical RAM-only owner, no genuine hardware activation claim.
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
    let mut size = 0;
    let source = unsafe { stela_amd_tmr_fixture(&mut size) };
    let source_bytes = unsafe { core::slice::from_raw_parts(source, size) };
    let begin = || unsafe {
        stela_amd_tmr_model_begin(window.direct_dword(0).unwrap().as_ptr(), source, size)
    };
    allocation_failure::arm(0);
    let no_allocation = discovery::FileRequest::new(&bars).unwrap();
    drop(no_allocation);
    assert!(!allocation_failure::disarm());
    let request = discovery::FileRequest::new(&bars).unwrap();
    assert_eq!(request.name(), "amdgpu/ip_discovery.bin");
    assert_eq!(
        request.target(),
        firmware::Target {
            driver: "amd-amdgpu-ip-discovery",
            hardware: "pci-1002-ffff",
            revision: "pci-45;subsys-abcd-5678",
            board: None
        }
    );
    let catalog = make_catalog(&request, source_bytes, "fixtures/ip-discovery.bin");
    let provider = make_provider(&catalog);
    begin();
    // SAFETY: only the bounded generated C RAM leaf handles original MM I/O.
    let discovery::SelectedFile::Dynamic(ip) =
        unsafe { request.acquire(&provider, &clock) }.unwrap()
    else {
        panic!("dynamic admission became static")
    };
    assert_eq!(provider.calls.get(), 1);
    assert_eq!(ip.identity(), bars.identity());
    assert_eq!(ip.image().bytes(), source_bytes);
    assert_eq!(
        ip.image().sha256(),
        <[u8; 32]>::from(Sha256::digest(source_bytes))
    );
    assert_eq!(ip.image().provenance().member, "fixtures/ip-discovery.bin");
    facts(&ip, source_bytes);
    information(ip, source_bytes);
    // Fresh immutable real inputs exercise original file policy/decoder unchanged.
    let mut real_inputs = 0;
    if let Ok(paths) = std::env::var("STELA_AMD_DISCOVERY_INPUTS") {
        for path in paths.lines() {
            let bytes = std::fs::read(path).unwrap();
            let request = discovery::FileRequest::new(&bars).unwrap();
            let member = std::path::Path::new(path)
                .file_name()
                .unwrap()
                .to_str()
                .unwrap();
            let catalog = make_catalog(&request, &bytes, member);
            let provider = make_provider(&catalog);
            begin();
            let discovery::SelectedFile::Dynamic(ip) =
                unsafe { request.acquire(&provider, &clock) }.unwrap()
            else {
                panic!("static")
            };
            facts(&ip, &bytes);
            assert_eq!(ip.image().bytes(), bytes);
            assert_eq!(ip.image().provenance().member, member);
            information(ip, &bytes);
            real_inputs += 1;
        }
    }
    // Each actual native Vec OOM point: query-storage precedes provider load;
    // the three IP allocations follow validated image acquisition.
    for allocation in 0..4 {
        begin();
        provider.calls.set(0);
        let request = discovery::FileRequest::new(&bars).unwrap();
        allocation_failure::arm(allocation);
        let error = unsafe { request.acquire(&provider, &clock) }.err().unwrap();
        assert!(allocation_failure::disarm());
        assert!(unsafe { stela_amd_tmr_model_accesses() } > 0);
        assert!(matches!(
            (allocation, error),
            (
                0,
                discovery::FileError::Acquire(discovery::Error::PostQueryAllocation)
            ) | (
                1..=3,
                discovery::FileError::Ip(discovery::Error::PostAcquireAllocation)
            )
        ));
        assert_eq!(provider.calls.get(), u32::from(allocation != 0));
    }
    begin();
    provider.calls.set(0);
    let error = unsafe {
        discovery::FileRequest::new(&bars).unwrap().acquire(
            &provider,
            &Clock {
                ticks_per_microsecond: 0,
            },
        )
    }
    .err()
    .unwrap();
    assert!(matches!(
        error,
        discovery::FileError::Acquire(discovery::Error::ClockUnavailable)
    ));
    assert_eq!(provider.calls.get(), 0);
    assert_eq!(unsafe { stela_amd_tmr_model_accesses() }, 0);
    for system in [false, true] {
        begin();
        provider.calls.set(0);
        unsafe {
            if system {
                stela_amd_tmr_model_system()
            } else {
                stela_amd_tmr_model_vf()
            }
        };
        let error = unsafe {
            discovery::FileRequest::new(&bars)
                .unwrap()
                .acquire(&provider, &clock)
        }
        .err()
        .unwrap();
        assert!(matches!(
            error,
            discovery::FileError::Acquire(
                discovery::Error::VfOwnerUnavailable
                    | discovery::Error::SystemFirmwareOwnerUnavailable
            )
        ));
        assert_eq!(provider.calls.get(), 0);
    }
    let empty = Catalog::from_handoff(vec![]).unwrap();
    let missing = make_provider(&empty);
    for fail_diagnostic_name in [false, true] {
        begin();
        let request = discovery::FileRequest::new(&bars).unwrap();
        if fail_diagnostic_name {
            allocation_failure::arm(1);
        }
        let error = unsafe { request.acquire(&missing, &clock) }.err().unwrap();
        if fail_diagnostic_name {
            assert!(allocation_failure::disarm());
        }
        let discovery::FileError::Source {
            error: discovery::FileSourceError::Provider(error),
            pending: discovery::FileFailureDiagnostics::OmittedByOriginalOption2,
        } = error
        else {
            panic!("wrong source failure")
        };
        assert_eq!(error.kind, firmware::ErrorKind::Missing);
        if fail_diagnostic_name {
            assert!(error.name.as_str().is_none());
        }
    }
    // A real canonical image returned for the wrong request is still refused.
    let mut alternate = make_provider(&catalog);
    alternate.alternate = Some(firmware::Requirement {
        name: "amdgpu/ip_discovery.bin",
        target: firmware::Target {
            driver: "amd-amdgpu-ip-discovery",
            hardware: "pci-1002-ffff",
            revision: "pci-45;subsys-abcd-5678",
            board: None,
        },
        minimum_bytes: 1,
    });
    // The alternate uses identical image here; verify it is accepted first.
    begin();
    drop(
        unsafe {
            discovery::FileRequest::new(&bars)
                .unwrap()
                .acquire(&alternate, &clock)
        }
        .unwrap(),
    );
    let other = Catalog::from_handoff(vec![firmware::Resource {
        name: "other.bin",
        target: firmware::Target {
            driver: "other",
            hardware: "other",
            revision: "other",
            board: None,
        },
        provenance: firmware::Provenance {
            source: "fixture",
            revision: "1",
            member: "other.bin",
            license: "test",
        },
        expected_length: source_bytes.len(),
        expected_sha256: Sha256::digest(source_bytes).into(),
        bytes: source_bytes.to_vec(),
    }])
    .unwrap();
    let mut wrong = make_provider(&other);
    wrong.alternate = Some(firmware::Requirement {
        name: "other.bin",
        target: firmware::Target {
            driver: "other",
            hardware: "other",
            revision: "other",
            board: None,
        },
        minimum_bytes: 1,
    });
    begin();
    assert!(matches!(
        unsafe {
            discovery::FileRequest::new(&bars)
                .unwrap()
                .acquire(&wrong, &clock)
        },
        Err(discovery::FileError::Source {
            error: discovery::FileSourceError::WrongImage,
            ..
        })
    ));
    let other_target = firmware::Target {
        driver: "amd-amdgpu-ip-discovery",
        hardware: "pci-1002-ffff",
        revision: "pci-46;subsys-abcd-5678",
        board: None,
    };
    let other_same_name = Catalog::from_handoff(vec![firmware::Resource {
        name: "amdgpu/ip_discovery.bin",
        target: other_target,
        provenance: firmware::Provenance {
            source: "fixture",
            revision: "1",
            member: "same-name.bin",
            license: "test",
        },
        expected_length: source_bytes.len(),
        expected_sha256: Sha256::digest(source_bytes).into(),
        bytes: source_bytes.to_vec(),
    }])
    .unwrap();
    let mut wrong_target = make_provider(&other_same_name);
    wrong_target.alternate = Some(firmware::Requirement {
        name: "amdgpu/ip_discovery.bin",
        target: other_target,
        minimum_bytes: 1,
    });
    begin();
    assert!(matches!(
        unsafe {
            discovery::FileRequest::new(&bars)
                .unwrap()
                .acquire(&wrong_target, &clock)
        },
        Err(discovery::FileError::Source {
            error: discovery::FileSourceError::WrongImage,
            ..
        })
    ));
    // A valid manifest cannot hide invalid actual bytes or a too-large source.
    let mut oversized = source_bytes.to_vec();
    oversized.extend_from_slice(&[0; 4]);
    let mut corrupt = source_bytes.to_vec();
    corrupt[0] ^= 1;
    for bytes in [&oversized[..], &corrupt[..]] {
        let request = discovery::FileRequest::new(&bars).unwrap();
        let bad = make_catalog(&request, bytes, "bad.bin");
        let bad = make_provider(&bad);
        begin();
        assert!(matches!(
            unsafe { request.acquire(&bad, &clock) },
            Err(discovery::FileError::Source {
                error: discovery::FileSourceError::Policy(_),
                pending: discovery::FileFailureDiagnostics::OmittedByOriginalOption2
            })
        ));
    }
    let mut short = source_bytes.to_vec();
    // Original binary_size field comes from the actual retained packed header;
    // fixture helper exposes it without copying a Rust wire-format definition.
    let declared = unsafe { stela_amd_file_fixture_declared(source, size) };
    assert!(declared > 16 && declared <= short.len());
    short.truncate(declared - 1);
    let request = discovery::FileRequest::new(&bars).unwrap();
    let short_catalog = make_catalog(&request, &short, "short.bin");
    let short_provider = make_provider(&short_catalog);
    begin();
    assert!(matches!(
        unsafe { request.acquire(&short_provider, &clock) },
        Err(discovery::FileError::Source {
            error: discovery::FileSourceError::Policy(_),
            ..
        })
    ));
    unsafe { stela_amd_tmr_model_end() };
    drop(window);
    unsafe { bars.retire() }.unwrap();
    drop(bars);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    // Legacy static selected-file inventory never becomes dynamic facts. Missing
    // optional inventory reports its still-pending original version/RAS check.
    for option in [-1, 2] {
        let mut function = file_function(0x6860);
        let matched = unsafe { pci::identify(&mut function, policy(option)) }.unwrap();
        assert_eq!(matched.ip_path(), pci::IpPath::SocStatic);
        let (resource, drops) = super::resource(0x1500_0000, 0x60000, ResourceKind::Registers);
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
        let request = discovery::FileRequest::new(&bars).unwrap();
        assert_eq!(
            request.name(),
            if option == 2 {
                "amdgpu/ip_discovery.bin"
            } else {
                "amdgpu/vega10_ip_discovery.bin"
            }
        );
        let good = make_catalog(&request, source_bytes, "static.bin");
        let good = make_provider(&good);
        unsafe {
            stela_amd_tmr_model_begin(window.direct_dword(0).unwrap().as_ptr(), source, size)
        };
        let discovery::SelectedFile::Static(inventory) =
            unsafe { request.acquire(&good, &clock) }.unwrap()
        else {
            panic!("static inventory became dynamic")
        };
        assert_eq!(inventory.acquired_bytes(), source_bytes);
        assert_eq!(inventory.image().provenance().member, "static.bin");
        assert_eq!(inventory.identity(), bars.identity());
        drop(inventory);
        unsafe {
            stela_amd_tmr_model_begin(window.direct_dword(0).unwrap().as_ptr(), source, size)
        };
        let error = unsafe {
            discovery::FileRequest::new(&bars)
                .unwrap()
                .acquire(&missing, &clock)
        }
        .err()
        .unwrap();
        let discovery::FileError::Source { pending, .. } = error else {
            panic!("wrong static failure")
        };
        assert_eq!(
            pending,
            if option == 2 {
                discovery::FileFailureDiagnostics::OmittedByOriginalOption2
            } else {
                discovery::FileFailureDiagnostics::DiscoveryVersionAndRasCheckRequired
            }
        );
        unsafe { stela_amd_tmr_model_end() };
        drop(window);
        unsafe { bars.retire() }.unwrap();
        drop(bars);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
    println!(
        "AMD selected-file Rust/C: actual admitted source/provider owners, query-before-load, retained image/provenance, same original facts, static inventory isolation, four Vec OOMs + provider diagnostic OOM, missing owners, pending original failure diagnostics; {real_inputs} unchanged real inputs; CPU only"
    );
}

fn information(ip: discovery::FileIp<'_, '_>, expected_bytes: &[u8]) {
    let before = ip.counts();
    let identity = ip.identity();
    let hash = ip.image().sha256();
    let provenance = ip.image().provenance();
    let source = ip.acquired_bytes().as_ptr();
    let size = ip.acquired_bytes().len();
    allocation_failure::arm(0);
    let consumed = ip
        .into_information()
        .unwrap_or_else(|_| panic!("information preflight"));
    assert!(
        !allocation_failure::disarm(),
        "information transition allocated"
    );
    assert_eq!(consumed.source_bytes().as_ptr(), source);
    assert_eq!(
        &consumed.source_bytes()[..expected_bytes.len()],
        expected_bytes
    );
    assert_eq!(consumed.preharvest_counts(), before);
    assert_eq!(consumed.identity(), identity);
    assert_eq!(consumed.image().bytes(), expected_bytes);
    assert_eq!(consumed.image().sha256(), hash);
    assert_eq!(consumed.image().provenance(), provenance);
    let mut expected = *consumed.information();
    unsafe { stela_amd_info_oracle(source, size, 0xffff, 0x45, &mut expected) };
    assert_eq!(consumed.information(), &expected);
}
