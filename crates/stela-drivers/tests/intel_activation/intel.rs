//! Exercise the public native modules and their linked C library.
pub use stela_drivers::gpu::intel::{activation, firmware, wopcm};

use crate::firmware::{Catalog, ErrorKind, Provenance, Provider, Requirement, Resource};
use firmware::{Diagnostics, Error, Version};
use sha2::{Digest, Sha256};

pub(super) fn bytes(release: Version) -> Vec<u8> {
    // Original packed CSS128, uCode16 and RSA256; modulus/exponent lengths
    // remain declared while those optional bytes are absent.
    let mut bytes = vec![0; 400];
    for (word, value) in [
        (1, 32 + 64 + 64 + 1),
        (6, 32 + 64 + 64 + 1 + 4),
        (7, 64),
        (8, 64),
        (9, 1),
        (16, release.major << 16 | release.minor << 8 | release.patch),
        (17, 1 << 16 | 26 << 8 | 2),
        (30, 4096),
        (31, 1 << 2),
    ] {
        bytes[word * 4..word * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}
pub(super) fn catalog_for(request: &firmware::Request<'_>, bytes: Vec<u8>) -> Catalog {
    let digest = Sha256::digest(&bytes).into();
    Catalog::from_handoff(vec![Resource {
        name: request.name(),
        target: request.target(),
        provenance: Provenance {
            source: "synthetic-css-offline-fixture",
            revision: "xe-source-3f08a3b54062842f268da77f913aab57c3c09fb4",
            member: "synthetic/css-test.bin",
            license: "MIT test data",
        },
        expected_length: bytes.len(),
        expected_sha256: digest,
        bytes,
    }])
    .unwrap()
}

pub fn canonical_catalog_contract(device: &activation::Device) {
    let request = device.guc_firmware().unwrap();
    assert_eq!(request.name(), "i915/tgl_guc_70.bin");
    assert_eq!(request.target().driver, "intel-xe-guc");
    assert_eq!(request.target().hardware, "pci-8086-9a49");
    assert_eq!(
        request.target().revision,
        "pci-00;gfx-1200.0;media-1200.0;gt-main;tile-0"
    );
    assert_eq!(request.target().board, None);
    assert_eq!(
        request.wanted(),
        Version {
            major: 70,
            minor: 44,
            patch: 1
        }
    );
    assert!(!request.full_version_required());
    let input = bytes(request.wanted());
    let pointer = input.as_ptr();
    let digest: [u8; 32] = Sha256::digest(&input).into();
    let catalog = catalog_for(&request, input);
    let image = request.load(&catalog).unwrap();
    assert_eq!(
        image.image().bytes().as_ptr(),
        pointer,
        "provider image must stay borrowed, not copied"
    );
    assert_eq!(image.image().sha256(), digest);
    assert_eq!(
        image.image().provenance().source,
        "synthetic-css-offline-fixture"
    );
    assert_eq!(image.image().provenance().member, "synthetic/css-test.bin");
    assert_eq!(image.identity().device, 0x9a49);
    assert_eq!(image.facts(), device.facts().unwrap());
    assert_eq!(image.wanted(), request.wanted());
    let metadata = image.metadata();
    assert_eq!(metadata.release, request.wanted());
    assert_eq!(
        metadata.submission,
        Version {
            major: 1,
            minor: 26,
            patch: 2
        }
    );
    assert_eq!(
        (
            metadata.ucode_bytes,
            metadata.rsa_bytes,
            metadata.upload_bytes
        ),
        (16, 256, 144)
    );
    assert_eq!(
        (
            metadata.private_bytes,
            metadata.build_type,
            metadata.diagnostics.bits()
        ),
        (4096, 1, 0)
    );
    let empty = Catalog::from_handoff(vec![]).unwrap();
    assert!(matches!(
        request.load(&empty),
        Err(Error::Provider(crate::firmware::Error {
            kind: ErrorKind::Missing,
            ..
        }))
    ));
    let short = catalog_for(&request, vec![0; 127]);
    assert!(matches!(
        request.load(&short),
        Err(Error::Provider(crate::firmware::Error {
            kind: ErrorKind::Truncated {
                expected: 128,
                actual: 127
            },
            ..
        }))
    ));
    // A safe Provider can ignore a requested lower bound while returning a
    // Image. The native parser must still enforce its readable span.
    struct BelowMinimum<'a>(&'a Catalog);
    impl Provider for BelowMinimum<'_> {
        fn load(
            &self,
            requirement: Requirement<'_>,
        ) -> Result<crate::firmware::Image<'_>, crate::firmware::Error> {
            self.0.load(Requirement {
                minimum_bytes: 1,
                ..requirement
            })
        }
    }
    assert!(matches!(request.load(&BelowMinimum(&short)),
        Err(Error::Parse { status: -61, diagnostics }) if diagnostics.bits() == Diagnostics::SHORT_HEADER));
    for (header_dw, size_dw, expected) in [
        (162u32, 166u32, Diagnostics::HEADER_SIZE),
        (161, 166, Diagnostics::SHORT_IMAGE),
    ] {
        let mut malformed = bytes(request.wanted());
        malformed[4..8].copy_from_slice(&header_dw.to_le_bytes());
        malformed[24..28].copy_from_slice(&size_dw.to_le_bytes());
        let malformed = catalog_for(&request, malformed);
        assert!(
            matches!(request.load(&malformed), Err(Error::Parse { diagnostics, .. }) if diagnostics.bits() == expected)
        );
    }
    let wrong = Catalog::from_handoff(vec![Resource {
        name: request.name(),
        target: crate::firmware::Target {
            revision: "wrong-silicon",
            ..request.target()
        },
        provenance: image.image().provenance(),
        expected_length: 400,
        expected_sha256: digest,
        bytes: bytes(request.wanted()),
    }])
    .unwrap();
    assert!(matches!(
        request.load(&wrong),
        Err(Error::Provider(crate::firmware::Error {
            kind: ErrorKind::WrongTarget,
            ..
        }))
    ));
    assert!(matches!(
        Catalog::from_handoff(vec![Resource {
            name: request.name(),
            target: request.target(),
            provenance: image.image().provenance(),
            expected_length: 400,
            expected_sha256: [0; 32],
            bytes: bytes(request.wanted()),
        }]),
        Err(crate::firmware::Error {
            kind: ErrorKind::DigestMismatch { .. },
            ..
        })
    ));
    for (release, expected) in [
        (
            Version {
                major: 69,
                minor: 255,
                patch: 255,
            },
            Diagnostics::GUC_TOO_OLD,
        ),
        (
            Version {
                major: 70,
                minor: 29,
                patch: 1,
            },
            Diagnostics::GUC_TOO_OLD,
        ),
        (
            Version {
                major: 71,
                minor: 0,
                patch: 0,
            },
            Diagnostics::VERSION_MISMATCH,
        ),
    ] {
        let candidate = catalog_for(&request, bytes(release));
        assert!(
            matches!(request.load(&candidate), Err(Error::Parse { diagnostics, .. }) if diagnostics.bits() == expected)
        );
    }
    let older = catalog_for(
        &request,
        bytes(Version {
            major: 70,
            minor: 30,
            patch: 0,
        }),
    );
    assert_eq!(
        request.load(&older).unwrap().metadata().diagnostics.bits(),
        Diagnostics::RECOMMENDED_NEWER
    );
    let mut overflow = bytes(request.wanted());
    overflow[24..28].copy_from_slice(&0u32.to_le_bytes());
    let overflow = catalog_for(&request, overflow);
    assert!(
        matches!(request.load(&overflow), Err(Error::Parse { status: -75, diagnostics }) if diagnostics.bits() == Diagnostics::UNREPRESENTABLE)
    );
    struct Misdirected<'a>(&'a Catalog);
    impl Provider for Misdirected<'_> {
        fn load(
            &self,
            requirement: Requirement<'_>,
        ) -> Result<crate::firmware::Image<'_>, crate::firmware::Error> {
            self.0.load(Requirement {
                target: crate::firmware::Target {
                    revision: "wrong-silicon",
                    ..requirement.target
                },
                ..requirement
            })
        }
    }
    assert!(matches!(
        request.load(&Misdirected(&wrong)),
        Err(Error::WrongImage)
    ));
}

fn huc_catalog(request: &firmware::HucRequest<'_>, input: Vec<u8>) -> Catalog {
    let requirement = request.requirement().unwrap();
    Catalog::from_handoff(vec![Resource {
        name: requirement.name,
        target: requirement.target,
        provenance: Provenance {
            source: "synthetic-huc-offline-fixture",
            revision: "xe-source-3f08a3b54062842f268da77f913aab57c3c09fb4",
            member: "synthetic/huc-test.bin",
            license: "MIT test data",
        },
        expected_length: input.len(),
        expected_sha256: Sha256::digest(&input).into(),
        bytes: input,
    }])
    .unwrap()
}

pub fn huc_catalog_contract(device: &activation::Device) {
    use firmware::HucDisposition;
    let request = device.huc_firmware().unwrap();
    assert_eq!(request.disposition(), HucDisposition::Selected);
    assert_eq!(request.name(), Some("i915/tgl_huc.bin"));
    assert_eq!(request.target().driver, "intel-xe-huc");
    assert_eq!(request.target().hardware, "pci-8086-9a49");
    assert_eq!(
        request.target().revision,
        device.guc_firmware().unwrap().target().revision
    );
    assert_eq!(request.wanted(), Some(Version::default()));
    assert!(!request.full_version_required());
    let release = Version {
        major: 1,
        minor: 2,
        patch: 3,
    };
    let input = bytes(release);
    let pointer = input.as_ptr();
    let digest: [u8; 32] = Sha256::digest(&input).into();
    let catalog = huc_catalog(&request, input);
    crate::allocation_failure::arm(0);
    let loaded = request.load(&catalog);
    let observed = crate::allocation_failure::disarm();
    let loaded = loaded.unwrap();
    assert_eq!(
        observed.attempts, 0,
        "actual positive load/parser must allocate nothing"
    );
    assert_eq!(loaded.image().bytes().as_ptr(), pointer);
    assert_eq!(loaded.image().sha256(), digest);
    assert_eq!(
        loaded.image().provenance().source,
        "synthetic-huc-offline-fixture"
    );
    assert_eq!(loaded.identity().device, 0x9a49);
    assert_eq!(loaded.facts(), device.facts().unwrap());
    assert_eq!(loaded.wanted(), Version::default());
    let metadata = loaded.metadata();
    assert_eq!(
        metadata.release, release,
        "GuC-only minimum version must never leak into HuC"
    );
    assert_eq!(
        (
            metadata.ucode_bytes,
            metadata.rsa_bytes,
            metadata.upload_bytes,
            metadata.css_offset
        ),
        (16, 256, 144, 0)
    );
    assert!(!metadata.has_gsc_headers());
    assert_eq!(metadata.diagnostics.bits(), 0);

    let empty = Catalog::from_handoff(vec![]).unwrap();
    crate::allocation_failure::arm(0);
    let missing = request.load(&empty);
    let observed = crate::allocation_failure::disarm();
    assert_eq!(observed.attempts, 1);
    assert!(observed.failed);
    match missing {
        Err(Error::Provider(crate::firmware::Error {
            kind: ErrorKind::Missing,
            name:
                crate::firmware::ErrorName::AllocationFailed {
                    original_bytes,
                    sha256,
                },
        })) => {
            assert_eq!(original_bytes, request.name().unwrap().len());
            assert_eq!(
                sha256,
                <[u8; 32]>::from(Sha256::digest(request.name().unwrap().as_bytes()))
            );
        }
        _ => panic!("selected HuC failure must retain its actual diagnostic identity under OOM"),
    }
    let short = huc_catalog(&request, vec![0; 127]);
    crate::allocation_failure::arm(0);
    let truncated = request.load(&short);
    let observed = crate::allocation_failure::disarm();
    assert_eq!(observed.attempts, 1);
    assert!(observed.failed);
    assert!(matches!(
        truncated,
        Err(Error::Provider(crate::firmware::Error {
            kind: ErrorKind::Truncated {
                expected: 128,
                actual: 127
            },
            name: crate::firmware::ErrorName::AllocationFailed { .. },
        }))
    ));
    struct BelowMinimum<'a>(&'a Catalog);
    impl Provider for BelowMinimum<'_> {
        fn load(
            &self,
            requirement: Requirement<'_>,
        ) -> Result<crate::firmware::Image<'_>, crate::firmware::Error> {
            self.0.load(Requirement {
                minimum_bytes: 1,
                ..requirement
            })
        }
    }
    assert!(matches!(request.load(&BelowMinimum(&short)),
        Err(Error::Parse { status: -61, diagnostics }) if diagnostics.bits() == Diagnostics::SHORT_HEADER));
    let mut cpd = vec![0; 784];
    cpd[0..4].copy_from_slice(&0x44504324u32.to_le_bytes());
    cpd[4..8].copy_from_slice(&2u32.to_le_bytes());
    cpd[10] = 20;
    cpd[20..29].copy_from_slice(b"HUCP.man\0");
    cpd[32..36].copy_from_slice(&160u32.to_le_bytes());
    cpd[44..51].copy_from_slice(b"huc_fw\0");
    cpd[56..60].copy_from_slice(&384u32.to_le_bytes());
    cpd[384..].copy_from_slice(&bytes(release));
    let cpd = huc_catalog(&request, cpd);
    let loaded = request.load(&cpd).unwrap();
    assert!(loaded.metadata().has_gsc_headers());
    assert_eq!(loaded.metadata().css_offset, 384);
    assert_eq!(loaded.metadata().upload_bytes, 144);
    assert_eq!(loaded.metadata().release, release);
    for (change, expected_status, expected_diagnostic) in [
        (0, -22, Diagnostics::CPD_HEADER_LENGTH),
        (1, -61, Diagnostics::CPD_SHORT_IMAGE),
        (2, -61, Diagnostics::CPD_MISSING_MANIFEST),
    ] {
        let mut bad = cpd
            .load(request.requirement().unwrap())
            .unwrap()
            .bytes()
            .to_vec();
        match change {
            0 => bad[10] = 19,
            1 => bad[4..8].copy_from_slice(&1000u32.to_le_bytes()),
            _ => bad[20] = b'x',
        }
        let bad = huc_catalog(&request, bad);
        crate::allocation_failure::arm(0);
        let refused = request.load(&bad);
        let observed = crate::allocation_failure::disarm();
        assert_eq!(observed.attempts, 0);
        assert!(matches!(refused, Err(Error::Parse { status, diagnostics })
            if status == expected_status && diagnostics.bits() == expected_diagnostic));
    }

    // Safe Provider can return another image; exact filename/target
    // are rechecked at the native consumer, even after catalog validation.
    let requirement = request.requirement().unwrap();
    let wrong = Catalog::from_handoff(vec![Resource {
        name: "i915/wrong_huc.bin",
        target: requirement.target,
        provenance: loaded.image().provenance(),
        expected_length: 400,
        expected_sha256: digest,
        bytes: bytes(release),
    }])
    .unwrap();
    struct Misdirected<'a>(&'a Catalog);
    impl Provider for Misdirected<'_> {
        fn load(
            &self,
            requirement: Requirement<'_>,
        ) -> Result<crate::firmware::Image<'_>, crate::firmware::Error> {
            self.0.load(Requirement {
                name: "i915/wrong_huc.bin",
                ..requirement
            })
        }
    }
    assert!(matches!(
        request.load(&Misdirected(&wrong)),
        Err(Error::WrongImage)
    ));
}
