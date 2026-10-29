use super::*;

// NIST SHA-256 vector; all firmware contents here are synthetic fixtures.
const ABC_SHA: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];
fn target() -> Target<'static> {
    Target {
        driver: "iwlwifi",
        hardware: "8086:2725",
        revision: "ty-a0-gf-a0",
        board: None,
    }
}
fn requirement() -> Requirement<'static> {
    Requirement {
        name: "iwlwifi-ty-a0-gf-a0-89.ucode",
        target: target(),
        minimum_bytes: 3,
    }
}
fn resource() -> Resource<'static> {
    Resource {
        name: requirement().name,
        target: target(),
        provenance: Provenance {
            source: "synthetic-fixtures",
            revision: "v1",
            member: "fixtures/abc.bin",
            license: "CC0-1.0",
        },
        expected_length: 3,
        expected_sha256: ABC_SHA,
        bytes: b"abc".to_vec(),
    }
}
fn rejected(resources: Vec<Resource<'_>>) -> ErrorKind {
    match Catalog::from_handoff(resources) {
        Err(error) => error.kind,
        Ok(_) => panic!("invalid catalog published"),
    }
}

#[test]
fn immutable_handoff_moves_buffer_and_owns_metadata() {
    let source = String::from("temporary-source");
    let revision = String::from("temporary-revision");
    let mut input = resource();
    input.provenance.source = &source;
    input.target.revision = &revision;
    let original_buffer = input.bytes.as_ptr();
    let catalog = Catalog::from_handoff(vec![input]).unwrap();
    drop(source);
    drop(revision);
    let provider: &dyn Provider = &catalog;
    let image = provider
        .load(Requirement {
            target: Target {
                revision: "temporary-revision",
                ..target()
            },
            ..requirement()
        })
        .unwrap();
    assert_eq!(image.bytes().as_ptr(), original_buffer);
    assert_eq!(image.bytes(), b"abc");
    assert_eq!(image.sha256(), ABC_SHA);
    assert_eq!(image.provenance().source, "temporary-source");
    assert_eq!(image.name(), requirement().name);
    assert_eq!(catalog.entries.len(), 1);
}

#[test]
fn optional_handoff_provider_preserves_validation_and_missing_resource_details() {
    let provider = HandoffProvider::new(None);
    let empty = Catalog::from_handoff(vec![]).unwrap();
    for request in [
        requirement(),
        Requirement {
            name: "../invalid",
            ..requirement()
        },
        Requirement {
            minimum_bytes: 0,
            ..requirement()
        },
        Requirement {
            target: Target {
                hardware: "",
                ..target()
            },
            ..requirement()
        },
    ] {
        assert_eq!(
            provider.load(request).unwrap_err(),
            empty.load(request).unwrap_err()
        );
    }
    let missing = provider.load(requirement()).unwrap_err();
    assert_eq!(missing.name, requirement().name);
    assert_eq!(missing.kind, ErrorKind::Missing);
}

#[test]
fn optional_handoff_provider_borrows_exact_catalog_images_without_fallback_or_copy() {
    let resource = resource();
    let original = resource.bytes.as_ptr();
    let catalog = Catalog::from_handoff(vec![resource]).unwrap();
    let provider = HandoffProvider::new(Some(&catalog));
    let image = provider.load(requirement()).unwrap();
    assert_eq!(image.bytes().as_ptr(), original);
    assert_eq!(image.sha256(), ABC_SHA);
    assert_eq!(image.provenance().member, "fixtures/abc.bin");
    for request in [
        Requirement {
            target: Target {
                revision: "different-api",
                ..target()
            },
            ..requirement()
        },
        Requirement {
            target: Target {
                board: Some("different-board"),
                ..target()
            },
            ..requirement()
        },
        Requirement {
            name: "another.bin",
            ..requirement()
        },
        Requirement {
            minimum_bytes: 4,
            ..requirement()
        },
    ] {
        assert_eq!(
            provider.load(request).unwrap_err(),
            catalog.load(request).unwrap_err()
        );
    }
    assert_eq!(
        provider
            .load(Requirement {
                target: Target {
                    revision: "different-api",
                    ..target()
                },
                ..requirement()
            })
            .unwrap_err()
            .kind,
        ErrorKind::WrongTarget
    );
}

#[test]
fn every_identity_component_and_name_is_exact() {
    let catalog = Catalog::from_handoff(vec![resource()]).unwrap();
    for target in [
        Target {
            driver: "btintel",
            ..target()
        },
        Target {
            hardware: "8086:2723",
            ..target()
        },
        Target {
            revision: "ty-a1-gf-a0",
            ..target()
        },
        Target {
            board: Some("oem-board"),
            ..target()
        },
    ] {
        assert_eq!(
            catalog
                .load(Requirement {
                    target,
                    ..requirement()
                })
                .unwrap_err()
                .kind,
            ErrorKind::WrongTarget
        );
    }
    assert_eq!(
        catalog
            .load(Requirement {
                name: "iwlwifi-ty-a0-gf-a0-88.ucode",
                ..requirement()
            })
            .unwrap_err()
            .kind,
        ErrorKind::Missing
    );
    let empty = Catalog::from_handoff(vec![]).unwrap();
    assert_eq!(
        empty.load(requirement()).unwrap_err().kind,
        ErrorKind::Missing
    );
}

#[test]
fn same_filename_can_bind_distinct_boards_and_revisions() {
    let mut board = resource();
    board.target.board = Some("board-one");
    board.bytes = b"abd".to_vec();
    board.expected_sha256 = Sha256::digest(&board.bytes).into();
    let mut revision = resource();
    revision.target.revision = "b0";
    let catalog = Catalog::from_handoff(vec![resource(), board, revision]).unwrap();
    assert_eq!(catalog.load(requirement()).unwrap().bytes(), b"abc");
    assert_eq!(
        catalog
            .load(Requirement {
                target: Target {
                    board: Some("board-one"),
                    ..target()
                },
                ..requirement()
            })
            .unwrap()
            .bytes(),
        b"abd"
    );
    assert_eq!(
        catalog
            .load(Requirement {
                target: Target {
                    revision: "b0",
                    ..target()
                },
                ..requirement()
            })
            .unwrap()
            .target()
            .revision,
        "b0"
    );
    assert_eq!(
        catalog
            .load(Requirement {
                target: Target {
                    board: Some("board-two"),
                    ..target()
                },
                ..requirement()
            })
            .unwrap_err()
            .kind,
        ErrorKind::WrongTarget
    );
    let mut board_only = resource();
    board_only.target.board = Some("board-one");
    let catalog = Catalog::from_handoff(vec![board_only]).unwrap();
    assert_eq!(
        catalog.load(requirement()).unwrap_err().kind,
        ErrorKind::WrongTarget
    );
}

#[test]
fn manifest_detects_truncation_extra_bytes_and_corruption() {
    for (bytes, expected_kind) in [
        (
            b"ab".to_vec(),
            ErrorKind::Truncated {
                expected: 3,
                actual: 2,
            },
        ),
        (
            b"abcd".to_vec(),
            ErrorKind::LengthMismatch {
                expected: 3,
                actual: 4,
            },
        ),
    ] {
        let mut input = resource();
        input.bytes = bytes;
        assert_eq!(rejected(vec![resource(), input]), expected_kind);
    }
    let mut input = resource();
    input.bytes[2] = b'd';
    let ErrorKind::DigestMismatch { expected, actual } = rejected(vec![input]) else {
        panic!("corruption accepted");
    };
    assert_eq!(expected, ABC_SHA);
    assert_ne!(actual, expected);
}

#[test]
fn duplicate_and_conflicting_bindings_are_rejected() {
    assert_eq!(rejected(vec![resource(), resource()]), ErrorKind::Duplicate);
    let mut different = resource();
    different.bytes = b"abd".to_vec();
    different.expected_sha256 = Sha256::digest(&different.bytes).into();
    assert_eq!(rejected(vec![resource(), different]), ErrorKind::Conflict);
    let mut provenance = resource();
    provenance.provenance.revision = "v2";
    assert_eq!(rejected(vec![resource(), provenance]), ErrorKind::Conflict);
}

#[test]
fn canonical_paths_and_nonempty_identities_are_required() {
    for name in [
        "", "/abc", "abc/", "a//b", "a/./b", "a/../b", "a\\b", "a\0b", "a\nb",
    ] {
        let mut input = resource();
        input.name = name;
        assert_eq!(rejected(vec![input]), ErrorKind::InvalidName);
    }
    for (field, target) in [
        (
            "driver",
            Target {
                driver: "",
                ..target()
            },
        ),
        (
            "hardware",
            Target {
                hardware: "bad\0id",
                ..target()
            },
        ),
        (
            "revision",
            Target {
                revision: "",
                ..target()
            },
        ),
        (
            "board",
            Target {
                board: Some(""),
                ..target()
            },
        ),
    ] {
        let mut input = resource();
        input.target = target;
        assert_eq!(rejected(vec![input]), ErrorKind::InvalidTarget(field));
    }
    let mut input = resource();
    input.provenance.member = "../firmware";
    assert_eq!(
        rejected(vec![input]),
        ErrorKind::InvalidProvenance("member")
    );
    let mut input = resource();
    input.provenance.source = "";
    assert_eq!(
        rejected(vec![input]),
        ErrorKind::InvalidProvenance("source")
    );
    let mut input = resource();
    input.provenance.revision = "";
    assert_eq!(
        rejected(vec![input]),
        ErrorKind::InvalidProvenance("revision")
    );
    let mut input = resource();
    input.provenance.license = "";
    assert_eq!(
        rejected(vec![input]),
        ErrorKind::InvalidProvenance("license")
    );
}

#[test]
fn invalid_name_diagnostics_escape_control_characters() {
    let mut input = resource();
    input.name = "bad\n\0\x1b[31m";
    let error = Catalog::from_handoff(vec![input]).err().unwrap();
    let rendered = alloc::format!("{error}");
    assert_eq!(
        rendered,
        "firmware \"bad\\n\\0\\u{1b}[31m\": invalid resource name"
    );
    assert!(!rendered.chars().any(char::is_control));
}

#[test]
fn valid_manifest_does_not_override_driver_minimum_length() {
    let catalog = Catalog::from_handoff(vec![resource()]).unwrap();
    assert_eq!(
        catalog
            .load(Requirement {
                minimum_bytes: 4,
                ..requirement()
            })
            .unwrap_err()
            .kind,
        ErrorKind::Truncated {
            expected: 4,
            actual: 3
        }
    );
    assert_eq!(
        catalog
            .load(Requirement {
                minimum_bytes: 0,
                ..requirement()
            })
            .unwrap_err()
            .kind,
        ErrorKind::InvalidRequirement
    );
    let mut input = resource();
    input.bytes.clear();
    input.expected_length = 0;
    input.expected_sha256 = Sha256::digest([]).into();
    let catalog = Catalog::from_handoff(vec![input]).unwrap();
    assert_eq!(
        catalog.load(requirement()).unwrap_err().kind,
        ErrorKind::Truncated {
            expected: 3,
            actual: 0
        }
    );
}
