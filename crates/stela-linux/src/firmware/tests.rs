use super::*;
use crate::catalogue::FirmwareTarget;
use alloc::{sync::Arc, vec};
use stela_crypto::{Sha256, digest::Digest};
use stela_driver_core::firmware::{Provenance, Resource};

fn target(revision: &'static str) -> Target<'static> {
    Target {
        driver: "fixture-driver",
        hardware: "fixture-hardware",
        revision,
        board: None,
    }
}
fn catalog() -> Catalog {
    Catalog::from_handoff(
        [
            (
                "vendor/same.bin",
                target("first"),
                b"first-payload".as_slice(),
            ),
            (
                "vendor/same.bin",
                target("second"),
                b"second-payload".as_slice(),
            ),
            (
                "vendor/other.bin",
                target("first"),
                b"other-device".as_slice(),
            ),
        ]
        .into_iter()
        .map(|(name, target, bytes)| Resource {
            name,
            target,
            provenance: Provenance {
                source: "synthetic-fixture",
                revision: "v1",
                member: "fixtures/same.bin",
                license: "CC0-1.0",
            },
            expected_length: bytes.len(),
            expected_sha256: Sha256::digest(bytes).into(),
            bytes: bytes.to_vec(),
        })
        .collect(),
    )
    .unwrap()
}
#[test]
fn same_name_routes_only_by_exact_qualified_target() {
    let catalog = catalog();
    assert_eq!(
        from_catalog(&catalog, target("second"), "vendor/same.bin").unwrap(),
        b"second-payload"
    );
    assert_eq!(
        from_catalog(&catalog, target("first"), "vendor/same.bin").unwrap(),
        b"first-payload"
    );
    let error = from_catalog(&catalog, target("unknown"), "vendor/same.bin").unwrap_err();
    assert!(matches!(&error, Error::Catalog(error) if error.kind == ErrorKind::WrongTarget));
    assert_eq!(error.errno(), -13);
}

#[test]
fn pci_lookup_requires_both_the_selected_name_and_the_exact_target() {
    let catalog = Arc::new(catalog());
    let labels = target("first");
    let selected = FirmwareTarget::new(
        labels.driver.into(),
        labels.hardware.into(),
        labels.revision.into(),
        None,
    )
    .unwrap();
    let selection = PciFirmware::new(
        selected,
        catalog.clone(),
        vec!["vendor/same.bin".into(), "vendor/missing.bin".into()].into_boxed_slice(),
    )
    .unwrap();
    assert_eq!(
        from_pci(&selection, "vendor/same.bin").unwrap(),
        b"first-payload"
    );
    assert_eq!(
        from_catalog(&catalog, labels, "vendor/other.bin").unwrap(),
        b"other-device"
    );
    assert_eq!(
        from_pci(&selection, "vendor/other.bin"),
        Err(Error::UnapprovedImage)
    );
    assert_eq!(
        from_pci(&selection, "vendor/other.bin")
            .unwrap_err()
            .errno(),
        -13
    );
    assert_eq!(
        from_pci(&selection, "vendor/missing.bin")
            .unwrap_err()
            .errno(),
        -2
    );
    assert_eq!(
        from_pci(&selection, "vendor/../same.bin")
            .unwrap_err()
            .errno(),
        -22
    );
}
#[test]
fn misses_and_invalid_names_keep_typed_refusal() {
    let catalog = catalog();
    let error = from_catalog(&catalog, target("first"), "vendor/missing.bin").unwrap_err();
    assert!(matches!(&error, Error::Catalog(error) if error.kind == ErrorKind::Missing));
    assert_eq!(error.errno(), -2);
    for name in ["", "../same.bin", "/same.bin"] {
        let error = from_catalog(&catalog, target("first"), name).unwrap_err();
        assert!(matches!(&error, Error::Catalog(error) if error.kind == ErrorKind::InvalidName));
        assert_eq!(error.errno(), -22);
    }
    let invalid = c"vendor/\xff.bin";
    assert_eq!(decode_name(invalid), Err(Error::InvalidEncoding));
    let empty = Catalog::from_handoff(vec![]).unwrap();
    assert_eq!(
        from_catalog(&empty, target("first"), "vendor/same.bin")
            .unwrap_err()
            .errno(),
        -2
    );
}
