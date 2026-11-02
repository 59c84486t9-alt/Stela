use super::*;
use alloc::vec;
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
            (target("first"), b"first-payload".as_slice()),
            (target("second"), b"second-payload".as_slice()),
        ]
        .into_iter()
        .map(|(target, bytes)| Resource {
            name: "vendor/same.bin",
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
        from_catalog(&catalog, target("second"), c"vendor/same.bin").unwrap(),
        b"second-payload"
    );
    assert_eq!(
        from_catalog(&catalog, target("first"), c"vendor/same.bin").unwrap(),
        b"first-payload"
    );
    let error = from_catalog(&catalog, target("unknown"), c"vendor/same.bin").unwrap_err();
    assert!(matches!(&error, Error::Catalog(error) if error.kind == ErrorKind::WrongTarget));
    assert_eq!(error.errno(), -13);
}
#[test]
fn misses_and_invalid_names_keep_typed_refusal() {
    let catalog = catalog();
    let error = from_catalog(&catalog, target("first"), c"vendor/missing.bin").unwrap_err();
    assert!(matches!(&error, Error::Catalog(error) if error.kind == ErrorKind::Missing));
    assert_eq!(error.errno(), -2);
    for name in [c"", c"../same.bin", c"/same.bin"] {
        let error = from_catalog(&catalog, target("first"), name).unwrap_err();
        assert!(matches!(&error, Error::Catalog(error) if error.kind == ErrorKind::InvalidName));
        assert_eq!(error.errno(), -22);
    }
    let invalid = CStr::from_bytes_with_nul(b"vendor/\xff.bin\0").unwrap();
    assert_eq!(
        from_catalog(&catalog, target("first"), invalid),
        Err(Error::InvalidEncoding)
    );
    let empty = Catalog::from_handoff(vec![]).unwrap();
    assert_eq!(
        from_catalog(&empty, target("first"), c"vendor/same.bin")
            .unwrap_err()
            .errno(),
        -2
    );
}
