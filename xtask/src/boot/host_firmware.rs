//! Compare actual pre/post-EBS catalog records against every selected package
//! identity. Disk hashes alone do not prove what survived engine relocation.
use crate::tools::binding;
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{fs, path::Path};
use stela_loader::host_firmware::{DIRECTORY, MANIFEST_PATH, MAX_IMAGES, Manifest};

const PREFIX: &str = "HOST FIRMWARE RECORD ";
/// Ten bounded identity/provenance strings can at most double under JSON
/// escaping; this also bounds malformed records before parsing them.
const MAX_RECORD_BYTES: usize = 8 * 1024;
const MAX_RECORDS: usize = 2 * (MAX_IMAGES + 1);

fn expected(data: &[u8]) -> Result<Vec<Value>> {
    let manifest = Manifest::parse(data)?;
    let mut records = Vec::with_capacity(2 * (manifest.images.len() + 1));
    for phase in ["before-ebs", "after-ebs"] {
        records.push(json!({"kind":"manifest", "phase":phase,
            "images":manifest.images.len(), "bytes":manifest.total_bytes(),
            "sha256":stela_formats::sha256(data)}));
        for (index, image) in manifest.images.iter().enumerate() {
            let target = &image.target;
            let source = &image.provenance;
            records.push(json!({"kind":"resource", "phase":phase, "index":index,
                "name":image.name, "bytes":image.length, "sha256":image.sha256,
                "target":{"driver":target.driver, "hardware":target.hardware,
                    "revision":target.revision, "board":target.board},
                "provenance":{"source":source.source, "revision":source.revision,
                    "member":source.member, "license":source.license}}));
        }
    }
    Ok(records)
}

fn verify(expected: &[Value], serial: &str) -> Result<Vec<Value>> {
    let mut records = Vec::with_capacity(expected.len());
    for line in serial.lines().filter_map(|line| line.strip_prefix(PREFIX)) {
        ensure!(
            records.len() < MAX_RECORDS,
            "too many host firmware records"
        );
        ensure!(
            line.len() <= MAX_RECORD_BYTES,
            "host firmware record exceeds its budget"
        );
        let record = serde_json::from_str::<Value>(line)?;
        // The emitter writes compact canonical JSON. Requiring that encoding
        // also rejects duplicate object keys that Value would otherwise merge.
        let canonical = serde_json::to_vec(&record)?;
        ensure!(
            canonical == line.as_bytes(),
            "noncanonical host firmware record"
        );
        records.push(record);
    }
    ensure!(
        records.len() == expected.len(),
        "missing or duplicate host firmware phase records"
    );
    for (index, (record, expected)) in records.iter().zip(expected).enumerate() {
        ensure!(
            record == expected,
            "host firmware phase record {index} differs: expected {expected}, received {record}"
        );
    }
    Ok(records)
}

pub(super) fn report(volume: &Path, serial: &str) -> Result<Value> {
    let path = volume.join(MANIFEST_PATH);
    let data = fs::read(&path)?;
    let manifest = Manifest::parse(&data)?;
    let resources = manifest
        .images
        .iter()
        .map(|image| {
            let resource = binding(&volume.join(DIRECTORY).join(image.path))?;
            ensure!(
                resource["sha256"] == image.sha256 && resource["bytes"] == image.length,
                "host firmware disk resource differs from its manifest"
            );
            Ok(resource)
        })
        .collect::<Result<Vec<_>>>()?;
    let expected = expected(&data)?;
    let verification = verify(&expected, serial);
    let error = verification.as_ref().err().map(ToString::to_string);
    Ok(json!({"manifest":binding(&path)?, "resources":resources,
        "images":manifest.images.len(), "bytes":manifest.total_bytes(),
        "passed":verification.is_ok(), "error":error,
        "phase_records":verification.ok(), "expected_phase_records":expected}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records() -> Vec<Value> {
        let image = |name, board| {
            json!({"name":name, "path":name, "length":3,
            "sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "target":{"driver":"alternate-driver", "hardware":"1234:5678",
                "revision":"silicon/API-9", "board":board},
            "provenance":{"source":"local-package", "revision":"commit-17",
                "member":"upstream/data.bin", "license":"CC0-1.0"}})
        };
        expected(
            &serde_json::to_vec(&json!({"schema":1,"images":[
            image("one.bin", Some("board-2")), image("two.bin", None)]}))
            .unwrap(),
        )
        .unwrap()
    }

    fn serial(records: &[Value]) -> String {
        records
            .iter()
            .map(|record| format!("{PREFIX}{record}\n"))
            .collect()
    }

    #[test]
    fn exact_catalog_records_include_escaped_identity_and_both_board_forms() {
        let mut records = records();
        // Current manifests borrow literal strings and reject JSON escapes.
        // Exercise the record transport separately, so future identities stay
        // unambiguous without weakening that manifest parser contract.
        records[1]["target"]["driver"] = json!("a \"driver\"");
        records[1]["provenance"]["source"] = json!("local\\package");
        assert_eq!(verify(&records, &serial(&records)).unwrap(), records);
        assert_eq!(records[1]["target"]["driver"], "a \"driver\"");
        assert_eq!(records[1]["provenance"]["source"], "local\\package");
        assert_eq!(records[2]["target"]["board"], Value::Null);
        assert!(verify(&records, "HOST FIRMWARE phase=before-ebs images=2 bytes=6\nHOST FIRMWARE phase=after-ebs images=2 bytes=6\n").is_err());
    }

    #[test]
    fn phase_verifier_refuses_missing_duplicate_wrong_phase_and_reordered_records() {
        let expected = records();
        for index in 0..expected.len() {
            let mut changed = expected.clone();
            changed.remove(index);
            assert!(verify(&expected, &serial(&changed)).is_err());
            let mut changed = expected.clone();
            changed.insert(index, expected[index].clone());
            assert!(verify(&expected, &serial(&changed)).is_err());
            let mut changed = expected.clone();
            changed[index]["phase"] = json!("unknown-phase");
            assert!(verify(&expected, &serial(&changed)).is_err());
        }
        let mut changed = expected.clone();
        changed.swap(0, 3);
        assert!(verify(&expected, &serial(&changed)).is_err());
        changed[0] = json!({"kind":"manifest", "phase":"after-ebs"});
        assert!(verify(&expected, &serial(&changed)).is_err());
    }

    #[test]
    fn phase_verifier_refuses_changed_hash_identity_provenance_and_length() {
        let expected = records();
        for index in [0, 3] {
            let mut changed = expected.clone();
            changed[index]["sha256"] = json!("00".repeat(32));
            assert!(verify(&expected, &serial(&changed)).is_err());
        }
        for index in [1, 2, 4, 5] {
            for pointer in [
                "/name",
                "/sha256",
                "/bytes",
                "/index",
                "/target/driver",
                "/target/hardware",
                "/target/revision",
                "/target/board",
                "/provenance/source",
                "/provenance/revision",
                "/provenance/member",
                "/provenance/license",
            ] {
                let mut changed = expected.clone();
                *changed[index].pointer_mut(pointer).unwrap() = json!("changed");
                assert!(
                    verify(&expected, &serial(&changed)).is_err(),
                    "{index}: {pointer}"
                );
            }
        }
        let mut changed = expected.clone();
        changed[1]["unexpected"] = json!(true);
        assert!(verify(&expected, &serial(&changed)).is_err());
        assert!(verify(&expected, &format!("{PREFIX}{{\n")).is_err());
        let duplicate_key = serial(&expected).replacen(
            "\"kind\":\"manifest\"",
            "\"kind\":\"resource\",\"kind\":\"manifest\"",
            1,
        );
        assert!(verify(&expected, &duplicate_key).is_err());
        assert!(
            verify(
                &expected,
                &serial(&vec![expected[0].clone(); MAX_RECORDS + 1])
            )
            .is_err()
        );
        assert!(
            verify(
                &expected,
                &format!("{PREFIX}{}\n", " ".repeat(MAX_RECORD_BYTES + 1))
            )
            .is_err()
        );
    }
}
