use super::*;
use crate::Cli;
use clap::Parser;

#[test]
fn research_state_json_retains_vector_bits_and_fp_status() -> Result<()> {
    let mut state = stela_compiler::GuestState::default();
    state.v[0] = [u64::MAX, 0x7ff8000000001234];
    state.v[31] = [0x0123456789abcdef, 0xfedcba9876543210];
    state.fpcr = 0x03c00000;
    state.fpsr = 0x0800009f;
    let input: RegisterInput = serde_json::from_value(register_json(&state))?;
    assert_eq!(input.v, state.v);
    assert_eq!(input.fpcr, state.fpcr);
    assert_eq!(input.fpsr, state.fpsr);
    // Older scalar-only inputs are accepted with zeroed SIMD state.
    let scalar: RegisterInput = serde_json::from_value(serde_json::json!({"x":([0u64;31])}))?;
    assert_eq!(scalar.v, [[0; 2]; 32]);
    assert_eq!((scalar.fpcr, scalar.fpsr), (0, 0));
    Ok(())
}

#[test]
fn research_state_rejects_truncated_vectors_and_unknown_fields() {
    for value in [
        serde_json::json!({"x":([0u64;31]),"v":[[0,0]]}),
        serde_json::json!({"x":([0u64;31]),"fpcrr":0}),
    ] {
        assert!(serde_json::from_value::<RegisterInput>(value).is_err());
    }
}

#[test]
fn full_pauth_keys_and_owned_memory_cli_inputs_are_explicit_and_strict() -> Result<()> {
    let folder = tempfile::tempdir()?;
    let path = folder.path().join("keys.json");
    let valid = r#"{"ia":{"low":1,"high":2},"ib":{"low":3,"high":4},"da":{"low":5,"high":6},"db":{"low":7,"high":8}}"#;
    std::fs::write(&path, valid)?;
    let context = pauth_all_keys_context(&path, 92)?;
    assert_eq!(context.address_space(), 92);
    for key in [
        stela_runtime::pauth::Key::Ia,
        stela_runtime::pauth::Key::Ib,
        stela_runtime::pauth::Key::Da,
        stela_runtime::pauth::Key::Db,
    ] {
        assert!(context.has_key(key));
    }
    for invalid in [
        r#"{"low":1,"high":2}"#,
        r#"{"ia":{"low":1,"high":2},"ib":{"low":3,"high":4},"da":{"low":5,"high":6}}"#,
    ] {
        std::fs::write(&path, invalid)?;
        assert!(pauth_all_keys_context(&path, 92).is_err());
    }
    let mut padded = valid.to_owned();
    padded.push_str(&" ".repeat(4096 - valid.len()));
    std::fs::write(&path, &padded)?;
    assert!(pauth_all_keys_context(&path, 92).is_ok());
    padded.push(' ');
    std::fs::write(&path, padded)?;
    assert!(pauth_all_keys_context(&path, 92).is_err());
    assert!(
        Cli::try_parse_from([
            "stela",
            "run-blocks",
            "code.arm64",
            "--software-pauth-keys",
            "keys.json"
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "stela",
            "run-blocks",
            "code.arm64",
            "--software-pauth-keys",
            "keys.json",
            "--software-pauth-ib-key",
            "ib.json"
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "stela",
            "run-blocks",
            "code.arm64",
            "--software-pauth-keys",
            "keys.json",
            "--clock-snapshot",
            "clock.json"
        ])
        .is_ok()
    );
    let memory = folder.path().join("memory.json");
    std::fs::write(&memory, r#"{"regions":[]}"#)?;
    assert!(raw_memory(Some(&memory))?.regions().is_empty());
    for invalid in [
        r#"{"regions":[],"extra":1}"#,
        r#"{"regions":[{"guest_address":0,"virtual_bytes":4096,"initial_bytes":[],"readable":true,"writable":false,"executable":true}]}"#,
    ] {
        std::fs::write(&memory, invalid)?;
        assert!(raw_memory(Some(&memory)).is_err());
    }
    std::fs::write(&memory, vec![b' '; 4 * 1024 * 1024 + 1])?;
    assert!(raw_memory(Some(&memory)).is_err());
    let payload = folder.path().join("payload.bin");
    std::fs::write(&payload, [9, 8, 7, 6, 5, 4])?;
    let region = serde_json::json!({"guest_address":0,"virtual_bytes":4096,
        "readable":true,"writable":false,
        "initial_file":{"path":"payload.bin","offset":2,"bytes":3,
            "sha256":stela_core::sha256(&[7,6,5])}});
    let parsed: RawMemoryRegionInput = serde_json::from_value(region.clone())?;
    assert_eq!(raw_initial_bytes(&parsed, folder.path())?, [7, 6, 5]);
    for change in [
        serde_json::json!({"offset":5}),
        serde_json::json!({"offset":u64::MAX}),
        serde_json::json!({"bytes":4097}),
        serde_json::json!({"sha256":"wrong"}),
        serde_json::json!({"path":"missing.bin"}),
    ] {
        let mut invalid = region.clone();
        for (key, value) in change.as_object().unwrap() {
            invalid["initial_file"][key] = value.clone();
        }
        let parsed = serde_json::from_value(invalid)?;
        assert!(raw_initial_bytes(&parsed, folder.path()).is_err());
    }
    let mut conflicting = region;
    conflicting["initial_bytes"] = serde_json::json!([]);
    assert!(raw_initial_bytes(&serde_json::from_value(conflicting)?, folder.path()).is_err());
    Ok(())
}

#[test]
fn snapshot_input_is_strict_bounded_and_validated() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("clock.json");
    for input in [
        r#"{"counter":10,"sleep_ticks":11}"#,
        r#"{"counter":-1,"sleep_ticks":0}"#,
        r#"{"counter":10}"#,
        r#"{"counter":10,"sleep_ticks":0,"frequency":1}"#,
        r#"{"counter":10,"counter":11,"sleep_ticks":0}"#,
    ] {
        std::fs::write(&path, input)?;
        assert!(clock_snapshot(&path).is_err());
    }
    let valid = r#"{"counter":130,"sleep_ticks":40}"#;
    let mut boundary = valid.to_owned();
    boundary.extend(std::iter::repeat_n(' ', 4096 - valid.len()));
    std::fs::write(&path, &boundary)?;
    assert_eq!(
        clock_snapshot(&path)?,
        stela_runtime::clock::Snapshot {
            counter: 130,
            sleep_ticks: 40
        }
    );
    boundary.push(' ');
    std::fs::write(&path, boundary)?;
    assert!(clock_snapshot(&path).is_err());
    Ok(())
}
