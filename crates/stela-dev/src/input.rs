//! JSON and file inputs: register state, PAuth keys, guest memory and clocks.
use anyhow::{Context, Result, ensure};
use std::{fs::File, path::PathBuf};

#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegisterInput {
    pub(crate) x: [u64; 31],
    #[serde(default)]
    pub(crate) sp: u64,
    #[serde(default)]
    pub(crate) nzcv: u32,
    #[serde(default)]
    pub(crate) reserved: u32,
    /// Little-endian low/high 64-bit limbs of each architectural V register.
    #[serde(default)]
    pub(crate) v: [[u64; 2]; 32],
    #[serde(default)]
    pub(crate) fpcr: u32,
    #[serde(default)]
    pub(crate) fpsr: u32,
}

pub(crate) fn register_json(state: &stela_compiler::GuestState) -> serde_json::Value {
    serde_json::json!({"x":state.x,"sp":state.sp,"nzcv":state.nzcv,"reserved":state.reserved,
        "v":state.v,"fpcr":state.fpcr,"fpsr":state.fpsr})
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PauthKeyInput {
    pub(crate) low: u64,
    pub(crate) high: u64,
}

pub(crate) fn pauth_context(
    path: &std::path::Path,
    address_space: u64,
) -> Result<stela_runtime::pauth::Context> {
    pauth_context_version(path, address_space, stela_runtime::pauth::Version::Classic)
}

pub(crate) fn pauth_context_version(
    path: &std::path::Path,
    address_space: u64,
    version: stela_runtime::pauth::Version,
) -> Result<stela_runtime::pauth::Context> {
    use std::io::Read;
    let mut bytes = Vec::new();
    File::open(path)?.take(4097).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 4096,
        "software PAuth key input exceeds 4096 bytes"
    );
    let keys: PauthKeyInput = serde_json::from_slice(&bytes)?;
    Ok(stela_runtime::pauth::Context::new_with_version(
        address_space,
        stela_runtime::pauth::Keys::from_ib_words(keys.low, keys.high),
        version,
    ))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PauthKeysInput {
    pub(crate) ia: PauthKeyInput,
    pub(crate) ib: PauthKeyInput,
    pub(crate) da: PauthKeyInput,
    pub(crate) db: PauthKeyInput,
}

pub(crate) fn pauth_all_keys_context(
    path: &std::path::Path,
    address_space: u64,
) -> Result<stela_runtime::pauth::Context> {
    use std::io::Read;
    let mut bytes = Vec::new();
    File::open(path)?.take(4097).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 4096,
        "software PAuth keys input exceeds 4096 bytes"
    );
    let keys: PauthKeysInput = serde_json::from_slice(&bytes)?;
    Ok(stela_runtime::pauth::Context::new(
        address_space,
        stela_runtime::pauth::Keys::from_words(
            [keys.ia.low, keys.ia.high],
            [keys.ib.low, keys.ib.high],
            [keys.da.low, keys.da.high],
            [keys.db.low, keys.db.high],
        ),
    ))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawMemoryInput {
    pub(crate) regions: Vec<RawMemoryRegionInput>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawMemoryRegionInput {
    pub(crate) guest_address: u64,
    pub(crate) virtual_bytes: u64,
    pub(crate) initial_bytes: Option<Vec<u8>>,
    pub(crate) initial_file: Option<RawMemoryFileInput>,
    pub(crate) readable: bool,
    pub(crate) writable: bool,
    pub(crate) maximum_readable: Option<bool>,
    pub(crate) maximum_writable: Option<bool>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawMemoryFileInput {
    pub(crate) path: PathBuf,
    #[serde(default)]
    pub(crate) offset: u64,
    pub(crate) bytes: u64,
    sha256: String,
}

pub(crate) fn raw_initial_bytes(
    region: &RawMemoryRegionInput,
    directory: &std::path::Path,
) -> Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    ensure!(
        region.initial_bytes.is_none() || region.initial_file.is_none(),
        "raw memory must select inline bytes or a file, not both"
    );
    if let Some(source) = &region.initial_file {
        ensure!(
            source.bytes <= region.virtual_bytes
                && source.bytes <= stela_runtime::memory::MAX_IMAGE_MEMORY_BYTES,
            "raw memory file bytes exceed region or input bound"
        );
        let end = source
            .offset
            .checked_add(source.bytes)
            .context("raw memory file extent overflow")?;
        let mut file = File::open(directory.join(&source.path))?;
        ensure!(
            file.metadata()?.is_file(),
            "raw memory source must be an ordinary file"
        );
        ensure!(
            end <= file.metadata()?.len(),
            "raw memory file extent exceeds source"
        );
        let mut bytes = vec![0; usize::try_from(source.bytes)?];
        file.seek(SeekFrom::Start(source.offset))?;
        file.read_exact(&mut bytes)?;
        ensure!(
            stela_formats::sha256(&bytes) == source.sha256,
            "raw memory file hash differs"
        );
        Ok(bytes)
    } else {
        let bytes = region.initial_bytes.clone().unwrap_or_default();
        ensure!(
            bytes.len() as u64 <= region.virtual_bytes,
            "raw initial bytes exceed region"
        );
        Ok(bytes)
    }
}

pub(crate) fn raw_memory(
    path: Option<&std::path::Path>,
) -> Result<stela_runtime::memory::OwnedMemory> {
    use std::io::Read;
    let Some(path) = path else {
        return stela_runtime::memory::OwnedMemory::map(vec![]);
    };
    let mut bytes = Vec::new();
    File::open(path)?
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 4 * 1024 * 1024,
        "raw memory input exceeds 4 MiB"
    );
    let input: RawMemoryInput = serde_json::from_slice(&bytes)?;
    ensure!(
        input.regions.len() <= 1024,
        "raw memory region count exceeds 1024"
    );
    let mut limits = Vec::new();
    let mut specs = Vec::new();
    let mut total = 0u64;
    for r in input.regions {
        total = total
            .checked_add(r.virtual_bytes)
            .context("raw memory extent overflow")?;
        ensure!(
            total <= stela_runtime::memory::MAX_IMAGE_MEMORY_BYTES,
            "raw memory exceeds input bound"
        );
        let initial_bytes = raw_initial_bytes(
            &r,
            path.parent().unwrap_or_else(|| std::path::Path::new(".")),
        )?;
        if r.maximum_readable.is_some() || r.maximum_writable.is_some() {
            limits.push(stela_runtime::memory::DataProtectionLimit {
                guest_address: r.guest_address,
                readable: r.maximum_readable.unwrap_or(r.readable),
                writable: r.maximum_writable.unwrap_or(r.writable),
            });
        }
        specs.push(stela_runtime::memory::MemoryRegionSpec {
            guest_address: r.guest_address,
            virtual_bytes: r.virtual_bytes,
            initial_bytes,
            readable: r.readable,
            writable: r.writable,
            executable: false,
        });
    }
    stela_runtime::memory::OwnedMemory::map_with_data_limits(specs, limits)
}

pub(crate) fn memory_hashes(
    memory: &stela_runtime::memory::OwnedMemory,
) -> Result<Vec<serde_json::Value>> {
    memory.regions().iter().filter(|r| r.readable).map(|r| Ok(serde_json::json!({
        "address":r.guest_address,"bytes":r.virtual_bytes,
        "sha256":stela_formats::sha256(&memory.read_snapshot(r.guest_address, usize::try_from(r.virtual_bytes)?)?),
    }))).collect()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClockSnapshotInput {
    pub(crate) counter: u64,
    pub(crate) sleep_ticks: u64,
}

pub(crate) fn clock_snapshot(path: &std::path::Path) -> Result<stela_runtime::clock::Snapshot> {
    use std::io::Read;
    let mut bytes = Vec::new();
    File::open(path)?.take(4097).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 4096,
        "clock snapshot input exceeds 4096 bytes"
    );
    let input: ClockSnapshotInput = serde_json::from_slice(&bytes)?;
    let snapshot = stela_runtime::clock::Snapshot {
        counter: input.counter,
        sleep_ticks: input.sleep_ticks,
    };
    snapshot.awake_ticks()?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
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
            stela_contracts::pauth::Key::Ia,
            stela_contracts::pauth::Key::Ib,
            stela_contracts::pauth::Key::Da,
            stela_contracts::pauth::Key::Db,
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
            "sha256":stela_formats::sha256(&[7,6,5])}});
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
}
