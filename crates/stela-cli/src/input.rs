//! Bounded JSON and file inputs: register state, PAuth keys, owned memory and clocks.
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
            stela_core::sha256(&bytes) == source.sha256,
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
        "sha256":stela_core::sha256(&memory.read_snapshot(r.guest_address, usize::try_from(r.virtual_bytes)?)?),
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
mod tests;
