//! The parts of an app's code signature macOS checks before it runs the app
//! and `codesign --verify` checks of the whole bundle, read from the files
//! the guest receives: the main executable's code directory, which hashes
//! each code page, `Info.plist` and `_CodeSignature/CodeResources`, and the
//! resource seal, which hashes every other file. Layouts follow `cs_blobs.h`
//! at `xnu-12377.121.6`. The signer's identity and its validity are macOS's
//! to judge; this checks that the bytes the kext delivers are the ones the
//! signer sealed, so a bundle copied with metadata files or changed after
//! signing is refused before it is embedded.
use anyhow::{Context, Result, bail, ensure};
use object::{LittleEndian as LE, macho, read::macho::MachHeader};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const FAT_MAGIC: u32 = 0xcafe_babe;
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSSLOT_CODEDIRECTORY: u32 = 0;
const CSSLOT_ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;
const CSSLOT_ALTERNATE_LIMIT: u32 = 0x1005;
const CS_HASHTYPE_SHA256: u8 = 2;
const HASH_BYTES: usize = 32;
/// The special slots holding `Info.plist`'s and `CodeResources`' hashes.
const INFO_SLOT: usize = 1;
const RESOURCES_SLOT: usize = 3;

fn word(bytes: &[u8], at: usize) -> Result<u32> {
    let value = bytes
        .get(at..)
        .and_then(|tail| tail.get(..4))
        .context("a code signature is truncated")?;
    Ok(u32::from_be_bytes(value.try_into().unwrap()))
}

/// Checks each slice of `executable`, which must include arm64 code: its
/// SHA-256 code directory names `identifier` and hashes its code pages,
/// `info` (`Contents/Info.plist`) and `resources` (`CodeResources`).
pub fn check_executable(
    executable: &[u8],
    identifier: &str,
    info: &[u8],
    resources: &[u8],
) -> Result<()> {
    let slices = slices(executable)?;
    ensure!(
        slices.iter().any(|(cpu, _)| *cpu == macho::CPU_TYPE_ARM64),
        "the executable has no arm64 code, which the guest runs"
    );
    for (_, slice) in slices {
        check_slice(slice, identifier, info, resources)?;
    }
    Ok(())
}

/// Each slice's CPU type and bytes, of a fat or a thin 64-bit file.
fn slices(file: &[u8]) -> Result<Vec<(u32, &[u8])>> {
    if word(file, 0).ok() == Some(FAT_MAGIC) {
        let count = word(file, 4)? as usize;
        ensure!(
            count > 0 && count < 16,
            "the executable's fat header is malformed"
        );
        return (0..count)
            .map(|index| {
                let entry = 8 + index * 20;
                let (offset, size) = (word(file, entry + 8)? as usize, word(file, entry + 12)?);
                let slice = file
                    .get(offset..)
                    .and_then(|tail| tail.get(..size as usize))
                    .context("a fat slice exceeds the executable")?;
                Ok((word(file, entry)?, slice))
            })
            .collect();
    }
    let header = macho::MachHeader64::<LE>::parse(file, 0)
        .ok()
        .context("the executable is not a 64-bit Mach-O file")?;
    Ok(vec![(header.cputype(LE), file)])
}

fn check_slice(slice: &[u8], identifier: &str, info: &[u8], resources: &[u8]) -> Result<()> {
    let header = macho::MachHeader64::<LE>::parse(slice, 0)
        .ok()
        .context("a slice is not a 64-bit Mach-O file")?;
    ensure!(
        header.filetype(LE) == macho::MH_EXECUTE,
        "the app's executable is not an executable"
    );
    let mut commands = header.load_commands(LE, slice, 0)?;
    let mut signature = None;
    while let Some(command) = commands.next()? {
        if command.cmd() == macho::LC_CODE_SIGNATURE {
            ensure!(signature.is_none(), "a slice has two signatures");
            let data: &macho::LinkeditDataCommand<LE> = command.data()?;
            signature = Some((
                data.dataoff.get(LE) as usize,
                data.datasize.get(LE) as usize,
            ));
        }
    }
    let (offset, bytes) = signature.context("a slice of the executable is unsigned")?;
    let blob = slice
        .get(offset..)
        .and_then(|tail| tail.get(..bytes))
        .context("a signature exceeds its slice")?;
    ensure!(
        word(blob, 0)? == CSMAGIC_EMBEDDED_SIGNATURE && word(blob, 4)? as usize <= blob.len(),
        "a slice's signature is not an embedded signature"
    );
    let mut chosen = None;
    for index in 0..word(blob, 8)? as usize {
        let kind = word(blob, 12 + index * 8)?;
        if kind != CSSLOT_CODEDIRECTORY
            && !(CSSLOT_ALTERNATE_CODEDIRECTORIES..CSSLOT_ALTERNATE_LIMIT).contains(&kind)
        {
            continue;
        }
        let at = word(blob, 16 + index * 8)? as usize;
        let directory = blob
            .get(at..)
            .context("a code directory exceeds its signature")?;
        ensure!(
            word(directory, 0)? == CSMAGIC_CODEDIRECTORY,
            "a code directory slot holds no code directory"
        );
        let directory = directory
            .get(..word(directory, 4)? as usize)
            .context("a code directory exceeds its signature")?;
        if directory.get(37) == Some(&CS_HASHTYPE_SHA256) {
            chosen = Some(directory);
        }
    }
    let directory = chosen.context("a slice has no SHA-256 code directory")?;
    check_directory(directory, &slice[..offset], identifier, info, resources)
}

fn check_directory(
    directory: &[u8],
    signed: &[u8],
    identifier: &str,
    info: &[u8],
    resources: &[u8],
) -> Result<()> {
    ensure!(directory.len() >= 44, "a code directory is truncated");
    let hashes = word(directory, 16)? as usize;
    let name = word(directory, 20)? as usize;
    let special = word(directory, 24)? as usize;
    let code = word(directory, 28)? as usize;
    ensure!(
        word(directory, 32)? as usize == signed.len() && directory[36] as usize == HASH_BYTES,
        "a code directory does not cover its slice's code with SHA-256"
    );
    let named = directory
        .get(name..)
        .and_then(|tail| tail.split(|&byte| byte == 0).next())
        .context("a code directory's identifier is malformed")?;
    ensure!(
        named == identifier.as_bytes(),
        "the signature names {:?}, not {identifier}",
        String::from_utf8_lossy(named)
    );
    let page = match directory[39] {
        0 => signed.len().max(1),
        shift @ 9..=16 => 1 << shift,
        shift => bail!("a code directory's page size 2^{shift} is unsupported"),
    };
    ensure!(
        code == signed.len().div_ceil(page) && special >= RESOURCES_SLOT,
        "a code directory's slot counts do not match its slice"
    );
    let slot = |index: isize| -> Result<&[u8]> {
        let at = hashes
            .checked_add_signed(index * HASH_BYTES as isize)
            .context("a code directory's hash offset is malformed")?;
        directory
            .get(at..at + HASH_BYTES)
            .context("a code directory's hashes exceed it")
    };
    for (index, page) in signed.chunks(page).enumerate() {
        ensure!(
            Sha256::digest(page).as_slice() == slot(index as isize)?,
            "code page {index} differs from its signature"
        );
    }
    for (index, bytes, name) in [
        (INFO_SLOT, info, "Info.plist"),
        (RESOURCES_SLOT, resources, "CodeResources"),
    ] {
        ensure!(
            Sha256::digest(bytes).as_slice() == slot(-(index as isize))?,
            "{name} differs from the executable's signature"
        );
    }
    Ok(())
}

/// Checks that `resources`, `_CodeSignature/CodeResources`, seals each of
/// `files` (path in the bundle to bytes) that the code directory does not:
/// every other file is listed in `files2` with its SHA-256, and every listed
/// file that is not optional is present.
pub fn check_resources(
    resources: &[u8],
    files: &BTreeMap<String, Vec<u8>>,
    executable: &str,
) -> Result<()> {
    let seal: plist::Value =
        plist::from_bytes(resources).context("CodeResources is not a property list")?;
    let listed = seal
        .as_dictionary()
        .and_then(|seal| seal.get("files2"))
        .and_then(plist::Value::as_dictionary)
        .context("CodeResources has no files2 seal")?;
    let mut sealed = BTreeSet::new();
    for (path, entry) in listed {
        let entry = entry
            .as_dictionary()
            .with_context(|| format!("CodeResources' entry for {path} is malformed"))?;
        let hash = entry
            .get("hash2")
            .and_then(plist::Value::as_data)
            .with_context(|| {
                format!("CodeResources seals {path} as nested code or a link, which Stela.app has none of")
            })?;
        let optional = entry
            .get("optional")
            .and_then(plist::Value::as_boolean)
            .unwrap_or(false);
        let path = format!("Contents/{path}");
        match files.get(&path) {
            Some(bytes) => ensure!(
                Sha256::digest(bytes).as_slice() == hash,
                "{path} differs from its seal"
            ),
            None => ensure!(optional, "{path} is sealed but absent"),
        }
        sealed.insert(path);
    }
    let executable = format!("Contents/MacOS/{executable}");
    let own = [
        "Contents/Info.plist",
        "Contents/PkgInfo",
        "Contents/_CodeSignature/CodeResources",
        executable.as_str(),
    ];
    for path in files.keys() {
        ensure!(
            own.contains(&path.as_str()) || sealed.contains(path),
            "{path} is not sealed by the app's signature (a metadata file from copying, or added after signing)"
        );
    }
    Ok(())
}
