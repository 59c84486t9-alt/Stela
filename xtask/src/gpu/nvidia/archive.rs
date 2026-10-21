//! Inspect every member rather than trust the archive's filename or first object.
use anyhow::{Context, Result, ensure};
use object::{Object, ObjectSymbol, read::archive::ArchiveFile};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::Path};

#[derive(Debug)]
pub struct Report {
    pub bytes: u64,
    pub sha256: String,
    pub members: usize,
    pub imports: BTreeSet<String>,
}

pub fn inspect(path: &Path, exports: &Path) -> Result<Report> {
    let data = fs::read(path)?;
    let archive = ArchiveFile::parse(data.as_slice())?;
    let mut definitions = BTreeSet::new();
    let mut imports = BTreeSet::new();
    let mut members = 0;
    for member in archive.members() {
        let member = member?;
        let bytes = member.data(data.as_slice())?;
        let file = object::File::parse(bytes).with_context(|| {
            format!("invalid object in {}: {:?}", path.display(), member.name())
        })?;
        ensure!(
            file.format() == object::BinaryFormat::Coff
                && file.architecture() == object::Architecture::X86_64
                && file.kind() == object::ObjectKind::Relocatable,
            "{} contains a non-x86-64 COFF member: {:?}",
            path.display(),
            member.name()
        );
        let stamp = match &file {
            object::File::Coff(coff) => {
                coff.coff_header().time_date_stamp.get(object::LittleEndian)
            }
            object::File::CoffBig(coff) => {
                coff.coff_header().time_date_stamp.get(object::LittleEndian)
            }
            _ => unreachable!("COFF format checked above"),
        };
        ensure!(
            stamp == 0,
            "{} contains a timestamped COFF member: {:?}",
            path.display(),
            member.name()
        );
        members += 1;
        for symbol in file.symbols() {
            let name = symbol.name()?;
            if name.is_empty() {
                continue;
            }
            if symbol.is_undefined() {
                imports.insert(name.to_owned());
            } else if symbol.is_global() {
                definitions.insert(name.to_owned());
            }
        }
    }
    ensure!(members > 0, "{} is empty", path.display());
    let export_list = fs::read_to_string(exports)?;
    for symbol in export_list.split_whitespace() {
        let name = symbol
            .strip_prefix("--undefined=")
            .context("unexpected NVIDIA export-list syntax")?;
        ensure!(definitions.contains(name), "missing vendor export: {name}");
    }
    if path.file_name().and_then(|name| name.to_str()) == Some("libnv-kernel.a") {
        for width in ["byte", "word", "dword"] {
            for operation in ["read", "write"] {
                let name = format!("os_pci_{operation}_{width}");
                ensure!(
                    definitions.contains(&name),
                    "missing native PCI hook {name}"
                );
            }
        }
    }
    imports.retain(|name| !definitions.contains(name));
    Ok(Report {
        bytes: data.len() as u64,
        sha256: format!("{:x}", Sha256::digest(&data)),
        members,
        imports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpu::{nvidia::Toolchain, support::capture};
    use std::process::Command;

    fn fixture(mixed: bool) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let tools = Toolchain::discover().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let sources = [
            "extern int helper(void); extern int platform(void); int entry(void) { return helper() + platform(); }",
            "int helper(void) { return 7; }",
        ];
        let mut objects = Vec::new();
        for (index, text) in sources.into_iter().enumerate() {
            let source = directory.path().join(format!("part{index}.c"));
            let output = source.with_extension("o");
            fs::write(&source, text).unwrap();
            let target = if mixed && index == 1 {
                "--target=x86_64-unknown-linux-gnu"
            } else {
                "--target=x86_64-unknown-windows"
            };
            capture(
                Command::new(&tools.clang)
                    .args([
                        target,
                        "-ffreestanding",
                        "-mno-incremental-linker-compatible",
                        "-c",
                    ])
                    .arg(&source)
                    .arg("-o")
                    .arg(&output),
            )
            .unwrap();
            objects.push(output);
        }
        let archive = directory.path().join("fixture.a");
        capture(
            Command::new(tools.archiver)
                .arg("rcs")
                .arg(&archive)
                .args(objects),
        )
        .unwrap();
        let exports = directory.path().join("exports.txt");
        fs::write(&exports, "--undefined=entry").unwrap();
        (directory, archive, exports)
    }

    #[test]
    fn archive_inventory_resolves_other_members_and_requires_vendor_exports() {
        let (_directory, archive, exports) = fixture(false);
        let report = inspect(&archive, &exports).unwrap();
        assert_eq!(report.members, 2);
        assert_eq!(report.imports, BTreeSet::from(["platform".into()]));
        fs::write(&exports, "--undefined=absent").unwrap();
        assert!(
            inspect(&archive, &exports)
                .unwrap_err()
                .to_string()
                .contains("absent")
        );
    }

    #[test]
    fn archive_inventory_rejects_a_foreign_object_after_a_valid_member() {
        let (_directory, archive, exports) = fixture(true);
        assert!(
            inspect(&archive, &exports)
                .unwrap_err()
                .to_string()
                .contains("non-x86-64 COFF")
        );
    }

    #[test]
    fn archive_inventory_rejects_nondeterministic_object_timestamps() {
        let (_directory, archive, exports) = fixture(false);
        let mut data = fs::read(&archive).unwrap();
        let parsed = ArchiveFile::parse(data.as_slice()).unwrap();
        let (offset, _) = parsed.members().next().unwrap().unwrap().file_range();
        // IMAGE_FILE_HEADER.TimeDateStamp follows the two 16-bit fields.
        let offset = usize::try_from(offset).unwrap() + 4;
        data[offset..offset + 4].copy_from_slice(&1_u32.to_le_bytes());
        fs::write(&archive, data).unwrap();
        assert!(
            inspect(&archive, &exports)
                .unwrap_err()
                .to_string()
                .contains("timestamped")
        );
    }
}
