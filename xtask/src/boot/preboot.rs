//! The installed-system scenario: a GPT disk image whose APFS container holds
//! an installed system's Preboot volume, attached over NVMe. `stela.efi`
//! reads it with Stela's own storage drivers after boot services end, builds
//! the boot bundle with `stela_loader::installed` and enters it on the
//! system-mode engine. The run passes when the mount reports the bundle the
//! same code builds on the host from the same image: every region by name,
//! guest address and sizes, and the entry point and `x0`.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
    process::Command,
};
use stela_loader::{
    boot_bundle::{Manifest, Options},
    installed,
};
use stela_runtime::{
    apfs::{self, Container},
    payload::{ReadAt, gpt},
};

/// The serial the NVMe disk reports, which `stela.cfg` names.
const SERIAL: &str = "STELA-PREBOOT-01";
const BLOCK: u64 = 512;

/// A byte range of the image file.
struct Range {
    file: fs::File,
    start: u64,
    bytes: u64,
}

impl ReadAt for Range {
    type Error = std::io::Error;
    fn len(&self) -> u64 {
        self.bytes
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> std::io::Result<()> {
        self.file.read_exact_at(buffer, self.start + offset)
    }
}

pub struct Preboot {
    path: PathBuf,
    /// The APFS partition's unique GUID.
    partition: String,
    expected: Manifest,
}

/// Find the image's single APFS partition and build its bundle on the host.
pub fn prepare(path: &Path) -> Result<Preboot> {
    let disk = gpt::Disk {
        block_bytes: BLOCK,
        blocks: fs::metadata(path)?.len() / BLOCK,
    };
    let open = |start, bytes| -> Result<Range> {
        Ok(Range {
            file: fs::File::open(path)?,
            start,
            bytes,
        })
    };
    let mut whole = open(0, disk.blocks * BLOCK)?;
    let mut header = vec![0u8; BLOCK as usize];
    whole.read_at(BLOCK, &mut header)?;
    let error = |e| anyhow::anyhow!("{}: {e}", path.display());
    let info = gpt::parse_header(disk, 1, &header)
        .map_err(error)?
        .with_context(|| format!("{} has no GPT", path.display()))?;
    let mut entries = vec![0u8; info.entry_array_bytes() as usize];
    whole.read_at(info.entries_lba * BLOCK, &mut entries)?;
    let table = gpt::parse_entries(&info, &entries).map_err(error)?;
    let apfs_type = gpt::Guid::parse(apfs::PARTITION_TYPE).unwrap();
    let containers: Vec<_> = table
        .partitions
        .iter()
        .filter(|p| p.type_guid == apfs_type)
        .collect();
    ensure!(
        containers.len() == 1,
        "{} has {} APFS partitions; the scenario needs exactly one",
        path.display(),
        containers.len()
    );
    let partition = containers[0];
    let mut container = Container::open(
        open(partition.first_lba * BLOCK, partition.blocks() * BLOCK)?,
        0,
    )
    .map_err(|e| anyhow::anyhow!("APFS container: {e}"))?;
    let installed = installed::prepare(
        &mut container,
        &installed::Request::default(),
        &Options::default(),
    )?;
    Ok(Preboot {
        path: path.to_owned(),
        partition: partition.unique_guid.to_string(),
        expected: installed.bundle.manifest,
    })
}

impl Preboot {
    /// The mount options: system mode on the bundle built from this disk.
    pub fn options(&self) -> String {
        format!("--system --preboot {SERIAL}:{}", self.partition)
    }

    /// Attach the image read-only to the guest through a snapshot overlay.
    pub fn attach(&self, command: &mut Command) {
        command
            .arg("-drive")
            .arg(format!(
                "if=none,id=preboot,format=raw,snapshot=on,file={}",
                super::option_path(&self.path)
            ))
            .arg("-device")
            .arg(format!("nvme,drive=preboot,serial={SERIAL}"));
    }

    /// Check the mount's REGION and ENTRY lines against the host's bundle.
    pub fn verify(&self, log: &str) -> Result<Value> {
        let field = |line: &str, name: &str| -> Result<u64> {
            let text = line
                .split_ascii_whitespace()
                .find_map(|word| word.strip_prefix(name))
                .with_context(|| format!("no {name} in {line:?}"))?;
            Ok(u64::from_str_radix(text.trim_start_matches("0x"), 16)?)
        };
        ensure!(
            log.lines().any(|line| line.starts_with("PREBOOT ")),
            "the mount reported no Preboot boot directory"
        );
        let regions: Vec<&str> = log
            .lines()
            .filter(|line| line.starts_with("REGION "))
            .collect();
        ensure!(
            regions.len() == self.expected.regions.len(),
            "the mount loaded {} regions; the host bundle has {}",
            regions.len(),
            self.expected.regions.len()
        );
        for (line, region) in regions.iter().zip(&self.expected.regions) {
            let name = line.split_ascii_whitespace().nth(1).unwrap_or_default();
            ensure!(
                name == region.name
                    && field(line, "pa=")? == region.guest_pa
                    && field(line, "bytes=")? == region.bytes
                    && field(line, "memory=")? == region.memory_bytes,
                "{line:?} differs from the host's region {} at {:#x}",
                region.name,
                region.guest_pa
            );
        }
        let entry = log
            .lines()
            .find(|line| line.starts_with("ENTRY "))
            .context("the mount did not reach the bundle's entry")?;
        ensure!(
            field(entry, "pc=")? == self.expected.entry.physical_address
                && field(entry, "x0=")? == self.expected.entry_x0,
            "{entry:?} differs from the host's entry {:#x}, x0 {:#x}",
            self.expected.entry.physical_address,
            self.expected.entry_x0
        );
        Ok(json!({
            "passed": true,
            "partition": self.partition,
            "regions": regions.len(),
            "entry": self.expected.entry.physical_address,
            "x0": self.expected.entry_x0,
        }))
    }
}
