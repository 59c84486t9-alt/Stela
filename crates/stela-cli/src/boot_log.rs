//! `stela boot-log`: the persistent boot log `stela.efi` keeps on a
//! machine-state partition (`stela_runtime::pc::boot_log`), read from a
//! whole-disk image by the partition's GUID or from a raw partition at a
//! byte offset. `stela setup --boot-log` reads the same region of a setup's
//! install.
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use std::{
    fmt::Write as _,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use stela_runtime::pc::{
    block::{BlockDevice, BlockError, Identity, Transport},
    boot_log::{self, Log},
    gpt::{self, Guid},
};

#[derive(Args)]
pub(crate) struct BootLog {
    /// A whole-disk image or a raw partition, a file or a device.
    file: PathBuf,
    /// The machine-state partition's unique GUID in FILE's GPT.
    #[arg(long, conflicts_with = "offset")]
    partition: Option<String>,
    /// The machine-state partition's byte offset in FILE (0 for a raw
    /// partition).
    #[arg(long, value_parser = crate::args::parse_address)]
    offset: Option<u64>,
}

impl BootLog {
    pub(crate) fn run(&self) -> Result<()> {
        let log = self.load()?;
        eprint!("{}", summary(&log));
        match std::io::stdout().write_all(&log.stream) {
            // A reader that closed the pipe early (`| head`) has what it
            // asked for.
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
            result => Ok(result?),
        }
    }

    fn load(&self) -> Result<Log> {
        let mut file = File::open(&self.file)
            .with_context(|| format!("cannot open {}", self.file.display()))?;
        let offset = match (&self.partition, self.offset) {
            (Some(guid), _) => {
                let guid: Guid = guid.parse().map_err(anyhow::Error::msg)?;
                let (table, block) = table(&self.file)?;
                let partition = table
                    .partitions
                    .iter()
                    .find(|partition| partition.unique == guid)
                    .with_context(|| {
                        format!(
                            "{} has no partition {guid}; it has:\n{}",
                            self.file.display(),
                            listing(&table, block)
                        )
                    })?;
                let bytes = partition.blocks() * block;
                ensure!(
                    bytes >= boot_log::PARTITION_BYTES,
                    "partition {guid} holds {bytes:#x} bytes; the boot log needs {:#x}, so \
                     stela.efi boots it without one",
                    boot_log::PARTITION_BYTES
                );
                partition.first_lba * block
            }
            (None, Some(offset)) => offset,
            (None, None) => {
                let found = table(&self.file)
                    .map(|(table, block)| format!("; its GPT has:\n{}", listing(&table, block)))
                    .unwrap_or_default();
                bail!(
                    "name the machine-state partition: --partition GUID in a whole-disk image, or \
                     --offset BYTES for a raw partition (0 when FILE is one){found}"
                )
            }
        };
        let start = offset + boot_log::OFFSET;
        let mut region = vec![0; boot_log::LOG_BYTES as usize];
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut region).with_context(|| {
            format!(
                "{} holds no boot log region at {start:#x}: the machine-state partition needs \
                 {:#x} bytes",
                self.file.display(),
                boot_log::PARTITION_BYTES
            )
        })?;
        boot_log::read(&region)
            .with_context(|| format!("{} has no boot log at {start:#x}", self.file.display()))
    }
}

/// What a log holds, one line.
pub(crate) fn summary(log: &Log) -> String {
    let mut text = format!(
        "Stela boot log: {} boots, {} bytes",
        log.boots,
        log.stream.len()
    );
    if log.overwritten() != 0 {
        let _ = write!(
            text,
            "; the {} bytes before them were overwritten",
            log.overwritten()
        );
    }
    text.push('\n');
    text
}

/// A disk image read through 512- or 4096-byte blocks.
struct Image {
    file: File,
    identity: Identity,
}

impl BlockDevice for Image {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.identity.check(lba, buffer.len())?;
        self.file
            .seek(SeekFrom::Start(lba * u64::from(self.identity.block_size)))
            .and_then(|_| self.file.read_exact(buffer))
            .map_err(|_| BlockError::Device { status: 0 })
    }

    fn write(&mut self, _: u64, _: &[u8]) -> Result<(), BlockError> {
        Err(BlockError::ReadOnly)
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        Ok(())
    }
}

/// The GPT of a whole-disk image and its block size.
fn table(path: &Path) -> Result<(gpt::Table, u64)> {
    let bytes = std::fs::metadata(path)?.len();
    let mut last = None;
    for block in [512u32, 4096] {
        let mut image = Image {
            file: File::open(path)?,
            identity: Identity {
                transport: Transport::VirtioBlk,
                location: path.display().to_string(),
                model: String::from("image"),
                serial: String::new(),
                blocks: bytes / u64::from(block),
                block_size: block,
                read_only: true,
            },
        };
        match gpt::read(&mut image) {
            Ok(table) => return Ok((table, u64::from(block))),
            Err(error) => last = Some(error),
        }
    }
    bail!(
        "{} holds no GPT ({}); pass --offset for a raw partition",
        path.display(),
        last.expect("two block sizes were tried")
    )
}

fn listing(table: &gpt::Table, block: u64) -> String {
    let mut text = String::new();
    for partition in &table.partitions {
        let _ = writeln!(
            text,
            "  {}  {:#x} bytes at {:#x}  {}",
            partition.unique,
            partition.blocks() * block,
            partition.first_lba * block,
            partition.name
        );
    }
    text
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use stela_runtime::pc::{
        block::{BlockDevice, BlockError, Identity, Transport},
        boot_log::Writer,
        gpt::Partition,
    };

    /// A partition of a byte vector.
    struct Bytes<'a> {
        bytes: &'a mut [u8],
        identity: Identity,
    }

    impl BlockDevice for Bytes<'_> {
        fn identity(&self) -> &Identity {
            &self.identity
        }

        fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
            self.identity.check(lba, buffer.len())?;
            let at = (lba * 512) as usize;
            buffer.copy_from_slice(&self.bytes[at..at + buffer.len()]);
            Ok(())
        }

        fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
            self.identity.check(lba, data.len())?;
            let at = (lba * 512) as usize;
            self.bytes[at..at + data.len()].copy_from_slice(data);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), BlockError> {
            Ok(())
        }
    }

    /// A log region with one boot per entry of `boots`, each printing it.
    pub(crate) fn region(boots: &[&str]) -> Vec<u8> {
        let mut bytes = vec![0u8; boot_log::LOG_BYTES as usize];
        let mut region = Bytes {
            bytes: &mut bytes,
            identity: Identity {
                transport: Transport::VirtioBlk,
                location: "test".into(),
                model: "RAM".into(),
                serial: String::new(),
                blocks: boot_log::LOG_BYTES / 512,
                block_size: 512,
                read_only: false,
            },
        };
        for line in boots {
            let mut writer = Writer::open(&mut region).unwrap();
            writer.append(line.as_bytes());
            writer.flush(&mut region).unwrap();
        }
        bytes
    }

    const GUID: &str = "5E1A0000-0000-4000-8000-0000000000C0";

    /// A 16 MiB GPT image with a machine-state partition at 1 MiB, whose log
    /// has two boots when it holds one.
    fn image(path: &Path, partition_bytes: u64) {
        let blocks = 16 * 1024 * 1024 / 512;
        let mut bytes = vec![0u8; 16 * 1024 * 1024];
        let partition = Partition {
            kind: "0FC63DAF-8483-4772-8E79-3D69D8477DE4".parse().unwrap(),
            unique: GUID.parse().unwrap(),
            first_lba: 2048,
            last_lba: 2048 + partition_bytes / 512 - 1,
            attributes: 0,
            name: "machine state".into(),
        };
        for (lba, block) in gpt::format(blocks, 512, Guid([7; 16]), &[partition]).unwrap() {
            let at = (lba * 512) as usize;
            bytes[at..at + block.len()].copy_from_slice(&block);
        }
        if partition_bytes >= boot_log::PARTITION_BYTES {
            let start = (2048 * 512 + boot_log::OFFSET) as usize;
            bytes[start..start + boot_log::LOG_BYTES as usize]
                .copy_from_slice(&region(&["first boot\n", "second boot\n"]));
        }
        std::fs::write(path, bytes).unwrap();
    }

    fn command(file: &Path, partition: Option<&str>, offset: Option<u64>) -> BootLog {
        BootLog {
            file: file.into(),
            partition: partition.map(Into::into),
            offset,
        }
    }

    #[test]
    fn the_log_is_read_from_a_gpt_image_by_guid_or_offset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("machine-state.img");
        image(&path, 8 * 1024 * 1024);
        let expected = "=== STELA BOOT 1 ===\nfirst boot\n=== STELA BOOT 2 ===\nsecond boot\n";
        let log = command(&path, Some(&GUID.to_lowercase()), None)
            .load()
            .unwrap();
        assert_eq!(log.boots, 2);
        assert_eq!(String::from_utf8(log.stream.clone()).unwrap(), expected);
        assert_eq!(
            summary(&log),
            format!("Stela boot log: 2 boots, {} bytes\n", expected.len())
        );
        let raw = command(&path, None, Some(2048 * 512)).load().unwrap();
        assert_eq!(raw, log);

        // Without a partition the command lists the GPT's.
        let error = format!("{:#}", command(&path, None, None).load().unwrap_err());
        assert!(error.contains(GUID), "{error}");
        let error = format!(
            "{:#}",
            command(&path, Some("5E1A0000-0000-4000-8000-0000000000C1"), None)
                .load()
                .unwrap_err()
        );
        assert!(error.contains("has no partition"), "{error}");
        // A region that holds no log is refused by name.
        let error = format!("{:#}", command(&path, None, Some(0)).load().unwrap_err());
        assert!(error.contains("the log region is blank"), "{error}");
    }

    #[test]
    fn a_partition_too_small_for_the_log_is_named() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("small.img");
        image(&path, 2 * 1024 * 1024);
        let error = format!("{:#}", command(&path, Some(GUID), None).load().unwrap_err());
        assert!(error.contains("boots it without one"), "{error}");
    }
}
