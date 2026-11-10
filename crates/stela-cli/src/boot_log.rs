//! `stela boot-log`: the persistent boot log `stela.efi` keeps on a
//! machine-state partition (`stela_runtime::pc::boot_log`), found in a
//! whole-disk image or a raw partition: at each partition's start, and in
//! the tail of an Apple region that also holds the machine state
//! (`pc::machine_state`), as a setup with `--target` alone lays it out.
//! The hidden `--partition`, `--offset` and `--in-target` name one place
//! instead. `stela setup boot-log` reads the same regions of a setup.
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use std::{
    fmt::Write as _,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use stela_drivers::block::{BlockDevice, BlockError, Identity, Transport};
use stela_runtime::pc::{
    boot_log::{self, Log},
    gpt::{self, Guid},
    machine_state,
};

#[derive(Args)]
pub(crate) struct BootLog {
    /// A whole-disk image or a raw partition, a file or a device. Every
    /// boot log on it is printed.
    file: PathBuf,
    /// Only the machine-state partition with this unique GUID in FILE's
    /// GPT.
    #[arg(long, conflicts_with = "offset", hide = true)]
    partition: Option<String>,
    /// Only the machine-state partition at this byte offset in FILE (0 for
    /// a raw partition).
    #[arg(long, value_parser = crate::args::parse_address, hide = true)]
    offset: Option<u64>,
    /// With --partition or --offset: the partition is a Mac's SSD partition
    /// whose last bytes hold the machine state; with --offset, FILE ends
    /// where the partition does.
    #[arg(long, hide = true)]
    in_target: bool,
}

impl BootLog {
    pub(crate) fn run(&self) -> Result<()> {
        let logs = if self.partition.is_none() && self.offset.is_none() {
            self.find()?
        } else {
            vec![(String::new(), self.load()?)]
        };
        let several = logs.len() > 1;
        let mut stdout = std::io::stdout();
        for (place, log) in logs {
            let mut written = Ok(());
            if several {
                eprint!("{place}: ");
                written = writeln!(stdout, "=== {place} ===");
            }
            eprint!("{}", summary(&log));
            match written.and_then(|()| stdout.write_all(&log.stream)) {
                // A reader that closed the pipe early (`| head`) has what it
                // asked for.
                Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
                result => result?,
            }
        }
        Ok(())
    }

    /// Every boot log on FILE, each with where it is: at the start or in
    /// the tail of each GPT partition, or of FILE itself without a GPT.
    fn find(&self) -> Result<Vec<(String, Log)>> {
        let mut file = File::open(&self.file)
            .with_context(|| format!("cannot open {}", self.file.display()))?;
        let (spans, listed) = match table(&self.file) {
            Ok((table, block)) => (
                table
                    .partitions
                    .iter()
                    .map(|partition| {
                        let start = partition.first_lba * block;
                        let place = format!("partition {}", partition.unique_guid);
                        (place, start, start + partition.blocks() * block)
                    })
                    .collect::<Vec<_>>(),
                format!("; its GPT has:\n{}", listing(&table, block)),
            ),
            Err(_) => (
                vec![(String::from("the file"), 0, file.seek(SeekFrom::End(0))?)],
                String::new(),
            ),
        };
        let mut logs = Vec::new();
        for (place, start, end) in spans {
            let bytes = end - start;
            if bytes >= boot_log::PARTITION_BYTES
                && let Ok(log) = read(&mut file, start)
            {
                logs.push((place.clone(), log));
            }
            if let Ok(layout) = machine_state::split(bytes)
                && let Ok(log) = read(&mut file, start + layout.state_offset())
            {
                logs.push((format!("{place}, machine state in its last bytes"), log));
            }
        }
        ensure!(
            !logs.is_empty(),
            "{} holds no Stela boot log at the start or in the last 16 MiB of any partition{listed}",
            self.file.display()
        );
        Ok(logs)
    }

    fn load(&self) -> Result<Log> {
        let mut file = File::open(&self.file)
            .with_context(|| format!("cannot open {}", self.file.display()))?;
        let (offset, end) = match (&self.partition, self.offset) {
            (Some(guid), _) => {
                let guid: Guid = guid.parse().map_err(anyhow::Error::msg)?;
                let (table, block) = table(&self.file)?;
                let partition = table
                    .partitions
                    .iter()
                    .find(|partition| partition.unique_guid == guid)
                    .with_context(|| {
                        format!(
                            "{} has no partition {guid}; it has:\n{}",
                            self.file.display(),
                            listing(&table, block)
                        )
                    })?;
                let bytes = partition.blocks() * block;
                ensure!(
                    self.in_target || bytes >= boot_log::PARTITION_BYTES,
                    "partition {guid} holds {bytes:#x} bytes; the boot log needs {:#x}, so \
                     stela.efi boots it without one",
                    boot_log::PARTITION_BYTES
                );
                let start = partition.first_lba * block;
                (start, start + bytes)
            }
            (None, Some(offset)) => (offset, file.seek(SeekFrom::End(0))?),
            (None, None) => unreachable!("`run` finds the logs without a place"),
        };
        // The machine state starts at the partition's start, or in its tail.
        let offset = if self.in_target {
            let layout = machine_state::split(end.saturating_sub(offset)).map_err(|error| {
                anyhow::anyhow!(
                    "{} at {offset:#x} holds no machine state in its last bytes: {error}",
                    self.file.display()
                )
            })?;
            offset + layout.state_offset()
        } else {
            offset
        };
        read(&mut file, offset).with_context(|| format!("{}", self.file.display()))
    }
}

/// The boot log of the machine state that starts at byte `state` of `file`.
fn read(file: &mut File, state: u64) -> Result<Log> {
    let start = state + boot_log::OFFSET;
    let mut region = vec![0; boot_log::LOG_BYTES as usize];
    file.seek(SeekFrom::Start(start))?;
    file.read_exact(&mut region).with_context(|| {
        format!(
            "no boot log region at {start:#x}: the machine-state partition needs {:#x} bytes",
            boot_log::PARTITION_BYTES
        )
    })?;
    boot_log::read(&region).with_context(|| format!("no boot log at {start:#x}"))
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
                features: Default::default(),
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
            partition.unique_guid,
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
    use stela_formats::payload::gpt::{Disk, Partition, Table, encode};
    use stela_runtime::pc::boot_log::Writer;

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
                features: Default::default(),
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

    /// A GPT image with a machine-state partition at 1 MiB, whose log has two
    /// boots when it holds one.
    fn image(path: &Path, partition_bytes: u64) {
        let mib = 1024 * 1024;
        let disk_bytes = (partition_bytes + 2 * mib).max(16 * mib);
        let blocks = disk_bytes / 512;
        let mut bytes = vec![0u8; disk_bytes as usize];
        let table = Table {
            disk_guid: Guid([7; 16]),
            partitions: vec![Partition {
                type_guid: "0FC63DAF-8483-4772-8E79-3D69D8477DE4".parse().unwrap(),
                unique_guid: GUID.parse().unwrap(),
                first_lba: 2048,
                last_lba: 2048 + partition_bytes / 512 - 1,
                attributes: 0,
                name: "machine state".into(),
            }],
        };
        let disk = Disk {
            block_bytes: 512,
            blocks,
        };
        for write in encode(disk, &table).unwrap() {
            let at = (write.lba * 512) as usize;
            bytes[at..at + write.bytes.len()].copy_from_slice(&write.bytes);
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
            in_target: false,
        }
    }

    #[test]
    fn gpt_log_selection_accepts_guid_or_offset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("machine-state.img");
        image(&path, boot_log::PARTITION_BYTES);
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

        // Without a place the command finds the log itself.
        let found = command(&path, None, None).find().unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], (format!("partition {GUID}"), log.clone()));
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
    fn boot_log_reads_machine_state_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("region.img");
        // A 20 MiB partition keeps its machine state from 4 MiB.
        let partition_bytes = 20 * 1024 * 1024;
        image(&path, partition_bytes);
        let mut bytes = std::fs::read(&path).unwrap();
        let tail = machine_state::split(partition_bytes)
            .unwrap()
            .state_offset();
        assert_eq!(tail, 4 * 1024 * 1024);
        let at = (2048 * 512 + tail + boot_log::OFFSET) as usize;
        bytes[at..at + boot_log::LOG_BYTES as usize].copy_from_slice(&region(&["in the tail\n"]));
        std::fs::write(&path, &bytes).unwrap();
        let mut tail_log = command(&path, Some(GUID), None);
        tail_log.in_target = true;
        let log = tail_log.load().unwrap();
        assert_eq!(
            String::from_utf8(log.stream).unwrap(),
            "=== STELA BOOT 1 ===\nin the tail\n"
        );
        // A raw partition ends with the file.
        let raw = dir.path().join("raw.img");
        std::fs::write(
            &raw,
            &bytes[2048 * 512..2048 * 512 + partition_bytes as usize],
        )
        .unwrap();
        let mut raw_log = command(&raw, None, Some(0));
        raw_log.in_target = true;
        assert_eq!(raw_log.load().unwrap().boots, 1);
        // A partition too small for a tail is named.
        let small = dir.path().join("small.img");
        image(&small, 2 * 1024 * 1024);
        let mut small_log = command(&small, Some(GUID), None);
        small_log.in_target = true;
        let error = format!("{:#}", small_log.load().unwrap_err());
        assert!(
            error.contains("no machine state in its last bytes"),
            "{error}"
        );
    }

    #[test]
    fn boot_log_reports_undersized_partition() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("small.img");
        image(&path, 2 * 1024 * 1024);
        let error = format!("{:#}", command(&path, Some(GUID), None).load().unwrap_err());
        assert!(error.contains("boots it without one"), "{error}");
        // Without a place, no log anywhere is named with the GPT's partitions.
        let error = format!("{:#}", command(&path, None, None).find().unwrap_err());
        assert!(error.contains("holds no Stela boot log"), "{error}");
        assert!(error.contains(GUID), "{error}");
    }

    #[test]
    fn boot_log_finds_logs_at_a_partition_start_and_in_its_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("both.img");
        let partition_bytes = 20 * 1024 * 1024;
        image(&path, partition_bytes);
        let mut bytes = std::fs::read(&path).unwrap();
        let tail = machine_state::split(partition_bytes)
            .unwrap()
            .state_offset();
        let at = (2048 * 512 + tail + boot_log::OFFSET) as usize;
        bytes[at..at + boot_log::LOG_BYTES as usize].copy_from_slice(&region(&["in the tail\n"]));
        std::fs::write(&path, &bytes).unwrap();
        let found = command(&path, None, None).find().unwrap();
        let places: Vec<_> = found
            .iter()
            .map(|(place, log)| (place.as_str(), log.boots))
            .collect();
        assert_eq!(
            places,
            [
                (format!("partition {GUID}").as_str(), 2),
                (
                    format!("partition {GUID}, machine state in its last bytes").as_str(),
                    1
                ),
            ]
        );
        // A raw partition without a GPT is searched as one.
        let raw = dir.path().join("raw.img");
        std::fs::write(
            &raw,
            &bytes[2048 * 512..2048 * 512 + partition_bytes as usize],
        )
        .unwrap();
        let found = command(&raw, None, None).find().unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].0, "the file");
    }
}
