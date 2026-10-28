//! The host storage scenario: one GPT disk image per controller type, which
//! the mount's `--storage-check` overwrites at the start of one partition.
//! The run passes when the mount's reported hash matches the pattern, the
//! image holds exactly that pattern there, and every other byte is unchanged.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use {
    stela_formats::sha256, stela_runtime::pc::gpt, stela_runtime::pc::gpt::Guid,
    stela_runtime::pc::gpt::Partition, stela_runtime::pc::storage::pattern,
};

const BLOCK: u64 = 512;
const BLOCKS: u64 = 32 * 1024;
/// An ESP, the partition the mount may write, and one after it.
const LAYOUT: [(u64, u64, &str); 3] = [
    (2048, 4095, "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"),
    (8192, 16383, "0FC63DAF-8483-4772-8E79-3D69D8477DE4"),
    (16384, 24575, "0FC63DAF-8483-4772-8E79-3D69D8477DE4"),
];
const TARGET: usize = 1;
/// Serial, QEMU device and the byte that distinguishes each disk's GUIDs.
const DISKS: [(&str, &str, u8); 3] = [
    ("stela-virtio", "virtio-blk-pci", 1),
    ("stela-nvme", "nvme", 2),
    ("stela-ahci", "ide-hd", 3),
];

pub struct Disk {
    serial: &'static str,
    device: &'static str,
    tag: u8,
    path: PathBuf,
}

fn guid(tag: u8, index: u8) -> Guid {
    let mut bytes = [tag; 16];
    bytes[15] = index;
    Guid(bytes)
}

/// A fresh image: a filler that differs from the check pattern everywhere,
/// under a GPT with the three partitions.
fn image(tag: u8) -> Result<Vec<u8>> {
    let partitions: Vec<Partition> = LAYOUT
        .iter()
        .zip(1u8..)
        .map(|((first, last, kind), index)| Partition {
            kind: kind.parse().unwrap(),
            unique: guid(tag, index),
            first_lba: *first,
            last_lba: *last,
            attributes: 0,
            name: format!("stela test {index}"),
        })
        .collect();
    let mut image: Vec<u8> = (0..BLOCKS * BLOCK)
        .map(|offset| offset as u8 ^ (offset >> 9) as u8 ^ 0xa5)
        .collect();
    for (lba, bytes) in
        gpt::format(BLOCKS, BLOCK as u32, guid(tag, 0), &partitions).map_err(anyhow::Error::msg)?
    {
        let start = (lba * BLOCK) as usize;
        image[start..start + bytes.len()].copy_from_slice(&bytes);
    }
    Ok(image)
}

/// Create the three images in `output`.
pub fn create(output: &Path) -> Result<Vec<Disk>> {
    DISKS
        .into_iter()
        .map(|(serial, device, tag)| {
            let path = output.join(format!("{serial}.img"));
            fs::write(&path, image(tag)?)?;
            Ok(Disk {
                serial,
                device,
                tag,
                path,
            })
        })
        .collect()
}

impl Disk {
    fn partition(&self) -> Guid {
        guid(self.tag, TARGET as u8 + 1)
    }

    /// The mount option that names this disk's partition.
    pub fn option(&self) -> String {
        format!(" --storage-check {}:{}", self.serial, self.partition())
    }

    pub fn attach(&self, index: usize, command: &mut Command) {
        let id = format!("disk{index}");
        command.arg("-drive").arg(format!(
            "if=none,id={id},format=raw,file={}",
            super::option_path(&self.path)
        ));
        let bus = if self.device == "ide-hd" {
            command.args(["-device", "ahci,id=ahci"]);
            ",bus=ahci.0"
        } else {
            ""
        };
        command.arg("-device").arg(format!(
            "{},drive={id},serial={}{bus}",
            self.device, self.serial
        ));
    }

    /// Check the mount's report against the pattern and the image.
    fn verify(&self, log: &str) -> Result<Value> {
        let prefix = format!("serial={} partition={}", self.serial, self.partition());
        let line = log
            .lines()
            .find(|line| line.starts_with("STORAGE CHECKED") && line.contains(&prefix))
            .with_context(|| format!("the mount reported no check of {}", self.serial))?;
        let field = |name: &str| {
            line.split_ascii_whitespace()
                .find_map(|word| word.strip_prefix(name))
                .with_context(|| format!("no {name} in {line:?}"))
        };
        let bytes: usize = field("bytes=")?.parse()?;
        let reported = field("sha256=")?;
        let expected: Vec<u8> = (0..bytes as u64).map(pattern).collect();
        let hash = sha256(&expected);
        ensure!(
            reported == hash,
            "{}: the mount reported {reported}, the pattern is {hash}",
            self.serial
        );
        let start = (LAYOUT[TARGET].0 * BLOCK) as usize;
        let mut wanted = image(self.tag)?;
        wanted[start..start + bytes].copy_from_slice(&expected);
        let actual = fs::read(&self.path)?;
        let differs = actual.iter().zip(&wanted).position(|(a, b)| a != b);
        ensure!(
            actual.len() == wanted.len() && differs.is_none(),
            "{}: image byte {:?} differs from the expected disk",
            self.serial,
            differs
        );
        Ok(json!({
            "serial": self.serial,
            "partition": self.partition().to_string(),
            "bytes": bytes,
            "sha256": reported,
            "image": sha256(&actual),
        }))
    }
}

/// Verify every disk; the first failure is the error.
pub fn verify(disks: &[Disk], serial_log: &Path) -> Result<Value> {
    let log = String::from_utf8_lossy(&fs::read(serial_log)?).into_owned();
    disks
        .iter()
        .map(|disk| disk.verify(&log))
        .collect::<Result<Vec<_>>>()
        .map(Value::from)
}
