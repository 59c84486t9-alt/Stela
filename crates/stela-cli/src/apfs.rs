//! Inspect APFS images with Stela's own reader (`stela_runtime::apfs`), the
//! one `stela.efi` uses: list containers and volumes, directories, and copy
//! files out with their SHA-256.
use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::{
    fs::File,
    io::Write,
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
};
use stela_runtime::{
    apfs::{self, Container, Volume, uuid_text, volume::Snapshot},
    payload::ReadAt,
};

/// An image file as a reader source.
pub(crate) struct Image {
    file: File,
    bytes: u64,
}

impl ReadAt for Image {
    type Error = std::io::Error;
    fn len(&self) -> u64 {
        self.bytes
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> std::io::Result<()> {
        self.file.read_exact_at(buffer, offset)
    }
}

pub(crate) fn open_image(path: &Path) -> Result<Image> {
    let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let bytes = file.metadata()?.len();
    Ok(Image { file, bytes })
}

fn role_name(role: u16) -> &'static str {
    use apfs::volume::*;
    match role {
        APFS_VOL_ROLE_NONE => "none",
        APFS_VOL_ROLE_SYSTEM => "system",
        APFS_VOL_ROLE_USER => "user",
        APFS_VOL_ROLE_RECOVERY => "recovery",
        APFS_VOL_ROLE_VM => "vm",
        APFS_VOL_ROLE_PREBOOT => "preboot",
        APFS_VOL_ROLE_INSTALLER => "installer",
        APFS_VOL_ROLE_DATA => "data",
        APFS_VOL_ROLE_UPDATE => "update",
        _ => "other",
    }
}

#[derive(Subcommand)]
pub(crate) enum ApfsCommand {
    /// List the image's containers, volumes and snapshots.
    Info { image: PathBuf },
    /// List a directory.
    Ls(Target),
    /// Print every object below a directory, one JSON line each: kind and
    /// size, and the SHA-256 of a file or the target of a link.
    Walk(Target),
    /// Copy a file out, with its SHA-256.
    Read {
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Args)]
pub(crate) struct Target {
    image: PathBuf,
    /// A path from the volume root.
    path: String,
    /// The volume by name; otherwise the first volume.
    #[arg(long)]
    volume: Option<String>,
    /// The volume by role, such as `preboot` or `system`.
    #[arg(long, conflicts_with = "volume")]
    role: Option<String>,
    /// Read the named snapshot instead of the live volume.
    #[arg(long)]
    snapshot: Option<String>,
    /// The container, when the image has several.
    #[arg(long, default_value_t = 0)]
    container: usize,
}

impl Target {
    fn open(&self) -> Result<(Container<Image>, Volume)> {
        let mut image = open_image(&self.image)?;
        let offsets = apfs::containers(&mut image)?;
        let offset = *offsets
            .get(self.container)
            .with_context(|| format!("the image has {} APFS containers", offsets.len()))?;
        let mut container = Container::open(image, offset)?;
        let volumes = container.volumes()?;
        let volume = match (&self.volume, &self.role) {
            (Some(name), _) => volumes.into_iter().find(|v| &v.name == name),
            (_, Some(role)) => volumes.into_iter().find(|v| role_name(v.role) == role),
            _ => volumes.into_iter().next(),
        }
        .context("no such volume")?;
        let volume = match &self.snapshot {
            None => volume,
            Some(name) => {
                let snapshot = volume
                    .snapshots(&mut container.device)?
                    .into_iter()
                    .find(|s| &s.name == name)
                    .with_context(|| format!("no snapshot {name}"))?;
                volume.snapshot(&mut container.device, &snapshot)?
            }
        };
        Ok((container, volume))
    }
}

fn snapshot_json(snapshot: &Snapshot) -> Value {
    json!({"name": snapshot.name, "xid": snapshot.xid, "superblock": snapshot.superblock})
}

impl ApfsCommand {
    pub(crate) fn run(self) -> Result<()> {
        match self {
            Self::Info { image } => {
                let mut source = open_image(&image)?;
                let mut report = Vec::new();
                for offset in apfs::containers(&mut source)? {
                    let mut container = Container::open(open_image(&image)?, offset)?;
                    let superblock = container.superblock.clone();
                    let mut volumes = Vec::new();
                    for volume in container.volumes()? {
                        let snapshots = match volume.snapshots(&mut container.device) {
                            Ok(list) => json!(list.iter().map(snapshot_json).collect::<Vec<_>>()),
                            Err(error) => json!({"error": error.to_string()}),
                        };
                        let seal = match volume.seal(&mut container.device) {
                            Ok(Some(seal)) => json!({
                                "hash": format!("{:?}", seal.hash),
                                "root": hex::encode(&seal.root),
                            }),
                            Ok(None) => json!(null),
                            Err(error) => json!({"error": error.to_string()}),
                        };
                        volumes.push(json!({
                            "name": volume.name,
                            "role": role_name(volume.role),
                            "uuid": uuid_text(&volume.uuid),
                            "volume_group": uuid_text(&volume.volume_group),
                            "encrypted": volume.encrypted,
                            "sealed": volume.sealed,
                            "seal": seal,
                            "xid": volume.xid,
                            "snapshots": snapshots,
                        }));
                    }
                    report.push(json!({
                        "offset": offset,
                        "uuid": uuid_text(&superblock.uuid),
                        "block_size": superblock.block_size,
                        "block_count": superblock.block_count,
                        "xid": superblock.xid,
                        "checkpoint_superblock": superblock.paddr,
                        "volumes": volumes,
                    }));
                }
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            Self::Ls(target) => {
                let (mut container, volume) = target.open()?;
                let directory = volume.lookup(&mut container.device, &target.path, true)?;
                let mut entries = volume.entries(&mut container.device, directory.oid)?;
                entries.sort_by(|a, b| a.name.cmp(&b.name));
                for entry in entries {
                    let inode = volume.inode(&mut container.device, entry.oid)?;
                    println!("{:?}\t{}\t{}", entry.kind, inode.size, entry.name);
                }
            }
            Self::Walk(target) => {
                let (mut container, volume) = target.open()?;
                let start = volume.lookup(&mut container.device, &target.path, true)?;
                let mut pending = vec![(target.path.trim_end_matches('/').to_owned(), start.oid)];
                let mut out = std::io::BufWriter::new(std::io::stdout().lock());
                while let Some((path, oid)) = pending.pop() {
                    for entry in volume.entries(&mut container.device, oid)? {
                        let child = format!("{path}/{}", entry.name);
                        let inode = volume.inode(&mut container.device, entry.oid)?;
                        let line = match inode.kind {
                            apfs::FileKind::Directory => {
                                pending.push((child.clone(), entry.oid));
                                json!({"path": child, "kind": "directory"})
                            }
                            apfs::FileKind::Regular => {
                                match volume.read(&mut container.device, &inode) {
                                    Ok(bytes) => {
                                        json!({"path": child, "kind": "file", "bytes": inode.logical_size(),
                                    "sha256": stela_runtime::sha256(&bytes)})
                                    }
                                    Err(error) => {
                                        json!({"path": child, "kind": "file", "bytes": inode.logical_size(),
                                    "error": error.to_string()})
                                    }
                                }
                            }
                            apfs::FileKind::Symlink => json!({"path": child, "kind": "symlink",
                                "target": volume.symlink_target(&mut container.device, &inode)?}),
                            apfs::FileKind::Other => json!({"path": child, "kind": "other"}),
                        };
                        writeln!(out, "{line}")?;
                    }
                }
            }
            Self::Read { target, output } => {
                ensure!(!output.exists(), "{} exists", output.display());
                let (mut container, volume) = target.open()?;
                let inode = volume.lookup(&mut container.device, &target.path, true)?;
                if inode.kind != apfs::FileKind::Regular {
                    bail!("{} is not a regular file", target.path);
                }
                let bytes = volume.read(&mut container.device, &inode)?;
                File::create_new(&output)?.write_all(&bytes)?;
                println!(
                    "{}",
                    json!({"path": target.path, "bytes": bytes.len(), "sha256": stela_runtime::sha256(&bytes)})
                );
            }
        }
        Ok(())
    }
}
