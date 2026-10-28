//! Apple restore image discovery, download, inspection and extraction.
use crate::restore;
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use std::{io::Write, path::PathBuf};
use stela_runtime::write_json;

#[derive(Subcommand)]
pub(crate) enum ImagesCommand {
    List {
        #[arg(long)]
        model: Option<String>,
    },
    Fetch {
        /// Omit to select the newest unambiguous signed release in the catalog.
        #[arg(long)]
        build: Option<String>,
        #[arg(long)]
        model: Option<String>,
        #[arg(long, default_value = ".stela/images")]
        output_dir: PathBuf,
        /// Resolve the image and destination without downloading it.
        #[arg(long)]
        dry_run: bool,
    },
    /// Copy one model's recovery members from Apple's servers by byte
    /// ranges into a small archive, without downloading the whole image.
    FetchRecovery {
        #[arg(long)]
        build: String,
        #[arg(long)]
        model: String,
        #[arg(long, default_value = ".stela/images")]
        output_dir: PathBuf,
    },
    /// Write the `payload.json` and `blocks.bin` of an install `stela.efi`
    /// streams from Apple's servers, reading only the members it hashes.
    RemoteInventory {
        #[arg(long)]
        build: String,
        #[arg(long)]
        model: String,
        /// A new directory for the two files.
        #[arg(long)]
        output_dir: PathBuf,
        /// Read each recipient AEA key from this directory instead of
        /// fetching it (`image-manifest --aea-keys-in`).
        #[arg(long)]
        aea_keys_in: Option<PathBuf>,
    },
}

#[derive(Args)]
pub(crate) struct InspectAea {
    input: PathBuf,
}

#[derive(Args)]
pub(crate) struct ImageManifest {
    image: PathBuf,
    #[arg(long)]
    model: Option<String>,
    #[arg(long)]
    output: PathBuf,
    /// Also read and hash every component member of the selected identities.
    #[arg(long)]
    hash_members: bool,
    /// Also hash every member the model's identities name, list the global
    /// `apticket` manifests and each AEA member's key URL. Needs `--model`.
    #[arg(long, requires = "model")]
    payload: bool,
    /// Fetch each AEA member's public key response into this directory as
    /// 0600 files; the report lists them by SHA-256 only.
    #[arg(long, requires = "payload")]
    aea_keys: Option<PathBuf>,
    /// Read each image's recipient AEA key from this directory (the user's
    /// offline inputs, named `<header-sha256>.pem`) instead of fetching it,
    /// and record the offline `URLAsset` answer in the inventory.
    #[arg(long, requires = "payload")]
    aea_keys_in: Option<PathBuf>,
    /// Also write the in-place archive `payload.json`, carrying the keys
    /// `--aea-keys` fetched, for a restore that reads this IPSW unchanged
    /// from its own source partition, and beside it `blocks.bin`, the
    /// members' block hashes it names, so the restore host needs no scan.
    #[arg(long, requires = "payload")]
    payload_manifest: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct ExtractImage {
    image: PathBuf,
    #[arg(long)]
    member: String,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 16 * 1024 * 1024 * 1024)]
    max_bytes: u64,
}

#[derive(Args)]
pub(crate) struct DecodeIm4p {
    input: PathBuf,
    /// A new file for the decoded payload; the receipt goes beside it as `.json`.
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 512 * 1024 * 1024)]
    max_bytes: u64,
}

#[derive(Args)]
pub(crate) struct FetchAeaKey {
    input: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
pub(crate) struct DecryptAea {
    input: PathBuf,
    /// The PKCS8 PEM key that `fetch-aea-key` saved.
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
pub(crate) struct ExtractGuestFiles {
    /// A decrypted disk image, such as the OS image from `decrypt-aea`.
    image: PathBuf,
    /// A new directory that receives the files at their guest paths.
    #[arg(long)]
    output: PathBuf,
    /// An absolute guest file path; repeat for each file.
    #[arg(long)]
    path: Vec<String>,
    /// A guest file path copied when present.
    #[arg(long)]
    optional_path: Vec<String>,
    /// Also copy every arm64e dyld shared cache file.
    #[arg(long)]
    shared_cache: bool,
    /// The mounted volume to read, when the image has several.
    #[arg(long)]
    volume: Option<String>,
}

impl ExtractGuestFiles {
    pub(crate) fn run(self) -> Result<()> {
        let selection = restore::disk::Selection {
            required: self.path,
            optional: self.optional_path,
            shared_cache: self.shared_cache,
            volume: self.volume,
        };
        let receipt = restore::disk::extract(&self.image, &self.output, &selection)?;
        println!("{}", serde_json::to_string_pretty(&receipt)?);
        Ok(())
    }
}

impl ImageManifest {
    pub(crate) fn run(self) -> Result<()> {
        let Self {
            image: input,
            model,
            output,
            hash_members,
            payload,
            aea_keys,
            aea_keys_in,
            payload_manifest,
        } = self;
        ensure!(
            !output.exists(),
            "report exists; choose a new --output path"
        );
        let report = restore::archive::manifest(&input, model.as_deref(), hash_members)?;
        if let (true, Some(model)) = (payload, model.as_deref()) {
            let mut value = serde_json::to_value(&report)?;
            let inventory = restore::payload::inventory(
                &input,
                model,
                restore::payload::KeyOptions {
                    fetch: false,
                    output: aea_keys.as_deref(),
                    input: aea_keys_in.as_deref(),
                },
            )?;
            value["payload"] = inventory.report;
            write_json(&output, &value)?;
            if let Some(path) = payload_manifest {
                // The block hashes go beside the manifest, which names them.
                let blocks = path.with_file_name(stela_formats::payload::BLOCK_HASHES_FILE);
                std::fs::File::create_new(&blocks)
                    .with_context(|| format!("{} exists", blocks.display()))?
                    .write_all(&inventory.blocks)?;
                let mut file = std::fs::File::create_new(&path)
                    .with_context(|| format!("{} exists", path.display()))?;
                file.write_all((inventory.manifest.to_json() + "\n").as_bytes())?;
            }
        } else {
            write_json(&output, &report)?;
        }
        eprintln!(
            "macOS {} build {}: {} matching identities; {}",
            report.product_version,
            report.product_build,
            report.identities.len(),
            output.display()
        );
        Ok(())
    }
}

impl ExtractImage {
    pub(crate) fn run(self) -> Result<()> {
        let Self {
            image: input,
            member,
            output,
            max_bytes,
        } = self;
        let report = restore::archive::extract(&input, &member, &output, max_bytes)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        Ok(())
    }
}

impl DecodeIm4p {
    pub(crate) fn run(self) -> Result<()> {
        let mut receipt_name = self.output.as_os_str().to_owned();
        receipt_name.push(".json");
        let receipt_path = PathBuf::from(receipt_name);
        ensure!(
            !self.output.exists() && !receipt_path.exists(),
            "output or receipt exists; choose a new --output path"
        );
        let container = std::fs::read(&self.input)?;
        let (decoded, receipt) = stela_loader::im4p::decode(&container, self.max_bytes)?;
        let receipt = serde_json::json!({
            "input": self.input.canonicalize()?.display().to_string(),
            "im4p": receipt,
        });
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.output)?
            .write_all(&decoded)?;
        write_json(&receipt_path, &receipt)?;
        println!("{}", serde_json::to_string_pretty(&receipt)?);
        Ok(())
    }
}

impl InspectAea {
    pub(crate) fn run(self) -> Result<()> {
        let Self { input } = self;
        println!(
            "{}",
            serde_json::to_string_pretty(&restore::aea::inspect(&input)?)?
        );
        Ok(())
    }
}

impl FetchAeaKey {
    pub(crate) fn run(self) -> Result<()> {
        let Self { input, output } = self;
        println!(
            "{}",
            serde_json::to_string_pretty(&restore::aea::fetch_key(&input, &output)?)?
        );
        Ok(())
    }
}

impl DecryptAea {
    pub(crate) fn run(self) -> Result<()> {
        let report = restore::aea::decrypt(&self.input, &self.key, &self.output)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        Ok(())
    }
}

impl ImagesCommand {
    pub(crate) fn run(self) -> Result<()> {
        match self {
            Self::List { model } => {
                let mut images = restore::catalog()?;
                if let Some(model) = model {
                    images.retain(|i| i.models.contains(&model));
                }
                println!("{}", serde_json::to_string_pretty(&images)?);
            }
            Self::Fetch {
                build,
                model,
                output_dir,
                dry_run,
            } => {
                let images = restore::catalog()?;
                let image = restore::select(&images, build.as_deref(), model.as_deref())?;
                // Use a synthesized filename, never a remote path component.
                ensure!(
                    image.build.bytes().all(|c| c.is_ascii_alphanumeric()),
                    "invalid build identifier"
                );
                ensure!(
                    image
                        .version
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'.'),
                    "invalid version identifier"
                );
                let output = output_dir.join(format!(
                    "UniversalMac_{}_{}_Restore.ipsw",
                    image.version, image.build
                ));
                if dry_run {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &serde_json::json!({"image": image, "destination": output, "downloaded": false})
                        )?
                    );
                } else {
                    let receipt = restore::download(&image, &output)?;
                    println!("{}", serde_json::to_string_pretty(&receipt)?);
                    eprintln!("Saved {}", output.display());
                }
            }
            Self::FetchRecovery {
                build,
                model,
                output_dir,
            } => {
                let images = restore::catalog()?;
                let image = restore::select(&images, Some(&build), Some(&model))?;
                ensure!(
                    image.build.bytes().all(|c| c.is_ascii_alphanumeric())
                        && model
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b','),
                    "invalid build or model identifier"
                );
                std::fs::create_dir_all(&output_dir)?;
                let output = output_dir.join(format!(
                    "Recovery_{}_{}.ipsw",
                    image.build,
                    model.replace(',', "_")
                ));
                let started = std::time::Instant::now();
                let bytes = restore::fetch_recovery(&image, &model, &output)?;
                eprintln!(
                    "Saved {}: {:.2} GB of members in {:.0} s",
                    output.display(),
                    bytes as f64 / 1e9,
                    started.elapsed().as_secs_f64()
                );
            }
            Self::RemoteInventory {
                build,
                model,
                output_dir,
                aea_keys_in,
            } => {
                let images = restore::catalog()?;
                let image = restore::select(&images, Some(&build), Some(&model))?;
                let inventory = restore::remote_inventory(&image, &model, aea_keys_in.as_deref())?;
                std::fs::create_dir(&output_dir)
                    .with_context(|| format!("{} exists", output_dir.display()))?;
                let manifest = output_dir.join(stela_formats::payload::MANIFEST_FILE);
                let blocks = output_dir.join(stela_formats::payload::BLOCK_HASHES_FILE);
                std::fs::write(&blocks, &inventory.blocks)?;
                std::fs::write(&manifest, inventory.manifest.to_json() + "\n")?;
                eprintln!(
                    "{}: macOS {} streamed from {} ({} members hashed)",
                    manifest.display(),
                    image.build,
                    image.url,
                    inventory.report["hashed"]
                );
            }
        }
        Ok(())
    }
}
