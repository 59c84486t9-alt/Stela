//! Apple restore image discovery, download, inspection and extraction.
use crate::restore;
use anyhow::{Result, ensure};
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
        /// Omit to select the newest unambiguous version in Apple's catalog.
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
        } = self;
        ensure!(
            !output.exists(),
            "report exists; choose a new --output path"
        );
        let report = restore::archive::manifest(&input, model.as_deref(), hash_members)?;
        write_json(&output, &report)?;
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
        }
        Ok(())
    }
}
