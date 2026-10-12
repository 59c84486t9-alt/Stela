use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use stela_core::{Progress, Stage, read_json, write_json};
use std::{fs::File, path::PathBuf};

#[derive(Parser)]
#[command(
    name = "stela",
    version,
    about = "Native x86 macOS recompilation research tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Discover and fetch restore images directly from Apple's public feed.
    Images {
        #[command(subcommand)]
        command: Images,
    },
    /// List ZIP members without extracting or mounting an IPSW.
    InspectImage { image: PathBuf },
    /// Inventory standalone Mach-O files in an extracted filesystem.
    Inventory {
        root: PathBuf,
        #[arg(long)]
        build: String,
        #[arg(long, default_value = ".stela/inventory.json")]
        output: PathBuf,
    },
    /// Track per-build translation stages and hashed evidence.
    Progress {
        #[command(subcommand)]
        command: ProgressCommand,
    },
}

#[derive(Subcommand)]
enum Images {
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

#[derive(Subcommand)]
enum ProgressCommand {
    Init {
        inventory: PathBuf,
        #[arg(long, default_value = ".stela/progress.json")]
        ledger: PathBuf,
    },
    Status {
        #[arg(long, default_value = ".stela/progress.json")]
        ledger: PathBuf,
    },
    Record {
        id: String,
        #[arg(long)]
        stage: Stage,
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long, default_value = ".stela/progress.json")]
        ledger: PathBuf,
    },
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Images { command } => match command {
            Images::List { model } => {
                let mut images = stela_apple::catalog()?;
                if let Some(model) = model {
                    images.retain(|i| i.models.contains(&model));
                }
                println!("{}", serde_json::to_string_pretty(&images)?);
            }
            Images::Fetch {
                build,
                model,
                output_dir,
                dry_run,
            } => {
                let images = stela_apple::catalog()?;
                let image = stela_apple::select(&images, build.as_deref(), model.as_deref())?;
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
                    let receipt = stela_apple::download(&image, &output)?;
                    println!("{}", serde_json::to_string_pretty(&receipt)?);
                    eprintln!("Saved {}", output.display());
                }
            }
        },
        Command::InspectImage { image } => {
            let mut archive = zip::ZipArchive::new(File::open(image)?)?;
            let mut members = vec![];
            for i in 0..archive.len() {
                let file = archive.by_index(i)?;
                members.push(serde_json::json!({"name": file.name(), "bytes": file.size(), "compressed_bytes": file.compressed_size()}));
            }
            println!("{}", serde_json::to_string_pretty(&members)?);
        }
        Command::Inventory {
            root,
            build,
            output,
        } => {
            ensure!(
                !output.exists(),
                "inventory already exists; use a new output path for each scan"
            );
            let inventory = stela_macho::scan(&root, &build)?;
            write_json(&output, &inventory)?;
            eprintln!(
                "{} slices, {} scan errors, {} excluded containers; {}",
                inventory.artifacts.len(),
                inventory.issues.len(),
                inventory.excluded_containers.len(),
                output.display()
            );
            ensure!(
                inventory.issues.is_empty(),
                "inventory saved but scan was incomplete; inspect its issues before using it"
            );
        }
        Command::Progress { command } => match command {
            ProgressCommand::Init { inventory, ledger } => {
                ensure!(
                    !ledger.exists(),
                    "ledger exists; choose another --ledger to preserve progress"
                );
                let bytes = std::fs::read(inventory)?;
                let inventory = serde_json::from_slice(&bytes)?;
                write_json(&ledger, &Progress::new(inventory, &bytes)?)?;
                eprintln!("Created {}", ledger.display());
            }
            ProgressCommand::Status { ledger } => {
                let progress: Progress = read_json(&ledger)?;
                println!("{}", serde_json::to_string_pretty(&progress.report()?)?);
            }
            ProgressCommand::Record {
                id,
                stage,
                evidence,
                ledger,
            } => {
                let mut progress: Progress = read_json(&ledger)?;
                progress
                    .report()
                    .context("existing evidence validation failed")?;
                progress.record(&id, stage, &evidence)?;
                write_json(&ledger, &progress)?;
            }
        },
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}
