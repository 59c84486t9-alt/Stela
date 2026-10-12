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
    /// Export Mach-O text slices, symbols and bounded leaf-decoder recognition.
    BinaryText { input: PathBuf },
    /// Prepare a supported leaf function on demand; reuse an exact cached AOT.
    PrepareLeaf {
        input: PathBuf,
        #[arg(long, default_value = "0x100000", value_parser = parse_address)]
        guest_base: u64,
        #[arg(long, default_value = ".stela/cache/leaf-v1")]
        cache_dir: PathBuf,
    },
    /// AOT-compile a raw ARM64 leaf region with internal branches into x86.
    CompileLeaf {
        input: PathBuf,
        #[arg(long, default_value = "0x100000", value_parser = parse_address)]
        guest_base: u64,
        #[arg(long)]
        output_dir: PathBuf,
    },
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

fn parse_address(value: &str) -> Result<u64, String> {
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse()
    }
    .map_err(|e| e.to_string())
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
        Command::BinaryText { input } => {
            use stela_compiler::Lifter;
            let bytes = std::fs::read(&input)?;
            let slices = stela_macho::text_slices(&bytes, &input.display().to_string())?;
            let mut output = vec![];
            for slice in slices {
                let arm = matches!(slice.artifact.architecture.as_str(), "arm64" | "arm64e");
                let mut recognized = 0;
                let mut words = 0;
                if arm {
                    for section in &slice.sections {
                        let data = hex::decode(&section.data_hex)?;
                        for (index, word) in data.as_chunks::<4>().0.iter().enumerate() {
                            let pc = section
                                .guest_address
                                .checked_add(index as u64 * 4)
                                .context("text address overflow")?;
                            words += 1;
                            if stela_compiler::aarch64::Decoder
                                .lift(
                                    stela_compiler::GuestAddress(pc),
                                    u32::from_le_bytes(*word),
                                )
                                .is_ok()
                            {
                                recognized += 1;
                            }
                        }
                    }
                }
                output.push(serde_json::json!({"slice": slice, "arm64_text_words": words, "recognized_leaf_words": recognized,
                    "compiler_source_sha256": stela_core::sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
                    "note": "Word recognition is not function translation, reachability, or verified application coverage."}));
            }
            println!("{}", serde_json::to_string(&output)?);
        }
        Command::PrepareLeaf {
            input,
            guest_base,
            cache_dir,
        } => {
            let source = std::fs::read(input)?;
            let prepared = stela_runtime::prepare_leaf(
                &source,
                stela_compiler::GuestAddress(guest_base),
                &cache_dir,
            )?;
            println!("{}", serde_json::to_string_pretty(&prepared)?);
        }
        Command::CompileLeaf {
            input,
            guest_base,
            output_dir,
        } => {
            let source = std::fs::read(&input)?;
            let block =
                stela_compiler::compile(&source, stela_compiler::GuestAddress(guest_base))?;
            ensure!(
                !output_dir.exists(),
                "output directory exists; choose a new one"
            );
            if let Some(parent) = output_dir.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::create_dir(&output_dir)?;
            std::fs::write(output_dir.join("native.bin"), &block.x86_64_code)?;
            let manifest = serde_json::json!({
                "schema_version": 1,
                "kind": "raw_arm64_leaf_aot",
                "source_sha256": stela_core::sha256(&source),
                "guest_base": guest_base,
                "guest_instructions": source.len() / 4,
                "native_sha256": stela_core::sha256(&block.x86_64_code),
                "native_bytes": block.x86_64_code.len(),
                "source_map": block.source_map,
                "abi": "x86_64-sysv-guest-state-v1",
                "compiler_source_sha256": stela_core::sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
                "verified": false,
            });
            write_json(&output_dir.join("manifest.json"), &manifest)?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
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
