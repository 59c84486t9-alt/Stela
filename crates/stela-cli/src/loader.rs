//! Mach-O planning, dependency discovery, inventories and progress ledgers.
use crate::{args::*, input::pauth_all_keys_context};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use std::path::PathBuf;
use stela_loader as macho;
use stela_loader::inventory::{Progress, Stage};
use stela_runtime::{read_json, write_json};

#[derive(Subcommand)]
pub(crate) enum ProgressCommand {
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

#[derive(Args)]
pub(crate) struct DiscoverImages {
    input: PathBuf,
    #[arg(long)]
    guest_root: PathBuf,
    #[arg(long)]
    guest_path: Option<String>,
    #[arg(long, value_parser = ["arm64", "arm64e"])]
    architecture: Option<String>,
    #[arg(long, value_parser = parse_address)]
    image_base: Option<u64>,
    #[arg(long, default_value = "0x50000000000", value_parser = parse_address)]
    library_base: u64,
    #[arg(long, default_value = "0x10000000000", value_parser = parse_address)]
    library_stride: u64,
}

#[derive(Args)]
pub(crate) struct PlanFixups {
    input: PathBuf,
    #[arg(long, value_parser = ["arm64", "arm64e"])]
    architecture: Option<String>,
    #[arg(long, value_parser = parse_address)]
    image_base: Option<u64>,
    /// Plan authenticated rebases with the given IA/IB/DA/DB keys.
    #[arg(long)]
    software_pauth_keys: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct PlanExecutable {
    input: PathBuf,
    #[arg(long, value_parser = ["arm64", "arm64e"])]
    architecture: Option<String>,
}

#[derive(Args)]
pub(crate) struct Inventory {
    root: PathBuf,
    #[arg(long)]
    build: String,
    #[arg(long, default_value = ".stela/inventory.json")]
    output: PathBuf,
}

impl DiscoverImages {
    pub(crate) fn run(self) -> Result<()> {
        let Self {
            input,
            guest_root,
            guest_path,
            architecture,
            image_base,
            library_base,
            library_stride,
        } = self;
        let discovery = macho::dependency_graph::discover(
            &input,
            macho::dependency_graph::DiscoveryOptions {
                guest_root,
                guest_path,
                architecture,
                image_base,
                library_base,
                library_stride,
            },
        )?;
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({"kind":"dependency_discovery",
            "graph":discovery.graph,"complete_binary_verified":false}))?
        );
        Ok(())
    }
}

impl PlanFixups {
    pub(crate) fn run(self) -> Result<()> {
        let Self {
            input,
            architecture,
            image_base,
            software_pauth_keys,
        } = self;
        let data = std::fs::read(&input)?;
        let (slice_offset, bytes) = macho::select_slice(&data, &input, architecture.as_deref())?;
        let file_type = u32::from_le_bytes(
            bytes
                .get(12..16)
                .context("truncated Mach header")?
                .try_into()?,
        );
        let plan = match file_type {
            6 => macho::load_plan::plan_library(bytes)?,
            7 => macho::load_plan::plan_dynamic_linker(bytes)?.image,
            _ => macho::load_plan::plan(bytes)?,
        };
        let preferred = plan
            .segments
            .iter()
            .find(|segment| segment.name == "__TEXT")
            .context("missing preferred image base")?
            .guest
            .address;
        let load_base = image_base.unwrap_or(preferred);
        let (fixups, decoded_fixups) = if let Some(path) = software_pauth_keys.as_deref() {
            let context = pauth_all_keys_context(path, 1)?;
            let decoded = macho::chained_fixups::decode_authenticated(bytes, &plan, load_base)?;
            (
                serde_json::to_value(decoded.sign_rebases(&context)?)?,
                Some(decoded),
            )
        } else {
            (
                serde_json::to_value(macho::chained_fixups::plan(bytes, &plan, load_base)?)?,
                None,
            )
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "kind":"chained_fixup_plan","container_sha256":stela_runtime::sha256(&data),
                "slice_offset":slice_offset,"plan":plan,"fixups":fixups,"decoded_fixups":decoded_fixups,
                "fixups_applied":false,"native_executed":false,"complete_binary_verified":false
            }))?
        );
        Ok(())
    }
}

impl PlanExecutable {
    pub(crate) fn run(self) -> Result<()> {
        let Self {
            input,
            architecture,
        } = self;
        let data = std::fs::read(&input)?;
        let (offset, bytes) = macho::select_slice(&data, &input, architecture.as_deref())?;
        let plan = macho::load_plan::plan(bytes)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "kind": "macho_executable_load_plan", "container_sha256": stela_runtime::sha256(&data),
                "slice_offset": offset, "plan": plan
            }))?
        );
        Ok(())
    }
}

impl Inventory {
    pub(crate) fn run(self) -> Result<()> {
        let Self {
            root,
            build,
            output,
        } = self;
        ensure!(
            !output.exists(),
            "inventory already exists; use a new output path for each scan"
        );
        let inventory = stela_loader::scan(&root, &build)?;
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
        Ok(())
    }
}

impl ProgressCommand {
    pub(crate) fn run(self) -> Result<()> {
        match self {
            Self::Init { inventory, ledger } => {
                ensure!(
                    !ledger.exists(),
                    "ledger exists; choose another --ledger to preserve progress"
                );
                let bytes = std::fs::read(inventory)?;
                let inventory = serde_json::from_slice(&bytes)?;
                write_json(&ledger, &Progress::new(inventory, &bytes)?)?;
                eprintln!("Created {}", ledger.display());
            }
            Self::Status { ledger } => {
                let progress: Progress = read_json(&ledger)?;
                println!("{}", serde_json::to_string_pretty(&progress.report()?)?);
            }
            Self::Record {
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
        }
        Ok(())
    }
}
