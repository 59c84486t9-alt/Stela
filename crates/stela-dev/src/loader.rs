//! Mach-O planning and dependency discovery.
use crate::{args::*, input::pauth_all_keys_context};
use anyhow::{Context, Result};
use clap::Args;
use std::path::PathBuf;
use stela_loader as macho;

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
                "kind":"chained_fixup_plan","container_sha256":stela_formats::sha256(&data),
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
                "kind": "macho_executable_load_plan", "container_sha256": stela_formats::sha256(&data),
                "slice_offset": offset, "plan": plan
            }))?
        );
        Ok(())
    }
}
