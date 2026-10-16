//! Ahead-of-time compilation commands and the host capability report.
use crate::args::*;
use anyhow::{Context, Result, ensure};
use clap::Args;
use std::path::PathBuf;
use stela_core::write_json;

mod profile;
pub(crate) use profile::block_profile;
use profile::*;

#[derive(Args)]
pub(crate) struct CompileBlock {
    input: PathBuf,
    /// Select native host features or an explicit portable AOT tier.
    #[arg(long,default_value="native",value_parser=parse_cpu_target)]
    cpu_target: stela_compiler::TargetCpu,
    #[arg(long, default_value = "0x100000", value_parser = parse_address)]
    guest_base: u64,
    /// Compile for an explicit guest execution profile.
    #[arg(long, requires_all = ["svl_bytes", "svcr"], value_parser = [stela_compiler::extended::PROFILE_ID, stela_compiler::extended::DECLARED_PROFILE_ID])]
    guest_profile: Option<String>,
    /// Streaming vector length in bytes: 16, 32, 64, 128 or 256.
    #[arg(long, requires = "guest_profile", value_parser = parse_scalable_vector_length)]
    svl_bytes: Option<stela_compiler::aarch64::scalable::VectorLength>,
    /// Explicit initial SVCR bits: streaming mode is bit0, ZA enable is bit1.
    #[arg(long, requires = "guest_profile", value_parser = parse_scalable_mode)]
    svcr: Option<stela_compiler::aarch64::scalable::ScalableMode>,
    /// Explicit architectural feature declaration; repeat for each V2 feature.
    #[arg(long, requires = "guest_profile")]
    guest_feature: Vec<String>,
    /// Explicit maximum streaming vector length for the V2 guest profile.
    #[arg(long, requires = "guest_profile", value_parser = parse_scalable_vector_length)]
    max_svl_bytes: Option<stela_compiler::aarch64::scalable::VectorLength>,
    /// Explicit V2 ZT0 permission: true or false.
    #[arg(long, requires = "guest_profile", num_args = 1)]
    zt0_enabled: Option<bool>,
    /// Effective indirect FPMR access; V2 only, omission means disabled.
    #[arg(long, requires = "guest_profile", num_args = 1)]
    fpmr_enabled: Option<bool>,
    /// Explicit effective FullA64 availability for contextual blocks.
    #[arg(long, requires = "guest_profile", num_args = 1)]
    full_a64: Option<bool>,
    /// Explicit extended BF16 availability for contextual blocks.
    #[arg(long, requires = "guest_profile", num_args = 1)]
    ebf16: Option<bool>,
    /// Explicit reciprocal precision availability for contextual blocks.
    #[arg(long, requires = "guest_profile", num_args = 1)]
    rpres: Option<bool>,
    #[arg(long)]
    output_dir: PathBuf,
    /// Emit explicit software PAuth helper boundaries; preparation needs no keys.
    #[arg(long)]
    software_pauth: bool,
    /// Prepare reviewed clock helper boundaries without executing a clock service.
    #[arg(long, requires = "software_pauth")]
    software_clock: bool,
    /// Prepare guest TPIDRRO_EL0 reads without supplying a thread context.
    #[arg(long)]
    thread_registers: bool,
    /// Prepare source-bound System exits without supplying a CPU/service backend.
    #[arg(long, conflicts_with_all = ["software_pauth", "software_clock", "thread_registers"])]
    system_boundaries: bool,
    /// Prepare the typed EL1 platform ABI; no CPU, memory or service owner is supplied.
    #[arg(long, conflicts_with_all = ["system_boundaries", "software_pauth", "software_clock", "thread_registers", "guest_profile", "checked_memory_sa0_off", "checked_process_sa0_off"])]
    el1_platform: bool,
    /// Prepare checked GPR memory with SA0 disabled; no CPU/native entry is supplied.
    #[arg(long, conflicts_with_all = ["system_boundaries", "software_pauth", "software_clock", "thread_registers", "guest_profile"])]
    checked_memory_sa0_off: bool,
    /// Prepare checked memory plus PAuth/clock/TSD exits with SA0 disabled; no native entry.
    #[arg(long, conflicts_with_all = ["checked_memory_sa0_off", "system_boundaries", "software_pauth", "software_clock", "thread_registers", "guest_profile"])]
    checked_process_sa0_off: bool,
    /// Select explicit CPA effects for checked preparation; no CPU/native grant.
    #[arg(long,requires="checked_process_sa0_off",value_parser=parse_pointer_mode)]
    checked_pointer_mode: Option<stela_compiler::context::pointer::EffectivePointerChecks>,
}

#[derive(Args)]
pub(crate) struct PrepareLeaf {
    input: PathBuf,
    #[arg(long, default_value = "0x100000", value_parser = parse_address)]
    guest_base: u64,
    #[arg(long, default_value = ".stela/cache/leaf-v1")]
    cache_dir: PathBuf,
}

#[derive(Args)]
pub(crate) struct CompileLeaf {
    input: PathBuf,
    /// Select native host features or an explicit portable AOT tier.
    #[arg(long,default_value="native",value_parser=parse_cpu_target)]
    cpu_target: stela_compiler::TargetCpu,
    #[arg(long, default_value = "0x100000", value_parser = parse_address)]
    guest_base: u64,
    /// Compile for an explicit guest execution profile.
    #[arg(long, requires_all = ["svl_bytes", "svcr"], value_parser = [stela_compiler::extended::PROFILE_ID, stela_compiler::extended::DECLARED_PROFILE_ID])]
    guest_profile: Option<String>,
    /// Streaming vector length in bytes: 16, 32, 64, 128 or 256.
    #[arg(long, requires = "guest_profile", value_parser = parse_scalable_vector_length)]
    svl_bytes: Option<stela_compiler::aarch64::scalable::VectorLength>,
    /// Explicit initial SVCR bits: streaming mode is bit0, ZA enable is bit1.
    #[arg(long, requires = "guest_profile", value_parser = parse_scalable_mode)]
    svcr: Option<stela_compiler::aarch64::scalable::ScalableMode>,
    /// Explicit architectural feature declaration; repeat for each V2 feature.
    #[arg(long, requires = "guest_profile")]
    guest_feature: Vec<String>,
    /// Explicit maximum streaming vector length for the V2 guest profile.
    #[arg(long, requires = "guest_profile", value_parser = parse_scalable_vector_length)]
    max_svl_bytes: Option<stela_compiler::aarch64::scalable::VectorLength>,
    /// Explicit V2 ZT0 permission: true or false.
    #[arg(long, requires = "guest_profile", num_args = 1)]
    zt0_enabled: Option<bool>,
    /// Effective indirect FPMR access; V2 only, omission means disabled.
    #[arg(long, requires = "guest_profile", num_args = 1)]
    fpmr_enabled: Option<bool>,
    #[arg(long)]
    output_dir: PathBuf,
}

pub(crate) fn cpu_info() -> Result<()> {
    use stela_compiler::{
        TargetCpu,
        x86_64::isa::{ShiftOpcode, SimdOpcode},
    };
    let opcodes: Vec<_> = SimdOpcode::ALL
        .iter()
        .map(|opcode| {
            serde_json::json!({
                "mnemonic": opcode.mnemonic(), "opcode_bytes": opcode.encoding(),
                "minimum_target": opcode.requires().id(),
                "available_on_host": opcode.requires().supported(),
                "lowering_enabled": true,
            })
        })
        .collect();
    let shifts: Vec<_> = ShiftOpcode::ALL
        .iter()
        .map(|opcode| {
            serde_json::json!({
                "mnemonic":opcode.mnemonic(), "opcode_bytes":[0x66,0x0f,opcode.opcode()],
                "modrm_group":opcode.group(), "minimum_target":TargetCpu::Baseline.id(),
            })
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "detected_target": TargetCpu::detect().id(),
            "baseline": TargetCpu::Baseline.id(),
            "atomic_load16": TargetCpu::detect().supports(TargetCpu::AtomicLoad16),
            "cx16": TargetCpu::detect().supports(TargetCpu::Cx16),
            "cx8": TargetCpu::detect().supports(TargetCpu::Cx8),
            "simd_opcodes": opcodes,
            "simd_immediate_shifts": shifts,
            "scope": "Named legacy SIMD output forms; scalar encoding recipes remain in x86_64 modules. Catalog membership is not input ISA coverage.",
        }))?
    );
    Ok(())
}

impl CompileBlock {
    pub(crate) fn run(self) -> Result<()> {
        let Self {
            input,
            cpu_target,
            guest_base,
            guest_profile,
            svl_bytes,
            svcr,
            guest_feature,
            max_svl_bytes,
            zt0_enabled,
            fpmr_enabled,
            full_a64,
            ebf16,
            rpres,
            output_dir,
            software_pauth,
            software_clock,
            thread_registers,
            system_boundaries,
            el1_platform,
            checked_memory_sa0_off,
            checked_process_sa0_off,
            checked_pointer_mode,
        } = self;
        let profile = if el1_platform {
            stela_compiler::block::BlockProfile::El1PlatformV1
        } else if checked_process_sa0_off {
            stela_compiler::block::BlockProfile::CheckedMemoryPauthClockThread(checked_process(
                checked_pointer_mode,
            )?)
        } else if checked_memory_sa0_off {
            stela_compiler::block::BlockProfile::CheckedMemory(
                stela_compiler::block::CheckedMemoryProfile::SpAlignmentDisabled,
            )
        } else if system_boundaries {
            stela_compiler::block::BlockProfile::SystemV1
        } else {
            block_profile(software_pauth, software_clock, thread_registers)
        };
        let scalable = compile_scalable_profile(
            guest_profile.as_deref(),
            svl_bytes,
            svcr,
            &guest_feature,
            max_svl_bytes,
            zt0_enabled,
            fpmr_enabled,
        )?;
        let context_profile =
            compile_context_block_profile(scalable, profile, full_a64, ebf16, rpres)?;
        let source = std::fs::read(&input)?;
        let window = &source[..source
            .len()
            .min(stela_compiler::block::MAX_BLOCK_INSTRUCTIONS * 4)];
        let preparation_plan = if checked_memory_sa0_off || checked_process_sa0_off || el1_platform
        {
            Some(stela_compiler::block::CompilationPlan::new(
                window,
                stela_compiler::GuestAddress(guest_base),
                profile,
                cpu_target,
            )?)
        } else {
            None
        };
        let preparation_requirements = preparation_plan
            .as_ref()
            .and_then(|plan| plan.memory_requirements());
        let compiled = if let Some(context_profile) = context_profile {
            stela_compiler::extended::block::compile_for_profile(
                window,
                stela_compiler::GuestAddress(guest_base),
                context_profile,
                cpu_target,
            )?
        } else if let Some(plan) = preparation_plan {
            plan.compile()?
        } else {
            stela_compiler::block::compile_for_target(
                window,
                stela_compiler::GuestAddress(guest_base),
                profile,
                cpu_target,
            )?
        };
        ensure!(
            !output_dir.exists(),
            "output directory exists; choose a new one"
        );
        std::fs::create_dir_all(&output_dir)?;
        std::fs::write(output_dir.join("native.bin"), &compiled.native.x86_64_code)?;
        let mut manifest = serde_json::json!({"schema_version":1,"kind":"raw_arm64_block_aot","target_cpu":cpu_target.id(),
            "source_bytes":compiled.source_bytes,"source_sha256":stela_core::sha256(&source[..compiled.source_bytes]),
            "guest_base":guest_base,"abi":profile.abi(),
            "native_sha256":stela_core::sha256(&compiled.native.x86_64_code),
            "native_bytes":compiled.native.x86_64_code.len(),"source_map":compiled.native.source_map,
            "compiler_source_sha256":stela_compiler::SOURCE_SHA256,
            "verified":false});
        if el1_platform || preparation_requirements.is_some() {
            manifest["memory_requirements"] = serde_json::to_value(preparation_requirements)?;
        }
        if let Some(context_profile) = context_profile {
            manifest["schema_version"] = serde_json::json!(2);
            manifest["abi"] = serde_json::json!(stela_compiler::context::CONTEXT_BLOCK_ABI);
            manifest["execution_profile"] =
                scalable_execution_manifest(context_profile.scalable(), fpmr_enabled)?;
            manifest["numerical_features"] =
                serde_json::to_value(context_profile.numerical_features())?;
            manifest["guest_instructions"] =
                serde_json::json!(compiled.source_bytes / size_of::<u32>());
            manifest["entry_prefix_bytes"] =
                serde_json::json!(stela_compiler::extended::CONTEXT_WRAPPER_BYTES);
        }
        write_json(&output_dir.join("manifest.json"), &manifest)?;
        println!("{}", serde_json::to_string_pretty(&manifest)?);
        Ok(())
    }
}

impl PrepareLeaf {
    pub(crate) fn run(self) -> Result<()> {
        let Self {
            input,
            guest_base,
            cache_dir,
        } = self;
        let source = std::fs::read(input)?;
        let prepared = stela_runtime::prepare_leaf(
            &source,
            stela_compiler::GuestAddress(guest_base),
            &cache_dir,
        )?;
        println!("{}", serde_json::to_string_pretty(&prepared)?);
        Ok(())
    }
}

impl CompileLeaf {
    pub(crate) fn run(self) -> Result<()> {
        let Self {
            input,
            cpu_target,
            guest_base,
            guest_profile,
            svl_bytes,
            svcr,
            guest_feature,
            max_svl_bytes,
            zt0_enabled,
            fpmr_enabled,
            output_dir,
        } = self;
        let profile = compile_scalable_profile(
            guest_profile.as_deref(),
            svl_bytes,
            svcr,
            &guest_feature,
            max_svl_bytes,
            zt0_enabled,
            fpmr_enabled,
        )?;
        let source = std::fs::read(&input)?;
        let memory_requirements = profile
            .map(|profile| {
                stela_compiler::extended::memory_requirements(
                    &source,
                    stela_compiler::GuestAddress(guest_base),
                    profile,
                    cpu_target,
                )
            })
            .transpose()?;
        let block = if let Some(profile) = profile {
            stela_compiler::extended::compile_for_profile(
                &source,
                stela_compiler::GuestAddress(guest_base),
                profile,
                cpu_target,
            )?
        } else {
            stela_compiler::compile_for_target(
                &source,
                stela_compiler::GuestAddress(guest_base),
                cpu_target,
            )?
        };
        ensure!(
            !output_dir.exists(),
            "output directory exists; choose a new one"
        );
        if let Some(parent) = output_dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::create_dir(&output_dir)?;
        std::fs::write(output_dir.join("native.bin"), &block.x86_64_code)?;
        let mut manifest = serde_json::json!({
            "schema_version": 1,
            "kind": "raw_arm64_leaf_aot",
            "target_cpu":cpu_target.id(),
            "source_sha256": stela_core::sha256(&source),
            "guest_base": guest_base,
            "guest_instructions": source.len() / 4,
            "native_sha256": stela_core::sha256(&block.x86_64_code),
            "native_bytes": block.x86_64_code.len(),
            "source_map": block.source_map,
            "abi": stela_compiler::NATIVE_ABI,
            "compiler_source_sha256": stela_compiler::SOURCE_SHA256,
            "verified": false,
        });
        if let Some(profile) = profile {
            manifest["schema_version"] = serde_json::json!(2);
            manifest["abi"] = serde_json::json!(stela_compiler::context::CONTEXT_LEAF_ABI);
            manifest["execution_profile"] = scalable_execution_manifest(profile, fpmr_enabled)?;
            manifest["entry_prefix_bytes"] =
                serde_json::json!(stela_compiler::extended::CONTEXT_WRAPPER_BYTES);
            let requirements = memory_requirements
                .context("context leaf requires compiler-derived memory metadata")?;
            use stela_compiler::context::memory::SpAlignmentRequirement;
            let sp_alignment = match requirements.required_sp_alignment {
                SpAlignmentRequirement::Any => "any",
                SpAlignmentRequirement::Enabled => "enabled",
                SpAlignmentRequirement::Disabled => "disabled",
            };
            manifest["memory_requirements"] = serde_json::json!({
                "required_flags": requirements.required_flags,
                "required_host_caps": requirements.required_host_caps,
                "required_profile": requirements.required_profile,
                "required_sp_alignment": sp_alignment,
            });
            use stela_compiler::context::memory::{
                MEMORY_IMPLEMENTATION_PROFILE_ID, profile_requirements,
            };
            manifest["memory_implementation_profile"] = serde_json::json!(
                (requirements.required_profile & profile_requirements::NATIVE_ACCESS != 0)
                    .then_some(MEMORY_IMPLEMENTATION_PROFILE_ID)
            );
        }
        write_json(&output_dir.join("manifest.json"), &manifest)?;
        println!("{}", serde_json::to_string_pretty(&manifest)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
