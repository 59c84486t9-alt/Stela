//! Ahead-of-time compilation commands and the host capability report.
use crate::args::*;
use anyhow::{Context, Result, ensure};
use clap::Args;
use std::path::{Path, PathBuf};
use stela_compiler::{
    GuestAddress, Options,
    block::{BlockProfile, CompilationPlan, Features},
    scalable_context::ScalableProfile,
};
use stela_engine::write_json;

mod profile;
mod throughput;
pub(crate) use profile::block_profile;
use profile::*;
pub(crate) use throughput::CompileThroughput;

#[derive(Args)]
pub(crate) struct CompileBlock {
    input: PathBuf,
    /// Use the host's CPU features, or a portable feature tier.
    #[arg(long,default_value="native",value_parser=parse_cpu_target)]
    cpu_target: stela_compiler::TargetCpu,
    #[arg(long, default_value = "0x100000", value_parser = parse_address)]
    guest_base: u64,
    /// Compile for a guest execution profile.
    #[arg(long, requires_all = ["svl_bytes", "svcr"], value_parser = [stela_compiler::scalable_context::PROFILE_ID, stela_compiler::scalable_context::DECLARED_PROFILE_ID])]
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
    /// Emit software PAuth helper calls; no keys are needed to compile.
    #[arg(long)]
    software_pauth: bool,
    /// Emit clock helper calls.
    #[arg(long, requires = "software_pauth")]
    software_clock: bool,
    /// Prepare guest TPIDRRO_EL0 reads without supplying a thread context.
    #[arg(long)]
    thread_registers: bool,
    /// Prepare source-bound System exits without supplying a CPU/service backend.
    #[arg(long, conflicts_with_all = ["software_pauth", "software_clock", "thread_registers"])]
    system_boundaries: bool,
    /// Compile for the system-mode engine: guest VAs, EL1/EL2 code and an exit
    /// at every System instruction. No CPU or memory owner is supplied.
    #[arg(long, conflicts_with_all = ["system_boundaries", "software_pauth", "software_clock", "thread_registers", "guest_profile", "checked_memory_sa0_off", "checked_process_sa0_off"])]
    system_mode: bool,
    /// Prepare checked GPR memory with SA0 disabled; no CPU/native entry is supplied.
    #[arg(long, conflicts_with_all = ["system_boundaries", "software_pauth", "software_clock", "thread_registers", "guest_profile"])]
    checked_memory_sa0_off: bool,
    /// Prepare checked memory plus PAuth/clock/TSD exits with SA0 disabled; no native entry.
    #[arg(long, conflicts_with_all = ["checked_memory_sa0_off", "system_boundaries", "software_pauth", "software_clock", "thread_registers", "guest_profile"])]
    checked_process_sa0_off: bool,
    /// FEAT_CPA effects for checked compilation.
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
    /// Use the host's CPU features, or a portable feature tier.
    #[arg(long,default_value="native",value_parser=parse_cpu_target)]
    cpu_target: stela_compiler::TargetCpu,
    #[arg(long, default_value = "0x100000", value_parser = parse_address)]
    guest_base: u64,
    /// Compile for a guest execution profile.
    #[arg(long, requires_all = ["svl_bytes", "svcr"], value_parser = [stela_compiler::scalable_context::PROFILE_ID, stela_compiler::scalable_context::DECLARED_PROFILE_ID])]
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
    /// What the block compiles for: its services, or for a scalable guest
    /// the context block's specialization.
    fn options(&self) -> Result<Options> {
        let services = if self.system_mode {
            BlockProfile::new(Features::SYSTEM_MODE)
        } else if self.checked_process_sa0_off {
            BlockProfile::new(Features::PROCESS_HELPERS)
                .with_checked_memory(checked_process(self.checked_pointer_mode)?)
        } else if self.checked_memory_sa0_off {
            BlockProfile::ORDINARY.with_checked_memory(
                stela_compiler::block::CheckedMemoryProfile::SpAlignmentDisabled,
            )
        } else if self.system_boundaries {
            BlockProfile::new(Features::SYSTEM)
        } else {
            block_profile(
                self.software_pauth,
                self.software_clock,
                self.thread_registers,
            )
        };
        let scalable = compile_scalable_profile(
            self.guest_profile.as_deref(),
            self.svl_bytes,
            self.svcr,
            &self.guest_feature,
            self.max_svl_bytes,
            self.zt0_enabled,
            self.fpmr_enabled,
        )?;
        let context = compile_context_block_profile(
            scalable,
            services,
            self.full_a64,
            self.ebf16,
            self.rpres,
        )?;
        Ok(match context {
            Some((scalable, numerical)) => {
                Options::new(BlockProfile::new(Features::CONTEXT), self.cpu_target)
                    .with_scalable(scalable)
                    .with_numerical_features(numerical)
            }
            None => Options::new(services, self.cpu_target),
        })
    }

    fn compile(self, source: &[u8]) -> Result<Compiled> {
        let options = self.options()?;
        let Self {
            cpu_target,
            guest_base,
            fpmr_enabled,
            ..
        } = self;
        let window = &source[..source
            .len()
            .min(stela_compiler::block::MAX_BLOCK_INSTRUCTIONS * 4)];
        let plan = CompilationPlan::new(window, GuestAddress(guest_base), &options)?;
        let preparation_requirements = plan.memory_requirements();
        let compiled = plan.compile()?;
        let mut manifest = serde_json::json!({"schema_version":1,"kind":"raw_arm64_block_aot","target_cpu":cpu_target.id(),
            "source_bytes":compiled.source_bytes,"source_sha256":stela_formats::sha256(&source[..compiled.source_bytes]),
            "guest_base":guest_base,"abi":options.profile().abi(),
            "native_sha256":stela_formats::sha256(&compiled.native.x86_64_code),
            "native_bytes":compiled.native.x86_64_code.len(),"source_map":compiled.native.source_map,
            "compiler_source_sha256":stela_compiler::SOURCE_SHA256,
            "verified":false});
        if preparation_requirements.is_some() {
            manifest["memory_requirements"] = serde_json::to_value(preparation_requirements)?;
        }
        if let Some(scalable) = options.scalable() {
            manifest["schema_version"] = serde_json::json!(2);
            manifest["execution_profile"] = scalable_execution_manifest(scalable, fpmr_enabled)?;
            manifest["numerical_features"] = serde_json::to_value(options.numerical_features())?;
            manifest["guest_instructions"] =
                serde_json::json!(compiled.source_bytes / size_of::<u32>());
            manifest["entry_prefix_bytes"] =
                serde_json::json!(stela_compiler::scalable_context::CONTEXT_WRAPPER_BYTES);
        }
        Ok(Compiled {
            native: compiled.native.x86_64_code,
            manifest,
        })
    }

    pub(crate) fn run(self) -> Result<()> {
        let source = std::fs::read(&self.input)?;
        let output = self.output_dir.clone();
        self.compile(&source)?.write(&output)
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
        let prepared = stela_engine::prepare_leaf(
            &source,
            stela_compiler::GuestAddress(guest_base),
            &cache_dir,
        )?;
        println!("{}", serde_json::to_string_pretty(&prepared)?);
        Ok(())
    }
}

impl CompileLeaf {
    /// The scalable guest profile, when one is declared.
    fn profile(&self) -> Result<Option<ScalableProfile>> {
        compile_scalable_profile(
            self.guest_profile.as_deref(),
            self.svl_bytes,
            self.svcr,
            &self.guest_feature,
            self.max_svl_bytes,
            self.zt0_enabled,
            self.fpmr_enabled,
        )
    }

    fn compile(self, source: &[u8]) -> Result<Compiled> {
        let profile = self.profile()?;
        let Self {
            cpu_target,
            guest_base,
            fpmr_enabled,
            ..
        } = self;
        let options = match profile {
            Some(scalable) => Options::new(
                BlockProfile::new(Features::LEAF | Features::CONTEXT),
                cpu_target,
            )
            .with_scalable(scalable),
            None => Options::new(BlockProfile::new(Features::LEAF), cpu_target),
        };
        let plan = CompilationPlan::new(source, GuestAddress(guest_base), &options)?;
        let memory_requirements = plan.memory_requirements();
        let block = plan.compile()?.native;
        let mut manifest = serde_json::json!({
            "schema_version": 1,
            "kind": "raw_arm64_leaf_aot",
            "target_cpu":cpu_target.id(),
            "source_sha256": stela_formats::sha256(source),
            "guest_base": guest_base,
            "guest_instructions": source.len() / 4,
            "native_sha256": stela_formats::sha256(&block.x86_64_code),
            "native_bytes": block.x86_64_code.len(),
            "source_map": block.source_map,
            "abi": options.profile().abi(),
            "compiler_source_sha256": stela_compiler::SOURCE_SHA256,
            "verified": false,
        });
        if let Some(profile) = profile {
            manifest["schema_version"] = serde_json::json!(2);
            manifest["execution_profile"] = scalable_execution_manifest(profile, fpmr_enabled)?;
            manifest["entry_prefix_bytes"] =
                serde_json::json!(stela_compiler::scalable_context::CONTEXT_WRAPPER_BYTES);
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
        Ok(Compiled {
            native: block.x86_64_code,
            manifest,
        })
    }

    pub(crate) fn run(self) -> Result<()> {
        let source = std::fs::read(&self.input)?;
        let output = self.output_dir.clone();
        self.compile(&source)?.write(&output)
    }
}

/// Native code and its manifest for one compiled source.
pub struct Compiled {
    pub native: Vec<u8>,
    pub manifest: serde_json::Value,
}

impl Compiled {
    fn write(&self, output: &Path) -> Result<()> {
        ensure!(
            !output.exists(),
            "output directory exists; choose a new one"
        );
        std::fs::create_dir_all(output)?;
        std::fs::write(output.join("native.bin"), &self.native)?;
        write_json(&output.join("manifest.json"), &self.manifest)?;
        println!("{}", serde_json::to_string_pretty(&self.manifest)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
