//! Ahead-of-time compilation commands and the host capability report.
use crate::args::*;
use anyhow::{Context, Result, ensure};
use clap::Args;
use clap::Parser;
use std::path::{Path, PathBuf};
use stela_compiler::{
    block::BlockProfile,
    extended::{ScalableProfile, block::ExtendedBlockProfile},
};
use stela_runtime::write_json;

mod profile;
pub(crate) use profile::block_profile;
use profile::*;

#[derive(Args)]
pub(crate) struct CompileBlock {
    input: PathBuf,
    /// Use the host's CPU features, or a portable feature tier.
    #[arg(long,default_value="native",value_parser=parse_cpu_target)]
    cpu_target: stela_compiler::TargetCpu,
    #[arg(long, default_value = "0x100000", value_parser = parse_address)]
    guest_base: u64,
    /// Compile for a guest execution profile.
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
    /// Prepare the typed EL1 platform ABI; no CPU, memory or service owner is supplied.
    #[arg(long, conflicts_with_all = ["system_boundaries", "software_pauth", "software_clock", "thread_registers", "guest_profile", "checked_memory_sa0_off", "checked_process_sa0_off"])]
    el1_platform: bool,
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
    /// The service profile and, for scalable guests, the contextual profile.
    fn profiles(&self) -> Result<(BlockProfile, Option<ExtendedBlockProfile>)> {
        let services = if self.el1_platform {
            BlockProfile::El1PlatformV1
        } else if self.checked_process_sa0_off {
            BlockProfile::CheckedMemoryPauthClockThread(checked_process(self.checked_pointer_mode)?)
        } else if self.checked_memory_sa0_off {
            BlockProfile::CheckedMemory(
                stela_compiler::block::CheckedMemoryProfile::SpAlignmentDisabled,
            )
        } else if self.system_boundaries {
            BlockProfile::SystemV1
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
        Ok((services, context))
    }

    fn compile(self, source: &[u8]) -> Result<Compiled> {
        let (profile, context_profile) = self.profiles()?;
        let Self {
            cpu_target,
            guest_base,
            fpmr_enabled,
            el1_platform,
            checked_memory_sa0_off,
            checked_process_sa0_off,
            ..
        } = self;
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
        let mut manifest = serde_json::json!({"schema_version":1,"kind":"raw_arm64_block_aot","target_cpu":cpu_target.id(),
            "source_bytes":compiled.source_bytes,"source_sha256":stela_runtime::sha256(&source[..compiled.source_bytes]),
            "guest_base":guest_base,"abi":profile.abi(),
            "native_sha256":stela_runtime::sha256(&compiled.native.x86_64_code),
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
        let memory_requirements = profile
            .map(|profile| {
                stela_compiler::extended::memory_requirements(
                    source,
                    stela_compiler::GuestAddress(guest_base),
                    profile,
                    cpu_target,
                )
            })
            .transpose()?;
        let block = if let Some(profile) = profile {
            stela_compiler::extended::compile_for_profile(
                source,
                stela_compiler::GuestAddress(guest_base),
                profile,
                cpu_target,
            )?
        } else {
            stela_compiler::compile_for_target(
                source,
                stela_compiler::GuestAddress(guest_base),
                cpu_target,
            )?
        };
        let mut manifest = serde_json::json!({
            "schema_version": 1,
            "kind": "raw_arm64_leaf_aot",
            "target_cpu":cpu_target.id(),
            "source_sha256": stela_runtime::sha256(source),
            "guest_base": guest_base,
            "guest_instructions": source.len() / 4,
            "native_sha256": stela_runtime::sha256(&block.x86_64_code),
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

/// The scalable guest profile a `compile-leaf` command line declares, if any.
pub fn context_leaf_profile(arguments: &[&str]) -> Result<Option<ScalableProfile>> {
    match crate::Cli::try_parse_from(arguments)?.command {
        crate::Command::CompileLeaf(command) => command.profile(),
        _ => anyhow::bail!("expected compile-leaf"),
    }
}

/// The contextual block profile a `compile-block` command line selects, if its
/// guest is scalable.
pub fn context_block_profile(arguments: &[&str]) -> Result<Option<ExtendedBlockProfile>> {
    match crate::Cli::try_parse_from(arguments)?.command {
        crate::Command::CompileBlock(command) => Ok(command.profiles()?.1),
        _ => anyhow::bail!("expected compile-block"),
    }
}

/// Compile `source` as the `compile-leaf` or `compile-block` command line in
/// `arguments` would, without reading the input or writing outputs.
pub fn compile(arguments: &[&str], source: &[u8]) -> Result<Compiled> {
    match crate::Cli::try_parse_from(arguments)?.command {
        crate::Command::CompileLeaf(command) => command.compile(source),
        crate::Command::CompileBlock(command) => command.compile(source),
        _ => anyhow::bail!("expected compile-leaf or compile-block"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Command};
    use clap::Parser;

    mod scalable {
        use super::*;

        fn resolve(extra: &[&str]) -> Result<Option<stela_compiler::extended::ScalableProfile>> {
            let mut args = vec!["stela", "compile-leaf", "input.bin", "--output-dir", "out"];
            args.extend_from_slice(extra);
            let Command::CompileLeaf(crate::compile::CompileLeaf {
                guest_profile,
                svl_bytes,
                svcr,
                guest_feature,
                max_svl_bytes,
                zt0_enabled,
                fpmr_enabled,
                ..
            }) = Cli::try_parse_from(args)?.command
            else {
                anyhow::bail!("expected compile-leaf");
            };
            compile_scalable_profile(
                guest_profile.as_deref(),
                svl_bytes,
                svcr,
                &guest_feature,
                max_svl_bytes,
                zt0_enabled,
                fpmr_enabled,
            )
        }

        #[test]
        fn existing_profile_identity_and_rejected_metadata() -> Result<()> {
            assert_eq!(resolve(&[])?, None);
            let original = [
                "--guest-profile",
                "apple-sme2-streaming-v1",
                "--svl-bytes",
                "64",
                "--svcr",
                "1",
            ];
            let profile = resolve(&original)?.unwrap();
            assert_eq!(profile.declared_features(), None);
            assert_eq!(profile.required_dit(), None);
            for extra in [
                vec!["--guest-feature", "FEAT_SME"],
                vec!["--max-svl-bytes", "64"],
                vec!["--zt0-enabled", "false"],
            ] {
                let mut args = original.to_vec();
                args.extend(extra);
                assert!(resolve(&args).is_err());
            }
            Ok(())
        }

        #[test]
        fn declared_profile_requires_and_preserves_explicit_metadata() -> Result<()> {
            let original = [
                "--guest-profile",
                "sme-streaming-v2",
                "--svl-bytes",
                "32",
                "--svcr",
                "2",
            ];
            for suffix in [
                vec![],
                vec!["--guest-feature", "FEAT_SME"],
                vec!["--guest-feature", "FEAT_SME", "--max-svl-bytes", "128"],
            ] {
                let mut args = original.to_vec();
                args.extend(suffix);
                assert!(resolve(&args).is_err());
            }
            let mut args = original.to_vec();
            args.extend([
                "--guest-feature",
                "FEAT_SME2",
                "--guest-feature",
                "FEAT_SME",
                "--max-svl-bytes",
                "128",
                "--zt0-enabled",
                "false",
            ]);
            let profile = resolve(&args)?.unwrap();
            assert_eq!(profile.features().names(), ["FEAT_SME", "FEAT_SME2"]);
            assert_eq!(profile.controls().max_vector_length().bytes(), 128);
            assert!(!profile.controls().zt0_enabled());
            assert_eq!(profile.required_dit(), Some(false));
            assert!(!profile.mode().streaming());
            assert!(profile.mode().za_enabled());
            Ok(())
        }
    }

    mod context_block {
        use super::*;
        use stela_compiler::{aarch64::floating::features::NumericalFeatures, block::BlockProfile};

        fn resolve(
            extra: &[&str],
        ) -> Result<Option<stela_compiler::extended::block::ExtendedBlockProfile>> {
            let mut args = vec!["stela", "compile-block", "input.bin", "--output-dir", "out"];
            args.extend_from_slice(extra);
            let Command::CompileBlock(crate::compile::CompileBlock {
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
                software_pauth,
                software_clock,
                thread_registers,
                system_boundaries,
                ..
            }) = Cli::try_parse_from(args)?.command
            else {
                anyhow::bail!("expected compile-block");
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
            compile_context_block_profile(
                scalable,
                if system_boundaries {
                    BlockProfile::SystemV1
                } else {
                    block_profile(software_pauth, software_clock, thread_registers)
                },
                full_a64,
                ebf16,
                rpres,
            )
        }

        #[test]
        fn contextual_numerical_declarations_are_explicit_and_separate() -> Result<()> {
            let guest = [
                "--guest-profile",
                "sme-streaming-v2",
                "--svl-bytes",
                "32",
                "--svcr",
                "3",
                "--guest-feature",
                "FEAT_SME",
                "--max-svl-bytes",
                "256",
                "--zt0-enabled",
                "false",
            ];
            let numerical = [
                "--full-a64",
                "false",
                "--ebf16",
                "false",
                "--rpres",
                "false",
            ];
            for omitted in 0..3 {
                let mut args = guest.to_vec();
                for (index, pair) in numerical.as_chunks::<2>().0.iter().enumerate() {
                    if index != omitted {
                        args.extend_from_slice(pair);
                    }
                }
                assert!(resolve(&args).is_err());
            }
            let mut args = guest.to_vec();
            args.extend(numerical);
            let profile = resolve(&args)?.unwrap();
            assert_eq!(profile.services(), BlockProfile::Ordinary);
            assert_eq!(
                profile.numerical_features(),
                NumericalFeatures::new(false, false, false)
            );
            assert_eq!(
                scalable_execution_manifest(profile.scalable(), None)?,
                serde_json::json!({
                    "id":"sme-streaming-v2", "svl_bytes":32, "svcr":3, "features":["FEAT_SME"],
                    "max_svl_bytes":256, "zt0_enabled":false, "dit":false
                })
            );
            for service in [
                "--software-pauth",
                "--thread-registers",
                "--system-boundaries",
            ] {
                let mut invalid = args.clone();
                invalid.push(service);
                assert!(resolve(&invalid).is_err());
            }
            Ok(())
        }

        #[test]
        fn ordinary_blocks_keep_their_profile_and_reject_numerical_options() -> Result<()> {
            assert_eq!(resolve(&[])?, None);
            assert_eq!(resolve(&["--system-boundaries"])?, None);
            assert_eq!(resolve(&["--software-pauth", "--software-clock"])?, None);
            for flag in ["--full-a64", "--ebf16", "--rpres"] {
                assert!(resolve(&[flag, "false"]).is_err());
            }
            Ok(())
        }
    }

    mod cpu_target {
        use super::*;

        #[test]
        fn cpu_selectors_keep_native_and_explicit_capabilities_distinct() {
            use stela_compiler::TargetCpu;
            assert_eq!(parse_cpu_target("native"), Ok(TargetCpu::detect()));
            assert_eq!(
                parse_cpu_target("baseline+popcnt+bmi1+aes+sha"),
                Ok(TargetCpu::Baseline
                    .with_popcnt()
                    .with_bmi1()
                    .with_aes()
                    .with_sha())
            );
            for invalid in ["native+aes", "baseline+sha+aes", "baseline+bmi1+bmi1"] {
                assert!(parse_cpu_target(invalid).is_err(), "{invalid}");
            }
        }
    }

    mod services {
        use super::*;

        #[test]
        fn clock_flags_require_their_explicit_parent_profiles() {
            for args in [
                vec![
                    "stela",
                    "run-blocks",
                    "code",
                    "--clock-snapshot",
                    "clock.json",
                ],
                vec![
                    "stela",
                    "probe-dyld-entry",
                    "dyld",
                    "--executable",
                    "app",
                    "--bootstrap-clock",
                ],
                vec![
                    "stela",
                    "probe-dyld-entry",
                    "dyld",
                    "--executable",
                    "app",
                    "--clock-snapshot",
                    "clock.json",
                ],
                vec![
                    "stela",
                    "compile-block",
                    "code",
                    "--output-dir",
                    "out",
                    "--software-clock",
                ],
            ] {
                assert!(Cli::try_parse_from(args).is_err());
            }
            assert!(
                Cli::try_parse_from([
                    "stela",
                    "probe-dyld-entry",
                    "dyld",
                    "--executable",
                    "app",
                    "--software-pauth-ib-key",
                    "key.json",
                    "--bootstrap-clock",
                    "--clock-snapshot",
                    "clock.json"
                ])
                .is_ok()
            );
            assert!(
                Cli::try_parse_from([
                    "stela",
                    "compile-block",
                    "code",
                    "--output-dir",
                    "out",
                    "--software-pauth",
                    "--software-clock"
                ])
                .is_ok()
            );
            assert!(
                Cli::try_parse_from([
                    "stela",
                    "run-blocks",
                    "code",
                    "--software-pauth-ib-key",
                    "key.json",
                    "--clock-snapshot",
                    "clock.json"
                ])
                .is_ok()
            );
            assert_eq!(
                block_profile(true, true, false),
                stela_compiler::block::BlockProfile::AppleArm64eSoftwarePauthClockV1
            );
            assert_eq!(
                block_profile(true, false, false),
                stela_compiler::block::BlockProfile::AppleArm64eSoftwarePauthV1
            );
            assert_eq!(
                block_profile(false, false, false),
                stela_compiler::block::BlockProfile::Ordinary
            );
        }

        #[test]
        fn system_boundary_preparation_is_explicit_and_compile_only() {
            let parse = |extra: &[&str]| {
                let mut args = vec![
                    "stela",
                    "compile-block",
                    "code",
                    "--output-dir",
                    "out",
                    "--system-boundaries",
                ];
                args.extend_from_slice(extra);
                Cli::try_parse_from(args)
            };
            assert!(matches!(
                parse(&[]).unwrap().command,
                Command::CompileBlock(crate::compile::CompileBlock {
                    system_boundaries: true,
                    ..
                })
            ));
            for flag in ["--software-pauth", "--software-clock", "--thread-registers"] {
                assert!(parse(&[flag]).is_err());
            }
            assert!(
                Cli::try_parse_from(["stela", "run-blocks", "code", "--system-boundaries"])
                    .is_err()
            );
        }

        #[test]
        fn el1_platform_preparation_is_explicit_and_has_no_execution_resources() {
            let parse = |extra: &[&str]| {
                let mut args = vec![
                    "stela",
                    "compile-block",
                    "code",
                    "--output-dir",
                    "out",
                    "--el1-platform",
                ];
                args.extend_from_slice(extra);
                Cli::try_parse_from(args)
            };
            assert!(matches!(
                parse(&[]).unwrap().command,
                Command::CompileBlock(crate::compile::CompileBlock {
                    el1_platform: true,
                    ..
                })
            ));
            for flag in [
                "--system-boundaries",
                "--software-pauth",
                "--software-clock",
                "--thread-registers",
                "--checked-memory-sa0-off",
                "--checked-process-sa0-off",
            ] {
                assert!(parse(&[flag]).is_err());
            }
            assert!(
                Cli::try_parse_from(["stela", "run-blocks", "code", "--el1-platform"]).is_err()
            );
        }

        #[test]
        fn thread_register_preparation_flags_select_distinct_profiles_without_context() {
            use stela_compiler::block::BlockProfile;
            assert!(
                Cli::try_parse_from([
                    "stela",
                    "compile-block",
                    "code",
                    "--output-dir",
                    "out",
                    "--thread-registers",
                ])
                .is_ok()
            );
            assert_eq!(
                block_profile(false, false, true),
                BlockProfile::DarwinArm64ThreadV1
            );
            assert_eq!(
                block_profile(true, false, true),
                BlockProfile::AppleArm64eSoftwarePauthThreadV1
            );
            assert_eq!(
                block_profile(true, true, true),
                BlockProfile::AppleArm64eSoftwarePauthClockThreadV1
            );
        }
    }

    mod fpmr {
        use super::*;
        use std::hash::{Hash, Hasher};
        use stela_compiler::extended::ScalableProfile;

        fn resolve(
            command: &str,
            permission: Option<&str>,
            declare_fpmr: bool,
        ) -> Result<(ScalableProfile, Option<bool>)> {
            let mut args = vec![
                "stela",
                command,
                "input.bin",
                "--output-dir",
                "out",
                "--guest-profile",
                "sme-streaming-v2",
                "--svl-bytes",
                "32",
                "--svcr",
                "0",
                "--guest-feature",
                "FEAT_SME",
                "--guest-feature",
                "FEAT_FP8",
                "--max-svl-bytes",
                "256",
                "--zt0-enabled",
                "false",
            ];
            if declare_fpmr {
                args.extend(["--guest-feature", "FEAT_FPMR"]);
            }
            if let Some(permission) = permission {
                args.extend(["--fpmr-enabled", permission]);
            }
            if command == "compile-block" {
                args.extend([
                    "--full-a64",
                    "false",
                    "--ebf16",
                    "false",
                    "--rpres",
                    "false",
                ]);
            }
            let (
                guest_profile,
                svl_bytes,
                svcr,
                guest_feature,
                max_svl_bytes,
                zt0_enabled,
                fpmr_enabled,
            ) = match Cli::try_parse_from(args)?.command {
                Command::CompileLeaf(crate::compile::CompileLeaf {
                    guest_profile,
                    svl_bytes,
                    svcr,
                    guest_feature,
                    max_svl_bytes,
                    zt0_enabled,
                    fpmr_enabled,
                    ..
                })
                | Command::CompileBlock(crate::compile::CompileBlock {
                    guest_profile,
                    svl_bytes,
                    svcr,
                    guest_feature,
                    max_svl_bytes,
                    zt0_enabled,
                    fpmr_enabled,
                    ..
                }) => (
                    guest_profile,
                    svl_bytes,
                    svcr,
                    guest_feature,
                    max_svl_bytes,
                    zt0_enabled,
                    fpmr_enabled,
                ),
                _ => anyhow::bail!("unexpected command"),
            };
            Ok((
                compile_scalable_profile(
                    guest_profile.as_deref(),
                    svl_bytes,
                    svcr,
                    &guest_feature,
                    max_svl_bytes,
                    zt0_enabled,
                    fpmr_enabled,
                )?
                .context("missing profile")?,
                fpmr_enabled,
            ))
        }

        fn hash(profile: ScalableProfile) -> u64 {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            profile.hash(&mut hasher);
            hasher.finish()
        }

        #[test]
        fn fpmr_effective_controls_are_hash_identity_and_preserve_historical_serialization()
        -> Result<()> {
            for command in ["compile-leaf", "compile-block"] {
                let (absent, absent_raw) = resolve(command, None, true)?;
                let (disabled, disabled_raw) = resolve(command, Some("false"), true)?;
                let (enabled, enabled_raw) = resolve(command, Some("true"), true)?;
                assert_eq!(absent, disabled);
                assert_eq!(hash(absent), hash(disabled));
                assert_ne!(enabled, disabled);
                assert_ne!(hash(enabled), hash(disabled));
                assert!(!absent.controls().fpmr_enabled());
                assert!(enabled.controls().fpmr_enabled());
                let historical = scalable_execution_manifest(absent, absent_raw)?;
                assert!(historical.get("fpmr_enabled").is_none());
                let explicit = scalable_execution_manifest(disabled, disabled_raw)?;
                assert_eq!(explicit["fpmr_enabled"], serde_json::json!(false));
                let mut stripped = explicit;
                stripped.as_object_mut().unwrap().remove("fpmr_enabled");
                assert_eq!(stripped, historical);
                assert_eq!(
                    scalable_execution_manifest(enabled, enabled_raw)?["fpmr_enabled"],
                    serde_json::json!(true)
                );
            }
            Ok(())
        }

        #[test]
        fn fpmr_permission_never_implies_guest_feature_and_malformed_bools_decline() -> Result<()> {
            for command in ["compile-leaf", "compile-block"] {
                assert!(resolve(command, Some("true"), false).is_err());
                assert!(
                    !resolve(command, Some("false"), false)?
                        .0
                        .controls()
                        .fpmr_enabled()
                );
                for value in ["0", "1", "yes", "", "TRUE"] {
                    assert!(resolve(command, Some(value), true).is_err());
                }
            }
            Ok(())
        }

        #[test]
        fn fpmr_options_decline_without_context_and_under_legacy_profile() {
            for command in ["compile-leaf", "compile-block"] {
                for permission in ["false", "true"] {
                    assert!(
                        Cli::try_parse_from([
                            "stela",
                            command,
                            "input.bin",
                            "--output-dir",
                            "out",
                            "--fpmr-enabled",
                            permission
                        ])
                        .is_err()
                    );
                    assert!(
                        compile_scalable_profile(
                            Some(stela_compiler::extended::PROFILE_ID),
                            Some(
                                stela_compiler::aarch64::scalable::VectorLength::from_bytes(32)
                                    .unwrap()
                            ),
                            Some(stela_compiler::aarch64::scalable::ScalableMode::default()),
                            &[],
                            None,
                            None,
                            Some(permission == "true")
                        )
                        .is_err()
                    );
                }
            }
        }
    }

    mod checked_memory {
        use super::super::profile::*;
        use crate::{Cli, Command};
        use clap::{Parser, error::ErrorKind};
        use stela_compiler::{
            block::CheckedMemoryProfile, context::pointer::EffectivePointerChecks,
        };

        #[test]
        fn checked_memory_flag_selects_compile_preparation_only() {
            let cli = Cli::try_parse_from([
                "stela",
                "compile-block",
                "input.bin",
                "--output-dir",
                "output",
                "--checked-memory-sa0-off",
            ])
            .unwrap();
            assert!(matches!(
                cli.command,
                Command::CompileBlock(crate::compile::CompileBlock {
                    checked_memory_sa0_off: true,
                    ..
                })
            ));
            assert!(
                Cli::try_parse_from([
                    "stela",
                    "run-blocks",
                    "input.bin",
                    "--checked-memory-sa0-off",
                ])
                .is_err()
            );
        }

        #[test]
        fn checked_memory_preparation_rejects_other_service_and_extended_profiles() {
            for alternative in [
                "--system-boundaries",
                "--software-pauth",
                "--thread-registers",
            ] {
                let error = match Cli::try_parse_from([
                    "stela",
                    "compile-block",
                    "input.bin",
                    "--output-dir",
                    "output",
                    "--checked-memory-sa0-off",
                    alternative,
                ]) {
                    Ok(_) => panic!("conflicting preparation profiles accepted"),
                    Err(error) => error,
                };
                assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
            }
            assert!(
                Cli::try_parse_from([
                    "stela",
                    "compile-block",
                    "input.bin",
                    "--output-dir",
                    "output",
                    "--checked-memory-sa0-off",
                    "--software-pauth",
                    "--software-clock",
                ])
                .is_err()
            );
            assert!(
                Cli::try_parse_from([
                    "stela",
                    "compile-block",
                    "input.bin",
                    "--output-dir",
                    "output",
                    "--checked-memory-sa0-off",
                    "--guest-profile",
                    "apple-sme2-streaming-v1",
                    "--svl-bytes",
                    "16",
                    "--svcr",
                    "0",
                ])
                .is_err()
            );
        }

        #[test]
        fn checked_process_preparation_is_explicit_and_exclusive() {
            let args = [
                "stela",
                "compile-block",
                "input.bin",
                "--output-dir",
                "output",
                "--checked-process-sa0-off",
            ];
            assert!(matches!(
                Cli::try_parse_from(args).unwrap().command,
                Command::CompileBlock(crate::compile::CompileBlock {
                    checked_process_sa0_off: true,
                    checked_memory_sa0_off: false,
                    ..
                })
            ));
            for alternative in [
                "--checked-memory-sa0-off",
                "--system-boundaries",
                "--software-pauth",
                "--thread-registers",
            ] {
                let mut conflict = args.to_vec();
                conflict.push(alternative);
                let error = match Cli::try_parse_from(conflict) {
                    Ok(_) => panic!("conflicting preparation profiles accepted"),
                    Err(error) => error,
                };
                assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
            }
            assert!(
                Cli::try_parse_from([
                    "stela",
                    "run-blocks",
                    "input.bin",
                    "--checked-process-sa0-off"
                ])
                .is_err()
            );
        }

        #[test]
        fn explicit_modes_preserve_legacy_default_and_exact_typed_effects() {
            assert_eq!(
                checked_process(None).unwrap(),
                CheckedMemoryProfile::SpAlignmentDisabled
            );
            for (name, mode) in [
                ("unchecked", EffectivePointerChecks::Unchecked),
                ("addition", EffectivePointerChecks::Addition),
                (
                    "addition-multiplication",
                    EffectivePointerChecks::AdditionAndMultiplication,
                ),
            ] {
                assert_eq!(parse_pointer_mode(name), Ok(mode));
                assert_ne!(
                    checked_process(Some(mode)).unwrap(),
                    CheckedMemoryProfile::SpAlignmentDisabled
                );
            }
            assert!(parse_pointer_mode("enabled").is_err());
        }
    }
}
