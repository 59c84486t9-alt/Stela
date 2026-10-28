//! Profile and command-line compilation behavior.
use super::*;
use crate::{Cli, Command};
use clap::Parser;

mod scalable {
    use super::*;

    fn resolve(
        extra: &[&str],
    ) -> Result<Option<stela_compiler::scalable_context::ScalableProfile>> {
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
    fn legacy_profile_rejects_extra_metadata() -> Result<()> {
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
    fn declared_profile_metadata() -> Result<()> {
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

    fn resolve(extra: &[&str]) -> Result<Option<(ScalableProfile, NumericalFeatures)>> {
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
                BlockProfile::new(Features::SYSTEM)
            } else {
                block_profile(software_pauth, software_clock, thread_registers)
            },
            full_a64,
            ebf16,
            rpres,
        )
    }

    #[test]
    fn numerical_feature_declarations() -> Result<()> {
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
        let (scalable, numerical) = resolve(&args)?.unwrap();
        assert_eq!(numerical, NumericalFeatures::new(false, false, false));
        assert_eq!(
            scalable_execution_manifest(scalable, None)?,
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
    fn ordinary_block_profile_options() -> Result<()> {
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
    fn cpu_target_selection() {
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
    fn clock_requires_pauth_profile() {
        assert!(
            Cli::try_parse_from([
                "stela-dev",
                "compile-block",
                "code",
                "--output-dir",
                "out",
                "--software-clock"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "stela-dev",
                "compile-block",
                "code",
                "--output-dir",
                "out",
                "--software-pauth",
                "--software-clock"
            ])
            .is_ok()
        );
        assert_eq!(
            block_profile(true, true, false),
            stela_compiler::block::BlockProfile::new(
                Features::POINTER_AUTHENTICATION.union(Features::CLOCK)
            )
        );
        assert_eq!(
            block_profile(true, false, false),
            stela_compiler::block::BlockProfile::new(Features::POINTER_AUTHENTICATION)
        );
        assert_eq!(
            block_profile(false, false, false),
            stela_compiler::block::BlockProfile::ORDINARY
        );
    }

    #[test]
    fn system_boundary_profile() {
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
            Cli::try_parse_from(["stela", "run-blocks", "code", "--system-boundaries"]).is_err()
        );
    }

    #[test]
    fn thread_register_profiles() {
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
            BlockProfile::new(Features::THREAD_REGISTERS.union(Features::AMX))
        );
        assert_eq!(
            block_profile(true, false, true),
            BlockProfile::new(
                Features::POINTER_AUTHENTICATION
                    .union(Features::THREAD_REGISTERS)
                    .union(Features::AMX)
            )
        );
        assert_eq!(
            block_profile(true, true, true),
            BlockProfile::new(Features::PROCESS_HELPERS.union(Features::AMX))
        );
    }
}

mod fpmr {
    use super::*;
    use std::hash::{Hash, Hasher};
    use stela_compiler::scalable_context::ScalableProfile;

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
    fn fpmr_profile_identity() -> Result<()> {
        for command in ["compile-leaf", "compile-block"] {
            let (absent, _) = resolve(command, None, true)?;
            let (disabled, _) = resolve(command, Some("false"), true)?;
            let (enabled, _) = resolve(command, Some("true"), true)?;
            assert_eq!(absent, disabled);
            assert_eq!(hash(absent), hash(disabled));
            assert_ne!(enabled, disabled);
            assert_ne!(hash(enabled), hash(disabled));
            assert!(!absent.controls().fpmr_enabled());
            assert!(enabled.controls().fpmr_enabled());
        }
        Ok(())
    }

    #[test]
    fn fpmr_manifest_encoding() -> Result<()> {
        for command in ["compile-leaf", "compile-block"] {
            let (absent, absent_raw) = resolve(command, None, true)?;
            let (disabled, disabled_raw) = resolve(command, Some("false"), true)?;
            let (enabled, enabled_raw) = resolve(command, Some("true"), true)?;
            let default_manifest = scalable_execution_manifest(absent, absent_raw)?;
            assert!(default_manifest.get("fpmr_enabled").is_none());
            let explicit = scalable_execution_manifest(disabled, disabled_raw)?;
            assert_eq!(explicit["fpmr_enabled"], serde_json::json!(false));
            let mut stripped = explicit;
            stripped.as_object_mut().unwrap().remove("fpmr_enabled");
            assert_eq!(stripped, default_manifest);
            assert_eq!(
                scalable_execution_manifest(enabled, enabled_raw)?["fpmr_enabled"],
                serde_json::json!(true)
            );
        }
        Ok(())
    }

    #[test]
    fn fpmr_permission_validation() -> Result<()> {
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
    fn fpmr_requires_declared_context() {
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
                        Some(stela_compiler::scalable_context::PROFILE_ID),
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
    use stela_compiler::{block::CheckedMemoryProfile, context::pointer::EffectivePointerChecks};

    #[test]
    fn checked_memory_profile() {
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
    fn checked_memory_profile_conflicts() {
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
    fn checked_process_profile_conflicts() {
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
    fn pointer_mode_presets() {
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
