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
    let (guest_profile, svl_bytes, svcr, guest_feature, max_svl_bytes, zt0_enabled, fpmr_enabled) =
        match Cli::try_parse_from(args)?.command {
            Command::CompileLeaf {
                guest_profile,
                svl_bytes,
                svcr,
                guest_feature,
                max_svl_bytes,
                zt0_enabled,
                fpmr_enabled,
                ..
            }
            | Command::CompileBlock {
                guest_profile,
                svl_bytes,
                svcr,
                guest_feature,
                max_svl_bytes,
                zt0_enabled,
                fpmr_enabled,
                ..
            } => (
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
fn fpmr_effective_controls_are_hash_identity_and_preserve_historical_serialization() -> Result<()> {
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
                    Some(stela_compiler::aarch64::scalable::VectorLength::from_bytes(32).unwrap()),
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
