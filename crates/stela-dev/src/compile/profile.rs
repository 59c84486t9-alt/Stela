//! Resolve declared guest execution profiles from command-line options.
use anyhow::{Context, Result, ensure};
use stela_compiler::{
    CompileError,
    block::CheckedMemoryProfile,
    context::{
        memory::address::{AccessEl, AddressAddChecks, EffectiveAddressChecks},
        pointer::EffectivePointerChecks,
    },
};

pub(crate) fn parse_pointer_mode(value: &str) -> Result<EffectivePointerChecks, String> {
    match value {
        "unchecked" => Ok(EffectivePointerChecks::Unchecked),
        "addition" => Ok(EffectivePointerChecks::Addition),
        "addition-multiplication" => Ok(EffectivePointerChecks::AdditionAndMultiplication),
        _ => Err("expected unchecked, addition, or addition-multiplication".into()),
    }
}
/// Checked EL0 process profile. Without a pointer mode, the existing profile
/// and ABI are kept.
pub(crate) fn checked_process(
    mode: Option<EffectivePointerChecks>,
) -> Result<CheckedMemoryProfile, CompileError> {
    let base = CheckedMemoryProfile::SpAlignmentDisabled;
    let Some(mode) = mode else {
        return Ok(base);
    };
    let addition = if mode == EffectivePointerChecks::Unchecked {
        AddressAddChecks::Disabled
    } else {
        AddressAddChecks::Enabled
    };
    base.with_address_checks(
        AccessEl::El0,
        AccessEl::El0,
        EffectiveAddressChecks::new(addition, AddressAddChecks::Disabled),
    )
    .with_pointer_arithmetic(mode)
    .ok_or_else(|| CompileError("incompatible CPA/address specialization".into()))
}

pub(crate) fn block_profile(
    software_pauth: bool,
    software_clock: bool,
    thread_registers: bool,
) -> stela_compiler::block::BlockProfile {
    use stela_compiler::block::BlockProfile;
    match (software_pauth, software_clock, thread_registers) {
        (_, true, true) => BlockProfile::AppleArm64eSoftwarePauthClockThreadV1,
        (_, true, false) => BlockProfile::AppleArm64eSoftwarePauthClockV1,
        (true, false, true) => BlockProfile::AppleArm64eSoftwarePauthThreadV1,
        (true, false, false) => BlockProfile::AppleArm64eSoftwarePauthV1,
        (false, false, true) => BlockProfile::DarwinArm64ThreadV1,
        (false, false, false) => BlockProfile::Ordinary,
    }
}

/// Validate the guest profile before reading or compiling the input.
pub(crate) fn compile_scalable_profile(
    id: Option<&str>,
    length: Option<stela_compiler::aarch64::scalable::VectorLength>,
    mode: Option<stela_compiler::aarch64::scalable::ScalableMode>,
    feature_names: &[String],
    max_length: Option<stela_compiler::aarch64::scalable::VectorLength>,
    zt0_enabled: Option<bool>,
    fpmr_enabled: Option<bool>,
) -> Result<Option<stela_compiler::scalable_context::ScalableProfile>> {
    use stela_compiler::{
        aarch64::scalable::{features::ScalableFeatures, profile::ScalableControls},
        scalable_context::{DECLARED_PROFILE_ID, PROFILE_ID, ScalableProfile},
    };
    let Some(id) = id else {
        ensure!(
            length.is_none()
                && mode.is_none()
                && feature_names.is_empty()
                && max_length.is_none()
                && zt0_enabled.is_none()
                && fpmr_enabled.is_none(),
            "scalable options require an explicit guest profile"
        );
        return Ok(None);
    };
    let length = length.context("guest profile requires an explicit SVL")?;
    let mode = mode.context("guest profile requires an initial SVCR")?;
    let profile = match id {
        PROFILE_ID => {
            ensure!(
                feature_names.is_empty()
                    && max_length.is_none()
                    && zt0_enabled.is_none()
                    && fpmr_enabled.is_none(),
                "V1 profile does not accept V2 feature or control options"
            );
            ScalableProfile::new(length, mode)
        }
        DECLARED_PROFILE_ID => {
            ensure!(
                !feature_names.is_empty(),
                "V2 profile requires explicit guest features"
            );
            let features =
                ScalableFeatures::checked_from_names(feature_names.iter().map(String::as_str))?;
            let controls = ScalableControls::new(
                max_length.context("V2 profile requires an explicit maximum SVL")?,
                zt0_enabled.context("V2 profile requires explicit ZT0 permission")?,
            )
            .with_fpmr_enabled(fpmr_enabled.unwrap_or(false));
            ScalableProfile::new_with_features(length, mode, features, controls)?
        }
        _ => anyhow::bail!("unknown guest profile {id:?}"),
    };
    Ok(Some(profile))
}

pub(crate) fn compile_context_block_profile(
    scalable: Option<stela_compiler::scalable_context::ScalableProfile>,
    services: stela_compiler::block::BlockProfile,
    full_a64: Option<bool>,
    ebf16: Option<bool>,
    rpres: Option<bool>,
) -> Result<Option<stela_compiler::scalable_context::block::ExtendedBlockProfile>> {
    use stela_compiler::{
        aarch64::floating::features::NumericalFeatures, block::BlockProfile,
        scalable_context::block::ExtendedBlockProfile,
    };
    let Some(scalable) = scalable else {
        ensure!(
            full_a64.is_none() && ebf16.is_none() && rpres.is_none(),
            "numerical declarations require an explicit contextual guest profile"
        );
        return Ok(None);
    };
    ensure!(
        services == BlockProfile::Ordinary,
        "context block services are not integrated"
    );
    let numerical = NumericalFeatures::new(
        full_a64.context("context block requires explicit FullA64 availability")?,
        ebf16.context("context block requires explicit extended BF16 availability")?,
        rpres.context("context block requires explicit reciprocal precision availability")?,
    );
    Ok(Some(ExtendedBlockProfile::new(
        scalable, services, numerical,
    )))
}

pub(crate) fn scalable_execution_manifest(
    profile: stela_compiler::scalable_context::ScalableProfile,
    fpmr_enabled: Option<bool>,
) -> Result<serde_json::Value> {
    let mut execution = serde_json::json!({
        "id": profile.id(),
        "svl_bytes": profile.vector_length().bytes(),
        "svcr": profile.mode().svcr(),
    });
    if let Some(features) = profile.declared_features() {
        let controls = profile.controls();
        execution["features"] = serde_json::json!(features.names());
        execution["max_svl_bytes"] = serde_json::json!(controls.max_vector_length().bytes());
        execution["zt0_enabled"] = serde_json::json!(controls.zt0_enabled());
        ensure!(
            fpmr_enabled.unwrap_or(false) == controls.fpmr_enabled(),
            "FPMR manifest declaration differs from resolved profile"
        );
        if fpmr_enabled.is_some() {
            execution["fpmr_enabled"] = serde_json::json!(controls.fpmr_enabled());
        }
        execution["dit"] = serde_json::json!(
            profile
                .required_dit()
                .context("V2 profile requires a DIT declaration")?
        );
    }
    Ok(execution)
}
