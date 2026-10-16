//! Explicit checked compilation effects; this module grants no CPU/native entry.
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
/// The source/current EL0 owner must later validate this complete specialization.
/// Without an explicit mode, preserve the exact existing profile and ABI.
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
#[cfg(test)]
mod tests {
    use super::*;
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
