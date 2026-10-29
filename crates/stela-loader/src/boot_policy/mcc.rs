//! Original kernel cacheless configuration. This does not authorize a mount;
//! the caller must keep its Prepared MCC owner and canonical memory
//! completion admission. The bundle's default arguments are unchanged here.
use crate::Result;
use crate::boot_args::BOOT_LINE_LENGTH;
use alloc::string::String;
use stela_contracts::require;

pub const DISABLE_MCC: &str = "-disable_mcc";

/// Add the unchanged kernel's generic boolean argument, preserving existing
/// arguments byte-for-byte. Reject NULs/truncation and ambiguous spellings;
/// no cached bundle is changed until the parent adopts its full resource plan.
pub fn cacheless_arguments(arguments: &str) -> Result<String> {
    require!(
        !arguments.as_bytes().contains(&0),
        "boot arguments contain a NUL"
    );
    for word in arguments.split_ascii_whitespace() {
        require!(
            !word.starts_with("-disable_mcc="),
            "cacheless MCC requires the original standalone boolean argument"
        );
    }
    let present = arguments
        .split_ascii_whitespace()
        .any(|word| word == DISABLE_MCC);
    let extra = if present {
        0
    } else {
        DISABLE_MCC.len() + usize::from(!arguments.is_empty())
    };
    require!(
        arguments
            .len()
            .checked_add(extra)
            .is_some_and(|bytes| bytes < BOOT_LINE_LENGTH),
        "cacheless boot arguments exceed boot_args command line"
    );
    let mut result = String::from(arguments);
    if !present {
        if !result.is_empty() {
            result.push(' ');
        }
        result.push_str(DISABLE_MCC);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keeps_existing_arguments_and_never_truncates_or_reinterprets_a_value() {
        assert_eq!(
            cacheless_arguments("-v keepsyms=1").unwrap(),
            "-v keepsyms=1 -disable_mcc"
        );
        assert_eq!(cacheless_arguments("").unwrap(), DISABLE_MCC);
        let existing = "-v\t-disable_mcc  mcc_clampwaycount=12";
        assert_eq!(cacheless_arguments(existing).unwrap(), existing);
        assert!(cacheless_arguments("-disable_mcc=0").is_err());
        assert!(cacheless_arguments("-v\0-hidden").is_err());
        assert!(cacheless_arguments(&"x".repeat(BOOT_LINE_LENGTH)).is_err());
        let limit = BOOT_LINE_LENGTH - DISABLE_MCC.len() - 2;
        assert_eq!(
            cacheless_arguments(&"x".repeat(limit)).unwrap().len(),
            BOOT_LINE_LENGTH - 1
        );
        assert!(cacheless_arguments(&"x".repeat(limit + 1)).is_err());
    }
}
