//! No process, so no environment: Mesa's debug switches read as unset.
use alloc_crate::string::String;

#[derive(Debug, PartialEq, Eq)]
pub enum VarError {
    NotPresent,
}

pub fn var(_: &str) -> Result<String, VarError> {
    Err(VarError::NotPresent)
}
