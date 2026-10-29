//! Exception levels, security states and system-register access directions.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionLevel {
    El0,
    El1,
    El2,
    El3,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityState {
    NonSecure,
    Secure,
    Realm,
}

/// Explicit architectural inputs, independent of application or host identity.
/// Family Context types own their additional typed features and control readbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    pub current_el: ExceptionLevel,
    pub security: SecurityState,
    pub el2_enabled: bool,
    pub el3_present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Read,
    Write { value: u64 },
}
