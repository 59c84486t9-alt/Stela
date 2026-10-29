//! Immutable AP/SEP handoff security observations; no SEP execution owner.
/// The SEP's effective production status and security mode. The SEP shares
/// the AP's fuses, so Stela's SEP reports what the boot chain set for the AP
/// (`/chosen` `effective-production-status-ap`, `effective-security-mode-ap`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityMode {
    pub production: bool,
    pub secure: bool,
}
