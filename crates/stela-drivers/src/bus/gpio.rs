//! Chipset GPIO and pin control. Platform reservation and parent interrupt
//! ownership are prerequisites to native attachment, not inferred from pin IDs.
pub mod amd;
pub mod intel;
