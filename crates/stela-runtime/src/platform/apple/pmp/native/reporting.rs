//! Native endpoint-4 IOReporting, separate from the PMP custom registry.
//!
//! Original26A434 T8112 PMP b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//!102d7dc..102dd00 registers/refreshes records;102e004..102e324 owns
//! endpoint callbacks and AP-buffer lifecycle. RTBuddyIOReportingEndpoint
//! consumes the IORb buffer at J473 KC VA fffffe000b66aba0.
//! No Apple firmware executes. Numeric wire data grants no mapping authority.
pub mod getter;
mod owner;
mod receive;
pub mod record;
pub mod resources;
pub mod wire;
pub use owner::{Finished, NO_DATABASE, Owner, Progress, Registration, RegistrationResult};
pub use receive::Receiver;
