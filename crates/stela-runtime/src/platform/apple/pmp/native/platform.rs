//! Native generic PMP platform evaluation, separate from applied device effects.
//!
//! Original 26A434 T8112 PMP SHA256 b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//! initializer 100d350..100da2c, selection 10109d8..1010e8c, evaluator
//! 1011160..1011674, cycle 100f820..100fb28 and activation 101c504..101cb58.
//! The immutable ignored evidence is pmgr/platform-lifecycle-producer-r1
//! (75 windows, seal99e6589ab2ac169545825660da5918c8b5b9575a9455983f5f985a94fdf2ba80).
//! Additional packet/interpolation and counter selection operands are retained
//! in pmgr/platform-implementation-r1. No Apple code or firmware executes here.
//!
//! Software eligibility is a source policy result. It is neither PMGR ACTIVE,
//! a hardware observation nor an ACK. Backend operations retain actual effects,
//! busy waits and refusals under a stable request; there is no default backend.
//! The cycle API owns evaluation and hook dispatch through100fb50, including
//! retained manager controller save/restore, G540 clear and accumulator effects.
//! It is not the entire manager100e798..100fd70: the parent still owns request
//! queue draining before evaluation and the post-dispatch100fb50..100fd30 vote,
//! pending-work, trace-publication, scheduling and timing-accounting stages.
//! Completing this component does not admit that parent cycle or an MC ACK.
pub mod ingestion;
mod interpolation;
pub mod owner;
mod profile;
mod selection;

pub use interpolation::{Interpolation, Packed};
pub use profile::{Configuration, Descriptor, Hook, Ordinal, Profile, Slice};
pub use selection::{CounterReference, CounterSelection, McSelection};

/// Three source output words. Pending means prior control work, not a state
/// transition; falling means previously evaluated1 and now evaluated non1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Evaluation {
    pub eligible: u64,
    pub falling: u64,
    pub prior_pending: u64,
}
