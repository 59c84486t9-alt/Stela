//! The engine's constants and predicates that shape what a block compiles
//! to, apart from the compiler and the entry context: the block profile, the
//! fetch page and window bounds, and which words FP/SIMD enablement ends a
//! block before ([`super::prepare`]).
//!
//! The translation store's translator id fingerprints this file with
//! `prepare.rs`, `stored.rs` and `translations` (`build.rs`), not the rest
//! of the engine: code that changes what a block compiles to belongs here or
//! in those files.
use stela_compiler::block::{self, BlockProfile, Features};

pub(super) const PROFILE: BlockProfile = BlockProfile::new(Features::SYSTEM_MODE);
pub(super) const INSTRUCTION: u64 = 4;
pub(super) const FETCH_PAGE: u64 = 4096;
pub(super) const MAX_BLOCK_BYTES: u64 = block::MAX_BLOCK_INSTRUCTIONS as u64 * INSTRUCTION;

/// Floating-point and SIMD instructions, which CPACR_EL1.FPEN can trap:
/// SIMD&FP data processing (op0 x111) and SIMD&FP loads/stores (op0 x1x0, V=1).
pub(super) fn is_floating_point(word: u32) -> bool {
    (word >> 25) & 7 == 7 || word & 0x0a00_0000 == 0x0800_0000 && word & (1 << 26) != 0
}
