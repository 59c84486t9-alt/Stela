//! Guest register state, shared by hosted and freestanding execution.

/// The register state every compiled function takes in RDI
/// ([`crate::block::BlockProfile::abi`] names the ABI). Registers enter and
/// leave native code in this layout. Only NZCV bits 31:28 of PSTATE are held
/// here, or the flag word ([`crate::x86_64::flag_word`]) while pinned code
/// runs. V registers are little-endian pairs of 64-bit halves.
/// Arithmetic preserves unrelated FPCR/FPSR bits, and register accesses apply
/// the declared field masks; saturating integer SIMD sets QC and floating-point
/// arithmetic accumulates exception flags.
#[repr(C)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuestState {
    pub x: [u64; 31],
    pub sp: u64,
    pub nzcv: u32,
    /// The width of the exclusive load native code recorded, or 0 for none
    /// (`x86_64::native_exclusive`).
    pub exclusive_bytes: u32,
    pub v: [[u64; 2]; 32],
    pub fpcr: u32,
    pub fpsr: u32,
    /// The address and the zero-extended value of that load.
    pub exclusive_address: u64,
    pub exclusive_value: u64,
    /// PSTATE.{D,A,I,F} in bits 3:0 while native code runs, which may change
    /// them (`x86_64::register_read::mask_thunk`).
    pub daif: u32,
    /// The masks of interrupts waiting when native code was entered: clearing
    /// one is the engine's.
    pub pending: u32,
}

#[cfg(test)]
mod tests {
    use super::GuestState;
    use crate::block::{BlockProfile, Features};
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn layout_matches_native_abi() {
        for profile in [BlockProfile::ORDINARY, BlockProfile::new(Features::LEAF)] {
            assert!(profile.abi().starts_with("x86_64-sysv-guest-state-v7-"));
        }
        assert_eq!(size_of::<GuestState>(), 808);
        assert_eq!(align_of::<GuestState>(), 8);
        assert_eq!(offset_of!(GuestState, x), 0);
        assert_eq!(offset_of!(GuestState, sp), 248);
        assert_eq!(offset_of!(GuestState, nzcv), 256);
        assert_eq!(offset_of!(GuestState, exclusive_bytes), 260);
        assert_eq!(offset_of!(GuestState, v), 264);
        assert_eq!(size_of::<[[u64; 2]; 32]>(), 512);
        assert_eq!(offset_of!(GuestState, fpcr), 776);
        assert_eq!(offset_of!(GuestState, fpsr), 780);
    }

    #[test]
    fn default_initializes_every_architectural_field() {
        let state = GuestState::default();
        assert_eq!(state.x, [0; 31]);
        assert_eq!(state.sp, 0);
        assert_eq!(state.nzcv, 0);
        assert_eq!(state.exclusive_bytes, 0);
        assert_eq!(state.v, [[0; 2]; 32]);
        assert_eq!(state.fpcr, 0);
        assert_eq!(state.fpsr, 0);
    }
}
