//! Guest register state, shared by hosted and freestanding execution.

/// The register state every compiled function takes in RDI
/// ([`crate::block::BlockProfile::abi`] names the ABI). Registers enter and
/// leave native code in this layout. Only NZCV bits 31:28 of PSTATE are held
/// here. V registers are little-endian pairs of 64-bit halves.
/// Arithmetic preserves unrelated FPCR/FPSR bits, and register accesses apply
/// the declared field masks; saturating integer SIMD sets QC and floating-point
/// arithmetic accumulates exception flags.
#[repr(C)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuestState {
    pub x: [u64; 31],
    pub sp: u64,
    pub nzcv: u32,
    pub reserved: u32,
    pub v: [[u64; 2]; 32],
    pub fpcr: u32,
    pub fpsr: u32,
}

#[cfg(test)]
mod tests {
    use super::GuestState;
    use crate::block::{BlockProfile, Features};
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn layout_matches_native_abi() {
        for profile in [BlockProfile::ORDINARY, BlockProfile::new(Features::LEAF)] {
            assert!(profile.abi().starts_with("x86_64-sysv-guest-state-v4-"));
        }
        assert_eq!(size_of::<GuestState>(), 784);
        assert_eq!(align_of::<GuestState>(), 8);
        assert_eq!(offset_of!(GuestState, x), 0);
        assert_eq!(offset_of!(GuestState, sp), 248);
        assert_eq!(offset_of!(GuestState, nzcv), 256);
        assert_eq!(offset_of!(GuestState, reserved), 260);
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
        assert_eq!(state.reserved, 0);
        assert_eq!(state.v, [[0; 2]; 32]);
        assert_eq!(state.fpcr, 0);
        assert_eq!(state.fpsr, 0);
    }
}
