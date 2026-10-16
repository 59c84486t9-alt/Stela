use super::{GuestState, NATIVE_ABI};
use core::mem::{align_of, offset_of, size_of};

#[test]
fn layout_matches_native_abi() {
    assert_eq!(NATIVE_ABI, "x86_64-sysv-guest-state-v3-direct-ram");
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
