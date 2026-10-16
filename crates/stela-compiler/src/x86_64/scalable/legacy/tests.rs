use super::*;
use alloc::vec::Vec;

#[test]
fn minimum_length_upper_clear_has_no_native_effects() {
    let mut code = Vec::new();
    clear_z_upper(
        &mut code,
        31,
        7,
        VectorLength::from_bytes(16).unwrap(),
        TargetCpu::Baseline,
    );
    assert!(code.is_empty());
}
