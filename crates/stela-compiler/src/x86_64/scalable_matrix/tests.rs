use super::*;
use alloc::vec::Vec;

#[test]
fn pointer_chase_uses_the_shared_context_contract() {
    let mut code = Vec::new();
    load_za_pointer_r8(&mut code);
    assert_eq!(code, [0x4d, 0x8b, 0x47, 16, 0x4d, 0x8b, 0x40, 56]);
}

#[test]
fn rex_base_follows_mandatory_simd_prefix() {
    for register in 0..XMM_REGISTER_COUNT {
        let mut load = Vec::new();
        load_za_chunk_at_r8(&mut load, register, 0x1234, TargetCpu::Baseline);
        assert_eq!(load[..5], [0xf3, 0x41, 0x0f, 0x6f, 0x80 | register << 3]);
        assert_eq!(load[5..], 0x1234u32.to_le_bytes());
        let mut store = Vec::new();
        store_za_chunk_at_r8(&mut store, register, 0x5678, TargetCpu::Baseline);
        assert_eq!(store[..5], [0xf3, 0x41, 0x0f, 0x7f, 0x80 | register << 3]);
        assert_eq!(store[5..], 0x5678u32.to_le_bytes());
    }
}
