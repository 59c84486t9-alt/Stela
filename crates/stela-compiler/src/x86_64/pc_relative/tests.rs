use super::*;
use alloc::vec;
use alloc::vec::Vec;

#[test]
fn address_is_full_width_and_discarded_destination_keeps_map_interval() {
    let mut code = vec![];
    emit(
        &mut code,
        &Operand {
            destination: Register::Zero,
            address: u64::MAX,
        },
    );
    assert_eq!(code, [0x90]);
    code.clear();
    emit(
        &mut code,
        &Operand {
            destination: Register::X(30),
            address: 0xfedcba9876543210,
        },
    );
    assert_eq!(&code[..2], &[0x48, 0xb8]);
    assert_eq!(&code[2..10], &0xfedcba9876543210u64.to_le_bytes());
    assert_eq!(&code[10..], &[0x48, 0x89, 0x87, 240, 0, 0, 0]);
    let source: Vec<_> = [0x1000001fu32, 0xd65f03c0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let leaf = crate::compile(&source, crate::GuestAddress(0x100ffc)).unwrap();
    let block = crate::block::compile(&source, crate::GuestAddress(0x100ffc)).unwrap();
    for native in [&leaf, &block.native] {
        assert_eq!(
            native.source_map,
            [
                (crate::GuestAddress(0x100ffc), 0),
                (crate::GuestAddress(0x101000), 1)
            ]
        );
    }
}
