use super::*;
use alloc::vec;
use alloc::vec::Vec;

fn code(width: Width, kind: Kind, rotation: u8, mask_end: u8) -> Vec<u8> {
    let mut result = vec![];
    emit(
        &mut result,
        &Operand {
            width,
            kind,
            destination: Register::X(2),
            source: Register::X(1),
            rotation,
            mask_end,
        },
    );
    result
}

#[test]
fn full_width_extract_avoids_masked_x86_shifts_and_clears_w_upper_bits() {
    for kind in [Kind::Signed, Kind::Unsigned] {
        assert_eq!(
            code(Width::X64, kind, 0, 63),
            [0x48, 0x8b, 0x87, 8, 0, 0, 0, 0x48, 0x89, 0x87, 16, 0, 0, 0]
        );
        assert_eq!(
            code(Width::W32, kind, 0, 31),
            [
                0x48, 0x8b, 0x87, 8, 0, 0, 0, 0x89, 0xc0, 0x48, 0x89, 0x87, 16, 0, 0, 0,
            ]
        );
    }
}

#[test]
fn wrapping_signed_field_extends_before_placing_the_low_zero_bits() {
    let signed = code(Width::X64, Kind::Signed, 63, 0);
    assert_eq!(
        &signed[7..signed.len() - 7],
        [
            0x48, 0xc1, 0xe0, 63, 0x48, 0xc1, 0xf8, 63, 0x48, 0xc1, 0xe0, 1
        ]
    );
    let unsigned = code(Width::W32, Kind::Unsigned, 31, 0);
    assert_eq!(
        &unsigned[7..unsigned.len() - 7],
        [0x89, 0xc0, 0xc1, 0xe0, 31, 0xc1, 0xe8, 31, 0xc1, 0xe0, 1]
    );
    let extraction = code(Width::X64, Kind::Unsigned, 8, 15);
    assert_eq!(
        &extraction[7..extraction.len() - 7],
        [0x48, 0xc1, 0xe0, 48, 0x48, 0xc1, 0xe8, 56]
    );
}

#[test]
fn insert_masks_preserve_only_bits_outside_the_selected_destination_field() {
    for (rotation, mask_end, keep_mask) in [
        (8, 15, 0xffffffffffffff00u64),
        (60, 7, 0xfffffffffffff00f),
        (0, 63, 0),
        (1, 0, 0x7fffffffffffffff),
    ] {
        let emitted = code(Width::X64, Kind::Insert, rotation, mask_end);
        let mask_offset = emitted
            .windows(2)
            .position(|bytes| bytes == [0x48, 0xba])
            .unwrap()
            + 2;
        assert_eq!(
            &emitted[mask_offset..mask_offset + 8],
            keep_mask.to_le_bytes()
        );
    }
    let emitted = code(Width::W32, Kind::Insert, 28, 7);
    let mask_offset = emitted
        .windows(2)
        .position(|bytes| bytes == [0x81, 0xe1])
        .unwrap()
        + 2;
    assert_eq!(
        &emitted[mask_offset..mask_offset + 4],
        0xfffff00fu32.to_le_bytes()
    );
    assert_eq!(&emitted[mask_offset + 4..mask_offset + 6], [0x09, 0xc8]);
}

#[test]
fn aliased_insert_stages_both_original_operands_before_the_only_state_store() {
    let mut emitted = vec![];
    emit(
        &mut emitted,
        &Operand {
            width: Width::X64,
            kind: Kind::Insert,
            destination: Register::X(30),
            source: Register::X(30),
            rotation: 60,
            mask_end: 7,
        },
    );
    assert_eq!(&emitted[..7], [0x48, 0x8b, 0x87, 240, 0, 0, 0]);
    let destination_load = [0x48, 0x8b, 0x8f, 240, 0, 0, 0];
    assert!(emitted.windows(7).any(|bytes| bytes == destination_load));
    assert_eq!(
        &emitted[emitted.len() - 7..],
        [0x48, 0x89, 0x87, 240, 0, 0, 0]
    );
    assert_eq!(
        emitted
            .windows(3)
            .filter(|bytes| *bytes == [0x48, 0x89, 0x87])
            .count(),
        1
    );
}

#[test]
fn zero_register_reads_zero_and_discarded_results_keep_source_map_intervals() {
    for kind in [Kind::Signed, Kind::Insert, Kind::Unsigned] {
        let mut operand = Operand {
            width: Width::X64,
            kind,
            destination: Register::X(2),
            source: Register::Zero,
            rotation: 0,
            mask_end: 63,
        };
        let mut emitted = vec![];
        emit(&mut emitted, &operand);
        assert_eq!(&emitted[..2], [0x31, 0xc0]);
        operand.destination = Register::Zero;
        emitted.clear();
        emit(&mut emitted, &operand);
        assert_eq!(emitted, [0x90]);
    }
    let source: Vec<_> = [0xd340001fu32, 0xd65f03c0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let leaf = crate::compile(&source, crate::GuestAddress(0x100000)).unwrap();
    let block = crate::block::compile(&source, crate::GuestAddress(0x100000)).unwrap();
    for native in [&leaf, &block.native] {
        assert_eq!(
            native.source_map,
            [
                (crate::GuestAddress(0x100000), 0),
                (crate::GuestAddress(0x100004), 1)
            ]
        );
    }
}
