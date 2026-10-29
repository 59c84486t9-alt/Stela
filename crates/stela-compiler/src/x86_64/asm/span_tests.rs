//! Counted spans and bounded fixed-field patches.
use super::*;
use crate::x86_64::asm::Gpr;

#[test]
fn fixed_field_patching_preserves_length_and_count() {
    let mut code = Code::new();
    let jump = code.asm().jmp();
    let bytes = code.len();
    let count = code.instructions();
    code.patch(jump.offset(), 42_i32.to_le_bytes());
    assert_eq!((code.len(), code.instructions()), (bytes, count));
    assert_eq!(*code, [0xe9, 42, 0, 0, 0]);
}

#[test]
#[should_panic(expected = "patch field lies in emitted code")]
fn field_patch_refuses_out_of_bounds() {
    let mut code = Code::new();
    code.asm().nop();
    code.patch(1, [0u8; 4]);
}

#[test]
#[should_panic(expected = "patch field offset does not overflow")]
fn field_patch_refuses_offset_overflow() {
    Code::new().patch(usize::MAX, [0u8; 4]);
}

#[test]
fn spans_keep_inline_data_and_internal_branches_without_counting_data() {
    let mut source = Code::new();
    source.asm().nop();
    let start = source.checkpoint();
    {
        let mut asm = source.asm();
        asm.call_rm(Gpr::Rax);
        asm.data(&[8, 1]);
        let skip = asm.jmp8();
        asm.ud2();
        asm.bind(skip);
    }
    let span = source.span_since(start);
    source.asm().ret();
    assert_eq!(span.instructions(), 3);
    assert_eq!((span.start().offset(), span.end().offset()), (1, 9));
    let mut copied = Code::new();
    copied.asm().nop();
    copied.append_span(&source, span);
    assert_eq!(copied.instructions(), 4);
    assert_eq!(*copied, [0x90, 0xff, 0xd0, 8, 1, 0xeb, 2, 0x0f, 0x0b]);
    assert_eq!(source.instructions(), 5);
    let empty = source.span_since(source.checkpoint());
    assert!(empty.is_empty());
    copied.append_span(&source, empty);
    assert_eq!(copied.instructions(), 4);
}
