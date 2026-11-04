//! Counted spans and bounded fixed-field patches.
use super::super::*;
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

#[test]
fn guest_site_markers_follow_span_copy_split_and_instruction_elision() {
    use crate::block::RecoverySiteKind;
    let mut code = Code::new();
    code.asm().nop();
    let start = code.checkpoint();
    code.asm()
        .guest_access(|asm| asm.mov_load(Size::Qword, Gpr::Rcx, Mem::base(Gpr::Rax, 0)));
    let span = code.span_since(start);
    code.asm().guest_check();
    assert_eq!(&code[..], [0x90, 0x48, 0x8b, 0x08, 0x0f, 0x0b]);
    assert_eq!(
        (
            code.sites()[0].start,
            code.sites()[0].end,
            code.sites()[0].site.kind()
        ),
        (1, 4, RecoverySiteKind::GuestAccess)
    );
    let mut copied = Code::new();
    copied.asm().nop();
    copied.append_span(&code, span);
    assert_eq!(copied.sites(), &code.sites()[..1]);
    copied.remove_instruction(0..1);
    assert_eq!((copied.sites()[0].start, copied.sites()[0].end), (0, 3));
    let tail = code.split_off(start);
    assert!(code.sites().is_empty());
    assert_eq!((tail.sites()[0].start, tail.sites()[1].start), (0, 3));
    copied.append(tail);
    assert_eq!(copied.sites().len(), 3);
    copied.clear();
    assert!(copied.sites().is_empty());
}

#[test]
fn removing_an_access_preserves_sites_on_both_sides() {
    let mut code = Code::new();
    code.asm().guest_check();
    let start = code.len();
    code.asm()
        .guest_access(|asm| asm.mov_load(Size::Qword, Gpr::Rcx, Mem::base(Gpr::Rax, 0)));
    let end = code.len();
    code.asm().guest_check();
    let before = code.sites()[0];
    let after = code.sites()[2];
    code.remove_instruction(start..end);
    assert_eq!(code.instructions(), 2);
    assert_eq!(
        code.sites(),
        &[
            before,
            EmissionSite {
                start: 2,
                end: 4,
                ..after
            }
        ]
    );
}

#[test]
fn lock_prefix_is_part_of_the_guest_operand_site() {
    let mut code = Code::new();
    code.asm().guest_access(|asm| {
        asm.lock();
        asm.xadd(Size::Qword, Mem::base(Gpr::Rdx, 0), Gpr::Rax)
    });
    assert_eq!(&code[..], [0xf0, 0x48, 0x0f, 0xc1, 0x02]);
    assert_eq!((code.sites()[0].start, code.sites()[0].end), (0, 5));
}
