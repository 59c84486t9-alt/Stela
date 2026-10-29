//! Destination-local extended-state geometry and descriptor lifetime.
//!
//! This unit enables no processor feature and admits no compiler target. The
//! real entry stub must save the whole enabled state before Rust runs.
//! Standard XSAVE64/XRSTOR64 only; every entry owns a separate IST image.
pub(crate) use stela_boot_core::xstate::*;

// Shared scalar-only boundary routines. Their raw buffer arguments are not
// permission: callers must keep the destination owner and real mapped
// private stack image through restoration or terminal abandonment. No Rust
// runs before saving. The routines preserve SysV callee-saved GPRs; FP state
// is handled by this explicit ABI, never by a Rust prologue.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    r#"
.global stela_xstate_save_owned
stela_xstate_save_owned:
    test rdi, 63
    jnz stela_xstate_boundary_refuse
    mov r11, gs:[{image_bytes}]
    cmp r11, 512
    jb stela_xstate_boundary_refuse
    cmp r11, {max_image_bytes}
    ja stela_xstate_boundary_refuse
    lea rax, [rdi + r11]
    cmp rsi, rax
    jne stela_xstate_boundary_refuse
    cmp qword ptr gs:[{extended}], 0
    jne stela_xstate_boundary_save_extended
    mov qword ptr [rsi + {format}], {fxsave}
    mov qword ptr [rsi + {mask}], 0
    fxsave64 [rdi]
    ret
stela_xstate_boundary_save_extended:
    cmp qword ptr gs:[{available}], 1
    jne stela_xstate_boundary_refuse
    xor ecx, ecx
    xgetbv
    mov r9d, eax
    shl rdx, 32
    or r9, rdx
    test r9, 1
    jz stela_xstate_boundary_refuse
    mov rax, gs:[{supported_mask}]
    not rax
    test r9, rax
    jnz stela_xstate_boundary_refuse
    mov rax, {refused_mask}
    test r9, rax
    jnz stela_xstate_boundary_refuse
    mov [rsi + {mask}], r9
    mov qword ptr [rsi + {format}], {xsave}
    test r9, 2
    jnz stela_xstate_boundary_header
    fxsave64 [rdi]
    mov qword ptr [rsi + {format}], {xsave_legacy}
stela_xstate_boundary_header:
    xor eax, eax
    mov [rdi + {header} + 0], rax
    mov [rdi + {header} + 8], rax
    mov [rdi + {header} + 16], rax
    mov [rdi + {header} + 24], rax
    mov [rdi + {header} + 32], rax
    mov [rdi + {header} + 40], rax
    mov [rdi + {header} + 48], rax
    mov [rdi + {header} + 56], rax
    mov rax, r9
    mov rdx, r9
    shr rdx, 32
    xsave64 [rdi]
    ret

.global stela_xstate_restore_owned
stela_xstate_restore_owned:
    test rdi, 63
    jnz stela_xstate_boundary_refuse
    mov r11, gs:[{image_bytes}]
    cmp r11, 512
    jb stela_xstate_boundary_refuse
    cmp r11, {max_image_bytes}
    ja stela_xstate_boundary_refuse
    lea rax, [rdi + r11]
    cmp rsi, rax
    jne stela_xstate_boundary_refuse
    cmp qword ptr [rsi + {format}], {fxsave}
    je stela_xstate_boundary_restore_legacy
    cmp qword ptr gs:[{extended}], 0
    je stela_xstate_boundary_refuse
    cmp qword ptr gs:[{available}], 1
    jne stela_xstate_boundary_refuse
    xor ecx, ecx
    xgetbv
    mov r9d, eax
    shl rdx, 32
    or r9, rdx
    cmp r9, [rsi + {mask}]
    jne stela_xstate_boundary_refuse
    cmp qword ptr [rsi + {format}], {xsave}
    je stela_xstate_boundary_sse_tag
    cmp qword ptr [rsi + {format}], {xsave_legacy}
    jne stela_xstate_boundary_refuse
    test r9, 2
    jnz stela_xstate_boundary_refuse
    jmp stela_xstate_boundary_restore_extended
stela_xstate_boundary_sse_tag:
    test r9, 2
    jz stela_xstate_boundary_refuse
stela_xstate_boundary_restore_extended:
    mov rax, r9
    mov rdx, r9
    shr rdx, 32
    xrstor64 [rdi]
    cmp qword ptr [rsi + {format}], {xsave_legacy}
    jne stela_xstate_boundary_restored
    fxrstor64 [rdi]
stela_xstate_boundary_restored:
    ret
stela_xstate_boundary_restore_legacy:
    cmp qword ptr gs:[{extended}], 0
    jne stela_xstate_boundary_refuse
    cmp qword ptr [rsi + {mask}], 0
    jne stela_xstate_boundary_refuse
    fxrstor64 [rdi]
    ret
.global stela_xstate_boundary_refuse
stela_xstate_boundary_refuse:
    cli
stela_xstate_boundary_halt:
    hlt
    jmp stela_xstate_boundary_halt
"#,
    image_bytes = const super::host::local::XSTATE_IMAGE_BYTES_OFFSET,
    supported_mask = const super::host::local::XSTATE_SUPPORTED_MASK_OFFSET,
    available = const super::host::local::XSTATE_AVAILABLE_OFFSET,
    extended = const super::host::local::XSTATE_EXTENDED_OFFSET,
    max_image_bytes = const MAX_IMAGE_BYTES,
    refused_mask = const !ADMITTED_MASK,
    format = const ENTRY_FORMAT_OFFSET,
    mask = const ENTRY_MASK_OFFSET,
    header = const STANDARD_HEADER_OFFSET,
    fxsave = const FORMAT_FXSAVE,
    xsave = const FORMAT_XSAVE,
    xsave_legacy = const FORMAT_XSAVE_LEGACY_SSE,
);

#[cfg(target_arch = "x86_64")]
unsafe extern "sysv64" {
    /// # Safety
    /// Current CPL0 pinned Local/owner, IF clear and mapped stack owns
    /// image plus adjacent metadata; keep both until restore or abandonment.
    pub(crate) fn stela_xstate_save_owned(image: *mut u8, metadata: *mut EntryMetadata);
    /// # Safety
    /// Exactly that still-owned image/metadata and unchanged destination
    /// contract. Cannot be a copied pointer or caller-synthesized format/mask.
    pub(crate) fn stela_xstate_restore_owned(image: *const u8, metadata: *const EntryMetadata);
    pub(crate) fn stela_xstate_boundary_refuse() -> !;
}

pub(crate) static DEFAULT_MXCSR: u32 = 0x1f80;
