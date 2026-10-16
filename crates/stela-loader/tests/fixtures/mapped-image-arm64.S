// Own freestanding Mach-O entry fixture; this is not a macOS process ABI.
// X0 is a supplied input, X30 is a supplied dispatcher stop address. No
// imports, fixups or pointer authentication. A normal FP/LR frame uses owned
// guest stack RAM. Dirty GPRs and NZCV remain
// observable. ADR and ADRP use linked guest addresses without sliding.
.text
.p2align 2
.globl _mapped_entry
_mapped_entry:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    adr x8, Lcurrent
Lcurrent:
    adrp x9, _mapped_seed@PAGE
    add x9, x9, _mapped_seed@PAGEOFF
    ldr x1, [x9]
    add x0, x0, x1
    bl _mapped_callee
    ldp x29, x30, [sp], #16
    ret

.p2align 2
_mapped_callee:
    adrp x10, _mapped_output@PAGE
    add x10, x10, _mapped_output@PAGEOFF
    ldr x4, [x10]
    str x0, [x10]
    add x0, x0, #7
    str x0, [x10, #8]
    ret

.data
.p2align 3
.globl _mapped_seed
_mapped_seed:
    .quad 0x9e3779b97f4a7c15
// Large zero-fill forces a segment tail beyond file-backed page padding.
// Put the observed output beyond the file-backed segment page, so LDR/STR
// actually exercise owned zero-fill RAM rather than zero padding in the file.
.zerofill __DATA,__bss,_mapped_padding,16384,3
.zerofill __DATA,__bss,_mapped_output,16384,3
