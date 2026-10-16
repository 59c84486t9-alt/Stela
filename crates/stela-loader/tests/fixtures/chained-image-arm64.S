// Own unchanged linker executable with three genuine chained rebases.
// X0 supplies an integer input; X30 supplies a dispatcher return boundary.
// The entry dereferences relocated data/BSS/function pointers and calls BLR.
// A normal FP/LR frame uses owned stack RAM; no imports, PAC or system calls.
.text
.p2align 2
.globl _chained_entry
_chained_entry:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    adrp x9, _chained_pointers@PAGE
    add x9, x9, _chained_pointers@PAGEOFF
    ldp x10, x11, [x9]
    ldr x12, [x9, #16]
    ldr x1, [x10]
    ldr x4, [x11]
    add x0, x0, x1
    blr x12
    ldp x29, x30, [sp], #16
    ret

.p2align 2
_chained_callee:
    str x0, [x11]
    add x0, x0, #7
    str x0, [x11, #8]
    ret

.section __DATA_CONST,__const
.p2align 3
.globl _chained_pointers
_chained_pointers:
    .quad _chained_seed
    .quad _chained_output
    .quad _chained_callee

.data
.p2align 3
.globl _chained_seed
_chained_seed:
    .quad 0x9e3779b97f4a7c15
.zerofill __DATA,__bss,_chained_padding,16384,3
.zerofill __DATA,__bss,_chained_output,16384,3
