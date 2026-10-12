// Genuine middle dylib: main imports _bound_function/_bound_seed from this image.
// The function calls a leaf import through BLR, then stores the result and an
// adjusted result through a pointer rebased into its own zero-tail BSS.
.text
.p2align 2
.globl _bound_function
_bound_function:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    adrp x15, _middle_pointers@PAGE
    add x15, x15, _middle_pointers@PAGEOFF
    ldp x16, x17, [x15]
    blr x16
    str x0, [x17]
    add x0, x0, #13
    str x0, [x17, #8]
    ldp x29, x30, [sp], #16
    ret

.section __DATA_CONST,__const
.p2align 3
_middle_pointers:
    .quad _leaf_function
    .quad _middle_output

.data
.p2align 3
.globl _bound_seed
_bound_seed:
    .quad 0x9e3779b97f4a7c15
.zerofill __DATA,__bss,_middle_padding,16384,3
.zerofill __DATA,__bss,_middle_output,16384,3
