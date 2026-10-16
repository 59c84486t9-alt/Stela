// Own genuine dynamically linked entry fixture. DATA_CONST imports a function
// and data pointer from the companion dylib; the entry calls the resolved guest
// function with BLR and writes its result to a separate zero-tail BSS mapping.
.text
.p2align 2
.globl _bound_entry
_bound_entry:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    adrp x9, _bound_imports@PAGE
    add x9, x9, _bound_imports@PAGEOFF
    ldp x12, x13, [x9]
    ldr x1, [x13]
    add x0, x0, x1
    blr x12
    adrp x14, _bound_output@PAGE
    add x14, x14, _bound_output@PAGEOFF
    str x0, [x14]
    ldp x29, x30, [sp], #16
    ret

.section __DATA_CONST,__const
.p2align 3
_bound_imports:
    .quad _bound_function
    .quad _bound_seed

.data
.p2align 3
_bound_data_marker:
    .quad 0x123456789abcdef0
.zerofill __DATA,__bss,_bound_padding,16384,3
.zerofill __DATA,__bss,_bound_output,16384,3
