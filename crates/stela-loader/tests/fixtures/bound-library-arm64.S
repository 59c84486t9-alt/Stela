// Companion genuine MH_DYLIB. Only _bound_function and _bound_seed are exported.
// A chained rebase points at the dylib's own BSS; no imported symbols are used.
.text
.p2align 2
.globl _bound_function
_bound_function:
    adrp x9, _library_pointers@PAGE
    add x9, x9, _library_pointers@PAGEOFF
    ldr x10, [x9]
    ldr x4, [x10]
    str x0, [x10]
    add x0, x0, #11
    str x0, [x10, #8]
    ret

.section __DATA_CONST,__const
.p2align 3
_library_pointers:
    .quad _library_output

.data
.p2align 3
.globl _bound_seed
_bound_seed:
    .quad 0x9e3779b97f4a7c15
.zerofill __DATA,__bss,_library_padding,16384,3
.zerofill __DATA,__bss,_library_output,16384,3
