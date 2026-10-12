// Genuine leaf dylib with its own data/BSS mapping and chained rebase.
.text
.p2align 2
.globl _leaf_function
_leaf_function:
    adrp x9, _leaf_pointers@PAGE
    add x9, x9, _leaf_pointers@PAGEOFF
    ldr x10, [x9]
    ldr x4, [x10]
    str x0, [x10]
    add x0, x0, #11
    str x0, [x10, #8]
    ret

.section __DATA_CONST,__const
.p2align 3
_leaf_pointers:
    .quad _leaf_output

.data
.p2align 3
_leaf_marker:
    .quad 0x3141592653589793
.zerofill __DATA,__bss,_leaf_padding,16384,3
.zerofill __DATA,__bss,_leaf_output,16384,3
