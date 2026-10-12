// Original integer pair fixture; dedicated data at 0x8000 and guest SP=0x9000.
.text
.globl _pair_fixture
_pair_fixture:
    mov x1, #0x8000
    mov x2, #40
    mov x3, #2
    stp x2, x3, [x1]
    ldp x4, x5, [x1]
    add x0, x4, x5
    mov x10, #0x9000
    mov sp, x10
    stp x4, x5, [sp, #-16]!
    mov x4, #0
    mov x5, #0
    ldp x4, x5, [sp], #16
    stp w4, w5, [x1, #16]
    mov w6, #0x80000000
    mov w7, #0x7fffffff
    stp w6, w7, [x1, #24]
    ldpsw x6, x7, [x1, #24]
    stp x6, x7, [x1, #32]
    ret
