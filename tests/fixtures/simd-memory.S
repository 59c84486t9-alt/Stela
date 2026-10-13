// Original Stela SIMD fixture: V31 is distinct from SP/XZR, narrow loads and
// D MOVI clear upper bits, and Q transfers preserve both halves through a frame.
.text
.globl _simd_memory_fixture
_simd_memory_fixture:
    mov x1, #0x8000
    movi v31.2d, #0xff00ff0000ff00ff
    str q31, [x1]
    ldr b0, [x1]
    str q0, [x1, #16]
    movi d31, #0xff
    str q31, [x1, #32]
    stp q31, q31, [x1, #48]
    ldp q4, q5, [x1, #48]
    mov x10, #0x9000
    mov sp, x10
    ldr q2, [x1]
    str q2, [sp, #-16]!
    ldr q3, [sp], #16
    stp q2, q3, [sp, #-32]!
    ldp q6, q7, [sp], #32
    mov x0, #42
    ret
