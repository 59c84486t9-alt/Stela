// Own finite integer and ordinary-RAM fixtures for the GuestState ABI benchmark.
// x12 = element/iteration count, x13 = arithmetic seed; x10/x11 = RAM inputs.
// No instruction writes NZCV. Symbols are extracted from the assembled object.
.text
.p2align 2
.globl _bench_integer
_bench_integer:
    mov x0, #0
    mov x1, x12
    mov x2, x13
    cbz x1, 2f
1:
    add x0, x0, x2
    add x2, x2, #3
    sub x1, x1, #1
    cbnz x1, 1b
2:
    ret

.p2align 2
.globl _bench_sum
_bench_sum:
    mov x0, #0
    mov x1, x12
    mov x3, x10
    cbz x1, 2f
1:
    ldr x2, [x3], #8
    add x0, x0, x2
    sub x1, x1, #1
    cbnz x1, 1b
2:
    ret

.p2align 2
.globl _bench_copy_sum
_bench_copy_sum:
    mov x0, #0
    mov x1, x12
    mov x3, x10
    mov x4, x11
    cbz x1, 2f
1:
    ldr x2, [x3], #8
    str x2, [x4], #8
    add x0, x0, x2
    sub x1, x1, #1
    cbnz x1, 1b
2:
    ret
