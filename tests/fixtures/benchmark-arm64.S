// Own finite integer and ordinary-RAM fixtures for the GuestState ABI benchmark.
// x12 = element/iteration count, x13 = arithmetic seed; x10/x11 = RAM inputs.
// The original three loops preserve NZCV; bench_mix writes comparison flags.
// Symbols are extracted from the assembled object.
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

// Seeded nonlinear word hash. The two multiplies and three conditional selects
// depend on supplied RAM and previous hash; CMP supplies fresh flags each round.
// Nine instructions per iteration keep count1024 within the reference budget.
.p2align 2
.globl _bench_mix
_bench_mix:
    mov x0, x13
    mov x1, x12
    mov x3, x10
    mov x5, #0x9e37
    mov x6, #0x85eb
    cbz x1, 2f
1:
    ldr x2, [x3], #8
    madd x0, x0, x5, x2
    mul x4, x2, x6
    cmp x0, x4
    csel x7, x0, x4, hi
    csinv x8, x7, x0, cs
    csneg x0, x8, x7, mi
    sub x1, x1, #1
    cbnz x1, 1b
2:
    ret
