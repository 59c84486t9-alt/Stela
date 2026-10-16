// Bare-metal AArch64 oracle harness for QEMU `virt` with `-cpu max`.
//
// The host loads this image at HARNESS and a case batch at BATCH, then starts
// the CPU at EL1. Each case single-steps a declared number of EL0 instructions
// from the code page; the lower-EL vector records full register state after
// the last step or the first other exception. Results are written to the host
// file named in the batch header through semihosting, and QEMU exits with the
// harness status.
//
// Layout constants are shared with `lib.rs`.

    // QEMU places the device tree in the first MiB of RAM.
    .equ RAM,              0x40000000
    .equ HARNESS,          0x40100000
    .equ L1_TABLE,         0x40110000
    .equ L2_TABLE,         0x40111000
    .equ L3_DATA,          0x40113000
    .equ BATCH,            0x41000000
    .equ RESULTS,          0x50000000
    // Case windows sit above 8 GiB, where a macOS host process can map them.
    .equ CASE_REGION,      0x200000000
    .equ L2_CASE_TABLE,    0x40114000
    .equ CODE_PAGE,        0x200200000
    // EL1-only writable alias of the code block, for installing each case.
    .equ CODE_ALIAS,       0x200400000
    .equ DATA_WINDOW,      0x208000000
    .equ DATA_BYTES,       0x4000
    .equ PAGE_BYTES,       0x1000

    // Batch header. Case and result strides depend on the batch's largest SVL.
    .equ BATCH_COUNT,      0
    .equ BATCH_NAME_BYTES, 8
    .equ BATCH_CASE_BYTES, 16
    .equ BATCH_RESULT_BYTES, 24
    .equ BATCH_NAME,       32
    .equ BATCH_CASES,      0x1000

    // One case input; scalable registers follow the data window.
    .equ CASE_WORDS,       0
    .equ CASE_STEPS,       8
    .equ CASE_SVL,         16
    .equ CASE_SVCR,        24
    .equ CASE_TPIDR2,      32
    .equ CASE_FPMR,        40
    .equ CASE_FLAGS,       48
    .equ CASE_CODE,        64
    .equ CASE_STATE,       512
    .equ CASE_DATA,        0x1000
    .equ CASE_SCALABLE,    0x5000

    // One result record; DATA_BYTES of the window follow the header.
    .equ RESULT_X,         0
    .equ RESULT_SP,        248
    .equ RESULT_SPSR,      256
    .equ RESULT_FPCR,      264
    .equ RESULT_FPSR,      272
    .equ RESULT_ESR,       280
    .equ RESULT_ELR,       288
    .equ RESULT_FAR,       296
    .equ RESULT_V,         320
    .equ RESULT_SVCR,      832
    .equ RESULT_TPIDR2,    840
    .equ RESULT_FPMR,      848
    .equ RESULT_DATA,      0x400
    .equ RESULT_SCALABLE,  0x4400

    // GuestState layout (stela-state).
    .equ STATE_X,          0
    .equ STATE_SP,         248
    .equ STATE_NZCV,       256
    .equ STATE_V,          264
    .equ STATE_FPCR,       776
    .equ STATE_FPSR,       780

    // Architectural values.
    .equ CPACR_FP_SVE_SME, (3 << 20) | (3 << 16) | (3 << 24)
    .equ MAIR_NORMAL_WB,   0xff
    // T0SZ=25, inner/outer WB, inner shareable, 4 KiB granule, TTBR1 off, 48-bit PA.
    .equ TCR_VALUE,        25 | (1 << 8) | (1 << 10) | (3 << 12) | (1 << 23) | (5 << 32)
    // RES1 bits with the MMU on; caches, alignment and SP alignment checks off.
    // ATA0 allows EL0 allocation-tag arithmetic; tag checks stay disabled.
    // EnTP2 allows EL0 access to TPIDR2_EL0.
    .equ SCTLR_VALUE,      0x30d00801 | (1 << 42) | (1 << 60)
    .equ SPSR_EL0T_MASKED, 0x3c0
    .equ NZCV_MASK,        0xf0000000
    .equ SPSR_SS,          1 << 21
    .equ MDSCR_SS,         1
    .equ ESR_CLASS_SHIFT,  26
    .equ ESR_SOFTWARE_STEP, 0x32
    .equ SVCR_SM,          1
    .equ SVCR_ZA,          2
    .equ SMCR_EZT0,        1 << 30
    .equ SVE_GRANULE,      16
    .equ FLAG_FPMR,        1
    .equ ZT0_BYTES,        64
    .equ DESC_TABLE,       3
    .equ DESC_BLOCK,       1
    .equ DESC_PAGE,        3
    // AF, inner shareable, AttrIndx 0.
    .equ DESC_NORMAL,      (1 << 10) | (3 << 8)
    .equ DESC_EL0_RW,      1 << 6
    .equ DESC_READ_ONLY,   3 << 6
    .equ DESC_PXN,         1 << 53
    .equ DESC_UXN,         1 << 54
    .equ L2_ENTRIES,       512
    .equ BLOCK_2M,         0x200000
    .equ BLOCK_1G,         0x40000000

    // Semihosting.
    .equ SYS_OPEN,         0x01
    .equ SYS_CLOSE,        0x02
    .equ SYS_WRITE,        0x05
    .equ SYS_EXIT,         0x18
    .equ OPEN_WRITE_BINARY, 5
    .equ EXIT_APPLICATION, 0x20026
    .equ EXIT_HARNESS_FAULT, 0x20023

    .text
    .global _start
_start:
    adr     x0, vectors
    msr     vbar_el1, x0
    ldr     x0, =CPACR_FP_SVE_SME
    msr     cpacr_el1, x0
    isb
    bl      build_tables
    ldr     x0, =MAIR_NORMAL_WB
    msr     mair_el1, x0
    ldr     x0, =TCR_VALUE
    msr     tcr_el1, x0
    ldr     x0, =L1_TABLE
    msr     ttbr0_el1, x0
    isb
    msr     gcr_el1, xzr
    msr     oslar_el1, xzr
    mov     x0, #MDSCR_SS
    msr     mdscr_el1, x0
    ldr     x0, =SCTLR_VALUE
    msr     sctlr_el1, x0
    isb

    ldr     x23, =BATCH
    ldr     x22, [x23, #BATCH_COUNT]
    ldr     x24, [x23, #BATCH_CASE_BYTES]
    ldr     x25, [x23, #BATCH_RESULT_BYTES]
    add     x20, x23, #BATCH_CASES
    ldr     x21, =RESULTS
    mov     x19, #0
next_case:
    cmp     x19, x22
    b.eq    finish

    // Install the code on a cleared page, then the initial data window.
    ldr     x2, =CODE_ALIAS
    mov     x3, #PAGE_BYTES
3:  stp     xzr, xzr, [x2], #16
    subs    x3, x3, #16
    b.ne    3b
    ldr     x0, [x20, #CASE_WORDS]
    add     x1, x20, #CASE_CODE
    ldr     x2, =CODE_ALIAS
1:  cbz     x0, 2f
    ldr     w3, [x1], #4
    str     w3, [x2], #4
    sub     x0, x0, #1
    b       1b
2:  add     x0, x20, #CASE_DATA
    ldr     x1, =DATA_WINDOW
    mov     x2, #DATA_BYTES
    bl      copy
    dsb     ish
    ic      iallu
    dsb     ish
    isb

    // Load the guest state and enter EL0.
    bl      load_scalable
    add     x30, x20, #CASE_STATE
    ldr     w0, [x30, #STATE_FPCR]
    msr     fpcr, x0
    ldr     w0, [x30, #STATE_FPSR]
    msr     fpsr, x0
    // In streaming mode V is the low part of Z, already loaded.
    mrs     x0, svcr
    tbnz    x0, #0, 4f
    add     x0, x30, #STATE_V
    ldp     q0, q1, [x0], #32
    ldp     q2, q3, [x0], #32
    ldp     q4, q5, [x0], #32
    ldp     q6, q7, [x0], #32
    ldp     q8, q9, [x0], #32
    ldp     q10, q11, [x0], #32
    ldp     q12, q13, [x0], #32
    ldp     q14, q15, [x0], #32
    ldp     q16, q17, [x0], #32
    ldp     q18, q19, [x0], #32
    ldp     q20, q21, [x0], #32
    ldp     q22, q23, [x0], #32
    ldp     q24, q25, [x0], #32
    ldp     q26, q27, [x0], #32
    ldp     q28, q29, [x0], #32
    ldp     q30, q31, [x0], #32
4:  ldr     x0, [x30, #STATE_SP]
    msr     sp_el0, x0
    ldr     x0, [x20, #CASE_STEPS]
    msr     tpidr_el1, x0
    ldr     w0, [x30, #STATE_NZCV]
    and     x0, x0, #NZCV_MASK
    orr     x0, x0, #SPSR_EL0T_MASKED
    orr     x0, x0, #SPSR_SS
    msr     spsr_el1, x0
    ldr     x0, =CODE_PAGE
    msr     elr_el1, x0
    mov     sp, x21
    ldp     x0, x1, [x30, #0]
    ldp     x2, x3, [x30, #16]
    ldp     x4, x5, [x30, #32]
    ldp     x6, x7, [x30, #48]
    ldp     x8, x9, [x30, #64]
    ldp     x10, x11, [x30, #80]
    ldp     x12, x13, [x30, #96]
    ldp     x14, x15, [x30, #112]
    ldp     x16, x17, [x30, #128]
    ldp     x18, x19, [x30, #144]
    ldp     x20, x21, [x30, #160]
    ldp     x22, x23, [x30, #176]
    ldp     x24, x25, [x30, #192]
    ldp     x26, x27, [x30, #208]
    ldp     x28, x29, [x30, #224]
    ldr     x30, [x30, #240]
    eret

    // Lower-EL synchronous exception: SP_EL1 is the case result record and
    // TPIDR_EL1 counts the steps left. Re-arm the step until the last one.
lower_sync:
    str     x0, [sp, #0]
    mrs     x0, esr_el1
    lsr     x0, x0, #ESR_CLASS_SHIFT
    cmp     x0, #ESR_SOFTWARE_STEP
    b.ne    1f
    mrs     x0, tpidr_el1
    subs    x0, x0, #1
    msr     tpidr_el1, x0
    b.eq    1f
    mrs     x0, spsr_el1
    orr     x0, x0, #SPSR_SS
    msr     spsr_el1, x0
    ldr     x0, [sp, #0]
    eret
1:  ldr     x0, [sp, #0]
    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]
    stp     x8, x9, [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30, [sp, #240]
    mrs     x0, sp_el0
    mrs     x1, spsr_el1
    stp     x0, x1, [sp, #RESULT_SP]
    mrs     x0, fpcr
    mrs     x1, fpsr
    stp     x0, x1, [sp, #RESULT_FPCR]
    mrs     x0, esr_el1
    mrs     x1, elr_el1
    stp     x0, x1, [sp, #RESULT_ESR]
    mrs     x0, far_el1
    str     x0, [sp, #RESULT_FAR]
    mrs     x0, svcr
    str     x0, [sp, #RESULT_SVCR]
    mrs     x0, tpidr2_el0
    str     x0, [sp, #RESULT_TPIDR2]
    bl      save_scalable
    mrs     x0, svcr
    tbnz    x0, #0, 4f
    add     x0, sp, #RESULT_V
    stp     q0, q1, [x0], #32
    stp     q2, q3, [x0], #32
    stp     q4, q5, [x0], #32
    stp     q6, q7, [x0], #32
    stp     q8, q9, [x0], #32
    stp     q10, q11, [x0], #32
    stp     q12, q13, [x0], #32
    stp     q14, q15, [x0], #32
    stp     q16, q17, [x0], #32
    stp     q18, q19, [x0], #32
    stp     q20, q21, [x0], #32
    stp     q22, q23, [x0], #32
    stp     q24, q25, [x0], #32
    stp     q26, q27, [x0], #32
    stp     q28, q29, [x0], #32
    stp     q30, q31, [x0], #32
4:  smstop

    // Restore the loop registers from the record position and save the window.
    mov     x21, sp
    ldr     x23, =BATCH
    ldr     x22, [x23, #BATCH_COUNT]
    ldr     x24, [x23, #BATCH_CASE_BYTES]
    ldr     x25, [x23, #BATCH_RESULT_BYTES]
    add     x20, x23, #BATCH_CASES
    ldr     x0, =RESULTS
    sub     x19, x21, x0
    udiv    x19, x19, x25
    madd    x20, x19, x24, x20
    ldr     x0, =DATA_WINDOW
    add     x1, x21, #RESULT_DATA
    mov     x2, #DATA_BYTES
    bl      copy
    add     x19, x19, #1
    add     x20, x20, x24
    add     x21, x21, x25
    b       next_case

finish:
    ldr     x23, =BATCH
    adr     x0, params
    add     x1, x23, #BATCH_NAME
    ldr     x2, [x23, #BATCH_NAME_BYTES]
    mov     x3, #OPEN_WRITE_BINARY
    stp     x1, x3, [x0]
    str     x2, [x0, #16]
    mov     x1, x0
    mov     w0, #SYS_OPEN
    hlt     #0xf000
    mov     x24, x0
    adr     x1, params
    ldr     x2, =RESULTS
    ldr     x3, [x23, #BATCH_COUNT]
    ldr     x4, [x23, #BATCH_RESULT_BYTES]
    mul     x3, x3, x4
    stp     x24, x2, [x1]
    str     x3, [x1, #16]
    mov     w0, #SYS_WRITE
    hlt     #0xf000
    adr     x1, params
    str     x24, [x1]
    mov     w0, #SYS_CLOSE
    hlt     #0xf000
    ldr     x0, =EXIT_APPLICATION
    b       exit

harness_fault:
    ldr     x0, =EXIT_HARNESS_FAULT
exit:
    adr     x1, params
    stp     x0, xzr, [x1]
    mov     w0, #SYS_EXIT
    hlt     #0xf000
    b       .

    // Set the case's streaming vector length, SVCR, TPIDR2 and FPMR, then load
    // Z, P, ZA and ZT0 from the case (x20). Clobbers x0-x3 and w12.
load_scalable:
    smstop
    ldr     x1, [x20, #CASE_SVL]
    cbz     x1, 9f
    lsr     x1, x1, #4
    sub     x1, x1, #1
    orr     x1, x1, #SMCR_EZT0
    msr     smcr_el1, x1
    isb
    ldr     x0, [x20, #CASE_TPIDR2]
    msr     tpidr2_el0, x0
    ldr     x0, [x20, #CASE_FLAGS]
    tbz     x0, #0, 1f
    ldr     x0, [x20, #CASE_FPMR]
    msr     S3_3_C4_C4_2, x0
1:  ldr     x3, [x20, #CASE_SVCR]
    tbz     x3, #0, 2f
    smstart sm
2:  tbz     x3, #1, 3f
    smstart za
3:  add     x0, x20, #CASE_SCALABLE
    tbz     x3, #0, 5f
    ldr     z0, [x0]
    addvl   x0, x0, #1
    .irp n, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    ldr     z\n, [x0]
    addvl   x0, x0, #1
    .endr
    .irp n, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
    ldr     p\n, [x0]
    addpl   x0, x0, #1
    .endr
    b       6f
    // Without streaming mode the register banks are skipped.
5:  rdsvl   x1, #1
    lsl     x2, x1, #5
    add     x0, x0, x2
    lsl     x2, x1, #1
    add     x0, x0, x2
6:  tbz     x3, #1, 9f
    rdsvl   x1, #1
    mov     w12, #0
7:  ldr     za[w12, 0], [x0]
    addsvl  x0, x0, #1
    add     w12, w12, #1
    cmp     x12, x1
    b.ne    7b
    ldr     zt0, [x0]
9:  ret

    // Save Z, P, ZA and ZT0 into the result record at SP (lower_sync).
    // Clobbers x0-x3 and w12.
save_scalable:
    mrs     x3, svcr
    mov     x0, #RESULT_SCALABLE
    add     x0, sp, x0
    cbz     x3, 9f
    tbz     x3, #0, 5f
    .irp n, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    str     z\n, [x0]
    addvl   x0, x0, #1
    .endr
    .irp n, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
    str     p\n, [x0]
    addpl   x0, x0, #1
    .endr
    b       6f
5:  rdsvl   x1, #1
    lsl     x2, x1, #5
    add     x0, x0, x2
    lsl     x2, x1, #1
    add     x0, x0, x2
6:  tbz     x3, #1, 9f
    rdsvl   x1, #1
    mov     w12, #0
7:  str     za[w12, 0], [x0]
    addsvl  x0, x0, #1
    add     w12, w12, #1
    cmp     x12, x1
    b.ne    7b
    str     zt0, [x0]
9:  ret

    // copy x2 bytes (a multiple of 16) from x0 to x1; clobbers x0-x4.
copy:
    ldp     x3, x4, [x0], #16
    stp     x3, x4, [x1], #16
    subs    x2, x2, #16
    b.ne    copy
    ret

    // Identity-map the first GiB of RAM for EL1. EL0 may execute the 2 MiB code
    // region and read it and the 2 MiB below it, so literal loads reach +-1 MiB
    // of the code, and may read or write the data window. Everything else
    // faults at EL0. The code region is read-only, so its contents are the same
    // for every case; the harness writes code through an EL1-only alias.
build_tables:
    ldr     x0, =L1_TABLE
    ldr     x1, =L2_TABLE | DESC_TABLE
    str     x1, [x0, #(RAM / BLOCK_1G) * 8]
    ldr     x1, =L2_CASE_TABLE | DESC_TABLE
    str     x1, [x0, #(CASE_REGION / BLOCK_1G) * 8]
    ldr     x0, =L2_TABLE
    ldr     x1, =RAM | DESC_NORMAL | DESC_BLOCK | DESC_UXN
    mov     x2, #L2_ENTRIES
1:  str     x1, [x0], #8
    add     x1, x1, #BLOCK_2M
    subs    x2, x2, #1
    b.ne    1b
    ldr     x0, =L2_CASE_TABLE
    ldr     x1, =CASE_REGION | DESC_NORMAL | DESC_BLOCK | DESC_READ_ONLY | DESC_PXN | DESC_UXN
    str     x1, [x0]
    ldr     x1, =CODE_PAGE | DESC_NORMAL | DESC_BLOCK | DESC_READ_ONLY | DESC_PXN
    str     x1, [x0, #((CODE_PAGE - CASE_REGION) / BLOCK_2M) * 8]
    ldr     x1, =CODE_PAGE | DESC_NORMAL | DESC_BLOCK | DESC_PXN | DESC_UXN
    str     x1, [x0, #((CODE_ALIAS - CASE_REGION) / BLOCK_2M) * 8]
    ldr     x1, =L3_DATA | DESC_TABLE
    str     x1, [x0, #((DATA_WINDOW - CASE_REGION) / BLOCK_2M) * 8]
    ldr     x0, =L3_DATA
    ldr     x1, =DATA_WINDOW | DESC_NORMAL | DESC_PAGE | DESC_EL0_RW | DESC_PXN | DESC_UXN
    mov     x2, #DATA_BYTES / PAGE_BYTES
2:  str     x1, [x0], #8
    add     x1, x1, #PAGE_BYTES
    subs    x2, x2, #1
    b.ne    2b
    dsb     ish
    ret

    .ltorg

    .balign 16
params:
    .quad   0, 0, 0

    // Only lower-EL synchronous exceptions are expected.
    .balign 2048
vectors:
    .rept 8
    .balign 128
    b       harness_fault
    .endr
    .balign 128
    b       lower_sync
    .rept 7
    .balign 128
    b       harness_fault
    .endr
