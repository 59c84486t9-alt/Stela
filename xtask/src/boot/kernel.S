// Stela's system-mode test kernel: a flat, position-independent AArch64 image
// loaded anywhere in the first 32 MiB of guest DRAM and entered at EL1h with
// the MMU off and DAIF masked.
//
// It builds 16 KiB-granule tables (TTBR0: 47-bit with an identity block and
// three EL0 pages; TTBR1: 39-bit high half mapping the DRAM block at
// 0xffffff8000000000), turns the MMU on, continues in the high half, takes a
// data abort and an SVC at EL1, then runs two EL0 tasks that make SVCs while
// the virtual timer's FIQ switches between them. After SWITCHES switches it
// disables the timer, leaves its results in X0-X7 and waits with nothing able
// to wake it:
//   x0 = 0x5354454c41204f4b ("STELA OK"), or 0xbad for an unexpected exception
//   x1, x2 = SVCs made by task A and task B
//   x3 = timer switches
//   x4, x5 = ESR and FAR of the EL1 data abort
//   x6 = ESR of the EL1 SVC, x7 = ESR of the last EL0 SVC

.set BLOCK, 0x2000000
.set KERNEL_VA, 0xffffff8000000000
.set TABLES, 0x100000
.set USER_CODE, 0x200000
.set STACK_A, 0x204000
.set STACK_B, 0x208000
.set KDATA, 0x320000
.set KSTACK_TOP, 0x310000
.set USER_VA, 0x100000000
.set SWITCHES, 6
.set PERIOD, 240000                 // 10 ms of the 24 MHz counter
.set MAIR, 0xff                     // Attr0 Normal WB, Attr1 Device-nGnRnE
// T0SZ 17, TG0 16K, T1SZ 25, TG1 16K, inner-shareable WB walks, IPS 48 bits.
.set TCR, 0x57519b511
// M, C, SA, I, SPAN and the SCTLR_EL1 RES1 bits; EL0 WFI/WFE trap.
.set SCTLR, 0x30d0180d
.set KERNEL_BLOCK, 0x0040000000000701 // block, SH inner, AF, Attr0, UXN
.set DEVICE_BLOCK, 0x0060000000000405 // block, AF, Attr1 Device, PXN, UXN
// J473AP S5L UART (DeviceTree /arm-io/uart0) and its 32 MiB device block,
// mapped by TTBR1 level 2 entry 1.
.set UART_PA, 0x235200000
.set UART_BLOCK, 0x234000000
.set UART_VA, (KERNEL_VA + BLOCK + (UART_PA - UART_BLOCK))
.set USER_TEXT, 0x0020000000000fc3   // page, AF, nG, AP EL0 RO, PXN
.set USER_DATA, 0x0060000000000f43   // page, AF, nG, AP EL0 RW, PXN, UXN

// Kernel data, at KERNEL_VA + KDATA.
.set D_ABORT_ESR, 0
.set D_ABORT_FAR, 8
.set D_SVC_ESR, 16
.set D_SVC_A, 24
.set D_SVC_B, 32
.set D_SWITCHES, 40
.set D_CURRENT, 48
.set D_USER_ESR, 56
.set D_CONTEXT, 0x100              // two 0x200-byte contexts
// Context: x0-x30, then SP_EL0, ELR, SPSR.
.set C_X8, 64
.set C_SP, 248
.set C_ELR, 256
.set C_SPSR, 264

.text
_start:
    adr x19, .
    and x20, x19, #~(BLOCK - 1)         // DRAM block base
    // Zero tables, user pages, stack and data.
    add x1, x20, #TABLES
    add x2, x20, #0x330000
1:  stp xzr, xzr, [x1], #16
    cmp x1, x2
    b.lo 1b
    add x1, x20, #TABLES                // TTBR1 level 1 (8 entries)
    add x2, x20, #(TABLES + 0x4000)     // TTBR1 level 2
    add x3, x20, #(TABLES + 0x8000)     // TTBR0 level 1
    add x4, x20, #(TABLES + 0xc000)     // TTBR0 level 2
    add x5, x20, #(TABLES + 0x10000)    // TTBR0 level 3
    orr x6, x2, #3
    str x6, [x1]
    ldr x7, =KERNEL_BLOCK
    orr x6, x20, x7
    str x6, [x2]                        // KERNEL_VA -> block
    str x6, [x4, #(0x400 * 8)]          // identity for the MMU switch
    ldr x6, =(UART_BLOCK | DEVICE_BLOCK)
    str x6, [x2, #8]                    // KERNEL_VA + 32 MiB -> UART block
    orr x6, x4, #3
    str x6, [x3]
    orr x6, x5, #3
    str x6, [x4, #(0x80 * 8)]           // USER_VA level 2 -> level 3
    ldr x7, =USER_TEXT
    add x6, x20, #USER_CODE
    orr x6, x6, x7
    str x6, [x5]
    ldr x7, =USER_DATA
    add x6, x20, #STACK_A
    orr x6, x6, x7
    str x6, [x5, #8]
    add x6, x20, #STACK_B
    orr x6, x6, x7
    str x6, [x5, #16]
    // Copy the EL0 code to its page, then make it visible to fetches.
    adr x6, user_start
    adr x7, user_end
    add x8, x20, #USER_CODE
2:  ldp x9, x10, [x6], #16
    stp x9, x10, [x8], #16
    cmp x6, x7
    b.lo 2b
    dsb ish
    ic iallu
    dsb ish
    isb
    ldr x6, =MAIR
    msr mair_el1, x6
    ldr x6, =TCR
    msr tcr_el1, x6
    msr ttbr1_el1, x1
    orr x6, x3, #(1 << 48)              // ASID 1
    msr ttbr0_el1, x6
    isb
    ldr x6, =SCTLR
    msr sctlr_el1, x6
    isb
    ldr x7, =KERNEL_VA
    adr x6, high
    sub x6, x6, x20
    add x6, x6, x7
    br x6

high:
    ldr x21, =KERNEL_VA
    adr x6, vectors
    msr vbar_el1, x6
    add x6, x21, #KSTACK_TOP
    mov sp, x6
    isb
    ldr x22, =(KERNEL_VA + KDATA)
    // Device loads and stores: the banner through the UART.
    adr x1, banner
    ldr x2, =UART_VA
3:  ldrb w3, [x1], #1
    cbz w3, 5f
4:  ldr w4, [x2, #0x10]                 // UTRSTAT: wait for TX buffer empty
    tbz w4, #1, 4b
    str w3, [x2, #0x20]                 // UTXH
    b 3b
5:
    // EL1 data abort: level 2 of TTBR1 maps only the first block.
    ldr x6, =(KERNEL_VA + 0x4000000)
    ldr x7, [x6]
    // EL1 SVC.
    svc #0x10
    // Task B's first context; task A starts below.
    add x1, x22, #(D_CONTEXT + 0x200)
    mov x6, #1
    str x6, [x1, #C_X8]
    ldr x6, =(USER_VA + 0xc000)
    str x6, [x1, #C_SP]
    ldr x6, =(USER_VA + (task_b - user_start))
    str x6, [x1, #C_ELR]
    str xzr, [x1, #C_SPSR]
    ldr x6, =PERIOD
    msr cntv_tval_el0, x6
    mov x6, #1
    msr cntv_ctl_el0, x6
    ldr x6, =(USER_VA + 0x8000)
    msr sp_el0, x6
    ldr x6, =(USER_VA + (task_a - user_start))
    msr elr_el1, x6
    msr spsr_el1, xzr                   // EL0t, nothing masked
    mov x8, #0
    eret

// EL1 synchronous: record a data abort and skip it, or record an SVC.
el1_sync:
    sub sp, sp, #32
    stp x0, x1, [sp]
    stp x2, x3, [sp, #16]
    mrs x0, esr_el1
    lsr x1, x0, #26
    ldr x2, =(KERNEL_VA + KDATA)
    cmp x1, #0x25
    b.ne 1f
    str x0, [x2, #D_ABORT_ESR]
    mrs x3, far_el1
    str x3, [x2, #D_ABORT_FAR]
    mrs x3, elr_el1
    add x3, x3, #4
    msr elr_el1, x3
    b 2f
1:  cmp x1, #0x15
    b.ne unexpected
    str x0, [x2, #D_SVC_ESR]
2:  ldp x2, x3, [sp, #16]
    ldp x0, x1, [sp]
    add sp, sp, #32
    eret

// EL0 synchronous: count SVCs per task (X8 names the task).
el0_sync:
    sub sp, sp, #32
    stp x0, x1, [sp]
    stp x2, x3, [sp, #16]
    mrs x0, esr_el1
    lsr x1, x0, #26
    cmp x1, #0x15
    b.ne unexpected
    ldr x2, =(KERNEL_VA + KDATA)
    str x0, [x2, #D_USER_ESR]
    cmp x8, #0
    mov x1, #D_SVC_A
    mov x3, #D_SVC_B
    csel x1, x1, x3, eq
    ldr x3, [x2, x1]
    add x3, x3, #1
    str x3, [x2, x1]
    ldp x2, x3, [sp, #16]
    ldp x0, x1, [sp]
    add sp, sp, #32
    eret

// EL0 FIQ: the virtual timer. Save the running task and resume the other.
el0_fiq:
    sub sp, sp, #16
    stp x0, x1, [sp]
    ldr x0, =(KERNEL_VA + KDATA)
    ldr x1, [x0, #D_CURRENT]
    lsl x1, x1, #9
    add x1, x1, x0
    add x1, x1, #D_CONTEXT
    stp x2, x3, [x1, #16]
    stp x4, x5, [x1, #32]
    stp x6, x7, [x1, #48]
    stp x8, x9, [x1, #64]
    stp x10, x11, [x1, #80]
    stp x12, x13, [x1, #96]
    stp x14, x15, [x1, #112]
    stp x16, x17, [x1, #128]
    stp x18, x19, [x1, #144]
    stp x20, x21, [x1, #160]
    stp x22, x23, [x1, #176]
    stp x24, x25, [x1, #192]
    stp x26, x27, [x1, #208]
    stp x28, x29, [x1, #224]
    str x30, [x1, #240]
    ldp x2, x3, [sp]
    stp x2, x3, [x1]
    add sp, sp, #16
    mrs x2, sp_el0
    str x2, [x1, #C_SP]
    mrs x2, elr_el1
    str x2, [x1, #C_ELR]
    mrs x2, spsr_el1
    str x2, [x1, #C_SPSR]
    ldr x3, [x0, #D_SWITCHES]
    add x3, x3, #1
    str x3, [x0, #D_SWITCHES]
    cmp x3, #SWITCHES
    b.hs done
    ldr x2, =PERIOD
    msr cntv_tval_el0, x2
    ldr x2, [x0, #D_CURRENT]
    eor x2, x2, #1
    str x2, [x0, #D_CURRENT]
    lsl x2, x2, #9
    add x1, x0, x2
    add x1, x1, #D_CONTEXT
    ldr x2, [x1, #C_SP]
    msr sp_el0, x2
    ldr x2, [x1, #C_ELR]
    msr elr_el1, x2
    ldr x2, [x1, #C_SPSR]
    msr spsr_el1, x2
    ldp x2, x3, [x1, #16]
    ldp x4, x5, [x1, #32]
    ldp x6, x7, [x1, #48]
    ldp x8, x9, [x1, #64]
    ldp x10, x11, [x1, #80]
    ldp x12, x13, [x1, #96]
    ldp x14, x15, [x1, #112]
    ldp x16, x17, [x1, #128]
    ldp x18, x19, [x1, #144]
    ldp x20, x21, [x1, #160]
    ldp x22, x23, [x1, #176]
    ldp x24, x25, [x1, #192]
    ldp x26, x27, [x1, #208]
    ldp x28, x29, [x1, #224]
    ldr x30, [x1, #240]
    ldp x0, x1, [x1]
    eret

done:
    msr cntv_ctl_el0, xzr
    ldr x0, =(KERNEL_VA + KDATA)
    ldr x1, [x0, #D_SVC_A]
    ldr x2, [x0, #D_SVC_B]
    ldr x3, [x0, #D_SWITCHES]
    ldr x4, [x0, #D_ABORT_ESR]
    ldr x5, [x0, #D_ABORT_FAR]
    ldr x6, [x0, #D_SVC_ESR]
    ldr x7, [x0, #D_USER_ESR]
    ldr x0, =0x5354454c41204f4b
    b finish

unexpected:
    mov x0, #0xbad
    mrs x1, esr_el1
    mrs x2, elr_el1
    mrs x3, far_el1
finish:
    msr daifset, #0xf
1:  wfi
    b 1b

.ltorg

banner:
    .asciz "STELA TEST KERNEL: MMU ON, UART MMIO\n"
.balign 4

// The EL1 vector table; only the expected entries are reachable.
.balign 2048
vectors:
.irp group, 0, 1, 2, 3
    .irp kind, 0, 1, 2, 3
        .balign 128
        .if \group == 1 && \kind == 0
            b el1_sync
        .elseif \group == 2 && \kind == 0
            b el0_sync
        .elseif \group == 2 && \kind == 2
            b el0_fiq
        .else
            b unexpected
        .endif
    .endr
.endr

// EL0 code, copied to USER_CODE and mapped at USER_VA.
.balign 16
user_start:
task_a:
    mov x8, #0
    b 1f
task_b:
    mov x8, #1
1:  mov x9, #0
    adr x12, touch
2:  bl increment                        // a call out of the 4 KiB page
    blr x12                             // and an indirect one
    str x9, [sp, #-16]!
    ldr x10, [sp], #16
    tst x9, #0xff
    b.ne 2b
    svc #1
    b 2b
// The next 4 KiB page of the user text (USER_VA + 0x1000): the calls to it
// and the returns from it go through the engine's lookup thunks.
.org user_start + 0x1000
increment:
    add x9, x9, #1
    ret
touch:
    ret
.balign 16
user_end:
