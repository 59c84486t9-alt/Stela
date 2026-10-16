// Entry for the AMX reference image at EL1: identity-map RAM as Normal
// write-back memory (the emulator makes unaligned accesses, which fault on the
// MMU-off Device type), enable FP/AdvSIMD, set FPCR.DN as corsix test.c does,
// then run the C driver.
    .equ RAM_BLOCK,     0x40000000      // 1 GiB level-1 block holding image, batch and results
    .equ BLOCK_NORMAL,  0x401           // valid block, AF, AttrIndx 0
    .equ BLOCK_SHARED,  (3 << 8)        // inner shareable
    .equ MAIR_NORMAL,   0xff            // attribute 0: Normal write-back
    .equ TCR_VALUE,     25 | (1 << 8) | (1 << 10) | (3 << 12) | (1 << 23) | (2 << 32)
    .equ SCTLR_MMU,     (1 << 0) | (1 << 2) | (1 << 12)

    .section .text.start, "ax"
    .global _start
_start:
    ldr     x0, =__stack_top
    mov     sp, x0
    adrp    x1, page_table
    ldr     x2, =(RAM_BLOCK | BLOCK_NORMAL | BLOCK_SHARED)
    str     x2, [x1, #8]
    mov     x0, #MAIR_NORMAL
    msr     mair_el1, x0
    ldr     x0, =TCR_VALUE
    msr     tcr_el1, x0
    msr     ttbr0_el1, x1
    isb
    mrs     x0, sctlr_el1
    ldr     x2, =SCTLR_MMU
    orr     x0, x0, x2
    bic     x0, x0, #(1 << 1)
    msr     sctlr_el1, x0
    isb
    mov     x0, #(3 << 20)
    msr     cpacr_el1, x0
    isb
    mov     x0, #(1 << 25)
    msr     fpcr, x0
    bl      reference_main
1:  b       1b

    .section .bss.page_table, "aw", %nobits
    .balign 4096
page_table:
    .space 4096
