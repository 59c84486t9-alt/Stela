/* Original Stela fixture: BIOS entry -> x86-64 long mode -> test payload.
 * Link at 0x7c00. No Apple code, filesystem, or operating system required.
 * PML4=0x1000, PDPT=0x2000, PD=0x3000; identity maps the first 2 MiB.
 */
.section .text
.global _start, long_mode, payload, completed
.code16
_start:
    cli
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw $0x7c00, %sp
    cld
    inb $0x92, %al
    orb $2, %al
    outb %al, $0x92

    xorw %ax, %ax
    movw $0x1000, %di
    movw $0x1800, %cx
    rep stosw
    movl $0x2003, 0x1000
    movl $0x3003, 0x2000
    movl $0x0083, 0x3000
    lgdt gdt_pointer
    movl %cr4, %eax
    orl $0x20, %eax
    movl %eax, %cr4
    movl $0x1000, %eax
    movl %eax, %cr3
    movl $0xc0000080, %ecx
    rdmsr
    orl $0x100, %eax
    wrmsr
    movl %cr0, %eax
    orl $0x80000001, %eax
    movl %eax, %cr0
    ljmpl $8, $long_mode

.code64
long_mode:
    movw $16, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movq $0x7000, %rsp
payload:
    /* Replace this function body with emitted native code in later stages. */
    movq $40, %rax
    addq $2, %rax
    movq %rax, 0x5000
    movw $0xe9, %dx
    movb $'O', %al
    outb %al, %dx
    movb $'K', %al
    outb %al, %dx
    movb $10, %al
    outb %al, %dx
    movq 0x5000, %rax
completed:
    hlt
    jmp completed

.balign 8
gdt:
    .quad 0
    .quad 0x00af9a000000ffff
    .quad 0x00cf92000000ffff
gdt_end:
gdt_pointer:
    .word gdt_end - gdt - 1
    .long gdt
.org 510
.word 0xaa55
