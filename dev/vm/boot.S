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
#ifdef STELA_TRANSLATED
    /* BIOS overwrites low RAM during startup. Read native code from LBA 1
     * into 0x1000:0000 after BIOS has handed us the boot sector. */
    movw $disk_packet, %si
    movb $0x42, %ah
    sti
    int $0x13
    cli
    jc disk_failure
#endif
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
#ifdef STELA_TRANSLATED
    /* ABI v2: zero GuestState at 0x6000; call AOT code loaded at 0x10000. */
    xorq %rax, %rax
    movq $0x6000, %rdi
    movq $33, %rcx
    rep stosq
    movq $0x6000, %rdi
    movq $0x10000, %rax
    call *%rax
    movq 0x6000, %rax
#else
    movq $40, %rax
    addq $2, %rax
#endif
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

#ifdef STELA_TRANSLATED
.code16
disk_failure:
    movw $0xe9, %dx
    movb $'E', %al
    outb %al, %dx
    hlt
    jmp disk_failure
.balign 4
disk_packet:
    .byte 0x10, 0
    .word STELA_NATIVE_SECTORS
    .word 0, 0x1000
    .quad 1
#endif

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
