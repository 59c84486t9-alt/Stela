/* QEMU Multiboot1 address-fields development image. No ELF loader or ARM
 * execution path is implemented here. The Rust entry mounts the shared runtime. */
.set MB_MAGIC, 0x1badb002
.set MB_FLAGS, 0x10003
.set CR0_WP_PG_PE, 0x80010001
.set CR4_PAE_OSFXSR_OSXMMEXCPT, 0x620
.set CR4_PGE_LA57_PCIDE, 0x21080
.set EFER_MSR, 0xc0000080
.set EFER_LME_NXE, 0x900
.set PAGE_PRESENT_RW_LARGE, 0x83
.section .multiboot,"a"
.balign 4
.global stela_multiboot_header
stela_multiboot_header:
.long MB_MAGIC, MB_FLAGS, -(MB_MAGIC + MB_FLAGS)
.long stela_multiboot_header, __image_start, __load_end, __image_end, stela_start32

.section .text.boot,"ax"
.code32
.global stela_start32
stela_start32:
    cli
    cld
    movl %eax, stela_boot_magic
    movl %ebx, stela_boot_info
    lgdt stela_gdt_pointer
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movl $stela_stack_top, %esp
    cmpl $0x2badb002, stela_boot_magic
    jne stela_boot_failure
    movl $0x80000000, %eax
    cpuid
    cmpl $0x80000008, %eax
    jb stela_boot_failure
    movl $0x80000001, %eax
    cpuid
    andl $0x20100000, %edx
    cmpl $0x20100000, %edx
    jne stela_boot_failure
    movl $1, %eax
    cpuid
    andl $0x07000021, %edx
    cmpl $0x07000021, %edx
    jne stela_boot_failure
    movl $stela_boot_pdpt, %eax
    orl $3, %eax
    movl %eax, stela_boot_pml4
    movl $stela_boot_pd, %eax
    orl $3, %eax
    movl %eax, stela_boot_pdpt
    xorl %ecx, %ecx
.Lidentity:
    movl %ecx, %eax
    shll $21, %eax
    orl $PAGE_PRESENT_RW_LARGE, %eax
    movl %eax, stela_boot_pd(,%ecx,8)
    incl %ecx
    cmpl $512, %ecx
    jne .Lidentity
    movl %cr4, %eax
    andl $~CR4_PGE_LA57_PCIDE, %eax
    orl $CR4_PAE_OSFXSR_OSXMMEXCPT, %eax
    movl %eax, %cr4
    movl $stela_boot_pml4, %eax
    movl %eax, %cr3
    movl $EFER_MSR, %ecx
    rdmsr
    orl $EFER_LME_NXE, %eax
    wrmsr
    movl %cr0, %eax
    andl $~12, %eax
    orl $CR0_WP_PG_PE, %eax
    movl %eax, %cr0
    ljmp $8, $stela_start64
stela_boot_failure:
    movb $'B', %al
    movw $0x3f8, %dx
    outb %al, %dx
    movl $0x11, %eax
    movw $0xf4, %dx
    outl %eax, %dx
.Lboot_halt:
    cli
    hlt
    jmp .Lboot_halt

.code64
stela_start64:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    xorl %eax, %eax
    movw %ax, %fs
    movw %ax, %gs
    leaq stela_stack_top(%rip), %rsp
    andq $-16, %rsp
    xorq %rbp, %rbp
    ldmxcsr stela_initial_mxcsr(%rip)
    movl stela_boot_info(%rip), %edi
    movl stela_boot_magic(%rip), %esi
    call stela_boot_main
    jmp stela_fatal_interrupt

/* Terminal handlers never call Rust, allocate, acquire runtime locks, return,
 * or resume a partially executed native call. IF stays clear. No successful
 * guest exception-delivery or host-fault recovery is inferred. */
.global stela_fatal_interrupt
stela_fatal_interrupt:
    movb $'I', %al
    jmp .Lfatal_emit
.global stela_fatal_nmi
stela_fatal_nmi:
    movb $'N', %al
    jmp .Lfatal_emit
.global stela_fatal_page_fault
stela_fatal_page_fault:
    movb $'P', %al
.Lfatal_emit:
    movw $0x3f8, %dx
    outb %al, %dx
    movl $0x12, %eax
    movw $0xf4, %dx
    outl %eax, %dx
.Lfatal_halt:
    cli
    hlt
    jmp .Lfatal_halt

.section .data.boot,"aw"
.balign 8
stela_gdt:
.quad 0
.quad 0x00af9b000000ffff
.quad 0x00cf93000000ffff
stela_gdt_end:
stela_gdt_pointer:
.word stela_gdt_end - stela_gdt - 1
.long stela_gdt
stela_initial_mxcsr:
.long 0x1f80
stela_boot_magic:
.long 0
stela_boot_info:
.long 0

.section .bss.boot,"aw",@nobits
.balign 4096
.global stela_boot_pml4
stela_boot_pml4:
.skip 4096
.global stela_boot_pdpt
stela_boot_pdpt:
.skip 4096
.global stela_boot_pd
stela_boot_pd:
.skip 4096
.balign 4096
.global stela_stack_bottom
stela_stack_bottom:
.skip 1048576
.global stela_stack_top
stela_stack_top:
