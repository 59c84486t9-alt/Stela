/* Freestanding x86 debug substrate. This is a host platform test, not an ARM
 * exception/MMU implementation. Actual compiler blocks use the ordinary ABI.
 * Entry is called by dev/vm/boot.S at 0x10000 with State A at 0x6000. */
.set STATE_A, 0x6000
.set STATE_B, 0x6400
.set STATE_BYTES, 784
.set STATE_X3, 3 * 8
.set TASK_RAM_QWORDS, 9
.set TRACE_QWORDS, 15
.set TASK_A_DATA, 0x8000
.set TIMER_TICKS, 0x8040
.set TRACE, 0x9000
.set DISPATCHES, TRACE
.set TASK_A_DONE, TRACE + 8
.set TASK_B_DONE, TRACE + 16
.set PAGE_FAULTS, TRACE + 24
.set FAULT_ADDRESS, TRACE + 32
.set FAULT_ERROR, TRACE + 40
.set FAULT_RIP, TRACE + 48
.set IRQ_RIP, TRACE + 56
.set LAST_GUEST_PC, TRACE + 64
.set ACTIVE_TASK, TRACE + 72
.set FAULT_GUEST_PC, TRACE + 80
.set FAULT_DESTINATION_BEFORE, TRACE + 88
.set TASK_A_PC, TRACE + 96
.set TASK_B_PC, TRACE + 104
.set ALL_IRQS, TRACE + 112
.set FAULT_STATE, 0xb000
.set FAULT_RAM, 0xb400
.set DISPATCH_LIMIT, 10000000
.set PAGE_DIRECTORY_SECOND, 0x3008
.set RETRY_ADDRESS, 0x200000
.set PAGE_PRESENT_WRITE_LARGE, 0x83
.set RETRY_PAGE_FLAGS, RETRY_ADDRESS | PAGE_PRESENT_WRITE_LARGE
.set PAGE_FAULT_ERROR_OFFSET, 4 * 8
.set PAGE_FAULT_RIP_OFFSET, PAGE_FAULT_ERROR_OFFSET + 8
.set IRQ_RIP_OFFSET, 8
.set X86_STACK_SLOT_BYTES, 8
.set DEBUG_PORT, 0xe9
.set PIC_MASTER_COMMAND, 0x20
.set PIC_MASTER_DATA, 0x21
.set PIC_SLAVE_COMMAND, 0xa0
.set PIC_SLAVE_DATA, 0xa1
.set PIC_INIT, 0x11
.set PIC_TIMER_VECTOR, 0x20
.set PIC_SLAVE_VECTOR, 0x28
.set PIC_MASTER_CASCADE, 4
.set PIC_SLAVE_CASCADE, 2
.set PIC_8086, 1
.set PIC_TIMER_ONLY_MASK, 0xfe
.set PIC_ALL_MASK, 0xff
.set PIC_EOI, 0x20
.set PIT_COMMAND, 0x43
.set PIT_CHANNEL_ZERO, 0x40
.set PIT_RATE_GENERATOR, 0x34
.set PIT_DIVISOR, 11932
.set IDT_GATE_BYTES, 16
.set IDT_GATE_SHIFT, 4
.set IDT_OFFSET_HIGH_SHIFT, 16
.set IDT_INTERRUPT_GATE, 0x8e
.set CODE_SELECTOR, 8
.set PAGE_FAULT_VECTOR, 14
.set BLOCK_TRAP, 5
.set TASK_B_OFFSET, 0x400

.section .text
.global _start, page_fault, timer_irq, loop_native, trap_native, loop_native_end, completed
.code64
_start:
    cli
    sub $X86_STACK_SLOT_BYTES, %rsp /* nested SysV CALL sites require RSP%16=0 */
    cld
    lea initial_state_a(%rip), %rsi
    mov $STATE_A, %edi
    mov $(STATE_BYTES / 8), %ecx
    rep movsq
    lea initial_state_b(%rip), %rsi
    mov $STATE_B, %edi
    mov $(STATE_BYTES / 8), %ecx
    rep movsq
    xor %eax, %eax
    mov $TASK_A_DATA, %edi
    mov $TASK_RAM_QWORDS, %ecx
    rep stosq
    mov $TRACE, %edi
    mov $TRACE_QWORDS, %ecx
    rep stosq
    movabs $GUEST_LOOP_PC, %rax
    mov %rax, TASK_A_PC
    mov %rax, TASK_B_PC
    lea page_fault(%rip), %rax
    mov $PAGE_FAULT_VECTOR, %ecx
    call install_gate
    lea timer_irq(%rip), %rax
    mov $PIC_TIMER_VECTOR, %ecx
    call install_gate
    lidt idt_pointer(%rip)
    /* Remap and mask both 8259s before enabling only PIT IRQ0. */
    mov $PIC_INIT, %al
    outb %al, $PIC_MASTER_COMMAND
    outb %al, $PIC_SLAVE_COMMAND
    mov $PIC_TIMER_VECTOR, %al
    outb %al, $PIC_MASTER_DATA
    mov $PIC_SLAVE_VECTOR, %al
    outb %al, $PIC_SLAVE_DATA
    mov $PIC_MASTER_CASCADE, %al
    outb %al, $PIC_MASTER_DATA
    mov $PIC_SLAVE_CASCADE, %al
    outb %al, $PIC_SLAVE_DATA
    mov $PIC_8086, %al
    outb %al, $PIC_MASTER_DATA
    outb %al, $PIC_SLAVE_DATA
    mov $PIC_ALL_MASK, %al
    outb %al, $PIC_SLAVE_DATA
    mov $PIT_RATE_GENERATOR, %al
    outb %al, $PIT_COMMAND
    mov $PIT_DIVISOR, %ax
    outb %al, $PIT_CHANNEL_ZERO
    mov %ah, %al
    outb %al, $PIT_CHANNEL_ZERO
    mov $PIC_TIMER_ONLY_MASK, %al
    outb %al, $PIC_MASTER_DATA
    sti
schedule:
    mov ACTIVE_TASK, %r12
    mov $STATE_A, %edi
    mov TASK_A_PC(,%r12,8), %rax
    test %r12, %r12
    jz dispatch
    add $TASK_B_OFFSET, %rdi
dispatch:
    mov %rax, LAST_GUEST_PC
    incq DISPATCHES
    cmpq $DISPATCH_LIMIT, DISPATCHES
    ja failed
    movabs $GUEST_LOOP_PC, %rcx
    cmp %rcx, %rax
    je run_loop
    movabs $GUEST_TRAP_PC, %rcx
    cmp %rcx, %rax
    jne failed
    lea trap_native(%rip), %rax
    jmp execute
run_loop:
    lea loop_native(%rip), %rax
execute:
    call *%rax
    mov %rax, TASK_A_PC(,%r12,8)
    cmp $BLOCK_TRAP, %rdx
    jne switch_task
    movq $1, TASK_A_DONE(,%r12,8)
switch_task:
    xorq $1, ACTIVE_TASK
    cmpq $1, TASK_A_DONE
    jne schedule
    cmpq $1, TASK_B_DONE
    jne schedule
    cli
    mov $DEBUG_PORT, %dx
    mov $'O', %al
    outb %al, %dx
    mov $'K', %al
    outb %al, %dx
    mov $10, %al
    outb %al, %dx
completed:
    hlt
    jmp completed
failed:
    cli
    mov $DEBUG_PORT, %dx
    mov $'E', %al
    outb %al, %dx
    jmp completed

/* RAX handler, ECX vector. Only these two explicitly supported vectors exist. */
install_gate:
    shl $IDT_GATE_SHIFT, %ecx
    lea idt(%rip), %rdx
    add %rcx, %rdx
    mov %ax, 0(%rdx)
    movw $CODE_SELECTOR, 2(%rdx)
    movb $0, 4(%rdx)
    movb $IDT_INTERRUPT_GATE, 5(%rdx)
    shr $IDT_OFFSET_HIGH_SHIFT, %rax
    mov %ax, 6(%rdx)
    shr $IDT_OFFSET_HIGH_SHIFT, %rax
    mov %eax, 8(%rdx)
    movl $0, 12(%rdx)
    ret

page_fault:
    push %rax
    push %rcx
    push %rsi
    push %rdi
    incq PAGE_FAULTS
    mov %cr2, %rax
    mov %rax, FAULT_ADDRESS
    mov PAGE_FAULT_ERROR_OFFSET(%rsp), %rax
    mov %rax, FAULT_ERROR
    mov PAGE_FAULT_RIP_OFFSET(%rsp), %rax
    mov %rax, FAULT_RIP
    movabs $GUEST_FAULT_PC, %rax
    mov %rax, FAULT_GUEST_PC
    mov STATE_X3(%rdi), %rax
    mov %rax, FAULT_DESTINATION_BEFORE
    mov %rdi, %rsi
    mov $FAULT_STATE, %edi
    mov $(STATE_BYTES / 8), %ecx
    rep movsq
    mov $TASK_A_DATA, %esi
    mov $FAULT_RAM, %edi
    mov $TASK_RAM_QWORDS, %ecx
    rep movsq
    /* Exactly one unmapped read of the dedicated identity page is permitted.
     * Retrying the unchanged host RIP demonstrates recovery, not ARM MMU entry. */
    cmpq $RETRY_ADDRESS, FAULT_ADDRESS
    jne fault_failed
    cmpq $0, FAULT_ERROR
    jne fault_failed
    movq $RETRY_PAGE_FLAGS, PAGE_DIRECTORY_SECOND
    mov $RETRY_ADDRESS, %eax
    invlpg (%rax)
    movq $0, (%rax) /* initialize the sole fixture-owned word before retry */
    pop %rdi
    pop %rsi
    pop %rcx
    pop %rax
    add $X86_STACK_SLOT_BYTES, %rsp
    iretq
fault_failed:
    jmp failed

timer_irq:
    push %rax
    mov IRQ_RIP_OFFSET(%rsp), %rax
    incq ALL_IRQS
    cmp $loop_native, %rax
    jb irq_acknowledge
    cmp $loop_native_end, %rax
    jae irq_acknowledge
    mov %rax, IRQ_RIP
    incq TIMER_TICKS
irq_acknowledge:
    mov $PIC_EOI, %al
    outb %al, $PIC_MASTER_COMMAND
    pop %rax
    iretq

.balign 16
loop_native:
.incbin "LOOP_NATIVE_PATH"
loop_native_end:
.balign 16
trap_native:
.incbin "TRAP_NATIVE_PATH"
.balign 16
initial_state_a:
.incbin "STATE_A_PATH"
initial_state_b:
.incbin "STATE_B_PATH"
.balign 16
idt:
.zero (PIC_TIMER_VECTOR + 1) * IDT_GATE_BYTES
idt_end:
idt_pointer:
.word idt_end - idt - 1
.quad idt
