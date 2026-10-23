// Intel SDM3A ch6 / AMD APM2 ch8: exception gates and CPU error-code frames.
// Only CPU exceptions 0..31 are installed. IF remains clear throughout.
.code32
.balign 4
.global stela_ap_stubs32
stela_ap_stubs32:
.set stela_ap_vector, 0
.rept {faults}
1:
.if (({error_mask} >> stela_ap_vector) & 1) == 0
    pushl $0
.endif
    .byte 0x6a, stela_ap_vector
    jmp stela_ap_fault32
    .fill {stub_bytes} - (. - 1b), 1, 0x90
.set stela_ap_vector, stela_ap_vector + 1
.endr
stela_ap_fault32:
    cli
    xor %eax, %eax
    mov ${fault_writing}, %edx
    lock cmpxchgl %edx, (stela_ap_fault_record - stela_ap_start)(%ebp)
    jne stela_ap_fault32_halt
    mov (%esp), %eax
    mov %eax, (stela_ap_fault_record - stela_ap_start + 4)(%ebp)
    movl $32, (stela_ap_fault_record - stela_ap_start + 8)(%ebp)
    mov 4(%esp), %eax
    mov %eax, (stela_ap_fault_record - stela_ap_start + 16)(%ebp)
    mov 8(%esp), %eax
    mov %eax, (stela_ap_fault_record - stela_ap_start + 24)(%ebp)
    mov %cr2, %eax
    mov %eax, (stela_ap_fault_record - stela_ap_start + 32)(%ebp)
    // The copied image initialized upper halves to zero. Locked publication
    // drains preceding stores even while this offline AP has caching disabled;
    // the BSP uses an actual Acquire load of the same aligned physical word.
    mov ${fault_ready}, %eax
    xchgl %eax, (stela_ap_fault_record - stela_ap_start)(%ebp)
stela_ap_fault32_halt:
    cli
    hlt
    jmp stela_ap_fault32_halt

.code64
.balign 4
.global stela_ap_stubs64
stela_ap_stubs64:
.set stela_ap_vector, 0
.rept {faults}
1:
.if (({error_mask} >> stela_ap_vector) & 1) == 0
    pushq $0
.endif
    .byte 0x6a, stela_ap_vector
    jmp stela_ap_fault64
    .fill {stub_bytes} - (. - 1b), 1, 0x90
.set stela_ap_vector, stela_ap_vector + 1
.endr
stela_ap_fault64:
    cli
    // The executable identity page is read-only. Only its loader-owned
    // writable physmap alias can receive the retained failure record.
    mov stela_ap_fault_alias(%rip), %rdi
    xor %eax, %eax
    mov ${fault_writing}, %edx
    lock cmpxchgl %edx, (%rdi)
    jne stela_ap_fault64_halt
    mov (%rsp), %eax
    mov %eax, 4(%rdi)
    movl $64, 8(%rdi)
    mov 8(%rsp), %rax
    mov %rax, 16(%rdi)
    mov 16(%rsp), %rax
    mov %rax, 24(%rdi)
    mov %cr2, %rax
    mov %rax, 32(%rdi)
    mov ${fault_ready}, %eax
    xchgl %eax, (%rdi)
stela_ap_fault64_halt:
    cli
    hlt
    jmp stela_ap_fault64_halt

.balign 8
.global stela_ap_fault_record
stela_ap_fault_record: .zero {fault_record_bytes}
.global stela_ap_fault_alias
stela_ap_fault_alias: .quad 0
.global stela_ap_early_stack
stela_ap_early_stack: .quad 0
.global stela_ap_idtr32
stela_ap_idtr32: .word ({faults} * 8 - 1)
.long 0
.global stela_ap_idtr64
stela_ap_idtr64: .word ({faults} * 16 - 1)
.quad 0
.balign 8
.global stela_ap_idt32
stela_ap_idt32: .zero ({faults} * 8)
.global stela_ap_idt64
stela_ap_idt64: .zero ({faults} * 16)
