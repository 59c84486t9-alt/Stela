// Original Stela research inputs. All are pure SysV functions of RDI/RSI.
.text
.globl _rosetta_mov32
_rosetta_mov32:
    movl $42, %eax
    ret
.globl _rosetta_mov64
_rosetta_mov64:
    movabsq $0x123456789abcdef0, %rax
    ret
.globl _rosetta_argument32
_rosetta_argument32:
    movl %edi, %eax
    ret
.globl _rosetta_add64
_rosetta_add64:
    movq %rdi, %rax
    addq %rsi, %rax
    ret
.globl _rosetta_zero_branch
_rosetta_zero_branch:
    movl $1, %eax
    testq %rdi, %rdi
    je Lzero_return
    movl $2, %eax
Lzero_return:
    ret
.globl _rosetta_unsigned_less
_rosetta_unsigned_less:
    xorl %eax, %eax
    cmpq %rsi, %rdi
    setb %al
    ret
.globl _rosetta_signed_less
_rosetta_signed_less:
    xorl %eax, %eax
    cmpq %rsi, %rdi
    setl %al
    ret
.globl _rosetta_signed_overflow
_rosetta_signed_overflow:
    xorl %eax, %eax
    addq %rsi, %rdi
    seto %al
    ret
.globl _rosetta_add_carry
_rosetta_add_carry:
    movq %rdi, %rax
    addq %rsi, %rax
    adcq $0, %rax
    ret
.globl _rosetta_variable_shift
_rosetta_variable_shift:
    movq %rdi, %rax
    movl %esi, %ecx
    shlq %cl, %rax
    ret
.globl _rosetta_parity
_rosetta_parity:
    xorl %eax, %eax
    testb %dil, %dil
    setp %al
    ret
.globl _rosetta_sum_loop
_rosetta_sum_loop:
    xorl %eax, %eax
    xorl %ecx, %ecx
    testl %edi, %edi
    je Lsum_return
Lsum_loop:
    addl %ecx, %eax
    incl %ecx
    cmpl %edi, %ecx
    jb Lsum_loop
Lsum_return:
    ret
