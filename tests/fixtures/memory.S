// Original scalar memory fixture. Compile with clang --target=arm64-apple-macos.
// Uses dedicated guest RAM at 0x8000 and stack at 0x9000 in the debug VM.
.text
.globl _memory_fixture
_memory_fixture:
    mov x1, #0x8000
    mov x2, #40
    str x2, [x1]
    ldr w0, [x1]
    add x0, x0, #2
    str x0, [x1, #8]
    mov x10, #0x9000
    mov sp, x10
    str x0, [sp, #-16]!
    ldr x3, [sp], #16
    str xzr, [x1, #16]
    strb w3, [x1, #16]
    ldrsb x0, [x1, #16]
    ret
