// Own BSD write stub for native Darwin syscall-bridge integration tests.
// Input X0 is a guest descriptor capability, X1 a private guest buffer, X2 its
// length. The bridge supplies X0/X1 and carry status; B.CC must observe that flag.
// X9 distinguishes the translated success/error paths. No host fd is embedded.
.text
.p2align 2
.globl _darwin_write_fixture
_darwin_write_fixture:
    mov x16, #4
    svc #0x80
    b.cc Lsuccess
    mov x9, #0xbad
    ret
Lsuccess:
    mov x9, #0x600d
    ret

.p2align 2
.globl _darwin_unsupported_fixture
_darwin_unsupported_fixture:
    mov x16, #0x7fff
    svc #0x80
    ret
