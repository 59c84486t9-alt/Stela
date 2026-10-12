// Original ARM64 leaf function used by the native x86/QEMU smoke test.
.text
.global _leaf
_leaf:
    movz x0, #40
    add x0, x0, #2
    ret
