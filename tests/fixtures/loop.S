// Original ARM64 leaf with backward control flow, flags and register MOV.
.text
.global _loop
_loop:
    movz x0, #7
    movz x1, #0
.Lrepeat:
    add x1, x1, #3
    subs x0, x0, #1
    b.ne .Lrepeat
    mov x0, x1
    ret
