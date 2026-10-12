set pagination off
target remote 127.0.0.1:1234
# ELF is 32-bit because BIOS enters in real mode; payload runs in long mode.
symbol-file .stela/vm/boot.elf
hbreak payload
continue
monitor info registers
monitor xp /8gx 0x1000
# Use stepi / info registers / x to inspect execution. After completed:
# monitor xp /1gx 0x5000
