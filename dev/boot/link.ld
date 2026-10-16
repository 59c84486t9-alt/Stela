OUTPUT_FORMAT(elf64-x86-64)
ENTRY(stela_start32)
SECTIONS {
  . = 0x100000;
  __image_start = .;
  .text : ALIGN(4096) {
    KEEP(*(.multiboot))
    *(.text.boot)
    *(.text .text.*)
  }
  __text_end = .;
  . = ALIGN(4096);
  __rodata_start = .;
  .rodata : { *(.rodata .rodata.*) }
  __rodata_end = .;
  . = ALIGN(4096);
  __data_start = .;
  .data : { *(.data .data.*) *(.got .got.*) }
  __load_end = .;
  . = ALIGN(4096);
  .bss (NOLOAD) : {
    *(.bss.boot)
    *(.bss .bss.*)
    *(COMMON)
  }
  . = ALIGN(4096);
  __image_end = .;
  /DISCARD/ : { *(.eh_frame .eh_frame.*) *(.comment) }
  ASSERT(__image_end < 0x10000000, "boot image/heap must fit reserved lower identity window")
  ASSERT(SIZEOF(.text) > 0, "missing real runtime code")
}
