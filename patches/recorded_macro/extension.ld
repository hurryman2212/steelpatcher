MEMORY
{
  PATCH (rx) : ORIGIN = PATCH_ORIGIN, LENGTH = PATCH_LENGTH
}

SECTIONS
{
  .patch_header ORIGIN(PATCH) :
  {
    KEEP(*(.patch_header))
  } > PATCH

  .text ALIGN(4) :
  {
    *(.text*)
    *(.rodata*)
  } > PATCH

  /DISCARD/ :
  {
    *(.ARM.attributes)
    *(.ARM.exidx*)
    *(.comment)
    *(.data*)
    *(.bss*)
  }
}

ASSERT(ADDR(.text) + SIZEOF(.text) <= ORIGIN(PATCH) + LENGTH(PATCH),
       "patch image exceeds its reviewed code area")
