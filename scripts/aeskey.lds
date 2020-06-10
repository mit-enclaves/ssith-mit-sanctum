
OUTPUT_ARCH( "riscv" )

MEMORY
{
  AESKEY (ax) : ORIGIN = (0x80000160), LENGTH = (0x40)
}

SECTIONS
{
  . = ORIGIN(AESKEY);
  .data : {
    *(.data)
  } > AESKEY =0x0
}
