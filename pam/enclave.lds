OUTPUT_ARCH( "riscv" )
ENTRY( enclave_section_entry )

SECTIONS
{
  .text : {
    PROVIDE( enclave_section_entry = . );
    KEEP( *(.text.call_enclave_entry) )
    *(.text.*)
    *(.text)
  }

  .rodata ALIGN(64) : {
    *(.rodata)  /* read-only data */
    *(.rodata.*)
  }

  .data ALIGN(64)  : {
    KEEP(*(.data.stack))
    *(.data.*)
    *(.data)  /* initialized data */
  }

  .bss ALIGN(64)  : {
    *(.bss)   /* uninitialized data */
    *(.bss.*)
  }
}
