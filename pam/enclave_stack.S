#include <parameters.h>

.section ".data.stack"
.align PAGE_SHIFT
.globl enclave_stack_base, enclave_stack_ptr
enclave_stack_base:
  .skip (STACK_SIZE)
enclave_stack_ptr:
