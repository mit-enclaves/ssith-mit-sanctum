.section ".text.call_enclave_entry","ax"

la ra, enclave_entry
jr ra

# enclave_entry should not return!
.hang:
  j .hang
