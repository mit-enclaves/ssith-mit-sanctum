//
// Created by Jamey Hicks on 6/8/20.
//

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sodium/randombytes.h"
#include "sodium/crypto_stream_aes128ctr.h"
#include "sodium/crypto_hash_sha512.h"

const int measurement_BYTES = 64;

int main(int argc, const char **argv)
{
    const char *filename = argv[1];
    const char *cipherfilename = argv[2];
    if (!filename || !cipherfilename) {
        fprintf(stderr, "Usage: %s plaintext ciphertext", argv[0]);
        return -1;
    }
    struct stat statbuf;
    int result = lstat(filename, &statbuf);
    if (result != 0) {
        fprintf(stderr, "Error: filename %s %s\n", filename, strerror(errno));
    }
    off_t filesize = statbuf.st_size;
    int num_blocks = (filesize + 4095) / 4096;
    int plaintextlen = 4096 * num_blocks;
    uint8_t *plaintext = (uint8_t *) calloc(1, plaintextlen);
    int cipherlen = plaintextlen + num_blocks * crypto_stream_aes128ctr_NONCEBYTES + measurement_BYTES;
    // round up to page size
    cipherlen = (cipherlen + 4095) / 4096 * 4096;
    uint8_t *ciphertext = (uint8_t *) calloc(1, cipherlen);

    printf("plaintext %d blocks %d/%x bytes ciphertext %d blocks %d/%x bytes\n", num_blocks, plaintextlen, plaintextlen, cipherlen / 4096, cipherlen, cipherlen);

    uint8_t key[crypto_stream_aes128ctr_KEYBYTES] = { 0xfc, 0x8e, 0x3f, 0x47, 0xd2, 0x27, 0x58, 0xfc, 0xe7, 0x30, 0x82, 0x6a, 0xb, 0xde, 0x92, 0xaf};
    //randombytes(key, sizeof(key));
    printf("uint8_t key[] = { ");
    for (size_t i = 0; i < sizeof(key); i++) {
        if (i)
            printf(", ");
        printf("0x%0x", key[i]);
    }
    printf("};\n");

    int bytes_to_read = statbuf.st_size;
    int total_bytes_read = 0;
    int fd = open(filename, O_RDONLY);
    while (bytes_to_read > 0) {
        int bytes_read = read(fd, plaintext + total_bytes_read, bytes_to_read);
        if (bytes_read < 0) {
            return -1;
        }
        total_bytes_read += bytes_read;
        bytes_to_read -= bytes_read;
    }
    close(fd);

#if COMPUTE_MEASUREMENT
    crypto_hash_sha512_state hash_context;
    uintptr_t ev_base = 0;
    uintptr_t ev_mask = ~0x00FFFFFF;
    uint64_t num_mailboxes = 1;
    bool    enclave_debug = 0;

    crypto_hash_sha512_init(&hash_context);
    crypto_hash_sha512_update(&hash_context, &ev_base, sizeof(ev_base));
    crypto_hash_sha512_update(&hash_context, &ev_mask, sizeof(ev_mask));
    crypto_hash_sha512_update(&hash_context, &num_mailboxes, sizeof(num_mailboxes));
    crypto_hash_sha512_update(&hash_context, &enclave_debug, sizeof(enclave_debug));

    crypto_hash_sha512_update(&hash_context, enclave_handler_start, HANDLER_LEN);

    // load page table (3)
    crypto_hash_sha512_update(&hash_context, &virtual_addr, sizeof(virtual_addr));
    crypto_hash_sha512_update(&hash_context, &level, sizeof(level));
    crypto_hash_sha512_update(&hash_context, &acl, sizeof(acl));
    // load page table (2)
    crypto_hash_sha512_update(&hash_context, &virtual_addr, sizeof(virtual_addr));
    crypto_hash_sha512_update(&hash_context, &level, sizeof(level));
    crypto_hash_sha512_update(&hash_context, &acl, sizeof(acl));
    // load page table (1)
    crypto_hash_sha512_update(&hash_context, &virtual_addr, sizeof(virtual_addr));
    crypto_hash_sha512_update(&hash_context, &level, sizeof(level));
    crypto_hash_sha512_update(&hash_context, &acl, sizeof(acl));
    // load page table (0) for stack
    crypto_hash_sha512_update(&hash_context, &virtual_addr, sizeof(virtual_addr));
    crypto_hash_sha512_update(&hash_context, &level, sizeof(level));
    crypto_hash_sha512_update(&hash_context, &acl, sizeof(acl));
#endif

    for (int i = 0; i < num_blocks; i++) {
        uint8_t nonce[crypto_stream_aes128ctr_NONCEBYTES];
        randombytes(nonce, crypto_stream_aes128ctr_NONCEBYTES);
        // copy nonce to output
        memcpy(ciphertext + num_blocks * 4096 + i * crypto_stream_aes128ctr_NONCEBYTES, nonce, crypto_stream_aes128ctr_NONCEBYTES);
        // encrypt a block
        crypto_stream_aes128ctr_xor(ciphertext + i * 4096, plaintext + i * 4096, 4096, nonce, key);

#if COMPUTE_MEASUREMENT
	// update the measurement with this page
	crypto_hash_sha512_update(&hash_context, &virtual_addr, sizeof(virtual_addr));
	crypto_hash_sha512_update(&hash_context, &acl, sizeof(acl));
	crypto_hash_sha512_update(&hash_context, (const void *) phys_addr, PAGE_SIZE);
#endif

    }

#if COMPUTE_MEASUREMENT
  // thread_load
  crypto_hash_sha512_update(&hash_context, &entry_pc, sizeof(entry_pc));
  crypto_hash_sha512_update(&hash_context, &entry_stack, sizeof(entry_stack));
  crypto_hash_sha512_update(&hash_context, &fault_pc, sizeof(fault_pc));
  crypto_hash_sha512_update(&hash_context, &fault_stack, sizeof(fault_stack));
  crypto_hash_sha512_update(&hash_context, &timer_limit, sizeof(timer_limit));
#endif

    // magic value, should come from a file
    uint8_t measurement[] = {
0x00000022, 0x000000de, 0x000000bc, 0x000000e7, 0x00000076, 0x00000011, 0x0000005e, 0x000000fa, 0x0000006d, 0x000000de, 0x0000000b, 0x000000e2, 0x000000ce, 0x000000f0, 0x0000003f, 0x00000012, 0x00000011, 0x00000002, 0x00000018, 0x0000005c, 0x000000b1, 0x000000ca, 0x000000bd, 0x00000047, 0x00000071, 0x000000d1, 0x0000005b, 0x0000002c, 0x000000af, 0x000000c6, 0x00000088, 0x00000005, 0x000000c5, 0x000000a7, 0x000000e7, 0x00000053, 0x000000ac, 0x000000d3, 0x000000f6, 0x0000005d, 0x00000034, 0x00000079, 0x00000051, 0x000000c2, 0x00000054, 0x000000e3, 0x00000064, 0x00000088, 0x000000b3, 0x0000000a, 0x000000fa, 0x00000078, 0x00000022, 0x00000016, 0x0000006c, 0x000000a4, 0x000000f1, 0x000000a8, 0x00000004, 0x000000c9, 0x000000de, 0x00000064, 0x00000053, 0x000000d1
    };
    memcpy(ciphertext + num_blocks * 4096 + num_blocks * crypto_stream_aes128ctr_NONCEBYTES, measurement, sizeof(measurement));

    int bytes_to_write = cipherlen;
    int total_bytes_written = 0;
    fd = open(cipherfilename, O_RDWR|O_CREAT|O_TRUNC, 0666);
    while (bytes_to_write > 0) {
        int bytes_written = write(fd, ciphertext + total_bytes_written, bytes_to_write);
        if (bytes_written < 0) {
            return -1;
        }
        total_bytes_written += bytes_written;
        bytes_to_write -= bytes_written;
    }
    close(fd);

    // AES KEY goes at 80000160
    fd = open("aeskey.bin", O_RDWR|O_CREAT, 0666);
    if ((total_bytes_written = write(fd, key, crypto_stream_aes128ctr_KEYBYTES)) != crypto_stream_aes128ctr_KEYBYTES) {
      fprintf(stderr, "Failed to write %d bytes (wrote %d) to aeskey.bin: %s\n", crypto_stream_aes128ctr_KEYBYTES, total_bytes_written, strerror(errno));
    }
    close(fd);
    fprintf(stderr, "Wrote aeskey.bin (%d bytes)\n", crypto_stream_aes128ctr_KEYBYTES);

    return 0;
}
