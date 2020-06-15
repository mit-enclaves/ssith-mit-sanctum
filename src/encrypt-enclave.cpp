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
    uint8_t *plaintext = (uint8_t *) calloc(1, num_blocks * 4096);
    int cipherlen = num_blocks * 4096 + num_blocks * crypto_stream_aes128ctr_NONCEBYTES + measurement_BYTES;
    // round up to page size
    cipherlen = (cipherlen + 4095 - 1) / 4096 * 4096;
    uint8_t *ciphertext = (uint8_t *) calloc(1, cipherlen);
    uint8_t key[crypto_stream_aes128ctr_KEYBYTES];

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

    randombytes(key, sizeof(key));
    printf("uint8_t key[] = { ");
    for (size_t i = 0; i < sizeof(key); i++) {
        if (i)
            printf(", ");
        printf("0x%0x", key[i]);
    }
    printf("};\n");
    for (int i = 0; i < num_blocks; i++) {
        uint8_t nonce[crypto_stream_aes128ctr_NONCEBYTES];
        randombytes(nonce, crypto_stream_aes128ctr_NONCEBYTES);
        // copy nonce to output
        memcpy(ciphertext + num_blocks * 4096 + i * crypto_stream_aes128ctr_NONCEBYTES, nonce, crypto_stream_aes128ctr_NONCEBYTES);
        // encrypt a block
        crypto_stream_aes128ctr_xor(ciphertext + i * 4096, plaintext + i * 4096, 4096, nonce, key);
    }
    // magic value, should come from a file
    uint8_t measurement[] = {
      0xf2, 0xeb, 0x03, 0x9f, 0x84, 0x35, 0xe3, 0xde, 0x2c, 0x13, 0x99, 0xa8, 0x6f, 0xf5, 0xc3, 0xa9,
      0x29, 0x2e, 0xdc, 0xad, 0x48, 0x74, 0x84, 0xc4, 0x73, 0x5c, 0x57, 0x41, 0x3b, 0x2b, 0x30, 0xca,
      0x9b, 0x3b, 0xac, 0x4e, 0x6f, 0x96, 0x8a, 0x41, 0xc1, 0x3f, 0x20, 0x3c, 0x10, 0x33, 0x54, 0xba,
      0xda, 0x32, 0x1c, 0x57, 0x72, 0x1b, 0xad, 0xcc, 0xba, 0x87, 0xa1, 0x95, 0x2b, 0x2b, 0xcc, 0x50
    };
    memcpy(ciphertext + num_blocks * 4096 + num_blocks * crypto_stream_aes128ctr_NONCEBYTES, measurement, sizeof(measurement));

    int bytes_to_write = cipherlen;
    int total_bytes_written = 0;
    fd = open(cipherfilename, O_RDWR|O_CREAT, 0666);
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
