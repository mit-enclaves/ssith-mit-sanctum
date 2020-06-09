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
    for (int i = 0; i < sizeof(key); i++) {
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

    return 0;
}