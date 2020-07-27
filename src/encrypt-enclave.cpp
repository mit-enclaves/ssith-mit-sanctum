//
// Created by Jamey Hicks on 6/8/20.
//

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
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

const struct option long_options[] = {
    { "key", required_argument, 0, 'k' },
    { "measurement", required_argument, 0, 'm' },
    { "newkey", no_argument, 0, 'n' },
    { "output", required_argument, 0, 'o' },
    { 0,         0,                 0, 0 }
};

void usage(const char *name)
{
    fprintf(stderr, "Usage: %s [options] enclavefilename [cipherfilename]\r\n", name);
    for (const struct option *option = long_options; option->name != 0; option++) {
        if (option->has_arg == required_argument) {
            fprintf(stderr, "        --%s arg\r\n", option->name);
        } else if (option->has_arg == optional_argument) {
            fprintf(stderr, "        --%s [arg]\r\n", option->name);
        } else {
            fprintf(stderr, "        --%s\r\n", option->name);
        }
    }
}

int main(int argc, char * const *argv)
{

    const char *cipher_filename = 0;
    const char *key_filename = 0;
    const char *measurement_filename = 0;
    bool newkey = false;

    while (1) {
        int option_index = optind ? optind : 1;
        char c = getopt_long(argc, argv, "k:o:n",
                             long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'k':
            key_filename = optarg;
            break;
        case 'm':
            measurement_filename = optarg;
            break;
        case 'n':
            newkey = true;
            break;
        case 'o':
            cipher_filename = optarg;
            break;
        default:
            fprintf(stderr, "Unknown argument: %d index %d\n", c, option_index);
            usage(argv[0]);
            return -1;
        }
    }

    if (!cipher_filename) {
	cipher_filename = argv[optind+1];
    }
    fprintf(stderr, "optind=%d filename=%s key_filename=%s\n", optind, argv[optind], key_filename);
    const char *filename = argv[optind];
    if (!filename || !cipher_filename) {
        usage(argv[0]);
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

    uint8_t key[crypto_stream_aes128ctr_KEYBYTES] = {0};
    if (newkey) {
        randombytes(key, sizeof(key));
        int key_fd = open(key_filename, O_RDWR|O_CREAT|O_TRUNC, 0600);
        if (write(key_fd, key, sizeof(key)) < 0) {
            fprintf(stderr, "Error writing key: %s\n", strerror(errno));
        }
        close(key_fd);
    } else {
        int key_fd = open(key_filename, O_RDONLY);
        if (read(key_fd, key, sizeof(key)) < 0) {
            fprintf(stderr, "Error reading key from %s: %s\n", key_filename, strerror(errno));
        }
        if ((key[0] == 0x7f) && (strncmp((const char *)key + 1, "ELF", 3) == 0)) {
            lseek(key_fd, 0x160, SEEK_SET);
            if (read(key_fd, key, sizeof(key)) < 0) {
                fprintf(stderr, "Error reading key: %s\n", strerror(errno));
            }
        }
        close(key_fd);
    }
    printf("uint8_t key[] = { ");
    for (size_t i = 0; i < sizeof(key); i++) {
        if (i)
            printf(", ");
        printf("0x%0x", key[i]);
    }
    printf(" };\n");

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

    uint8_t measurement[64] = { 0 };
    if (measurement_filename) {
	FILE *mfile = fopen(measurement_filename, "r");
	if (!mfile) {
	    fprintf(stderr, "Error opening measurement %s: %s\n", measurement_filename, strerror(errno));
	    return -errno;
	}
	char buffer[1024];
	char *line = fgets(buffer, sizeof(buffer), mfile);
	for (size_t i = 0; i < sizeof(measurement); i++) {
	    char *endptr = 0;
	    uint32_t value = strtoul(line, &endptr, 0);
	    measurement[i] = value;
	    if (endptr) {
		line = endptr;
		if (line[0] == ',')
		    line++;
		if (line[0] == ' ')
		    line++;
	    } else {
		break;
	    }
	}
	fclose(mfile);
	fprintf(stderr, "measurement[] = { ");
	for (size_t i = 0; i < sizeof(measurement); i++) {
	    fprintf(stderr, "%s0x%02x", (i ? ", " : ""), measurement[i]);
	}
	fprintf(stderr, "}\n");
    }

    memcpy(ciphertext + num_blocks * 4096 + num_blocks * crypto_stream_aes128ctr_NONCEBYTES, measurement, sizeof(measurement));

    int bytes_to_write = cipherlen;
    int total_bytes_written = 0;
    fd = open(cipher_filename, O_RDWR|O_CREAT|O_TRUNC, 0666);
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
