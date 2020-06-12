//
// Created by Jamey Hicks on 6/11/20.
//

#ifndef PAM_ENCLAVE_H
#define PAM_ENCLAVE_H

#include <stdint.h>
#include "sodium/crypto_secretbox.h"
#include "sodium/crypto_generichash.h"

struct db_entry {
    uint8_t username[32];
    uint8_t hash[crypto_generichash_BYTES];
};

struct auth_db {
    uint32_t num_entries;
    struct db_entry entries[32];
};

struct enclave_params {
    uint8_t username[32];
    uint8_t password[32];
    uint8_t response[32];
    int clen;
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
    uint8_t cdb[sizeof(struct auth_db) + crypto_secretbox_MACBYTES + crypto_secretbox_ZEROBYTES];
};

extern uint8_t pam_enclave_secret_key[crypto_secretbox_KEYBYTES];

int memncmp(uint8_t *a, uint8_t *b, int len);
int encrypt_db(const struct auth_db *db, struct enclave_params *params);
int decrypt_db(struct auth_db *db, const struct enclave_params *params);

void enclave_main(struct enclave_params *params);
void sm_exit_enclave();
#endif //PAM_ENCLAVE_H
