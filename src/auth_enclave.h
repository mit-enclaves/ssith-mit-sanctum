//
// Created by Jamey Hicks on 5/21/20.
//

#ifndef LIBSODIUM_AUTH_ENCLAVE_H
#define LIBSODIUM_AUTH_ENCLAVE_H

#include "crypto_secretbox.h"

typedef struct AuthEnclaveArgs {
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
    int clen;
    uint8_t c[];
} AuthEnclaveArgs;

int run_auth_enclave(AuthEnclaveArgs *args);
#endif //LIBSODIUM_AUTH_ENCLAVE_H
