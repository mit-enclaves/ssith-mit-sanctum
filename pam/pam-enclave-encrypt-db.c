//
// Created by Jamey Hicks on 6/11/20.
//

#include <string.h>
#include "sodium/randombytes.h"

//#include "security_monitor/api/api_enclave.h"

#include "pam-enclave.h"

int encrypt_db(const struct auth_db *db, struct enclave_params *params) {
    randombytes(params->nonce, crypto_secretbox_noncebytes());

    int clen = sizeof(struct auth_db) + crypto_secretbox_macbytes();
    params->clen = clen;

    int result = crypto_secretbox_easy(params->cdb,
                                       (uint8_t *)db, sizeof(*db),
                                       params->nonce,
                                       pam_enclave_secret_key);
    return result;
}
