//
// Created by Jamey Hicks on 6/11/20.
//

#include <string.h>

//#include "security_monitor/api/api_enclave.h"

#include "pam-enclave.h"

int decrypt_db(struct auth_db *db, const struct enclave_params *params) {
    int clen = sizeof(struct auth_db) + crypto_secretbox_macbytes();
    int result = crypto_secretbox_open_easy((uint8_t *) db,
                                            params->cdb, clen,
                                            params->nonce,
                                            pam_enclave_secret_key);
    return result;
}
