//
// Created by Jamey Hicks on 6/11/20.
//

#include <string.h>
#include "sodium/randombytes.h"

//#include "security_monitor/api/api_enclave.h"

#include "pam-enclave.h"

static struct auth_db db;
uint8_t pam_enclave_secret_key[crypto_secretbox_KEYBYTES];

int memncmp(uint8_t *a, uint8_t *b, int len) {
    int mismatch = 0;
    for (int i = 0; i < len; i++) {
        mismatch |= a[i] != b[i];
    }
    return mismatch;
}

void enclave_main(struct enclave_params *params) {
    int opened = decrypt_db(&db, params);
    memset(params->response, 0, sizeof(params->response));
    if (opened != 0) {
        strcpy((char *) params->response, "failed");
        return;
    }

    uint8_t pwhash[crypto_generichash_BYTES];
    crypto_generichash(pwhash, sizeof(pwhash), params->password, sizeof(params->password), NULL, 0);

    int authenticated = 0;
    for (int i = 0; i < sizeof(db.entries) / sizeof(db.entries[0]); i++) {
        int matches = (memncmp(params->username, db.entries[i].username, sizeof(params->username)) == 0)
                      & (memncmp(pwhash, db.entries[i].hash, sizeof(pwhash)) == 0);
        authenticated |= matches;
    }

    if (authenticated == 1) {
        strcpy((char *) params->response, "authenticated");
    } else {
        strcpy((char *) params->response, "failed");
    }
}

void enclave_entry() {
    struct enclave_params *params = (struct enclave_params *) 0xF000000;

    enclave_main(params);
    sm_exit_enclave();
}

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

int decrypt_db(struct auth_db *db, const struct enclave_params *params) {
    int clen = sizeof(struct auth_db) + crypto_secretbox_macbytes();
    int result = crypto_secretbox_open_easy((uint8_t *) db,
                                            params->cdb, clen,
                                            params->nonce,
                                            pam_enclave_secret_key);
    return result;
}