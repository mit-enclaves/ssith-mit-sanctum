//
// Created by Jamey Hicks on 6/11/20.
//

#include "gtest/gtest.h"
#include "randombytes.h"
#include <stdio.h>
#include <string.h>
#include <string>

extern "C" {
#include "pam-enclave.h"
void sm_exit_enclave() {
}

}
namespace pam_enclave {

// The fixture for testing class Foo.
    class PamEnclaveTest : public ::testing::Test {
    protected:
        // You can remove any or all of the following functions if their bodies would
        // be empty.
        uint8_t key[crypto_secretbox_KEYBYTES];

        PamEnclaveTest() {
            // You can do set-up work for each test here.
            crypto_secretbox_keygen(key);
            memcpy(pam_enclave_secret_key, key, sizeof(pam_enclave_secret_key));
        }

        ~PamEnclaveTest() override {
            // You can do clean-up work that doesn't throw exceptions here.
        }

        // If the constructor and destructor are not enough for setting up
        // and cleaning up each test, you can define the following methods:

        void SetUp() override {
            // Code here will be called immediately after the constructor (right
            // before each test).
        }

        void TearDown() override {
            // Code here will be called immediately after each test (right
            // before the destructor).
        }

        // Class members declared here can be used by all tests in the test suite
        // for Foo.

        void dumphex(const char *label, const uint8_t *data, int len) {
            printf("%s: ", label);
            for (int i = 0; i < len; i++) {
                printf("%02x", data[i]);
            }
            printf("\n");
        }
    };

// Tests that the Foo::Bar() method does Abc.
    TEST_F(PamEnclaveTest, EncryptDbWorks) {
        struct auth_db *db = (struct auth_db *) calloc(1, sizeof(struct auth_db));
        randombytes((uint8_t *) db, sizeof(*db));
        struct enclave_params *params = (struct enclave_params *) calloc(1, sizeof(struct enclave_params));
        int result = encrypt_db(db, params);
        EXPECT_EQ(result, 0);
    }

    TEST_F(PamEnclaveTest, EncryptDecryptWorks) {
        size_t mlen = 132;
        size_t clen = 132 + crypto_secretbox_macbytes();
        uint8_t nonce[crypto_secretbox_NONCEBYTES];
        randombytes(nonce, sizeof(nonce));

        uint8_t *m = new uint8_t[mlen];
        randombytes(m, mlen);
        uint8_t *c = new uint8_t[clen];
        uint8_t *new_m = new uint8_t[mlen];

        EXPECT_EQ(crypto_secretbox_easy(c, m, mlen, nonce, key), 0);
        EXPECT_EQ(crypto_secretbox_open_easy(new_m, c, clen, nonce, key), 0);
        EXPECT_EQ(memcmp(m, new_m, mlen), 0);
    }

    TEST_F(PamEnclaveTest, EncryptDecryptDBWorks) {
        struct auth_db *db = (struct auth_db *) calloc(1, sizeof(struct auth_db));
        struct auth_db *db2 = (struct auth_db *) calloc(1, sizeof(struct auth_db));
        randombytes((uint8_t *) db, sizeof(*db));

        struct enclave_params *params = (struct enclave_params *) calloc(1, sizeof(struct enclave_params));
        int encrypt_result = encrypt_db(db, params);
        EXPECT_EQ(encrypt_result, 0);
        EXPECT_EQ(params->clen, sizeof(struct auth_db) + crypto_secretbox_macbytes());
        EXPECT_EQ(memcmp(pam_enclave_secret_key, key, sizeof(key)), 0);

        dumphex("authenticator", params->cdb, crypto_secretbox_macbytes());

        int decrypt_result = decrypt_db(db2, params);
        EXPECT_EQ(decrypt_result, 0);
        EXPECT_EQ(memcmp((uint8_t *) db2, (uint8_t *) db, sizeof(*db)), 0);

    }

    TEST_F(PamEnclaveTest, MemncmpWorks) {
        EXPECT_EQ(memncmp((uint8_t *) "abc", (uint8_t *) "abc", 3), 0);
        EXPECT_EQ(memncmp((uint8_t *) "abc", (uint8_t *) "def", 3), 1);
        EXPECT_EQ(memncmp((uint8_t *) "abd", (uint8_t *) "abc", 3), 1);
    }

    TEST_F(PamEnclaveTest, SingleEntryAuthWorks) {
        struct auth_db *db = (struct auth_db *) calloc(1, sizeof(struct auth_db));
        struct enclave_params *params = (struct enclave_params *) calloc(1, sizeof(struct enclave_params));

        strcpy((char *) db->entries[0].username, "ubuntu");
        strcpy((char *) params->username, "ubuntu");
        strcpy((char *) params->password, "fred");
        crypto_generichash(db->entries[0].hash, sizeof(db->entries[0].hash),
                           params->password, sizeof(params->password), NULL, 0);

        int encrypt_result = encrypt_db(db, params);
        EXPECT_EQ(encrypt_result, 0);

        enclave_main(params);
        EXPECT_EQ(std::string((char *) params->response), "authenticated");
    }

    TEST_F(PamEnclaveTest, MultiEntryAuthWorks) {
        struct auth_db *db = (struct auth_db *) calloc(1, sizeof(struct auth_db));
        struct enclave_params *params = (struct enclave_params *) calloc(1, sizeof(struct enclave_params));

        struct userdata {
            uint8_t username[32];
            uint8_t password[32];
        } entries[] = {
                {"ubuntu", "fred"},
                {"root",   "rootme"},
                {"bob",    "secret password"},
                {"alice",  "better password"}
        };
        for (int i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
            strcpy((char *) db->entries[i].username, (char *) entries[i].username);
            if (i == 2) {
                strcpy((char *) params->username, (char *) entries[i].username);
                strcpy((char *) params->password, (char *) entries[i].password);
            }
            uint8_t password[32];
            memset(password, 0, sizeof(password));
            strcpy((char *)password, (char *) entries[i].password);
            crypto_generichash(db->entries[i].hash, sizeof(db->entries[i].hash),
                               password, sizeof(password), NULL, 0);
        }

        int encrypt_result = encrypt_db(db, params);
        EXPECT_EQ(encrypt_result, 0);

        enclave_main(params);
        EXPECT_EQ(std::string((char *) params->response), "authenticated");
    }

    TEST_F(PamEnclaveTest, MultiEntryNoauthWorks) {
        struct auth_db *db = (struct auth_db *) calloc(1, sizeof(struct auth_db));
        struct enclave_params *params = (struct enclave_params *) calloc(1, sizeof(struct enclave_params));

        struct userdata {
            uint8_t username[32];
            uint8_t password[32];
        } entries[] = {
                {"ubuntu", "fred"},
                {"root",   "rootme"},
                {"bob",    "secret password"},
                {"alice",  "better password"}
        };
        for (int i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
            strcpy((char *) db->entries[i].username, (char *) entries[i].username);
            crypto_generichash(db->entries[i].hash, sizeof(db->entries[i].hash),
                               entries[i].password, sizeof(entries[i].password), NULL, 0);
        }

        int encrypt_result = encrypt_db(db, params);
        EXPECT_EQ(encrypt_result, 0);

        strcpy((char *) params->username, "carol");
        strcpy((char *) params->password, (char *) entries[0].password);

        enclave_main(params);
        EXPECT_EQ(std::string((char *) params->response), "failed");

        strcpy((char *) params->username, (char *) entries[0].username);
        strcpy((char *) params->password, "mismatching password");

        enclave_main(params);
        EXPECT_EQ(std::string((char *) params->response), "failed");

    }

}  // namespace

