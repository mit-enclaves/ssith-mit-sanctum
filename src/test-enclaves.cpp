//
// Created by Jamey Hicks on 5/21/20.
//

#include "AuthEnclave.h"
#include "sodium/randombytes.h"

#include "gtest/gtest.h"

namespace enclaves {

// The fixture for testing class Foo.
    class FooTest : public ::testing::Test {
    protected:
        // You can remove any or all of the following functions if their bodies would
        // be empty.
        uint8_t key[crypto_secretbox_KEYBYTES];

        FooTest() {
            // You can do set-up work for each test here.
            crypto_secretbox_keygen(key);
        }

        ~FooTest() override {
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
    };

// Tests that the Foo::Bar() method does Abc.
    TEST_F(FooTest, SetDBWorks) {
        AuthEnclave ae;
        ae.SetKey(key);
        size_t mlen = 247;
        size_t clen = 247 + crypto_secretbox_macbytes();
        uint8_t nonce[crypto_secretbox_NONCEBYTES];
        randombytes(nonce, sizeof(nonce));
        uint8_t *m = new uint8_t[mlen];
        uint8_t *c = new uint8_t[clen];

        crypto_secretbox_easy(c, m, mlen, nonce, key);
        EXPECT_EQ(ae.setDatabase(c, clen, nonce), 0);
    }

    TEST_F(FooTest, GetDbWorks) {

        AuthEnclave ae;
        ae.SetKey(key);
        size_t mlen = 247;
        size_t clen = 247 + crypto_secretbox_macbytes();
        uint8_t nonce[crypto_secretbox_NONCEBYTES];
        uint8_t new_nonce[crypto_secretbox_NONCEBYTES];
        randombytes(nonce, sizeof(nonce));
        uint8_t *m = new uint8_t[mlen];
        uint8_t *c = new uint8_t[clen];
        uint8_t *new_c = new uint8_t [clen];
        uint8_t *new_m = new uint8_t[mlen];

        crypto_secretbox_easy(c, m, mlen, nonce, key);
        EXPECT_EQ(crypto_secretbox_open_easy(new_m, c, clen, nonce, key), 0);

        EXPECT_EQ(ae.setDatabase(c, clen, nonce), 0);

        EXPECT_EQ(ae.getDatabase(new_c, clen, new_nonce), 0);
        EXPECT_NE(memcmp(nonce, new_nonce, sizeof(nonce)), 0);
        EXPECT_EQ(crypto_secretbox_open_easy(new_m, new_c, clen, new_nonce, key), 0);
        EXPECT_EQ(memcmp(m, new_m, mlen), 0);
    }

// Tests that Foo does Xyz.
    TEST_F(FooTest, KeyNonZero) {
        // Exercises the Xyz feature of Foo.
        uint8_t zero[crypto_secretbox_KEYBYTES] = { 0 };
        EXPECT_FALSE(memcmp(key, zero, sizeof(key)) == 0);
    }

}  // namespace

