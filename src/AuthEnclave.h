//
// Created by Jamey Hicks on 5/21/20.
//

#pragma once

#include <string>

#include "sodium/crypto_secretbox.h"

namespace enclaves {
    class AuthEnclave {
        uint8_t m_Key[crypto_secretbox_KEYBYTES];
        uint8_t *m_DB;
    public:

        AuthEnclave() noexcept ;

        void SetKey(uint8_t *key);

        int setDatabase(const uint8_t *c, int clen, const uint8_t *nonce);

        int getDatabase(uint8_t *c, int clen, uint8_t *nonce);

        int Bar(std::string in, std::string o);

        virtual ~AuthEnclave();
    };
}

