//
// Created by Jamey Hicks on 5/21/20.
//

#include "sodium/randombytes.h"
#include <assert.h>
#include <string.h>

#include "AuthEnclave.h"
namespace enclaves {

    using namespace std;


    AuthEnclave::AuthEnclave() noexcept : m_Key() {
        memset(m_Key, 0, sizeof(m_Key));
    }

    int enclaves::AuthEnclave::Bar(string i, string o) {
        return 0;
    }

    AuthEnclave::~AuthEnclave() {
        memset(m_Key, 0, sizeof(m_Key));
    }

    void AuthEnclave::SetKey(uint8_t *key) {
        memcpy(m_Key, key, sizeof(m_Key));
    }

    int AuthEnclave::setDatabase(const uint8_t *cdb, int clen, const uint8_t *nonce) {
        m_DB = new uint8_t[clen];
        int result = crypto_secretbox_open_easy(m_DB, cdb, clen, nonce, m_Key);
        if (result != 0) {
            memset(m_DB, 0, clen);
            delete [] m_DB;
            m_DB = nullptr;
        }
        return result;
    }

    int AuthEnclave::getDatabase(uint8_t *cdb, int clen, uint8_t *nonce) {
        assert(m_DB);
        randombytes(nonce, crypto_secretbox_NONCEBYTES);
        int result = crypto_secretbox_easy(cdb, m_DB, clen - crypto_secretbox_MACBYTES, nonce, m_Key);
        return result;
    }


}
