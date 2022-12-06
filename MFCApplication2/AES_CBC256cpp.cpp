#ifndef _AES_CBC256_H_
#   include "AES_CBC256.h"
#endif




#include "pch.h"

AES_CBC256::AES_CBC256() {
    memcpy(m_userKey, "XZJE151628AED2A6ABF7158809CF4F3", USER_KEY_LENGTH);
    memcpy(m_ivec, "XZJ2030405060708090A0B0C0D0E0FT", IVEC_LENGTH);  // Vector initialization
}
AES_CBC256::~AES_CBC256() {

}
//只要传入一个要加密的东西，和加密后的载体，以及一个length（要是16的倍数,就是要输出数据的长度，mod16必须是0）。
bool AES_CBC256::AES_CBC256_Encrypt(const unsigned char* in, unsigned char* out, size_t length) {

    /*if (0 != (length % AES_BLOCK_SIZE)) {
        printf("%s\n", "the length is not multiple of AES_BLOCK_SIZE(16bytes)");
        return false;
    }*/
    unsigned char ivec[IVEC_LENGTH];
    memcpy(ivec, m_ivec, IVEC_LENGTH);
    AES_KEY key;
    // get the key with userkey
    if (AES_set_encrypt_key(m_userKey, BITS_LENGTH, &key) < 0) {
        printf("%s\n", "get the key error");
        return false;
    }
    else {
        printf("%s\n", "get the key successful");
    }

    AES_cbc_encrypt(in, out, length, &key, ivec, AES_ENCRYPT);
    return true;
}

bool AES_CBC256::AES_CBC256_Decrypt(const unsigned char* in, unsigned char* out, size_t length) {

    /* if (0 != (length % AES_BLOCK_SIZE)) {
         printf("%s\n", "the length is not multiple of AES_BLOCK_SIZE(16bytes)");
         return false;
     }*/
    unsigned char ivec[IVEC_LENGTH];
    memcpy(ivec, m_ivec, IVEC_LENGTH);
    AES_KEY key;
    // get the key with userkey
    if (AES_set_decrypt_key(m_userKey, BITS_LENGTH, &key) < 0) {
        printf("%s\n", "get the key error");
        return false;
    }
    else {
        printf("%s\n", "get the key successful");
    }

    AES_cbc_encrypt(in, out, length, &key, ivec, AES_DECRYPT);
    return true;
}
