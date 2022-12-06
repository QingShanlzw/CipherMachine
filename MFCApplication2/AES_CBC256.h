#pragma once
#ifndef _AES_CBC256_H_
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <stddef.h>



/*
����AES �����Լ� ECB CBC ��ģʽ
��ص�ͷ�ļ�������aes.h����ļ����棬����ͨ������鿴��
aes.h֮��װ��һЩ��������������ڲ�ϸ��û��չ�֡���������.
*/
#define _AES_CBC256_H_
#define USER_KEY_LENGTH 32
#define IVEC_LENGTH     16
#define AES_BLOCK_SIZE  16
#define BITS_LENGTH   (USER_KEY_LENGTH * 8)
class AES_CBC256 {

public:
    AES_CBC256();
    virtual ~AES_CBC256();
    // CBC Mode Encrypt
    bool AES_CBC256_Encrypt(const unsigned char* in, unsigned char* out, size_t length);
    // CBC Mode Decrypt
    bool AES_CBC256_Decrypt(const unsigned char* in, unsigned char* out, size_t length);

    unsigned char m_userKey[USER_KEY_LENGTH];
    unsigned char m_ivec[IVEC_LENGTH];  // Default value is all 0 of 16



};
#endif   // _AES_CBC256_H_

