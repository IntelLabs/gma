//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : EncryptorAesGcm.h


#ifndef _ENCRYPTOR_AES_GCM_H
#define _ENCRYPTOR_AES_GCM_H
#include <cstdint>

class EncryptorAesGcm{
public:
    static const int TAG_LENGTH_BIT = 128;
    static const int IV_LENGTH_BYTE = 12;

    int Encrypt(unsigned char *plaintext, int plaintext_len, 
            unsigned char *aad, int add_len,
            unsigned char *key,
            unsigned char *iv, int iv_len,
            unsigned char *ciphertext, unsigned char *tag);

    
    EncryptorAesGcm();

};



#endif