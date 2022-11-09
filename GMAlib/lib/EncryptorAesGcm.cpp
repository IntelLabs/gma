//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : EncryptorAesGcm.cpp

#include "../include/EncryptorAesGcm.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <cstdint>
#include <stdio.h>

int EncryptorAesGcm::Encrypt(unsigned char *plaintext,int plaintext_len, 
            unsigned char*aad, const int aad_len,
            unsigned char *key,
            unsigned char *iv, int iv_len,
            unsigned char *ciphertext, unsigned char *tag)

{
    EVP_CIPHER_CTX *ctx;
    int len;
    const int cipher_len = plaintext_len;
    int ret = 1;
    int i;
    
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return 0;

    ret = ret * (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));
    
    ret = ret * (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL)); // IV length is 12

    ret = ret * (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));
     
    ret = ret * (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)); // aad len is 4

    ret = ret * (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len));
    
    ret = ret * (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len));

    ret = ret * (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag));

    EVP_CIPHER_CTX_free(ctx);
    return ret;

}
EncryptorAesGcm::EncryptorAesGcm()
{
}