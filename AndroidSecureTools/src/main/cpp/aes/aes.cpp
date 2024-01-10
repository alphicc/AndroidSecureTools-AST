//
// Created by Petr Shubin (alphic_) on 21.05.2021.
//

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "aes.h"
#include "../utils/utils.h"
#include <android/log.h>
#include <crypto/evp.h>

AesKeyGenResult Aes::generateKey(int aesType) {
    AesKeyGenResult result = AesKeyGenResult();

    int length = aesType / 8;
    unsigned char key[length], iv[length];
    if (!RAND_bytes(key, length)) {
        result.code = -1;
        result.error = "key bytes generation failed";
    }
    if (!RAND_bytes(iv, length)) {
        result.code = -1;
        result.error = "iv bytes generation failed";
    }

    Utils utils = Utils();

    result.key = utils.encodeString(key, length);
    result.iv = utils.encodeString(iv, length);

    return result;
}

AesCryptoResult
Aes::encryptString(int cipherType, const std::string &inputKey, const std::string &inputIv,
                   const std::string &data) {

    auto result = AesCryptoResult();

    const EVP_CIPHER *cipher;
    switch (cipherType) {
        case 128:
            cipher = EVP_aes_128_cbc();
            break;
        case 192:
            cipher = EVP_aes_192_cbc();
            break;
        case 256:
            cipher = EVP_aes_256_cbc();
            break;
        default: {
            result.code = -1;
            result.error = "Unknown cipher";
            return result;
        }
    }

    int outLength = 0;
    size_t encMsgLen = 0;

    auto *msg = (unsigned char *) data.c_str();
    size_t msgLength = data.size();

    Utils utils = Utils();
    auto decKey = utils.decodeString(inputKey);
    auto *key = (unsigned char *) decKey.first;
    auto decIv = utils.decodeString(inputIv);
    auto *iv = (unsigned char *) decIv.first;

    EVP_CIPHER_CTX *aesEncryptCtx = EVP_CIPHER_CTX_new();

    auto *encMsg = (unsigned char *) malloc(msgLength + EVP_CIPHER_block_size(cipher));

    if (!EVP_EncryptInit(aesEncryptCtx, cipher, key, iv)) {
        result.code = -1;
        result.error = "UnknownError (Aes" + std::to_string(__LINE__) + ")";
        return result;
    }

    if (!EVP_EncryptUpdate(aesEncryptCtx, encMsg, &outLength, msg, msgLength)) {
        result.code = -1;
        result.error = "UnknownError (Aes" + std::to_string(__LINE__) + ")";
        return result;
    }

    encMsgLen += outLength;

    if (!EVP_EncryptFinal(aesEncryptCtx, encMsg + encMsgLen, &outLength)) {
        result.code = -1;
        result.error = "UnknownError (Aes" + std::to_string(__LINE__) + ")";
        return result;
    }
    encMsgLen += outLength;

    std::string encryptResult = utils.encodeString(encMsg, encMsgLen);
    result.message = encryptResult;

    EVP_CIPHER_CTX_free(aesEncryptCtx);

    return result;
}

AesCryptoResult
Aes::decryptString(int cipherType, const std::string &inputKey, const std::string &inputIv,
                   const std::string &data) {
    auto result = AesCryptoResult();

    const EVP_CIPHER *cipher;
    switch (cipherType) {
        case 128:
            cipher = EVP_aes_128_cbc();
            break;
        case 192:
            cipher = EVP_aes_192_cbc();
            break;
        case 256:
            cipher = EVP_aes_256_cbc();
            break;
        default: {
            result.code = -1;
            result.error = "Unknown cipher";
            return result;
        }
    }

    Utils utils = Utils();

    auto decodedData = utils.decodeString(data);

    auto *msg = (unsigned char *) decodedData.first;
    size_t msgLength = decodedData.second;

    auto decKey = utils.decodeString(inputKey);
    auto *key = (unsigned char *) decKey.first;
    auto decIv = utils.decodeString(inputIv);
    auto *iv = (unsigned char *) decIv.first;

    int outLength = 0;
    size_t decLen = 0;

    EVP_CIPHER_CTX *aesDecryptCtx = EVP_CIPHER_CTX_new();

    auto *decMsg = (unsigned char *) malloc(msgLength);

    if (!EVP_DecryptInit(aesDecryptCtx, cipher, key, iv)) {
        result.code = -1;
        result.error = "UnknownError (Aes" + std::to_string(__LINE__) + ")";
        return result;
    }

    if (!EVP_DecryptUpdate(aesDecryptCtx, decMsg, &outLength, msg, msgLength)) {
        result.code = -1;
        result.error = "UnknownError (Aes" + std::to_string(__LINE__) + ")";
        return result;
    }
    decLen += outLength;

    if (!EVP_DecryptFinal(aesDecryptCtx, decMsg + decLen, &outLength)) {
        result.code = -1;
        result.error = "UnknownError (Aes" + std::to_string(__LINE__) + ")";
        return result;
    }

    decLen += outLength;

    std::string decryptedString((char *) decMsg, decLen);
    result.message = decryptedString;

    EVP_CIPHER_CTX_free(aesDecryptCtx);

    return result;
}
