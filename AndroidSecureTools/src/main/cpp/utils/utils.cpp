//
// Created by Petr Shubin (alphic_) on 21.05.2021.
//

#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include "utils.h"
#include <android/log.h>

#define  LOG_TAG    "Alpha"
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)

std::string Utils::encodeString(unsigned char *data, size_t length) {
    EVP_ENCODE_CTX *evpEncodeCtx = EVP_ENCODE_CTX_new();

    int mallocSize = length;
    while (mallocSize % 3 != 0) {
        mallocSize++;
    }
    auto *out = (unsigned char *) malloc((mallocSize / 3) * 4);

    int outLength = 0;
    size_t tLength = 0;

    EVP_EncodeInit(evpEncodeCtx);
    EVP_EncodeUpdate(evpEncodeCtx,
                     out,
                     &outLength,
                     (const unsigned char *) data,
                     length);

    tLength += outLength;
    EVP_EncodeFinal(evpEncodeCtx, out + tLength, &outLength);
    tLength += outLength;

    std::string result((char *) out, tLength);

    free(out);
    EVP_ENCODE_CTX_free(evpEncodeCtx);
    result.erase(std::remove(result.begin(), result.end(), '\n'), result.end());

    return result;
}

std::pair<unsigned char *, size_t> Utils::decodeString(const std::string &data) {
    EVP_ENCODE_CTX *evpDecodeCtx = EVP_ENCODE_CTX_new();
    auto *out = (unsigned char *) malloc((data.size() / 4) * 3);
    int outLength = 0;
    size_t tLength = 0;

    EVP_DecodeInit(evpDecodeCtx);
    EVP_DecodeUpdate(evpDecodeCtx, out, &outLength, (unsigned char *) data.c_str(),
                     strlen(data.c_str()));
    tLength += outLength;
    EVP_DecodeFinal(evpDecodeCtx, out + tLength, &outLength);
    tLength += outLength;

    EVP_ENCODE_CTX_free(evpDecodeCtx);

    return std::make_pair(out, tLength);
}

std::string Utils::jstrTocstr(JNIEnv *env, jstring string) {
    jboolean isCopy = true;

    int length = (size_t) env->GetStringLength(string);
    const char *convertedValue = (env)->GetStringUTFChars(string, &isCopy);
    std::string path = std::string(convertedValue, length);
    (env)->ReleaseStringUTFChars(string, convertedValue);

    return convertedValue;
}
