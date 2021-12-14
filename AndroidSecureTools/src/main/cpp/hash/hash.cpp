#include <openssl/hash.h>
#include <string>
#include "../utils/utils.h"
#include <openssl/evp.h>
#include <android/log.h>

#define  LOG_TAG    "Alpha"
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)

class Hash {

public:
    class HashResult {

    public:
        int resultCode = 1;
        std::string message = "Default";
        std::string data = "Empty";

    public:
        HashResult(int resultCode, std::string message) {
            this->resultCode = resultCode;
            this->message = std::move(message);
        }

        HashResult() = default;
    };

public:
    static HashResult md5(std::string &data) {
        HashResult result;

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();

        unsigned char output[MD5_DIGEST_LENGTH];
        size_t outputSize = MD5_DIGEST_LENGTH;

        if (EVP_DigestInit(ctx, EVP_md5()) <= 0) {
            result = HashResult(-1, "UnknownError (md5-" + std::to_string(__LINE__) + ")");
        }

        if (EVP_DigestUpdate(ctx, data.c_str(), data.length()) <= 0) {
            result = HashResult(-1, "UnknownError (md5-" + std::to_string(__LINE__) + ")");
        }

        if (EVP_DigestFinal(ctx, output, &outputSize) <= 0) {
            result = HashResult(-1, "UnknownError (md5-" + std::to_string(__LINE__) + ")");
        }

        EVP_MD_CTX_free(ctx);

        result.data = Utils::charArrayToString(output, MD5_DIGEST_LENGTH);
        return result;
    }

    static HashResult sha1(std::string &data) {
        HashResult result;

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();

        unsigned char output[20];
        size_t outputSize = 20;

        if (EVP_DigestInit(ctx, EVP_sha1()) <= 0) {
            result = HashResult(-1, "UnknownError (sha1-" + std::to_string(__LINE__) + ")");
        }

        if (EVP_DigestUpdate(ctx, data.c_str(), data.length()) <= 0) {
            result = HashResult(-1, "UnknownError (sha1-" + std::to_string(__LINE__) + ")");
        }

        if (EVP_DigestFinal(ctx, output, &outputSize) <= 0) {
            result = HashResult(-1, "UnknownError (sha1-" + std::to_string(__LINE__) + ")");
        }

        EVP_MD_CTX_free(ctx);

        result.data = Utils::charArrayToString(output, 20);
        return result;
    }

    static HashResult sha256(std::string &data) {
        HashResult result;

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();

        unsigned char output[32];
        size_t outputSize = 32;

        if (EVP_DigestInit(ctx, EVP_sha256()) <= 0) {
            result = HashResult(-1, "UnknownError (sha256-" + std::to_string(__LINE__) + ")");
        }

        if (EVP_DigestUpdate(ctx, data.c_str(), data.length()) <= 0) {
            result = HashResult(-1, "UnknownError (sha256-" + std::to_string(__LINE__) + ")");
        }

        if (EVP_DigestFinal(ctx, output, &outputSize) <= 0) {
            result = HashResult(-1, "UnknownError (sha256-" + std::to_string(__LINE__) + ")");
        }

        EVP_MD_CTX_free(ctx);

        result.data = Utils::charArrayToString(output, 32);
        return result;
    }
};