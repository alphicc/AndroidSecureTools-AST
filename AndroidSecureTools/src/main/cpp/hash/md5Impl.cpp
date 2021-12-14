#include <openssl/md5Impl.h>
#include <string>
#include "../utils/utils.h"
#include <openssl/evp.h>
#include <android/log.h>

#define  LOG_TAG    "Alpha"
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)

class Md5Impl {

public:
    class Md5Result {

    public:
        int resultCode = 1;
        std::string message = "Default";
        std::string data = "Empty";

    public:
        Md5Result(int resultCode, std::string message) {
            this->resultCode = resultCode;
            this->message = std::move(message);
        }

        Md5Result() = default;
    };

public:
    static Md5Result hash(std::string &data) {
        Md5Result result;

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();

        unsigned char output[MD5_DIGEST_LENGTH];
        size_t outputSize = MD5_DIGEST_LENGTH;

        if (EVP_DigestInit(ctx, EVP_md5()) <= 0) {
            result = Md5Result(-1, "UnknownError (Md5-" + std::to_string(__LINE__) + ")");
        }

        if (EVP_DigestUpdate(ctx, data.c_str(), data.length()) <= 0) {
            result = Md5Result(-1, "UnknownError (Md5-" + std::to_string(__LINE__) + ")");
        }

        if (EVP_DigestFinal(ctx, output, &outputSize) <= 0) {
            result = Md5Result(-1, "UnknownError (Md5-" + std::to_string(__LINE__) + ")");
        }

        EVP_MD_CTX_free(ctx);

        result.data = Utils::charArrayToString(output, MD5_DIGEST_LENGTH);
        return result;
    }
};