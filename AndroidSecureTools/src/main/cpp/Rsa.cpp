#include <string>
#include "memory"
#include "openssl/rsa.h"
#include "openssl/bn.h"
#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/x509.h"
#include <openssl/engine.h>
#include <android/log.h>
#include "map"

#define  LOG_TAG    "Alpha"
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)

class Rsa {

public:
    static void
    generateKeys(int keyLength, const std::string &packageName, const std::string &passphrase) {
        RSA *rsa = RSA_new();
        BIGNUM *e = BN_new();
        BN_set_word(e, RSA_F4);
        RSA_generate_key_ex(rsa, keyLength, e, nullptr);
        std::string pathPublicKey = "/data/data/" + packageName + "/public_key.pem";
        std::string pathPrivateKey = "/data/data/" + packageName + "/private_key.pem";
        FILE *publicKeyFile = fopen(pathPublicKey.c_str(), "wb");
        FILE *privateKeyFile = fopen(pathPrivateKey.c_str(), "wb");
        PEM_write_RSAPublicKey(publicKeyFile, rsa);
        if (passphrase.empty()) {
            PEM_write_RSAPrivateKey(privateKeyFile, rsa, nullptr, nullptr, NULL, nullptr, nullptr);
        } else {
            PEM_write_RSAPrivateKey(privateKeyFile,
                                    rsa,
                                    EVP_aes_128_cbc(),
                                    (unsigned char *) passphrase.c_str(),
                                    strlen(passphrase.c_str()),
                                    nullptr, nullptr);
        }
        fclose(publicKeyFile);
        fclose(privateKeyFile);

        BN_free(e);
        RSA_free(rsa);
    }

    static std::pair<int, std::string>
    encryptWithStringKey(const std::string &publicKey, std::string &data) {
        std::pair<int, std::string> result = std::make_pair(1, "");

        RSA *rsa = RSA_new();
        BIO *bo = BIO_new_mem_buf(publicKey.c_str(), publicKey.length());
        BIO_write(bo, publicKey.c_str(), publicKey.length());
        PEM_read_bio_RSAPublicKey(bo, &rsa, nullptr, nullptr);

        auto dataSize = strlen(data.c_str());
        auto dataLimit = RSA_size(rsa) - 11;// RSA_PKCS1_PADDING size
        if (dataSize > dataLimit) {
            return std::make_pair(-1, "Data size (bytes) should be less than key size (" +
                                      std::to_string(dataLimit) + ")");
        }

        EVP_PKEY *pKey = EVP_PKEY_new();
        EVP_PKEY_set1_RSA(pKey, rsa);
        result = encryptData(pKey, data);
        BIO_free(bo);
        RSA_free(rsa);

        return result;
    }

private:
    static std::pair<int, std::string>
    encryptData(EVP_PKEY *key, std::string &data) {
        std::pair<int, std::string> result = std::make_pair(1, "");

        EVP_PKEY_CTX *ctx;
        auto *in = (unsigned char *) data.c_str();
        unsigned char *out;
        size_t outLength;

        ctx = EVP_PKEY_CTX_new(key, nullptr);
        if (!ctx) {
            result = std::make_pair(-1, "UnknownError (Rsa" + std::to_string(__LINE__) + ")");
        }

        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            result = std::make_pair(-1, "UnknownError (Rsa" + std::to_string(__LINE__) + ")");
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
            result = std::make_pair(-1, "UnknownError (Rsa" + std::to_string(__LINE__) + ")");
        }

        if (EVP_PKEY_encrypt(ctx, nullptr, &outLength, in, data.length()) <= 0) {
            result = std::make_pair(-1, "UnknownError (Rsa" + std::to_string(__LINE__) + ")");
        }

        out = (unsigned char *) OPENSSL_malloc(outLength);

        if (!out) {
            result = std::make_pair(-1, "UnknownError (Rsa" + std::to_string(__LINE__) + ")");
        }

        if (EVP_PKEY_encrypt(ctx, out, &outLength, in, data.length()) <= 0) {
            result = std::make_pair(-1, "UnknownError (Rsa" + std::to_string(__LINE__) + ")");
        }

        EVP_PKEY_CTX_free(ctx);

        LOGD("wrong guys %s", out);

        return result;
    }
};