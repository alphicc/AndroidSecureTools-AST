#include <string>
#include <utility>
#include "memory"
#include "openssl/rsa.h"
#include "openssl/bn.h"
#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/x509.h"
#include <openssl/engine.h>
#include <android/log.h>
#include "map"

class Rsa {

public:
    class RsaResult {

    public:
        int resultCode = 1;
        std::string message = "Default";
        std::string data = "Empty";

    public:
        RsaResult(int resultCode, std::string message) {
            this->resultCode = resultCode;
            this->message = std::move(message);
        }

        RsaResult() = default;
    };

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

    static RsaResult encryptWithStringKey(const std::string &publicKey, std::string &data) {
        RsaResult result = RsaResult();

        RSA *rsa = RSA_new();
        BIO *bo = BIO_new_mem_buf(publicKey.c_str(), publicKey.length());
        BIO_write(bo, publicKey.c_str(), publicKey.length());
        PEM_read_bio_RSAPublicKey(bo, &rsa, nullptr, nullptr);

        auto dataSize = strlen(data.c_str());
        auto dataLimit = RSA_size(rsa) - 11;// RSA_PKCS1_PADDING size
        if (dataSize > dataLimit) {
            return RsaResult(-1, "Data size (bytes) should be less than key size (" +
                                 std::to_string(dataLimit) + ")");
        }

        EVP_PKEY *pKey = EVP_PKEY_new();
        EVP_PKEY_set1_RSA(pKey, rsa);
        result = encryptData(pKey, data);
        BIO_free(bo);
        RSA_free(rsa);
        EVP_PKEY_free(pKey);

        return result;
    }

    static RsaResult decryptWithStringKey(const std::string &privateKey, std::string &data) {
        RsaResult result = RsaResult();

        RSA *rsa = RSA_new();
        BIO *bo = BIO_new_mem_buf(privateKey.c_str(), privateKey.length());
        BIO_write(bo, privateKey.c_str(), privateKey.length());
        PEM_read_bio_RSAPrivateKey(bo, &rsa, nullptr, nullptr);

        EVP_PKEY *pKey = EVP_PKEY_new();
        EVP_PKEY_set1_RSA(pKey, rsa);

        auto decodedData = decodeString(data);
        result = decryptData(pKey, decodedData.first, decodedData.second);

        BIO_free(bo);
        RSA_free(rsa);
        EVP_PKEY_free(pKey);

        return result;
    }

private:
    static RsaResult encryptData(EVP_PKEY *key, std::string &data) {
        RsaResult result = RsaResult();

        EVP_PKEY_CTX *ctx;
        auto *in = (unsigned char *) data.c_str();
        unsigned char *out;
        size_t outLength;

        ctx = EVP_PKEY_CTX_new(key, nullptr);
        if (!ctx) {
            result = RsaResult(-1, "UnknownError (Rsa" + std::to_string(__LINE__) + ")");
        }

        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            result = RsaResult(-1, "UnknownError (Rsa" + std::to_string(__LINE__) + ")");
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
            result = RsaResult(-1, "UnknownError (Rsa" + std::to_string(__LINE__) + ")");
        }

        if (EVP_PKEY_encrypt(ctx, nullptr, &outLength, in, data.length()) <= 0) {
            result = RsaResult(-1, "UnknownError (Rsa" + std::to_string(__LINE__) + ")");
        }

        out = (unsigned char *) OPENSSL_malloc(outLength);

        if (!out) {
            result = RsaResult(-1, "UnknownError (Rsa" + std::to_string(__LINE__) + ")");
        }

        if (EVP_PKEY_encrypt(ctx, out, &outLength, in, data.length()) <= 0) {
            result = RsaResult(-1, "UnknownError (Rsa" + std::to_string(__LINE__) + ")");
        }

        EVP_PKEY_CTX_free(ctx);
        OPENSSL_free(out);

        auto res = encodeString(out, outLength);
        result.data = res;

        return result;
    }

private:
    static RsaResult decryptData(EVP_PKEY *key, unsigned char *data, size_t dataLength) {
        RsaResult result = RsaResult();

        EVP_PKEY_CTX *ctx;
        unsigned char *out;
        size_t outLength;

        ctx = EVP_PKEY_CTX_new(key, nullptr);
        if (!ctx) {
            result = RsaResult(-1, "UnknownError (Rsa" + std::to_string(__LINE__) + ")");
        }
        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
            result = RsaResult(-1, "UnknownError (Rsa" + std::to_string(__LINE__) + ")");
        }
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
            result = RsaResult(-1, "UnknownError (Rsa" + std::to_string(__LINE__) + ")");
        }

        if (EVP_PKEY_decrypt(ctx, nullptr, &outLength, data, dataLength) <= 0) {
            result = RsaResult(-1, "UnknownError (Rsa" + std::to_string(__LINE__) + ")");
        }

        out = (unsigned char *) OPENSSL_malloc(outLength);

        if (!out) {
            result = RsaResult(-1, "UnknownError (Rsa" + std::to_string(__LINE__) + ")");
        }
        if (EVP_PKEY_decrypt(ctx, out, &outLength, data, dataLength) <= 0) {
            result = RsaResult(-1, "UnknownError (Rsa" + std::to_string(__LINE__) + ")");
        }

        EVP_PKEY_CTX_free(ctx);
        OPENSSL_free(out);

        //std::string decryptedString(reinterpret_cast<char const *>(out), outLength);
        std::string decryptedString((char *) out, outLength);
        result.data = decryptedString;

        return result;
    }

private:
    static std::string encodeString(unsigned char *data, size_t length) {
        EVP_ENCODE_CTX *evpEncodeCtx = EVP_ENCODE_CTX_new();

        int mallocSize = length;
        while (mallocSize % 3 != 0) {
            mallocSize++;
        }
        auto *out = (unsigned char *) malloc((mallocSize / 3) * 4);

        int outLength = 0;
        int tLength = 0;

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

    static std::pair<unsigned char *, size_t> decodeString(const std::string &data) {

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

        free(out);
        EVP_ENCODE_CTX_free(evpDecodeCtx);

        return std::make_pair(out, tLength);
    }
};