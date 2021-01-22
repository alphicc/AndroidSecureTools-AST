#include <string>
#include "memory"
#include "openssl/rsa.h"
#include "openssl/bn.h"
#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/x509.h"
#include <openssl/engine.h>
#include <android/log.h>

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

    static void
    encryptWithStringKey(const std::string &publicKey, std::string &data) {
        RSA *public_key_ = RSA_new();
        BIO *bo = BIO_new_mem_buf(publicKey.c_str(), publicKey.length());
        BIO_write(bo, publicKey.c_str(), publicKey.length());
        PEM_read_bio_RSA_PUBKEY(bo, &public_key_, nullptr, nullptr);
        LOGD("wrong guys %s", publicKey.c_str());
        EVP_PKEY *pkey = EVP_PKEY_new();
        auto result = EVP_PKEY_set1_RSA(pkey, public_key_);
        if (result <= 0) {
            LOGD("chee");
        }
        //BIO *bo = BIO_new(BIO_s_mem());
        //BIO_write(bo, publicKey.c_str(), publicKey.length());
        //EVP_PKEY *pkey = nullptr;
        //EVP_PKEY_set1_RSA()
        //PEM_read_bio_PUBKEY(bo, &pkey, nullptr, nullptr);
        LOGD("ne chee");
        encryptData(pkey, data);
        BIO_free(bo);
        RSA_free(public_key_);
        //BIO_free(bo);
        //EVP_PKEY_free(pkey);
    }

private:
    static void encryptData(EVP_PKEY *key, std::string &data) {
        EVP_PKEY_CTX *ctx;
        ENGINE *eng = ENGINE_new();
        auto *in = (unsigned char *) data.c_str();
        unsigned char *out = NULL;
        size_t outlen;

        /*
         * NB: assumes eng, key, in, inlen are already set up,
         * and that key is an RSA public key
         */
        LOGD("wrong guys %s", "0");
        ctx = EVP_PKEY_CTX_new(key, nullptr);
        if (!ctx) {
            LOGD("wrong guys %s", "1");
            /* Error occurred */
        }

        LOGD("wrong guys %s", "01");
        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            LOGD("wrong guys %s", "2");
            /* Error */
        }
        LOGD("wrong guys %s", "02");
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            LOGD("wrong guys %s", "3");
            /* Error */
        }
        LOGD("wrong guys %s", "03");

        //BIGNUM *e = BN_new();
        //BN_set_word(e, RSA_F4);
        //if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, e) <= 0) {
        //    LOGD("not good");
        //    /* Error */
        //}

        /* Determine buffer length */
        if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, in, data.length()) <= 0) {
            LOGD("wrong guys %s", "4");
            /* Error */
        }
        LOGD("wrong guys %s", "04");
        out = (unsigned char *) OPENSSL_malloc(outlen);

        LOGD("wrong guys %s", "05");
        if (!out) {
            LOGD("wrong guys %s", "5");
            /* malloc failure */
        }

        LOGD("wrong guys %s", "06");
        if (EVP_PKEY_encrypt(ctx, out, &outlen, in, data.length()) <= 0) {
            LOGD("wrong guys %s", "6");
            /* Error */
        }
        LOGD("wrong guys %s", "07");
        EVP_PKEY_CTX_free(ctx);

        /* Encrypted data is outlen bytes written to buffer out */
        LOGD("wrong guys %s", out);
    }
};