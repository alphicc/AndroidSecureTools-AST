#include <string>
#include "memory"
#include "openssl/rsa.h"
#include "openssl/bn.h"
#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/x509.h"

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
};