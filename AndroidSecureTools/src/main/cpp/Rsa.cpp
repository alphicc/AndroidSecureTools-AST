#include <string>
#include "memory"
#include "openssl/rsa.h"
#include "openssl/bn.h"
#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/x509.h"

class Rsa {

public:
    void generateKeys(int keyLength, const std::string &packageName) {
        RSA *rsa = RSA_new();
        BIGNUM *e = BN_new();
        BN_set_word(e, RSA_F4);
        RSA_generate_key_ex(rsa, keyLength, e, nullptr);
        std::string pathString = "/data/data/" + packageName + "/public_key.pem";
        FILE *fp = fopen(pathString.c_str(), "wb");
        PEM_write_RSAPublicKey(fp, rsa);
        PEM_write_RSAPrivateKey(fp, rsa, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(fp);
    }
};