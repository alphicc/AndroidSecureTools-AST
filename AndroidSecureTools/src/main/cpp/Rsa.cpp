#include "memory"
#include "openssl/rsa.h"
#include "openssl/bn.h"
#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/x509.h"

class Rsa {

public:
    void generateKeys(int keyLength) {
        RSA *rsa = RSA_new();
        BIGNUM *e = BN_new();
        BN_set_word(e, RSA_F4);
        RSA_generate_key_ex(rsa, keyLength, e, nullptr);
        FILE *fp = fopen("/data/data/com.ast.sample/public_key.pem", "wb");
        PEM_write_RSAPublicKey(fp, rsa);
        fclose(fp);
    }
};