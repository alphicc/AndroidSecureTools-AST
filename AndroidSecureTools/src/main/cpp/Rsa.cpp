#include "memory"
#include "openssl/rsa.h"
#include "openssl/bn.h"
#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/x509.h"

using RSA_ptr = std::unique_ptr<RSA, decltype(&::RSA_free)>;
using BN_ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
using EVP_KEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using BIO_FILE_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;

class Rsa {

public:
    void generateKeys(int keyLength) {
        BIO_FILE_ptr publicKeyPem(BIO_new_file("rsa_public.pem", "w"), ::BIO_free);
        BIO_FILE_ptr privateKeyPem(BIO_new_file("rsa_private.pem", "w"), ::BIO_free);

        RSA_ptr rsa(RSA_new(), ::RSA_free);
        BN_ptr bn(BN_new(), ::BN_free);

        BN_set_word(bn.get(), RSA_F4);
        RSA_generate_key_ex(rsa.get(), keyLength, bn.get(), nullptr);

        EVP_KEY_ptr pemKey(EVP_PKEY_new(), ::EVP_PKEY_free);
        EVP_PKEY_set1_RSA(pemKey.get(), rsa.get());

        PEM_write_bio_PUBKEY(publicKeyPem.get(), pemKey.get());
    }
};