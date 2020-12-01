//
// Created by AlphaN on 19.11.2020.
//
#include "rsa.h"
#include <android/log.h>

#define  LOG_TAG    "Alpha"
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)

class Rsa {

public:
    std::pair<std::string, std::string> generateKeyPair(int keyLength) {
        LOGD("dot %d", 11);
        CryptoPP::RandomNumberGenerator randomNumberGenerator;
        LOGD("dot %d", 12);
        CryptoPP::RSA::PrivateKey privateKey;
        LOGD("dot %d %d", 121, keyLength);
        privateKey.GenerateRandomWithKeySize(rng, keyLength);
        LOGD("dot %d", 122);
        CryptoPP::RSA::PublicKey publicKey(privateKey);
        LOGD("dot %d", 13);

        std::string publicKeyString = "", privateKeyString = "";

        CryptoPP::StringSource publicKeyStringSource(publicKeyString, true);
        CryptoPP::StringSource privateKeyStringSource(privateKeyString, true);
        publicKey.Load(publicKeyStringSource);
        privateKey.Load(privateKeyStringSource);
        LOGD("dot %d", 14);

        return std::pair<std::string, std::string>(publicKeyString, privateKeyString);
    }
};