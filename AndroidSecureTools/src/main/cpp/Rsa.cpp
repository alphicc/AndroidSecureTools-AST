//
// Created by AlphaN on 19.11.2020.
//
#include "rsa.h"

class Rsa {

public:
    std::pair<CryptoPP::ByteQueue, CryptoPP::ByteQueue> generateKeyPair(int keyLength) {
        CryptoPP::RandomNumberGenerator randomNumberGenerator;
        CryptoPP::RSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(randomNumberGenerator, keyLength);
        CryptoPP::RSA::PublicKey publicKey(privateKey);
        CryptoPP::ByteQueue queue;
        privateKey.Save(queue);
        return std::pair<CryptoPP::ByteQueue, CryptoPP::ByteQueue>(queue, queue);
    }
};