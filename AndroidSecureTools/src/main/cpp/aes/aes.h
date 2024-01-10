//
// Created by Petr Shubin (alphic_) on 21.05.2021.
//

#ifndef ANDROIDSECURETOOLS_AES_H
#define ANDROIDSECURETOOLS_AES_H

#include "aesResults.h"

class Aes {
public:
    AesKeyGenResult generateKey(int aesType);

    AesCryptoResult
    encryptString(int cipherType, const std::string &inputKey, const std::string &inputIv,
                  const std::string &data);

    AesCryptoResult
    decryptString(int cipherType, const std::string &inputKey, const std::string &inputIv,
                  const std::string &data);
};


#endif //ANDROIDSECURETOOLS_AES_H
