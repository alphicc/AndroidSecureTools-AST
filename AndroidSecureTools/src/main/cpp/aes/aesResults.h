//
// Created by AlphaN on 21.05.2021.
//

#ifndef ANDROIDSECURETOOLS_AESRESULTS_H
#define ANDROIDSECURETOOLS_AESRESULTS_H


#include <string>

struct AesKeyGenResult {
    int code = 1;
    std::string key = "Undefined";
    std::string iv = "Undefined";
    std::string error = "Undefined";
};

struct AesCryptoResult {
    int code = 1;
    std::string message = "Undefined";
    std::string error = "Undefined";
};


#endif //ANDROIDSECURETOOLS_AESRESULTS_H
