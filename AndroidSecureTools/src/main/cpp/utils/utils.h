//
// Created by Petr Shubin (alphic_) on 21.05.2021.
//

#ifndef ANDROIDSECURETOOLS_UTILS_H
#define ANDROIDSECURETOOLS_UTILS_H

#include <string>
#include <jni.h>
#include "jni.h"

class Utils {
public:
    std::string encodeString(unsigned char *data, size_t length);
    std::pair<unsigned char *, size_t> decodeString(const std::string& data);
    std::string jstrTocstr(JNIEnv *env, jstring string);
};


#endif //ANDROIDSECURETOOLS_UTILS_H
