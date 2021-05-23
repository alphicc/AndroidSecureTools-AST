//
// Created by Petr Shubin (alphic_) on 21.05.2021.
//

#include <jni.h>
#include "aes.h"
#include "../utils/utils.h"

extern "C" JNIEXPORT jobject
JNICALL
Java_com_ast_aes_AstAes_generateKey(JNIEnv *env, jobject obj, jint key) {
    auto aes = Aes();
    auto keyLength = (int) key;
    auto result = aes.generateKey(keyLength);
    if (result.code <= 0) {
        jclass exception = env->FindClass("java/lang/Exception");
        auto *message = (const char *) result.error.c_str();
        env->ThrowNew(exception, message);
        return nullptr;
    } else {
        jclass resultClass = env->FindClass("com/ast/aes/models/AesKeyGenResult");
        jmethodID methodId = env->GetMethodID(resultClass, "<init>",
                                              "(Ljava/lang/String;Ljava/lang/String;)V");
        jstring jKey = env->NewStringUTF(result.key.c_str());
        jstring jIv = env->NewStringUTF(result.iv.c_str());
        jobject aesKeyGenResult = env->NewObject(resultClass, methodId, jKey, jIv);
        return aesKeyGenResult;
    }
}

extern "C" JNIEXPORT jstring
JNICALL
Java_com_ast_aes_AstAes_encryptMessage(JNIEnv *env, jobject obj, jint cipher, jstring key,
                                       jstring iv,
                                       jstring message) {
    auto aes = Aes();
    auto utils = Utils();
    auto cipherType = (int) cipher;
    std::string keyString = utils.jstrTocstr(env, key);
    std::string ivString = utils.jstrTocstr(env, iv);
    std::string messageString = utils.jstrTocstr(env, message);
    auto result = aes.encryptString(cipherType, keyString, ivString, messageString);
    if (result.code <= 0) {
        jclass exception = env->FindClass("java/lang/Exception");
        auto *errorMessage = (const char *) result.error.c_str();
        env->ThrowNew(exception, errorMessage);
        return nullptr;
    } else {
        return env->NewStringUTF(result.message.c_str());
    }
}

extern "C" JNIEXPORT jstring
JNICALL
Java_com_ast_aes_AstAes_decryptMessage(JNIEnv *env, jobject obj, jint cipher, jstring key,
                                       jstring iv,
                                       jstring message) {
    auto aes = Aes();
    auto utils = Utils();
    auto cipherType = (int) cipher;
    std::string keyString = utils.jstrTocstr(env, key);
    std::string ivString = utils.jstrTocstr(env, iv);
    std::string messageString = utils.jstrTocstr(env, message);
    auto result = aes.decryptString(cipherType, keyString, ivString, messageString);
    if (result.code <= 0) {
        jclass exception = env->FindClass("java/lang/Exception");
        auto *errorMessage = (const char *) result.error.c_str();
        env->ThrowNew(exception, errorMessage);
        return nullptr;
    } else {
        return env->NewStringUTF(result.message.c_str());
    }
}