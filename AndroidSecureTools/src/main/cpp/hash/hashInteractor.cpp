#include "../utils/utils.h"
#include <jni.h>
#include "hash.cpp"

extern "C" JNIEXPORT jstring
JNICALL
Java_com_ast_hash_AstHash_md5(JNIEnv *env, jobject obj, jstring message) {
    auto utils = Utils();
    std::string messageString = utils.jstrTocstr(env, message);
    auto result = Hash::md5(messageString);
    if (result.resultCode <= 0) {
        jclass exception = env->FindClass("java/lang/Exception");
        auto *errorMessage = (const char *) result.message.c_str();
        env->ThrowNew(exception, errorMessage);
        return nullptr;
    } else {
        return env->NewStringUTF(result.data.c_str());
    }
}

extern "C" JNIEXPORT jstring
JNICALL
Java_com_ast_hash_AstHash_sha1(JNIEnv *env, jobject obj, jstring message) {
    auto utils = Utils();
    std::string messageString = utils.jstrTocstr(env, message);
    auto result = Hash::sha1(messageString);
    if (result.resultCode <= 0) {
        jclass exception = env->FindClass("java/lang/Exception");
        auto *errorMessage = (const char *) result.message.c_str();
        env->ThrowNew(exception, errorMessage);
        return nullptr;
    } else {
        return env->NewStringUTF(result.data.c_str());
    }
}

extern "C" JNIEXPORT jstring
JNICALL
Java_com_ast_hash_AstHash_sha256(JNIEnv *env, jobject obj, jstring message) {
    auto utils = Utils();
    std::string messageString = utils.jstrTocstr(env, message);
    auto result = Hash::sha256(messageString);
    if (result.resultCode <= 0) {
        jclass exception = env->FindClass("java/lang/Exception");
        auto *errorMessage = (const char *) result.message.c_str();
        env->ThrowNew(exception, errorMessage);
        return nullptr;
    } else {
        return env->NewStringUTF(result.data.c_str());
    }
}