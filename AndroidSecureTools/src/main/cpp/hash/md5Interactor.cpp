#include "../utils/utils.h"
#include <jni.h>
#include "md5Impl.cpp"

extern "C" JNIEXPORT jstring
JNICALL
Java_com_ast_hash_AstMd5_hash(JNIEnv *env, jobject obj, jstring message) {
    auto utils = Utils();
    std::string messageString = utils.jstrTocstr(env, message);
    auto result = Md5Impl::hash(messageString);
    if (result.resultCode <= 0) {
        jclass exception = env->FindClass("java/lang/Exception");
        auto *errorMessage = (const char *) result.message.c_str();
        env->ThrowNew(exception, errorMessage);
        return nullptr;
    } else {
        return env->NewStringUTF(result.data.c_str());
    }
}
