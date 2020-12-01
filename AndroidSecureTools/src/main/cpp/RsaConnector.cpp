#include "jni.h"
#include "Rsa.cpp"
#include <android/log.h>

#define  LOG_TAG    "Alpha"
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_ast_AstRsa_generateKeyPair(JNIEnv *env, jobject obj, jint key) {
    int keyLength = (int) key;
    LOGD("dot %d", 1);
    std::pair<std::string, std::string> keyPair = Rsa().generateKeyPair(keyLength);

    LOGD("dot %d", 2);
    jobjectArray returnData = (jobjectArray) env->NewObjectArray(2,
                                                                 env->FindClass("java/lang/String"),
                                                                 env->NewStringUTF(""));
    LOGD("dot %d", 3);
    env->SetObjectArrayElement(returnData, 0, env->NewStringUTF(keyPair.first.c_str()));
    env->SetObjectArrayElement(returnData, 1, env->NewStringUTF(keyPair.second.c_str()));
    LOGD("dot %d", 4);
    return returnData;
}