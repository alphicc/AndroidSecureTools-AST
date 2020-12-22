#include <android/log.h>
#include <jni.h>
#include "Rsa.cpp"

#define  LOG_TAG    "Alpha"
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)

extern "C" JNIEXPORT jobjectArray

JNICALL Java_com_ast_AstRsa_generateKeyPair(JNIEnv *env, jobject obj, jint key) {

    LOGD("dot %d", 111);
    int keyLength = (int) key;

    Rsa rsa = Rsa();
    rsa.generateKeys(keyLength);

    LOGD("dot %d", 2);
    jobjectArray
            returnData = (jobjectArray)
            env->NewObjectArray(2,
                                env->FindClass("java/lang/String"),
                                env->NewStringUTF(""));
    LOGD("dot %d", 3);
    env->SetObjectArrayElement(returnData, 0, env->NewStringUTF("0"));
    env->SetObjectArrayElement(returnData, 1, env->NewStringUTF("1"));
    LOGD("dot %d", 4);
    return returnData;
}