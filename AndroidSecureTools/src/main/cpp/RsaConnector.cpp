#include <android/log.h>
#include <jni.h>
#include "string"
#include "Rsa.cpp"
#include "Utils.cpp"

#define  LOG_TAG    "Alpha"
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)

extern "C" JNIEXPORT jobjectArray

JNICALL
Java_com_ast_AstRsa_generateKeyPair(JNIEnv *env, jobject obj, jint key, jstring packageName,
                                    jboolean encryptPrivateKey, jstring passphrase) {
    LOGD("dot %d", 111);

    int keyLength = (int) key;

    std::string packageNameString = Utils::jString_to_cString(env, packageName);
    std::string passphraseString = Utils::jString_to_cString(env, passphrase);

    if (encryptPrivateKey) {
        Rsa::generateKeys(keyLength, packageNameString, passphraseString);
    } else Rsa::generateKeys(keyLength, packageNameString, "");

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