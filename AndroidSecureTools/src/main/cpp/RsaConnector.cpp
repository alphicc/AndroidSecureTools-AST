#include <android/log.h>
#include <jni.h>
#include "openssl/rsa.h"
#include "dlfcn.h"

#define  LOG_TAG    "Alpha"
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)

extern "C" JNIEXPORT jobjectArray

JNICALL Java_com_ast_AstRsa_generateKeyPair(JNIEnv *env, jobject obj, jint key) {
    int keyLength = (int) key;
    LOGD("dot %d", 1);

    RSA *key_pair = RSA_new();
    BIGNUM *public_key_exponent = BN_new();
    BN_set_word(public_key_exponent, RSA_F4);
    int result = RSA_generate_key_ex(key_pair, 2048, public_key_exponent, nullptr);

    if (!result) {
        LOGD("dot %d", 111);
    }

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