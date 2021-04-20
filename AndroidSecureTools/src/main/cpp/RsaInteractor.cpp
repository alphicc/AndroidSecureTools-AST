#include <android/log.h>
#include <jni.h>
#include "string"
#include "Rsa.cpp"
#include "Utils.cpp"
#include "fstream"

#define  LOG_TAG    "Alpha"
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG,__VA_ARGS__)

extern "C" JNIEXPORT jobjectArray

JNICALL
Java_com_ast_rsa_AstRsa_generateKeyPair(JNIEnv *env, jobject obj, jint key, jstring packageName,
                                    jboolean encryptPrivateKey, jstring passphrase) {
    auto keyLength = (int) key;

    std::string packageNameString = Utils::jString_to_cString(env, packageName);
    std::string passphraseString = Utils::jString_to_cString(env, passphrase);

    if (encryptPrivateKey) {
        Rsa::generateKeys(keyLength, packageNameString, passphraseString);
    } else Rsa::generateKeys(keyLength, packageNameString, "");

    auto returnData = (jobjectArray)
            env->NewObjectArray(2,
                                env->FindClass("java/lang/String"),
                                env->NewStringUTF(""));

    std::ifstream publicKeyIfs("/data/data/" + packageNameString + "/public_key.pem");
    std::string publicKey((std::istreambuf_iterator<char>(publicKeyIfs)),
                          (std::istreambuf_iterator<char>()));

    std::ifstream privateKeyIfs("/data/data/" + packageNameString + "/private_key.pem");
    std::string privateKey((std::istreambuf_iterator<char>(privateKeyIfs)),
                           (std::istreambuf_iterator<char>()));

    env->SetObjectArrayElement(returnData, 0, env->NewStringUTF(publicKey.c_str()));
    env->SetObjectArrayElement(returnData, 1, env->NewStringUTF(privateKey.c_str()));

    return returnData;
}

extern "C" JNIEXPORT jstring

JNICALL
Java_com_ast_rsa_AstRsa_encryptString(JNIEnv *env, jobject obj, jstring publicKey, jstring data) {
    std::string dataString = Utils::jString_to_cString(env, data);
    std::string publicKeyString = Utils::jString_to_cString(env, publicKey);
    auto result = Rsa::encryptWithStringKey(publicKeyString, dataString);

    if (result.resultCode <= 0) {
        jclass exception = env->FindClass("java/lang/Exception");
        auto *message = (const char *) result.message.c_str();
        env->ThrowNew(exception, message);
        return nullptr;
    } else {
        return env->NewStringUTF(result.data.c_str());
    }
}

extern "C" JNIEXPORT jstring

JNICALL
Java_com_ast_rsa_AstRsa_decryptString(JNIEnv *env, jobject obj, jstring privateKey, jstring data) {
    std::string dataString = Utils::jString_to_cString(env, data);
    std::string publicKeyString = Utils::jString_to_cString(env, privateKey);
    auto result = Rsa::decryptWithStringKey(publicKeyString, dataString);

    if (result.resultCode <= 0) {
        jclass exception = env->FindClass("java/lang/Exception");
        auto *message = (const char *) result.message.c_str();
        env->ThrowNew(exception, message);
        return nullptr;
    } else {
        return env->NewStringUTF(result.data.c_str());
    }
}