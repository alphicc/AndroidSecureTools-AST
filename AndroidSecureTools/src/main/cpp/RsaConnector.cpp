#include "jni.h"
#include "Rsa.cpp"

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_ast_AstRsa_generateKeyPair(JNIEnv *env, jobject obj, jint key) {
    int keyLength = (int) key;
    std::pair<CryptoPP::ByteQueue, CryptoPP::ByteQueue> keyPair = Rsa().generateKeyPair(keyLength);
}