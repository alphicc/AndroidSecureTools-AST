#include "string"
#include "jni.h"

class Utils {
public:
    static std::string jString_to_cString(JNIEnv *env, jstring string) {
        jboolean isCopy = true;

        int length = (size_t) env->GetStringLength(string);
        const char *convertedValue = (env)->GetStringUTFChars(string, &isCopy);
        std::string path = std::string(convertedValue, length);
        (env)->ReleaseStringUTFChars(string, convertedValue);

        return convertedValue;
    }
};