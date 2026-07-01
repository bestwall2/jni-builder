#include <jni.h>

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_testcppapp_NativeLib_stringFromJNI(
        JNIEnv* env,
        jobject thiz) {

    return env->NewStringUTF("Hello from GitHub Actions!");
}
