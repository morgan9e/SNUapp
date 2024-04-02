#include "com_ubivelox_security_EncryptionKeyStore.h"
#include <dlfcn.h>
#include <stdio.h>
#include <android/log.h>

void* libhandle = dlopen("libEncryptionKeyStore-orig.so", RTLD_LAZY);

typedef void (*checkRooting_ft)(JNIEnv*, jobject, jstring);
typedef jstring (*getBleInfo_ft)(JNIEnv*, jobject);
typedef jstring (*getSecretKeyEx_ft)(JNIEnv*, jobject);
checkRooting_ft checkRooting_ptr;
getBleInfo_ft getBleInfo_ptr;
getSecretKeyEx_ft getSecretKeyEx_ptr;

JNIEXPORT void JNICALL checkRooting(JNIEnv* arg1, jobject arg2, jstring arg3) {
    if (!checkRooting_ptr)
        checkRooting_ptr = (checkRooting_ft)dlsym(libhandle, "Java_com_ubivelox_security_EncryptionKeyStore_checkRooting");
    if (checkRooting_ptr)
//      return checkRooting_ptr(arg1, arg2, arg3);
        return;
}

JNIEXPORT jstring JNICALL getBleInfo(JNIEnv* env, jobject obj) {
    if (!getBleInfo_ptr)
        getBleInfo_ptr = (getBleInfo_ft)dlsym(libhandle, "Java_com_ubivelox_security_EncryptionKeyStore_getBleInfo");
    if (getBleInfo_ptr) {
        jstring ret = getBleInfo_ptr(env, obj);

        const char *cStr = env->GetStringUTFChars(ret, NULL);
        if (cStr == NULL) {
            return NULL;
        }
        char log[2048] = {0};
        snprintf(log, sizeof(log), "getBleInfo: %s", cStr);
        __android_log_write(ANDROID_LOG_ERROR, "libEncryptionKeyStore", log);
        env->ReleaseStringUTFChars(ret, cStr);
        return ret;
    }
    return NULL;
}

JNIEXPORT jstring JNICALL getSecretKeyEx(JNIEnv* env, jobject obj) {
    if (!getSecretKeyEx_ptr)
        getSecretKeyEx_ptr = (getSecretKeyEx_ft)dlsym(libhandle, "Java_com_ubivelox_security_EncryptionKeyStore_getSecretKeyEx");
    if (getSecretKeyEx_ptr) {
        jstring ret = getSecretKeyEx_ptr(env, obj);

        const char *cStr = env->GetStringUTFChars(ret, NULL);
        if (cStr == NULL) {
            return NULL;
        }
        char log[2048] = {0};
        snprintf(log, sizeof(log), "getSecretKeyEx: %s, %p", cStr, *(*env + 0x538));
        __android_log_write(ANDROID_LOG_ERROR, "libEncryptionKeyStore", log);
        env->ReleaseStringUTFChars(ret, cStr);
        return ret;
    }
    return NULL;
}

JNIEXPORT void JNICALL Java_com_ubivelox_security_EncryptionKeyStore_checkRooting (JNIEnv* arg1, jobject arg2, jstring arg3)
{
    return checkRooting(arg1, arg2, arg3);
}
JNIEXPORT jstring JNICALL Java_com_ubivelox_security_EncryptionKeyStore_getBleInfo (JNIEnv* arg1, jobject arg2) 
{
    return getBleInfo(arg1, arg2);
}

JNIEXPORT jstring JNICALL Java_com_ubivelox_security_EncryptionKeyStore_getSecretKeyEx (JNIEnv* arg1, jobject arg2)
{
    return getSecretKeyEx(arg1, arg2);
}
