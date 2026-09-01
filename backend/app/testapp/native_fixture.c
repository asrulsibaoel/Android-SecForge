/*
 * AndroidSecForge native test fixture.
 *
 * INTENTIONALLY DEMONSTRATIVE — for local analysis-pipeline testing only.
 * It is NOT malware and performs no harmful action. It exists so the ELF/JNI/
 * native-rule analyzers have a real shared object to parse:
 *   - JNI_OnLoad
 *   - one JNI-exported function (Java_com_androidsecforge_testapp_NativeBridge_verify)
 *   - one normal exported function (asf_normal_export)
 *   - imported libc functions (strcpy, strlen, malloc, free)
 *   - one deliberately suspicious API usage (strcpy into a fixed buffer)
 */
#include <string.h>
#include <stdlib.h>

/* JNI-ish types kept minimal so the fixture builds without the Android NDK. */
typedef void *JNIEnv;
typedef void *JavaVM;
typedef void *jobject;
typedef int jint;

#define JNI_VERSION_1_6 0x00010006

/* Suspicious API usage: unbounded copy into a fixed buffer (indicator only). */
__attribute__((visibility("default")))
jint Java_com_androidsecforge_testapp_NativeBridge_verify(JNIEnv *env, jobject self, const char *input) {
    char buffer[16];
    strcpy(buffer, input);   /* deliberately unsafe: no bounds check */
    return (jint)strlen(buffer);
}

__attribute__((visibility("default")))
int asf_normal_export(int a, int b) {
    char *tmp = (char *)malloc(8);
    int result = a + b;
    free(tmp);
    return result;
}

__attribute__((visibility("default")))
jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    return JNI_VERSION_1_6;
}
