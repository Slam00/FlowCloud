//go:build android

package main

/*
#include <stdlib.h>
#include <jni.h>

static inline const char *flow_router_get_utf(JNIEnv *env, jstring value) {
	return (*env)->GetStringUTFChars(env, value, NULL);
}

static inline void flow_router_release_utf(JNIEnv *env, jstring value, const char *chars) {
	(*env)->ReleaseStringUTFChars(env, value, chars);
}
*/
import "C"

// JNI entry for AutoRouteProxy.jniSetOptions. It is exported straight from
// libflowrouter.so (loaded by AutoRouteProxy) so the byedpi JNI glue in
// native-lib.c does not need to know about router options.
//
//export Java_io_github_dovecoteescapee_byedpi_core_AutoRouteProxy_jniSetOptions
func Java_io_github_dovecoteescapee_byedpi_core_AutoRouteProxy_jniSetOptions(env *C.JNIEnv, _ C.jobject, optionsJSON C.jstring) C.jint {
	if optionsJSON == 0 {
		return C.jint(setFlowRouterOptions(""))
	}
	chars := C.flow_router_get_utf(env, optionsJSON)
	if chars == nil {
		return -1
	}
	text := C.GoString(chars)
	C.flow_router_release_utf(env, optionsJSON, chars)
	return C.jint(setFlowRouterOptions(text))
}
