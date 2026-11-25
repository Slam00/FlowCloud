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

static inline jstring flow_router_new_utf(JNIEnv *env, const char *chars) {
	return (*env)->NewStringUTF(env, chars);
}
*/
import "C"

import "unsafe"

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

// JNI entry for AutoRouteProxy.jniWarpState, exported straight from
// libflowrouter.so like jniSetOptions.
//
//export Java_io_github_dovecoteescapee_byedpi_core_AutoRouteProxy_jniWarpState
func Java_io_github_dovecoteescapee_byedpi_core_AutoRouteProxy_jniWarpState(env *C.JNIEnv, _ C.jobject) C.jstring {
	value := C.CString(flowRouterWarpState())
	defer C.free(unsafe.Pointer(value))
	return C.flow_router_new_utf(env, value)
}

// JNI entry for AutoRouteProxy.jniWarpInfo. Blocks while measuring the ping, so
// the app calls it off the main thread.
//
//export Java_io_github_dovecoteescapee_byedpi_core_AutoRouteProxy_jniWarpInfo
func Java_io_github_dovecoteescapee_byedpi_core_AutoRouteProxy_jniWarpInfo(env *C.JNIEnv, _ C.jobject, measurePing C.jboolean) C.jstring {
	value := C.CString(flowRouterWarpInfo(measurePing != 0))
	defer C.free(unsafe.Pointer(value))
	return C.flow_router_new_utf(env, value)
}
