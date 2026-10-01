package main

/*
#cgo android LDFLAGS: -llog
#include <stdlib.h>
#include <stdio.h>
#ifdef __ANDROID__
#include <android/log.h>
static inline void flow_router_log(const char *message) {
	__android_log_write(ANDROID_LOG_INFO, "FlowRouter", message);
}
#else
static inline void flow_router_log(const char *message) {
	fprintf(stderr, "FlowRouter: %s\n", message);
}
#endif
*/
import "C"

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"unsafe"
)

var bridgeState struct {
	sync.Mutex
	router *flowRouter
	err    string
}

func init() {
	flowRouterLogSink = func(text string) {
		message := C.CString(text)
		defer C.free(unsafe.Pointer(message))
		C.flow_router_log(message)
	}
}

//export FlowRouterStart
func FlowRouterStart(listenAddress, byeDPIAddress, dnsRelayAddress, warpRulesText, byeDPIRulesText, warpJSON *C.char) C.int {
	bridgeState.Lock()
	defer bridgeState.Unlock()
	if bridgeState.router != nil {
		bridgeState.err = "router is already running"
		return -1
	}
	router, err := newFlowRouter(
		C.GoString(listenAddress),
		C.GoString(byeDPIAddress),
		C.GoString(dnsRelayAddress),
		C.GoString(warpRulesText),
		C.GoString(byeDPIRulesText),
		C.GoString(warpJSON),
	)
	if err != nil {
		bridgeState.err = err.Error()
		return -2
	}
	if err = router.start(); err != nil {
		router.close()
		bridgeState.err = err.Error()
		return -3
	}
	bridgeState.router = router
	bridgeState.err = ""
	return 0
}

//export FlowRouterStop
func FlowRouterStop() {
	bridgeState.Lock()
	router := bridgeState.router
	bridgeState.router = nil
	bridgeState.Unlock()
	if router != nil {
		router.close()
	}
}

//export FlowRouterLastError
func FlowRouterLastError() *C.char {
	bridgeState.Lock()
	defer bridgeState.Unlock()
	if bridgeState.err == "" {
		return C.CString("")
	}
	return C.CString(fmt.Sprintf("%s", bridgeState.err))
}

//export FlowRouterDrainDiagnostics
func FlowRouterDrainDiagnostics() *C.char {
	return C.CString(drainFlowRouterDiagnostics())
}

//export FlowRouterGenerateKeyPair
func FlowRouterGenerateKeyPair() *C.char {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		bridgeState.Lock()
		bridgeState.err = fmt.Sprintf("generate WireGuard key: %v", err)
		bridgeState.Unlock()
		return C.CString("")
	}
	payload, err := json.Marshal(map[string]string{
		"private_key": base64.StdEncoding.EncodeToString(privateKey.Bytes()),
		"public_key":  base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
	})
	if err != nil {
		bridgeState.Lock()
		bridgeState.err = fmt.Sprintf("encode WireGuard key: %v", err)
		bridgeState.Unlock()
		return C.CString("")
	}
	return C.CString(string(payload))
}

//export FlowRouterFree
func FlowRouterFree(value *C.char) {
	C.free(unsafe.Pointer(value))
}

func main() {}
