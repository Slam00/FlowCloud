package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

var flowRouterLogSink = func(message string) {
	log.Printf("FlowRouter: %s", message)
}

var flowRouterDiagnostics struct {
	sync.Mutex
	entries []string
}

const flowRouterDiagnosticsLimit = 1024

func flowRouterLogf(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	entry := fmt.Sprintf("%s FlowRouter: %s", time.Now().Format("2006-01-02 15:04:05.000"), message)
	flowRouterDiagnostics.Lock()
	flowRouterDiagnostics.entries = append(flowRouterDiagnostics.entries, entry)
	if overflow := len(flowRouterDiagnostics.entries) - flowRouterDiagnosticsLimit; overflow > 0 {
		copy(flowRouterDiagnostics.entries, flowRouterDiagnostics.entries[overflow:])
		flowRouterDiagnostics.entries = flowRouterDiagnostics.entries[:flowRouterDiagnosticsLimit]
	}
	flowRouterDiagnostics.Unlock()
	flowRouterLogSink(message)
}

func drainFlowRouterDiagnostics() string {
	flowRouterDiagnostics.Lock()
	defer flowRouterDiagnostics.Unlock()
	if len(flowRouterDiagnostics.entries) == 0 {
		return ""
	}
	result := strings.Join(flowRouterDiagnostics.entries, "\n") + "\n"
	flowRouterDiagnostics.entries = flowRouterDiagnostics.entries[:0]
	return result
}
