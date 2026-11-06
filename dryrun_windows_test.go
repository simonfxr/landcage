//go:build windows

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/simonfxr/landcage/policy"
)

func TestWindowsKernelFeaturesUseNativePSEC(t *testing.T) {
	var got, want bytes.Buffer
	printKernelFeatures(&got)
	policy.PrintSandboxFeatures(&want)
	if got.String() != want.String() || !strings.Contains(got.String(), "Windows PSEC API support:") {
		t.Fatalf("CLI feature reporting did not dispatch to native PSEC:\n%s", got.String())
	}
	if !strings.HasPrefix(got.String(), "Kernel features: Windows PSEC") ||
		strings.Contains(got.String(), "Landlock") || strings.Contains(got.String(), "ABI ") {
		t.Fatalf("CLI feature reporting used Landlock fallback:\n%s", got.String())
	}
}
