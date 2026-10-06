//go:build !linux

package main

import (
	"fmt"
	"os"

	"github.com/simonfxr/landcage/policy"
)

// setupNamespaces refuses a private network namespace. Unshare on Darwin is
// reported once by runSandboxed, which then continues with Seatbelt.
func setupNamespaces(pol *policy.Policy, env policy.Environ, bin string, cmd []string, net networkMode) {
	if net.private() {
		fmt.Fprintln(os.Stderr, "landcage: private network namespace setup failed; refusing host network fallback")
		os.Exit(1)
	}
}

func mountProc() error {
	return fmt.Errorf("mount namespaces are not supported on this platform")
}

func dropAllCaps() error {
	return fmt.Errorf("dropping capabilities is not supported on this platform")
}
