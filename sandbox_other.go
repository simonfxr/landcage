//go:build !linux && !windows && !(darwin && cgo)

package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/simonfxr/landcage/policy"
)

// runSandboxed is the enforce path for targets without Landlock and without
// a cgo Seatbelt apply. Darwin without cgo cannot call libsandbox.
func runSandboxed(pol *policy.Policy, env policy.Environ, bin string, cmd []string) {
	if runtime.GOOS == "darwin" {
		fmt.Fprintln(os.Stderr, "landcage: Darwin enforcement needs cgo")
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "landcage: sandbox is not supported on %s\n", runtime.GOOS)
	os.Exit(1)
}
