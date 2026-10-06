//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/simonfxr/landcage/policy"
)

// runSandboxed enforces the policy and execs bin with the resolved payload env.
func runSandboxed(pol *policy.Policy, env policy.Environ, bin string, cmd []string) {
	if err := policy.Enforce(pol); err != nil {
		fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
		os.Exit(1)
	}

	argv := env.ToSlice()

	if isChild {
		os.Exit(reaperExec(bin, cmd, argv))
	}

	if err := syscall.Exec(bin, cmd, argv); err != nil {
		fmt.Fprintf(os.Stderr, "landcage: exec: %v\n", err)
		os.Exit(126)
	}
}
