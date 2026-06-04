package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/simonfxr/landcage/policy"
)

func main() {
	dryRun := flag.Bool("dry-run", false, "show resolved rules without enforcing")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: landcage [flags] <policy.json> -- <command> [args...]\n\nFlags:\n")
		flag.PrintDefaults()
	}

	// Parse flags up to "--"
	var flagArgs []string
	rest := os.Args[1:]
	for i, a := range rest {
		if a == "--" {
			flagArgs = rest[:i]
			rest = rest[i:]
			break
		}
	}
	if flagArgs == nil {
		flagArgs = rest
		rest = nil
	}

	flag.CommandLine.Parse(flagArgs)

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(2)
	}

	policyFile := flag.Arg(0)

	// Load and validate policy
	p, err := policy.Load(policyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
		os.Exit(1)
	}

	if *dryRun {
		if err := policy.DryRun(p, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Need command after "--"
	if len(rest) < 2 { // rest[0] is "--"
		flag.Usage()
		os.Exit(2)
	}
	cmdArgs := rest[1:]

	// Enforce sandbox
	if err := policy.Enforce(p); err != nil {
		fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
		os.Exit(1)
	}

	// Exec child process
	bin, err := exec.LookPath(cmdArgs[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
		os.Exit(127)
	}

	if err := syscall.Exec(bin, cmdArgs, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "landcage: exec: %v\n", err)
		os.Exit(126)
	}
}
