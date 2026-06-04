package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/alexflint/go-arg"
	"github.com/simonfxr/landcage/policy"
)

type args struct {
	DryRun bool     `arg:"--dry-run" help:"show resolved rules without enforcing"`
	RO     []string `arg:"--ro,separate" help:"additional read-only path (rx)"`
	RW     []string `arg:"--rw,separate" help:"additional read-write path (rwxcd+refer)"`
	Policy string   `arg:"--policy,-p" help:"policy JSON file"`
	Cmd    []string `arg:"positional" help:"command to execute (after --)"`
}

func (args) Description() string {
	return "landcage - Landlock-based process sandbox\n\nExamples:\n  landcage -p policy.json -- cmd args...\n  landcage --rw /project --ro /usr -- cmd args..."
}

func main() {
	// Split at "--" for go-arg (it doesn't handle -- natively for positionals)
	goArgs, cmdArgs := splitAtDash(os.Args[1:])
	os.Args = append([]string{os.Args[0]}, goArgs...)

	var a args
	p := arg.MustParse(&a)
	a.Cmd = cmdArgs

	if !a.DryRun && len(a.Cmd) == 0 {
		p.Fail("command is required (use -- to separate)")
	}

	// Build policy
	var pol *policy.Policy
	if a.Policy != "" {
		var err error
		pol, err = policy.Load(a.Policy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
			os.Exit(1)
		}
	} else if len(a.RO) > 0 || len(a.RW) > 0 {
		pol = &policy.Policy{Name: "cli"}
	} else {
		p.Fail("either --policy or --rw/--ro flags are required")
	}

	// Append CLI path flags to policy
	for _, path := range a.RO {
		pol.FS = append(pol.FS, policy.FSRule{
			Path:          path,
			Access:        "rx",
			IgnoreMissing: true,
		})
	}
	for _, path := range a.RW {
		pol.FS = append(pol.FS, policy.FSRule{
			Path:          path,
			Access:        "rwxcd",
			Refer:         true,
			IgnoreMissing: true,
		})
	}

	// Create options from process environment
	opts := policy.DefaultOptions()

	if a.DryRun {
		if err := policy.DryRun(pol, &opts, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Enforce sandbox
	if err := policy.Enforce(pol, &opts); err != nil {
		fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
		os.Exit(1)
	}

	// Apply environment changes (after Enforce so fs expansion uses original env)
	env, err := policy.ApplyEnv(pol, &opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
		os.Exit(1)
	}

	// Exec child process
	bin, err := exec.LookPath(a.Cmd[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
		os.Exit(127)
	}

	if err := syscall.Exec(bin, a.Cmd, env.ToSlice()); err != nil {
		fmt.Fprintf(os.Stderr, "landcage: exec: %v\n", err)
		os.Exit(126)
	}
}

func splitAtDash(args []string) (before, after []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	// No "--" found — check if last args look like a command (heuristic: no leading -)
	// For safety, treat everything as flags/options
	return args, nil
}

func (a args) Usage() string {
	var sb strings.Builder
	sb.WriteString("landcage [options] -- <command> [args...]\n")
	return sb.String()
}
