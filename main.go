package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"github.com/alexflint/go-arg"
	"github.com/simonfxr/landcage/policy"
)

type args struct {
	DryRun           bool     `arg:"--dry-run" help:"show resolved rules without enforcing"`
	RO               []string `arg:"--ro,separate" help:"additional read-only path (rx)"`
	RW               []string `arg:"--rw,separate" help:"additional read-write path (rwxcd+refer)"`
	Policy           string   `arg:"--policy,-p" help:"policy JSON file or .j2 template"`
	PolicyJSON       bool     `arg:"--policy-json-from-env" help:"read policy JSON from LANDCAGE_POLICY_JSON env var (cleared for child)"`
	TemplateVar      []string `arg:"--var,separate" help:"required template variable KEY=VALUE; must be mentioned as var.KEY in .j2 policy"`
	OptionalTemplate []string `arg:"--optional-var,separate" help:"optional template variable KEY=VALUE; may be unused"`
	Cmd              []string `arg:"positional" help:"command to execute (after --)"`
}

func (args) Description() string {
	return "landcage - Landlock-based process sandbox\n\nExamples:\n  landcage -p policy.json -- cmd args...\n  landcage -p policy.json.j2 --var profile=default --optional-var debug=1 -- cmd args...\n  landcage --policy-json-from-env -- cmd args...\n  landcage --rw /project --ro /usr -- cmd args..."
}

func main() {
	// Save original args before modification (needed for re-exec)
	origArgs := os.Args[1:]

	// Split at "--" for go-arg (it doesn't handle -- natively for positionals)
	goArgs, cmdArgs := splitAtDash(origArgs)
	os.Args = append([]string{os.Args[0]}, goArgs...)

	var a args
	p := arg.MustParse(&a)
	a.Cmd = cmdArgs

	if !a.DryRun && len(a.Cmd) == 0 {
		p.Fail("command is required (use -- to separate)")
	}

	// Build policy
	var pol *policy.Policy
	if a.Policy != "" && a.PolicyJSON {
		p.Fail("--policy and --policy-json-from-env are mutually exclusive")
	}
	templateVars, err := parseKeyValueFlags(a.TemplateVar, "--var")
	if err != nil {
		p.Fail(err.Error())
	}
	optionalTemplateVars, err := parseKeyValueFlags(a.OptionalTemplate, "--optional-var")
	if err != nil {
		p.Fail(err.Error())
	}
	if err := checkNoSharedKeys(templateVars, optionalTemplateVars, "--var", "--optional-var"); err != nil {
		p.Fail(err.Error())
	}
	if a.Policy != "" {
		opts := policy.DefaultOptions()
		opts.TemplateVars = templateVars
		opts.OptionalTemplateVars = optionalTemplateVars
		pol, err = policy.LoadWithOptions(a.Policy, &opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
			os.Exit(1)
		}
	} else if a.PolicyJSON {
		if len(templateVars) > 0 || len(optionalTemplateVars) > 0 {
			p.Fail("--var/--optional-var require a .j2 policy template file")
		}
		raw := os.Getenv("LANDCAGE_POLICY_JSON")
		if raw == "" {
			fmt.Fprintln(os.Stderr, "landcage: LANDCAGE_POLICY_JSON environment variable is not set")
			os.Exit(1)
		}
		var err error
		pol, err = policy.Parse([]byte(raw))
		if err != nil {
			fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
			os.Exit(1)
		}
	} else if len(a.RO) > 0 || len(a.RW) > 0 {
		if len(templateVars) > 0 || len(optionalTemplateVars) > 0 {
			p.Fail("--var/--optional-var require a .j2 policy template file")
		}
		pol = &policy.Policy{Name: "cli"}
	} else {
		p.Fail("either --policy, --policy-json-from-env, or --rw/--ro flags are required")
	}

	// Namespace isolation via clone(2). The child process is created in all new
	// namespaces simultaneously — it's PID 1 in the PID ns and root (uid 0) in
	// the user ns (giving it capabilities for mount). Falls back to Landlock-only
	// if namespace creation fails (e.g. nested sandbox).
	if pol.Unshare.Enabled() && !isChild {
		code, ok := forkChild(pol.Unshare, origArgs)
		if ok {
			os.Exit(code)
		}
		fmt.Fprintf(os.Stderr, "landcage: namespace unavailable (nested sandbox?), continuing with landlock only\n")
	}

	// Child (PID 1): mount /proc, drop caps, signal success to parent.
	// LockOSThread ensures cap drop + ForkExec happen on the same thread
	// (caps are per-thread on Linux).
	if isChild {
		runtime.LockOSThread()
		setupFD := -1
		if fdStr := os.Getenv(setupFDEnvKey); fdStr != "" {
			fmt.Sscanf(fdStr, "%d", &setupFD)
		}
		os.Unsetenv(childEnvKey)
		os.Unsetenv(setupFDEnvKey)

		if pol.Unshare != nil && pol.Unshare.MountProc {
			if err := mountProc(); err != nil {
				os.Exit(1) // parent detects via pipe EOF → falls back
			}
		}
		// Drop all capabilities — no longer needed after mount.
		// Prevents target from inheriting CAP_SYS_ADMIN.
		dropAllCaps()

		// Signal parent that setup succeeded, then close the pipe.
		if setupFD >= 0 {
			syscall.Write(setupFD, []byte("ok"))
			syscall.Close(setupFD)
		}
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

	// Create options from process environment.
	// Clear LANDCAGE_POLICY_JSON now — after any forkChild so the child got it,
	// but before DefaultOptions captures the env, so the target never sees it.
	if a.PolicyJSON {
		os.Unsetenv("LANDCAGE_POLICY_JSON")
	}

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

	// Exec target
	bin, err := exec.LookPath(a.Cmd[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
		os.Exit(127)
	}

	// If we're PID 1 (child/reaper), use ForkExec + reaper loop to reap orphans.
	if isChild {
		os.Exit(reaperExec(bin, a.Cmd, env.ToSlice()))
	}

	if err := syscall.Exec(bin, a.Cmd, env.ToSlice()); err != nil {
		fmt.Fprintf(os.Stderr, "landcage: exec: %v\n", err)
		os.Exit(126)
	}
}

func checkNoSharedKeys(a, b map[string]string, aName, bName string) error {
	for key := range a {
		if _, ok := b[key]; ok {
			return fmt.Errorf("%s and %s cannot both specify %s", aName, bName, key)
		}
	}
	return nil
}

func parseKeyValueFlags(values []string, flagName string) (map[string]string, error) {
	out := make(map[string]string, len(values))
	for _, value := range values {
		key, val, ok := strings.Cut(value, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("%s must be KEY=VALUE", flagName)
		}
		if _, exists := out[key]; exists {
			return nil, fmt.Errorf("%s specified more than once: %s", flagName, key)
		}
		out[key] = val
	}
	return out, nil
}

func splitAtDash(args []string) (before, after []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func (a args) Usage() string {
	var sb strings.Builder
	sb.WriteString("landcage [options] -- <command> [args...]\n")
	return sb.String()
}
