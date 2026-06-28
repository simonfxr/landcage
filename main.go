package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"github.com/alexflint/go-arg"
	"github.com/simonfxr/landcage/policy"
)

// Internal env var used to pass the resolved policy to the re-exec'd child.
const policyEnvKey = "_LANDCAGE_POLICY"

type args struct {
	DryRun           bool     `arg:"--dry-run" help:"show resolved rules without enforcing"`
	Expand           bool     `arg:"--expand" help:"expand policy and output JSON to stdout (no enforcement)"`
	RO               []string `arg:"--ro,separate" help:"additional read-only path (rx)"`
	RW               []string `arg:"--rw,separate" help:"additional read-write path (rwxcd+refer)"`
	Policy           string   `arg:"--policy,-p" help:"policy file (.json or .json.j2 template)"`
	PolicyJSON       bool     `arg:"--policy-json-from-env" help:"read expanded policy JSON from LANDCAGE_POLICY_JSON env var"`
	PolicyStdin      bool     `arg:"--policy-json-from-stdin" help:"read expanded policy JSON from stdin"`
	TemplateVar      []string `arg:"--var,separate" help:"required template variable KEY=VALUE (.json.j2 only)"`
	OptionalTemplate []string `arg:"--optional-var,separate" help:"optional template variable KEY=VALUE (.json.j2 only)"`
	Cmd              []string `arg:"positional" help:"command to execute (after --)"`
}

func (args) Description() string {
	return "landcage - Landlock-based process sandbox\n\nExamples:\n  landcage -p policy.json -- cmd args...\n  landcage -p policy.json.j2 --var profile=default -- cmd args...\n  landcage --expand -p policy.json.j2 --var profile=default\n  landcage --expand -p policy.json.j2 | my-filter | landcage --policy-json-from-stdin -- cmd\n  landcage --policy-json-from-env -- cmd args...\n  landcage --rw /project --ro /usr -- cmd args..."
}

func main() {
	// Child path: the re-exec'd child receives the fully-resolved policy
	// via an internal env var. It skips all argument parsing for policy sources.
	if isChild {
		childMain()
		return
	}

	// Split at "--" for go-arg (it doesn't handle -- natively for positionals)
	goArgs, cmdArgs := splitAtDash(os.Args[1:])
	os.Args = append([]string{os.Args[0]}, goArgs...)

	var a args
	p := arg.MustParse(&a)
	a.Cmd = cmdArgs

	if !a.DryRun && !a.Expand && len(a.Cmd) == 0 {
		p.Fail("command is required (use -- to separate)")
	}

	if a.Expand {
		if a.Policy == "" {
			p.Fail("--expand requires --policy/-p")
		}
		if a.DryRun {
			p.Fail("--expand and --dry-run are mutually exclusive")
		}
	}

	// Build policy
	pol := buildPolicy(&a, p)

	// Expand mode: render template → validate → pretty-print JSON to stdout
	if a.Expand {
		out, err := json.MarshalIndent(pol, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
			os.Exit(1)
		}
		os.Stdout.Write(out)
		os.Stdout.WriteString("\n")
		return
	}

	// Namespace isolation: serialize policy to env, re-exec in new namespaces.
	if pol.Unshare.Enabled() {
		code, ok := forkChild(pol, a.Cmd)
		if ok {
			os.Exit(code)
		}
		fmt.Fprintf(os.Stderr, "landcage: namespace unavailable (nested sandbox?), continuing with landlock only\n")
	}

	// No unshare (or fallback): enforce and exec directly.
	runSandboxed(pol, a.Cmd, a.DryRun)
}

// childMain is the entry point for the re-exec'd child process (PID 1 in new namespaces).
func childMain() {
	runtime.LockOSThread()

	// Read setup pipe fd.
	setupFD := -1
	if fdStr := os.Getenv(setupFDEnvKey); fdStr != "" {
		fmt.Sscanf(fdStr, "%d", &setupFD)
	}

	// Load policy from internal env var.
	raw := os.Getenv(policyEnvKey)
	if raw == "" {
		fmt.Fprintln(os.Stderr, "landcage: child: missing internal policy")
		os.Exit(1)
	}

	// Clear internal env vars immediately.
	os.Unsetenv(childEnvKey)
	os.Unsetenv(setupFDEnvKey)
	os.Unsetenv(policyEnvKey)

	pol, err := policy.Parse([]byte(raw))
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: child: %v\n", err)
		os.Exit(1)
	}

	// Perform namespace setup (mount /proc, etc.)
	if pol.Unshare != nil && pol.Unshare.MountProc {
		if err := mountProc(); err != nil {
			os.Exit(1) // parent detects via pipe EOF → falls back
		}
	}

	// Drop all capabilities — no longer needed after mount.
	dropAllCaps()

	// Signal parent that setup succeeded, then close the pipe.
	if setupFD >= 0 {
		syscall.Write(setupFD, []byte("ok"))
		syscall.Close(setupFD)
	}

	// The command is passed as the remaining args after "--".
	_, cmdArgs := splitAtDash(os.Args[1:])
	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "landcage: child: no command")
		os.Exit(1)
	}

	runSandboxed(pol, cmdArgs, false)
}

// runSandboxed enforces the policy and execs the command.
func runSandboxed(pol *policy.Policy, cmd []string, dryRun bool) {
	// Clear user-facing policy env so the target never sees it.
	os.Unsetenv("LANDCAGE_POLICY_JSON")

	if dryRun {
		if err := policy.DryRun(pol, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := policy.Enforce(pol); err != nil {
		fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
		os.Exit(1)
	}

	env, err := policy.ApplyEnv(pol, policy.ProcessEnv())
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
		os.Exit(1)
	}

	bin, err := exec.LookPath(cmd[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
		os.Exit(127)
	}

	if isChild {
		os.Exit(reaperExec(bin, cmd, env.ToSlice()))
	}

	if err := syscall.Exec(bin, cmd, env.ToSlice()); err != nil {
		fmt.Fprintf(os.Stderr, "landcage: exec: %v\n", err)
		os.Exit(126)
	}
}

// buildPolicy resolves the policy from CLI flags. All expansion, parsing,
// and validation happens here in the parent process.
func buildPolicy(a *args, p *arg.Parser) *policy.Policy {
	policySources := 0
	if a.Policy != "" {
		policySources++
	}
	if a.PolicyJSON {
		policySources++
	}
	if a.PolicyStdin {
		policySources++
	}
	if policySources > 1 {
		p.Fail("--policy, --policy-json-from-env, and --policy-json-from-stdin are mutually exclusive")
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

	var pol *policy.Policy
	if a.Policy != "" {
		isTemplate := strings.HasSuffix(a.Policy, ".json.j2")
		if !isTemplate && !strings.HasSuffix(a.Policy, ".json") {
			p.Fail("policy file must have .json or .json.j2 extension")
		}
		if !isTemplate && (len(templateVars) > 0 || len(optionalTemplateVars) > 0) {
			p.Fail("--var/--optional-var require a .json.j2 policy template")
		}
		opts := policy.DefaultOptions()
		opts.TemplateVars = templateVars
		opts.OptionalTemplateVars = optionalTemplateVars
		pol, err = policy.LoadWithOptions(a.Policy, &opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
			os.Exit(1)
		}
	} else if a.PolicyJSON || a.PolicyStdin {
		if len(templateVars) > 0 || len(optionalTemplateVars) > 0 {
			p.Fail("--var/--optional-var require a .json.j2 policy template")
		}
		var raw []byte
		if a.PolicyJSON {
			s := os.Getenv("LANDCAGE_POLICY_JSON")
			if s == "" {
				fmt.Fprintln(os.Stderr, "landcage: LANDCAGE_POLICY_JSON environment variable is not set")
				os.Exit(1)
			}
			raw = []byte(s)
		} else {
			raw, err = io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "landcage: reading stdin: %v\n", err)
				os.Exit(1)
			}
		}
		pol, err = policy.Parse(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
			os.Exit(1)
		}
	} else if len(a.RO) > 0 || len(a.RW) > 0 {
		if len(templateVars) > 0 || len(optionalTemplateVars) > 0 {
			p.Fail("--var/--optional-var require a .json.j2 policy template")
		}
		pol = &policy.Policy{Name: "cli"}
	} else {
		p.Fail("either --policy, --policy-json-from-stdin, --policy-json-from-env, or --rw/--ro flags are required")
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

	return pol
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
