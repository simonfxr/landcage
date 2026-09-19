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

// publicPolicyEnvKey is the user's own policy variable for --policy-json-from-env.
const publicPolicyEnvKey = "LANDCAGE_POLICY_JSON"

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
	if err := setCommandArgs(&a, cmdArgs); err != nil {
		p.Fail(err.Error())
	}

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

	// Dry-run without policy: just print detected kernel features.
	if a.DryRun && a.Policy == "" && !a.PolicyJSON && !a.PolicyStdin && len(a.RO) == 0 && len(a.RW) == 0 {
		if len(a.TemplateVar) > 0 || len(a.OptionalTemplate) > 0 {
			p.Fail("--var/--optional-var require a .json.j2 policy template")
		}
		if len(a.Cmd) > 0 {
			p.Fail("--dry-run without a policy does not accept a command")
		}
		printKernelFeatures(os.Stdout)
		return
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
	if a.DryRun {
		if err := policy.DryRun(pol, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
			os.Exit(1)
		}
		return
	}

	env, err := payloadEnv(pol)
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
		os.Exit(1)
	}

	// Before enforcement, and before the payload env (which may rewrite PATH).
	bin, err := exec.LookPath(a.Cmd[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
		os.Exit(127)
	}

	if pol.Unshare.Enabled() {
		code, ok := forkChild(pol, env, bin, a.Cmd)
		if ok {
			os.Exit(code)
		}
		fmt.Fprintf(os.Stderr, "landcage: namespace unavailable (nested sandbox?), continuing with landlock only\n")
	}

	runSandboxed(pol, env, bin, a.Cmd)
}

// payloadEnv resolves the environment the payload must see. The re-exec'd child
// runs with exactly this environment, plus the pipe fds in childStartup.
func payloadEnv(pol *policy.Policy) (policy.Environ, error) {
	env := policy.ProcessEnv()
	delete(env, publicPolicyEnvKey)
	return policy.ApplyEnv(pol, env)
}

func printKernelFeatures(w io.Writer) {
	feat, err := policy.DetectFeatures()
	if err != nil {
		fmt.Fprintf(w, "Kernel features: unavailable (%v)\n", err)
		return
	}
	fmt.Fprintf(w, "Kernel features: %s\n", feat.String())
}

// childMain is the entry point for the re-exec'd child process (PID 1 in new namespaces).
func childMain() {
	runtime.LockOSThread()

	setupFD, err := childFD(setupFDEnvKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: child: %v\n", err)
		os.Exit(1)
	}
	startupFD, err := childFD(startupFDEnvKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: child: %v\n", err)
		os.Exit(1)
	}

	// Plumbing must never reach the payload.
	os.Unsetenv(childEnvKey)
	os.Unsetenv(setupFDEnvKey)
	os.Unsetenv(startupFDEnvKey)

	startup, err := readChildStartup(startupFD)
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: child: %v\n", err)
		os.Exit(1)
	}

	pol, err := policy.Parse(startup.Policy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: child: %v\n", err)
		os.Exit(1)
	}

	if pol.Unshare != nil && pol.Unshare.MountProc {
		if err := mountProc(); err != nil {
			os.Exit(1) // parent sees EOF on the setup pipe and falls back
		}
	}

	dropAllCaps()

	syscall.Write(setupFD, []byte("ok"))
	syscall.Close(setupFD)

	// The command is the args after "--".
	_, cmdArgs := splitAtDash(os.Args[1:])
	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "landcage: child: no command")
		os.Exit(1)
	}

	// Already the payload env: re-applying the env rules would double PATH edits.
	runSandboxed(pol, policy.ProcessEnv(), startup.Bin, cmdArgs)
}

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
			s := os.Getenv(publicPolicyEnvKey)
			if s == "" {
				fmt.Fprintf(os.Stderr, "landcage: %s environment variable is not set\n", publicPolicyEnvKey)
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

func setCommandArgs(a *args, command []string) error {
	if len(a.Cmd) > 0 {
		return fmt.Errorf("command must follow --")
	}
	a.Cmd = command
	return nil
}

func (a args) Usage() string {
	var sb strings.Builder
	sb.WriteString("landcage [options] -- <command> [args...]\n")
	return sb.String()
}
