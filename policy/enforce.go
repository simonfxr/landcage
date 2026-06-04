package policy

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	ll "github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// ABI version to config mapping (max rights per version).
var abiConfigs = []struct {
	fs     ll.AccessFSSet
	net    ll.AccessNetSet
	scoped ll.ScopedSet
}{
	{}, // V0 — no support
	{fs: (1 << 13) - 1},                                           // V1
	{fs: (1 << 14) - 1},                                           // V2
	{fs: (1 << 15) - 1},                                           // V3
	{fs: (1 << 15) - 1, net: (1 << 2) - 1},                       // V4
	{fs: (1 << 16) - 1, net: (1 << 2) - 1},                       // V5
	{fs: (1 << 16) - 1, net: (1 << 2) - 1, scoped: (1 << 2) - 1}, // V6
	{fs: (1 << 16) - 1, net: (1 << 2) - 1, scoped: (1 << 2) - 1}, // V7
	{fs: (1 << 16) - 1, net: (1 << 2) - 1, scoped: (1 << 2) - 1}, // V8
}

// Enforce applies the policy: expands variables, creates directories,
// resolves globs, and enforces the Landlock ruleset.
func Enforce(p *Policy) error {
	// Detect kernel ABI version
	abi, err := llsys.LandlockGetABIVersion()
	if err != nil {
		return fmt.Errorf("landlock not available: %w", err)
	}
	if abi < 1 {
		return fmt.Errorf("landlock ABI version %d not usable", abi)
	}

	// Determine IPC scope flags
	scopedFlags, err := resolveScopes(p.IPC, abi)
	if err != nil {
		return err
	}

	// Build config for detected ABI version
	cfg, err := buildConfig(abi, scopedFlags)
	if err != nil {
		return fmt.Errorf("building landlock config: %w", err)
	}

	// Build filesystem rules
	exp := NewExpander()
	var fsRules []ll.Rule
	for i, r := range p.FS {
		rules, err := buildFSRules(exp, &r)
		if err != nil {
			if r.IgnoreMissing && isPathError(err) {
				continue
			}
			return fmt.Errorf("fs rule %d (%s): %w", i, r.Path, err)
		}
		fsRules = append(fsRules, rules...)
	}

	// Build network rules
	var netRules []ll.Rule
	for _, r := range p.Net {
		netRules = append(netRules, buildNetRules(&r)...)
	}

	// Combine and enforce
	allRules := make([]ll.Rule, 0, len(fsRules)+len(netRules))
	allRules = append(allRules, fsRules...)
	allRules = append(allRules, netRules...)
	if err := cfg.Restrict(allRules...); err != nil {
		return fmt.Errorf("enforcing landlock: %w", err)
	}
	return nil
}

type ipcMode int

const (
	ipcIncludeScopes       ipcMode = iota // kernel supports scopes, include them
	ipcExcludeScopes                      // explicitly "allow" or kernel too old (best-effort)
	ipcHardDenyUnavailable                // "deny" requested but kernel can't enforce
)

// resolveIPC determines how to handle IPC scopes (kept for testing).
// Values: "" = best-effort deny, "deny" = hard deny, "allow" = no restriction.
func resolveIPC(ipc *IPCConfig, abi int) ipcMode {
	abstractUnix := "" // default: best-effort deny
	signal := ""

	if ipc != nil {
		abstractUnix = ipc.AbstractUnix
		signal = ipc.Signal
	}

	// If everything is explicitly "allow", exclude scopes entirely
	if abstractUnix == "allow" && signal == "allow" {
		return ipcExcludeScopes
	}

	// If kernel doesn't support scopes (< V6)
	if abi < 6 {
		// Hard "deny" requested but can't enforce
		if abstractUnix == "deny" || signal == "deny" {
			return ipcHardDenyUnavailable
		}
		// Best-effort (omitted/"") — silently skip on old kernel
		return ipcExcludeScopes
	}

	// Kernel supports scopes
	return ipcIncludeScopes
}

// resolveScopes returns the ScopedSet bitmask to use, or an error for hard deny on unsupported kernels.
func resolveScopes(ipc *IPCConfig, abi int) (ll.ScopedSet, error) {
	abstractUnix := "" // default: best-effort deny
	signal := ""

	if ipc != nil {
		abstractUnix = ipc.AbstractUnix
		signal = ipc.Signal
	}

	// Check for hard deny on unsupported kernel
	if abi < 6 {
		if abstractUnix == "deny" || signal == "deny" {
			return 0, fmt.Errorf("ipc \"deny\" requires Landlock ABI >= 6 (detected: %d)", abi)
		}
		// Best-effort or allow — no scopes available
		return 0, nil
	}

	// Kernel supports scopes — build per-flag bitmask
	var scoped ll.ScopedSet
	if abstractUnix != "allow" {
		scoped |= llsys.ScopeAbstractUnixSocket
	}
	if signal != "allow" {
		scoped |= llsys.ScopeSignal
	}
	return scoped, nil
}

// buildConfig creates a landlock Config for the detected ABI version.
func buildConfig(abi int, scoped ll.ScopedSet) (ll.Config, error) {
	idx := abi
	if idx >= len(abiConfigs) {
		idx = len(abiConfigs) - 1
	}
	info := abiConfigs[idx]

	var args []any
	if info.fs != 0 {
		args = append(args, info.fs)
	}
	if info.net != 0 {
		args = append(args, info.net)
	}
	if scoped != 0 {
		args = append(args, scoped)
	}

	cfg, err := ll.NewConfig(args...)
	if err != nil {
		return ll.Config{}, err
	}
	return *cfg, nil
}

func buildFSRules(exp *Expander, r *FSRule) ([]ll.Rule, error) {
	ep, err := exp.Expand(r.Path)
	if err != nil {
		if r.IgnoreMissing {
			return nil, nil
		}
		return nil, err
	}

	path := ep.String()
	if path == "" {
		if r.IgnoreMissing {
			return nil, nil
		}
		return nil, fmt.Errorf("path is empty after variable expansion")
	}

	if r.CreateDir != "" {
		mode, _ := parseOctalMode(r.CreateDir)
		if err := os.MkdirAll(path, mode); err != nil {
			return nil, fmt.Errorf("creating directory: %w", err)
		}
	}

	paths, err := ep.Resolve()
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		if r.IgnoreMissing {
			return nil, nil
		}
		return nil, fmt.Errorf("glob matched no paths: %s", path)
	}

	var rules []ll.Rule
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			if r.IgnoreMissing && os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		access, err := fsAccessSet(r, fi.IsDir())
		if err != nil {
			return nil, fmt.Errorf("path %s: %w", p, err)
		}
		rules = append(rules, ll.PathAccess(access, p))
	}
	return rules, nil
}

func fsAccessSet(r *FSRule, isDir bool) (ll.AccessFSSet, error) {
	var access ll.AccessFSSet
	for _, ch := range r.Access {
		switch ch {
		case 'r':
			if isDir {
				access |= llsys.AccessFSReadFile | llsys.AccessFSReadDir
			} else {
				access |= llsys.AccessFSReadFile
			}
		case 'w':
			access |= llsys.AccessFSWriteFile | llsys.AccessFSTruncate
		case 'x':
			access |= llsys.AccessFSExecute
		case 'c':
			if !isDir {
				return 0, fmt.Errorf("'c' (create) access is invalid on files")
			}
			access |= llsys.AccessFSMakeReg | llsys.AccessFSMakeDir |
				llsys.AccessFSMakeSym | llsys.AccessFSMakeFifo | llsys.AccessFSMakeSock
		case 'd':
			if !isDir {
				return 0, fmt.Errorf("'d' (delete) access is invalid on files")
			}
			access |= llsys.AccessFSRemoveFile | llsys.AccessFSRemoveDir
		case 'u':
			// RESOLVE_UNIX — not yet in go-landlock (V9), skip for now
		}
	}
	if r.Refer {
		access |= llsys.AccessFSRefer
	}
	if r.IoctlDev {
		access |= llsys.AccessFSIoctlDev
	}
	return access, nil
}

func buildNetRules(r *NetRule) []ll.Rule {
	var rules []ll.Rule
	switch r.Access {
	case "connect":
		rules = append(rules, ll.ConnectTCP(r.Port))
	case "bind":
		rules = append(rules, ll.BindTCP(r.Port))
	case "connect+bind":
		rules = append(rules, ll.ConnectTCP(r.Port))
		rules = append(rules, ll.BindTCP(r.Port))
	}
	return rules
}

func isPathError(err error) bool {
	if os.IsNotExist(err) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && errno == syscall.ENOTDIR {
		return true
	}
	return false
}
