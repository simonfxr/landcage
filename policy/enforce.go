package policy

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	ll "github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// Enforce applies the policy: resolves globs and enforces the Landlock ruleset.
// All variable expansion must have been performed before calling Enforce (via
// template rendering at load time).
func Enforce(p *Policy) error {
	feat, err := DetectFeatures()
	if err != nil {
		return err
	}

	if err := validatePolicyFeatures(p, feat); err != nil {
		return err
	}

	cfg, err := buildConfig(p, feat)
	if err != nil {
		return fmt.Errorf("building landlock config: %w", err)
	}

	var fsRules []ll.Rule
	for i, r := range p.FS {
		rules, err := buildFSRules(&r, feat)
		if err != nil {
			if r.IgnoreMissing && isPathError(err) {
				continue
			}
			return fmt.Errorf("fs rule %d (%s): %w", i, r.Path, err)
		}
		fsRules = append(fsRules, rules...)
	}

	var netRules []ll.Rule
	for _, r := range p.Net.Rules {
		netRules = append(netRules, buildNetRules(&r)...)
	}

	allRules := make([]ll.Rule, 0, len(fsRules)+len(netRules))
	allRules = append(allRules, fsRules...)
	allRules = append(allRules, netRules...)
	if err := cfg.Restrict(allRules...); err != nil {
		return fmt.Errorf("enforcing landlock: %w", err)
	}
	return nil
}

// validatePolicyFeatures checks that the policy does not request features
// the current kernel cannot provide.
func validatePolicyFeatures(p *Policy, feat LandlockFeatures) error {
	for i, r := range p.FS {
		unsupported := feat.ValidateFSAccess(&r)
		if len(unsupported) > 0 {
			return fmt.Errorf("fs rule %d (%s): unsupported access flags on kernel ABI %d: %s",
				i, r.Path, feat.ABI, strings.Join(unsupported, "; "))
		}
	}

	if err := feat.ValidateNet(&p.Net); err != nil {
		return err
	}

	if err := feat.ValidateIPC(p.IPC); err != nil {
		return err
	}

	return nil
}

// buildConfig creates a go-landlock Config with the correct handled access
// sets for the detected kernel features. Only includes access categories
// (net, scoped) that are requested by the policy.
func buildConfig(p *Policy, feat LandlockFeatures) (ll.Config, error) {
	args := []any{feat.MaxFSAccess()}

	if len(p.Net.Rules) > 0 && feat.SupportsNet() {
		args = append(args, feat.MaxNetAccess())
	}

	scopedFlags, err := resolveScopes(p.IPC, feat)
	if err != nil {
		return ll.Config{}, err
	}
	if scopedFlags != 0 {
		args = append(args, scopedFlags)
	}

	cfg, err := ll.NewConfig(args...)
	if err != nil {
		return ll.Config{}, fmt.Errorf("new config: %w", err)
	}
	return *cfg, nil
}

type ipcMode int

const (
	ipcIncludeScopes ipcMode = iota
	ipcExcludeScopes
	ipcHardDenyUnavailable
)

// resolveIPC determines how to handle IPC scopes.
// Exists alongside resolveScopes only to support TestResolveIPC — the production
// code path uses resolveScopes, which returns the actual ScopedSet bitmask.
// Keep both in sync if IPC logic changes.
func resolveIPC(ipc *IPCConfig, feat LandlockFeatures) ipcMode {
	abstractUnix := ""
	signal := ""
	if ipc != nil {
		abstractUnix = ipc.AbstractUnix
		signal = ipc.Signal
	}

	if abstractUnix == "allow" && signal == "allow" {
		return ipcExcludeScopes
	}
	if !feat.SupportsScoped() {
		if abstractUnix == "deny" || signal == "deny" {
			return ipcHardDenyUnavailable
		}
		return ipcExcludeScopes
	}
	return ipcIncludeScopes
}

// resolveScopes returns the ScopedSet bitmask to use, or an error for
// hard deny on unsupported kernels.
func resolveScopes(ipc *IPCConfig, feat LandlockFeatures) (ll.ScopedSet, error) {
	abstractUnix := ""
	signal := ""
	if ipc != nil {
		abstractUnix = ipc.AbstractUnix
		signal = ipc.Signal
	}

	if !feat.SupportsScoped() {
		if abstractUnix == "deny" || signal == "deny" {
			return 0, fmt.Errorf("ipc \"deny\" requires Landlock ABI >= 6 (detected: %d)", feat.ABI)
		}
		return 0, nil
	}

	var scoped ll.ScopedSet
	if abstractUnix != "allow" {
		scoped |= llsys.ScopeAbstractUnixSocket
	}
	if signal != "allow" {
		scoped |= llsys.ScopeSignal
	}
	return scoped, nil
}

func buildFSRules(r *FSRule, feat LandlockFeatures) ([]ll.Rule, error) {
	path := r.Path
	if path == "" {
		if r.IgnoreMissing {
			return nil, nil
		}
		return nil, fmt.Errorf("path is empty")
	}

	if r.CreateDir != "" {
		mode, _ := parseOctalMode(r.CreateDir)
		if err := os.MkdirAll(path, mode); err != nil {
			return nil, fmt.Errorf("creating directory: %w", err)
		}
	}

	paths, err := resolvePath(path)
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
		access, err := fsAccessSet(r, fi.IsDir(), feat)
		if err != nil {
			return nil, fmt.Errorf("path %s: %w", p, err)
		}
		rules = append(rules, ll.PathAccess(access, p))
	}
	return rules, nil
}

// fsAccessSet translates a policy FSRule into a go-landlock AccessFSSet.
// The feat parameter gates ABI-dependent flags (e.g., truncate is silently
// dropped on pre-ABI-3 kernels so that write-only policies remain usable).
func fsAccessSet(r *FSRule, isDir bool, feat LandlockFeatures) (ll.AccessFSSet, error) {
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
			access |= llsys.AccessFSWriteFile
			if feat.SupportsTruncate() {
				access |= llsys.AccessFSTruncate
			}
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
			access |= llsys.AccessFSResolveUnix
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
