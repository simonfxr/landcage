package policy

import (
	"fmt"
	"strings"

	ll "github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// LandlockFeatures describes the Landlock capabilities detected on the running kernel.
//
// All capability queries should go through this type's methods rather than
// inspecting the raw ABI field directly. This keeps feature-gating logic in one
// place and makes the minimum-ABI relationships explicit.
type LandlockFeatures struct {
	ABI int // raw kernel ABI version (0 = unavailable)
}

// DetectFeatures queries the kernel for Landlock support.
func DetectFeatures() (LandlockFeatures, error) {
	abi, err := llsys.LandlockGetABIVersion()
	if err != nil {
		return LandlockFeatures{}, fmt.Errorf("landlock not available: %w", err)
	}
	if abi < 1 {
		return LandlockFeatures{}, fmt.Errorf("landlock ABI version %d not usable", abi)
	}
	return LandlockFeatures{ABI: abi}, nil
}

// FeaturesForABI creates a LandlockFeatures for a synthetic ABI level.
// Intended for testing; production code uses DetectFeatures.
func FeaturesForABI(abi int) LandlockFeatures {
	return LandlockFeatures{ABI: abi}
}

// ---- High-level capability queries ----

// SupportsNet reports whether the kernel can restrict TCP bind/connect.
func (f LandlockFeatures) SupportsNet() bool { return f.ABI >= 4 }

// SupportsScoped reports whether the kernel can restrict IPC scopes
// (abstract UNIX sockets and signals).
func (f LandlockFeatures) SupportsScoped() bool { return f.ABI >= 6 }

// SupportsTSync reports whether the kernel supports thread-synchronous
// Landlock enforcement (ABI 8+).
func (f LandlockFeatures) SupportsTSync() bool { return f.ABI >= 8 }

// SupportsRefer reports whether the kernel can restrict file reparenting
// (refer access, ABI 2+).
func (f LandlockFeatures) SupportsRefer() bool { return f.ABI >= 2 }

// SupportsTruncate reports whether the kernel can restrict file truncation
// (ABI 3+).
func (f LandlockFeatures) SupportsTruncate() bool { return f.ABI >= 3 }

// SupportsIoctlDev reports whether the kernel can restrict ioctl on device
// files (ABI 5+).
func (f LandlockFeatures) SupportsIoctlDev() bool { return f.ABI >= 5 }

// SupportsResolveUnix reports whether the kernel can restrict connect(2)
// and sendmsg(2) on pathname UNIX domain sockets (ABI 9+).
func (f LandlockFeatures) SupportsResolveUnix() bool { return f.ABI >= 9 }

// ---- Access-set constructors ----

// MaxFSAccess returns the maximum AccessFSSet supported at this ABI level.
//
// Bitmask mapping:
//
//	V1: bits 0-12 (13 flags) — execute through make_sym
//	V2: bits 0-13 (14 flags) — adds refer
//	V3: bits 0-14 (15 flags) — adds truncate
//	V5: bits 0-15 (16 flags) — adds ioctl_dev
//	V9: bits 0-16 (17 flags) — adds resolve_unix
func (f LandlockFeatures) MaxFSAccess() ll.AccessFSSet {
	switch {
	case f.ABI >= 9:
		return ll.AccessFSSet((1 << 17) - 1)
	case f.ABI >= 5:
		return ll.AccessFSSet((1 << 16) - 1)
	case f.ABI >= 3:
		return ll.AccessFSSet((1 << 15) - 1)
	case f.ABI >= 2:
		return ll.AccessFSSet((1 << 14) - 1)
	default: // ABI 1
		return ll.AccessFSSet((1 << 13) - 1)
	}
}

// MaxNetAccess returns the full AccessNetSet (TCP bind + connect).
// Network access rights have not grown since their introduction at ABI 4.
func (f LandlockFeatures) MaxNetAccess() ll.AccessNetSet {
	return ll.AccessNetSet((1 << 2) - 1)
}

// ---- Validation ----

// minABIForFSAccess maps Landlock FS access flags to their minimum kernel ABI.
//
// Only flags introduced after V1 are listed. All V1 flags (execute, write_file,
// read_file, read_dir, remove_dir, remove_file, make_char, make_dir, make_reg,
// make_sock, make_fifo, make_block, make_sym) have an implicit min ABI of 1 and
// therefore always pass validation when Landlock is available.
var minABIForFSAccess = map[ll.AccessFSSet]int{
	llsys.AccessFSRefer:       2,
	llsys.AccessFSTruncate:    3,
	llsys.AccessFSIoctlDev:    5,
	llsys.AccessFSResolveUnix: 9,
}

// ValidateFSAccess checks whether the kernel supports all FS access flags
// requested by the rule. Returns a slice of human-readable descriptions for
// any unsupported flags, or nil if all flags are supported by the kernel.
//
// Syntactic errors (e.g., "c" on a file) are not caught here — they are
// deferred to fsAccessSet during enforcement, which produces better
// context-specific messages.
func (f LandlockFeatures) ValidateFSAccess(rule *FSRule) (unsupported []string) {
	// Use dir=true for widest flag coverage; syntactic enforcement
	// ("c"/"d" on files) happens in fsAccessSet during enforcement.
	access, err := fsAccessSet(rule, true, f)
	if err != nil {
		return nil // syntactic errors surface during enforcement
	}

	var missing []string
	for flag, minABI := range minABIForFSAccess {
		if access&flag != 0 && f.ABI < minABI {
			name := fsAccessFlagName(flag)
			missing = append(missing,
				fmt.Sprintf("%s (requires ABI >= %d, kernel has ABI %d)", name, minABI, f.ABI))
		}
	}
	return missing
}

// ValidateNet checks whether the kernel supports network restrictions.
func (f LandlockFeatures) ValidateNet(net *NetConfig) error {
	if net == nil || net.Allow || len(net.Rules) == 0 {
		return nil
	}
	if !f.SupportsNet() {
		return fmt.Errorf("network rules require Landlock ABI >= 4 (kernel has ABI %d)", f.ABI)
	}
	return nil
}

// ValidateIPC checks whether the kernel supports IPC scoping.
func (f LandlockFeatures) ValidateIPC(ipc *IPCConfig) error {
	if ipc == nil || !ipc.hasHardDeny() {
		return nil
	}
	if !f.SupportsScoped() {
		return fmt.Errorf("ipc \"deny\" requires Landlock ABI >= 6 (kernel has ABI %d)", f.ABI)
	}
	return nil
}

func (c *IPCConfig) hasHardDeny() bool {
	return c != nil && (c.AbstractUnix == "deny" || c.Signal == "deny")
}

// fsAccessFlagName returns a human-readable name for an AccessFSSet flag.
func fsAccessFlagName(flag ll.AccessFSSet) string {
	switch flag {
	case llsys.AccessFSRefer:
		return "refer"
	case llsys.AccessFSTruncate:
		return "truncate"
	case llsys.AccessFSIoctlDev:
		return "ioctl_dev"
	case llsys.AccessFSResolveUnix:
		return "resolve_unix"
	default:
		return fmt.Sprintf("flag(%d)", flag)
	}
}

// String returns a human-readable summary of the detected features.
func (f LandlockFeatures) String() string {
	var parts []string
	parts = append(parts, fmt.Sprintf("ABI=%d", f.ABI))

	fsFlags := []string{"V1"}
	if f.SupportsRefer() {
		fsFlags = append(fsFlags, "refer")
	}
	if f.SupportsTruncate() {
		fsFlags = append(fsFlags, "truncate")
	}
	if f.SupportsIoctlDev() {
		fsFlags = append(fsFlags, "ioctl_dev")
	}
	if f.SupportsResolveUnix() {
		fsFlags = append(fsFlags, "resolve_unix")
	}
	parts = append(parts, "fs="+strings.Join(fsFlags, "+"))

	if f.SupportsNet() {
		parts = append(parts, "net=yes")
	} else {
		parts = append(parts, "net=no")
	}
	if f.SupportsScoped() {
		parts = append(parts, "scoped=yes")
	} else {
		parts = append(parts, "scoped=no")
	}
	if f.SupportsTSync() {
		parts = append(parts, "tsync=yes")
	}

	return "LandlockFeatures{" + strings.Join(parts, " ") + "}"
}
