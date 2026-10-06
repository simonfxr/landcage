package policy

import (
	"fmt"
	"strings"
)

// LandlockFeatures describes the Landlock capabilities detected on the running kernel.
//
// All capability queries should go through this type's methods rather than
// inspecting the raw ABI field directly. This keeps feature-gating logic in one
// place and makes the minimum-ABI relationships explicit.
type LandlockFeatures struct {
	ABI int // raw kernel ABI version (0 = unavailable)
}

// FeaturesForABI creates a LandlockFeatures for a synthetic ABI level.
// Intended for testing; production code uses DetectFeatures.
func FeaturesForABI(abi int) LandlockFeatures {
	return LandlockFeatures{ABI: abi}
}

// ---- High-level capability queries ----

// SupportsNet reports whether the kernel can restrict TCP bind/connect.
func (f LandlockFeatures) SupportsNet() bool { return f.ABI >= 4 }

// SupportsUDP reports whether the kernel can restrict UDP bind, connect,
// and send-to-port (ABI 10+).
func (f LandlockFeatures) SupportsUDP() bool { return f.ABI >= 10 }

// SupportsScoped reports whether the kernel can restrict IPC scopes
// (abstract UNIX sockets and signals).
func (f LandlockFeatures) SupportsScoped() bool { return f.ABI >= 6 }

// SupportsTSync reports whether the kernel supports thread-synchronous
// Landlock enforcement (ABI 8+).
func (f LandlockFeatures) SupportsTSync() bool { return f.ABI >= 8 }

// SupportsAtomicNoNewPrivs reports whether restrict_self can set no_new_privs
// as part of enforcement (ABI 11+). go-landlock selects this automatically;
// older kernels require a separate prctl before applying the ruleset.
func (f LandlockFeatures) SupportsAtomicNoNewPrivs() bool { return f.ABI >= 11 }

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

// ValidateNet checks whether the kernel supports network restrictions.
func (f LandlockFeatures) ValidateNet(net *NetConfig) error {
	if net == nil || net.Allow || len(net.Rules) == 0 {
		return nil
	}
	for i, r := range net.Rules {
		if r.usesUDP() && !f.SupportsUDP() {
			return fmt.Errorf("net rule %d: udp requires Landlock ABI >= 10 (Linux >= 7.2; kernel has ABI %d)", i, f.ABI)
		}
	}
	if !f.SupportsNet() {
		return fmt.Errorf("network rules require Landlock ABI >= 4 (Linux >= 6.7; kernel has ABI %d)", f.ABI)
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
		if f.SupportsUDP() {
			parts = append(parts, "net=tcp+udp")
		} else {
			parts = append(parts, "net=tcp")
		}
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
	if f.SupportsAtomicNoNewPrivs() {
		parts = append(parts, "nnp=atomic")
	} else if f.ABI >= 1 {
		parts = append(parts, "nnp=prctl")
	}

	return "LandlockFeatures{" + strings.Join(parts, " ") + "}"
}
