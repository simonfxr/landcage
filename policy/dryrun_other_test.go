//go:build !windows

package policy

import (
	"bytes"
	"fmt"
	"testing"
)

func TestDryRunPreservesDefaultPlatformOutput(t *testing.T) {
	p := &Policy{
		Name: "platform-dispatch",
		FS:   []FSRule{{Path: t.TempDir(), Access: "rx"}},
		Net:  NetConfig{Allow: true},
		IPC:  &IPCConfig{AbstractUnix: "allow", Signal: "allow"},
	}
	var want, got bytes.Buffer
	wantErr := dryRunDefault(p, &want)
	gotErr := DryRun(p, &got)
	if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || got.String() != want.String() {
		t.Fatalf("platform dispatch changed dry-run output:\ngot %s (%v)\nwant %s (%v)", got.String(), gotErr, want.String(), wantErr)
	}
}

func TestSandboxFeaturesPreservesDefaultPlatformOutput(t *testing.T) {
	var want, got bytes.Buffer
	feat, err := DetectFeatures()
	if err != nil {
		fmt.Fprintf(&want, "Kernel features: unavailable (%v)\n", err)
	} else {
		fmt.Fprintf(&want, "Kernel features: %s\n", feat.String())
	}
	PrintSandboxFeatures(&got)
	if got.String() != want.String() {
		t.Fatalf("feature output changed: got %q, want %q", got.String(), want.String())
	}
}
