//go:build linux

package policy

import (
	"fmt"
	"strings"
	"testing"

	ll "github.com/landlock-lsm/go-landlock/landlock"
)

func TestFeatureAccessSetsMatchUpstreamABIs(t *testing.T) {
	// In particular, ABI 11 introduces an enforcement flag, not new access
	// rights. Keep our custom config aligned with upstream without raising
	// the minimum kernel ABI or widening the policy.
	versions := []ll.Config{
		ll.V1, ll.V2, ll.V3, ll.V4, ll.V5, ll.V6,
		ll.V7, ll.V8, ll.V9, ll.V10, ll.V11,
	}
	for i, want := range versions {
		t.Run(fmt.Sprint(i+1), func(t *testing.T) {
			got, err := buildConfig(&Policy{}, FeaturesForABI(i+1))
			if err != nil {
				t.Fatal(err)
			}
			if got.HandledAccessFS != want.HandledAccessFS ||
				got.HandledAccessNet != want.HandledAccessNet ||
				got.Scoped != want.Scoped {
				t.Errorf("config = %v, want upstream access sets %v", got, want)
			}
		})
	}
}

func TestABI11NoNewPrivsDetection(t *testing.T) {
	for _, abi := range []int{1, 7, 8, 9, 10, 11, 12} {
		t.Run(fmt.Sprint(abi), func(t *testing.T) {
			feat := FeaturesForABI(abi)
			if got, want := feat.SupportsAtomicNoNewPrivs(), abi >= 11; got != want {
				t.Fatalf("SupportsAtomicNoNewPrivs = %v, want %v", got, want)
			}
			want := "nnp=prctl"
			if abi >= 11 {
				want = "nnp=atomic"
			}
			if !strings.Contains(feat.String(), want) {
				t.Errorf("features = %s, want %s", feat, want)
			}
		})
	}
}

func TestABI11PolicySemanticsUnchanged(t *testing.T) {
	for _, netAllow := range []bool{false, true} {
		for _, ipc := range []*IPCConfig{nil, {AbstractUnix: "allow", Signal: "allow"}, {Signal: "deny"}} {
			p := &Policy{Net: NetConfig{Allow: netAllow}, IPC: ipc}
			old, err := buildConfig(p, FeaturesForABI(10))
			if err != nil {
				t.Fatal(err)
			}
			for _, abi := range []int{11, 12} {
				got, err := buildConfig(p, FeaturesForABI(abi))
				if err != nil {
					t.Fatal(err)
				}
				if got.HandledAccessFS != old.HandledAccessFS ||
					got.HandledAccessNet != old.HandledAccessNet ||
					got.Scoped != old.Scoped {
					t.Errorf("ABI %d: config = %v, want ABI 10 rights %v", abi, got, old)
				}
			}
		}
	}
}
