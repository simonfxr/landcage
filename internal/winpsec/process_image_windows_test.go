package winpsec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinProcessImageRequiresExplicitGrant(t *testing.T) {
	dir := t.TempDir()
	bin := testPathFile(t, dir, "payload.exe")
	if _, _, err := pinProcessPaths(Spec{}, bin); err == nil || !strings.Contains(err.Error(), "explicit rx") {
		t.Fatalf("ungranted image error = %v", err)
	}
	// This rejection is preflight only: no PSEC environment or payload starts,
	// even on a host without the native API or a nonstandard caller token.
	code, err := Run(Spec{}, bin, []string{bin}, nil)
	if code != 0 || err == nil || !strings.Contains(err.Error(), "explicit rx") {
		t.Fatalf("Run(ungranted image) = %#x, %v", code, err)
	}
	for _, spec := range []Spec{
		{ReadOnlyPaths: []string{dir}},
		{ReadOnlyPaths: []string{bin}},
		{ReadWritePaths: []string{dir}},
	} {
		path, release, err := pinProcessPaths(spec, bin)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.EqualFold(path, bin) {
			t.Errorf("resolved image = %q, want %q", path, bin)
		}
		if err := release(); err != nil {
			t.Fatal(err)
		}
		if err := release(); err != nil {
			t.Fatalf("release must be idempotent: %v", err)
		}
	}
}

func TestPinProcessImageRejectsDirectoriesDeniesAndPrefixConfusion(t *testing.T) {
	dir := t.TempDir()
	grant := filepath.Join(dir, "grant")
	outside := filepath.Join(dir, "grant-other")
	for _, path := range []string{grant, outside} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	bin := testPathFile(t, outside, "payload.exe")
	for _, test := range []struct {
		spec Spec
		bin  string
	}{
		{Spec{ReadOnlyPaths: []string{dir}}, dir},
		{Spec{ReadOnlyPaths: []string{grant}}, bin},
		{Spec{ReadOnlyPaths: []string{dir}, DeniedPaths: []string{outside}}, bin},
		{Spec{ReadOnlyPaths: []string{dir}}, filepath.Join(dir, "*.exe")},
		{Spec{ReadOnlyPaths: []string{dir}}, `\\server\share\payload.exe`},
	} {
		if _, release, err := pinProcessPaths(test.spec, test.bin); err == nil {
			release()
			t.Errorf("unexpectedly accepted image %q, spec %+v", test.bin, test.spec)
		}
	}
}

func TestPinProcessImageDoesNotWidenOrMutateSpec(t *testing.T) {
	dir := t.TempDir()
	bin := testPathFile(t, dir, "payload.exe")
	backing := []string{dir, "untouched"}
	spec := Spec{ReadOnlyPaths: backing[:1]}
	_, release, err := pinProcessPaths(spec, bin)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if len(spec.ReadOnlyPaths) != 1 || backing[1] != "untouched" {
		t.Fatalf("pinning widened or mutated spec: %+v, %q", spec, backing)
	}
	// Both the grant anchor and image must be held until explicitly released.
	if err := os.Rename(bin, filepath.Join(dir, "moved.exe")); err == nil {
		t.Fatal("initial image was not pinned")
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(bin, filepath.Join(dir, "moved.exe")); err != nil {
		t.Fatalf("released image remains pinned: %v", err)
	}
}

func TestPinProcessImageRejectsReparseTraversal(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	testPathFile(t, target, "payload.exe")
	junction := testPathJunction(t, dir, target)
	if _, release, err := pinProcessPaths(Spec{ReadOnlyPaths: []string{dir}}, filepath.Join(junction, "payload.exe")); err == nil {
		release()
		t.Fatal("initial image through junction was accepted")
	}
}
