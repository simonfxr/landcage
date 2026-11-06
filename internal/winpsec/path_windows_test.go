package winpsec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func testPathFile(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testPathJunction(t *testing.T, dir, target string) string {
	t.Helper()
	path := filepath.Join(dir, "junction")
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", path, target).CombinedOutput(); err != nil {
		t.Fatalf("creating unprivileged junction: %v: %s", err, out)
	}
	return path
}

func TestPinPathsHoldAnchorsAndRelease(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "anchor")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := testPathFile(t, dir, "file")
	release, err := PinPaths(Spec{ReadOnlyPaths: []string{file}})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	moved := filepath.Join(root, "renamed")
	if err := os.Rename(dir, moved); err == nil {
		t.Fatal("pinned ancestor could be renamed")
	}
	name, err := windows.UTF16PtrFromString(file)
	if err != nil {
		t.Fatal(err)
	}
	flags := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	if handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, flags, nil, windows.OPEN_EXISTING, 0, 0); err == nil {
		windows.CloseHandle(handle)
		t.Fatal("pinned final component could be opened for writing")
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatalf("release was not idempotent: %v", err)
	}
	if err := os.Rename(dir, moved); err != nil {
		t.Fatalf("ancestor handle leaked after release: %v", err)
	}
	if err := os.WriteFile(filepath.Join(moved, "file"), []byte("changed"), 0o600); err != nil {
		t.Fatalf("final handle leaked after release: %v", err)
	}
}

func TestPinDirectoryDoesNotOpenDescendantHandles(t *testing.T) {
	dir := t.TempDir()
	file := testPathFile(t, dir, "child")
	release, err := PinPaths(Spec{ReadWritePaths: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := os.WriteFile(file, []byte("changed"), 0o600); err != nil {
		t.Fatalf("directory pin interfered with descendant operations: %v", err)
	}
}

func TestPinPathsRechecksReplacedGrantAndRollsBack(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	file := testPathFile(t, root, "file")
	resolved, err := ResolvePaths(target)
	if err != nil || len(resolved) != 1 {
		t.Fatalf("initial resolution: %v, %v", resolved, err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatalf("ResolvePaths retained an inspection handle: %v", err)
	}
	replacement := filepath.Join(root, "replacement")
	if err := os.Mkdir(replacement, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", target, replacement).CombinedOutput(); err != nil {
		t.Fatalf("replacing grant with junction: %v: %s", err, out)
	}
	release, err := PinPaths(Spec{ReadOnlyPaths: []string{file, resolved[0].Path}})
	if err == nil || !strings.Contains(err.Error(), "reparse") || release != nil {
		t.Fatalf("replaced grant accepted: release present=%t, error=%v", release != nil, err)
	}
	if err := os.Rename(file, filepath.Join(root, "moved")); err != nil {
		t.Fatalf("partial pin leaked after failure: %v", err)
	}
}

func TestResolvePathsRejectsJunctionsAndGlobs(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	testPathFile(t, target, "file")
	junction := testPathJunction(t, root, target)
	for _, path := range []string{junction, filepath.Join(junction, "file"), filepath.Join(junction, "*"), filepath.Join(root, "j*")} {
		if _, err := ResolvePaths(path); err == nil || !strings.Contains(err.Error(), "reparse") {
			t.Errorf("junction path %q not rejected before traversal: %v", path, err)
		}
	}
	for _, spec := range []Spec{
		{ReadOnlyPaths: []string{junction}},
		{ReadWritePaths: []string{junction}},
		{DeniedPaths: []string{junction}},
	} {
		if release, err := PinPaths(spec); err == nil {
			release()
			t.Error("PinPaths accepted a junction grant")
		}
	}
}

func TestResolvePathsRejectsRemoteSymlinkWithoutFollowing(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "remote-link")
	linkName, err := windows.UTF16PtrFromString(link)
	if err != nil {
		t.Fatal(err)
	}
	// Use the native creation API: os.Symlink may stat a target to infer its
	// type. This test itself must never probe an unsandboxed network target.
	target, err := windows.UTF16PtrFromString(`\\127.0.0.1\landcage-no-network-probe\missing`)
	if err != nil {
		t.Fatal(err)
	}
	err = windows.CreateSymbolicLink(linkName, target, windows.SYMBOLIC_LINK_FLAG_DIRECTORY|2)
	if err == windows.ERROR_INVALID_PARAMETER {
		err = windows.CreateSymbolicLink(linkName, target, windows.SYMBOLIC_LINK_FLAG_DIRECTORY)
	}
	if err != nil {
		t.Skipf("symlink privilege/developer mode unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := windows.RemoveDirectory(linkName); err != nil {
			t.Errorf("removing remote symlink without traversal: %v", err)
		}
	})
	for _, path := range []string{link, filepath.Join(link, "file"), filepath.Join(link, "*"), filepath.Join(root, "remote-*")} {
		if _, err := ResolvePaths(path); err == nil || !strings.Contains(err.Error(), "reparse") {
			t.Errorf("remote symlink path %q not rejected: %v", path, err)
		}
	}
	if release, err := PinPaths(Spec{ReadOnlyPaths: []string{link}}); err == nil {
		release()
		t.Error("PinPaths accepted remote symlink")
	}
}

func TestPinPathsRejectsUnsafeNamespaces(t *testing.T) {
	for _, path := range []string{`\\server\share\file`, `\\?\C:\Windows`, `C:relative`, `C:\NUL.txt`, `C:\file:stream`, `C:\*`} {
		if release, err := PinPaths(Spec{ReadOnlyPaths: []string{path}}); err == nil {
			release()
			t.Errorf("unsafe path accepted: %q", path)
		}
	}
	release, err := PinPaths(Spec{})
	if err != nil || release == nil {
		t.Fatalf("empty spec pin: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

func TestResolvePathsRejectsForeignDOSMappings(t *testing.T) {
	var volume string
	for letter := 'Z'; letter >= 'P'; letter-- {
		candidate := string(letter) + ":"
		name, _ := windows.UTF16PtrFromString(candidate)
		var buffer [32768]uint16
		if _, err := windows.QueryDosDevice(name, &buffer[0], uint32(len(buffer))); err == windows.ERROR_FILE_NOT_FOUND {
			volume = candidate
			break
		}
	}
	if volume == "" {
		t.Skip("no unused DOS drive letter for temporary namespace test")
	}
	for _, target := range []string{`\Device\Mup\127.0.0.1\landcage-no-network-probe`, `\??\C:\local-alias`} {
		t.Run(target, func(t *testing.T) {
			name, _ := windows.UTF16PtrFromString(volume)
			value, _ := windows.UTF16PtrFromString(target)
			flags := uint32(windows.DDD_RAW_TARGET_PATH | windows.DDD_NO_BROADCAST_SYSTEM)
			// DefineDosDevice only creates a DOS symbolic-link string. It does
			// not open/probe this remote or SUBST-like target.
			if err := windows.DefineDosDevice(flags, name, value); err != nil {
				t.Skipf("temporary DOS mapping unavailable: %v", err)
			}
			defer func() {
				if err := windows.DefineDosDevice(flags|windows.DDD_REMOVE_DEFINITION|windows.DDD_EXACT_MATCH_ON_REMOVE, name, value); err != nil {
					t.Errorf("removing temporary DOS mapping: %v", err)
				}
			}()
			for _, path := range []string{volume + `\file`, volume + `\*`} {
				if _, err := ResolvePaths(path); err == nil || !strings.Contains(err.Error(), "only local Windows disk volumes") {
					t.Errorf("foreign DOS target %q not rejected: %v", target, err)
				}
			}
		})
	}
}
