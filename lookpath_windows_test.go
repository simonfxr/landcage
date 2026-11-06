package main

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func lookupTestEnvironment(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("PATH", "")
	t.Setenv("PATHEXT", ".COM;.EXE;.BAT;.CMD")
	t.Setenv("NoDefaultCurrentDirectoryInExePath", "")
	if err := os.Unsetenv("NoDefaultCurrentDirectoryInExePath"); err != nil {
		t.Fatal(err)
	}
	return dir
}

// These are deliberately NOT executable images. Lookup must inspect files,
// never start a process to test them.
func lookupTestFile(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("not an executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireLookupPath(t *testing.T, name, want string) {
	t.Helper()
	path, err := resolveExecutable(name)
	if err != nil || !strings.EqualFold(path, want) || !filepath.IsAbs(path) {
		t.Fatalf("resolveExecutable(%q) = %q, %v; want absolute %q", name, path, err, want)
	}
}

func TestResolveExecutableDirectLocalPaths(t *testing.T) {
	dir := lookupTestEnvironment(t)
	bin := lookupTestFile(t, dir, "payload.exe")
	t.Setenv("PATH", `\\server.invalid\share`)
	requireLookupPath(t, bin, bin) // Direct lookup never inspects PATH.
	requireLookupPath(t, `.\payload`, bin)
	requireLookupPath(t, "./payload.exe", bin)
	custom := lookupTestFile(t, dir, "payload.custom")
	requireLookupPath(t, custom, custom) // Explicit extension need not be PATHEXT.
	fallback := lookupTestFile(t, dir, "double.custom.exe")
	requireLookupPath(t, filepath.Join(dir, "double.custom"), fallback)
	if err := os.Mkdir(filepath.Join(dir, "directory.exe"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveExecutable(filepath.Join(dir, "directory.exe")); err == nil {
		t.Fatal("directory accepted as executable")
	}
}

func TestResolveExecutablePathAndPATHEXT(t *testing.T) {
	lookupTestEnvironment(t)
	dir := t.TempDir()
	exe := lookupTestFile(t, dir, "payload.exe")
	custom := lookupTestFile(t, dir, "payload.custom")
	t.Setenv("PATH", `"`+dir+`"`)
	t.Setenv("PATHEXT", "CUSTOM;.EXE")
	requireLookupPath(t, "payload", custom)
	t.Setenv("PATHEXT", ".EXE;.CUSTOM")
	requireLookupPath(t, "payload", exe)
	plain := lookupTestFile(t, dir, "plain")
	t.Setenv("PATHEXT", ";")
	requireLookupPath(t, "plain", plain)
	t.Setenv("PATHEXT", "")
	if _, err := resolveExecutable("plain"); !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("extensionless file with default PATHEXT: %v", err)
	}
}

func TestResolveExecutableErrDotCannotBeDisabled(t *testing.T) {
	dir := lookupTestEnvironment(t)
	bin := lookupTestFile(t, dir, "payload.exe")
	t.Setenv("GODEBUG", "execerrdot=0")
	if path, err := resolveExecutable("payload"); !errors.Is(err, exec.ErrDot) || !strings.EqualFold(path, bin) {
		t.Fatalf("implicit current-directory lookup = %q, %v; want ErrDot", path, err)
	}
	requireLookupPath(t, `.\payload`, bin)
	t.Setenv("PATH", dir)
	requireLookupPath(t, "payload", bin) // Explicit absolute PATH exception.
	t.Setenv("NoDefaultCurrentDirectoryInExePath", "")
	t.Setenv("PATH", "")
	if _, err := resolveExecutable("payload"); !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("disabled default current directory: %v", err)
	}
	t.Setenv("PATH", ".")
	if _, err := resolveExecutable("payload"); !errors.Is(err, exec.ErrDot) {
		t.Fatalf("relative PATH entry must not enable implicit execution: %v", err)
	}
}

func TestResolveExecutableErrDotShadowAndHardlink(t *testing.T) {
	cwd := lookupTestEnvironment(t)
	dot := lookupTestFile(t, cwd, "payload.exe")
	dir := t.TempDir()
	pathBin := lookupTestFile(t, dir, "payload.exe")
	t.Setenv("PATH", dir)
	if _, err := resolveExecutable("payload"); !errors.Is(err, exec.ErrDot) {
		t.Fatalf("CWD shadows a different PATH executable: %v", err)
	}
	if err := os.Remove(pathBin); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(dot, pathBin); err != nil {
		t.Fatal(err)
	}
	requireLookupPath(t, "payload", pathBin)
}

func TestResolveExecutableRejectsUnsafeNamespacesAndGlobs(t *testing.T) {
	lookupTestEnvironment(t)
	for _, name := range []string{
		`\\server.invalid\share\payload.exe`, `\\?\C:\payload.exe`,
		`\\.\C:\payload.exe`, `C:payload.exe`, `payload:stream.exe`,
		`*.exe`, `payload?.exe`, `payload[0].exe`, "payload\x00.exe", ".", `.\..`,
	} {
		if _, err := resolveExecutable(name); err == nil {
			t.Errorf("unsafe command accepted: %q", name)
		}
	}
	valid := t.TempDir()
	lookupTestFile(t, valid, "payload.exe")
	t.Setenv("NoDefaultCurrentDirectoryInExePath", "")
	for _, unsafe := range []string{`\\server.invalid\share`, `\\?\C:\bin`, `C:bin`, `C:\wild*`} {
		t.Setenv("PATH", unsafe+";"+valid)
		if _, err := resolveExecutable("payload"); err == nil || !strings.Contains(err.Error(), "explicit local") {
			t.Errorf("unsafe PATH entry %q silently skipped: %v", unsafe, err)
		}
	}
	for _, ext := range []string{".exe;\\server\\share", ".exe;*", ".exe;.bad ", ".exe;:stream"} {
		t.Setenv("PATHEXT", ext)
		if _, err := resolveExecutable("payload"); err == nil {
			t.Errorf("unsafe PATHEXT accepted: %q", ext)
		}
	}
}

func TestResolveExecutableRejectsReparseDirectories(t *testing.T) {
	root := lookupTestEnvironment(t)
	target := t.TempDir()
	lookupTestFile(t, target, "payload.exe")
	junction := lookupTestJunction(t, filepath.Join(root, "junction"), target)
	for _, name := range []string{filepath.Join(junction, "payload.exe"), filepath.Join(junction, "payload")} {
		if _, err := resolveExecutable(name); err == nil || !strings.Contains(err.Error(), "reparse") {
			t.Fatalf("reparse executable lookup = %v", err)
		}
	}
	t.Setenv("NoDefaultCurrentDirectoryInExePath", "")
	t.Setenv("PATH", junction+";"+target)
	if _, err := resolveExecutable("payload"); err == nil || !strings.Contains(err.Error(), "reparse") {
		t.Fatalf("reparse PATH entry silently skipped: %v", err)
	}
}

// Create an unprivileged junction directly: these lookup tests execute no
// subprocess, not even cmd.exe for mklink.
func lookupTestJunction(t *testing.T, path, target string) string {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	substitute := utf16.Encode([]rune(`\??\` + target))
	printName := utf16.Encode([]rune(target))
	names := append(append(append(substitute[:len(substitute):len(substitute)], 0), printName...), 0)
	buffer := make([]byte, 16+len(names)*2)
	binary.LittleEndian.PutUint32(buffer[0:4], windows.IO_REPARSE_TAG_MOUNT_POINT)
	binary.LittleEndian.PutUint16(buffer[4:6], uint16(len(buffer)-8))
	binary.LittleEndian.PutUint16(buffer[10:12], uint16(len(substitute)*2))
	binary.LittleEndian.PutUint16(buffer[12:14], uint16((len(substitute)+1)*2))
	binary.LittleEndian.PutUint16(buffer[14:16], uint16(len(printName)*2))
	for i, value := range names {
		binary.LittleEndian.PutUint16(buffer[16+i*2:], value)
	}
	var returned uint32
	if err := windows.DeviceIoControl(handle, windows.FSCTL_SET_REPARSE_POINT, &buffer[0], uint32(len(buffer)), nil, 0, &returned, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(path); err != nil {
			t.Errorf("remove test junction: %v", err)
		}
	})
	return path
}
