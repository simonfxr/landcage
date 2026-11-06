//go:build darwin && cgo

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDarwinCLIRestrictedSystemPaths(t *testing.T) {
	dir := t.TempDir()
	cli := filepath.Join(dir, "landcage")
	if out, err := exec.Command("go", "build", "-o", cli, ".").CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, out)
	}

	secret := filepath.Join(dir, "secret")
	const contents = "ungranted descendant contents\n"
	if err := os.WriteFile(secret, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	ungrantedExe := filepath.Join(dir, "echo.sh")
	if err := os.WriteFile(ungrantedExe, []byte("#!/bin/sh\nexec /bin/echo hi\n"), 0700); err != nil {
		t.Fatal(err)
	}

	// Do not grant --ro /: that hides dyld's need to open the root directory
	// during shared-cache startup. Its literal root grant must not grant reads
	// or execution of descendants outside the policy.
	for _, tc := range []struct {
		name string
		ro   string
		cmd  []string
		code int
		want string
	}{
		{name: "startup", cmd: []string{"/bin/echo", "hi"}, want: "hi\n"},
		{name: "root-metadata", cmd: []string{"/usr/bin/stat", "-f", "%HT", "/"}, want: "Directory\n"},
		{name: "deny-descendant-metadata", cmd: []string{"/usr/bin/stat", secret}, code: 1, want: "Operation not permitted"},
		{name: "deny-descendant-read", cmd: []string{"/bin/cat", secret}, code: 1, want: "Operation not permitted"},
		{name: "grant-descendant-read", ro: secret, cmd: []string{"/bin/cat", secret}, want: contents},
		{name: "deny-descendant-exec", cmd: []string{ungrantedExe, "hi"}, code: 126, want: "landcage: exec: operation not permitted"},
		{name: "grant-descendant-exec", ro: ungrantedExe, cmd: []string{ungrantedExe, "hi"}, want: "hi\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"--ro", "/bin", "--ro", "/usr", "--ro", "/System"}
			if tc.ro != "" {
				args = append(args, "--ro", tc.ro)
			}
			args = append(args, "--")
			args = append(args, tc.cmd...)
			out, err := exec.Command(cli, args...).CombinedOutput()
			code := 0
			if err != nil {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					t.Fatalf("run CLI: %v\n%s", err, out)
				}
				code = exitErr.ExitCode()
			}
			if code != tc.code {
				t.Fatalf("exit code = %d, want %d (error: %v)\n%s", code, tc.code, err, out)
			}
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("output = %q, want %q", out, tc.want)
			}
		})
	}
}
