package policy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func sbplTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCompileSBPLPreamble(t *testing.T) {
	profile, params, err := CompileSBPL(&Policy{Name: "empty"})
	if err != nil {
		t.Fatal(err)
	}
	if len(params) != 0 {
		t.Fatalf("params = %#v", params)
	}
	const want = `(version 1)
(deny default)
(allow process-fork)
(allow system-socket (socket-domain AF_UNIX))
(allow signal (target same-sandbox))
(allow process-info* (target same-sandbox))
(allow file-ioctl (literal "/dev/null"))
(allow file-read* file-write-data (literal "/dev/null"))
(allow file-read* (literal "/dev/urandom"))
(allow file-read* (literal "/dev/random"))
(allow file-read* (literal "/dev/zero"))
(allow mach-lookup
  (global-name "com.apple.system.logger")
  (global-name "com.apple.system.opendirectoryd.libinfo"))
`
	if profile != want {
		t.Fatalf("preamble mismatch:\n%s", profile)
	}
	if strings.Count(profile, "(allow signal") != 1 {
		t.Fatalf("signal allow widened:\n%s", profile)
	}
}

func TestCompileSBPLFileAndDirectoryFilters(t *testing.T) {
	dir := sbplTempDir(t)
	file := filepath.Join(dir, "note")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	fileProfile, fileParams, err := CompileSBPL(&Policy{
		Name: "file",
		FS:   []FSRule{{Path: file, Access: "rx", Refer: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantFile := `(allow file-read* file-map-executable process-exec (literal (param "p0")))`
	if !strings.Contains(fileProfile, wantFile) {
		t.Fatalf("file allow missing:\n%s", fileProfile)
	}
	if strings.Contains(fileProfile, "subpath") || strings.Contains(fileProfile, file) || strings.Contains(fileProfile, "refer") {
		t.Fatalf("file profile leaked path, subpath, or refer:\n%s", fileProfile)
	}
	if strings.Join(fileParams, "\x00") != strings.Join([]string{"p0", file}, "\x00") {
		t.Fatalf("file params = %#v", fileParams)
	}

	dirProfile, dirParams, err := CompileSBPL(&Policy{
		Name: "dir",
		FS:   []FSRule{{Path: dir, Access: "rwxcd", IoctlDev: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantDir := `(allow file-read* file-write-data file-map-executable process-exec file-write-create file-write-unlink file-ioctl (subpath (param "p0")))`
	if !strings.Contains(dirProfile, wantDir) {
		t.Fatalf("dir allow missing:\n%s", dirProfile)
	}
	if strings.Contains(dirProfile, dir) {
		t.Fatalf("directory path leaked into profile:\n%s", dirProfile)
	}
	if strings.Join(dirParams, "\x00") != strings.Join([]string{"p0", dir}, "\x00") {
		t.Fatalf("dir params = %#v", dirParams)
	}
}

func TestCompileSBPLCreateOnFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := CompileSBPL(&Policy{Name: "bad", FS: []FSRule{{Path: file, Access: "c"}}})
	if err == nil || !strings.Contains(err.Error(), "invalid on files") {
		t.Fatalf("expected create-on-file error, got %v", err)
	}
	_, _, err = CompileSBPL(&Policy{Name: "bad", FS: []FSRule{{Path: file, Access: "d"}}})
	if err == nil || !strings.Contains(err.Error(), "invalid on files") {
		t.Fatalf("expected delete-on-file error, got %v", err)
	}
}

func TestCompileSBPLIgnoreMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	profile, params, err := CompileSBPL(&Policy{
		Name: "skip",
		FS:   []FSRule{{Path: missing, Access: "r", IgnoreMissing: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(params) != 0 || strings.Contains(profile, "(param ") {
		t.Fatalf("missing path was not skipped: params=%#v\n%s", params, profile)
	}

	_, _, err = CompileSBPL(&Policy{Name: "fail", FS: []FSRule{{Path: missing, Access: "r"}}})
	if err == nil {
		t.Fatal("expected error for missing path")
	}

	dir := t.TempDir()
	pattern := filepath.Join(dir, "nope*")
	profile, params, err = CompileSBPL(&Policy{
		Name: "skip-glob",
		FS:   []FSRule{{Path: pattern, Access: "r", IgnoreMissing: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(params) != 0 || strings.Contains(profile, "regex") {
		t.Fatalf("empty glob was not skipped: params=%#v\n%s", params, profile)
	}
	_, _, err = CompileSBPL(&Policy{Name: "fail-glob", FS: []FSRule{{Path: pattern, Access: "r"}}})
	if err == nil || !strings.Contains(err.Error(), "glob matched no paths") {
		t.Fatalf("expected glob error, got %v", err)
	}
}

func TestCompileSBPLGlobSnapshotsFiles(t *testing.T) {
	dir := sbplTempDir(t)
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	pattern := filepath.Join(dir, "*.txt")
	profile, params, err := CompileSBPL(&Policy{
		Name: "glob",
		FS:   []FSRule{{Path: pattern, Access: "w"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"p0", "p1"} {
		if !strings.Contains(profile, fmt.Sprintf(`(allow file-write-data (literal (param %q)))`, name)) {
			t.Fatalf("glob allow missing:\n%s", profile)
		}
	}
	if strings.Contains(profile, "regex") || strings.Contains(profile, "subpath") || strings.Contains(profile, dir) {
		t.Fatalf("glob was not expanded to parameterized literals:\n%s", profile)
	}
	want := []string{"p0", filepath.Join(dir, "a.txt"), "p1", filepath.Join(dir, "b.txt")}
	if !slices.Equal(params, want) {
		t.Fatalf("params = %#v, want %#v", params, want)
	}
	// The compiled policy must not start matching new files later.
	if err := os.WriteFile(filepath.Join(dir, "future.txt"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	_, updated, err := CompileSBPL(&Policy{FS: []FSRule{{Path: pattern, Access: "w"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated) != 6 || slices.Equal(params, updated) {
		t.Fatalf("expected the new file only after recompilation: %#v, %#v", params, updated)
	}
}

func TestCompileSBPLGlobDirectorySubtrees(t *testing.T) {
	dir := sbplTempDir(t)
	project := filepath.Join(dir, "project-a")
	if err := os.MkdirAll(filepath.Join(project, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	profile, params, err := CompileSBPL(&Policy{FS: []FSRule{
		{Path: filepath.Join(dir, "project-*"), Access: "rwcdu"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(params, []string{"p0", project}) {
		t.Fatalf("params = %#v", params)
	}
	for _, want := range []string{
		`(allow file-read* file-write-data file-write-create file-write-unlink (subpath (param "p0")))`,
		`(allow network-outbound (remote unix-socket (subpath (param "p0"))))`,
		`(allow network-bind network-inbound (local unix-socket (subpath (param "p0"))))`,
	} {
		if !strings.Contains(profile, want) {
			t.Fatalf("missing recursive directory grant %s:\n%s", want, profile)
		}
	}
	if strings.Contains(profile, "regex") {
		t.Fatalf("glob still allows future matches:\n%s", profile)
	}
}

func TestCompileSBPLMixedGlobAndSymlinks(t *testing.T) {
	dir := sbplTempDir(t)
	file := filepath.Join(dir, "a-file")
	child := filepath.Join(dir, "b-dir")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	// The final glob component can itself be a symlink, not just its parent.
	target := sbplTempDir(t)
	if err := os.Symlink(target, filepath.Join(dir, "c-link")); err != nil {
		t.Fatal(err)
	}
	profile, params, err := CompileSBPL(&Policy{FS: []FSRule{
		{Path: filepath.Join(dir, "*"), Access: "rw"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(params, []string{"p0", file, "p1", child, "p2", target}) {
		t.Fatalf("params = %#v", params)
	}
	for _, want := range []string{
		`(allow file-read* file-write-data (literal (param "p0")))`,
		`(allow file-read* file-write-data (subpath (param "p1")))`,
		`(allow file-read* file-write-data (subpath (param "p2")))`,
	} {
		if !strings.Contains(profile, want) {
			t.Fatalf("missing typed grant %s:\n%s", want, profile)
		}
	}
	for _, access := range []string{"c", "d"} {
		_, _, err := CompileSBPL(&Policy{FS: []FSRule{{Path: filepath.Join(dir, "*"), Access: access}}})
		if err == nil || !strings.Contains(err.Error(), "invalid on files") {
			t.Fatalf("mixed glob %q: want file-type error, got %v", access, err)
		}
	}
}

func TestCompileSBPLNet(t *testing.T) {
	allow, _, err := CompileSBPL(&Policy{Name: "allow", Net: NetConfig{Allow: true}})
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{
		`(allow system-socket (socket-domain AF_INET) (socket-domain AF_INET6))`,
		`(allow network-outbound (remote ip "*:*"))`,
		`(allow network-bind network-inbound (local ip "*:*"))`,
	} {
		if !strings.Contains(allow, rule) {
			t.Fatalf("missing IP network grant %s:\n%s", rule, allow)
		}
	}
	if strings.Contains(allow, "(allow network*)") || strings.Contains(allow, "unix-socket") {
		t.Fatalf("net=allow bypasses filesystem socket policy:\n%s", allow)
	}

	for _, name := range []string{"omitted", "deny"} {
		t.Run(name, func(t *testing.T) {
			p := &Policy{Name: name}
			if name == "deny" {
				parsed, err := Parse([]byte(`{"name":"deny","net":"deny"}`))
				if err != nil {
					t.Fatal(err)
				}
				p = parsed
			}
			profile, _, err := CompileSBPL(p)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(profile, "network") {
				t.Fatalf("deny profile granted network:\n%s", profile)
			}
		})
	}

	profile, _, err := CompileSBPL(&Policy{
		Name: "https",
		Net:  NetConfig{Rules: []NetRule{{Port: 443, Access: "connect"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(profile, `(allow network-outbound (remote tcp "*:443"))`) {
		t.Fatalf("missing port 443:\n%s", profile)
	}
	if strings.Contains(profile, "(allow network*)") {
		t.Fatalf("port rule also granted network*:\n%s", profile)
	}

	profile, _, err = CompileSBPL(&Policy{
		Name: "ephemeral",
		Net: NetConfig{Rules: []NetRule{
			{Port: 0, Access: "bind", Proto: "any"},
			{Port: 0, Access: "connect", Proto: "udp"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`(allow network-bind (local tcp "*:*"))`,
		`(allow network-bind (local udp "*:*"))`,
		`(allow network-inbound (local tcp "*:*"))`,
		`(allow network-inbound (local udp "*:*"))`,
		`(allow network-outbound (remote udp "*:0"))`,
	} {
		if !strings.Contains(profile, want) {
			t.Fatalf("missing %s in:\n%s", want, profile)
		}
	}
}

func TestCompileSBPLBindAllowsInboundOnlyOnRequestedPort(t *testing.T) {
	for _, proto := range []string{"tcp", "udp"} {
		t.Run(proto, func(t *testing.T) {
			profile, _, err := CompileSBPL(&Policy{Net: NetConfig{Rules: []NetRule{
				{Port: 8080, Access: "bind", Proto: proto},
			}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, op := range []string{"network-bind", "network-inbound"} {
				want := `(allow ` + op + ` (local ` + proto + ` "*:8080"))`
				if !strings.Contains(profile, want) {
					t.Fatalf("missing %s in:\n%s", want, profile)
				}
			}
			if strings.Contains(profile, "network-outbound") || strings.Contains(profile, "*:*") {
				t.Fatalf("bind rule widened network permissions:\n%s", profile)
			}
		})
	}
}

func TestCompileSBPLPathDoesNotEnterProfile(t *testing.T) {
	dir := sbplTempDir(t)
	name := `weird) (allow file-write*`
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	profile, params, err := CompileSBPL(&Policy{
		Name: "inject",
		FS:   []FSRule{{Path: path, Access: "r"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The star makes this a final-component glob; its matched path still
	// goes into a parameter, never into Scheme source.
	if strings.Contains(profile, name) || strings.Contains(profile, "file-write*") {
		t.Fatalf("path text entered the profile:\n%s", profile)
	}
	if !strings.Contains(profile, `(literal (param "p0"))`) {
		t.Fatalf("missing literal param filter:\n%s", profile)
	}
	if len(params) != 2 || params[0] != "p0" || params[1] != path || strings.Contains(profile, params[1]) {
		t.Fatalf("params = %#v profile:\n%s", params, profile)
	}

	plain := filepath.Join(dir, `weird) (allow file-write`)
	if err := os.WriteFile(plain, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	profile, params, err = CompileSBPL(&Policy{
		Name: "inject-literal",
		FS:   []FSRule{{Path: plain, Access: "r"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(profile, `weird) (allow file-write`) {
		t.Fatalf("literal path entered the profile:\n%s", profile)
	}
	if !strings.Contains(profile, `(literal (param "p0"))`) {
		t.Fatalf("missing literal param filter:\n%s", profile)
	}
	if len(params) != 2 || params[0] != "p0" || params[1] != plain {
		t.Fatalf("literal params = %#v", params)
	}
}

func TestCompileSBPLDoesNotCreateDirectories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "newdir")
	_, _, err := CompileSBPL(&Policy{
		Name: "create",
		FS:   []FSRule{{Path: path, Access: "rwcd", CreateDir: "0700"}},
	})
	if err == nil {
		t.Fatal("expected missing create_dir path to fail compile")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("compile created %s: %v", path, statErr)
	}

	if err := CreatePolicyDirs(&Policy{
		Name: "create",
		FS:   []FSRule{{Path: path, Access: "rwcd", CreateDir: "0700"}},
	}); err != nil {
		t.Fatal(err)
	}
	profile, _, err := CompileSBPL(&Policy{
		Name: "create",
		FS:   []FSRule{{Path: path, Access: "rwcd", CreateDir: "0700"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(profile, "file-write-create") || !strings.Contains(profile, "(subpath (param \"p0\"))") {
		t.Fatalf("created directory profile:\n%s", profile)
	}
}

func TestCompileSBPLUnixSocket(t *testing.T) {
	sock := filepath.Join(sbplTempDir(t), "sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	profile, params, err := CompileSBPL(&Policy{
		Name: "unix",
		FS:   []FSRule{{Path: sock, Access: "u"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`(allow system-socket (socket-domain AF_UNIX))`,
		`(allow network-outbound (remote unix-socket (path-literal (param "p0"))))`,
	} {
		if !strings.Contains(profile, want) {
			t.Fatalf("missing %s in:\n%s", want, profile)
		}
	}
	if len(params) != 2 || params[1] != sock {
		t.Fatalf("params = %#v", params)
	}
	if strings.Contains(strings.TrimPrefix(profile, sbplPreamble), "file-") {
		t.Fatalf("socket-only rule granted file-data access:\n%s", profile)
	}
}

func TestCompileSBPLUnixPermissionsStaySeparate(t *testing.T) {
	dir := sbplTempDir(t)
	file := filepath.Join(dir, "regular")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, file, filepath.Join(dir, "*")} {
		t.Run(path, func(t *testing.T) {
			profile, _, err := CompileSBPL(&Policy{FS: []FSRule{{Path: path, Access: "u"}}})
			if err != nil {
				t.Fatal(err)
			}
			rules := strings.TrimPrefix(profile, sbplPreamble)
			if strings.Contains(rules, "file-") || strings.Contains(rules, "network-bind") || strings.Contains(rules, "network-inbound") {
				t.Fatalf("'u' granted data or server permissions:\n%s", rules)
			}
			filter := "path-literal"
			if path == dir {
				filter = "subpath"
			}
			want := fmt.Sprintf(`(allow network-outbound (remote unix-socket (%s (param "p0"))))`, filter)
			if !strings.Contains(rules, want) {
				t.Fatalf("missing %s:\n%s", want, rules)
			}
		})
	}
	profile, _, err := CompileSBPL(&Policy{FS: []FSRule{{Path: dir, Access: "c"}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(profile, "network-outbound") {
		t.Fatalf("'c' grants connections to existing host sockets:\n%s", profile)
	}
	if !strings.Contains(profile, `(allow network-bind network-inbound (local unix-socket (subpath (param "p0"))))`) {
		t.Fatalf("'c' does not permit socket creation:\n%s", profile)
	}
}

func TestCompileSBPLCanonicalPaths(t *testing.T) {
	dir := sbplTempDir(t)
	file := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(sbplTempDir(t), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	t.Chdir(filepath.Dir(alias))
	for _, path := range []string{
		filepath.Join(alias, "note.txt"),
		"alias/note.txt",
		"alias",
	} {
		_, params, err := CompileSBPL(&Policy{FS: []FSRule{{Path: path, Access: "r"}}})
		if err != nil {
			t.Fatal(err)
		}
		want := file
		if path == "alias" {
			want = dir
		}
		if len(params) != 2 || params[1] != want {
			t.Fatalf("path %q: params = %#v, want %q", path, params, want)
		}
	}
	for _, path := range []string{filepath.Join(alias, "*.txt"), "alias/*.txt"} {
		_, params, err := CompileSBPL(&Policy{FS: []FSRule{{Path: path, Access: "r"}}})
		if err != nil {
			t.Fatal(err)
		}
		want := file
		if len(params) != 2 || params[1] != want {
			t.Fatalf("path %q: params = %#v, want %q", path, params, want)
		}
	}
}

func TestCompileSBPLGlobMatchesFilepathPattern(t *testing.T) {
	patterns := []string{
		"*.txt", "a?.txt", "*[^a]*", "[a-c]*",
		`file\*.txt`, `file\?.txt`, `[\]]*`, `[\-]*`, `[\^]*`,
		`[\d]*`, `[\n]*`, `[\a]*`, `[^\d]*`, `\é*`,
	}
	names := []string{
		"a.txt", "b.txt", "file*.txt", "file?.txt", "]x", "-x", "^x",
		"abc", "é.txt", "d.txt", "n.txt", "1.txt", "\a.txt", "\n.txt",
	}
	dir := sbplTempDir(t)
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			profile, params, err := CompileSBPL(&Policy{FS: []FSRule{
				{Path: filepath.Join(dir, pattern), Access: "r", IgnoreMissing: true},
			}})
			if err != nil {
				t.Fatal(err)
			}
			got := make(map[string]bool)
			for i := 1; i < len(params); i += 2 {
				got[filepath.Base(params[i])] = true
			}
			for _, name := range names {
				want, err := filepath.Match(pattern, name)
				if err != nil {
					t.Fatal(err)
				}
				if got[name] != want {
					t.Errorf("name %q: grant = %v, want %v", name, got[name], want)
				}
			}
			if strings.Contains(profile, "regex") || strings.Contains(profile, "subpath") {
				t.Fatalf("file glob granted more than matched literals:\n%s", profile)
			}
		})
	}
}

func TestCompileSBPLExecuteIsPathScoped(t *testing.T) {
	dir := sbplTempDir(t)
	for _, access := range []string{"r", "rw", "x", "rx"} {
		t.Run(access, func(t *testing.T) {
			profile, _, err := CompileSBPL(&Policy{FS: []FSRule{{Path: dir, Access: access}}})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(profile, "file-exec") || strings.Contains(profile, "(allow process-exec)") {
				t.Fatalf("invalid or unscoped execution permission:\n%s", profile)
			}
			if got, want := strings.Contains(profile, "process-exec"), strings.Contains(access, "x"); got != want {
				t.Fatalf("access %q: process-exec = %v, want %v", access, got, want)
			}
		})
	}
}
