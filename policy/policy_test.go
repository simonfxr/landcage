package policy

import (
	"os"
	"path/filepath"
	"testing"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func TestParseValid(t *testing.T) {
	data := []byte(`{
		"name": "test",
		"fs": [
			{"path": "/usr", "access": "rx"},
			{"path": "/tmp", "access": "rwcd", "refer": true},
			{"path": "/dev/null", "access": "rw", "ioctl_dev": true}
		],
		"net": [
			{"port": 443, "access": "connect"},
			{"port": 8080, "access": "bind"}
		],
		"ipc": {"abstract_unix": "deny", "signal": "allow"}
	}`)
	p, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "test" {
		t.Errorf("name = %q, want %q", p.Name, "test")
	}
	if len(p.FS) != 3 {
		t.Errorf("len(fs) = %d, want 3", len(p.FS))
	}
	if len(p.Net) != 2 {
		t.Errorf("len(net) = %d, want 2", len(p.Net))
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"missing name", `{"fs": [{"path": "/", "access": "r"}]}`},
		{"missing path", `{"name": "x", "fs": [{"access": "r"}]}`},
		{"missing access", `{"name": "x", "fs": [{"path": "/"}]}`},
		{"invalid access char", `{"name": "x", "fs": [{"path": "/", "access": "z"}]}`},
		{"invalid net access", `{"name": "x", "net": [{"port": 80, "access": "foo"}]}`},
		{"invalid ipc value", `{"name": "x", "ipc": {"signal": "maybe"}}`},
		{"create_dir + ignore_missing", `{"name": "x", "fs": [{"path": "/x", "access": "r", "create_dir": "0700", "ignore_missing": true}]}`},
		{"bad create_dir mode", `{"name": "x", "fs": [{"path": "/x", "access": "r", "create_dir": "9999"}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.json))
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestExpandSimple(t *testing.T) {
	os.Setenv("LANDCAGE_TEST_VAR", "hello")
	defer os.Unsetenv("LANDCAGE_TEST_VAR")

	exp := NewExpander()
	got, err := exp.Expand("/prefix/${LANDCAGE_TEST_VAR}/suffix")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "/prefix/hello/suffix" {
		t.Errorf("got %q, want %q", got.String(), "/prefix/hello/suffix")
	}
}

func TestExpandDefault(t *testing.T) {
	os.Unsetenv("LANDCAGE_UNSET_VAR")
	exp := NewExpander()
	got, err := exp.Expand("${LANDCAGE_UNSET_VAR:-/fallback}")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "/fallback" {
		t.Errorf("got %q, want %q", got.String(), "/fallback")
	}
}

func TestExpandNested(t *testing.T) {
	os.Unsetenv("LANDCAGE_OUTER")
	os.Setenv("LANDCAGE_INNER", "/inner")
	defer os.Unsetenv("LANDCAGE_INNER")

	exp := NewExpander()
	got, err := exp.Expand("${LANDCAGE_OUTER:-${LANDCAGE_INNER}/sub}")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "/inner/sub" {
		t.Errorf("got %q, want %q", got.String(), "/inner/sub")
	}
}

func TestExpandBuiltins(t *testing.T) {
	exp := NewExpander()
	got, err := exp.Expand("${home}")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != os.Getenv("HOME") {
		t.Errorf("got %q, want %q", got.String(), os.Getenv("HOME"))
	}
}

func TestExpandEscapesGlob(t *testing.T) {
	os.Setenv("LANDCAGE_GLOB", "foo*bar")
	defer os.Unsetenv("LANDCAGE_GLOB")

	exp := NewExpander()
	got, err := exp.Expand("/dir/${LANDCAGE_GLOB}")
	if err != nil {
		t.Fatal(err)
	}
	// With the new typed approach, String() returns the raw text (no escaping)
	if got.String() != "/dir/foo*bar" {
		t.Errorf("got %q, want %q", got.String(), "/dir/foo*bar")
	}
	// But the segment from the variable is marked FromVar=true
	if len(got) != 2 {
		t.Fatalf("expected 2 segments, got %d", len(got))
	}
	if got[1].FromVar != true || got[1].Text != "foo*bar" {
		t.Errorf("expected FromVar=true segment with raw text, got %+v", got[1])
	}
}

func TestExpandUnset(t *testing.T) {
	os.Unsetenv("LANDCAGE_NOPE")
	exp := NewExpander()
	_, err := exp.Expand("${LANDCAGE_NOPE}")
	if err == nil {
		t.Error("expected error for unset var without default")
	}
}

func TestExpandEmptyDefault(t *testing.T) {
	os.Unsetenv("LANDCAGE_EMPTY")
	exp := NewExpander()
	got, err := exp.Expand("${LANDCAGE_EMPTY:-}")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "" {
		t.Errorf("got %q, want empty", got.String())
	}
}

func TestResolveGlob(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"foo.txt", "bar.txt", "baz.log"} {
		os.WriteFile(filepath.Join(dir, name), nil, 0644)
	}

	exp := testExpander(nil)
	ep, err := exp.Expand(dir + "/*.txt")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := ep.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Errorf("got %d matches, want 2: %v", len(paths), paths)
	}
}

func TestResolveNoMatch(t *testing.T) {
	dir := t.TempDir()
	exp := testExpander(nil)
	ep, err := exp.Expand(dir + "/*.xyz")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := ep.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 {
		t.Errorf("got %d matches, want 0", len(paths))
	}
}

func TestResolveNoMeta(t *testing.T) {
	exp := testExpander(nil)
	ep, err := exp.Expand("/usr/bin/ls")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := ep.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "/usr/bin/ls" {
		t.Errorf("got %v, want [/usr/bin/ls]", paths)
	}
}

func TestResolveMiddleComponent(t *testing.T) {
	exp := testExpander(nil)
	ep, err := exp.Expand("/dev/*/card0")
	if err != nil {
		t.Fatal(err)
	}
	_, err = ep.Resolve()
	if err == nil {
		t.Error("expected error for glob in middle component")
	}
}

func TestResolveVarWithGlobCharsIsLiteral(t *testing.T) {
	// A variable containing * should NOT be treated as a glob
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "file*name"), nil, 0644)
	os.WriteFile(filepath.Join(dir, "fileXname"), nil, 0644)

	os.Setenv("_LC_LITERAL", "file*name")
	defer os.Unsetenv("_LC_LITERAL")

	exp := testExpander(nil)
	ep, err := exp.Expand(dir + "/${_LC_LITERAL}")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := ep.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	// Should match only the literal "file*name", not "fileXname"
	if len(paths) != 1 || filepath.Base(paths[0]) != "file*name" {
		t.Errorf("got %v, want single file with literal *", paths)
	}
}

func TestResolveVarWithGlobCharsInDirIsLiteral(t *testing.T) {
	// A variable containing * in a non-final component should NOT trigger error
	dir := t.TempDir()
	subdir := filepath.Join(dir, "a*b")
	os.MkdirAll(subdir, 0755)
	os.WriteFile(filepath.Join(subdir, "file.txt"), nil, 0644)

	os.Setenv("_LC_STARDIR", "a*b")
	defer os.Unsetenv("_LC_STARDIR")

	exp := testExpander(nil)
	ep, err := exp.Expand(dir + "/${_LC_STARDIR}/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := ep.Resolve()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) != 1 || filepath.Base(paths[0]) != "file.txt" {
		t.Errorf("got %v, want single file.txt under literal a*b dir", paths)
	}
}

func TestResolveBracketGlob(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"card0", "card1", "card2", "cardX"} {
		os.WriteFile(filepath.Join(dir, name), nil, 0644)
	}

	exp := testExpander(nil)
	ep, err := exp.Expand(dir + "/card[0-2]")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := ep.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 3 {
		t.Errorf("got %d matches, want 3: %v", len(paths), paths)
	}
}

func TestResolveMixedVarAndLiteralGlob(t *testing.T) {
	// Variable with metacharacters + literal glob in same final component
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a*b_1.txt"), nil, 0644)
	os.WriteFile(filepath.Join(dir, "a*b_2.txt"), nil, 0644)
	os.WriteFile(filepath.Join(dir, "aXb_1.txt"), nil, 0644)

	os.Setenv("_LC_PFX", "a*b_")
	defer os.Unsetenv("_LC_PFX")

	exp := testExpander(nil)
	ep, err := exp.Expand(dir + "/${_LC_PFX}*.txt")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := ep.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	// Should match "a*b_1.txt" and "a*b_2.txt" but NOT "aXb_1.txt"
	if len(paths) != 2 {
		t.Errorf("got %d matches, want 2: %v", len(paths), paths)
	}
}

func TestResolveRoot(t *testing.T) {
	exp := testExpander(nil)
	ep, err := exp.Expand("/u*")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := ep.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range paths {
		if p == "/usr" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected /usr in glob results, got %v", paths)
	}
}

func TestFSAccessSetFileRejectsCreate(t *testing.T) {
	r := &FSRule{Path: "/tmp/f", Access: "rwc"}
	_, err := fsAccessSet(r, false)
	if err == nil {
		t.Error("expected error for 'c' on file")
	}
}

func TestFSAccessSetFileRejectsDelete(t *testing.T) {
	r := &FSRule{Path: "/tmp/f", Access: "rd"}
	_, err := fsAccessSet(r, false)
	if err == nil {
		t.Error("expected error for 'd' on file")
	}
}

func TestFSAccessSetDirAllFlags(t *testing.T) {
	r := &FSRule{Path: "/tmp", Access: "rwxcd", Refer: true, IoctlDev: true}
	access, err := fsAccessSet(r, true)
	if err != nil {
		t.Fatal(err)
	}
	if access == 0 {
		t.Error("expected non-zero access set")
	}
}

func TestFSAccessSetFileReadOnly(t *testing.T) {
	r := &FSRule{Path: "/tmp/f", Access: "r"}
	access, err := fsAccessSet(r, false)
	if err != nil {
		t.Fatal(err)
	}
	// Should only have READ_FILE, not READ_DIR
	if access&llsys.AccessFSReadDir != 0 {
		t.Error("READ_DIR should not be set for file rule")
	}
	if access&llsys.AccessFSReadFile == 0 {
		t.Error("READ_FILE should be set for file rule")
	}
}

func TestResolveIPC(t *testing.T) {
	tests := []struct {
		name string
		ipc  *IPCConfig
		abi  int
		want ipcMode
	}{
		{"nil ipc, old kernel", nil, 5, ipcExcludeScopes},
		{"nil ipc, new kernel", nil, 6, ipcIncludeScopes},
		{"deny on old kernel", &IPCConfig{AbstractUnix: "deny"}, 5, ipcHardDenyUnavailable},
		{"deny on new kernel", &IPCConfig{AbstractUnix: "deny"}, 8, ipcIncludeScopes},
		{"allow all", &IPCConfig{AbstractUnix: "allow", Signal: "allow"}, 8, ipcExcludeScopes},
		{"mixed allow+deny, new", &IPCConfig{AbstractUnix: "deny", Signal: "allow"}, 8, ipcIncludeScopes},
		{"mixed allow+deny, old", &IPCConfig{AbstractUnix: "deny", Signal: "allow"}, 5, ipcHardDenyUnavailable},
		{"mixed allow+empty, old", &IPCConfig{AbstractUnix: "allow", Signal: ""}, 5, ipcExcludeScopes},
		{"empty fields, old kernel", &IPCConfig{}, 5, ipcExcludeScopes},
		{"empty fields, new kernel", &IPCConfig{}, 6, ipcIncludeScopes},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveIPC(tt.ipc, tt.abi)
			if got != tt.want {
				t.Errorf("resolveIPC() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestResolveScopesGranular(t *testing.T) {
	// Mixed: deny abstract_unix but allow signal
	scoped, err := resolveScopes(&IPCConfig{AbstractUnix: "deny", Signal: "allow"}, 8)
	if err != nil {
		t.Fatal(err)
	}
	if scoped&llsys.ScopeAbstractUnixSocket == 0 {
		t.Error("expected ScopeAbstractUnixSocket to be set")
	}
	if scoped&llsys.ScopeSignal != 0 {
		t.Error("expected ScopeSignal to NOT be set")
	}

	// Both default (best-effort deny)
	scoped, err = resolveScopes(nil, 8)
	if err != nil {
		t.Fatal(err)
	}
	if scoped != llsys.ScopeAbstractUnixSocket|llsys.ScopeSignal {
		t.Errorf("expected both scopes set, got %d", scoped)
	}

	// Old kernel, best-effort
	scoped, err = resolveScopes(nil, 5)
	if err != nil {
		t.Fatal(err)
	}
	if scoped != 0 {
		t.Errorf("expected 0 scopes on old kernel, got %d", scoped)
	}

	// Old kernel, hard deny
	_, err = resolveScopes(&IPCConfig{Signal: "deny"}, 5)
	if err == nil {
		t.Error("expected error for hard deny on old kernel")
	}
}
