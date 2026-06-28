package policy

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func TestParseNetAllow(t *testing.T) {
	data := []byte(`{"name": "test", "net": "allow"}`)
	p, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Net.Allow {
		t.Error("expected Net.Allow = true")
	}
	if len(p.Net.Rules) != 0 {
		t.Errorf("expected no net rules, got %d", len(p.Net.Rules))
	}
}

func TestParseUnshare(t *testing.T) {
	data := []byte(`{"name": "test", "unshare": {"user": true, "pid": true, "cgroup": true, "mount_proc": true}, "net": "allow"}`)
	p, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if p.Unshare == nil {
		t.Fatal("expected Unshare to be set")
	}
	if !p.Unshare.User || !p.Unshare.PID || !p.Unshare.Cgroup || !p.Unshare.MountProc {
		t.Errorf("unexpected unshare config: %+v", p.Unshare)
	}
}

func TestParseUnshareOmitted(t *testing.T) {
	data := []byte(`{"name": "test", "net": "allow"}`)
	p, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if p.Unshare.Enabled() {
		t.Error("expected Unshare.Enabled() = false when omitted")
	}
}

func TestValidateUnshareMountProcRequiresPID(t *testing.T) {
	data := []byte(`{"name": "test", "unshare": {"mount_proc": true}, "net": "allow"}`)
	_, err := Parse(data)
	if err == nil {
		t.Error("expected error: mount_proc without pid")
	}
}

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
	if len(p.Net.Rules) != 2 {
		t.Errorf("len(net) = %d, want 2", len(p.Net.Rules))
	}
}

func TestLoadRendersJ2Policy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json.j2")
	if err := os.WriteFile(path, []byte(`{
		"name": "templated-{{ var.name }}",
		"fs": [
			{% if env.LANDCAGE_TEMPLATE_INCLUDE_TMP %}
			{"path": "{{ tmpDir }}", "access": "r"}
			{% endif %}
		],
		"net": "allow"
	}`), 0644); err != nil {
		t.Fatal(err)
	}

	opts := DefaultOptions()
	opts.Env["LANDCAGE_TEMPLATE_INCLUDE_TMP"] = "1"
	opts.Dirs.TmpDir = "/template-tmp"
	opts.TemplateVars = map[string]string{"name": "policy"}

	p, err := LoadWithOptions(path, &opts)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "templated-policy" {
		t.Fatalf("name = %q", p.Name)
	}
	if len(p.FS) != 1 || p.FS[0].Path != "/template-tmp" {
		t.Fatalf("unexpected fs rules: %+v", p.FS)
	}
}

func TestLoadRendersPlainJSONWithBuiltins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(`{
		"name": "test",
		"fs": [{"path": "{{ tmpDir }}", "access": "r"}],
		"net": "allow"
	}`), 0644); err != nil {
		t.Fatal(err)
	}

	opts := DefaultOptions()
	opts.Dirs.TmpDir = "/my-tmp"

	p, err := LoadWithOptions(path, &opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.FS) != 1 || p.FS[0].Path != "/my-tmp" {
		t.Fatalf("unexpected fs rules: %+v", p.FS)
	}
}

func TestRenderTemplateVars(t *testing.T) {
	opts := DefaultOptions()
	opts.TemplateVars = map[string]string{"name": "policy"}
	opts.OptionalTemplateVars = map[string]string{"unused": "ok"}

	got, err := RenderTemplate([]byte(`{"name": "{{ var.name }}"}`), &opts, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"name": "policy"}` {
		t.Fatalf("got %q", got)
	}
}

func TestRenderTemplateMissingVarFailsEvenInUntakenBranch(t *testing.T) {
	opts := DefaultOptions()

	_, err := RenderTemplate([]byte(`{% if false %}{{ var.missing }}{% endif %}`), &opts, true)
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected missing template var error, got %v", err)
	}
}

func TestRenderTemplateUnusedRequiredVarFails(t *testing.T) {
	opts := DefaultOptions()
	opts.TemplateVars = map[string]string{"unused": "value"}

	_, err := RenderTemplate([]byte(`{"name": "static"}`), &opts, true)
	if err == nil || !strings.Contains(err.Error(), "unused") {
		t.Fatalf("expected unused required template var error, got %v", err)
	}
}

func TestRenderTemplateOptionalVarMayBeUnused(t *testing.T) {
	opts := DefaultOptions()
	opts.OptionalTemplateVars = map[string]string{"unused": "value"}

	_, err := RenderTemplate([]byte(`{"name": "static"}`), &opts, true)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRenderTemplateMentionedOptionalVarInUntakenBranchIsSatisfied(t *testing.T) {
	opts := DefaultOptions()
	opts.OptionalTemplateVars = map[string]string{"maybe": "value"}

	_, err := RenderTemplate([]byte(`{% if false %}{{ var.maybe }}{% endif %}{"name": "static"}`), &opts, true)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRenderTemplateStrictNilOnOutput(t *testing.T) {
	opts := DefaultOptions()

	// Accessing an unset env var directly errors
	_, err := RenderTemplate([]byte(`{{ env.LANDCAGE_TEST_UNSET_12345 }}`), &opts, false)
	if err == nil {
		t.Fatal("expected error for undefined env var output")
	}

	// Using 'or' provides a default
	got, err := RenderTemplate([]byte(`{{ env.LANDCAGE_TEST_UNSET_12345 or "/fallback" }}`), &opts, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "/fallback" {
		t.Fatalf("got %q", got)
	}
}

func TestRenderTemplateEnvAccess(t *testing.T) {
	opts := DefaultOptions()
	opts.Env["LANDCAGE_TEST_RENDER"] = "hello"
	opts.Dirs.Home = "/home/test"

	got, err := RenderTemplate([]byte(`{{ home }}:{{ env.LANDCAGE_TEST_RENDER }}`), &opts, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "/home/test:hello" {
		t.Fatalf("got %q", got)
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

func TestResolveGlob(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"foo.txt", "bar.txt", "baz.log"} {
		os.WriteFile(filepath.Join(dir, name), nil, 0644)
	}

	paths, err := resolvePath(dir + "/*.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Errorf("got %d matches, want 2: %v", len(paths), paths)
	}
}

func TestResolveNoMatch(t *testing.T) {
	dir := t.TempDir()
	paths, err := resolvePath(dir + "/*.xyz")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 {
		t.Errorf("got %d matches, want 0", len(paths))
	}
}

func TestResolveNoMeta(t *testing.T) {
	paths, err := resolvePath("/usr/bin/ls")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "/usr/bin/ls" {
		t.Errorf("got %v, want [/usr/bin/ls]", paths)
	}
}

func TestResolveMiddleComponent(t *testing.T) {
	_, err := resolvePath("/dev/*/card0")
	if err == nil {
		t.Error("expected error for glob in middle component")
	}
}

func TestResolveBracketGlob(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"card0", "card1", "card2", "cardX"} {
		os.WriteFile(filepath.Join(dir, name), nil, 0644)
	}

	paths, err := resolvePath(dir + "/card[0-2]")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 3 {
		t.Errorf("got %d matches, want 3: %v", len(paths), paths)
	}
}

func TestResolveRoot(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(dir+"/aaa", 0755)
	os.MkdirAll(dir+"/aab", 0755)
	os.MkdirAll(dir+"/bbb", 0755)

	paths, err := resolvePath(dir + "/aa*")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Errorf("expected 2 matches, got %v", paths)
	}
}

func TestFSAccessSetFileRejectsCreate(t *testing.T) {
	r := &FSRule{Path: "/tmp/f", Access: "rwc"}
	_, err := fsAccessSet(r, false, FeaturesForABI(9))
	if err == nil {
		t.Error("expected error for 'c' on file")
	}
}

func TestFSAccessSetFileRejectsDelete(t *testing.T) {
	r := &FSRule{Path: "/tmp/f", Access: "rd"}
	_, err := fsAccessSet(r, false, FeaturesForABI(9))
	if err == nil {
		t.Error("expected error for 'd' on file")
	}
}

func TestFSAccessSetDirAllFlags(t *testing.T) {
	r := &FSRule{Path: "/tmp", Access: "rwxcdu", Refer: true, IoctlDev: true}
	access, err := fsAccessSet(r, true, FeaturesForABI(9))
	if err != nil {
		t.Fatal(err)
	}
	if access == 0 {
		t.Error("expected non-zero access set")
	}
	if access&llsys.AccessFSResolveUnix == 0 {
		t.Error("RESOLVE_UNIX should be set for 'u' access")
	}
}

func TestFSAccessSetFileReadOnly(t *testing.T) {
	r := &FSRule{Path: "/tmp/f", Access: "r"}
	access, err := fsAccessSet(r, false, FeaturesForABI(9))
	if err != nil {
		t.Fatal(err)
	}
	if access&llsys.AccessFSReadDir != 0 {
		t.Error("READ_DIR should not be set for file rule")
	}
	if access&llsys.AccessFSReadFile == 0 {
		t.Error("READ_FILE should be set for file rule")
	}
}

func TestFSAccessSetFileUnixSocketResolve(t *testing.T) {
	r := &FSRule{Path: "/tmp/sock", Access: "u"}
	access, err := fsAccessSet(r, false, FeaturesForABI(9))
	if err != nil {
		t.Fatal(err)
	}
	if access != llsys.AccessFSResolveUnix {
		t.Errorf("got access %d, want RESOLVE_UNIX %d", access, llsys.AccessFSResolveUnix)
	}
}

func TestFSAccessSetTruncateDowngrade(t *testing.T) {
	r := &FSRule{Path: "/tmp/f", Access: "w"}
	access, err := fsAccessSet(r, false, FeaturesForABI(9))
	if err != nil {
		t.Fatal(err)
	}
	if access&llsys.AccessFSTruncate == 0 {
		t.Error("expected truncate to be set on ABI 9")
	}

	access, err = fsAccessSet(r, false, FeaturesForABI(2))
	if err != nil {
		t.Fatal(err)
	}
	if access&llsys.AccessFSTruncate != 0 {
		t.Error("expected truncate to NOT be set on ABI 2")
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
			got := resolveIPC(tt.ipc, FeaturesForABI(tt.abi))
			if got != tt.want {
				t.Errorf("resolveIPC() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestResolveScopesGranular(t *testing.T) {
	scoped, err := resolveScopes(&IPCConfig{AbstractUnix: "deny", Signal: "allow"}, FeaturesForABI(8))
	if err != nil {
		t.Fatal(err)
	}
	if scoped&llsys.ScopeAbstractUnixSocket == 0 {
		t.Error("expected ScopeAbstractUnixSocket to be set")
	}
	if scoped&llsys.ScopeSignal != 0 {
		t.Error("expected ScopeSignal to NOT be set")
	}

	scoped, err = resolveScopes(nil, FeaturesForABI(8))
	if err != nil {
		t.Fatal(err)
	}
	if scoped != llsys.ScopeAbstractUnixSocket|llsys.ScopeSignal {
		t.Errorf("expected both scopes set, got %d", scoped)
	}

	scoped, err = resolveScopes(nil, FeaturesForABI(5))
	if err != nil {
		t.Fatal(err)
	}
	if scoped != 0 {
		t.Errorf("expected 0 scopes on old kernel, got %d", scoped)
	}

	_, err = resolveScopes(&IPCConfig{Signal: "deny"}, FeaturesForABI(5))
	if err == nil {
		t.Error("expected error for hard deny on old kernel")
	}
}

func TestDryRunEnvOutput(t *testing.T) {
	strPtr := func(s string) *string { return &s }
	p := &Policy{
		Name: "test",
		Env: map[string]EnvEntry{
			"SET_VAR":   {Value: strPtr("hello")},
			"UNSET_VAR": {Unset: true},
			"PATH_VAR":  {Prepend: StringBag{"/a"}, Append: StringBag{"/b"}, Remove: StringBag{"/c"}, Sep: ":"},
		},
	}
	var buf bytes.Buffer
	if err := DryRun(p, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, `SET_VAR = "hello"`) {
		t.Errorf("missing SET_VAR output in:\n%s", out)
	}
	if !strings.Contains(out, "UNSET_VAR: UNSET") {
		t.Errorf("missing UNSET_VAR output in:\n%s", out)
	}
	if !strings.Contains(out, "PATH_VAR:") && !strings.Contains(out, "prepend") {
		t.Errorf("missing PATH_VAR path op output in:\n%s", out)
	}
}
