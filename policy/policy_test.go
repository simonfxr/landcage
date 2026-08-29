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

func TestParseNetDeny(t *testing.T) {
	data := []byte(`{"name": "test", "net": "deny"}`)
	p, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if p.Net.Allow {
		t.Error("expected Net.Allow = false")
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

func TestLoadRendersTemplateWithBuiltins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json.j2")
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

func TestLoadPlainJSONNoExpansion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(`{
		"name": "test",
		"fs": [{"path": "/usr", "access": "r"}],
		"net": "allow"
	}`), 0644); err != nil {
		t.Fatal(err)
	}

	p, err := LoadWithOptions(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.FS) != 1 || p.FS[0].Path != "/usr" {
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

func TestRenderTemplateRequiredVarOnlyInIsDefinedFails(t *testing.T) {
	// --var foo=val with template that only uses foo in "is defined" guard:
	// foo is exempt from mentioned, so "unused required" fires.
	opts := DefaultOptions()
	opts.TemplateVars = map[string]string{"foo": "val"}

	_, err := RenderTemplate([]byte(`{% if var.foo is defined %}{{ var.foo }}{% endif %}`), &opts, true)
	if err == nil || !strings.Contains(err.Error(), "unused") {
		t.Fatalf("expected unused required var error, got %v", err)
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
		{"invalid net proto", `{"name": "x", "net": [{"port": 80, "access": "connect", "proto": "sctp"}]}`},
		{"old tcp+udp proto", `{"name": "x", "net": [{"port": 80, "access": "connect", "proto": "tcp+udp"}]}`},
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

	// On ABI 8, 'u' alone results in zero access (silently dropped)
	access, err = fsAccessSet(r, false, FeaturesForABI(8))
	if err != nil {
		t.Fatal(err)
	}
	if access != 0 {
		t.Errorf("got access %d on ABI 8, want 0 (resolve_unix dropped)", access)
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

func TestFSAccessSetResolveUnixDowngrade(t *testing.T) {
	r := &FSRule{Path: "/tmp", Access: "rwu"}

	// On ABI 9+, resolve_unix should be present
	access, err := fsAccessSet(r, true, FeaturesForABI(9))
	if err != nil {
		t.Fatal(err)
	}
	if access&llsys.AccessFSResolveUnix == 0 {
		t.Error("expected resolve_unix to be set on ABI 9")
	}

	// On ABI 8, resolve_unix should be silently dropped
	access, err = fsAccessSet(r, true, FeaturesForABI(8))
	if err != nil {
		t.Fatal(err)
	}
	if access&llsys.AccessFSResolveUnix != 0 {
		t.Error("expected resolve_unix to NOT be set on ABI 8")
	}
	// But write should still be present
	if access&llsys.AccessFSWriteFile == 0 {
		t.Error("expected write to still be set on ABI 8")
	}
}

func TestFSAccessSetReferDowngrade(t *testing.T) {
	r := &FSRule{Path: "/tmp", Access: "rw", Refer: true}

	// On ABI 2+, refer should be present
	access, err := fsAccessSet(r, true, FeaturesForABI(2))
	if err != nil {
		t.Fatal(err)
	}
	if access&llsys.AccessFSRefer == 0 {
		t.Error("expected refer to be set on ABI 2")
	}

	// On ABI 1, refer should be silently dropped
	access, err = fsAccessSet(r, true, FeaturesForABI(1))
	if err != nil {
		t.Fatal(err)
	}
	if access&llsys.AccessFSRefer != 0 {
		t.Error("expected refer to NOT be set on ABI 1")
	}
}

func TestFSAccessSetIoctlDevDowngrade(t *testing.T) {
	r := &FSRule{Path: "/dev/null", Access: "rw", IoctlDev: true}

	// On ABI 5+, ioctl_dev should be present
	access, err := fsAccessSet(r, false, FeaturesForABI(5))
	if err != nil {
		t.Fatal(err)
	}
	if access&llsys.AccessFSIoctlDev == 0 {
		t.Error("expected ioctl_dev to be set on ABI 5")
	}

	// On ABI 4, ioctl_dev should be silently dropped
	access, err = fsAccessSet(r, false, FeaturesForABI(4))
	if err != nil {
		t.Fatal(err)
	}
	if access&llsys.AccessFSIoctlDev != 0 {
		t.Error("expected ioctl_dev to NOT be set on ABI 4")
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

func TestDryRunNetOutput(t *testing.T) {
	feat, err := DetectFeatures()
	if err != nil {
		feat = LandlockFeatures{ABI: 0}
	}
	tests := []struct {
		name string
		net  NetConfig
		want string
	}{
		{"deny", NetConfig{}, "Network: deny (" + netDenySummary(feat)},
		{"allow", NetConfig{Allow: true}, "Network: allow (unrestricted)"},
		{"rules", NetConfig{Rules: []NetRule{{Port: 443, Access: "connect"}}}, "port 443/tcp"},
		{"udp", NetConfig{Rules: []NetRule{{Port: 53, Access: "connect", Proto: "udp"}}}, "port 53/udp"},
		{"both", NetConfig{Rules: []NetRule{{Port: 53, Access: "connect", Proto: "any"}}}, "port 53/any"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Policy{Name: "test", Net: tt.net}
			var buf bytes.Buffer
			gotErr := DryRun(p, &buf)
			wantErr := feat.ValidateNet(&tt.net)
			if (gotErr != nil) != (wantErr != nil) {
				t.Fatalf("DryRun error = %v, expected compatibility error %v", gotErr, wantErr)
			}
			if !strings.Contains(buf.String(), tt.want) {
				t.Errorf("expected %q in output:\n%s", tt.want, buf.String())
			}
		})
	}
}

func TestDryRunRejectsDirectoryAccessOnFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	p := &Policy{
		Name: "invalid-file-access",
		FS:   []FSRule{{Path: path, Access: "c"}},
		Net:  NetConfig{Allow: true},
	}
	var out bytes.Buffer
	err := DryRun(p, &out)
	if err == nil || !strings.Contains(err.Error(), "invalid on files") {
		t.Fatalf("expected contextual file access error, got %v", err)
	}
}

func TestDryRunCompatibilityError(t *testing.T) {
	tests := []struct {
		name string
		p    Policy
		abi  int
		want string
	}{
		{
			name: "tcp before ABI 4",
			p:    Policy{Net: NetConfig{Rules: []NetRule{{Port: 443, Access: "connect"}}}},
			abi:  3,
			want: "ABI >= 4",
		},
		{
			name: "udp before ABI 10",
			p:    Policy{Net: NetConfig{Rules: []NetRule{{Port: 53, Access: "connect", Proto: "udp"}}}},
			abi:  9,
			want: "ABI >= 10",
		},
		{
			name: "hard IPC deny before ABI 6",
			p:    Policy{Net: NetConfig{Allow: true}, IPC: &IPCConfig{Signal: "deny"}},
			abi:  5,
			want: "ABI >= 6",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := dryRunCompatibilityError(&tt.p, FeaturesForABI(tt.abi))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q compatibility error, got %v", tt.want, err)
			}
		})
	}
}

func TestDryRunShowsCreateDirWithoutCreatingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new", "directory")
	p := &Policy{
		Name: "create-dir",
		FS: []FSRule{{
			Path:      path,
			Access:    "rwcd",
			CreateDir: "0700",
		}},
		Net: NetConfig{Allow: true},
	}
	var out bytes.Buffer
	if err := DryRun(p, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("dry-run created %s", path)
	}
	if !strings.Contains(out.String(), "would create mode 0700") {
		t.Fatalf("missing create_dir plan in output:\n%s", out.String())
	}
}

func TestDryRunShowsNamespaceConfiguration(t *testing.T) {
	p := &Policy{
		Name: "namespaces",
		Unshare: &UnshareConfig{
			User:      true,
			PID:       true,
			Cgroup:    true,
			MountProc: true,
		},
		Net: NetConfig{Allow: true},
	}
	var out bytes.Buffer
	if err := DryRun(p, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Namespaces:", "user: true", "pid: true", "cgroup: true", "mount_proc: true"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in output:\n%s", want, out.String())
		}
	}
}

func TestNetDenySummary(t *testing.T) {
	tests := []struct {
		abi  int
		want string
	}{
		{3, "not enforced; TCP and UDP unrestricted"},
		{4, "all TCP blocked; UDP unrestricted"},
		{10, "all TCP and UDP blocked"},
	}
	for _, tt := range tests {
		if got := netDenySummary(FeaturesForABI(tt.abi)); got != tt.want {
			t.Errorf("ABI %d: netDenySummary() = %q, want %q", tt.abi, got, tt.want)
		}
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

func TestABI10UDPDetection(t *testing.T) {
	if FeaturesForABI(9).SupportsUDP() {
		t.Error("ABI 9 should not report UDP support")
	}
	if !FeaturesForABI(10).SupportsUDP() {
		t.Error("ABI 10 should report UDP support")
	}

	got9 := FeaturesForABI(9).MaxNetAccess()
	want9 := uint64(llsys.AccessNetBindTCP | llsys.AccessNetConnectTCP)
	if uint64(got9) != want9 {
		t.Errorf("ABI 9 MaxNetAccess = %d, want TCP bits %d", got9, want9)
	}

	got10 := FeaturesForABI(10).MaxNetAccess()
	want10 := uint64(llsys.AccessNetBindTCP | llsys.AccessNetConnectTCP | llsys.AccessNetBindUDP | llsys.AccessNetConnectSendUDP)
	if uint64(got10) != want10 {
		t.Errorf("ABI 10 MaxNetAccess = %d, want TCP+UDP bits %d", got10, want10)
	}
}

func TestValidateNetUDP(t *testing.T) {
	udp := &NetConfig{Rules: []NetRule{{Port: 53, Access: "connect", Proto: "udp"}}}
	if err := FeaturesForABI(3).ValidateNet(udp); err == nil || !strings.Contains(err.Error(), "ABI >= 10") {
		t.Fatalf("expected ABI 10 error for udp rules on ABI 3, got %v", err)
	}
	if err := FeaturesForABI(9).ValidateNet(udp); err == nil {
		t.Fatal("expected error for udp rules on ABI 9")
	}
	if err := FeaturesForABI(10).ValidateNet(udp); err != nil {
		t.Fatal(err)
	}

	both := &NetConfig{Rules: []NetRule{{Port: 53, Access: "connect", Proto: "any"}}}
	if err := FeaturesForABI(9).ValidateNet(both); err == nil {
		t.Fatal("expected error for any-proto rules on ABI 9")
	}

	tcp := &NetConfig{Rules: []NetRule{{Port: 443, Access: "connect"}}}
	if err := FeaturesForABI(4).ValidateNet(tcp); err != nil {
		t.Fatal(err)
	}
}

func TestNetRuleProto(t *testing.T) {
	tcp := &NetRule{Port: 443, Access: "connect"}
	if !tcp.usesTCP() || tcp.usesUDP() || tcp.protoName() != "tcp" {
		t.Errorf("omitted proto: tcp=%v udp=%v name=%s", tcp.usesTCP(), tcp.usesUDP(), tcp.protoName())
	}
	udp := &NetRule{Port: 53, Access: "connect", Proto: "udp"}
	if udp.usesTCP() || !udp.usesUDP() {
		t.Errorf("udp proto: tcp=%v udp=%v", udp.usesTCP(), udp.usesUDP())
	}
	both := &NetRule{Port: 53, Access: "connect", Proto: "any"}
	if !both.usesTCP() || !both.usesUDP() || both.protoName() != "any" {
		t.Errorf("any proto: tcp=%v udp=%v name=%s", both.usesTCP(), both.usesUDP(), both.protoName())
	}
}

func TestParseNetProto(t *testing.T) {
	p, err := Parse([]byte(`{"name":"x","net":[{"port":53,"access":"connect","proto":"udp"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Net.Rules) != 1 || p.Net.Rules[0].Proto != "udp" {
		t.Fatalf("got %+v", p.Net.Rules)
	}

	p, err = Parse([]byte(`{"name":"x","net":[{"port":53,"access":"connect","proto":"any"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Net.Rules[0].Proto != "any" || !p.Net.Rules[0].usesTCP() || !p.Net.Rules[0].usesUDP() {
		t.Fatalf("any proto: %+v", p.Net.Rules[0])
	}
}

func TestFeaturesStringUDP(t *testing.T) {
	s := FeaturesForABI(10).String()
	if !strings.Contains(s, "net=tcp+udp") {
		t.Errorf("ABI 10 String() = %s, want net=tcp+udp", s)
	}
	s9 := FeaturesForABI(9).String()
	if !strings.Contains(s9, "net=tcp") || strings.Contains(s9, "udp") {
		t.Errorf("ABI 9 String() = %s, want net=tcp without udp", s9)
	}
}

func TestBuildNetRules(t *testing.T) {
	tcp := buildNetRules(&NetRule{Port: 443, Access: "connect"})
	if len(tcp) != 1 {
		t.Errorf("tcp connect: got %d rules, want 1", len(tcp))
	}
	udp := buildNetRules(&NetRule{Port: 53, Access: "connect", Proto: "udp"})
	if len(udp) != 1 {
		t.Errorf("udp connect: got %d rules, want 1", len(udp))
	}
	both := buildNetRules(&NetRule{Port: 53, Access: "connect+bind", Proto: "any"})
	if len(both) != 4 {
		t.Errorf("any connect+bind: got %d rules, want 4", len(both))
	}
}
