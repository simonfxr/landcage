package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvEntryUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr bool
		check   func(*testing.T, *Policy)
	}{
		{
			name: "set string",
			json: `{"name":"test","env":{"FOO":"bar"}}`,
			check: func(t *testing.T, p *Policy) {
				e := p.Env["FOO"]
				if e.Value == nil || *e.Value != "bar" {
					t.Errorf("expected Value='bar', got %v", e.Value)
				}
			},
		},
		{
			name: "unset null",
			json: `{"name":"test","env":{"FOO":null}}`,
			check: func(t *testing.T, p *Policy) {
				e := p.Env["FOO"]
				if !e.Unset {
					t.Error("expected Unset=true")
				}
			},
		},
		{
			name: "path op object",
			json: `{"name":"test","env":{"PATH":{"prepend":"/a","append":["/b","/c"],"remove":"/d","sep":":"}}}`,
			check: func(t *testing.T, p *Policy) {
				e := p.Env["PATH"]
				if len(e.Prepend) != 1 || e.Prepend[0] != "/a" {
					t.Errorf("prepend: got %v", e.Prepend)
				}
				if len(e.Append) != 2 || e.Append[0] != "/b" || e.Append[1] != "/c" {
					t.Errorf("append: got %v", e.Append)
				}
				if len(e.Remove) != 1 || e.Remove[0] != "/d" {
					t.Errorf("remove: got %v", e.Remove)
				}
				if e.Sep != ":" {
					t.Errorf("sep: got %q", e.Sep)
				}
			},
		},
		{
			name: "path op default sep",
			json: `{"name":"test","env":{"X":{"prepend":"/a"}}}`,
			check: func(t *testing.T, p *Policy) {
				if p.Env["X"].Sep != ":" {
					t.Errorf("expected default sep ':', got %q", p.Env["X"].Sep)
				}
			},
		},
		{
			name:    "empty var name",
			json:    `{"name":"test","env":{"":"x"}}`,
			wantErr: true,
		},
		{
			name:    "invalid env entry json",
			json:    `{"name":"test","env":{"FOO":123}}`,
			wantErr: true,
		},
		{
			name: "empty prepend/append/remove",
			json: `{"name":"test","env":{"X":{"prepend":[],"append":[],"remove":[]}}}`,
			check: func(t *testing.T, p *Policy) {
				e := p.Env["X"]
				if len(e.Prepend) != 0 || len(e.Append) != 0 || len(e.Remove) != 0 {
					t.Errorf("expected empty slices, got prepend=%v append=%v remove=%v", e.Prepend, e.Append, e.Remove)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Parse([]byte(tt.json))
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, p)
			}
		})
	}
}

func TestApplyEnv(t *testing.T) {
	tests := []struct {
		name   string
		env    Environ
		policy string
		want   Environ
	}{
		{
			name:   "set simple",
			env:    Environ{},
			policy: `{"name":"test","env":{"TEST_VAR":"hello"}}`,
			want:   Environ{"TEST_VAR": "hello"},
		},
		{
			name:   "unset",
			env:    Environ{"TEST_UNSET": "exists"},
			policy: `{"name":"test","env":{"TEST_UNSET":null}}`,
			want:   Environ{},
		},
		{
			name:   "path prepend",
			env:    Environ{"TEST_PATH": "/a:/b"},
			policy: `{"name":"test","env":{"TEST_PATH":{"prepend":"/z"}}}`,
			want:   Environ{"TEST_PATH": "/z:/a:/b"},
		},
		{
			name:   "path append",
			env:    Environ{"TEST_PATH": "/a:/b"},
			policy: `{"name":"test","env":{"TEST_PATH":{"append":"/z"}}}`,
			want:   Environ{"TEST_PATH": "/a:/b:/z"},
		},
		{
			name:   "path remove",
			env:    Environ{"TEST_PATH": "/a:/b:/c"},
			policy: `{"name":"test","env":{"TEST_PATH":{"remove":"/b"}}}`,
			want:   Environ{"TEST_PATH": "/a:/c"},
		},
		{
			name:   "path combined",
			env:    Environ{"TEST_PATH": "/a:/b:/c"},
			policy: `{"name":"test","env":{"TEST_PATH":{"prepend":"/x","append":"/y","remove":"/b"}}}`,
			want:   Environ{"TEST_PATH": "/x:/a:/c:/y"},
		},
		{
			name:   "path custom sep",
			env:    Environ{"TEST_PATH": "a;b;c"},
			policy: `{"name":"test","env":{"TEST_PATH":{"prepend":"x","sep":";"}}}`,
			want:   Environ{"TEST_PATH": "x;a;b;c"},
		},
		{
			name:   "path op on unset var",
			env:    Environ{},
			policy: `{"name":"test","env":{"TEST_PATH":{"prepend":"/a","append":"/b"}}}`,
			want:   Environ{"TEST_PATH": "/a:/b"},
		},
		{
			name:   "multiple prepends",
			env:    Environ{"TEST_PATH": "/x"},
			policy: `{"name":"test","env":{"TEST_PATH":{"prepend":["/a","/b","/c"]}}}`,
			want:   Environ{"TEST_PATH": "/a:/b:/c:/x"},
		},
		{
			name:   "multiple removes",
			env:    Environ{"TEST_PATH": "/a:/b:/c:/d:/e"},
			policy: `{"name":"test","env":{"TEST_PATH":{"remove":["/b","/d"]}}}`,
			want:   Environ{"TEST_PATH": "/a:/c:/e"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Parse([]byte(tt.policy))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			result, err := ApplyEnv(p, tt.env)
			if err != nil {
				t.Fatalf("ApplyEnv: %v", err)
			}

			for k, v := range tt.want {
				if result[k] != v {
					t.Errorf("%s=%q, want %q", k, result[k], v)
				}
			}
			for k := range tt.env {
				if _, inWant := tt.want[k]; !inWant {
					if _, inResult := result[k]; inResult {
						t.Errorf("%s should be unset but is %q", k, result[k])
					}
				}
			}
		})
	}
}

func TestStringBagMarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		bag  StringBag
		want string
	}{
		{"single element", StringBag{"foo"}, `"foo"`},
		{"multiple elements", StringBag{"a", "b", "c"}, `["a","b","c"]`},
		{"empty", StringBag{}, `[]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.bag)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestStringBagUnmarshalJSONInvalidArray(t *testing.T) {
	var sb StringBag
	err := json.Unmarshal([]byte(`[123, 456]`), &sb)
	if err == nil {
		t.Error("expected error for non-string array elements")
	}
}

func TestEnvEntryIsPathOp(t *testing.T) {
	strPtr := func(s string) *string { return &s }
	tests := []struct {
		name  string
		entry EnvEntry
		want  bool
	}{
		{"empty", EnvEntry{}, false},
		{"value set", EnvEntry{Value: strPtr("x")}, false},
		{"unset", EnvEntry{Unset: true}, false},
		{"prepend only", EnvEntry{Prepend: StringBag{"/a"}}, true},
		{"append only", EnvEntry{Append: StringBag{"/a"}}, true},
		{"remove only", EnvEntry{Remove: StringBag{"/a"}}, true},
		{"all ops", EnvEntry{Prepend: StringBag{"/a"}, Append: StringBag{"/b"}, Remove: StringBag{"/c"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.entry.IsPathOp(); got != tt.want {
				t.Errorf("IsPathOp() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyEnvDoesNotModifyInput(t *testing.T) {
	p, _ := Parse([]byte(`{"name":"test","env":{"NEW":"value"}}`))
	inputEnv := Environ{"EXISTING": "keep"}

	result, err := ApplyEnv(p, inputEnv)
	if err != nil {
		t.Fatal(err)
	}
	if result["NEW"] != "value" || result["EXISTING"] != "keep" {
		t.Fatalf("unexpected result: %v", result)
	}
	if _, ok := inputEnv["NEW"]; ok {
		t.Error("input env was modified")
	}
}

func TestDryRunEnvOutputStrings(t *testing.T) {
	strPtr := func(s string) *string { return &s }
	p := &Policy{
		Name: "test",
		Env: map[string]EnvEntry{
			"SET_VAR":   {Value: strPtr("hello")},
			"UNSET_VAR": {Unset: true},
			"PATH_VAR":  {Prepend: StringBag{"/a"}, Append: StringBag{"/b"}, Remove: StringBag{"/c"}, Sep: ":"},
		},
	}

	var buf strings.Builder
	if err := DryRun(p, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, `SET_VAR = "hello"`) {
		t.Errorf("missing SET_VAR in:\n%s", out)
	}
	if !strings.Contains(out, "UNSET_VAR: UNSET") {
		t.Errorf("missing UNSET_VAR in:\n%s", out)
	}
}

func TestBuiltinExists(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "marker"), nil, 0644)

	opts := DefaultOptions()
	opts.Dirs.Home = dir

	got, err := RenderTemplate([]byte(`{% if exists(home + "/marker") %}yes{% else %}no{% endif %}`), &opts, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "yes" {
		t.Fatalf("got %q", got)
	}

	got, err = RenderTemplate([]byte(`{% if exists(home + "/nope") %}yes{% else %}no{% endif %}`), &opts, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "no" {
		t.Fatalf("got %q", got)
	}
}

func TestBuiltinIsDirIsFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "file"), nil, 0644)
	os.MkdirAll(filepath.Join(dir, "subdir"), 0755)

	opts := DefaultOptions()
	opts.Dirs.Home = dir

	tests := []struct {
		expr string
		want string
	}{
		{`{% if is_dir(home + "/subdir") %}y{% else %}n{% endif %}`, "y"},
		{`{% if is_dir(home + "/file") %}y{% else %}n{% endif %}`, "n"},
		{`{% if is_file(home + "/file") %}y{% else %}n{% endif %}`, "y"},
		{`{% if is_file(home + "/subdir") %}y{% else %}n{% endif %}`, "n"},
		{`{% if is_file(home + "/nope") %}y{% else %}n{% endif %}`, "n"},
	}
	for _, tt := range tests {
		got, err := RenderTemplate([]byte(tt.expr), &opts, false)
		if err != nil {
			t.Fatalf("%s: %v", tt.expr, err)
		}
		if string(got) != tt.want {
			t.Errorf("%s: got %q, want %q", tt.expr, got, tt.want)
		}
	}
}

func TestBuiltinFindUpward(t *testing.T) {
	// Create: tmpdir/project/mobydick/.git
	root := t.TempDir()
	project := filepath.Join(root, "project")
	os.MkdirAll(filepath.Join(project, "mobydick", ".git"), 0755)
	subdir := filepath.Join(project, "src", "deep")
	os.MkdirAll(subdir, 0755)

	opts := DefaultOptions()
	opts.Dirs.Pwd = subdir

	// Should find 'project' when starting from deep subdir
	got, err := RenderTemplate([]byte(`{% set ws = find_upward(pwd, "mobydick/.git") %}{% if ws %}{{ ws }}{% else %}none{% endif %}`), &opts, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != project {
		t.Fatalf("got %q, want %q", got, project)
	}

	// Should return nil when no marker found
	opts.Dirs.Pwd = root
	got, err = RenderTemplate([]byte(`{% set ws = find_upward(pwd, "nonexistent/.git") %}{% if ws %}{{ ws }}{% else %}none{% endif %}`), &opts, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "none" {
		t.Fatalf("got %q", got)
	}
}

func TestSetWithFindUpward(t *testing.T) {
	// Integration test: {% set %} + find_upward + conditional
	root := t.TempDir()
	project := filepath.Join(root, "workspace")
	os.MkdirAll(filepath.Join(project, ".git"), 0755)
	sub := filepath.Join(project, "pkg")
	os.MkdirAll(sub, 0755)

	opts := DefaultOptions()
	opts.Dirs.Pwd = sub

	tmpl := `{% set ws = find_upward(pwd, ".git") %}{% if ws %}{"workspace": "{{ ws }}"}{% else %}{"workspace": null}{% endif %}`
	got, err := RenderTemplate([]byte(tmpl), &opts, false)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"workspace": "` + project + `"}`
	if string(got) != expected {
		t.Fatalf("got %q, want %q", got, expected)
	}
}

func TestBuiltinExistsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.WriteFile(target, nil, 0644)
	link := filepath.Join(dir, "link")
	os.Symlink(target, link)
	// Broken symlink
	brokenLink := filepath.Join(dir, "broken")
	os.Symlink(filepath.Join(dir, "nonexistent"), brokenLink)

	opts := DefaultOptions()
	opts.Dirs.Home = dir

	tests := []struct {
		name string
		tmpl string
		want string
	}{
		{"valid symlink exists", `{% if exists(home + "/link") %}y{% else %}n{% endif %}`, "y"},
		{"broken symlink exists (lstat)", `{% if exists(home + "/broken") %}y{% else %}n{% endif %}`, "y"},
		{"non-existent path", `{% if exists(home + "/nope") %}y{% else %}n{% endif %}`, "n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RenderTemplate([]byte(tt.tmpl), &opts, false)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuiltinExistsArgErrors(t *testing.T) {
	// Wrong number of args
	_, err := builtinExists([]any{})
	if err == nil {
		t.Fatal("expected error for 0 args")
	}
	_, err = builtinExists([]any{"a", "b"})
	if err == nil {
		t.Fatal("expected error for 2 args")
	}
	// Non-string arg returns false (no error)
	v, err := builtinExists([]any{123})
	if err != nil {
		t.Fatal(err)
	}
	if v != false {
		t.Fatalf("got %v, want false", v)
	}
}

func TestBuiltinIsDirSymlink(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "subdir")
	os.MkdirAll(sub, 0755)
	linkToDir := filepath.Join(dir, "linkdir")
	os.Symlink(sub, linkToDir)
	file := filepath.Join(dir, "file")
	os.WriteFile(file, nil, 0644)
	linkToFile := filepath.Join(dir, "linkfile")
	os.Symlink(file, linkToFile)

	opts := DefaultOptions()
	opts.Dirs.Home = dir

	tests := []struct {
		name string
		tmpl string
		want string
	}{
		{"symlink to dir is dir", `{% if is_dir(home + "/linkdir") %}y{% else %}n{% endif %}`, "y"},
		{"symlink to file is not dir", `{% if is_dir(home + "/linkfile") %}y{% else %}n{% endif %}`, "n"},
		{"non-existent is not dir", `{% if is_dir(home + "/nope") %}y{% else %}n{% endif %}`, "n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RenderTemplate([]byte(tt.tmpl), &opts, false)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuiltinIsDirArgErrors(t *testing.T) {
	_, err := builtinIsDir([]any{})
	if err == nil {
		t.Fatal("expected error for 0 args")
	}
	v, err := builtinIsDir([]any{42})
	if err != nil {
		t.Fatal(err)
	}
	if v != false {
		t.Fatalf("got %v, want false", v)
	}
}

func TestBuiltinIsFileSymlink(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	os.WriteFile(file, nil, 0644)
	linkToFile := filepath.Join(dir, "linkfile")
	os.Symlink(file, linkToFile)
	sub := filepath.Join(dir, "subdir")
	os.MkdirAll(sub, 0755)
	linkToDir := filepath.Join(dir, "linkdir")
	os.Symlink(sub, linkToDir)

	opts := DefaultOptions()
	opts.Dirs.Home = dir

	tests := []struct {
		name string
		tmpl string
		want string
	}{
		{"symlink to file is file", `{% if is_file(home + "/linkfile") %}y{% else %}n{% endif %}`, "y"},
		{"symlink to dir is not file", `{% if is_file(home + "/linkdir") %}y{% else %}n{% endif %}`, "n"},
		{"non-existent is not file", `{% if is_file(home + "/nope") %}y{% else %}n{% endif %}`, "n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RenderTemplate([]byte(tt.tmpl), &opts, false)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuiltinIsFileArgErrors(t *testing.T) {
	_, err := builtinIsFile([]any{})
	if err == nil {
		t.Fatal("expected error for 0 args")
	}
	v, err := builtinIsFile([]any{true})
	if err != nil {
		t.Fatal(err)
	}
	if v != false {
		t.Fatalf("got %v, want false", v)
	}
}

func TestBuiltinFindUpwardMultipleMarkers(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	os.MkdirAll(filepath.Join(project, "go.mod"), 0755) // marker as dir for simplicity
	deep := filepath.Join(project, "a", "b", "c")
	os.MkdirAll(deep, 0755)

	opts := DefaultOptions()
	opts.Dirs.Pwd = deep

	// Should find project dir via go.mod marker
	got, err := RenderTemplate(
		[]byte(`{% set r = find_upward(pwd, "Cargo.toml", "go.mod") %}{% if r %}{{ r }}{% else %}none{% endif %}`),
		&opts, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != project {
		t.Fatalf("got %q, want %q", got, project)
	}
}

func TestBuiltinFindUpwardArgErrors(t *testing.T) {
	// Too few args
	_, err := builtinFindUpward([]any{"start"})
	if err == nil {
		t.Fatal("expected error for 1 arg")
	}
	_, err = builtinFindUpward([]any{})
	if err == nil {
		t.Fatal("expected error for 0 args")
	}
	// Non-string start returns nil
	v, err := builtinFindUpward([]any{123, "marker"})
	if err != nil {
		t.Fatal(err)
	}
	if v != nil {
		t.Fatalf("got %v, want nil", v)
	}
	// Non-string marker errors
	_, err = builtinFindUpward([]any{"/tmp", 123})
	if err == nil {
		t.Fatal("expected error for non-string marker")
	}
}

func TestBuiltinFindUpwardStartsAtRoot(t *testing.T) {
	// When starting at /, should not infinite loop; should return nil for nonexistent marker
	v, err := builtinFindUpward([]any{"/", "definitely_not_here_xyzzy"})
	if err != nil {
		t.Fatal(err)
	}
	if v != nil {
		t.Fatalf("got %v, want nil", v)
	}
}
