package policy

import (
	"bytes"
	"encoding/json"
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
		name    string
		env     Environ
		policy  string
		want    Environ
		wantErr bool
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
			name:   "expand variable",
			env:    Environ{"TEST_SRC": "source-value"},
			policy: `{"name":"test","env":{"TEST_DST":"${TEST_SRC}-copy"}}`,
			want:   Environ{"TEST_SRC": "source-value", "TEST_DST": "source-value-copy"},
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
			name:    "expand error",
			env:     Environ{},
			policy:  `{"name":"test","env":{"X":"${NONEXISTENT_VAR_12345}"}}`,
			wantErr: true,
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
		{
			name:    "expand error in prepend",
			env:     Environ{},
			policy:  `{"name":"test","env":{"X":{"prepend":"${NONEXISTENT_VAR_12345}"}}}`,
			wantErr: true,
		},
		{
			name:    "expand error in append",
			env:     Environ{},
			policy:  `{"name":"test","env":{"X":{"append":"${NONEXISTENT_VAR_12345}"}}}`,
			wantErr: true,
		},
		{
			name:    "expand error in remove",
			env:     Environ{},
			policy:  `{"name":"test","env":{"X":{"remove":"${NONEXISTENT_VAR_12345}"}}}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Parse([]byte(tt.policy))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			opts := &Options{
				Env:  tt.env,
				Dirs: ResolveDirs(tt.env),
			}
			result, err := ApplyEnv(p, opts)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
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
	opts := &Options{
		Env:  Environ{},
		Dirs: Dirs{Home: "/home/test"},
	}
	var buf bytes.Buffer
	if err := DryRun(p, opts, &buf); err != nil {
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
