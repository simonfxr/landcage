package policy

import (
	"os"
	"testing"
)

// testExpander creates an Expander with controlled builtins (no real env dependency).
func testExpander(builtins map[string]string) *Expander {
	return &Expander{builtins: builtins}
}

func TestExpandLiteral(t *testing.T) {
	exp := testExpander(nil)
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"/usr/bin/ls", "/usr/bin/ls"},
		{"no vars here", "no vars here"},
		{"/path/with spaces/file", "/path/with spaces/file"},
		{"$notavar", "$notavar"}, // lone $ without { is literal
		{"${", "${"},             // incomplete — no matching }, but only 2 chars
	}
	for _, tt := range tests {
		// The "${" case will error, skip it from the "want" checks
		if tt.in == "${" {
			_, err := exp.Expand(tt.in)
			if err == nil {
				t.Error("expected error for unterminated ${")
			}
			continue
		}
		got, err := exp.Expand(tt.in)
		if err != nil {
			t.Errorf("Expand(%q): unexpected error: %v", tt.in, err)
			continue
		}
		if got.String() != tt.want {
			t.Errorf("Expand(%q) = %q, want %q", tt.in, got.String(), tt.want)
		}
	}
}

func TestExpandSimpleVar(t *testing.T) {
	os.Setenv("_LC_TEST_A", "/foo")
	defer os.Unsetenv("_LC_TEST_A")

	exp := testExpander(nil)
	tests := []struct {
		in, want string
	}{
		{"${_LC_TEST_A}", "/foo"},
		{"${_LC_TEST_A}/bar", "/foo/bar"},
		{"/prefix/${_LC_TEST_A}/suffix", "/prefix//foo/suffix"},
		{"${_LC_TEST_A}${_LC_TEST_A}", "/foo/foo"},
	}
	for _, tt := range tests {
		got, err := exp.Expand(tt.in)
		if err != nil {
			t.Errorf("Expand(%q): %v", tt.in, err)
			continue
		}
		if got.String() != tt.want {
			t.Errorf("Expand(%q) = %q, want %q", tt.in, got.String(), tt.want)
		}
	}
}

func TestExpandBuiltinPrecedence(t *testing.T) {
	os.Setenv("home", "/env-home")
	defer os.Unsetenv("home")

	exp := testExpander(map[string]string{"home": "/builtin-home"})
	got, err := exp.Expand("${home}")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "/builtin-home" {
		t.Errorf("builtin should take precedence, got %q", got.String())
	}
}

func TestExpandUnsetNoDefault(t *testing.T) {
	os.Unsetenv("_LC_UNSET_VAR")
	exp := testExpander(nil)
	_, err := exp.Expand("${_LC_UNSET_VAR}")
	if err == nil {
		t.Error("expected error for unset var without default")
	}
}

func TestExpandDefaultLiteral(t *testing.T) {
	os.Unsetenv("_LC_UNSET")
	exp := testExpander(nil)
	tests := []struct {
		in, want string
	}{
		{"${_LC_UNSET:-/fallback}", "/fallback"},
		{"${_LC_UNSET:-}", ""},
		{"${_LC_UNSET:-literal text}", "literal text"},
		{"${_LC_UNSET:-/a/b/c}", "/a/b/c"},
	}
	for _, tt := range tests {
		got, err := exp.Expand(tt.in)
		if err != nil {
			t.Errorf("Expand(%q): %v", tt.in, err)
			continue
		}
		if got.String() != tt.want {
			t.Errorf("Expand(%q) = %q, want %q", tt.in, got.String(), tt.want)
		}
	}
}

func TestExpandDefaultUsedOnlyWhenEmpty(t *testing.T) {
	os.Setenv("_LC_SET", "/real")
	defer os.Unsetenv("_LC_SET")

	exp := testExpander(nil)
	got, err := exp.Expand("${_LC_SET:-/fallback}")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "/real" {
		t.Errorf("should use real value, got %q", got.String())
	}
}

func TestExpandNestedDefault(t *testing.T) {
	os.Unsetenv("_LC_OUTER")
	os.Setenv("_LC_INNER", "/inner")
	defer os.Unsetenv("_LC_INNER")

	exp := testExpander(nil)
	tests := []struct {
		in, want string
	}{
		{"${_LC_OUTER:-${_LC_INNER}}", "/inner"},
		{"${_LC_OUTER:-${_LC_INNER}/sub}", "/inner/sub"},
		{"${_LC_OUTER:-prefix/${_LC_INNER}/suffix}", "prefix//inner/suffix"},
	}
	for _, tt := range tests {
		got, err := exp.Expand(tt.in)
		if err != nil {
			t.Errorf("Expand(%q): %v", tt.in, err)
			continue
		}
		if got.String() != tt.want {
			t.Errorf("Expand(%q) = %q, want %q", tt.in, got.String(), tt.want)
		}
	}
}

func TestExpandDeeplyNested(t *testing.T) {
	os.Unsetenv("_LC_A")
	os.Unsetenv("_LC_B")
	os.Setenv("_LC_C", "/deep")
	defer os.Unsetenv("_LC_C")

	exp := testExpander(nil)
	got, err := exp.Expand("${_LC_A:-${_LC_B:-${_LC_C}}}")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "/deep" {
		t.Errorf("got %q, want /deep", got.String())
	}
}

func TestExpandNestedDefaultWithBuiltin(t *testing.T) {
	os.Unsetenv("_LC_CARGO_HOME")
	exp := testExpander(map[string]string{"dataDir": "/home/user/.local/share"})
	got, err := exp.Expand("${_LC_CARGO_HOME:-${dataDir}/cargo}")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "/home/user/.local/share/cargo" {
		t.Errorf("got %q", got.String())
	}
}

func TestExpandSegmentProvenance(t *testing.T) {
	os.Setenv("_LC_GLOB", "foo*bar")
	defer os.Unsetenv("_LC_GLOB")

	exp := testExpander(nil)

	// Variable with glob chars: FromVar=true, text is raw (no escaping)
	got, err := exp.Expand("${_LC_GLOB}")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "foo*bar" {
		t.Errorf("String() = %q, want %q", got.String(), "foo*bar")
	}
	if len(got) != 1 || !got[0].FromVar {
		t.Errorf("expected single FromVar=true segment, got %v", got)
	}

	// Literal glob stays as FromVar=false
	got, err = exp.Expand("/dir/*")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "/dir/*" {
		t.Errorf("String() = %q", got.String())
	}
	if len(got) != 1 || got[0].FromVar {
		t.Errorf("expected single FromVar=false segment, got %v", got)
	}

	// Mixed: var segment + literal segment
	got, err = exp.Expand("${_LC_GLOB}/*")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "foo*bar/*" {
		t.Errorf("String() = %q", got.String())
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 segments, got %d", len(got))
	}
	if !got[0].FromVar || got[0].Text != "foo*bar" {
		t.Errorf("seg[0] = %+v", got[0])
	}
	if got[1].FromVar || got[1].Text != "/*" {
		t.Errorf("seg[1] = %+v", got[1])
	}
}

func TestExpandGlobInDefault(t *testing.T) {
	os.Unsetenv("_LC_X")
	os.Setenv("_LC_STAR", "a*b")
	defer os.Unsetenv("_LC_STAR")

	exp := testExpander(nil)
	// Nested var in fallback: FromVar=true
	got, err := exp.Expand("${_LC_X:-${_LC_STAR}}")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "a*b" {
		t.Errorf("got %q", got.String())
	}
	if len(got) != 1 || !got[0].FromVar {
		t.Errorf("expected FromVar=true segment, got %v", got)
	}
}

func TestExpandLiteralGlobInDefault(t *testing.T) {
	os.Unsetenv("_LC_X")
	exp := testExpander(nil)
	// Literal * in fallback: FromVar=false
	got, err := exp.Expand("${_LC_X:-/dev/dri/card*}")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "/dev/dri/card*" {
		t.Errorf("got %q", got.String())
	}
	if len(got) != 1 || got[0].FromVar {
		t.Errorf("expected FromVar=false segment, got %v", got)
	}
}

func TestExpandQuestionMark(t *testing.T) {
	os.Setenv("_LC_Q", "a?b")
	defer os.Unsetenv("_LC_Q")

	exp := testExpander(nil)
	got, err := exp.Expand("${_LC_Q}")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "a?b" {
		t.Errorf("got %q", got.String())
	}
	if len(got) != 1 || !got[0].FromVar {
		t.Errorf("expected FromVar=true, got %v", got)
	}
}

func TestExpandBracket(t *testing.T) {
	os.Setenv("_LC_BR", "a[0]b")
	defer os.Unsetenv("_LC_BR")

	exp := testExpander(nil)
	got, err := exp.Expand("${_LC_BR}")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "a[0]b" {
		t.Errorf("got %q", got.String())
	}
	if !got[0].FromVar {
		t.Error("expected FromVar=true")
	}
}

func TestExpandBackslashInValue(t *testing.T) {
	os.Setenv("_LC_BS", `a\b`)
	defer os.Unsetenv("_LC_BS")

	exp := testExpander(nil)
	got, err := exp.Expand("${_LC_BS}")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != `a\b` {
		t.Errorf("got %q, want %q", got.String(), `a\b`)
	}
}

func TestExpandUnterminatedBrace(t *testing.T) {
	exp := testExpander(nil)
	cases := []string{
		"${FOO",
		"${FOO:-${BAR}",
		"${FOO:-${BAR:-baz}",
		"/path/${UNCLOSED",
	}
	for _, c := range cases {
		_, err := exp.Expand(c)
		if err == nil {
			t.Errorf("Expand(%q): expected error for unterminated", c)
		}
	}
}

func TestExpandDollarLiteral(t *testing.T) {
	exp := testExpander(nil)
	tests := []struct {
		in, want string
	}{
		{"$", "$"},
		{"$$", "$$"},
		{"$x", "$x"},
		{"$ {foo}", "$ {foo}"},
		{"cost is $5", "cost is $5"},
	}
	for _, tt := range tests {
		got, err := exp.Expand(tt.in)
		if err != nil {
			t.Errorf("Expand(%q): %v", tt.in, err)
			continue
		}
		if got.String() != tt.want {
			t.Errorf("Expand(%q) = %q, want %q", tt.in, got.String(), tt.want)
		}
	}
}

func TestExpandMultipleVars(t *testing.T) {
	os.Setenv("_LC_A", "aaa")
	os.Setenv("_LC_B", "bbb")
	defer os.Unsetenv("_LC_A")
	defer os.Unsetenv("_LC_B")

	exp := testExpander(nil)
	got, err := exp.Expand("/${_LC_A}/${_LC_B}/end")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "/aaa/bbb/end" {
		t.Errorf("got %q", got.String())
	}
}

func TestExpandAdjacentVars(t *testing.T) {
	os.Setenv("_LC_X", "x")
	os.Setenv("_LC_Y", "y")
	defer os.Unsetenv("_LC_X")
	defer os.Unsetenv("_LC_Y")

	exp := testExpander(nil)
	got, err := exp.Expand("${_LC_X}${_LC_Y}")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "xy" {
		t.Errorf("got %q, want %q", got.String(), "xy")
	}
}

func TestExpandColonInVarName(t *testing.T) {
	os.Setenv("_LC_COLON:VAR", "val")
	defer os.Unsetenv("_LC_COLON:VAR")

	exp := testExpander(nil)
	got, err := exp.Expand("${_LC_COLON:VAR}")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "val" {
		t.Errorf("got %q, want %q", got.String(), "val")
	}
}

func TestExpandDefaultContainsColon(t *testing.T) {
	os.Unsetenv("_LC_X")
	exp := testExpander(nil)
	got, err := exp.Expand("${_LC_X:-a:-b}")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "a:-b" {
		t.Errorf("got %q, want %q", got.String(), "a:-b")
	}
}

func TestExpandEmptyVarName(t *testing.T) {
	exp := testExpander(nil)
	_, err := exp.Expand("${}")
	if err == nil {
		t.Error("expected error for empty var name")
	}
}

func TestExpandEmptyBuiltin(t *testing.T) {
	exp := testExpander(map[string]string{"emptyBuiltin": ""})
	_, err := exp.Expand("${emptyBuiltin}")
	if err == nil {
		t.Error("expected error for empty builtin without default")
	}

	got, err := exp.Expand("${emptyBuiltin:-/fallback}")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "/fallback" {
		t.Errorf("got %q, want /fallback", got.String())
	}
}

func TestExpandRealWorldPatterns(t *testing.T) {
	os.Setenv("HOME", "/home/user")
	os.Unsetenv("XDG_DATA_HOME")
	os.Unsetenv("CARGO_HOME")
	defer os.Setenv("HOME", os.Getenv("HOME"))

	exp := NewExpander()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"simple home", "${home}/.config", "/home/user/.config"},
		{"dataDir default", "${dataDir}", "/home/user/.local/share"},
		{"cargo with fallback", "${CARGO_HOME:-${dataDir}/cargo}", "/home/user/.local/share/cargo"},
		{"tmpDir", "${tmpDir}", firstNonEmpty(os.Getenv("TMPDIR"), "/tmp")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := exp.Expand(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != tt.want {
				t.Errorf("got %q, want %q", got.String(), tt.want)
			}
		})
	}
}

func TestSplitDefault(t *testing.T) {
	tests := []struct {
		in          string
		name, def   string
		hasFallback bool
	}{
		{"FOO", "FOO", "", false},
		{"FOO:-bar", "FOO", "bar", true},
		{"FOO:-", "FOO", "", true},
		{"FOO:-${BAR:-baz}", "FOO", "${BAR:-baz}", true},
		{":-val", "", "val", true},
		{"X:-a:-b", "X", "a:-b", true},
	}
	for _, tt := range tests {
		name, def, has := splitDefault(tt.in)
		if name != tt.name || def != tt.def || has != tt.hasFallback {
			t.Errorf("splitDefault(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.in, name, def, has, tt.name, tt.def, tt.hasFallback)
		}
	}
}
