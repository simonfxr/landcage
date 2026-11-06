package winpsec

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestCommandLine(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want string
	}{
		{"simple", []string{"tool", "one", "two"}, `tool one two`},
		{"full argv", []string{`C:\Program Files\tool.exe`, "--flag"}, `"C:\Program Files\tool.exe" --flag`},
		{"empty argument", []string{"tool", ""}, `tool ""`},
		{"spaces tabs", []string{"tool", "a b", "a\tb"}, "tool \"a b\" \"a\tb\""},
		{"quote", []string{"tool", `a"b`}, `tool "a\"b"`},
		{"backslash quote", []string{"tool", `a\"b`}, `tool "a\\\"b"`},
		{"trailing backslash", []string{"tool", `a b\`}, `tool "a b\\"`},
		{"plain backslashes", []string{"tool", `a\b\`}, `tool a\b\`},
		{"argv0 special", []string{`C:\a b\`, `a b\`}, `"C:\a b\" "a b\\"`},
		{"literal shell metacharacters", []string{"tool", "$HOME", "a&b", ";", "%PATH%"}, `tool $HOME a&b ; %PATH%`},
		{"unicode", []string{"プログラム", "中文 😀"}, "プログラム \"中文 😀\""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command, err := commandLine(test.argv)
			if err != nil {
				t.Fatal(err)
			}
			if command[len(command)-1] != 0 {
				t.Fatal("command line is not NUL-terminated")
			}
			if got := string(utf16.Decode(command[:len(command)-1])); got != test.want {
				t.Fatalf("commandLine(%q) = %q, want %q", test.argv, got, test.want)
			}
		})
	}
}

func TestCommandLineRejectsInvalidInput(t *testing.T) {
	for _, argv := range [][]string{
		nil, {}, {""}, {`bad"argv0`}, {"tool", "embedded\x00NUL"},
		{"tool", "\xff"}, {"\xff"}, {strings.Repeat("a", 32767)},
		{"tool", strings.Repeat("😀", 16384)},
	} {
		if _, err := commandLine(argv); err == nil {
			t.Errorf("commandLine(%q) should fail", argv)
		}
	}
	if _, err := commandLine([]string{strings.Repeat("a", 32766)}); err != nil {
		t.Fatalf("maximum-length command line rejected: %v", err)
	}
}

func decodeEnvironmentBlock(block []uint16) []string {
	var entries []string
	for len(block) > 0 && block[0] != 0 {
		end := 0
		for block[end] != 0 {
			end++
		}
		entries = append(entries, string(utf16.Decode(block[:end])))
		block = block[end+1:]
	}
	return entries
}

func TestEnvironmentBlock(t *testing.T) {
	tests := []struct {
		name string
		env  []string
		want []string
	}{
		{"nil is clean", nil, nil},
		{"empty is clean", []string{}, nil},
		{"sort", []string{"z=last", "Alpha=first", "beta=second"}, []string{"Alpha=first", "beta=second", "z=last"}},
		{"last wins", []string{"Path=old", "PATH=new", "path=last"}, []string{"path=last"}},
		{"values are verbatim", []string{"empty=", "equals=a=b", "UNICODE=中文😀"}, []string{"empty=", "equals=a=b", "UNICODE=中文😀"}},
		{"drive cwd", []string{"z=x", "=C:=C:\\path", "=d:=D:\\", "=c:=C:\\new"}, []string{"=c:=C:\\new", "=d:=D:\\", "z=x"}},
		{"unicode names", []string{"é=first", "É=last"}, []string{"É=last"}},
		{"UTF16 ordinal sort", []string{"\ue000=x", "\U00010000=y"}, []string{"\U00010000=y", "\ue000=x"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			original := append([]string(nil), test.env...)
			block, err := environmentBlock(test.env)
			if err != nil {
				t.Fatal(err)
			}
			if len(block) < 2 || block[len(block)-1] != 0 || block[len(block)-2] != 0 {
				t.Fatalf("block must end in double NUL: %v", block)
			}
			if got := decodeEnvironmentBlock(block); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("entries = %q, want %q", got, test.want)
			}
			if len(test.env) > 0 && !reflect.DeepEqual(test.env, original) {
				t.Fatal("environmentBlock mutated the caller's environment")
			}
		})
	}
}

func TestEnvironmentBlockRejectsInvalidInput(t *testing.T) {
	for _, entry := range []string{
		"", "missing separator", "=value", "A\x00B=value", "A=x\x00y",
		"A=\xff", "\xff=value", "=C:missing=value", "=C:no separator", "=1:=bad",
	} {
		if _, err := environmentBlock([]string{entry}); err == nil {
			t.Errorf("environmentBlock(%q) should fail", entry)
		}
	}
}
