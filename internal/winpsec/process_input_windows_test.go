package winpsec

import (
	"reflect"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func TestCommandLineWindowsRoundTrip(t *testing.T) {
	for _, argv0 := range []string{"tool", `C:\Program Files\tool.exe`, `C:\a b\`, "プログラム"} {
		argv := []string{argv0, "", " ", "\t", `plain\`, `spaced \`, `a"b`, `a\"b`, `a\\"b`, "中文😀"}
		command, err := commandLine(argv)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := windows.DecomposeCommandLine(string(utf16.Decode(command[:len(command)-1])))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(parsed, argv) {
			t.Fatalf("Windows command line round trip = %q, want %q", parsed, argv)
		}
	}
}
