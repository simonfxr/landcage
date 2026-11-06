//go:build darwin && cgo

package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSeatbeltEnforceAliases(t *testing.T) {
	for _, base := range []string{"/tmp", "/var/tmp", "chained"} {
		t.Run(base, func(t *testing.T) {
			var alias string
			if base == "chained" {
				dir := sbplTempDir(t)
				seatbeltMkdir(t, filepath.Join(dir, "target"))
				for name, target := range map[string]string{"first": "second", "second": "target"} {
					if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
						t.Fatal(err)
					}
				}
				alias = filepath.Join(dir, "first")
			} else {
				var err error
				alias, err = os.MkdirTemp(base, "landcage-alias-")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.RemoveAll(alias) })
			}
			canonical, err := filepath.EvalSymlinks(alias)
			if err != nil {
				t.Fatal(err)
			}
			if alias == canonical {
				t.Fatalf("fixture %s is not an alias", alias)
			}
			for _, name := range []string{"read", "write", "denied"} {
				seatbeltWriteFile(t, filepath.Join(alias, name))
			}
			if err := os.Symlink("read", filepath.Join(alias, "file-link")); err != nil {
				t.Fatal(err)
			}
			seatbeltMkdir(t, filepath.Join(alias, "allowed-dir"))
			seatbeltWriteFile(t, filepath.Join(alias, "allowed-dir", "child"))
			var probes []seatbeltProbe
			for _, dir := range []string{alias, canonical} {
				probes = append(probes,
					seatbeltProbe{"read", filepath.Join(dir, "read"), false},
					seatbeltProbe{"write", filepath.Join(dir, "read"), true},
					seatbeltProbe{"read", filepath.Join(dir, "file-link"), false},
					seatbeltProbe{"write", filepath.Join(dir, "file-link"), true},
					seatbeltProbe{"write", filepath.Join(dir, "write"), false},
					seatbeltProbe{"read", filepath.Join(dir, "write"), true},
					seatbeltProbe{"read", filepath.Join(dir, "denied"), true},
					seatbeltProbe{"write", filepath.Join(dir, "denied"), true},
					seatbeltProbe{"read", filepath.Join(dir, "allowed-dir", "child"), false},
				)
			}
			seatbeltRun(t, seatbeltCompile(t, &Policy{FS: []FSRule{
				{Path: filepath.Join(alias, "read"), Access: "r"},
				{Path: filepath.Join(alias, "file-link"), Access: "r"},
				{Path: filepath.Join(alias, "write"), Access: "w"},
				{Path: filepath.Join(alias, "allowed-dir"), Access: "r"},
			}}, probes))
		})
	}
}
