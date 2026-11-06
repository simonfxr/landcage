//go:build darwin && cgo

package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSeatbeltEnforcePlantedSymlink(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	allowed, outside := filepath.Join(dir, "allowed"), filepath.Join(dir, "outside")
	seatbeltMkdir(t, allowed)
	seatbeltMkdir(t, outside)
	secret := filepath.Join(outside, "secret")
	seatbeltWriteFile(t, secret)
	link := filepath.Join(allowed, "link")
	req := seatbeltCompile(t, &Policy{FS: []FSRule{
		{Path: allowed, Access: "rwcd"},
	}}, []seatbeltProbe{
		{"read", filepath.Join(link, "secret"), true},
		{"write", filepath.Join(link, "secret"), true},
		{"create", filepath.Join(link, "new-file"), true},
		{"remove", filepath.Join(link, "secret"), true},
	})
	// Plant the link after compilation, as an untrusted workload could.
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	seatbeltRun(t, req)
}

func TestSeatbeltEnforceMutations(t *testing.T) {
	for _, access := range []string{"r", "w", "c", "d", "wc", "rwcd"} {
		t.Run(access, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"write", "truncate", "append", "remove"} {
				seatbeltWriteFile(t, filepath.Join(dir, name))
			}
			seatbeltMkdir(t, filepath.Join(dir, "remove-dir"))
			write := strings.Contains(access, "w")
			create := strings.Contains(access, "c")
			remove := strings.Contains(access, "d")
			probes := []seatbeltProbe{
				{"write", filepath.Join(dir, "write"), !write},
				{"truncate", filepath.Join(dir, "truncate"), !write},
				{"append", filepath.Join(dir, "append"), !write},
				// Seatbelt checks file-write-create, not file-write-data,
				// when opening a new file. That descriptor is writable
				// even without w; reopening it for writing is still denied.
				{"create", filepath.Join(dir, "new-file"), !create},
				{"mkdir", filepath.Join(dir, "new-dir"), !create},
				{"remove", filepath.Join(dir, "remove"), !remove},
				{"remove", filepath.Join(dir, "remove-dir"), !remove},
			}
			if create {
				probes = append(probes, seatbeltProbe{"write", filepath.Join(dir, "new-file"), !write})
			}
			seatbeltRun(t, seatbeltCompile(t, &Policy{FS: []FSRule{
				{Path: dir, Access: access},
			}}, probes))
		})
	}
}
