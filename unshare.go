package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
)

const (
	childEnvKey     = "_LANDCAGE_CHILD"
	setupFDEnvKey   = "_LANDCAGE_SETUP_FD"
	startupFDEnvKey = "_LANDCAGE_STARTUP_FD"
)

// isChild is true in the re-exec'd child (PID 1 in new PID namespace / reaper).
var isChild = os.Getenv(childEnvKey) == "1"

// childStartup is the payload the parent sends the re-exec'd child over a pipe.
// The policy and resolved executable must not travel through the environment:
// /proc/1/environ keeps the exec-time block after unsetenv(3) and the payload
// can read it. The fds passed to childFD carry no policy data, so env is fine.
type childStartup struct {
	Policy json.RawMessage `json:"policy"`
	Bin    string          `json:"bin"`
	Net    networkMode     `json:"net,omitempty"`
}

// childFD returns one of the pipe fds the parent passed to the child, rejected
// below fd 3 where ExtraFiles land.
func childFD(key string) (int, error) {
	fd, err := strconv.Atoi(os.Getenv(key))
	if err != nil || fd < 3 {
		return 0, fmt.Errorf("missing or invalid %s", key)
	}
	return fd, nil
}

// readChildStartup reads the startup payload and closes the pipe, so the
// payload cannot inherit it.
func readChildStartup(fd int) (childStartup, error) {
	var startup childStartup
	f := os.NewFile(uintptr(fd), "landcage-startup")
	if f == nil {
		return startup, fmt.Errorf("invalid startup pipe fd %d", fd)
	}
	raw, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		return startup, fmt.Errorf("reading startup payload: %w", err)
	}
	if len(raw) == 0 {
		return startup, errors.New("missing startup payload")
	}
	if err := json.Unmarshal(raw, &startup); err != nil {
		return startup, fmt.Errorf("decoding startup payload: %w", err)
	}
	if len(startup.Policy) == 0 {
		return startup, errors.New("missing policy in startup payload")
	}
	return startup, nil
}
