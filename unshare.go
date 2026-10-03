package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/simonfxr/landcage/internal/allthreads"
	"github.com/simonfxr/landcage/policy"
)

const (
	childEnvKey     = "_LANDCAGE_CHILD"
	setupFDEnvKey   = "_LANDCAGE_SETUP_FD"
	startupFDEnvKey = "_LANDCAGE_STARTUP_FD"
)

// CAP_SYS_ADMIN capability number (needed for mount in user namespace).
const capSysAdmin = 21

// isChild is true in the re-exec'd child (PID 1 in new PID namespace / reaper).
var isChild = os.Getenv(childEnvKey) == "1"

// childStartup is the payload the parent sends the re-exec'd child over a pipe.
// The policy and resolved executable must not travel through the environment:
// /proc/1/environ keeps the exec-time block after unsetenv(3) and the payload
// can read it. The fds passed to childFD carry no policy data, so env is fine.
type childStartup struct {
	Policy json.RawMessage `json:"policy"`
	Bin    string          `json:"bin"`
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

// mountProc remounts /proc in the new mount+PID namespace.
func mountProc() error {
	if err := syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("making mounts private: %w", err)
	}
	if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		return fmt.Errorf("mounting /proc: %w", err)
	}
	return nil
}

// dropAllCaps clears all capabilities (ambient, inheritable, effective, permitted)
// on ALL threads so the target doesn't inherit caps from any Go runtime thread.
func dropAllCaps() error {
	const prCapAmbient = 47
	const prCapAmbientClearAll = 4
	if _, _, errno := allthreads.AllThreadsSyscall6(syscall.SYS_PRCTL, prCapAmbient, prCapAmbientClearAll, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("clearing ambient capabilities: %w", errno)
	}

	// Clear inheritable, effective, and permitted via capset(2) on ALL threads.
	type capHeader struct {
		Version uint32
		Pid     int32
	}
	type capData struct {
		Effective   uint32
		Permitted   uint32
		Inheritable uint32
	}
	hdr := capHeader{Version: 0x20080522} // _LINUX_CAPABILITY_VERSION_3
	data := [2]capData{}                  // all zeros = no caps
	_, _, errno := allthreads.AllThreadsSyscall3(syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&data[0])),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("clearing capabilities: %w", errno)
	}
	return nil
}

// namespaceAttrs builds the clone attributes for the re-exec'd child; with User,
// uid/gid map to themselves and CAP_SYS_ADMIN is ambient for mountProc.
func namespaceAttrs(cfg *policy.UnshareConfig) *syscall.SysProcAttr {
	attrs := &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if cfg == nil {
		return attrs
	}
	if cfg.User {
		attrs.Cloneflags |= syscall.CLONE_NEWUSER
		uid, gid := os.Geteuid(), os.Getegid()
		attrs.UidMappings = []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}}
		attrs.GidMappings = []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}}
		attrs.AmbientCaps = []uintptr{capSysAdmin}
	}
	if cfg.PID {
		attrs.Cloneflags |= syscall.CLONE_NEWPID
	}
	if cfg.Cgroup {
		attrs.Cloneflags |= syscall.CLONE_NEWCGROUP
	}
	if cfg.MountProc {
		attrs.Cloneflags |= syscall.CLONE_NEWNS
	}
	return attrs
}

// forkChild clones a child into new namespaces and waits for it. The child runs
// with the payload's environment and gets the policy and executable over the
// startup pipe.
// Returns (exit code, true) on success, or (0, false) if namespace creation failed.
func forkChild(pol *policy.Policy, env policy.Environ, bin string, cmdArgs []string) (int, bool) {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: resolving self: %v\n", err)
		return 1, true
	}

	policyJSON, err := json.Marshal(pol)
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: serializing policy: %v\n", err)
		return 1, true
	}
	startup, err := json.Marshal(childStartup{Policy: policyJSON, Bin: bin})
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: serializing startup: %v\n", err)
		return 1, true
	}

	// Setup-status pipe: the child writes "ok" once its namespaces are ready.
	// EOF instead means setup failed and the caller falls back to landlock only.
	pr, pw, err := os.Pipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: pipe: %v\n", err)
		return 1, true
	}
	startupR, startupW, err := os.Pipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: pipe: %v\n", err)
		pr.Close()
		pw.Close()
		return 1, true
	}

	// ExtraFiles[i] becomes fd i+3 in the child.
	extraFiles := extraFilesForInherit()
	setupFDIndex := len(extraFiles)
	extraFiles = append(extraFiles, pw)
	setupFD := setupFDIndex + 3
	startupFDIndex := len(extraFiles)
	extraFiles = append(extraFiles, startupR)
	startupFD := startupFDIndex + 3

	child := exec.Command(self, append([]string{"--"}, cmdArgs...)...)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	child.Env = append(env.ToSlice(),
		childEnvKey+"=1",
		fmt.Sprintf("%s=%d", setupFDEnvKey, setupFD),
		fmt.Sprintf("%s=%d", startupFDEnvKey, startupFD),
	)
	child.ExtraFiles = extraFiles
	child.SysProcAttr = namespaceAttrs(pol.Unshare)

	// Subscribe to signals BEFORE Start to avoid losing a fast SIGTERM.
	sigCh := make(chan os.Signal, 16)
	signal.Notify(sigCh,
		syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT,
		syscall.SIGWINCH, syscall.SIGUSR1, syscall.SIGUSR2,
	)

	if err := child.Start(); err != nil {
		signal.Stop(sigCh)
		pr.Close()
		pw.Close()
		startupR.Close()
		startupW.Close()
		closeExtraFiles(extraFiles[:setupFDIndex])
		if isNamespaceError(err) {
			return 0, false
		}
		fmt.Fprintf(os.Stderr, "landcage: namespace exec: %v\n", err)
		return 1, true
	}
	pw.Close()
	startupR.Close()
	closeExtraFiles(extraFiles[:setupFDIndex])

	// A failed write means the child died during setup; the pipe below reports it.
	_, _ = startupW.Write(startup)
	startupW.Close()

	// Read setup status from child. "ok" = success. EOF = setup failed.
	var buf [2]byte
	n, _ := pr.Read(buf[:])
	pr.Close()
	if n == 0 {
		// Child died or failed during setup — wait and fall back.
		signal.Stop(sigCh)
		child.Wait()
		return 0, false
	}

	go func() {
		for sig := range sigCh {
			_ = child.Process.Signal(sig)
		}
	}()

	err = child.Wait()
	signal.Stop(sigCh)
	close(sigCh)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), true
		}
		fmt.Fprintf(os.Stderr, "landcage: wait: %v\n", err)
		return 1, true
	}
	return 0, true
}

// isNamespaceError returns true if the error indicates namespace creation
// failed (e.g. nested sandbox, kernel limits).
func isNamespaceError(err error) bool {
	if errno, ok := errors.AsType[syscall.Errno](err); ok {
		switch errno {
		case syscall.EPERM, syscall.ENOSPC, syscall.EUSERS, syscall.EINVAL:
			return true
		}
	}
	return false
}

// reaperExec acts as PID 1: forks the target command and reaps all children.
func reaperExec(bin string, argv []string, env []string) int {
	// Subscribe to signals BEFORE fork to avoid missing a fast SIGCHLD.
	sigCh := make(chan os.Signal, 16)
	signal.Notify(sigCh,
		syscall.SIGCHLD,
		syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT,
		syscall.SIGWINCH, syscall.SIGUSR1, syscall.SIGUSR2,
	)
	defer signal.Stop(sigCh)

	childPid, err := syscall.ForkExec(bin, argv, &syscall.ProcAttr{
		Env:   env,
		Files: inheritFDs(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: exec: %v\n", err)
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENOTDIR) {
			return 127
		}
		return 126
	}

	for sig := range sigCh {
		switch sig {
		case syscall.SIGCHLD:
			for {
				var status syscall.WaitStatus
				pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
				if pid <= 0 || err != nil {
					break
				}
				if pid == childPid {
					if status.Exited() {
						return status.ExitStatus()
					}
					if status.Signaled() {
						return 128 + int(status.Signal())
					}
					return 1
				}
				// orphan reaped
			}
		default:
			if s, ok := sig.(syscall.Signal); ok {
				_ = syscall.Kill(childPid, s)
			}
		}
	}
	return 1
}

// inheritFDs builds a Files slice for ForkExec that passes through all open,
// non-CLOEXEC fds — matching fork()+exec() semantics.
func inheritFDs() []uintptr {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return []uintptr{0, 1, 2}
	}

	var openFDs []int
	var maxFD int
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		flags, _, errno := syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if errno != 0 {
			continue
		}
		if flags&syscall.FD_CLOEXEC != 0 {
			continue
		}
		openFDs = append(openFDs, fd)
		if fd > maxFD {
			maxFD = fd
		}
	}

	files := make([]uintptr, maxFD+1)
	for i := range files {
		files[i] = ^uintptr(0)
	}
	for _, fd := range openFDs {
		files[fd] = uintptr(fd)
	}
	return files
}

// extraFilesForInherit builds an ExtraFiles slice for exec.Cmd that passes
// all open non-CLOEXEC fds beyond 0,1,2 to the child at their original numbers.
func extraFilesForInherit() []*os.File {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil
	}

	var maxFD int
	openFDs := make(map[int]bool)
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd <= 2 {
			continue
		}
		flags, _, errno := syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if errno != 0 {
			continue
		}
		if flags&syscall.FD_CLOEXEC != 0 {
			continue
		}
		openFDs[fd] = true
		if fd > maxFD {
			maxFD = fd
		}
	}

	if maxFD <= 2 {
		return nil
	}

	// ExtraFiles[i] → fd i+3 in child.
	// Dup with CLOEXEC so the dup doesn't leak through exec
	// (forkAndExecInChild clears CLOEXEC on the target position after dup2).
	extra := make([]*os.File, maxFD-2)
	for fd := 3; fd <= maxFD; fd++ {
		if openFDs[fd] {
			newfd, err := syscall.Dup(fd)
			if err == nil {
				syscall.CloseOnExec(newfd)
				extra[fd-3] = os.NewFile(uintptr(newfd), "")
			}
		}
	}
	return extra
}

func closeExtraFiles(files []*os.File) {
	for _, f := range files {
		if f != nil {
			f.Close()
		}
	}
}
