package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/simonfxr/landcage/policy"
)

const childEnvKey = "_LANDCAGE_CHILD"

// Env var holding the fd number of the setup-status pipe in the child.
const setupFDEnvKey = "_LANDCAGE_SETUP_FD"

// CAP_SYS_ADMIN capability number (needed for mount in user namespace).
const capSysAdmin = 21

// isChild is true in the re-exec'd child (PID 1 in new PID namespace / reaper).
var isChild = os.Getenv(childEnvKey) == "1"

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
func dropAllCaps() {
	// Clear ambient capabilities (per-thread, but ambient is rarely on other threads).
	const prCapAmbient = 47
	const prCapAmbientClearAll = 4
	syscall.RawSyscall6(syscall.SYS_PRCTL, prCapAmbient, prCapAmbientClearAll, 0, 0, 0, 0)

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
	syscall.AllThreadsSyscall(syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&data[0])),
		0,
	)
}

// forkChild clones a child into new namespaces and waits for it.
// Uses clone(2) with all namespace flags — the child is PID 1 in the new PID ns
// and root (uid 0) in the new user ns (giving it full capabilities for mount etc).
// Returns (exit code, true) on success, or (0, false) if namespace creation failed.
func forkChild(cfg *policy.UnshareConfig, args []string) (int, bool) {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: resolving self: %v\n", err)
		return 1, true
	}

	// Pipe for child to signal setup status. Child writes "ok" after successful
	// mount/setup, then closes. If child dies during setup, read returns EOF → fallback.
	pr, pw, err := os.Pipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: pipe: %v\n", err)
		return 1, true
	}

	// Build ExtraFiles: all inherited fds + the setup pipe write end.
	extraFiles := extraFilesForInherit()
	setupFDIndex := len(extraFiles) // position in ExtraFiles
	extraFiles = append(extraFiles, pw)
	setupFD := setupFDIndex + 3 // fd number in child (ExtraFiles[i] → fd i+3)

	cmd := exec.Command(self, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), childEnvKey+"=1", fmt.Sprintf("%s=%d", setupFDEnvKey, setupFD))
	cmd.ExtraFiles = extraFiles

	var cloneFlags uintptr
	if cfg.User {
		cloneFlags |= syscall.CLONE_NEWUSER
	}
	if cfg.PID {
		cloneFlags |= syscall.CLONE_NEWPID
	}
	if cfg.Cgroup {
		cloneFlags |= syscall.CLONE_NEWCGROUP
	}
	if cfg.MountProc {
		cloneFlags |= syscall.CLONE_NEWNS
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: cloneFlags,
		Pdeathsig:  syscall.SIGKILL,
	}

	if cfg.User {
		uid := os.Geteuid()
		gid := os.Getegid()
		// Map current uid/gid to itself inside (like --map-current-user).
		// AmbientCaps grants CAP_SYS_ADMIN so the child can mount /proc after exec.
		cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
			{ContainerID: uid, HostID: uid, Size: 1},
		}
		cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
			{ContainerID: gid, HostID: gid, Size: 1},
		}
		cmd.SysProcAttr.AmbientCaps = []uintptr{capSysAdmin}
	}

	// Subscribe to signals BEFORE Start to avoid losing a fast SIGTERM.
	sigCh := make(chan os.Signal, 16)
	signal.Notify(sigCh,
		syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT,
		syscall.SIGWINCH, syscall.SIGUSR1, syscall.SIGUSR2,
	)

	if err := cmd.Start(); err != nil {
		signal.Stop(sigCh)
		pr.Close()
		pw.Close()
		closeExtraFiles(extraFiles[:setupFDIndex])
		if isNamespaceError(err) {
			return 0, false
		}
		fmt.Fprintf(os.Stderr, "landcage: namespace exec: %v\n", err)
		return 1, true
	}
	pw.Close() // parent doesn't write
	closeExtraFiles(extraFiles[:setupFDIndex])

	// Read setup status from child. "ok" = success. EOF = setup failed.
	var buf [2]byte
	n, _ := pr.Read(buf[:])
	pr.Close()
	if n == 0 {
		// Child died or failed during setup — wait and fall back.
		signal.Stop(sigCh)
		cmd.Wait()
		return 0, false
	}

	go func() {
		for sig := range sigCh {
			_ = cmd.Process.Signal(sig)
		}
	}()

	err = cmd.Wait()
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
	var errno syscall.Errno
	if errors.As(err, &errno) {
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
