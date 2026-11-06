# macOS backend: Seatbelt SBPL

Landlock stays the Linux enforcement path. On macOS, landcage should apply the
same JSON policy with Seatbelt, by calling `sandbox_init_with_parameters` in
this process and then `exec`ing the command. Do not shell out to
`/usr/bin/sandbox-exec`.

The policy schema does not change. Templates, env scrubbing, glob resolution,
and `create_dir` stay where they are. SBPL is a compile target, not a second
policy language.

## What calls the symbol

These maintained codebases call the private libsandbox symbols directly:

| Project | Call | File |
|---|---|---|
| WebKit | `sandbox_compile_string` / `sandbox_apply`, and `sandbox_init_with_parameters` | `Source/WebKit/Shared/mac/AuxiliaryProcessMac.mm` |
| Chromium | `sandbox_init`, `sandbox_init_with_parameters`, `sandbox_compile_string`, `sandbox_apply` | `sandbox/mac/seatbelt.cc` |
| Firefox | `sandbox_init_with_parameters` | `security/sandbox/mac/Sandbox.mm` in `mozilla-firefox/firefox` |
| Ladybird | `sandbox_init_with_parameters` | `Libraries/LibSandbox/Sandbox.cpp` |
| rustnet | `sandbox_init_with_parameters` via an extern in libSystem | `crates/rustnet-sandbox/src/macos/seatbelt.rs` |
| agentsh | cgo wrapper around `sandbox_init_with_parameters` | `cmd/agentsh-macwrap/main.go` |

Ladybird is the closest shape: build an SBPL string from an allowlist and apply
it in-process. WebKit and Chromium also pass paths as profile parameters, which
is what landcage should do. agentsh is the cgo pattern to copy.

`sandbox-exec` is only a client of this function. Apple marks both the CLI and
`sandbox_init` deprecated and still ships them. App Sandbox entitlements cannot
wrap an arbitrary command. The kernel accepts compiled bytecode through
`__sandbox_ms`; the compiler is `libsandbox`. Linking that library is the
dependency. Reimplementing the bytecode is not.

## Where it sits

`runSandboxed` already enforces, then replaces this process:

```go
policy.Enforce(pol)
syscall.Exec(bin, cmd, argv)
```

Darwin takes the same path. There is no pid namespace and no reaper. `unshare`
is Linux-only: if a policy sets it, print one stderr warning and continue.
The agent profile sets `unshare` and must still run.

Env rules are applied before enforcement, as on Linux. On Darwin, also unset
`DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `DYLD_FRAMEWORK_PATH`,
`DYLD_FALLBACK_LIBRARY_PATH`, and `DYLD_ROOT_PATH` when the policy did not
set that key itself.

## Calling it from Go

Landlock's all-thread helper is already cgo behind a build tag
(`internal/allthreads/syscall_cgo.go`, `//go:build linux && cgo`). Seatbelt
follows that split. The generator is pure Go and is what Linux tests cover.
The apply step is `//go:build darwin && cgo`.

agentsh (`cmd/agentsh-macwrap/main.go`) does the call like this, with a null
parameter list:

```c
extern int sandbox_init_with_parameters(const char *profile, uint64_t flags,
    const char *const parameters[], char **errorbuf);

int apply_sandbox(const char *profile, char **errorbuf) {
    return sandbox_init_with_parameters(profile, 0, NULL, errorbuf);
}
```

```go
cProfile := C.CString(profile)
defer C.free(unsafe.Pointer(cProfile))

var errorbuf *C.char
rc := C.apply_sandbox(cProfile, &errorbuf)
```

landcage needs the parameter array. Do not include `<sandbox.h>`: the SDK marks
the prototype unavailable, and a redeclaration next to that header breaks the
build. Declare the extern next to `stdlib.h` only, and link with `-lsandbox`
(libSystem re-exports it; `-lsandbox` makes the dependency obvious).

`flags` is `0` for an SBPL string. `parameters` is a NULL-terminated sequence
of key, value, key, value, …. The profile reads them as `(param "p0")`.
`sandbox_free_error` is deprecated; the buffer is malloc'd, so `free` it, which
is what agentsh does.

Sketch of the Go side:

```go
//go:build darwin && cgo

/*
#cgo LDFLAGS: -lsandbox
#include <stdlib.h>
#include <stdint.h>

extern int sandbox_init_with_parameters(const char *profile, uint64_t flags,
    const char *const parameters[], char **errorbuf);
*/
import "C"

func apply(profile string, params []string) error {
    cProfile := C.CString(profile)
    defer C.free(unsafe.Pointer(cProfile))

    // NULL-terminated key/value pairs. A single trailing NULL is an empty list.
    cParams := make([]*C.char, len(params)+1)
    for i, s := range params {
        cParams[i] = C.CString(s)
        defer C.free(unsafe.Pointer(cParams[i]))
    }
    var errbuf *C.char
    rc := C.sandbox_init_with_parameters(
        cProfile, 0, (**C.char)(unsafe.Pointer(&cParams[0])), &errbuf)
    if rc != 0 {
        // free errbuf and return its text
    }
    return nil
}
```

Call it once, from the enforce path, immediately before `syscall.Exec`. The
label is on the process and survives `exec`. One call is enough; the compiler
inside libsandbox is not safe for concurrent callers. A `//go:build darwin && !cgo`
file must fail with a clear error that Darwin enforcement needs cgo.

`nix build .#landcage-aarch64-darwin` cross-compiles it from Linux. zig cc
targets `aarch64-macos` and supplies libSystem. libsandbox, libresolv, and
CoreFoundation are stubs with the macOS install names
(`/usr/lib/libsandbox.1.dylib`, `/usr/lib/libresolv.9.dylib`,
`CoreFoundation.framework/Versions/A/CoreFoundation`), so dyld binds the real
libraries on a Mac. `pkgsCross.aarch64-darwin` is not used: its apple-sdk
rebuilds from source and currently fails. The generator tests do not need
this build.

## Compiling a policy to SBPL

Put the compiler in package `policy` (`sbpl.go`) so it can use `resolvePath`
and the existing `create_dir` checks. It must not import go-landlock.

Paths go in as parameters, never as scheme literals. A path containing
`") (allow file-write*` would otherwise rewrite the profile. Parameter names
are generated (`p0`, `p1`, …). Literal paths and each resolved glob match are
made absolute and symlink-resolved before emission, including macOS aliases
such as `/tmp` and `/var`.
Each symlink traversed in a policy path also gets a literal
`file-read-metadata` grant, including chained targets: otherwise Seatbelt denies
access through the alias before checking the canonical target's grant. This
reveals those aliases' metadata, not sibling data or directory contents.

Preparation (`create_dir`, stat, glob) happens before compile, matching
`buildFSRules` in `enforce.go`. Compile itself does not create directories
when called from tests; the Darwin enforce path creates them first, then
compiles, then applies.

### Base profile

Every generated profile starts with a fixed preamble:

```scheme
(version 1)
(deny default)
(allow process-fork)
(allow system-socket (socket-domain AF_UNIX))
(allow signal (target same-sandbox))
(allow process-info* (target same-sandbox))
(allow file-read-data file-read-metadata (literal "/"))
(allow sysctl-read (sysctl-name "hw.pagesize_compat"))
(allow file-ioctl (literal "/dev/null"))
(allow file-read* file-write-data (literal "/dev/null"))
(allow file-read* (literal "/dev/urandom"))
(allow file-read* (literal "/dev/random"))
(allow file-read* (literal "/dev/zero"))
(allow mach-lookup
  (global-name "com.apple.system.logger")
  (global-name "com.apple.system.opendirectoryd.libinfo"))
```

`(allow signal (target same-sandbox))` is the translation of a pid namespace
plus `"signal": "allow"`. Seatbelt cannot hide host processes and also let
`ps` work, so v1 does not allow `com.apple.sysmond.system`. A later change can
grow the mach and sysctl allowlist toward the set Chromium and Codex carry.
Do not block this branch on that list.

Execution is not allowed by the preamble: each `x` rule grants `process-exec`
and executable mappings only on its own path. `file-exec` is not a Seatbelt
operation. The AF_UNIX socket-creation grant does not allow pathname
connections or binding; those are controlled separately below.

The literal root-directory data grant is required for dyld shared-cache startup
on the tested macOS 26.7.2 VM: without it, even `/bin/echo` aborts despite `rx`
grants for `/bin`, `/usr`, and `/System`. The dyld abort payload is
`failed to open root directory: /: 1`. Metadata access alone does not fix it,
but is also needed by `realpath` (observed in Command Line Tools Python).
These grants permit listing/statting `/` itself, not reading or executing
arbitrary descendants; do not replace them with a recursive `(subpath "/")`.
The one named sysctl grant is also measured: denying `hw.pagesize_compat`
causes Apple's linker to abort on a buffer-alignment assertion. No general
`sysctl-read` grant is needed for the tested C build.

### Filesystem

Default deny comes from the preamble. Emit one allow per resolved path.

| Policy | SBPL operations | Filter |
|---|---|---|
| `r` | `file-read*` | `(subpath (param "pN"))` for a directory, `(literal (param "pN"))` for a file |
| `w` | `file-write-data` | same |
| `x` | `file-map-executable` `process-exec` | same |
| `c` on a directory | `file-write-create`, plus UNIX `network-bind` and `network-inbound` | filesystem `subpath`; `(local unix-socket (subpath (param "pN")))` for socket bind/accept |
| `d` on a directory | `file-write-unlink` | same |
| `u` | `network-outbound` | `(remote unix-socket (path-literal (param "pN")))` for an exact path; `(remote unix-socket (subpath (param "pN")))` for a directory |
| `ioctl_dev` | `file-ioctl` | same filter |

`c` or `d` on a path that stats as a file is an error, same as Landlock.
Missing path with `ignore_missing` is skipped. A glob that matches nothing
with `ignore_missing` is skipped; without it, compile fails.
`refer` has no Seatbelt right. `c` and `d` on two directories are enough to
rename between them. Do not emit anything for `refer`.

`u` never adds file read/write permissions. A regular file at the granted
pathname, including one replacing a socket later, must not become readable
or writable merely because of a connection grant. `c` allows creating and
serving UNIX sockets but does not imply `u` for connecting to host sockets.

Final-component globs use the same setup-time resolver as Landlock. Each
existing match gets its own literal or recursive subpath grant, including
separate file/directory treatment for mixed matches. A matched directory's
future children are covered, but new sibling matches are not. Symlinks in
the final component are resolved too. No glob-to-regex translation is used.

Seatbelt remains pathname-based, not inode-based: replacing an allowed
pathname can retain access, while moving an allowed inode elsewhere need
not retain it. This is not equivalent to Landlock across rename/replacement.
Also, Seatbelt requires `u` even for sockets created inside the sandbox;
it does not reproduce Landlock's same-domain socket exemption.

**Create-only is weaker than Landlock:** on macOS 26.7.2, `file-write-create`
allows opening a new regular file for writing and writing through that
descriptor even without `file-write-data`. Thus `c` without `w` is not a
guarantee against writing newly created files. Reopening that file for writing,
or writing/truncating an existing file, still requires `w`. The native mutation
tests explicitly cover this difference; it is not fixed by the current mapping.

### Network

| Policy | SBPL |
|---|---|
| `"net": "allow"` | `network-outbound` on `(remote ip "*:*")`; `network-bind` and `network-inbound` on `(local ip "*:*")` |
| `"net": "deny"` or omitted | no IP network allow; filesystem `u`/`c` rules still control UNIX sockets |
| TCP connect port N | `(allow network-outbound (remote tcp "*:N"))` |
| TCP bind port N, N ≠ 0 | `(allow network-bind (local tcp "*:N"))` plus `(allow network-inbound (local tcp "*:N"))` |
| UDP connect / bind | same with `udp` |
| bind port 0 | `network-bind` and `network-inbound` on `(local tcp "*:*")`, and the `udp` forms when the rule asks for UDP |

Port 0 is broader than Landlock. Seatbelt has no "ephemeral only" port.
Say so in a comment. Do not invent a narrower syntax.
Inbound permission uses the same local endpoint filter: binding alone does not
allow a Seatbelt-confined server to receive traffic.

IP grants also permit `system-socket` for AF_INET and AF_INET6. Network allow
does not emit a blanket `network*`: that would also allow UNIX connections
outside the filesystem allowlist. UNIX socket grants remain independent of
the IP network policy, as they are on Linux.

### IPC and namespaces

macOS has no abstract UNIX sockets. `ipc.abstract_unix` of `"deny"` or omitted
is a no-op, not an error. `"signal": "allow"`, `"deny"`, and omitted all stay
on `(allow signal (target same-sandbox))` from the preamble. Granting
`(allow signal)` would let the jail signal host processes, which the pid
namespace currently prevents.

## Build layout

go-landlock does not build on Darwin. Files that import it (`features.go`,
`enforce.go`, and tests that import it) need `//go:build linux`. Darwin needs
thin stubs for the symbols `main` and `DryRun` still call (`DetectFeatures`,
`String`, `Supports*`, `ValidateFSAccess`, `ValidateNet`, `ValidateIPC`) so
this passes on the Linux host:

```sh
go test ./...
GOOS=darwin CGO_ENABLED=0 go test -exec=true ./...
```

The second command compiles the Darwin test binaries without cgo and uses
`true` instead of running them. `seatbelt_darwin.go` is excluded because of `darwin && cgo`.
The `!cgo` Darwin file is what that command compiles, and it only has to
contain the error return.

`runSandboxed` should call a tiny wrapper:

- `sandbox_linux.go` (`//go:build linux`) calls `policy.Enforce`
- `sandbox_darwin.go` (`//go:build darwin && cgo`) creates directories, compiles SBPL, applies it
- `sandbox_other.go` for the rest, returning a clear error

Keep the Linux enforce path behavior-identical. Do not generate SBPL on Linux.

## Plan

### This branch

1. SBPL compiler in `policy/sbpl.go`, parameters for every resolved path.
2. Tests in `policy/sbpl_test.go` covering scoped execution, socket-only grants, recursive directory/glob grants, `c` on a file, `ignore_missing`, IP/UNIX network separation, and paths containing `)` staying out of the profile text.
3. Darwin cgo apply, and a non-cgo Darwin stub that errors.
4. `runSandboxed` dispatch via build tags, including the DYLD unset and the `unshare` warning.
5. Linux-only build tags plus Darwin stubs so both test commands above pass.
6. One line in the README documentation list pointing here. Already added with this doc; do not rewrite the README.
7. Native subprocess enforcement tests in `policy/seatbelt_darwin_test.go`.
   Run on a real Mac with `CGO_ENABLED=1 go test -count=1 -v ./policy`.
   Profile-application failures are test failures, not skips. Cross-building
   (including the cgo executable) does not run these enforcement checks or
   validate the generated profile with Apple's libsandbox.

### Later

- Mach and sysctl preamble large enough for compilers, `getpwuid`, and TLS (`trustd`), measured by running a real command under the agent profile on a Mac.
- `ps` policy: either keep sysmond denied, or add an explicit opt-in.
- Dry-run on Darwin prints the SBPL profile and the parameter list.
- Run the native tests on supported macOS versions and add them to Mac CI.
- Symlink handling. Seatbelt filters the path string. A symlink planted in a writable directory is the escape to test before calling the backends equivalent.
- `sandbox_compile_string` / `sandbox_apply` if we ever need to compile in the parent and apply in a child. Not needed while Darwin uses in-process `exec`.

## Non-goals

- `/usr/bin/sandbox-exec`, including re-execing through it.
- Apple Containerization, Virtualization.framework, or a Linux guest. Those do not run this profile's Darwin toolchain or its host UNIX sockets.
- A second policy schema, profile inheritance, or Mach rules in the JSON.
- Changing Linux Landlock behavior.

## Native VM validation (2026-11-06)

Tested on the `~/src/osx-vm` guest: macOS 26.7.2, x86_64, Go 1.27.3,
with cgo enabled. This is one OS/architecture, not a general security proof.

Run the native suite with the guest's normal `TMPDIR` (do not canonicalize it
to hide alias failures):

```sh
go test -count=1 -timeout=3m ./...
go test -count=10 -timeout=3m -run '^TestSeatbeltEnforce' ./policy
```

Runtime coverage includes:

- Allowed and denied file reads/writes, execution, UNIX socket connections and
  creation, and setup-time glob snapshots.
- IPv4 TCP/UDP connect and bind: default deny, unrestricted IP, exact ports,
  protocol separation, connect versus bind, and the documented port-zero
  broadening. UDP connect probes send and receive actual datagrams.
- File creation, existing-file writes, truncation, append-open, mkdir, file and
  directory deletion. Create-only writable descriptors are a known difference.
- A symlink planted after compilation in an allowed directory cannot grant
  read, write, create, or delete access to an otherwise denied target directory.

Real-command probes after the fixes:

- `/bin/echo`, a shell, direct Command Line Tools Python, and compiling, linking,
  and executing a C program work with explicit dependency/work-directory grants
  and an explicit SDK path.
- Apple's `/usr/bin/python3` and `/usr/bin/clang` launcher shims require
  `/var/select`, developer-tool paths, and xcrun cache access. The generic
  `/bin`, `/usr`, `/System` grants alone are not a usable developer policy.
- Linking initially reached `ld`, then failed its `UnsafeHeaderWriter.cpp:78`
  buffer-alignment assertion. An identical unsandboxed build succeeded;
  granting reads across `/` did not fix it. Isolating sysctl grants identified
  `hw.pagesize_compat`; the preamble now permits only that key. A native
  regression checks it remains readable while `hw.ncpu` stays denied.

Still unproven here: arm64, other macOS releases, IPv6, sandboxed servers'
inbound traffic, DNS/TLS and Mach-service requirements of real developer tools,
rename/replacement races, and comprehensive inherited-descriptor/IPC behavior.
