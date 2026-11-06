# Windows backend (experimental)

The main `landcage.exe` CLI has a native **Process Security Environment (PSEC)**
backend. It does not require MXC, change filesystem/device ACLs, elevate, or fall
back to legacy AppContainer or unsandboxed execution.

**This is a limited Windows preview, not general Git Bash/toolchain support or a
security certification.** Unmodified native Git operations and native executable
hooks have been exercised inside confinement. MSYS2 `sh.exe` still fails during
named-object initialization; shell hooks/helpers that depend on it do not work.
They are not run outside the sandbox as a workaround.

## Requirements

- A 64-bit Landcage executable and a Windows build providing the native PSEC 1.0
  APIs in System32's `processmodel.dll`. Export availability alone is not
  enforcement validation.
- The measured host is Windows 11 Pro x64 **26300.9711**.
  Other builds/architectures are not claimed
  runtime-validated. The launcher checks support and refuses missing APIs.
- Run without elevation. SYSTEM, elevated, and high-integrity callers are refused.
- Use a normal signed-in desktop session for PowerShell/Git. Windows OpenSSH's
  session 0 produced `STATUS_DLL_INIT_FAILED` for these runtimes, despite working
  Go probes. The launcher reports this failure; it does not relax confinement.

Windows 10 is not supported.

## Build and use

Build on Windows with `go build -o landcage.exe .`, or cross-compile:

```sh
GOOS=windows GOARCH=amd64 go build -o landcage.exe .
```

Create the workspace and scratch directories **before** launching. For example,
with Windows installed in `C:\Windows` and Git in `C:\Tools\Git`:

```json
{
  "name": "windows-offline-workspace",
  "fs": [
    {"path": "C:/Windows", "access": "rx"},
    {"path": "C:/Tools/Git", "access": "rx"},
    {
      "path": "C:/work/project", "access": "rwxcdu",
      "refer": true, "ioctl_dev": true
    }
  ],
  "net": "deny",
  "ipc": {"abstract_unix": "allow", "signal": "allow"},
  "env": {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "NUL",
    "GIT_CONFIG_SYSTEM": "NUL",
    "GIT_TERMINAL_PROMPT": "0",
    "HOME": "C:/work/project/.home",
    "USERPROFILE": "C:/work/project/.home",
    "LOCALAPPDATA": "C:/work/project/.home",
    "TEMP": "C:/work/project/.tmp",
    "TMP": "C:/work/project/.tmp"
  }
}
```

```powershell
landcage.exe --dry-run -p windows.json
landcage.exe -p windows.json -- C:\Tools\Git\cmd\git.exe -C C:\work\project status
```

Grant the actual executable/runtime locations explicitly. There are no automatic
profile, workspace, Windows-directory, or tool-directory grants. The example
intentionally avoids reading the host user's Git configuration and gives scratch
files a writable location. Do not grant an entire user profile just to fix a
missing dependency.

## Policy subset

Unsupported requests fail before payload execution, rather than being ignored.

| Policy | Current support |
|---|---|
| Filesystem `rx` | Read/execute, including directory traversal |
| Directory `rwxcdu`, `refer: true`, `ioctl_dev: true` | Full read/write/execute and mutations |
| Narrower permissions or writable file-only grants | Rejected; PSEC's coarse grants cannot represent them faithfully |
| Local drive-absolute paths, final-component globs, `ignore_missing` | Supported with checked local-volume traversal |
| Symlinks/junctions/mount points or case-sensitive grant/image ancestors | Rejected before traversal; not silently resolved |
| UNC, device paths, streams, SUBST/network drives, reserved DOS names | Rejected |
| `create_dir` | Rejected; prepare directories explicitly |
| `net: "deny"`, omitted/empty network rules | Default-deny networking |
| Unrestricted or per-port network policy | Rejected in this initial implementation |
| Linux namespaces / `--net none` / `--net isolated` | Rejected; no host-network fallback |
| Linux scoped IPC | Not implemented; both IPC fields must explicitly be `"allow"` |
| Environment | Explicit payload block, case-insensitive Windows overrides/unsets; inherited public policy variable scrubbed |

`--net host` means no *Linux network namespace* is requested; it does **not**
override the policy's network denial. Standalone `--ro`/`--rw` shortcuts do not
supply the explicit IPC opt-out: use a Windows policy file, optionally augmented
with those flags. An IPC opt-out does not disable PSEC token/process protections.

Win32k is enabled for runtime initialization. Separate job UI restrictions remain
configured for clipboard, input injection, cross-job handles/atoms, desktop/system
settings, and IME. These settings are not a claim of complete GUI/IPC auditing.
Environment path operations retain their explicit separator; use `"sep": ";"`
for Windows PATH lists.

## Launch and cleanup

The backend encodes the versioned Microsoft PSEC schema, creates the environment,
and attaches it to `CreateProcessW`. Preparation checks and pins local paths
without following reparse points; temporary anchors are released before payload
execution so nonempty-directory mutations are not blocked by retained handles.
Only duplicated stdin/stdout/stderr handles are inherited. The job and environment
handles are never passed to the payload.
Stdio remains an intentional inherited capability: do not supply sensitive file
or socket handles as stdin/stdout/stderr. Preparation requires readable ancestors
and support for querying directory case sensitivity.

The child starts suspended. The launcher assigns and verifies a non-breakaway,
kill-on-close job, verifies its token, then resumes it. Native PSEC currently
produces a low-integrity AppContainer-shaped token; that flag is **not** evidence
of a fallback. The native API and security-environment attribute are mandatory.
Normal completion/error cleanup terminates descendants and checks job accounting
before releasing the environment.

**Known lifecycle gap:** on the measured build, PSEC accepted a `JOB_LIST`
creation attribute but did not assign that job. The implementation therefore uses
explicit assignment before resume, as the reference backend does. Abrupt launcher
death between process creation and assignment can leave a suspended process. It
cannot execute payload code in that window, but this is not atomic crash cleanup.

## Validation and remaining limits

On 2026-11-06, the native Go backend completed **279 checks, zero failures**, as a
non-elevated standard user in a desktop session on Windows **26300.9711**, using
unmodified Git **2.56.0.windows.4** and a native executable hook. These integration
measurements are separate from the repository's unit tests.

- Git init/add/commit/status/show/worktree operations and native hook inheritance.
- Protected file contents, nonempty-directory mutations, NUL, denied-target
  junction/hardlink probes, TCP/UDP denial with successful unsandboxed controls,
  and parent-process tampering denial.
- Environment/cwd, unsupported-policy rejection, preserved exit status **37**,
  and descendant cleanup.
- Windows CLI/policy/PSEC tests passed, including real sharing-lock and
  case-sensitive-directory tests. The remote-symlink creation test was skipped
  because the standard account lacked symlink privilege; junction and foreign
  DOS-device mapping tests ran.
- Windows 10 **19045.6456** refused execution because the PSEC module was absent;
  the marker payload did not run.
- Linux tests/vet, Windows amd64 vet, and Windows arm64/Darwin arm64 builds passed.
  Cross-compilation is not runtime validation of those architectures.

MSYS shell hooks remain unsupported. Their measured failure is
`NtCreateDirectoryObject(\\BaseNamedObjects\\msys-...):
0xC0000022`. Granting shared host MSYS objects would weaken isolation and is not a
supported fix. Package managers, arbitrary broker-mediated IPC/network access,
all GUI surfaces, and a complete adversarial filesystem matrix are not certified
by these tests.
