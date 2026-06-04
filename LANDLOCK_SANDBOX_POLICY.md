# Sandbox Policy Specification

A JSON-based DSL for defining portable process sandboxing policies. On Linux,
enforced via Landlock. Designed to be adaptable to other OS sandboxing mechanisms
(e.g., macOS sandbox-exec).

## Top-Level Structure

```json
{
  "name": "my-policy",
  "description": "Optional human-readable description",
  "fs": [
    { "path": "/usr", "access": "rx" }
  ],
  "net": [
    { "port": 443, "access": "connect" }
  ],
  "ipc": {
    "abstract_unix": "deny",
    "signal": "deny"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Short identifier for the policy |
| `description` | string | no | Human-readable description |
| `env` | object | no | Environment variable modifications |
| `fs` | array | no | Filesystem access rules |
| `net` | array | no | Network access rules |
| `ipc` | object | no | IPC isolation settings |

One file = one complete policy for one program. No composition or inheritance.

---

## Environment Variables (`env`)

The `env` object modifies environment variables before exec. Useful for removing
sensitive credentials or adjusting PATH-style variables.

```json
{
  "env": {
    "FOO": "literal-value",
    "EXPANDED": "${home}/.config/app",
    "OPENAI_API_KEY": null,
    "EMPTY_VAR": "",
    "PATH": {
      "prepend": "/extra/bin",
      "append": ["/opt/bin", "/more/bin"],
      "remove": "/unwanted/bin",
      "sep": ":"
    }
  }
}
```

### Value Types

| JSON Value | Effect |
|------------|--------|
| `"string"` | Set variable to expanded string value |
| `null` | Unset (remove from environment) |
| `""` | Set to empty string (different from unset) |
| `{...}` | Path-style manipulation (see below) |

### Path Operations

For PATH-style variables (colon-separated lists), use an object:

| Field | Type | Description |
|-------|------|-------------|
| `prepend` | string \| string[] | Add element(s) to the front |
| `append` | string \| string[] | Add element(s) to the end |
| `remove` | string \| string[] | Remove matching element(s) (exact match) |
| `sep` | string | Separator (default `":"`) |

Order of operations: split by separator → remove matches → prepend → append → join.

Example with `PATH=/a:/b:/c`:
```json
{ "prepend": "/x", "append": "/y", "remove": "/b" }
```
Result: `/x:/a:/c:/y`

### Variable Expansion in Values

Values support `${VAR}` and `${VAR:-default}` syntax. Expansion uses the
**original** environment (before any `env` changes are applied):

```json
{
  "env": {
    "FOO": "new",
    "BAR": "${FOO}"
  }
}
```
Here `BAR` gets the original value of `FOO`, not `"new"`.

### Order of Operations

1. Filesystem path expansion (uses original env)
2. Landlock enforcement
3. Environment variable expansion and application
4. Exec child process

---

## Filesystem Rules (`fs`)

The `fs` array contains rule objects. Each rule grants specific access rights to
a path (file or directory hierarchy). **Everything not explicitly listed is
denied** (allowlist model).

### Rule Object

```json
{
  "path": "${dataDir}/myapp",
  "access": "rwcd",
  "refer": true,
  "ioctl_dev": true,
  "ignore_missing": true,
  "create_dir": "0700",
  "comment": "application data directory"
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `path` | string | yes | — | Path with variable expansion and optional glob |
| `access` | string | yes | — | Access flags: combination of `r`, `w`, `x`, `c`, `d` |
| `refer` | bool | no | `false` | Allow cross-directory link/rename |
| `ioctl_dev` | bool | no | `false` | Allow device-driver ioctls |
| `ignore_missing` | bool | no | `false` | Skip rule silently if path doesn't exist |
| `create_dir` | string | no | — | Create directory with this octal mode if missing (e.g., `"0700"`) |
| `comment` | string | no | — | Ignored; for documentation |

### Access Flags

| Flag | Mnemonic | For directories | For files |
|------|----------|-----------------|-----------|
| `r` | read | `READ_DIR` + `READ_FILE` on children | `READ_FILE` |
| `w` | write | `WRITE_FILE` + `TRUNCATE` on children | `WRITE_FILE` + `TRUNCATE` |
| `x` | execute | `EXECUTE` on children | `EXECUTE` |
| `c` | create | `MAKE_REG`, `MAKE_DIR`, `MAKE_SYM`, `MAKE_FIFO`, `MAKE_SOCK` | invalid (error) |
| `d` | delete | `REMOVE_FILE`, `REMOVE_DIR` | invalid (error) |
| `u` | unix connect | `RESOLVE_UNIX` on children (V9+) | `RESOLVE_UNIX` |

Common combinations:

| Combo | Use case |
|-------|----------|
| `rx` | Read-only + executable (`/usr`, `/bin`) |
| `r` | Read-only data (config files/dirs) |
| `rw` | Read + write existing files |
| `rwcd` | Full access (workspace, `/tmp`) |
| `rwc` | Read/write/create, no delete |
| `u` | Connect to existing UNIX socket |
| `uc` | Create and connect to UNIX sockets |

### Additional Flags

**`refer`** — allows `link()` and `rename()` to move files between different
directories. Only needed for cross-directory moves. Rename within the same
directory only needs `c` + `d` on that directory. Both source and destination
directories must have `refer: true`.

**`ioctl_dev`** — allows device-driver-specific `ioctl()` commands on character
and block devices. Generic ioctls (`FIONBIO`, `FIOCLEX`, etc.) are always
permitted regardless of this flag.

### Validation Rules

- `c` or `d` in `access` on a path resolving to a file → **error**
- `ioctl_dev` on a non-device path → **warning** (no effect)
- `create_dir` and `ignore_missing` on same rule → **error** (mutually exclusive)
- `create_dir` on a path resolving to a file → **error**
- Empty path after variable expansion → treated as missing (respects `ignore_missing`, otherwise error)

---

## Variable Expansion

Paths support `${...}` variable references with bash-style defaults.

### Syntax

| Form | Behavior |
|------|----------|
| `${VAR}` | Expand variable; error if unset/empty (unless `ignore_missing`) |
| `${VAR:-fallback}` | Expand variable; use `fallback` if unset/empty |
| `${VAR:-}` | Expand variable; use empty string if unset/empty |

Fallbacks can contain nested `${...}` references:
`${CARGO_HOME:-${dataDir}/cargo}`

### Resolution Order

1. Built-in variables (camelCase, always defined)
2. Environment variables (typically UPPER_SNAKE_CASE)

Built-ins take precedence over env vars with the same name.

### Built-in Variables

| Variable | Expands to |
|----------|-----------|
| `home` | `$HOME` |
| `uid` | Numeric user ID (from `getuid`) |
| `user` | Username (from `/etc/passwd`) |
| `pwd` | Current working directory (from `getcwd`) |
| `configDir` | `${XDG_CONFIG_HOME:-$HOME/.config}` |
| `dataDir` | `${XDG_DATA_HOME:-$HOME/.local/share}` |
| `cacheDir` | `${XDG_CACHE_HOME:-$HOME/.cache}` |
| `stateDir` | `${XDG_STATE_HOME:-$HOME/.local/state}` |
| `runtimeDir` | `${XDG_RUNTIME_DIR:-/run/user/$UID}` |
| `tmpDir` | `${TMPDIR:-/tmp}` |

### Glob Metacharacters in Substituted Values

After variable expansion, any glob metacharacters (`*`, `?`) in the substituted
value are treated as **literals**. Only metacharacters written directly in the
policy JSON are interpreted as globs. This prevents environment variable values
from accidentally triggering glob expansion.

---

## Glob Expansion

Paths may contain glob patterns in the **final path component only**:

```json
{ "path": "/dev/dri/card*", "access": "rw", "ioctl_dev": true }
{ "path": "/usr/lib/libfoo.so.?", "access": "r" }
```

### Rules

- `*` matches zero or more characters (excluding `/`)
- `?` matches exactly one character (excluding `/`)
- `**` is **not supported** (no recursive globbing)
- Globs in intermediate path components are **not supported** (no `/dev/*/card0`)
- Globs are expanded **at enforcement time** — matches are a snapshot of what exists when the sandbox starts
- If a glob matches zero paths: respects `ignore_missing` (skip) or errors
- Paths appearing after sandbox enforcement (e.g., hot-plugged devices) are **not covered**

---

## Symlink Handling

Symlinks are **always followed** during rule setup. The rule attaches to the
resolved target's inode. Since Landlock is inode-based, accesses through any
path (symlink or direct) reaching the same inode are covered by a single rule.

- Dead symlinks (target doesn't exist) → treated as missing path (respects `ignore_missing`)
- Symlinks that resolve outside the sandbox → the rule attaches to the target; if the target is not otherwise accessible, this is fine (it just creates a rule there)
- Runtime symlink traversal: the kernel resolves to the final path and checks Landlock against that resolved path, not intermediate symlink hops

---

## Default Policy Semantics

- **Deny-all by default.** Only paths with explicit rules are accessible.
- The tool handles the maximum set of access rights supported by the running kernel.
- Unhandled access rights (those the kernel doesn't support yet) remain unrestricted.
- Mount operations (`mount`, `umount`, `pivot_root`, `remount`) are **always denied** for any sandboxed process with filesystem rules.

---

## Network Rules (`net`)

The `net` array controls TCP bind and connect operations. **All TCP operations
are denied by default** unless explicitly permitted.

### Rule Object

```json
{ "port": 443, "access": "connect", "comment": "HTTPS" }
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `port` | integer | yes | — | TCP port (0–65535) |
| `access` | string | yes | — | `"connect"`, `"bind"`, or `"connect+bind"` |
| `comment` | string | no | — | Ignored; for documentation |

### Access Values

| Value | Landlock right | Description |
|-------|---------------|-------------|
| `"connect"` | `ACCESS_NET_CONNECT_TCP` | Allow `connect()` to this remote port |
| `"bind"` | `ACCESS_NET_BIND_TCP` | Allow `bind()` to this local port |
| `"connect+bind"` | Both | Allow both operations on this port |

### Notes

- **TCP only** — UDP, SCTP, and other protocols are not restricted by Landlock.
- **Port-based only** — destination/source IP is not checked. A rule allowing
  port 443 permits connecting to any host on port 443.
- Port 0 with `"bind"` allows binding to a kernel-assigned ephemeral port.
- `connect(AF_UNSPEC)` (disconnect) is always allowed regardless of rules.

### Example

```json
{
  "net": [
    { "port": 443, "access": "connect", "comment": "HTTPS" },
    { "port": 80, "access": "connect", "comment": "HTTP" },
    { "port": 53, "access": "connect", "comment": "DNS" },
    { "port": 8080, "access": "bind", "comment": "local dev server" },
    { "port": 0, "access": "bind", "comment": "ephemeral ports" }
  ]
}
```

---

## IPC Isolation (`ipc`)

The `ipc` object controls domain-wide IPC restrictions. These are blanket
deny rules — no per-object granularity. They block communication with processes
**outside** the sandbox domain (parent processes, unsandboxed processes).
Communication within the same domain or to nested child domains remains allowed.

```json
{
  "ipc": {
    "abstract_unix": "deny",
    "signal": "deny"
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `abstract_unix` | string | (omitted) | Control abstract UNIX socket connections outside domain |
| `signal` | string | (omitted) | Control sending signals outside domain |

### Values

| Value | Behavior |
|-------|----------|
| omitted or `""` | Best-effort deny — block if kernel supports it (ABI V6+), silently allow if not |
| `"deny"` | Hard deny — error if the kernel cannot enforce this restriction |
| `"allow"` | Explicitly unrestricted — do not set the scope flag |

**Default behavior:** When a field is omitted, the tool blocks cross-domain IPC
on a best-effort basis. This provides secure defaults on modern kernels while
remaining portable to older kernels or other OSes. If you need to **guarantee**
enforcement, use `"deny"` explicitly — the tool will fail with an error rather
than run without protection.

### `abstract_unix`

Denies connecting to abstract UNIX sockets (those with a NUL first byte in
`sun_path`) created by processes outside the sandbox. Returns `EPERM`.

This does NOT affect **pathname** UNIX sockets (filesystem-bound). Use the `u`
flag in `fs` rules to control those.

### `signal`

Denies sending signals to processes outside the sandbox domain. Signals to
processes within the same domain or nested domains remain allowed. Signals
between threads of the same process are always permitted.

### Relationship with `fs` Rules

For full UNIX socket control, combine both mechanisms:

- `ipc.abstract_unix: true` — blocks abstract sockets (no path, can't be controlled per-path)
- `u` flag in `fs` rules — allows connecting to specific pathname sockets

```json
{
  "ipc": { "abstract_unix": true },
  "fs": [
    { "path": "/run/dbus/system_bus_socket", "access": "u", "comment": "allow D-Bus" }
  ]
}
```

---

## Full Example

```json
{
  "name": "cargo-build",
  "description": "Sandbox for running cargo build in a Rust project",
  "fs": [
    { "path": "/usr", "access": "rx", "comment": "system binaries and libraries" },
    { "path": "/lib", "access": "rx", "comment": "system libraries (non-merged-usr)" },
    { "path": "/etc", "access": "r", "comment": "system configuration" },
    { "path": "/dev/null", "access": "rw" },
    { "path": "/dev/urandom", "access": "r" },
    { "path": "/proc/self", "access": "r", "comment": "process introspection" },

    { "path": "${home}/.rustup", "access": "rx", "comment": "Rust toolchains" },
    { "path": "${CARGO_HOME:-${dataDir}/cargo}", "access": "rwcd", "comment": "cargo cache and registry" },
    { "path": "${cacheDir}/cargo", "access": "rwcd", "create_dir": "0700" },

    { "path": "${PWD}", "access": "rwcd", "refer": true, "comment": "project working directory" },
    { "path": "${tmpDir}", "access": "rwcd", "comment": "temporary files" },

    { "path": "/run/dbus/system_bus_socket", "access": "u", "comment": "D-Bus access" }
  ],
  "net": [
    { "port": 443, "access": "connect", "comment": "HTTPS (crates.io)" },
    { "port": 53, "access": "connect", "comment": "DNS resolution" }
  ],
  "ipc": {
    "abstract_unix": "deny",
    "signal": "deny"
  }
}
```

---

## Landlock Mapping Reference

How policy fields map to Landlock primitives when enforced on Linux:

### Directory rules

| Flags | Landlock rights |
|-------|----------------|
| `r` | `READ_DIR`, `READ_FILE` |
| `w` | `WRITE_FILE`, `TRUNCATE` |
| `x` | `EXECUTE` |
| `c` | `MAKE_REG`, `MAKE_DIR`, `MAKE_SYM`, `MAKE_FIFO`, `MAKE_SOCK` |
| `d` | `REMOVE_FILE`, `REMOVE_DIR` |
| `u` | `RESOLVE_UNIX` (V9+) |
| `refer: true` | `REFER` |
| `ioctl_dev: true` | `IOCTL_DEV` |

### File rules

| Flags | Landlock rights |
|-------|----------------|
| `r` | `READ_FILE` |
| `w` | `WRITE_FILE`, `TRUNCATE` |
| `x` | `EXECUTE` |
| `u` | `RESOLVE_UNIX` (V9+) |
| `ioctl_dev: true` | `IOCTL_DEV` |

### Network rules

| Access | Landlock right |
|--------|----------------|
| `"connect"` | `ACCESS_NET_CONNECT_TCP` |
| `"bind"` | `ACCESS_NET_BIND_TCP` |

### IPC rules

| Field | Landlock scope flag |
|-------|---------------------|
| `abstract_unix: true` | `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` |
| `signal: true` | `LANDLOCK_SCOPE_SIGNAL` |

### Handled access rights (always set in ruleset)

The enforcement tool always declares all supported access rights as handled:
`EXECUTE`, `WRITE_FILE`, `READ_FILE`, `READ_DIR`, `REMOVE_DIR`, `REMOVE_FILE`,
`MAKE_CHAR`, `MAKE_DIR`, `MAKE_REG`, `MAKE_SOCK`, `MAKE_FIFO`, `MAKE_BLOCK`,
`MAKE_SYM`, `REFER`, `TRUNCATE`, `IOCTL_DEV`, `RESOLVE_UNIX` (V9+).

Note: `MAKE_CHAR` and `MAKE_BLOCK` are always handled (denied by default) but
not exposed through any access flag. Creating device nodes is a privileged
operation that this policy format intentionally does not permit.
