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
| `unshare` | object | no | Linux namespace isolation |
| `env` | object | no | Environment variable modifications |
| `fs` | array | no | Filesystem access rules |
| `net` | array | no | Network access rules |
| `ipc` | object | no | IPC isolation settings |

One file = one complete policy for one program. No composition or inheritance.

For the template language (`.json.j2` files), see
[POLICY_TEMPLATES.md](./POLICY_TEMPLATES.md).

---

## Namespace Isolation (`unshare`)

The `unshare` object controls Linux namespace isolation. When configured, landcage
re-executes itself inside new namespaces before applying Landlock and exec'ing the
target command. This replaces the need for an external `unshare` wrapper.

```json
{
  "unshare": {
    "user": true,
    "pid": true,
    "cgroup": true,
    "mount_proc": true
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `user` | bool | `false` | Create new user namespace, map current UID/GID |
| `pid` | bool | `false` | Create new PID namespace (child becomes PID 1) |
| `cgroup` | bool | `false` | Create new cgroup namespace |
| `mount_proc` | bool | `false` | Create mount namespace + remount `/proc` (requires `pid`) |

### Behavior

- **`user`**: Creates a `CLONE_NEWUSER` namespace and maps the current UID/GID to
  the same values inside. No privilege escalation — the process remains the same
  user. Enables unprivileged use of other namespace types.

- **`pid`**: Creates a `CLONE_NEWPID` namespace. The sandboxed process tree is
  isolated — it cannot see or signal processes outside its namespace. The first
  process in the namespace becomes PID 1.

- **`cgroup`**: Creates a `CLONE_NEWCGROUP` namespace. The process gets a
  virtualized view of `/proc/self/cgroup`.

- **`mount_proc`**: Implies a mount namespace (`CLONE_NEWNS`). Remounts `/proc`
  so it reflects only the new PID namespace. Requires `pid: true`.

### Implementation

landcage uses a re-exec pattern: it spawns itself as a child process with
`clone(2)` flags, then in the child performs any mount setup before continuing
with Landlock enforcement and exec. The parent forwards signals and propagates
the child's exit code. This works with pure Go (no CGO).

### Example

Equivalent of `unshare -UpC --fork --mount-proc --map-current-user`:

```json
{
  "unshare": {
    "user": true,
    "pid": true,
    "cgroup": true,
    "mount_proc": true
  }
}
```

---

## Environment Variables (`env`)

The `env` object modifies environment variables before exec. Useful for removing
sensitive credentials or adjusting PATH-style variables.

```json
{
  "env": {
    "FOO": "literal-value",
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
| `"string"` | Set variable to this string value |
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

### Template Expansion in Values

When using `.json.j2` templates, env values can contain template expressions.
See [POLICY_TEMPLATES.md](./POLICY_TEMPLATES.md) for details. In the expanded
`.json` policy, all values are plain strings:

```json
{
  "env": {
    "FOO": "new",
    "BAR": "/home/user/default-value"
  }
}
```

### Order of Operations

1. JSON parsing
2. Glob resolution + directory creation
3. Landlock enforcement
4. Environment variable application
5. Exec child process

---

## Filesystem Rules (`fs`)

The `fs` array contains rule objects. Each rule grants specific access rights to
a path (file or directory hierarchy). **Everything not explicitly listed is
denied** (allowlist model).

### Rule Object

```json
{
  "path": "/home/user/.local/share/myapp",
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
| `path` | string | yes | — | Path (supports final-component globs) |
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
- Empty path: treated as missing (respects `ignore_missing`, otherwise error)

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
- **Graceful downgrade:** ABI-gated FS flags (`u`/resolve_unix, `refer`, `ioctl_dev`,
  truncate via `w`) are silently dropped on kernels that don't support them. A warning
  is printed to stderr, but enforcement proceeds with the remaining flags. This makes
  policies portable across kernel versions without requiring per-kernel policy variants.
- Per-port network rules and IPC `"deny"` are **not** downgraded — they error if
  the kernel cannot enforce them, because silently running without network or
  IPC isolation would violate the policy's security intent. UDP rules require
  ABI 10 / Linux 7.2. On ABI 4–9, TCP-only net restriction proceeds and UDP
  stays unrestricted (warning). `"net": "deny"` is best effort as described
  below.
- Mount operations (`mount`, `umount`, `pivot_root`, `remount`) are **always denied** for any sandboxed process with filesystem rules.

---

## Network Rules (`net`)

The `net` field controls TCP and UDP bind/connect operations. **All handled
network operations are denied by default** unless explicitly permitted.

TCP bind/connect are handled on ABI 4+ (Linux 6.7+). UDP bind and connect/send
are handled on ABI 10+ (Linux 7.2+), so unspecified UDP is denied the same way
as TCP.

| Policy option | Minimum Landlock ABI | Minimum Linux | Behavior |
|---------------|----------------------|---------------|----------|
| `"net": "allow"` | 1 | 5.13 | No network restriction requested |
| `"net": "deny"` | 4 / 10 | 6.7 / 7.2 | Denies TCP from ABI 4; TCP and UDP from ABI 10 |
| `"proto": "tcp"` or omitted | 4 | 6.7 | TCP bind/connect |
| `"proto": "udp"` | 10 | 7.2 | UDP bind/connect/send |
| `"proto": "any"` | 10 | 7.2 | Both TCP and UDP rights |

Explicit UDP and `"any"` rules fail closed on older kernels rather than being
silently dropped. On ABI 4–9, a TCP-only policy still runs, but UDP remains
unrestricted because Landlock cannot mediate it. Before ABI 4 / Linux 6.7,
Landlock cannot mediate network access at all.

### Allowing All Network

Set `"net": "allow"` to leave TCP and UDP completely unrestricted (network
access rights are not declared as handled, so Landlock does not restrict them):

```json
{ "net": "allow" }
```

### Denying All Network

Set `"net": "deny"` to block all network access that the running Landlock ABI
can mediate. This is equivalent to omitting the `net` field or setting it to
`null`, but is more readable in templates:

```json
{ "net": "deny" }
```

On ABI 10+ (Linux 7.2+) this denies TCP and UDP. On ABI 4–9
(Linux 6.7–7.1) only TCP is denied because UDP cannot be restricted. Before
ABI 4, neither protocol is restricted. Enforcement prints a warning whenever
the requested deny cannot cover both protocols.

### Rule Object

```json
{ "port": 443, "access": "connect", "proto": "tcp", "comment": "HTTPS" }
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `port` | integer | yes | — | Port (0–65535) |
| `access` | string | yes | — | `"connect"`, `"bind"`, or `"connect+bind"` |
| `proto` | string | no | `"tcp"` | `"tcp"`, `"udp"`, or `"any"` |
| `comment` | string | no | — | Ignored; for documentation |

### Access Values

| Value | TCP (default / `"tcp"`) | UDP (`"udp"`) |
|-------|-------------------------|---------------|
| `"connect"` | `ACCESS_NET_CONNECT_TCP` | `ACCESS_NET_CONNECT_SEND_UDP` |
| `"bind"` | `ACCESS_NET_BIND_TCP` | `ACCESS_NET_BIND_UDP` |
| `"connect+bind"` | Both TCP rights | Both UDP rights |

`"proto": "any"` grants the TCP and UDP rights for the same access/port and
therefore requires ABI 10+ (Linux 7.2+).

### Notes

- **Port-based only** — destination/source IP is not checked. A rule allowing
  port 443 permits connecting to any host on port 443.
- Port 0 with `"bind"` allows binding to a kernel-assigned ephemeral port.
- `connect(AF_UNSPEC)` (TCP disconnect) is always allowed regardless of rules.
- **UDP autobind:** if both UDP bind and connect/send are handled, sending from
  an unbound UDP socket assigns an ephemeral local port. That requires
  `"bind"` on port 0 (or a prior `bind()` to an allowed port). A `"connect"`
  rule alone is not enough for typical DNS clients.
- Explicit `"proto": "udp"` / `"any"` rules **error** on kernels older than
  ABI 10 / Linux 7.2 (not silently dropped).
- SCTP and other non-TCP/UDP protocols are not restricted by Landlock.

### Example

```json
{
  "net": [
    { "port": 443, "access": "connect", "comment": "HTTPS over TCP (ABI 4+, Linux 6.7+)" },
    { "port": 80, "access": "connect", "comment": "HTTP over TCP (ABI 4+, Linux 6.7+)" },
    { "port": 53, "access": "connect", "proto": "any", "comment": "DNS over TCP+UDP (ABI 10+, Linux 7.2+)" },
    { "port": 0, "access": "bind", "proto": "udp", "comment": "UDP autobind (ABI 10+, Linux 7.2+)" },
    { "port": 8080, "access": "bind", "comment": "local TCP server (ABI 4+, Linux 6.7+)" },
    { "port": 0, "access": "bind", "comment": "TCP ephemeral ports (ABI 4+, Linux 6.7+)" }
  ]
}
```

Because this example contains explicit UDP rules, the complete policy requires
ABI 10+ (Linux 7.2+). For ABI 4–9, omit the UDP autobind rule and make the port
53 rule TCP-only; UDP is unrestricted on those kernels.

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

- `ipc.abstract_unix: "deny"` — blocks abstract sockets (no path, can't be controlled per-path)
- `u` flag in `fs` rules — allows connecting to specific pathname sockets

```json
{
  "ipc": { "abstract_unix": "deny" },
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

    { "path": "/home/user/.rustup", "access": "rx", "comment": "Rust toolchains" },
    { "path": "/home/user/.local/share/cargo", "access": "rwcd", "comment": "cargo cache and registry" },
    { "path": "/home/user/.cache/cargo", "access": "rwcd", "create_dir": "0700" },

    { "path": "/home/user/projects/myapp", "access": "rwcd", "refer": true, "comment": "project working directory" },
    { "path": "/tmp", "access": "rwcd", "comment": "temporary files" },

    { "path": "/run/dbus/system_bus_socket", "access": "u", "comment": "D-Bus access" }
  ],
  "net": [
    { "port": 443, "access": "connect", "comment": "HTTPS over TCP (ABI 4+, Linux 6.7+)" },
    { "port": 53, "access": "connect", "proto": "any", "comment": "DNS over TCP+UDP (ABI 10+, Linux 7.2+)" },
    { "port": 0, "access": "bind", "proto": "udp", "comment": "UDP autobind for DNS (ABI 10+, Linux 7.2+)" }
  ],
  "ipc": {
    "abstract_unix": "deny",
    "signal": "deny"
  }
}
```

The explicit UDP rules make this full example require ABI 10+ (Linux 7.2+).

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

| Access | `proto` | Landlock right |
|--------|---------|----------------|
| `"connect"` | `"tcp"` (default) | `ACCESS_NET_CONNECT_TCP` |
| `"bind"` | `"tcp"` (default) | `ACCESS_NET_BIND_TCP` |
| `"connect"` | `"udp"` | `ACCESS_NET_CONNECT_SEND_UDP` (V10+) |
| `"bind"` | `"udp"` | `ACCESS_NET_BIND_UDP` (V10+) |
| `"connect"` | `"any"` | `ACCESS_NET_CONNECT_TCP` + `ACCESS_NET_CONNECT_SEND_UDP` (V10+) |
| `"bind"` | `"any"` | `ACCESS_NET_BIND_TCP` + `ACCESS_NET_BIND_UDP` (V10+) |

UDP `BIND_UDP` / `CONNECT_SEND_UDP` are handled whenever net is restricted on
ABI 10+ (Linux 7.2+), so unspecified UDP is denied by default.

### IPC rules

| Field | Landlock scope flag |
|-------|---------------------|
| `abstract_unix: "deny"` | `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` |
| `signal: "deny"` | `LANDLOCK_SCOPE_SIGNAL` |

### Handled access rights (always set in ruleset)

The enforcement tool always declares all supported access rights as handled:
`EXECUTE`, `WRITE_FILE`, `READ_FILE`, `READ_DIR`, `REMOVE_DIR`, `REMOVE_FILE`,
`MAKE_CHAR`, `MAKE_DIR`, `MAKE_REG`, `MAKE_SOCK`, `MAKE_FIFO`, `MAKE_BLOCK`,
`MAKE_SYM`, `REFER`, `TRUNCATE`, `IOCTL_DEV`, `RESOLVE_UNIX` (V9+).

When network restriction is requested, handled net rights are `BIND_TCP` and
`CONNECT_TCP` on ABI 4+ (Linux 6.7+), plus `BIND_UDP` and
`CONNECT_SEND_UDP` on ABI 10+ (Linux 7.2+).

Note: `MAKE_CHAR` and `MAKE_BLOCK` are always handled (denied by default) but
not exposed through any access flag. Creating device nodes is a privileged
operation that this policy format intentionally does not permit.
