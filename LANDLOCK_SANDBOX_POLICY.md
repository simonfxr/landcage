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

---

## Jinja Policy Templates (`.j2`)

Policy files whose path ends in `.j2` are rendered as Jinja-style templates
before the resulting JSON is parsed and validated. This is intended for
instantiating a policy from explicit CLI-provided parameters while keeping
environment access separate.

Example `agent.json.j2`:

```jinja
{
  "name": "agent-{{ var.profile }}",
  "fs": [
    { "path": "{{ configDir }}/landcage/{{ var.profile }}", "access": "r" }
    {% if var.include_tmp %},
    { "path": "{{ tmpDir }}", "access": "rwcd" }
    {% endif %}
  ],
  "net": "allow"
}
```

Instantiate it with:

```sh
landcage -p agent.json.j2 \
  --var profile=default \
  --optional-var include_tmp=1 \
  -- agent
```

### Template Context

| Name | Description |
|------|-------------|
| `var.NAME` / `var["NAME"]` | CLI template variable from `--var` or `--optional-var` |
| `env.NAME` / `env["NAME"]` | Original process environment |
| `home`, `uid`, `user`, `pwd`, `configDir`, `dataDir`, `cacheDir`, `stateDir`, `runtimeDir`, `tmpDir` | Same built-ins as top-level template context |

### Template Variable Rules

- `--var KEY=VALUE` provides a **required** template variable.
- Required variables must be mentioned in the template as `var.KEY` or
  `var["KEY"]`; otherwise rendering fails.
- `--optional-var KEY=VALUE` provides an optional template variable.
- Optional variables may be unused.
- Any `var.KEY` mentioned in the template must be provided by either `--var` or
  `--optional-var`; otherwise rendering fails.
- “Mentioned” is based on the parsed template, not the execution path. A
  `var.KEY` inside an untaken `{% if %}` branch still counts as mentioned.
- `var` is intentionally separate from `env`; use `env.NAME` to read an
  environment variable in a template.

### Supported Template Syntax

The template engine is intentionally small and map-based:

- `{{ expr }}` interpolation
- `{% if %}`, `{% elif %}`, `{% else %}`, `{% endif %}`
- `{% for item in list %}`, optional `{% else %}`, `{% endfor %}`
- `{% set name = expr %}` local variable assignment
- `{% raw %}` / `{% endraw %}`
- `{# comment #}` (ignored)
- function calls: `{{ fn(arg1, arg2) }}`
- dotted and indexed access (`var.name`, `env["HOME"]`, `list[0]`)
- operators such as `and`, `or`, `not`, `==`, `!=`, `<`, `>`, `<=`, `>=`, `in`,
  `+`, `-`, `*`, `/`
- tests: `is defined`, `is undefined`, `is none`, `is true`, `is false`

Unsupported constructs fail rendering rather than being ignored.

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

Since the entire policy file is rendered through the Jinja-style template engine
before JSON parsing, env values can use template expressions:

```json
{
  "env": {
    "FOO": "new",
    "BAR": "{{ env.FOO or \"default\" }}"
  }
}
```

Note: template expansion happens once, before JSON parsing. `BAR` gets the
original value of `FOO` from the process environment, not the `"new"` value
defined in the same policy.

### Order of Operations

1. Template rendering (entire policy file)
2. JSON parsing
3. Glob resolution + directory creation
4. Landlock enforcement
5. Environment variable application
6. Exec child process

---

## Filesystem Rules (`fs`)

The `fs` array contains rule objects. Each rule grants specific access rights to
a path (file or directory hierarchy). **Everything not explicitly listed is
denied** (allowlist model).

### Rule Object

```json
{
  "path": "{{ dataDir }}/myapp",
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
| `path` | string | yes | — | Path (supports template expressions and final-component globs) |
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
- Empty path after template expansion: treated as missing (respects `ignore_missing`, otherwise error)

---

## Template Engine

Policy files with the `.json.j2` extension are rendered through a Jinja-style
template engine before JSON parsing. Plain `.json` policy files are parsed
directly without any template processing.

### Syntax

- `{{ expr }}` — interpolation (errors if the expression evaluates to undefined/nil)
- `{% if %}`, `{% elif %}`, `{% else %}`, `{% endif %}`
- `{% for item in list %}`, optional `{% else %}`, `{% endfor %}`
- `{% set name = expr %}` — local variable assignment
- `{% raw %}` / `{% endraw %}` — output verbatim without processing
- `{# comment #}` — ignored (not included in output)
- Function calls: `{{ fn(arg1, arg2) }}`
- Dotted and indexed access: `env.HOME`, `env["HOME"]`, `list[0]`
- Operators: `and`, `or`, `not`, `==`, `!=`, `<`, `>`, `<=`, `>=`, `in`, `+`, `-`, `*`, `/`
- Tests: `is defined`, `is undefined`, `is none`, `is true`, `is false`

### Built-in Context

| Name | Description |
|------|-------------|
| `home` | `$HOME` |
| `uid` | Numeric user ID |
| `user` | Username |
| `pwd` | Current working directory |
| `configDir` | `$XDG_CONFIG_HOME` or `~/.config` |
| `dataDir` | `$XDG_DATA_HOME` or `~/.local/share` |
| `cacheDir` | `$XDG_CACHE_HOME` or `~/.cache` |
| `stateDir` | `$XDG_STATE_HOME` or `~/.local/state` |
| `runtimeDir` | `$XDG_RUNTIME_DIR` or `/run/user/$UID` |
| `tmpDir` | `$TMPDIR` or `/tmp` |
| `env.NAME` / `env["NAME"]` | Process environment variable |
| `var.NAME` / `var["NAME"]` | CLI template variable (`.j2` files only) |

### Built-in Functions

| Function | Description |
|----------|-------------|
| `exists(path)` | Returns true if the path exists |
| `is_dir(path)` | Returns true if the path exists and is a directory |
| `is_file(path)` | Returns true if the path exists and is a regular file |
| `find_upward(start, marker...)` | Walks up from `start` looking for a directory containing any of the marker paths; returns the directory path or nil if not found |

Example:

```jinja
{% set project_root = find_upward(pwd, ".git", "Cargo.toml") %}
{% if project_root is defined %}
  { "path": "{{ project_root }}", "access": "rwcd" }
{% endif %}
```

### Strict Output

Any `{{ expr }}` that evaluates to undefined (nil) is a hard error. Use `or` to
provide a default:

```
{{ env.CARGO_HOME or (dataDir + "/cargo") }}
```

This replaces the old `${CARGO_HOME:-${dataDir}/cargo}` syntax.

Conditionals (`{% if %}`) can safely test undefined values without error:

```
{% if env.OPTIONAL_VAR is defined %}{{ env.OPTIONAL_VAR }}{% endif %}
```

### Unsupported Constructs

Filters, macros, extends, include, and block inheritance are not supported.
Attempting to use them fails at parse time.

`{% set %}` is an inline tag (no block/endset form). Its scope is the current
template level (not limited to the enclosing block).

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

The `net` field controls TCP bind and connect operations. **All TCP operations
are denied by default** unless explicitly permitted.

### Allowing All Network

Set `"net": "allow"` to leave TCP completely unrestricted (network access rights
are not declared as handled, so Landlock does not restrict them):

```json
{ "net": "allow" }
```

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

    { "path": "{{ home }}/.rustup", "access": "rx", "comment": "Rust toolchains" },
    { "path": "{{ env.CARGO_HOME or (dataDir + \"/cargo\") }}", "access": "rwcd", "comment": "cargo cache and registry" },
    { "path": "{{ cacheDir }}/cargo", "access": "rwcd", "create_dir": "0700" },

    { "path": "{{ pwd }}", "access": "rwcd", "refer": true, "comment": "project working directory" },
    { "path": "{{ tmpDir }}", "access": "rwcd", "comment": "temporary files" },

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
