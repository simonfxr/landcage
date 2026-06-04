# Landlock User Space API Reference

Landlock is an unprivileged, stackable access-control mechanism that allows
processes to sandbox themselves. No root privileges or special capabilities are
required — only the `no_new_privs` flag (or `CAP_SYS_ADMIN`).

**Current ABI version: 9 (in development, not yet released upstream)**

---

## System Calls

### `landlock_create_ruleset()`

```c
#include <linux/landlock.h>
#include <sys/syscall.h>

int syscall(SYS_landlock_create_ruleset,
            const struct landlock_ruleset_attr *attr,
            size_t size,
            __u32 flags);
```

Creates a new ruleset or queries Landlock support.

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `attr` | Pointer to `struct landlock_ruleset_attr`. Must be NULL if `flags` is set. |
| `size` | Size of `attr` in bytes (`sizeof(struct landlock_ruleset_attr)`). Must be 0 if `flags` is set. |
| `flags` | `0`, `LANDLOCK_CREATE_RULESET_VERSION`, or `LANDLOCK_CREATE_RULESET_ERRATA` |

**Returns:**

- Ruleset file descriptor on success (flags=0)
- ABI version number if `LANDLOCK_CREATE_RULESET_VERSION` is set
- Errata bitmask if `LANDLOCK_CREATE_RULESET_ERRATA` is set
- `-1` with errno on failure

**Errors:**

| errno | Condition |
|-------|-----------|
| `EOPNOTSUPP` | Landlock supported but disabled at boot |
| `EINVAL` | Unknown flags, unknown access rights, unknown scope, or size too small |
| `E2BIG` | `attr` or `size` inconsistencies |
| `EFAULT` | `attr` is not a valid address |
| `ENOMSG` | `handled_access_fs` is empty (no FS access rights handled) |

---

### `landlock_add_rule()`

```c
int syscall(SYS_landlock_add_rule,
            int ruleset_fd,
            enum landlock_rule_type rule_type,
            const void *rule_attr,
            __u32 flags);
```

Adds an allow-rule to an existing ruleset.

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `ruleset_fd` | File descriptor returned by `landlock_create_ruleset()` |
| `rule_type` | `LANDLOCK_RULE_PATH_BENEATH` or `LANDLOCK_RULE_NET_PORT` |
| `rule_attr` | Pointer to rule struct matching `rule_type` |
| `flags` | Must be 0 |

**Returns:** `0` on success, `-1` with errno on failure.

**Errors:**

| errno | Condition |
|-------|-----------|
| `EOPNOTSUPP` | Landlock disabled at boot |
| `EAFNOSUPPORT` | `LANDLOCK_RULE_NET_PORT` used but TCP/IP not compiled in |
| `EINVAL` | Non-zero flags, `allowed_access` not a subset of handled accesses, or port > 65535 |
| `ENOMSG` | `allowed_access` is 0 (empty rule) |
| `EBADF` | Invalid `ruleset_fd` or invalid `parent_fd` in rule attr |
| `EBADFD` | `ruleset_fd` is not a ruleset FD, or `parent_fd` is not a valid path FD |
| `EPERM` | `ruleset_fd` lacks write access |
| `EFAULT` | `rule_attr` is not a valid address |

---

### `landlock_restrict_self()`

```c
int syscall(SYS_landlock_restrict_self,
            int ruleset_fd,
            __u32 flags);
```

Enforces a ruleset on the calling thread, creating a new Landlock domain (or
stacking onto an existing one).

**Prerequisites:** The thread must either:
- Have `no_new_privs` set (`prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`), or
- Have `CAP_SYS_ADMIN` in its user namespace

**Parameters:**

| Parameter | Description |
|-----------|-------------|
| `ruleset_fd` | Ruleset FD, or `-1` when only setting `LOG_SUBDOMAINS_OFF` |
| `flags` | Bitmask of `LANDLOCK_RESTRICT_SELF_*` flags (see below) |

**Flags:**

| Flag | Description |
|------|-------------|
| `LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF` | Disable audit logging for denials from the current executable |
| `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON` | Enable audit logging for denials after `execve()` |
| `LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF` | Disable audit logging for nested subdomain denials |
| `LANDLOCK_RESTRICT_SELF_TSYNC` | Apply domain to all threads in the process atomically |

**Returns:** `0` on success, `-1` with errno on failure.

**Errors:**

| errno | Condition |
|-------|-----------|
| `EOPNOTSUPP` | Landlock disabled at boot |
| `EINVAL` | Unknown flags |
| `EBADF` | Invalid `ruleset_fd` |
| `EBADFD` | `ruleset_fd` is not a ruleset FD |
| `EPERM` | No `no_new_privs` and no `CAP_SYS_ADMIN`, or no read access to ruleset |
| `E2BIG` | Maximum 16 stacked rulesets reached |

---

## Structures

### `struct landlock_ruleset_attr`

Defines which access rights the ruleset will handle (deny by default).

```c
struct landlock_ruleset_attr {
    __u64 handled_access_fs;   /* Bitmask of LANDLOCK_ACCESS_FS_* */
    __u64 handled_access_net;  /* Bitmask of LANDLOCK_ACCESS_NET_* */
    __u64 scoped;              /* Bitmask of LANDLOCK_SCOPE_* */
};
```

Size: 24 bytes. Extensible in future ABI versions.

---

### `struct landlock_path_beneath_attr`

Used with `LANDLOCK_RULE_PATH_BENEATH`.

```c
struct landlock_path_beneath_attr {
    __u64 allowed_access;  /* Bitmask of LANDLOCK_ACCESS_FS_* to allow */
    __s32 parent_fd;       /* FD to directory (or file), preferably O_PATH */
} __attribute__((packed));
```

Size: 12 bytes. The rule grants `allowed_access` to the file hierarchy rooted at
`parent_fd`.

---

### `struct landlock_net_port_attr`

Used with `LANDLOCK_RULE_NET_PORT`.

```c
struct landlock_net_port_attr {
    __u64 allowed_access;  /* Bitmask of LANDLOCK_ACCESS_NET_* to allow */
    __u64 port;            /* TCP port in host byte order (0–65535) */
};
```

Size: 16 bytes.

---

## Access Rights

### Filesystem Flags (`LANDLOCK_ACCESS_FS_*`)

Used in `handled_access_fs` and `landlock_path_beneath_attr.allowed_access`.

| Flag | Value | Applies to | ABI | Description |
|------|-------|-----------|-----|-------------|
| `LANDLOCK_ACCESS_FS_EXECUTE` | `1 << 0` | Files | 1 | Execute a file |
| `LANDLOCK_ACCESS_FS_WRITE_FILE` | `1 << 1` | Files | 1 | Open file with write access |
| `LANDLOCK_ACCESS_FS_READ_FILE` | `1 << 2` | Files | 1 | Open file with read access |
| `LANDLOCK_ACCESS_FS_READ_DIR` | `1 << 3` | Directories | 1 | Open or list a directory |
| `LANDLOCK_ACCESS_FS_REMOVE_DIR` | `1 << 4` | Dir contents | 1 | Remove an empty directory |
| `LANDLOCK_ACCESS_FS_REMOVE_FILE` | `1 << 5` | Dir contents | 1 | Unlink (or rename) a file |
| `LANDLOCK_ACCESS_FS_MAKE_CHAR` | `1 << 6` | Dir contents | 1 | Create a character device |
| `LANDLOCK_ACCESS_FS_MAKE_DIR` | `1 << 7` | Dir contents | 1 | Create a directory |
| `LANDLOCK_ACCESS_FS_MAKE_REG` | `1 << 8` | Dir contents | 1 | Create a regular file |
| `LANDLOCK_ACCESS_FS_MAKE_SOCK` | `1 << 9` | Dir contents | 1 | Create a UNIX domain socket |
| `LANDLOCK_ACCESS_FS_MAKE_FIFO` | `1 << 10` | Dir contents | 1 | Create a named pipe |
| `LANDLOCK_ACCESS_FS_MAKE_BLOCK` | `1 << 11` | Dir contents | 1 | Create a block device |
| `LANDLOCK_ACCESS_FS_MAKE_SYM` | `1 << 12` | Dir contents | 1 | Create a symbolic link |
| `LANDLOCK_ACCESS_FS_REFER` | `1 << 13` | Dir contents | 2 | Reparent (link/rename across directories) |
| `LANDLOCK_ACCESS_FS_TRUNCATE` | `1 << 14` | Files | 3 | Truncate a file |
| `LANDLOCK_ACCESS_FS_IOCTL_DEV` | `1 << 15` | Files (devices) | 5 | Invoke ioctl on character/block devices |
| `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` | `1 << 16` | Files | 9 | Connect to pathname UNIX domain sockets |

**Notes:**

- `LANDLOCK_ACCESS_FS_REFER` is **always denied by default**, even if not listed
  in `handled_access_fs`. It must be explicitly allowed via a rule.
- "Dir contents" flags apply to operations on entries *within* the directory, not
  the directory itself.
- `LANDLOCK_ACCESS_FS_IOCTL_DEV` does not restrict generic FD/file-description
  ioctls (`FIOCLEX`, `FIONBIO`, etc.) — only device-driver-specific ones.
- `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` only restricts connections to UNIX sockets
  created *outside* the current domain.

### Network Flags (`LANDLOCK_ACCESS_NET_*`)

Used in `handled_access_net` and `landlock_net_port_attr.allowed_access`.

| Flag | Value | ABI | Description |
|------|-------|-----|-------------|
| `LANDLOCK_ACCESS_NET_BIND_TCP` | `1 << 0` | 4 | Bind a TCP socket to a local port |
| `LANDLOCK_ACCESS_NET_CONNECT_TCP` | `1 << 1` | 4 | Connect a TCP socket to a remote port |

**Note:** Port 0 with `BIND_TCP` allows binding to a kernel-assigned ephemeral port.

### Scope Flags (`LANDLOCK_SCOPE_*`)

Used in `landlock_ruleset_attr.scoped`. These are **domain-wide IPC isolation
rules** — unlike FS/net rules which allow access to specific objects (paths,
ports), scopes blanket-deny certain cross-domain interactions. There are no
per-object rules for scopes; you simply set the bits at ruleset creation time and
the restriction applies globally to the domain.

| Flag | Value | ABI | Description |
|------|-------|-----|-------------|
| `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` | `1 << 0` | 6 | Block connecting to abstract UNIX sockets outside the domain |
| `LANDLOCK_SCOPE_SIGNAL` | `1 << 1` | 6 | Block sending signals to processes outside the domain |

#### `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`

Restricts `connect()` and `sendmsg()` to abstract UNIX sockets (those in the
abstract namespace with a NUL first byte in `sun_path`) that were created by
processes **outside** the sandboxed domain. Connections to abstract sockets
created within the same domain or a nested domain remain allowed.

Returns `EPERM` on denial.

This only applies to abstract sockets. For pathname-based UNIX sockets, use
`LANDLOCK_ACCESS_FS_RESOLVE_UNIX` (ABI v9) which provides per-path granularity.

#### `LANDLOCK_SCOPE_SIGNAL`

Restricts sending signals (`kill()`, `sigqueue()`, `tgkill()`, `tkill()`,
`rt_sigqueueinfo()`, and async I/O signals like `SIGIO`/`SIGURG`) to processes
**outside** the sandboxed domain.

**What "outside the domain" means:**

The check walks the domain hierarchy to determine if the target process is
reachable. A signal is:

- **Allowed** if the target is in the **same domain** or a **nested (child)
  domain** — i.e., the target's domain is a descendant of the sender's domain.
- **Denied** (`EPERM`) if the target is in a **parent domain**, a **sibling
  domain**, or is **unsandboxed**.

**Example hierarchy:**

```
unsandboxed parent (PID 1000)
  └─ domain A (PID 2000)       ← sets LANDLOCK_SCOPE_SIGNAL
       ├─ forked child (PID 3000)    ← inherits domain A
       └─ nested domain B (PID 4000) ← domain A + extra ruleset
```

From PID 2000:
- `kill(3000, SIGTERM)` → **allowed** (same domain, inherited via fork)
- `kill(4000, SIGTERM)` → **allowed** (target is in a nested/child domain)
- `kill(1000, SIGTERM)` → **EPERM** (target is outside/above the domain)

**Exceptions:**

- Signals between threads of the **same process** (`same_thread_group()`) are
  always allowed regardless of scoping. This is required for NPTL's internal
  `tgkill()` calls during `setuid()`/`setgid()` credential changes.

**Async I/O signals (`SIGIO`/`SIGURG`):**

The scope check also applies to `fcntl(F_SETOWN)`-based async signals. If a
sandboxed process sets up `SIGIO` on a file descriptor, that signal cannot be
delivered to a process outside its domain.

---

## Semantics

### Deny-by-Default Model

Access rights listed in `handled_access_fs` / `handled_access_net` are **denied
by default**. Rules added via `landlock_add_rule()` selectively **allow** specific
accesses on specific objects. Any handled access that is not explicitly allowed by
a matching rule will be denied with `EACCES`.

Access rights *not* listed as handled are unrestricted by this ruleset.

### Domain Stacking (Layering)

- Up to **16 rulesets** can be stacked on a single thread.
- Each stacked ruleset forms a **layer**. An access is granted only if **every
  layer** independently allows it.
- A child domain can never grant more access than its parent. Stacking is
  monotonically restrictive.
- Stacking is inherited across `fork()` and `clone()`.

### The REFER Rule

`LANDLOCK_ACCESS_FS_REFER` controls **reparenting** — moving a file from one
directory to another via `link()` or `rename()`. This only applies to the
cross-directory case; renaming within the same directory does not trigger it.

**Always denied by default:** Unlike every other access right (which is
unrestricted unless explicitly handled), REFER is blocked even if you don't list
it in `handled_access_fs`. The rationale is that reparenting can grant a file
more access rights in its new location, creating a privilege escalation path.
The only way to allow it is to explicitly add a rule with REFER for the relevant
directories.

**Additional constraints** for a cross-directory `link()`/`rename()` to succeed:

1. Source directory must have `REFER` allowed.
2. Destination directory must have `REFER` allowed.
3. Destination directory must have the relevant `MAKE_*` right for the file type
   (e.g., `MAKE_REG` for a regular file, `MAKE_SYM` for a symlink).
4. For `rename()`, the source directory must have the relevant `REMOVE_*` right
   (`REMOVE_FILE` or `REMOVE_DIR`). Not required for `link()`.
5. **Anti-escalation check:** The file must NOT gain more access rights in the
   destination than it had in the source location.

**Error codes:**

- `EACCES` — missing REFER, MAKE_*, or REMOVE_* rights (takes precedence)
- `EXDEV` — anti-escalation check failed (file would gain access rights)

The `EXDEV` error is intentional: it's the same error returned when moving files
across filesystem boundaries, so programs already handle it gracefully (typically
by falling back to copy+delete).

**Practical implication:** If you don't add any REFER rules, files can never be
linked or renamed across directories. This is often acceptable for sandboxed
applications. However, if your app uses atomic write patterns like
`rename(tmpfile, final_path)` where the temp file and final path are in different
directories, you need REFER on both parent directories.

### The IOCTL_DEV Rule

`LANDLOCK_ACCESS_FS_IOCTL_DEV` controls whether `ioctl()` can be called on
**character and block devices only**. It does NOT apply to regular files,
directories, pipes, or sockets.

When handled and not allowed for a device's path, any device-driver-specific
ioctl returns `EACCES`.

**Always-permitted ioctls** (these are VFS-level, not device-driver-specific):

- FD flags: `FIOCLEX`, `FIONCLEX`
- File description flags: `FIONBIO`, `FIOASYNC`
- File size: `FIOQSIZE`
- Filesystem-level: `FIFREEZE`, `FITHAW`, `FIGETBSZ`, `FS_IOC_GETFSUUID`,
  `FS_IOC_GETFSSYSFSPATH`
- No-ops on devices: `FS_IOC_FIEMAP`, `FICLONE`, `FICLONERANGE`,
  `FIDEDUPERANGE`

**Not permitted** (guarded by the access right): `FIONREAD`, `FS_IOC_GETFLAGS`,
`FS_IOC_SETFLAGS`, `FS_IOC_FSGETXATTR`, `FS_IOC_FSSETXATTR`, `FIBMAP`,
and all device-specific commands.

**Open-time check:** The permission is determined at `open()` time and stored on
the file struct. If you open a device when `IOCTL_DEV` is allowed, then later
stack a more restrictive layer, ioctls on that already-open FD still work.

**Use case:** Allow a sandboxed process to `read()`/`write()` a device file
(e.g., `/dev/video0`) while preventing it from calling device-specific ioctls
that could reconfigure hardware or access kernel memory.

### How Filesystem Access Checks Work

Landlock filesystem rules are attached to **inodes** (not path strings). When an
operation is checked, the kernel walks **up the directory tree** from the accessed
path toward the filesystem root, looking for matching rules at each level:

```
open("/home/user/project/src/main.c", O_RDONLY)

Walk: main.c → src/ → project/ → user/ → home/ → /
      ↑ check each inode for a matching rule
```

A rule on a directory grants access to **everything beneath it** (hence the name
`PATH_BENEATH`). An access is granted when every layer that handles that access
right has been "unmasked" by at least one matching ancestor rule.

Because rules are inode-based:
- They survive file/directory renames
- They follow bind mounts (the same inode is checked regardless of mount path)
- Symlink resolution uses the real target path for checking

#### Rules on Files vs Directories

You can attach rules to **specific files** (not just directories):

```c
/* Grant read access to /etc/passwd only, NOT all of /etc */
int fd = open("/etc/passwd", O_PATH | O_CLOEXEC);
struct landlock_path_beneath_attr attr = {
    .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
    .parent_fd = fd,
};
syscall(SYS_landlock_add_rule, ruleset_fd,
        LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
close(fd);
```

When `parent_fd` refers to a regular file, only file-applicable rights are
accepted: `EXECUTE`, `READ_FILE`, `WRITE_FILE`, `TRUNCATE`, `IOCTL_DEV`,
`RESOLVE_UNIX`. Attempting to set directory rights (like `MAKE_REG`) on a file
rule returns `EINVAL`.

#### What's Hooked

| Syscall / Operation | Access Right Checked |
|---------------------|---------------------|
| `open()` (read) | `READ_FILE` or `READ_DIR` |
| `open()` (write) | `WRITE_FILE` |
| `open()` (exec, e.g. `execve`) | `EXECUTE` |
| `mkdir()` | `MAKE_DIR` on parent directory |
| `mknod()` / `creat()` | `MAKE_REG`/`MAKE_CHAR`/`MAKE_BLOCK`/`MAKE_FIFO`/`MAKE_SOCK` on parent |
| `symlink()` | `MAKE_SYM` on parent directory |
| `unlink()` | `REMOVE_FILE` on parent directory |
| `rmdir()` | `REMOVE_DIR` on parent directory |
| `link()` / `rename()` (cross-dir) | `REFER` + `MAKE_*`/`REMOVE_*` |
| `truncate()` / `ftruncate()` | `TRUNCATE` |
| `ioctl()` on devices | `IOCTL_DEV` |
| `connect()` to pathname UNIX socket | `RESOLVE_UNIX` |
| `mount()` / `umount()` / `pivot_root()` / `remount()` | **Always denied** (see below) |

#### Mount Operations Are Always Denied

Any process with *any* filesystem access right handled is **unconditionally
blocked** from `mount()`, `umount()`, `pivot_root()`, `move_mount()`, and
`remount()`. This prevents bypassing the sandbox by reshaping the mount
namespace.

`chroot()` is intentionally still allowed since it can only further restrict the
view of the filesystem.

#### Open-Time vs Access-Time Checks

For `TRUNCATE` and `IOCTL_DEV`, the permission is determined **at open time** and
stored on the `struct file`. This means:

- If you open a file when `TRUNCATE` is allowed, then later add a more restrictive
  layer, `ftruncate()` on the already-open FD still succeeds.
- The same applies to `ioctl()` on devices.

This is consistent with how `READ_FILE`/`WRITE_FILE` work — the open mode is
checked once at `open()` time.

### Path Resolution and Bypass Attempts

#### `/proc/self/root/...`

Does **NOT** bypass Landlock. The kernel resolves the proc symlink to the real
file path, and `hook_file_open` checks using the resolved `file->f_path`. Opening
`/proc/self/root/etc/shadow` triggers the same access check as opening
`/etc/shadow` directly.

#### `/proc/<pid>/fd/<n>`

Does **NOT** bypass Landlock. Re-opening an FD through procfs still triggers
`hook_file_open` with the real underlying path. You cannot use this to regain
access that would be denied on a fresh `open()`.

#### Pseudo-filesystems (Always Accessible)

Internal pseudo-filesystems that are never mountable are **exempt** from Landlock
checks:

- `sockfs`, `pipefs`, `anon_inodefs` (marked `SB_NOUSER`)
- Inodes marked `IS_PRIVATE` (internal kernel objects)
- These are reachable through `/proc/<pid>/fd/` but contain no user data

#### Namespace Filesystems (`nsfs`)

Paths like `/proc/<pid>/ns/net` live on an internal filesystem (`MNT_INTERNAL`).
When the upward path walk reaches a disconnected root on an internal filesystem,
access is **granted**. This allows namespace FD operations even when sandboxed.

### File Descriptors Opened Before Sandboxing

Files opened before `landlock_restrict_self()` retain their full access rights.
Landlock only restricts **future** `open()` / `connect()` / `bind()` operations.
Pre-existing FDs are not affected.

This is by design — it allows a process to open config files, log files, etc.
before sandboxing itself, then continue using them.

### Not Yet Restrictable

The following operations cannot currently be restricted by Landlock:

- `stat()`, `lstat()`, `fstatat()` — metadata is always readable
- `access()`, `faccessat()` — permission checking is unrestricted
- `chdir()`, `fchdir()` — changing working directory
- `flock()` — file locking
- `chmod()`, `fchmod()` — permission changes
- `chown()`, `fchown()` — ownership changes
- `setxattr()`, `getxattr()` — extended attributes
- `utime()`, `utimensat()` — timestamp modification
- `fcntl()` — file descriptor control

This means a sandboxed process can still probe filesystem structure (checking
existence and metadata via `stat()`) even without read access. This is a known
information-leak surface that future Landlock versions may address.

### Network Access Check Details

#### `LANDLOCK_ACCESS_NET_CONNECT_TCP`

Hooks into the `connect(2)` syscall for **TCP sockets only**. Non-TCP sockets
(UDP, SCTP, raw, etc.) are completely unrestricted.

The check:
1. Extracts the destination **port** from the `sockaddr` (IPv4 or IPv6)
2. Looks up the port in the domain's rule tree
3. Every layer handling `CONNECT_TCP` must have a rule allowing that port

Key behaviors:
- **Port-based only** — the destination IP is not checked. A rule allowing port
  443 allows connecting to *any* host on port 443.
- **`AF_UNSPEC` always allowed** — `connect(sock, {AF_UNSPEC})` dissolves a TCP
  association (disconnect). This is treated as "closing" and never blocked.
- **No UDP/SCTP** — only TCP `connect()` is checked.
- **Already-connected sockets** — not affected; only the `connect()` call itself.

#### `LANDLOCK_ACCESS_NET_BIND_TCP`

Hooks into `bind(2)` for TCP sockets. Same port-based lookup as `CONNECT_TCP`.

Port 0 with `BIND_TCP` means "allow the kernel to assign an ephemeral port."
The ephemeral range is configurable via
`/proc/sys/net/ipv4/ip_local_port_range`.

---

## Policy Design Patterns

### Per-File Access (Granular)

```c
/* Allow reading only specific config files */
int fd1 = open("/etc/resolv.conf", O_PATH | O_CLOEXEC);
int fd2 = open("/etc/ssl/certs/ca-certificates.crt", O_PATH | O_CLOEXEC);
// Add rules for fd1 and fd2 with READ_FILE
// No rule on /etc itself → everything else in /etc is denied
```

### Read-Only Root with Write Areas

```c
struct landlock_ruleset_attr attr = {
    .handled_access_fs =
        LANDLOCK_ACCESS_FS_WRITE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_MAKE_DIR |
        LANDLOCK_ACCESS_FS_TRUNCATE |
        LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_REMOVE_DIR,
};
// Rule: allow all handled rights on /tmp
// Rule: allow all handled rights on /var/data
// Result: writes only possible under /tmp and /var/data
// Reads are unrestricted (not handled)
```

### Selective Deny via Layer Stacking

Since Landlock only has allow-rules (no deny-rules), you achieve "allow
everything except X" by stacking two layers:

```c
/* Layer 1: allow read everywhere */
// handled: READ_FILE | READ_DIR
// rule: allow READ_FILE|READ_DIR on /

/* Layer 2: allow read everywhere EXCEPT /secret */
// handled: READ_FILE | READ_DIR
// rule: allow READ_FILE|READ_DIR on /home
// rule: allow READ_FILE|READ_DIR on /usr
// rule: allow READ_FILE|READ_DIR on /etc
// (no rule on /secret → denied by layer 2)
```

Both layers must independently allow access. Layer 1 allows everything, but
layer 2 has no rule covering `/secret`, so access is denied there.

### Full Application Confinement

```c
struct landlock_ruleset_attr attr = {
    .handled_access_fs =
        LANDLOCK_ACCESS_FS_EXECUTE |
        LANDLOCK_ACCESS_FS_WRITE_FILE |
        LANDLOCK_ACCESS_FS_READ_FILE |
        LANDLOCK_ACCESS_FS_READ_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_MAKE_DIR |
        LANDLOCK_ACCESS_FS_TRUNCATE,
    .handled_access_net =
        LANDLOCK_ACCESS_NET_BIND_TCP |
        LANDLOCK_ACCESS_NET_CONNECT_TCP,
    .scoped =
        LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET |
        LANDLOCK_SCOPE_SIGNAL,
};

// Filesystem rules:
// /usr           → EXECUTE | READ_FILE | READ_DIR
// /etc           → READ_FILE | READ_DIR
// /tmp           → READ_FILE | READ_DIR | WRITE_FILE | MAKE_REG | TRUNCATE
// ~/.config/app  → READ_FILE | READ_DIR | WRITE_FILE | MAKE_REG | TRUNCATE
// /dev/null      → READ_FILE | WRITE_FILE

// Network rules:
// port 443       → CONNECT_TCP
// port 53        → CONNECT_TCP

// Result: app can only execute from /usr, read configs,
//         write to its own dirs, connect to HTTPS/DNS,
//         and cannot signal or IPC with parent processes.
```

### Prevent Data Exfiltration

```c
struct landlock_ruleset_attr attr = {
    .handled_access_fs =
        LANDLOCK_ACCESS_FS_WRITE_FILE |
        LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_MAKE_SYM |
        LANDLOCK_ACCESS_FS_TRUNCATE,
    .handled_access_net =
        LANDLOCK_ACCESS_NET_CONNECT_TCP,
    .scoped =
        LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET,
};
// No write rules anywhere → cannot write any file
// No connect rules → cannot connect to any TCP port
// Abstract UNIX scoped → cannot reach outside IPC
// Reads are unrestricted → process can read secrets but cannot exfil them
```

---

## Compatibility and Feature Detection

```c
/* Check if Landlock is available and get ABI version */
int abi = syscall(SYS_landlock_create_ruleset, NULL, 0,
                  LANDLOCK_CREATE_RULESET_VERSION);
if (abi < 0) {
    /* ENOSYS: kernel too old; EOPNOTSUPP: disabled at boot */
}

/* Get errata bitmask for current ABI version */
int errata = syscall(SYS_landlock_create_ruleset, NULL, 0,
                     LANDLOCK_CREATE_RULESET_ERRATA);
```

Best practice: declare all access rights you know about (up to your build-time ABI
version) in `handled_access_fs` / `handled_access_net`. At runtime, mask out flags
not supported by the detected ABI version.

---

## Complete Example

```c
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    /* 1. Create ruleset handling read/write/execute */
    struct landlock_ruleset_attr attr = {
        .handled_access_fs =
            LANDLOCK_ACCESS_FS_EXECUTE |
            LANDLOCK_ACCESS_FS_READ_FILE |
            LANDLOCK_ACCESS_FS_READ_DIR |
            LANDLOCK_ACCESS_FS_WRITE_FILE |
            LANDLOCK_ACCESS_FS_TRUNCATE,
        .handled_access_net =
            LANDLOCK_ACCESS_NET_BIND_TCP |
            LANDLOCK_ACCESS_NET_CONNECT_TCP,
    };
    int ruleset_fd = syscall(SYS_landlock_create_ruleset,
                             &attr, sizeof(attr), 0);

    /* 2. Allow read/execute under /usr */
    int usr_fd = open("/usr", O_PATH | O_DIRECTORY | O_CLOEXEC);
    struct landlock_path_beneath_attr path_attr = {
        .allowed_access = LANDLOCK_ACCESS_FS_EXECUTE |
                          LANDLOCK_ACCESS_FS_READ_FILE |
                          LANDLOCK_ACCESS_FS_READ_DIR,
        .parent_fd = usr_fd,
    };
    syscall(SYS_landlock_add_rule, ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0);
    close(usr_fd);

    /* 3. Allow connecting to port 443 */
    struct landlock_net_port_attr net_attr = {
        .allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP,
        .port = 443,
    };
    syscall(SYS_landlock_add_rule, ruleset_fd,
            LANDLOCK_RULE_NET_PORT, &net_attr, 0);

    /* 4. Enforce */
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    syscall(SYS_landlock_restrict_self, ruleset_fd, 0);
    close(ruleset_fd);

    /* Now sandboxed: only /usr is readable/executable,
       only TCP port 443 is connectable,
       no file writes allowed anywhere. */
}
```

---

## ABI Version History

| Version | Kernel | New Features |
|---------|--------|-------------|
| 1 | 5.13 | Initial: 13 FS access rights |
| 2 | 5.19 | `LANDLOCK_ACCESS_FS_REFER` |
| 3 | 6.2 | `LANDLOCK_ACCESS_FS_TRUNCATE` |
| 4 | 6.7 | Network rules (`BIND_TCP`, `CONNECT_TCP`) |
| 5 | 6.10 | `LANDLOCK_ACCESS_FS_IOCTL_DEV` |
| 6 | 6.12 | Scope flags (`ABSTRACT_UNIX_SOCKET`, `SIGNAL`) |
| 7 | 6.13 | (no new user-visible access rights) |
| 8 | 6.14 | (no new user-visible access rights) |
| 9 | TBD (unreleased) | `LANDLOCK_ACCESS_FS_RESOLVE_UNIX`, `RESTRICT_SELF_TSYNC`, logging flags, errata |
