# landcage

A Landlock-based process sandbox for Linux. Define access policies in JSON, enforce them with zero privileges.

## Install

```
go install github.com/simonfxr/landcage@latest
```

## Usage

```
landcage -p policy.json -- <command> [args...]
landcage -p policy.json.j2 --var name=value -- <command> [args...]
landcage --expand -p policy.json.j2 --var name=value
landcage --expand -p policy.json.j2 | my-filter | landcage --policy-json-from-stdin -- <command>
landcage --policy-json-from-env -- <command> [args...]
landcage --rw /project --ro /usr -- <command> [args...]
```

`--dry-run` resolves and validates a policy, then prints filesystem, network,
IPC, namespace, and environment behavior without creating directories,
entering namespaces, applying Landlock, or running the command. A command after
`--` is accepted for invocation compatibility but is never executed. With no
policy source or path flags, `landcage --dry-run` only prints detected kernel
features. A policy that requests unsupported network or hard IPC features is
printed with diagnostics and exits nonzero, matching enforcement validation.

## Example

```json
{
  "name": "restricted-curl",
  "fs": [
    { "path": "/usr", "access": "rx" },
    { "path": "/lib", "access": "rx", "ignore_missing": true },
    { "path": "/lib64", "access": "rx", "ignore_missing": true },
    { "path": "/etc/ssl", "access": "r" },
    { "path": "/etc/resolv.conf", "access": "r" },
    { "path": "/dev/null", "access": "rw" },
    { "path": "/tmp", "access": "rwcd" },
    { "path": "/home/user/project", "access": "rw" }
  ],
  "net": [
    { "port": 443, "access": "connect", "comment": "HTTPS over TCP (ABI 4+, Linux 6.7+)" },
    { "port": 53, "access": "connect", "proto": "any", "comment": "DNS over TCP+UDP (ABI 10+, Linux 7.2+)" },
    { "port": 0, "access": "bind", "proto": "udp", "comment": "UDP autobind (ABI 10+, Linux 7.2+)" }
  ]
}
```

The complete example requires **Landlock ABI 10+ / Linux 7.2+** because it
explicitly allows UDP. On ABI 4–9 (Linux 6.7–7.1), omit the UDP autobind rule
and use the default TCP protocol for port 53; UDP remains unrestricted because
those kernels cannot mediate it.

```
$ landcage -p policy.json -- curl -o /tmp/out https://example.com
# works

$ landcage -p policy.json -- curl -o /home/user/out https://example.com
# curl: Permission denied
```

## Policy Format

See [LANDLOCK_SANDBOX_POLICY.md](LANDLOCK_SANDBOX_POLICY.md) for the full specification.

### Quick Reference

**Filesystem access flags:**

| Flag | Meaning |
|------|---------|
| `r` | Read files/directories |
| `w` | Write/truncate files |
| `x` | Execute files |
| `c` | Create new files/dirs/sockets/pipes/symlinks |
| `d` | Delete files/dirs |
| `u` | Connect to pathname UNIX sockets (V9+) |

**Additional rule fields:** `refer` (cross-dir rename), `ioctl_dev` (device ioctls), `ignore_missing`, `create_dir`

**Network:** `"connect"`, `"bind"`, or `"connect+bind"` per port; `"proto": "tcp"` (default), `"udp"`, or `"any"`. `"net": "allow"` skips network restriction; `"net": "deny"` blocks TCP on ABI 4+ and UDP on ABI 10+. UDP connect from an unbound socket also needs `"bind"` on port 0.

| Network option | Minimum Landlock ABI | Minimum Linux | Behavior |
|----------------|----------------------|---------------|----------|
| `"net": "allow"` | 1 | 5.13 | No network restriction requested |
| `"net": "deny"` | 4 / 10 | 6.7 / 7.2 | Denies TCP from ABI 4; TCP and UDP from ABI 10 |
| `"proto": "tcp"` or omitted | 4 | 6.7 | TCP bind/connect |
| `"proto": "udp"` | 10 | 7.2 | UDP bind/connect/send |
| `"proto": "any"` | 10 | 7.2 | Both TCP and UDP rights |

`"proto": "any"` requires ABI 10 because it includes UDP. Explicit UDP/`any`
rules fail closed on older kernels rather than being silently dropped. Before
ABI 4 / Linux 6.7, Landlock cannot restrict network access.

**IPC:** `"deny"` (hard), `"allow"` (explicit), or omit for best-effort deny

**Template variables:** Policy files come in two formats:

- **`.json`** — plain JSON, parsed directly (no template expansion)
- **`.json.j2`** — Jinja-style template, expanded before JSON parsing

Templates have built-in variables (`home`, `pwd`, `tmpDir`, `configDir`, etc.),
access to environment via `env.NAME`, and CLI-provided variables via `var.NAME`.
See [POLICY_TEMPLATES.md](POLICY_TEMPLATES.md) for the full template reference.

**Inline policy from environment:** `--policy-json-from-env` reads pre-expanded
policy JSON from the `LANDCAGE_POLICY_JSON` environment variable (no template
expansion). Mutually exclusive with `-p`.

**Expand mode:** `--expand` renders the policy and outputs JSON to stdout (no
enforcement). Works with both `.json` and `.json.j2` files. This enables
pipelines:

```sh
landcage --expand -p policy.json.j2 --var profile=dev | my-filter | \
  landcage --policy-json-from-stdin -- cmd
```

**Stdin policy:** `--policy-json-from-stdin` reads pre-expanded policy JSON from
stdin (no template expansion).

**Quick path flags:** `--ro PATH` adds a read+execute rule (like `"access": "rx"`).
`--rw PATH` adds a full read/write/execute/create/delete+refer rule. Both
set `ignore_missing: true`. These can be combined with `-p` or used standalone.

## Documentation

- [Policy Specification](LANDLOCK_SANDBOX_POLICY.md) — JSON policy schema (filesystem, network, IPC, namespaces, env)
- [Template Reference](POLICY_TEMPLATES.md) — Jinja-style template language for `.json.j2` policies
- [Landlock API Reference](LANDLOCK.md) — kernel ABI, including Linux 7.2 / ABI 10

## Requirements

- Linux kernel 5.13+ (Landlock V1) — more features with newer kernels (ABI 10 on Linux 7.2: UDP bind/connect/send and quiet audit rules)
- Landlock enabled at boot (`CONFIG_SECURITY_LANDLOCK=y`)

## Kernel Compatibility

Filesystem policy rules are portable across kernel versions. ABI-gated filesystem flags
(`u`, `refer`, `ioctl_dev`, and `truncate` implied by `w`) are **silently
dropped** on kernels that don't support them, with a warning on stderr.
This lets you write one policy that works on both older and newer kernels.

Per-port network rules and IPC `"deny"` are **not** downgraded — they error if
the kernel is too old, since silently skipping them would compromise the
sandbox. TCP rules require ABI 4 / Linux 6.7; explicit
`"proto": "udp"` / `"any"` rules require ABI 10 / Linux 7.2.
On ABI 4–9, net restriction is TCP-only and UDP stays unrestricted (with
a warning). `"net": "deny"` is best effort across ABI levels as detailed in
the table above.

## How It Works

1. Loads the policy (renders Jinja template if `.json.j2`, otherwise parses directly)
2. Resolves globs and creates directories (`create_dir`)
3. Builds a Landlock ruleset with all supported access rights handled
4. Enforces via `landlock_restrict_self()` (sets `no_new_privs`)
5. `exec()`s the child process inside the sandbox
