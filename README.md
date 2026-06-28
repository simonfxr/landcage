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
    { "port": 443, "access": "connect" },
    { "port": 53, "access": "connect" }
  ]
}
```

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

**Network:** `"connect"`, `"bind"`, or `"connect+bind"` per TCP port; `"net": "allow"` to skip network restriction; or `"net": "deny"` to block all network access

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

## Requirements

- Linux kernel 5.13+ (Landlock V1) — more features with newer kernels
- Landlock enabled at boot (`CONFIG_SECURITY_LANDLOCK=y`)

## How It Works

1. Loads the policy (renders Jinja template if `.json.j2`, otherwise parses directly)
2. Resolves globs and creates directories (`create_dir`)
3. Builds a Landlock ruleset with all supported access rights handled
4. Enforces via `landlock_restrict_self()` (sets `no_new_privs`)
5. `exec()`s the child process inside the sandbox
