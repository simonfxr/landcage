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
    { "path": "{{ tmpDir }}", "access": "rwcd" },
    { "path": "{{ pwd }}", "access": "rw" }
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

**Network:** `"connect"`, `"bind"`, or `"connect+bind"` per TCP port; or `"net": "allow"` to skip network restriction entirely

**IPC:** `"deny"` (hard), `"allow"` (explicit), or omit for best-effort deny

**Template variables:** Policy files come in two formats:

- **`.json`** — plain JSON, parsed directly (no template expansion)
- **`.json.j2`** — Jinja-style template, expanded before JSON parsing

Template files (`.json.j2`) have built-in variables available at the top level:

| Variable | Value |
|----------|-------|
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

Environment variables are available as `{{ env.NAME }}` or `{{ env["NAME"] }}`.
Accessing an undefined variable in output (`{{ }}`) is an error; use `or` to
provide a default: `{{ env.CARGO_HOME or (dataDir + "/cargo") }}`.

**Built-in template functions:**

| Function | Description |
|----------|-------------|
| `exists(path)` | Returns true if the path exists |
| `is_dir(path)` | Returns true if the path exists and is a directory |
| `is_file(path)` | Returns true if the path exists and is a regular file |
| `find_upward(start, marker...)` | Walks up from `start` looking for a directory containing any marker; returns the directory path or nil |

**Additional template syntax:** `{% set name = expr %}` (local variable
assignment), `{# comment #}` (ignored), and `{{ fn(arg) }}` (function calls).

**Parameterized templates (`.j2`):** Files ending in `.j2` additionally support
CLI-provided template variables under the `var` namespace:

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

```sh
landcage -p agent.json.j2 \
  --var profile=default \
  --optional-var include_tmp=1 \
  -- agent
```

`--var KEY=VALUE` is required and must be mentioned as `var.KEY` or
`var["KEY"]` in the template. `--optional-var KEY=VALUE` may be unused. Any
mentioned `var.KEY` that was not provided fails template rendering, including
mentions in untaken branches.

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

## Requirements

- Linux kernel 5.13+ (Landlock V1) — more features with newer kernels
- Landlock enabled at boot (`CONFIG_SECURITY_LANDLOCK=y`)

## How It Works

1. Renders the policy file through the Jinja template engine
2. Parses the resulting JSON
3. Resolves globs and creates directories (`create_dir`)
4. Builds a Landlock ruleset with all supported access rights handled
5. Enforces via `landlock_restrict_self()` (sets `no_new_privs`)
6. `exec()`s the child process inside the sandbox
