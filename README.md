# landcage

A Landlock-based process sandbox for Linux. Define access policies in JSON, enforce them with zero privileges.

## Install

```
go install github.com/simonfxr/landcage@latest
```

## Usage

```
landcage -p policy.json -- <command> [args...]
landcage --dry-run -p policy.json --
landcage -p policy.json.j2 --var name=value --optional-var flag=1 -- <command> [args...]
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
    { "path": "${tmpDir}", "access": "rwcd" },
    { "path": "${PWD}", "access": "rw" }
  ],
  "net": [
    { "port": 443, "access": "connect" },
    { "port": 53, "access": "connect" }
  ]
}
```

```
$ landcage policy.json -- curl -o /tmp/out https://example.com
# works

$ landcage policy.json -- curl -o /home/user/out https://example.com
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

**Variables:** `${home}`, `${uid}`, `${user}`, `${pwd}`, `${configDir}`, `${dataDir}`, `${cacheDir}`, `${stateDir}`, `${runtimeDir}`, `${tmpDir}`, `${ENV_VAR}`, `${VAR:-default}`

**Jinja templates:** policy files ending in `.j2` are rendered before JSON
parsing. Template variables passed on the CLI live under the `var` namespace:

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

## Requirements

- Linux kernel 5.13+ (Landlock V1) — more features with newer kernels
- Landlock enabled at boot (`CONFIG_SECURITY_LANDLOCK=y`)

## How It Works

1. Parses the policy JSON
2. Expands variables and globs
3. Creates directories (`create_dir`)
4. Builds a Landlock ruleset with all supported access rights handled
5. Enforces via `landlock_restrict_self()` (sets `no_new_privs`)
6. `exec()`s the child process inside the sandbox
