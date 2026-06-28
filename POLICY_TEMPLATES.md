# Policy Templates

Policy files with the `.json.j2` extension are rendered through a Jinja-style
template engine before JSON parsing. Plain `.json` files are parsed directly
without any template processing.

For the policy schema itself, see [LANDLOCK_SANDBOX_POLICY.md](./LANDLOCK_SANDBOX_POLICY.md).

---

## Overview

Templates allow a single `.json.j2` file to produce different expanded policies
based on environment context and CLI-provided variables. The output of template
rendering is a fully-expanded JSON policy.

```sh
# Render and enforce directly:
landcage -p policy.json.j2 --var profile=default -- cmd

# Render to stdout for inspection or piping:
landcage --expand -p policy.json.j2 --var profile=default
```

---

## Template Syntax

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

Unsupported constructs (filters, macros, extends, include, block inheritance)
fail at parse time rather than being silently ignored.

`{% set %}` is an inline tag (no block/endset form). Its scope is the current
template level (not limited to the enclosing block).

---

## Built-in Context

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
| `var.NAME` / `var["NAME"]` | CLI template variable (from `--var` / `--optional-var`) |

---

## Built-in Functions

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

---

## CLI Template Variables

Variables are passed via `--var` and `--optional-var` flags and accessed under
the `var` namespace.

```sh
landcage -p agent.json.j2 \
  --var profile=default \
  --optional-var include_tmp=1 \
  -- agent
```

### Rules

- `--var KEY=VALUE` provides a **required** template variable.
- Required variables must be mentioned in the template as `var.KEY` or
  `var["KEY"]`; otherwise rendering fails.
- `--optional-var KEY=VALUE` provides an optional template variable.
- Optional variables may be unused without error.
- Any `var.KEY` mentioned in the template must be provided by either `--var` or
  `--optional-var`; otherwise rendering fails.
- "Mentioned" is based on the parsed template AST, not the execution path. A
  `var.KEY` inside an untaken `{% if %}` branch still counts as mentioned.
- `var` is intentionally separate from `env`; use `env.NAME` to read an
  environment variable in a template.

---

## Strict Output

Any `{{ expr }}` that evaluates to undefined (nil) is a hard error. Use `or` to
provide a default:

```jinja
{{ env.CARGO_HOME or (dataDir + "/cargo") }}
```

Conditionals (`{% if %}`) can safely test undefined values without error:

```jinja
{% if env.OPTIONAL_VAR is defined %}{{ env.OPTIONAL_VAR }}{% endif %}
```

---

## Template Expansion and Env Values

Template expansion happens once, before JSON parsing. When using template
expressions in `env` values, they resolve against the **original** process
environment — not values defined in the same policy:

```jinja
{
  "env": {
    "FOO": "new",
    "BAR": "{{ env.FOO or \"default\" }}"
  }
}
```

Here `BAR` gets the original value of `FOO` from the process environment, not
the `"new"` value defined in the same policy.

---

## Example Template

`agent.json.j2`:

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

Expanded with `--var profile=default --optional-var include_tmp=1`:

```json
{
  "name": "agent-default",
  "fs": [
    { "path": "/home/user/.config/landcage/default", "access": "r" },
    { "path": "/tmp", "access": "rwcd" }
  ],
  "net": "allow"
}
```
