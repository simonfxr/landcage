package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Policy is the top-level sandbox policy.
type Policy struct {
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	Env         map[string]EnvEntry `json:"env,omitempty"`
	FS          []FSRule            `json:"fs,omitempty"`
	Net         NetConfig           `json:"net"`
	IPC         *IPCConfig          `json:"ipc,omitempty"`
}

// NetConfig holds network rules or "allow" to skip network restriction.
type NetConfig struct {
	Allow bool      // true = unrestricted network
	Rules []NetRule // per-port rules (used when Allow is false)
}

func (nc *NetConfig) UnmarshalJSON(data []byte) error {
	if string(data) == `"allow"` {
		nc.Allow = true
		return nil
	}
	return json.Unmarshal(data, &nc.Rules)
}

func (nc NetConfig) MarshalJSON() ([]byte, error) {
	if nc.Allow {
		return json.Marshal("allow")
	}
	if nc.Rules == nil {
		return []byte("null"), nil
	}
	return json.Marshal(nc.Rules)
}

// StringBag is a slice that unmarshals from either a single string or an array.
type StringBag []string

func (sb *StringBag) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '[' {
		var arr []string
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*sb = arr
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*sb = []string{s}
	return nil
}

func (sb StringBag) MarshalJSON() ([]byte, error) {
	if len(sb) == 1 {
		return json.Marshal(sb[0])
	}
	return json.Marshal([]string(sb))
}

// EnvEntry defines how to modify an environment variable.
type EnvEntry struct {
	Value   *string   // set mode: non-nil = set to this value
	Unset   bool      // unset mode
	Prepend StringBag // path op: prepend these
	Append  StringBag // path op: append these
	Remove  StringBag // path op: remove these (exact match)
	Sep     string    // path op: separator (default ":")
}

func (e *EnvEntry) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		e.Unset = true
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		e.Value = &s
		return nil
	}
	var obj struct {
		Prepend StringBag `json:"prepend"`
		Append  StringBag `json:"append"`
		Remove  StringBag `json:"remove"`
		Sep     string    `json:"sep"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("env entry must be string, null, or {prepend,append,remove,sep}: %w", err)
	}
	e.Prepend = obj.Prepend
	e.Append = obj.Append
	e.Remove = obj.Remove
	e.Sep = obj.Sep
	if e.Sep == "" {
		e.Sep = ":"
	}
	return nil
}

func (e *EnvEntry) IsPathOp() bool {
	return len(e.Prepend) > 0 || len(e.Append) > 0 || len(e.Remove) > 0
}

// FSRule defines access to a filesystem path.
type FSRule struct {
	Path          string `json:"path"`
	Access        string `json:"access"`
	Refer         bool   `json:"refer,omitempty"`
	IoctlDev      bool   `json:"ioctl_dev,omitempty"`
	IgnoreMissing bool   `json:"ignore_missing,omitempty"`
	CreateDir     string `json:"create_dir,omitempty"`
	Comment       string `json:"comment,omitempty"`
}

// NetRule defines access to a TCP port.
type NetRule struct {
	Port    uint16 `json:"port"`
	Access  string `json:"access"`
	Comment string `json:"comment,omitempty"`
}

// IPCConfig controls domain-wide IPC isolation.
type IPCConfig struct {
	AbstractUnix string `json:"abstract_unix,omitempty"`
	Signal       string `json:"signal,omitempty"`
}

// Load reads and parses a policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy: %w", err)
	}
	return Parse(data)
}

// Parse parses policy JSON bytes.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks the policy for structural errors.
func (p *Policy) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("policy: name is required")
	}
	for i, r := range p.FS {
		if err := r.validate(); err != nil {
			return fmt.Errorf("fs rule %d: %w", i, err)
		}
	}
	for i, r := range p.Net.Rules {
		if err := r.validate(); err != nil {
			return fmt.Errorf("net rule %d: %w", i, err)
		}
	}
	if p.IPC != nil {
		if err := p.IPC.validate(); err != nil {
			return fmt.Errorf("ipc: %w", err)
		}
	}
	for name := range p.Env {
		if name == "" {
			return fmt.Errorf("env: empty variable name")
		}
	}
	return nil
}

const validAccessChars = "rwxcdu"

func (r *FSRule) validate() error {
	if r.Path == "" {
		return fmt.Errorf("path is required")
	}
	if r.Access == "" {
		return fmt.Errorf("access is required")
	}
	for _, ch := range r.Access {
		if !strings.ContainsRune(validAccessChars, ch) {
			return fmt.Errorf("invalid access flag %q (valid: %s)", string(ch), validAccessChars)
		}
	}
	if r.CreateDir != "" && r.IgnoreMissing {
		return fmt.Errorf("create_dir and ignore_missing are mutually exclusive")
	}
	if r.CreateDir != "" {
		if _, err := parseOctalMode(r.CreateDir); err != nil {
			return fmt.Errorf("invalid create_dir mode %q: %w", r.CreateDir, err)
		}
	}
	return nil
}

var validNetAccess = map[string]bool{
	"connect":      true,
	"bind":         true,
	"connect+bind": true,
}

func (r *NetRule) validate() error {
	if r.Access == "" {
		return fmt.Errorf("access is required")
	}
	if !validNetAccess[r.Access] {
		return fmt.Errorf("invalid access %q (valid: connect, bind, connect+bind)", r.Access)
	}
	return nil
}

var validIPCValues = map[string]bool{
	"":      true,
	"deny":  true,
	"allow": true,
}

func (c *IPCConfig) validate() error {
	if !validIPCValues[c.AbstractUnix] {
		return fmt.Errorf("abstract_unix: invalid value %q (valid: deny, allow, or omit)", c.AbstractUnix)
	}
	if !validIPCValues[c.Signal] {
		return fmt.Errorf("signal: invalid value %q (valid: deny, allow, or omit)", c.Signal)
	}
	return nil
}

func parseOctalMode(s string) (os.FileMode, error) {
	var mode uint32
	for _, ch := range s {
		if ch < '0' || ch > '7' {
			return 0, fmt.Errorf("not an octal digit: %c", ch)
		}
		mode = mode*8 + uint32(ch-'0')
	}
	if mode > 0o7777 {
		return 0, fmt.Errorf("mode too large")
	}
	return os.FileMode(mode), nil
}
