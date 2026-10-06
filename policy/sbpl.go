package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// sbplPreamble is applied to every generated profile. Seatbelt cannot hide
// host processes, so signals stay limited to this sandbox instead of a bare
// (allow signal), which would reach the host. v1 does not allow sysmond.
const sbplPreamble = `(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
(allow signal (target same-sandbox))
(allow process-info* (target same-sandbox))
(allow file-ioctl (literal "/dev/null"))
(allow file-read* file-write-data (literal "/dev/null"))
(allow file-read* (literal "/dev/urandom"))
(allow file-read* (literal "/dev/random"))
(allow file-read* (literal "/dev/zero"))
(allow mach-lookup
  (global-name "com.apple.system.logger")
  (global-name "com.apple.system.opendirectoryd.libinfo"))
`

// CompileSBPL compiles p into a Seatbelt profile and a parameter list of
// key, value, key, value, …. Paths and glob regexes are parameters, never
// scheme literals. CompileSBPL does not create directories; the Darwin
// enforce path calls CreatePolicyDirs first.
//
// A final-component glob is emitted as an anchored regular expression, not
// as the paths that exist now. Landlock snapshots glob matches. Seatbelt
// evaluates the regex at access time, so a file created later still matches.
// That is wider than Landlock.
//
// Bind on port 0 is also wider than Landlock. Seatbelt has no "ephemeral
// only" port, so a bind of port 0 allows every local port ("*:*").
func CompileSBPL(p *Policy) (string, []string, error) {
	g := &sbplGen{}
	g.b.WriteString(sbplPreamble)

	for i := range p.FS {
		if err := g.compileFS(&p.FS[i]); err != nil {
			return "", nil, fmt.Errorf("fs rule %d (%s): %w", i, p.FS[i].Path, err)
		}
	}
	// macOS has no abstract UNIX sockets, so ipc.abstract_unix "deny" or
	// omitted is a no-op. "signal" allow, deny, and omitted all stay on the
	// preamble rule; granting (allow signal) would reach host processes.
	g.compileNet(&p.Net)
	return g.b.String(), g.params, nil
}

// CreatePolicyDirs creates directories requested by create_dir rules.
// It matches the mkdir step of buildFSRules and is not called by CompileSBPL.
func CreatePolicyDirs(p *Policy) error {
	for i, r := range p.FS {
		if r.CreateDir == "" {
			continue
		}
		mode, _ := parseOctalMode(r.CreateDir)
		if err := os.MkdirAll(r.Path, mode); err != nil {
			return fmt.Errorf("fs rule %d (%s): creating directory: %w", i, r.Path, err)
		}
	}
	return nil
}

type sbplGen struct {
	b      strings.Builder
	params []string
	pathN  int
	reN    int
}

func (g *sbplGen) addParam(prefix string, n *int, value string) string {
	name := fmt.Sprintf("%s%d", prefix, *n)
	*n++
	g.params = append(g.params, name, value)
	return name
}

func (g *sbplGen) allow(ops []string, filter string) {
	if len(ops) == 0 {
		return
	}
	g.b.WriteString("(allow ")
	g.b.WriteString(strings.Join(ops, " "))
	if filter != "" {
		g.b.WriteByte(' ')
		g.b.WriteString(filter)
	}
	g.b.WriteString(")\n")
}

func (g *sbplGen) compileFS(r *FSRule) error {
	if r.Path == "" {
		if r.IgnoreMissing {
			return nil
		}
		return fmt.Errorf("path is empty")
	}
	if hasGlobMeta(r.Path) {
		return g.compileGlob(r)
	}
	return g.compileLiteral(r)
}

func (g *sbplGen) compileLiteral(r *FSRule) error {
	fi, err := os.Stat(r.Path)
	if err != nil {
		if r.IgnoreMissing && isPathError(err) {
			return nil
		}
		return err
	}
	if err := fsRuleError(r, fi.IsDir()); err != nil {
		return fmt.Errorf("path %s: %w", r.Path, err)
	}
	path, err := canonicalSBPLPath(r.Path)
	if err != nil {
		return err
	}
	param := g.addParam("p", &g.pathN, path)
	kind := "literal"
	if fi.IsDir() {
		kind = "subpath"
	}
	g.allow(fsOps(r, fi.IsDir()), fmt.Sprintf("(%s (param %q))", kind, param))
	g.allowUnix(r, param, "literal")
	return nil
}

func (g *sbplGen) compileGlob(r *FSRule) error {
	paths, err := resolvePath(r.Path)
	if err != nil {
		if r.IgnoreMissing && isPathError(err) {
			return nil
		}
		return err
	}
	if len(paths) == 0 {
		if r.IgnoreMissing {
			return nil
		}
		return fmt.Errorf("glob matched no paths: %s", r.Path)
	}

	saw := false
	allDirs := true
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			if r.IgnoreMissing && os.IsNotExist(err) {
				continue
			}
			return err
		}
		saw = true
		if !fi.IsDir() {
			allDirs = false
		}
		if err := fsRuleError(r, fi.IsDir()); err != nil {
			return fmt.Errorf("path %s: %w", p, err)
		}
	}
	if !saw {
		return nil
	}

	re, err := globPathRegex(r.Path)
	if err != nil {
		return err
	}
	param := g.addParam("re", &g.reN, re)
	// The filter is the regex, not the paths that matched at compile time.
	g.allow(fsOps(r, allDirs), fmt.Sprintf("(regex (param %q))", param))
	// A glob is not a single socket path, so the unix-socket filter uses the
	// same regex parameter instead of path-literal.
	g.allowUnix(r, param, "regex")
	return nil
}

func (g *sbplGen) allowUnix(r *FSRule, param, kind string) {
	if !strings.ContainsRune(r.Access, 'u') {
		return
	}
	filter := "path-literal"
	fileKind := "literal"
	if kind == "regex" {
		filter = "regex"
		fileKind = "regex"
	}
	g.allow([]string{"network-outbound"}, fmt.Sprintf("(remote unix-socket (%s (param %q)))", filter, param))
	g.allow([]string{"file-read*", "file-write-data"}, fmt.Sprintf("(%s (param %q))", fileKind, param))
}

// fsOps lists Seatbelt file operations for r. refer has no Seatbelt right;
// c and d on two directories are enough to rename between them. u is emitted
// separately because its filter is a UNIX-socket address.
func fsOps(r *FSRule, isDir bool) []string {
	var ops []string
	seen := map[string]bool{}
	add := func(op string) {
		if !seen[op] {
			seen[op] = true
			ops = append(ops, op)
		}
	}
	if strings.ContainsRune(r.Access, 'r') {
		add("file-read*")
	}
	if strings.ContainsRune(r.Access, 'w') {
		add("file-write-data")
	}
	if strings.ContainsRune(r.Access, 'x') {
		add("file-map-executable")
		add("file-exec")
	}
	if isDir && strings.ContainsRune(r.Access, 'c') {
		add("file-write-create")
	}
	if isDir && strings.ContainsRune(r.Access, 'd') {
		add("file-write-unlink")
	}
	if r.IoctlDev {
		add("file-ioctl")
	}
	return ops
}

// canonicalSBPLPath resolves aliases such as macOS's /tmp -> /private/tmp.
// Seatbelt compares absolute, resolved paths, not the spelling in the policy.
func canonicalSBPLPath(path string) (string, error) {
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	return filepath.Abs(path)
}

// globPathRegex quotes the canonical directory, maps * to [^/]* and ? to
// [^/], and anchors the full path.
func globPathRegex(path string) (string, error) {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	dir, err := canonicalSBPLPath(dir)
	if err != nil {
		return "", err
	}
	if !strings.HasSuffix(dir, string(filepath.Separator)) {
		dir += string(filepath.Separator)
	}
	var b strings.Builder
	b.WriteByte('^')
	b.WriteString(regexp.QuoteMeta(dir))
	if err := writeGlobRegex(&b, base); err != nil {
		return "", err
	}
	b.WriteByte('$')
	return b.String(), nil
}

func writeGlobRegex(b *strings.Builder, pat string) error {
	// Validate even when the directory is empty; in particular, Go glob
	// classes and regexp classes have different rules for '-' and ']'.
	if _, err := filepath.Match(pat, ""); err != nil {
		return fmt.Errorf("bad glob pattern %q: %w", pat, err)
	}
	for i := 0; i < len(pat); i++ {
		switch pat[i] {
		case '*':
			b.WriteString(`[^/]*`)
		case '?':
			b.WriteString(`[^/]`)
		case '[':
			j, err := globClassEnd(pat, i)
			if err != nil {
				return err
			}
			class := globClassRegex(pat[i:j])
			if strings.HasPrefix(class, "[^") {
				// A negated glob class only sees directory entry names.
				// Its regex equivalent must not match a path separator.
				class = "[^/" + class[2:]
			}
			re, err := regexp.Compile(class)
			if err != nil {
				return fmt.Errorf("unsupported glob class %q: %w", class, err)
			}
			if re.MatchString("/") {
				return fmt.Errorf("glob class %q can match a path separator", class)
			}
			b.WriteString(class)
			i = j - 1
		case '\\':
			i++
			_, size := utf8.DecodeRuneInString(pat[i:])
			b.WriteString(regexp.QuoteMeta(pat[i : i+size]))
			i += size - 1
		default:
			b.WriteString(regexp.QuoteMeta(pat[i : i+1]))
		}
	}
	return nil
}

// Go globs treat \d, \n, etc. as literal letters, while regexes interpret
// them as character classes or control characters. Only retain escaping
// where it is needed for a literal inside a regex character class.
func globClassRegex(class string) string {
	var b strings.Builder
	for i := 0; i < len(class); i++ {
		if class[i] != '\\' {
			b.WriteByte(class[i])
			continue
		}
		i++
		_, size := utf8.DecodeRuneInString(class[i:])
		literal := class[i : i+size]
		if literal == "-" {
			b.WriteString(`\-`)
		} else {
			b.WriteString(regexp.QuoteMeta(literal))
		}
		i += size - 1
	}
	return b.String()
}

func globClassEnd(pat string, i int) (int, error) {
	j := i + 1
	if j < len(pat) && pat[j] == '^' {
		j++
	}
	for j < len(pat) && pat[j] != ']' {
		if pat[j] == '\\' {
			j++
		}
		j++
	}
	if j >= len(pat) {
		return 0, fmt.Errorf("bad glob pattern %q", pat)
	}
	return j + 1, nil
}

func (g *sbplGen) compileNet(net *NetConfig) {
	if net == nil {
		return
	}
	if net.Allow {
		g.b.WriteString("(allow network*)\n")
		return
	}
	for i := range net.Rules {
		g.compileNetRule(&net.Rules[i])
	}
}

func (g *sbplGen) compileNetRule(r *NetRule) {
	switch r.Access {
	case "connect":
		g.allowConnect(r)
	case "bind":
		g.allowBind(r)
	case "connect+bind":
		g.allowConnect(r)
		g.allowBind(r)
	}
}

func (g *sbplGen) allowConnect(r *NetRule) {
	if r.usesTCP() {
		g.allowPort("network-outbound", "remote", "tcp", r.Port, false)
	}
	if r.usesUDP() {
		g.allowPort("network-outbound", "remote", "udp", r.Port, false)
	}
}

func (g *sbplGen) allowBind(r *NetRule) {
	// Port 0 is broader than Landlock: Seatbelt has no ephemeral-only port.
	// Landlock's bind permission also lets the bound socket receive traffic.
	// Seatbelt checks inbound traffic separately from binding the socket.
	if r.usesTCP() {
		g.allowPort("network-bind", "local", "tcp", r.Port, r.Port == 0)
		g.allowPort("network-inbound", "local", "tcp", r.Port, r.Port == 0)
	}
	if r.usesUDP() {
		g.allowPort("network-bind", "local", "udp", r.Port, r.Port == 0)
		g.allowPort("network-inbound", "local", "udp", r.Port, r.Port == 0)
	}
}

func (g *sbplGen) allowPort(op, where, proto string, port uint16, anyPort bool) {
	spec := fmt.Sprintf("*:%d", port)
	if anyPort {
		spec = "*:*"
	}
	fmt.Fprintf(&g.b, "(allow %s (%s %s \"%s\"))\n", op, where, proto, spec)
}
