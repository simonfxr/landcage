package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// sbplPreamble is applied to every generated profile. Seatbelt cannot hide
// host processes, so signals stay limited to this sandbox instead of a bare
// (allow signal), which would reach the host. v1 does not allow sysmond.
// dyld shared-cache startup needs data access to the root directory itself;
// realpath also needs its metadata. Neither literal grant covers descendants.
// The linker needs hw.pagesize_compat; do not grant unrestricted sysctl reads.
const sbplPreamble = `(version 1)
(deny default)
(allow process-fork)
(allow system-socket (socket-domain AF_UNIX))
(allow signal (target same-sandbox))
(allow process-info* (target same-sandbox))
(allow file-read-data file-read-metadata (literal "/"))
(allow sysctl-read (sysctl-name "hw.pagesize_compat"))
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
// key, value, key, value, …. Paths are parameters, never
// scheme literals. CompileSBPL does not create directories; the Darwin
// enforce path calls CreatePolicyDirs first.
//
// Like Landlock, final-component globs are resolved at setup time. Each
// matched directory grants access to its subtree, including future children.
// Unlike Landlock's inode rules, Seatbelt rules still follow pathnames:
// replacing a matched file or directory does not revoke its grant.
//
// Bind on port 0 is also wider than Landlock. Seatbelt has no "ephemeral
// only" port, so a bind of port 0 allows every local port ("*:*").
func CompileSBPL(p *Policy) (string, []string, error) {
	g := &sbplGen{aliases: make(map[string]bool)}
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
	b       strings.Builder
	params  []string
	pathN   int
	aliases map[string]bool
}

func (g *sbplGen) addPath(value string) string {
	name := fmt.Sprintf("p%d", g.pathN)
	g.pathN++
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
	paths, err := resolvePath(r.Path)
	if err != nil {
		if r.IgnoreMissing && isPathError(err) {
			return nil
		}
		return err
	}
	if len(paths) == 0 && !r.IgnoreMissing {
		return fmt.Errorf("glob matched no paths: %s", r.Path)
	}
	for _, path := range paths {
		if err := g.compilePath(r, path); err != nil {
			return err
		}
	}
	return nil
}

func (g *sbplGen) compilePath(r *FSRule, path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		if r.IgnoreMissing && isPathError(err) {
			return nil
		}
		return err
	}
	if err := fsRuleError(r, fi.IsDir()); err != nil {
		return fmt.Errorf("path %s: %w", path, err)
	}
	canonical, err := canonicalSBPLPath(path)
	if err != nil {
		return err
	}
	param := g.addPath(canonical)
	kind := "literal"
	if fi.IsDir() {
		kind = "subpath"
	}
	g.allow(fsOps(r, fi.IsDir()), fmt.Sprintf("(%s (param %q))", kind, param))
	g.allowUnix(r, param, fi.IsDir())
	return g.allowPathAliases(path)
}

// Seatbelt checks symlink metadata while resolving an aliased pathname, before
// checking the operation on its canonical target. Permit only those symlinks,
// not metadata or data reads of their parents or siblings. Follow link targets
// too, since one alias can resolve through another. canonicalSBPLPath has
// already rejected dangling links and loops before this is called.
func (g *sbplGen) allowPathAliases(path string) error {
	if !filepath.IsAbs(path) {
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		path = dir + "/" + path
	}
	// Do not Clean before walking: link/.. must resolve link before "..".
	prefix := "/"
	for _, part := range strings.Split(path, "/") {
		if part == "" {
			continue
		}
		parent := prefix
		candidate := parent + part
		prefix = candidate + "/"
		fi, err := os.Lstat(candidate)
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			continue
		}
		parent, err = canonicalSBPLPath(parent)
		if err != nil {
			return err
		}
		alias := filepath.Join(parent, part)
		if g.aliases[alias] {
			continue
		}
		g.aliases[alias] = true
		target, err := os.Readlink(alias)
		if err != nil {
			return err
		}
		if !filepath.IsAbs(target) {
			target = parent + "/" + target
		}
		param := g.addPath(alias)
		g.allow([]string{"file-read-metadata"}, fmt.Sprintf("(literal (param %q))", param))
		if err := g.allowPathAliases(target); err != nil {
			return err
		}
	}
	return nil
}

func (g *sbplGen) allowUnix(r *FSRule, param string, isDir bool) {
	// Never add file-data rights for 'u': a socket path can be replaced by
	// an ordinary file, and directory grants can contain both file types.
	filter := "path-literal"
	if isDir {
		filter = "subpath"
	}
	if strings.ContainsRune(r.Access, 'u') {
		g.allow([]string{"network-outbound"}, fmt.Sprintf("(remote unix-socket (%s (param %q)))", filter, param))
	}
	// Landlock's directory 'c' includes MAKE_SOCK. Seatbelt additionally
	// checks bind/accept independently from creating the filesystem entry.
	if isDir && strings.ContainsRune(r.Access, 'c') {
		g.allow([]string{"network-bind", "network-inbound"}, fmt.Sprintf("(local unix-socket (%s (param %q)))", filter, param))
	}
}

// fsOps lists Seatbelt path-scoped operations for r. refer has no Seatbelt right;
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
		add("process-exec")
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

func (g *sbplGen) compileNet(net *NetConfig) {
	if net == nil {
		return
	}
	if net.Allow || len(net.Rules) > 0 {
		g.allow([]string{"system-socket"}, "(socket-domain AF_INET) (socket-domain AF_INET6)")
	}
	if net.Allow {
		// Network policy controls IP traffic, not filesystem UNIX sockets.
		// A bare network* would bypass the separate 'u' and 'c' grants.
		g.allow([]string{"network-outbound"}, `(remote ip "*:*")`)
		g.allow([]string{"network-bind", "network-inbound"}, `(local ip "*:*")`)
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
