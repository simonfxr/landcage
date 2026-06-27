package policy

import (
	"maps"
	"os"
	"os/user"
)

// Environ is a map of environment variable names to values.
type Environ map[string]string

// ProcessEnv returns the current process environment as Environ.
func ProcessEnv() Environ {
	env := make(Environ)
	for _, kv := range os.Environ() {
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				env[kv[:i]] = kv[i+1:]
				break
			}
		}
	}
	return env
}

// ToSlice returns KEY=VALUE strings suitable for exec.
func (e Environ) ToSlice() []string {
	s := make([]string, 0, len(e))
	for k, v := range e {
		s = append(s, k+"="+v)
	}
	return s
}

// Clone returns a shallow copy.
func (e Environ) Clone() Environ {
	c := make(Environ, len(e))
	maps.Copy(c, e)
	return c
}

// Dirs holds resolved directory paths for policy expansion.
type Dirs struct {
	Home       string
	Pwd        string
	ConfigDir  string
	DataDir    string
	CacheDir   string
	StateDir   string
	RuntimeDir string
	TmpDir     string
}

// ResolveDirs computes standard directories from environment.
func ResolveDirs(env Environ) Dirs {
	home := env["HOME"]
	uid := ""
	if u, err := user.Current(); err == nil {
		uid = u.Uid
	}
	pwd, _ := os.Getwd()

	return Dirs{
		Home:       home,
		Pwd:        pwd,
		ConfigDir:  firstNonEmpty(env["XDG_CONFIG_HOME"], home+"/.config"),
		DataDir:    firstNonEmpty(env["XDG_DATA_HOME"], home+"/.local/share"),
		CacheDir:   firstNonEmpty(env["XDG_CACHE_HOME"], home+"/.cache"),
		StateDir:   firstNonEmpty(env["XDG_STATE_HOME"], home+"/.local/state"),
		RuntimeDir: firstNonEmpty(env["XDG_RUNTIME_DIR"], "/run/user/"+uid),
		TmpDir:     firstNonEmpty(env["TMPDIR"], "/tmp"),
	}
}

// Options configures policy expansion and enforcement.
type Options struct {
	Env                  Environ
	Dirs                 Dirs
	UID                  string
	User                 string
	TemplateVars         map[string]string
	OptionalTemplateVars map[string]string
}

// DefaultOptions creates Options from the current process environment.
func DefaultOptions() Options {
	env := ProcessEnv()
	uid := ""
	username := ""
	if u, err := user.Current(); err == nil {
		uid = u.Uid
		username = u.Username
	}
	return Options{
		Env:  env,
		Dirs: ResolveDirs(env),
		UID:  uid,
		User: username,
	}
}
