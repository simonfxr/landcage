package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	landtemplate "github.com/simonfxr/landcage/internal/template"
)

// RenderTemplate renders Jinja-style policy template bytes using landcage's
// process-derived context. The context exposes directory/user built-ins at the
// top level (home, pwd, configDir, dataDir, cacheDir, stateDir, runtimeDir,
// tmpDir, uid, user) and the original environment as env.NAME / env["NAME"].
//
// When checkVars is true (for .j2 files), the var namespace is populated from
// opts.TemplateVars/OptionalTemplateVars and strict checking applies: all
// mentioned var.KEY must be provided, and all required vars must be mentioned.
func RenderTemplate(data []byte, opts *Options, checkVars bool) ([]byte, error) {
	if opts == nil {
		defaultOpts := DefaultOptions()
		opts = &defaultOpts
	}

	tpl, err := landtemplate.Parse(string(data))
	if err != nil {
		return nil, err
	}

	// Register built-in filesystem functions
	tpl.WithFunc("exists", builtinExists)
	tpl.WithFunc("is_dir", builtinIsDir)
	tpl.WithFunc("is_file", builtinIsFile)
	tpl.WithFunc("find_upward", builtinFindUpward)

	templateVars := make(map[string]any, len(opts.TemplateVars)+len(opts.OptionalTemplateVars))
	if checkVars {
		for k, v := range opts.OptionalTemplateVars {
			templateVars[k] = v
		}
		for k, v := range opts.TemplateVars {
			templateVars[k] = v
		}
		mentioned := tpl.ReferencedVarNames()
		if err := checkTemplateVarConstraints(mentioned, opts.TemplateVars, templateVars); err != nil {
			return nil, err
		}
	}

	env := make(map[string]any, len(opts.Env))
	for k, v := range opts.Env {
		env[k] = v
	}

	ctx := map[string]any{
		"home":       opts.Dirs.Home,
		"pwd":        opts.Dirs.Pwd,
		"configDir":  opts.Dirs.ConfigDir,
		"dataDir":    opts.Dirs.DataDir,
		"cacheDir":   opts.Dirs.CacheDir,
		"stateDir":   opts.Dirs.StateDir,
		"runtimeDir": opts.Dirs.RuntimeDir,
		"tmpDir":     opts.Dirs.TmpDir,
		"uid":        opts.UID,
		"user":       opts.User,
		"env":        env,
		"var":        templateVars,
	}

	var out strings.Builder
	if err := tpl.Execute(&out, ctx); err != nil {
		return nil, err
	}
	return []byte(out.String()), nil
}

func checkTemplateVarConstraints(mentioned map[string]struct{}, required map[string]string, provided map[string]any) error {
	var missing []string
	for name := range mentioned {
		if _, ok := provided[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("missing template var(s): %s", strings.Join(missing, ", "))
	}

	var unused []string
	for name := range required {
		if _, ok := mentioned[name]; !ok {
			unused = append(unused, name)
		}
	}
	if len(unused) > 0 {
		sort.Strings(unused)
		return fmt.Errorf("unused required template var(s): %s", strings.Join(unused, ", "))
	}
	return nil
}

// Built-in template functions

// exists(path) returns true if the path exists.
func builtinExists(args []any) (any, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("exists() requires exactly 1 argument")
	}
	path, ok := args[0].(string)
	if !ok {
		return false, nil
	}
	_, err := os.Lstat(path)
	return err == nil, nil
}

// is_dir(path) returns true if the path exists and is a directory.
func builtinIsDir(args []any) (any, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("is_dir() requires exactly 1 argument")
	}
	path, ok := args[0].(string)
	if !ok {
		return false, nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return false, nil
	}
	return fi.IsDir(), nil
}

// is_file(path) returns true if the path exists and is a regular file.
func builtinIsFile(args []any) (any, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("is_file() requires exactly 1 argument")
	}
	path, ok := args[0].(string)
	if !ok {
		return false, nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return false, nil
	}
	return fi.Mode().IsRegular(), nil
}

// find_upward(start, marker1, marker2, ...) walks up from start looking for a
// directory containing any of the marker paths. Returns the directory path or
// nil if not found.
func builtinFindUpward(args []any) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("find_upward() requires at least 2 arguments (start, marker...)")
	}
	start, ok := args[0].(string)
	if !ok {
		return nil, nil
	}
	var markers []string
	for _, a := range args[1:] {
		s, ok := a.(string)
		if !ok {
			return nil, fmt.Errorf("find_upward() marker arguments must be strings")
		}
		markers = append(markers, s)
	}

	dir := filepath.Clean(start)
	for {
		for _, marker := range markers {
			_, err := os.Lstat(filepath.Join(dir, marker))
			if err == nil {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return nil, nil
}
