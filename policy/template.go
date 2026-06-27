package policy

import (
	"fmt"
	"sort"
	"strings"

	landtemplate "github.com/simonfxr/landcage/internal/template"
)

// RenderTemplate renders Jinja-style policy template bytes using landcage's
// process-derived context. The context exposes directory/user built-ins at the
// top level (home, pwd, configDir, dataDir, cacheDir, stateDir, runtimeDir,
// tmpDir, uid, user) and the original environment as env.NAME / env["NAME"].
func RenderTemplate(data []byte, opts *Options) ([]byte, error) {
	if opts == nil {
		defaultOpts := DefaultOptions()
		opts = &defaultOpts
	}

	tpl, err := landtemplate.Parse(string(data))
	if err != nil {
		return nil, err
	}

	mentioned := tpl.ReferencedVarNames()
	templateVars := make(map[string]any, len(opts.TemplateVars)+len(opts.OptionalTemplateVars))
	for k, v := range opts.OptionalTemplateVars {
		templateVars[k] = v
	}
	for k, v := range opts.TemplateVars {
		templateVars[k] = v
	}
	if err := checkTemplateVars(mentioned, opts.TemplateVars, templateVars); err != nil {
		return nil, err
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

func checkTemplateVars(mentioned map[string]struct{}, required map[string]string, provided map[string]any) error {
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
