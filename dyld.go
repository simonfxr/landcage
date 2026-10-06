package main

import "github.com/simonfxr/landcage/policy"

// dyldVars are removed from the payload environment on Darwin unless the
// policy set that key itself.
var dyldVars = []string{
	"DYLD_INSERT_LIBRARIES",
	"DYLD_LIBRARY_PATH",
	"DYLD_FRAMEWORK_PATH",
	"DYLD_FALLBACK_LIBRARY_PATH",
	"DYLD_ROOT_PATH",
}

func scrubDYLD(pol *policy.Policy, env policy.Environ) {
	for _, key := range dyldVars {
		if _, set := pol.Env[key]; set {
			continue
		}
		delete(env, key)
	}
}
