package main

import (
	"strings"
	"testing"

	"github.com/simonfxr/landcage/policy"
)

func TestPayloadEnvWindowsScrubsPublicPolicyEnv(t *testing.T) {
	for _, name := range []string{
		"LANDCAGE_POLICY_JSON",
		"landcage_policy_json",
		"Landcage_Policy_Json",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "inherited-policy-canary")
			env, err := payloadEnv(&policy.Policy{})
			if err != nil {
				t.Fatal(err)
			}
			for key := range env {
				if strings.EqualFold(key, publicPolicyEnvKey) {
					t.Fatalf("public policy environment leaked as %q", key)
				}
			}
		})
	}
}

func TestPayloadEnvWindowsKeepsExplicitPublicPolicyEnv(t *testing.T) {
	t.Setenv("landcage_policy_json", "inherited-policy-canary")
	p, err := policy.Parse([]byte(`{"name":"test","env":{"LANDCAGE_POLICY_JSON":"explicit"}}`))
	if err != nil {
		t.Fatal(err)
	}
	env, err := payloadEnv(p)
	if err != nil {
		t.Fatal(err)
	}
	if env[publicPolicyEnvKey] != "explicit" {
		t.Fatalf("policy-set %s = %q, want explicit", publicPolicyEnvKey, env[publicPolicyEnvKey])
	}
}
