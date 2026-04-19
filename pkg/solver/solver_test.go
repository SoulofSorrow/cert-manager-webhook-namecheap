package solver

import (
	"encoding/json"
	"testing"
)

func TestExtractSubdomain(t *testing.T) {
	cases := []struct {
		fqdn string
		zone string
		want string
	}{
		{
			fqdn: "_acme-challenge.example.com.",
			zone: "example.com.",
			want: "_acme-challenge",
		},
		{
			fqdn: "_acme-challenge.sub.example.com.",
			zone: "example.com.",
			want: "_acme-challenge.sub",
		},
		{
			fqdn: "_acme-challenge.groot.rocks.",
			zone: "groot.rocks.",
			want: "_acme-challenge",
		},
		{
			fqdn: "_acme-challenge.foo.groot.rocks.",
			zone: "groot.rocks.",
			want: "_acme-challenge.foo",
		},
		{
			// Apex — FQDN equals zone
			fqdn: "example.com.",
			zone: "example.com.",
			want: "@",
		},
	}

	for _, c := range cases {
		got := extractSubdomain(c.fqdn, c.zone)
		if got != c.want {
			t.Errorf("extractSubdomain(%q, %q) = %q, want %q", c.fqdn, c.zone, got, c.want)
		}
	}
}

func TestSolverConfig_EnsureCAAEnabled(t *testing.T) {
	truePtr := true
	falsePtr := false

	cases := []struct {
		name string
		cfg  solverConfig
		want bool
	}{
		{"default (nil pointer) should be enabled", solverConfig{}, true},
		{"explicit true", solverConfig{EnsureCAA: &truePtr}, true},
		{"explicit false", solverConfig{EnsureCAA: &falsePtr}, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.cfg.ensureCAAEnabled(); got != c.want {
				t.Errorf("ensureCAAEnabled() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestSolverConfig_CAAIssuer(t *testing.T) {
	cases := []struct {
		name string
		cfg  solverConfig
		want string
	}{
		{"empty defaults to letsencrypt.org", solverConfig{}, "letsencrypt.org"},
		{"explicit issuer", solverConfig{CAAIssuer: "sectigo.com"}, "sectigo.com"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.cfg.caaIssuer(); got != c.want {
				t.Errorf("caaIssuer() = %q, want %q", got, c.want)
			}
		})
	}
}

// TestJSONUnmarshalPreservesDefault verifies the critical bug fix:
// When the ClusterIssuer config JSON omits ensureCAA, the webhook must
// default to enabled. With a non-pointer bool, json.Unmarshal would set
// it to false (the zero value) even if the struct was initialized to true.
func TestJSONUnmarshalPreservesDefault(t *testing.T) {
	configJSON := `{"secretName":"namecheap-credentials","secretNamespace":"cert-manager"}`

	var cfg solverConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if cfg.EnsureCAA != nil {
		t.Errorf("EnsureCAA should be nil when not in JSON, got %v", *cfg.EnsureCAA)
	}
	if !cfg.ensureCAAEnabled() {
		t.Error("ensureCAAEnabled() must be true when field is absent from JSON")
	}
}

func TestJSONUnmarshalExplicitFalse(t *testing.T) {
	configJSON := `{"secretName":"x","ensureCAA":false}`

	var cfg solverConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if cfg.EnsureCAA == nil {
		t.Fatal("EnsureCAA should be non-nil when present in JSON")
	}
	if *cfg.EnsureCAA != false {
		t.Errorf("EnsureCAA should be false, got %v", *cfg.EnsureCAA)
	}
	if cfg.ensureCAAEnabled() {
		t.Error("ensureCAAEnabled() must be false when explicitly set to false")
	}
}

func TestJSONUnmarshalExplicitTrue(t *testing.T) {
	configJSON := `{"ensureCAA":true}`

	var cfg solverConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !cfg.ensureCAAEnabled() {
		t.Error("ensureCAAEnabled() must be true when explicitly set to true")
	}
}
