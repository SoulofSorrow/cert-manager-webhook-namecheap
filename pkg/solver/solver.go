package solver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/yourusername/cert-manager-webhook-namecheap/pkg/namecheap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

type NamecheapSolver struct {
	client *kubernetes.Clientset
}

// solverConfig is the per-issuer configuration parsed from the ClusterIssuer
// webhook.config JSON. EnsureCAA is a pointer so the zero value ("not set")
// is distinguishable from explicit false.
type solverConfig struct {
	SecretName      string `json:"secretName"`
	SecretNamespace string `json:"secretNamespace"`

	// EnsureCAA: if nil or true, the webhook ensures CAA records for the
	// issuer exist before presenting the challenge. Default: enabled.
	EnsureCAA *bool  `json:"ensureCAA,omitempty"`
	CAAIssuer string `json:"caaIssuer,omitempty"` // defaults to "letsencrypt.org"
}

// ensureCAAEnabled returns true unless EnsureCAA is explicitly set to false.
func (c *solverConfig) ensureCAAEnabled() bool {
	if c.EnsureCAA == nil {
		return true
	}
	return *c.EnsureCAA
}

// caaIssuer returns the configured CA or the default "letsencrypt.org".
func (c *solverConfig) caaIssuer() string {
	if c.CAAIssuer == "" {
		return "letsencrypt.org"
	}
	return c.CAAIssuer
}

func New() *NamecheapSolver {
	return &NamecheapSolver{}
}

func (s *NamecheapSolver) Name() string {
	return "namecheap"
}

func (s *NamecheapSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("create kubernetes client: %w", err)
	}
	s.client = cl
	return nil
}

func (s *NamecheapSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("present: fqdn=%s zone=%s", ch.ResolvedFQDN, ch.ResolvedZone)

	nc, cfg, err := s.newClientFromChallenge(ch)
	if err != nil {
		return err
	}

	domain := strings.TrimSuffix(ch.ResolvedZone, ".")

	if cfg.ensureCAAEnabled() {
		ca := cfg.caaIssuer()
		klog.Infof("present: ensuring CAA records for %s on %s", ca, domain)
		if err := nc.EnsureCAARecords(domain, ca); err != nil {
			// Non-fatal: missing CAA does not block issuance when no CAA exists.
			// Log and continue to the TXT challenge.
			klog.Warningf("present: could not ensure CAA records: %v", err)
		}
	}

	subdomain := extractSubdomain(ch.ResolvedFQDN, ch.ResolvedZone)
	klog.Infof("present: adding TXT record name=%s domain=%s", subdomain, domain)

	if err := nc.AddTXTRecord(domain, subdomain, ch.Key); err != nil {
		return fmt.Errorf("add TXT record: %w", err)
	}
	klog.Infof("present: TXT record added successfully")
	return nil
}

func (s *NamecheapSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("cleanup: fqdn=%s zone=%s", ch.ResolvedFQDN, ch.ResolvedZone)

	nc, _, err := s.newClientFromChallenge(ch)
	if err != nil {
		return err
	}

	subdomain := extractSubdomain(ch.ResolvedFQDN, ch.ResolvedZone)
	domain := strings.TrimSuffix(ch.ResolvedZone, ".")

	klog.Infof("cleanup: removing TXT record name=%s domain=%s", subdomain, domain)
	if err := nc.RemoveTXTRecord(domain, subdomain, ch.Key); err != nil {
		return fmt.Errorf("remove TXT record: %w", err)
	}
	klog.Infof("cleanup: TXT record removed successfully")
	return nil
}

func (s *NamecheapSolver) newClientFromChallenge(ch *v1alpha1.ChallengeRequest) (*namecheap.Client, solverConfig, error) {
	// Defaults from environment
	apiUser := os.Getenv("NAMECHEAP_API_USER")
	apiKey := os.Getenv("NAMECHEAP_API_KEY")
	username := os.Getenv("NAMECHEAP_USERNAME")

	var cfg solverConfig

	if ch.Config != nil && len(ch.Config.Raw) > 0 {
		if err := json.Unmarshal(ch.Config.Raw, &cfg); err != nil {
			return nil, cfg, fmt.Errorf("parse solver config: %w", err)
		}

		if cfg.SecretName != "" {
			overrides, err := s.credsFromSecret(ch, cfg)
			if err != nil {
				return nil, cfg, err
			}
			if v, ok := overrides["apiUser"]; ok && v != "" {
				apiUser = v
			}
			if v, ok := overrides["apiKey"]; ok && v != "" {
				apiKey = v
			}
			if v, ok := overrides["username"]; ok && v != "" {
				username = v
			}
		}
	}

	if apiUser == "" || apiKey == "" {
		return nil, cfg, fmt.Errorf("namecheap credentials not configured: apiUser and apiKey are required")
	}
	if username == "" {
		username = apiUser
	}

	return namecheap.NewClient(apiUser, apiKey, username), cfg, nil
}

func (s *NamecheapSolver) credsFromSecret(ch *v1alpha1.ChallengeRequest, cfg solverConfig) (map[string]string, error) {
	if s.client == nil {
		return nil, fmt.Errorf("kubernetes client not initialized")
	}

	ns := cfg.SecretNamespace
	if ns == "" {
		ns = ch.ResourceNamespace
	}

	secret, err := s.client.CoreV1().Secrets(ns).Get(
		context.Background(),
		cfg.SecretName,
		metav1.GetOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("get secret %s/%s: %w", ns, cfg.SecretName, err)
	}

	result := make(map[string]string, len(secret.Data))
	for k, v := range secret.Data {
		result[k] = string(v)
	}
	return result, nil
}

// extractSubdomain returns the relative subdomain part of fqdn within zone.
// Example: fqdn="_acme-challenge.foo.example.com." zone="example.com." -> "_acme-challenge.foo"
func extractSubdomain(fqdn, zone string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	zone = strings.TrimSuffix(zone, ".")
	if fqdn == zone {
		return "@"
	}
	return strings.TrimSuffix(fqdn, "."+zone)
}
