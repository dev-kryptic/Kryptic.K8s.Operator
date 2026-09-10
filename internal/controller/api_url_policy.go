package controller

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/dev-kryptic/k8s-operator/internal/krypticapi"
)

const (
	EnvAllowInsecureAPIURL = "KRYPTIC_ALLOW_INSECURE_API_URL"
	EnvAPIURLAllowlist     = "KRYPTIC_API_URL_ALLOWLIST"
)

// APIURLPolicy gates the apiUrl value read from user-supplied credential
// Secrets. Anyone who can write a Secret in a watched namespace controls that
// value, so an unchecked URL is a server-side request forgery primitive: the
// operator would send machine credentials to, and fetch responses from, an
// attacker-chosen server reachable from the cluster. https is required (http
// only behind an explicit dev switch) and the host must be the hosted default
// or on the operator's allowlist.
type APIURLPolicy struct {
	// AllowInsecure permits http:// apiUrl values. Dev only.
	AllowInsecure bool
	// AllowedHosts holds host[:port] entries as they appear in the URL.
	// Empty means only the DefaultBaseURL host is allowed.
	AllowedHosts []string
}

// APIURLPolicyFromEnv reads the operator-level policy.
func APIURLPolicyFromEnv() APIURLPolicy {
	return APIURLPolicy{
		AllowInsecure: os.Getenv(EnvAllowInsecureAPIURL) == "true",
		AllowedHosts:  splitList(os.Getenv(EnvAPIURLAllowlist)),
	}
}

// Validate returns nil when raw is an acceptable Pipelines BFF base URL.
func (p APIURLPolicy) Validate(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("invalid apiUrl %q", raw)
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !p.AllowInsecure {
			return fmt.Errorf(
				"apiUrl %q must use https (set %s=true on the operator to allow http for development)",
				raw, EnvAllowInsecureAPIURL)
		}
	default:
		return fmt.Errorf("apiUrl %q must use https", raw)
	}

	allowed := p.AllowedHosts
	if len(allowed) == 0 {
		defaultURL, err := url.Parse(krypticapi.DefaultBaseURL)
		if err != nil {
			return err
		}
		allowed = []string{defaultURL.Host}
	}
	for _, host := range allowed {
		if strings.EqualFold(parsed.Host, host) {
			return nil
		}
	}
	return fmt.Errorf("apiUrl host %q is not allowed: add it to %s on the operator",
		parsed.Host, EnvAPIURLAllowlist)
}
