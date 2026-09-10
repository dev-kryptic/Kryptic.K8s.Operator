package controller

import (
	"os"
	"strings"

	"github.com/dev-kryptic/k8s-operator/internal/krypticapi"
)

const (
	EnvClientID          = "KRYPTIC_CLIENT_ID"
	EnvClientSecret      = "KRYPTIC_CLIENT_SECRET"
	EnvAPIURL            = "KRYPTIC_API_URL"
	EnvClusterNamespaces = "KRYPTIC_CLUSTER_NAMESPACES"
)

// ClusterCredentials is an optional operator-wide machine identity. When
// configured, a KrypticSecret may omit spec.auth. A Secret referenced by
// spec.auth.secretRef always wins and is never silently replaced by this.
// Intended for non-production clusters. Prefer per-namespace credentials
// in production so each app rotates and revokes on its own.
type ClusterCredentials struct {
	ClientID     string
	ClientSecret string
	BaseURL      string
	// Namespaces whose KrypticSecrets may omit spec.auth and use this
	// identity. "*" is an explicit allow-all; empty allows none.
	Namespaces []string
}

// Configured is true when both id and secret are present.
func (c ClusterCredentials) Configured() bool {
	return c.ClientID != "" && c.ClientSecret != ""
}

// AllowsNamespace reports whether a KrypticSecret in namespace may use the
// cluster identity. This is opt-in per namespace: anyone who can create a
// KrypticSecret in an allowed namespace can sync every project this identity
// decrypts into a Secret they control, so the operator admin must list
// namespaces explicitly in KRYPTIC_CLUSTER_NAMESPACES ("*" allows all).
func (c ClusterCredentials) AllowsNamespace(namespace string) bool {
	for _, allowed := range c.Namespaces {
		if allowed == "*" || allowed == namespace {
			return true
		}
	}
	return false
}

// Credentials maps to the API client, filling the hosted Pipelines URL when
// BaseURL is empty.
func (c ClusterCredentials) Credentials() krypticapi.Credentials {
	baseURL := c.BaseURL
	if baseURL == "" {
		baseURL = krypticapi.DefaultBaseURL
	}
	return krypticapi.Credentials{
		BaseURL:      baseURL,
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
	}
}

// ClusterCredentialsFromEnv reads the optional operator-wide identity.
func ClusterCredentialsFromEnv() ClusterCredentials {
	return ClusterCredentials{
		ClientID:     os.Getenv(EnvClientID),
		ClientSecret: os.Getenv(EnvClientSecret),
		BaseURL:      os.Getenv(EnvAPIURL),
		Namespaces:   splitList(os.Getenv(EnvClusterNamespaces)),
	}
}

// splitList parses a comma-separated env value, trimming blanks.
func splitList(raw string) []string {
	var entries []string
	for _, entry := range strings.Split(raw, ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			entries = append(entries, entry)
		}
	}
	return entries
}
