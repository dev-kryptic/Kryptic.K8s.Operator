package controller

import (
	"os"

	"github.com/dev-kryptic/k8s-operator/internal/krypticapi"
)

const (
	EnvClientID     = "KRYPTIC_CLIENT_ID"
	EnvClientSecret = "KRYPTIC_CLIENT_SECRET"
	EnvAPIURL       = "KRYPTIC_API_URL"
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
}

// Configured is true when both id and secret are present.
func (c ClusterCredentials) Configured() bool {
	return c.ClientID != "" && c.ClientSecret != ""
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
	}
}
