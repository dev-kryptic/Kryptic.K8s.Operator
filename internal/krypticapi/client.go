// Package krypticapi is the operator's client for the Kryptic Pipelines BFF:
// exchange machine credentials for a short-lived token, pull the ciphertext
// bundle for one project + environment, and decrypt it locally. Secrets are
// end-to-end encrypted - the client secret unwraps the machine private key
// (Argon2id), the private key opens the org key sealed to this machine, and
// the org key decrypts each envelope. The platform serves ciphertext only.
package krypticapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dev-kryptic/Kryptic.Encryption.Go/envelope"
	"github.com/dev-kryptic/Kryptic.Encryption.Go/kdf"
	"github.com/dev-kryptic/Kryptic.Encryption.Go/sealedbox"
)

// DefaultBaseURL is the hosted Pipelines BFF. Self-hosted deployments override
// it per KrypticSecret via the credentials secret's apiUrl key.
const DefaultBaseURL = "https://pipelines.kryptic.dev"

// Credentials are a machine identity's client id and secret, read from the
// Kubernetes secret referenced by a KrypticSecret.
type Credentials struct {
	BaseURL      string
	ClientID     string
	ClientSecret string
}

// Bundle is one environment's secrets, decrypted locally by the operator.
type Bundle map[string]string

// Fetcher is the seam the reconciler depends on, so tests never need a server.
type Fetcher interface {
	Fetch(ctx context.Context, creds Credentials, projectID, environment string) (Bundle, error)
}

// Client implements Fetcher against the real API, caching tokens and derived
// unwrap keys per client id (Argon2id costs 64 MiB per derivation - once per
// credential is enough).
type Client struct {
	HTTP *http.Client

	mu        sync.Mutex
	tokens    map[string]cachedToken
	unwrapKey map[string][]byte // sha256(secret:salt) -> Argon2id(clientSecret)
}

type cachedToken struct {
	value     string
	expiresAt time.Time
}

func NewClient() *Client {
	return &Client{
		HTTP:      &http.Client{Timeout: 30 * time.Second},
		tokens:    map[string]cachedToken{},
		unwrapKey: map[string][]byte{},
	}
}

// machineKeys is the machine's own key record from GET /api/keys/me: the
// private key arrives wrapped by an Argon2id key derived from the client
// secret, so only a caller holding the secret can use it.
type machineKeys struct {
	PublicKey            string `json:"publicKey"`
	WrappedPrivateKey    string `json:"wrappedPrivateKey"`
	KdfSalt              string `json:"kdfSalt"`
	KdfParametersVersion int    `json:"kdfParametersVersion"`
}

// bundleEntry is one ciphertext envelope; the ids rebuild the associated data.
type bundleEntry struct {
	Key           string `json:"key"`
	Envelope      string `json:"envelope"`
	DefinitionId  string `json:"definitionId"`
	EnvironmentId string `json:"environmentId"`
}

// cipherBundle is the end-to-end encrypted response from GET /api/secrets/bundle:
// envelopes plus the org key sealed to this machine's public key.
type cipherBundle struct {
	OrgKeyId      string        `json:"orgKeyId"`
	WrappedOrgKey string        `json:"wrappedOrgKey"`
	Secrets       []bundleEntry `json:"secrets"`
}

// APIError carries the status code so the reconciler can distinguish
// "misconfigured" (401/403/404 - do not hammer) from transient failures.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("kryptic api: %d %s", e.Status, e.Message)
}

// Permanent reports whether retrying without a spec change is pointless.
func (e *APIError) Permanent() bool {
	return e.Status == http.StatusUnauthorized ||
		e.Status == http.StatusForbidden ||
		e.Status == http.StatusNotFound
}

func (c *Client) Fetch(ctx context.Context, creds Credentials, projectID, environment string) (Bundle, error) {
	token, err := c.token(ctx, creds)
	if err != nil {
		return nil, err
	}

	var keys machineKeys
	if err := c.get(ctx, creds, token, "/api/keys/me", &keys); err != nil {
		return nil, fmt.Errorf("fetching machine keys: %w", err)
	}

	var bundle cipherBundle
	path := fmt.Sprintf("/api/secrets/bundle?projectPublicId=%s&environment=%s", projectID, environment)
	if err := c.get(ctx, creds, token, path, &bundle); err != nil {
		return nil, err
	}

	return c.decrypt(creds, keys, bundle)
}

// decrypt runs the full local chain: clientSecret -Argon2id-> machine private
// key -sealed box-> org key -AES-GCM-> plaintext values.
func (c *Client) decrypt(creds Credentials, keys machineKeys, bundle cipherBundle) (Bundle, error) {
	unwrapKey, err := c.deriveUnwrapKey(creds, keys)
	if err != nil {
		return nil, err
	}

	privateKey, err := envelope.Open(unwrapKey, keys.WrappedPrivateKey, nil)
	if err != nil {
		return nil, fmt.Errorf("could not unwrap the machine private key - wrong client secret?")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(keys.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid machine public key encoding: %w", err)
	}

	box, err := sealedbox.Parse(bundle.WrappedOrgKey)
	if err != nil {
		return nil, fmt.Errorf("invalid wrapped org key: %w", err)
	}
	orgKey, err := sealedbox.Open(sealedbox.KeyPair{Public: publicKey, Private: privateKey}, box)
	if err != nil {
		return nil, fmt.Errorf("could not unwrap the org key - the machine grant may be stale, rotate the identity")
	}

	pairs := make(Bundle, len(bundle.Secrets))
	for _, entry := range bundle.Secrets {
		associatedData := envelope.SecretContext(entry.DefinitionId, entry.EnvironmentId)
		plaintext, err := envelope.Open(orgKey, entry.Envelope, associatedData)
		if err != nil {
			return nil, fmt.Errorf("decrypt %q: %w", entry.Key, err)
		}
		pairs[entry.Key] = string(plaintext)
	}
	return pairs, nil
}

// deriveUnwrapKey computes (or returns the cached) Argon2id key for this
// credential. The cache key hashes the secret and the salt, so both a rotated
// identity (fresh salt) and a corrected client secret derive fresh.
func (c *Client) deriveUnwrapKey(creds Credentials, keys machineKeys) ([]byte, error) {
	digest := sha256.Sum256([]byte(creds.ClientSecret + ":" + keys.KdfSalt))
	cacheKey := string(digest[:])

	c.mu.Lock()
	cached, ok := c.unwrapKey[cacheKey]
	c.mu.Unlock()
	if ok {
		return cached, nil
	}

	salt, err := base64.RawURLEncoding.DecodeString(keys.KdfSalt)
	if err != nil {
		return nil, fmt.Errorf("invalid KDF salt encoding: %w", err)
	}
	derived, err := kdf.ForVersion(keys.KdfParametersVersion, creds.ClientSecret, salt)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.unwrapKey[cacheKey] = derived
	c.mu.Unlock()
	return derived, nil
}

// get performs an authenticated GET against the Pipelines BFF.
func (c *Client) get(ctx context.Context, creds Credentials, token, path string, out any) error {
	base := strings.TrimSuffix(creds.BaseURL, "/")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)

	response, err := c.HTTP.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		// A revoked or rotated machine secret shows up here as 401; drop the
		// cached token so the next pass re-authenticates.
		if response.StatusCode == http.StatusUnauthorized {
			c.invalidate(creds.ClientID)
		}
		return &APIError{Status: response.StatusCode, Message: readMessage(response)}
	}

	if err := json.NewDecoder(response.Body).Decode(out); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}

func (c *Client) token(ctx context.Context, creds Credentials) (string, error) {
	c.mu.Lock()
	if cached, ok := c.tokens[creds.ClientID]; ok && time.Until(cached.expiresAt) > time.Minute {
		c.mu.Unlock()
		return cached.value, nil
	}
	c.mu.Unlock()

	payload, _ := json.Marshal(map[string]string{
		"clientId": creds.ClientID, "clientSecret": creds.ClientSecret,
	})

	base := strings.TrimSuffix(creds.BaseURL, "/")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/token", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := c.HTTP.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", &APIError{Status: response.StatusCode, Message: readMessage(response)}
	}

	var token struct {
		AccessToken      string `json:"accessToken"`
		ExpiresInSeconds int    `json:"expiresInSeconds"`
	}
	if err := json.NewDecoder(response.Body).Decode(&token); err != nil {
		return "", fmt.Errorf("decoding token: %w", err)
	}

	c.mu.Lock()
	c.tokens[creds.ClientID] = cachedToken{
		value:     token.AccessToken,
		expiresAt: time.Now().Add(time.Duration(token.ExpiresInSeconds) * time.Second),
	}
	c.mu.Unlock()

	return token.AccessToken, nil
}

func (c *Client) invalidate(clientID string) {
	c.mu.Lock()
	delete(c.tokens, clientID)
	c.mu.Unlock()
}

func readMessage(response *http.Response) string {
	buffer := make([]byte, 512)
	n, _ := response.Body.Read(buffer)
	return strings.TrimSpace(string(buffer[:n]))
}
