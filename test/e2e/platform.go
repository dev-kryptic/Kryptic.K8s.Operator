//go:build e2e

package e2e

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/dev-kryptic/Kryptic.Encryption.Go/envelope"
	"github.com/dev-kryptic/Kryptic.Encryption.Go/kdf"
	"github.com/dev-kryptic/Kryptic.Encryption.Go/sealedbox"
)

const (
	platformClientID     = "kmi_e2eoperator"
	platformClientSecret = "e2e-client-secret-value"
	platformOrgKeyID     = "org-key-e2e"
	platformEnvID        = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)

// fakePlatform is a Pipelines BFF stand-in that performs the real encryption
// ceremony. The operator talks to it the same way it talks to the hosted API.
type fakePlatform struct {
	server *httptest.Server

	mu      sync.Mutex
	secrets map[string]string
	down    bool

	publicKey         string
	wrappedPrivateKey string
	kdfSalt           string
	wrappedOrgKey     string
	orgKey            []byte
	definitionIDs     map[string]string
}

func startFakePlatform() (*fakePlatform, error) {
	enc := base64.RawURLEncoding

	machine, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	salt, err := kdf.GenerateSalt()
	if err != nil {
		return nil, err
	}
	unwrapKey, err := kdf.ForVersion(1, platformClientSecret, salt)
	if err != nil {
		return nil, err
	}
	wrappedPrivateKey, err := envelope.Seal(unwrapKey, "machinesecret_v1", machine.Bytes(), nil)
	if err != nil {
		return nil, err
	}

	orgKey := make([]byte, 32)
	if _, err := rand.Read(orgKey); err != nil {
		return nil, err
	}
	grant, err := sealedbox.Seal(machine.PublicKey().Bytes(), platformOrgKeyID, orgKey)
	if err != nil {
		return nil, err
	}

	platform := &fakePlatform{
		secrets: map[string]string{
			"DATABASE_URL":  "postgres://qa/app",
			"REDIS_URL":     "redis://qa-cache",
			"OPERATOR_MARK": "keep-me",
		},
		publicKey:         enc.EncodeToString(machine.PublicKey().Bytes()),
		wrappedPrivateKey: wrappedPrivateKey,
		kdfSalt:           enc.EncodeToString(salt),
		wrappedOrgKey:     grant.Serialize(),
		orgKey:            orgKey,
		definitionIDs: map[string]string{
			"DATABASE_URL":  "11111111-2222-3333-4444-555555555555",
			"REDIS_URL":     "11111111-2222-3333-4444-555555555556",
			"OPERATOR_MARK": "11111111-2222-3333-4444-555555555557",
		},
	}
	platform.server = httptest.NewServer(http.HandlerFunc(platform.serve))
	return platform, nil
}

func (p *fakePlatform) URL() string { return p.server.URL }

func (p *fakePlatform) Close() { p.server.Close() }

func (p *fakePlatform) SetSecret(key, value string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.secrets[key] = value
	if _, ok := p.definitionIDs[key]; !ok {
		p.definitionIDs[key] = "11111111-2222-3333-4444-555555555558"
	}
}

func (p *fakePlatform) DeleteSecret(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.secrets, key)
}

func (p *fakePlatform) SetDown(down bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.down = down
}

func (p *fakePlatform) serve(writer http.ResponseWriter, request *http.Request) {
	p.mu.Lock()
	down := p.down
	p.mu.Unlock()
	if down {
		http.Error(writer, "platform unavailable", http.StatusBadGateway)
		return
	}

	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/api/token":
		p.serveToken(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == "/api/keys/me":
		if !p.authorized(request) {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		p.serveKeys(writer)
	case request.Method == http.MethodGet && request.URL.Path == "/api/secrets/bundle":
		if !p.authorized(request) {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		p.serveBundle(writer)
	default:
		http.NotFound(writer, request)
	}
}

func (p *fakePlatform) serveToken(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		http.Error(writer, "bad json", http.StatusBadRequest)
		return
	}
	if body.ClientID != platformClientID || body.ClientSecret != platformClientSecret {
		http.Error(writer, "invalid credentials", http.StatusUnauthorized)
		return
	}
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"accessToken":      "e2e-token",
		"expiresInSeconds": 900,
	})
}

func (p *fakePlatform) authorized(request *http.Request) bool {
	return strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ")
}

func (p *fakePlatform) serveKeys(writer http.ResponseWriter) {
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"publicKey":            p.publicKey,
		"wrappedPrivateKey":    p.wrappedPrivateKey,
		"kdfSalt":              p.kdfSalt,
		"kdfParametersVersion": 1,
	})
}

func (p *fakePlatform) serveBundle(writer http.ResponseWriter) {
	p.mu.Lock()
	defer p.mu.Unlock()

	type entry struct {
		Key           string `json:"key"`
		Envelope      string `json:"envelope"`
		DefinitionId  string `json:"definitionId"`
		EnvironmentId string `json:"environmentId"`
	}
	secrets := make([]entry, 0, len(p.secrets))
	for key, value := range p.secrets {
		definitionID := p.definitionIDs[key]
		sealed, err := envelope.Seal(
			p.orgKey, platformOrgKeyID, []byte(value),
			envelope.SecretContext(definitionID, platformEnvID),
		)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		secrets = append(secrets, entry{
			Key:           key,
			Envelope:      sealed,
			DefinitionId:  definitionID,
			EnvironmentId: platformEnvID,
		})
	}
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"orgKeyId":      platformOrgKeyID,
		"wrappedOrgKey": p.wrappedOrgKey,
		"secrets":       secrets,
	})
}
