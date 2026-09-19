package krypticapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dev-kryptic/Kryptic.Encryption.Go/envelope"
	dyn "github.com/dev-kryptic/k8s-operator/internal/dynsecret"
)

type workBatch struct {
	OrgKeyId      string         `json:"orgKeyId"`
	WrappedOrgKey string         `json:"wrappedOrgKey"`
	Items         []dyn.WorkItem `json:"items"`
}

type leaseDTO struct {
	Id                string `json:"id"`
	Status            int    `json:"status"`
	HasMintedEnvelope bool   `json:"hasMintedEnvelope"`
}

type secretEnvelope struct {
	Key           string `json:"key"`
	DefinitionId  string `json:"definitionId"`
	EnvironmentId string `json:"environmentId"`
	Envelope      string `json:"envelope"`
}

// SyncDynamic mints (or reuses) a lease for each dynamic hint in the bundle.
// existing maps secret key -> lease id from the last reconcile.
func (c *Client) SyncDynamic(ctx context.Context, creds Credentials, projectID, environment string, existing map[string]string) (Bundle, map[string]string, error) {
	token, err := c.token(ctx, creds)
	if err != nil {
		return nil, nil, err
	}
	keys, bundle, err := c.bundleAndKeys(ctx, creds, token, projectID, environment)
	if err != nil {
		return nil, nil, err
	}
	orgKey, err := c.orgKey(creds, keys, bundle.WrappedOrgKey)
	if err != nil {
		return nil, nil, err
	}

	if err := c.applyOwnWork(ctx, creds, token, orgKey); err != nil {
		return nil, nil, err
	}

	out := Bundle{}
	leases := map[string]string{}
	for _, hint := range bundle.DynamicSecrets {
		id := existing[hint.Key]
		pairs, newID, err := c.ensureLease(ctx, creds, token, orgKey, projectID, environment, hint, id)
		if err != nil {
			return nil, nil, err
		}
		for key, value := range pairs {
			out[key] = value
		}
		if newID != "" {
			leases[hint.Key] = newID
		}
	}

	var stale []string
	for key, id := range existing {
		if leases[key] != id {
			stale = append(stale, id)
		}
	}
	if err := c.RevokeLeases(ctx, creds, stale); err != nil {
		return nil, nil, err
	}
	return out, leases, nil
}

func (c *Client) RevokeLeases(ctx context.Context, creds Credentials, leaseIDs []string) error {
	if len(leaseIDs) == 0 {
		return nil
	}
	token, err := c.token(ctx, creds)
	if err != nil {
		return err
	}
	keys, err := c.machineKeys(ctx, creds, token)
	if err != nil {
		return err
	}
	for _, id := range leaseIDs {
		if strings.TrimSpace(id) == "" {
			continue
		}
		if err := c.revokeOne(ctx, creds, token, keys, id); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) ensureLease(ctx context.Context, creds Credentials, token string, orgKey []byte, projectID, environment string, hint dynamicHint, existingID string) (Bundle, string, error) {
	if existingID != "" {
		if pairs, ok := c.readMinted(ctx, creds, token, orgKey, existingID); ok {
			return pairs, existingID, nil
		}
	}

	var lease leaseDTO
	query := fmt.Sprintf("projectPublicId=%s&environment=%s&key=%s", urlQuery(projectID), urlQuery(environment), urlQuery(hint.Key))
	if err := c.do(ctx, creds, token, http.MethodPost, "/api/dynamic-secrets/leases?"+query, map[string]string{}, &lease); err != nil {
		return nil, "", fmt.Errorf("request lease %s: %w", hint.Key, err)
	}
	if err := c.applyLeaseWork(ctx, creds, token, orgKey, lease.Id); err != nil {
		return nil, "", fmt.Errorf("mint %s: %w", hint.Key, err)
	}
	pairs, ok := c.readMinted(ctx, creds, token, orgKey, lease.Id)
	if !ok {
		return nil, "", fmt.Errorf("mint %s: envelope missing after complete", hint.Key)
	}
	return pairs, lease.Id, nil
}

func (c *Client) applyOwnWork(ctx context.Context, creds Credentials, token string, orgKey []byte) error {
	var batch workBatch
	if err := c.do(ctx, creds, token, http.MethodGet, "/api/dynamic-secrets/work", nil, &batch); err != nil {
		return err
	}
	for _, item := range batch.Items {
		if err := c.applyItem(ctx, creds, token, orgKey, batch.OrgKeyId, item); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) applyLeaseWork(ctx context.Context, creds Credentials, token string, orgKey []byte, leaseID string) error {
	var batch workBatch
	if err := c.do(ctx, creds, token, http.MethodGet, "/api/dynamic-secrets/leases/"+leaseID+"/work", nil, &batch); err != nil {
		return err
	}
	if len(batch.Items) == 0 {
		return fmt.Errorf("no work for lease %s", leaseID)
	}
	return c.applyItem(ctx, creds, token, orgKey, batch.OrgKeyId, batch.Items[0])
}

func (c *Client) applyItem(ctx context.Context, creds Credentials, token string, orgKey []byte, orgKeyId string, item dyn.WorkItem) error {
	return dyn.Apply(ctx, orgKey, orgKeyId, item, func(body dyn.CompleteLease) error {
		return c.do(ctx, creds, token, http.MethodPost, "/api/dynamic-secrets/work/complete", body, nil)
	})
}

func (c *Client) revokeOne(ctx context.Context, creds Credentials, token string, keys machineKeys, leaseID string) error {
	if err := c.do(ctx, creds, token, http.MethodPost, "/api/dynamic-secrets/leases/"+leaseID+"/revoke", map[string]string{}, nil); err != nil {
		return err
	}
	var batch workBatch
	err := c.do(ctx, creds, token, http.MethodGet, "/api/dynamic-secrets/leases/"+leaseID+"/work", nil, &batch)
	if err != nil {
		var apiError *APIError
		if ok := asAPIError(err, &apiError); ok && apiError.Status == http.StatusNotFound {
			return nil
		}
		return err
	}
	if len(batch.Items) == 0 {
		return nil
	}
	orgKey, err := c.orgKey(creds, keys, batch.WrappedOrgKey)
	if err != nil {
		return err
	}
	return c.applyItem(ctx, creds, token, orgKey, batch.OrgKeyId, batch.Items[0])
}

func (c *Client) readMinted(ctx context.Context, creds Credentials, token string, orgKey []byte, leaseID string) (Bundle, bool) {
	var env secretEnvelope
	if err := c.do(ctx, creds, token, http.MethodGet, "/api/dynamic-secrets/leases/"+leaseID+"/envelope", nil, &env); err != nil {
		return nil, false
	}
	associated := envelope.SecretContext(env.DefinitionId, env.EnvironmentId)
	plaintext, err := envelope.Open(orgKey, env.Envelope, associated)
	if err != nil {
		return nil, false
	}
	var minted dyn.Minted
	if err := json.Unmarshal(plaintext, &minted); err != nil {
		return nil, false
	}
	out := Bundle{}
	for _, pair := range expandMinted(env.Key, minted) {
		out[pair.key] = pair.value
	}
	return out, true
}

type kv struct{ key, value string }

func expandMinted(key string, minted dyn.Minted) []kv {
	pairs := []kv{
		{key + "_USERNAME", minted.Username},
		{key + "_PASSWORD", minted.Password},
	}
	if minted.SessionToken != "" {
		pairs = append(pairs, kv{key + "_SESSION_TOKEN", minted.SessionToken})
	}
	if minted.AccessKeyId != "" {
		pairs = append(pairs, kv{key + "_ACCESS_KEY_ID", minted.AccessKeyId})
	}
	if strings.TrimSpace(minted.URL) != "" {
		pairs = append(pairs, kv{key, minted.URL})
	}
	return pairs
}

func (c *Client) bundleAndKeys(ctx context.Context, creds Credentials, token, projectID, environment string) (machineKeys, cipherBundle, error) {
	keys, err := c.machineKeys(ctx, creds, token)
	if err != nil {
		return machineKeys{}, cipherBundle{}, err
	}
	var bundle cipherBundle
	path := "/api/secrets/bundle?projectPublicId=" + urlQuery(projectID) + "&environment=" + urlQuery(environment)
	if err := c.do(ctx, creds, token, http.MethodGet, path, nil, &bundle); err != nil {
		return machineKeys{}, cipherBundle{}, err
	}
	return keys, bundle, nil
}

func (c *Client) machineKeys(ctx context.Context, creds Credentials, token string) (machineKeys, error) {
	var keys machineKeys
	if err := c.do(ctx, creds, token, http.MethodGet, "/api/keys/me", nil, &keys); err != nil {
		return machineKeys{}, fmt.Errorf("fetching machine keys: %w", err)
	}
	return keys, nil
}

func (c *Client) orgKey(creds Credentials, keys machineKeys, wrapped string) ([]byte, error) {
	return c.openOrgKey(creds, keys, wrapped)
}

func urlQuery(value string) string {
	return url.QueryEscape(value)
}

func asAPIError(err error, target **APIError) bool {
	if err == nil {
		return false
	}
	e, ok := err.(*APIError)
	if !ok {
		return false
	}
	*target = e
	return true
}

func (c *Client) do(ctx context.Context, creds Credentials, token, method, path string, payload any, out any) error {
	base := strings.TrimSuffix(creds.BaseURL, "/")
	var body *bytes.Reader
	if payload != nil && method != http.MethodGet {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	} else {
		body = bytes.NewReader(nil)
	}
	request, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if payload != nil && method != http.MethodGet {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := c.HTTP.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusUnauthorized {
			c.invalidate(creds.ClientID)
		}
		c.logFailure(path, response.StatusCode, readBody(response))
		return &APIError{Status: response.StatusCode}
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(response.Body).Decode(out); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}
