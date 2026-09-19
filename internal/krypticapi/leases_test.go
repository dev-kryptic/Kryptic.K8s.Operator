package krypticapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSyncDynamicSkipsWorkWhenBundleHasNoLeases(t *testing.T) {
	workHits := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/token":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"accessToken":      "tok",
				"expiresInSeconds": 900,
			})
		case request.Method == http.MethodGet && request.URL.Path == "/api/keys/me":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"publicKey":            "x",
				"wrappedPrivateKey":    "x",
				"kdfSalt":              "x",
				"kdfParametersVersion": 1,
			})
		case request.Method == http.MethodGet && request.URL.Path == "/api/secrets/bundle":
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"orgKeyId":       "org",
				"wrappedOrgKey":  "x",
				"secrets":        []any{},
				"dynamicSecrets": []any{},
			})
		case request.URL.Path == "/api/dynamic-secrets/work":
			workHits++
			http.NotFound(writer, request)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	client := NewClient()
	client.HTTP = server.Client()
	extra, leases, err := client.SyncDynamic(context.Background(), Credentials{
		BaseURL:      server.URL,
		ClientID:     "kmi_test",
		ClientSecret: "plain-secret",
	}, "proj_test", "production", nil)
	if err != nil {
		t.Fatalf("SyncDynamic: %v", err)
	}
	if len(extra) != 0 || len(leases) != 0 {
		t.Fatalf("expected empty result, got extra=%v leases=%v", extra, leases)
	}
	if workHits != 0 {
		t.Fatalf("GET /work should not run for a static bundle, hits=%d", workHits)
	}
}

func TestApplyOwnWorkTreatsMissingRouteAsEmpty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/dynamic-secrets/work" {
			http.NotFound(writer, request)
			return
		}
		http.NotFound(writer, request)
	}))
	t.Cleanup(server.Close)

	client := NewClient()
	client.HTTP = server.Client()
	err := client.applyOwnWork(context.Background(), Credentials{BaseURL: server.URL}, "tok", nil)
	if err != nil {
		t.Fatalf("applyOwnWork: %v", err)
	}
}
