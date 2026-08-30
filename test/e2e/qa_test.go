//go:build e2e

package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dev-kryptic/k8s-operator/internal/controller"
)

// TestQASection17
// section 17: the operator against a real API server and a real decrypt chain.
func TestQASection17(t *testing.T) {
	h := setup(t)
	const ns = "e2e-kryptic-qa"
	h.ns(ns)
	h.credentials(ns, "kryptic-machine-credentials", platformClientID, platformClientSecret)
	h.startOperator("")

	t.Run("17.1_install_crd", func(t *testing.T) {
		_, err := h.dyn.Resource(crdGVR).Get(context.Background(), "krypticsecrets.kryptic.dev", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("CRD missing: %v", err)
		}
	})

	t.Run("17.2_invalid_project_id", func(t *testing.T) {
		err := h.applyCRRaw(ns, "invalid-project", map[string]any{
			"projectId":   "not-valid",
			"environment": "development",
			"auth":        map[string]any{"secretRef": map[string]any{"name": "kryptic-machine-credentials"}},
		})
		if err == nil || !strings.Contains(err.Error(), "proj_") {
			t.Fatalf("expected schema rejection, got %v", err)
		}
	})

	t.Run("17.3_missing_auth", func(t *testing.T) {
		err := h.applyCRRaw(ns, "missing-auth", map[string]any{
			"projectId":   "proj_e2e000000001",
			"environment": "development",
		})
		if err != nil {
			t.Fatalf("auth is optional; schema rejected the CR: %v", err)
		}
		h.waitReady(ns, "missing-auth", metav1.ConditionFalse, controller.ReasonAuthSecret)
	})

	t.Run("17.4_sync", func(t *testing.T) {
		h.applyCR(h.cr(ns, "backend-secrets", "backend-env", nil))
		h.waitReady(ns, "backend-secrets", metav1.ConditionTrue, controller.ReasonSynced)
		data := h.secretData(ns, "backend-env")
		if data["DATABASE_URL"] != "postgres://qa/app" || data["REDIS_URL"] != "redis://qa-cache" || data["OPERATOR_MARK"] != "keep-me" {
			t.Fatalf("synced keys mismatch: %v", keysOf(data))
		}
	})

	t.Run("17.5_consume_envfrom", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "qa-consumer", Namespace: ns},
			Spec: corev1.PodSpec{
				RestartPolicy: corev1.RestartPolicyNever,
				Containers: []corev1.Container{{
					Name:  "consumer",
					Image: "busybox:1.36",
					Command: []string{"sh", "-c",
						`test "$DATABASE_URL" = "postgres://qa/app" && test "$REDIS_URL" = "redis://qa-cache" && test "$OPERATOR_MARK" = "keep-me"`},
					EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: "backend-env"},
					}}},
				}},
			},
		}
		if _, err := h.kube.CoreV1().Pods(ns).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			got, err := h.kube.CoreV1().Pods(ns).Get(context.Background(), "qa-consumer", metav1.GetOptions{})
			if err == nil && got.Status.Phase == corev1.PodSucceeded {
				return
			}
			if err == nil && got.Status.Phase == corev1.PodFailed {
				t.Fatal("consumer pod failed: envFrom values did not match")
			}
			time.Sleep(time.Second)
		}
		t.Fatal("consumer pod did not succeed")
	})

	t.Run("17.13_key_filter", func(t *testing.T) {
		h.applyCR(h.cr(ns, "filtered-secrets", "filtered-env", []string{"DATABASE_URL"}))
		h.waitReady(ns, "filtered-secrets", metav1.ConditionTrue, controller.ReasonSynced)
		data := h.secretData(ns, "filtered-env")
		if len(data) != 1 || data["DATABASE_URL"] == "" || data["REDIS_URL"] != "" {
			t.Fatalf("filter leaked keys: %v", keysOf(data))
		}
	})

	t.Run("17.14_status_columns", func(t *testing.T) {
		obj, err := h.dyn.Resource(controller.KrypticSecretGVR).Namespace(ns).
			Get(context.Background(), "backend-secrets", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		project, _, _ := unstructuredString(obj.Object, "spec", "projectId")
		env, _, _ := unstructuredString(obj.Object, "spec", "environment")
		count, _, _ := unstructuredInt(obj.Object, "status", "syncedKeyCount")
		status, reason := h.ready(ns, "backend-secrets")
		if project != "proj_e2e000000001" || env != "development" || count < 1 || status != "True" || reason != controller.ReasonSynced {
			t.Fatalf("columns: project=%s env=%s keys=%d ready=%s/%s", project, env, count, status, reason)
		}
	})

	t.Run("17.15_self_hosted_api_url", func(t *testing.T) {
		// Sync already used apiUrl on the credentials Secret. If that were ignored
		// the operator would have called pipelines.kryptic.dev and failed 17.4.
		if h.platform.URL() == "" {
			t.Fatal("fake platform URL empty")
		}
		status, _ := h.ready(ns, "backend-secrets")
		if status != "True" {
			t.Fatal("self-hosted apiUrl sync is not Ready")
		}
	})

	t.Run("17.6_refresh", func(t *testing.T) {
		h.platform.SetSecret("DATABASE_URL", "postgres://qa/app-refreshed")
		h.touchCR(ns, "backend-secrets")
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if h.secretData(ns, "backend-env")["DATABASE_URL"] == "postgres://qa/app-refreshed" {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatal("secret did not refresh")
	})

	t.Run("17.7_key_removal", func(t *testing.T) {
		h.platform.DeleteSecret("REDIS_URL")
		h.touchCR(ns, "backend-secrets")
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if _, present := h.secretData(ns, "backend-env")["REDIS_URL"]; !present {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatal("deleted key is still in the Secret")
	})

	t.Run("17.9_foreign_secret", func(t *testing.T) {
		_, err := h.kube.CoreV1().Secrets(ns).Create(context.Background(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "hand-managed-env", Namespace: ns},
			StringData: map[string]string{"HAND_MANAGED": "precious"},
		}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		h.applyCR(h.cr(ns, "foreign-secrets", "hand-managed-env", nil))
		h.waitReady(ns, "foreign-secrets", metav1.ConditionFalse, controller.ReasonSecretWriteFail)
		data := h.secretData(ns, "hand-managed-env")
		if data["HAND_MANAGED"] != "precious" || data["DATABASE_URL"] != "" {
			t.Fatal("operator overwrote a Secret it does not own")
		}
	})

	t.Run("17.10_bad_credentials", func(t *testing.T) {
		h.credentials(ns, "bad-credentials", "kmi_0000000000000000", "wrong-secret")
		cr := h.cr(ns, "bad-creds", "bad-creds-env", nil)
		cr.Spec.Auth.SecretRef.Name = "bad-credentials"
		h.applyCR(cr)
		h.waitReady(ns, "bad-creds", metav1.ConditionFalse, controller.ReasonPermanentError)
		if h.secretExists(ns, "bad-creds-env") {
			t.Fatal("secret created despite bad credentials")
		}
	})

	t.Run("17.11_platform_outage", func(t *testing.T) {
		before := h.secretData(ns, "backend-env")
		h.platform.SetDown(true)
		h.touchCR(ns, "backend-secrets")
		h.waitReady(ns, "backend-secrets", metav1.ConditionFalse, controller.ReasonFetchFailed)
		after := h.secretData(ns, "backend-env")
		if after["DATABASE_URL"] != before["DATABASE_URL"] || after["OPERATOR_MARK"] != before["OPERATOR_MARK"] {
			t.Fatal("outage emptied last-known-good values")
		}
	})

	t.Run("17.12_recovery", func(t *testing.T) {
		h.platform.SetDown(false)
		h.platform.SetSecret("OPERATOR_MARK", "recovered")
		h.touchCR(ns, "backend-secrets")
		h.waitReady(ns, "backend-secrets", metav1.ConditionTrue, controller.ReasonSynced)
		if h.secretData(ns, "backend-env")["OPERATOR_MARK"] != "recovered" {
			t.Fatal("did not sync after the platform came back")
		}
	})

	t.Run("17.8_garbage_collection", func(t *testing.T) {
		h.deleteCR(ns, "backend-secrets")
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if !h.secretExists(ns, "backend-env") {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatal("owned Secret was not garbage-collected")
	})

}

// Separate process-level manager so an all-namespaces operator from
// TestQASection17 cannot reconcile the ignored namespace.
func TestQASection17_WatchNamespace(t *testing.T) {
	h := setup(t)
	const watched, ignored = "e2e-kryptic-watched", "e2e-kryptic-ignored"
	h.ns(watched)
	h.ns(ignored)
	h.credentials(watched, "kryptic-machine-credentials", platformClientID, platformClientSecret)
	h.startOperator(watched)

	h.applyCR(h.cr(ignored, "other-ns-secrets", "other-ns-env", nil))
	time.Sleep(2 * time.Second)
	status, reason := h.ready(ignored, "other-ns-secrets")
	if status != "" || reason != "" {
		t.Fatalf("WATCH_NAMESPACE leaked into %s: Ready=%s/%s", ignored, status, reason)
	}
	if h.secretExists(ignored, "other-ns-env") {
		t.Fatal("WATCH_NAMESPACE created a Secret in an ignored namespace")
	}

	h.applyCR(h.cr(watched, "watched-secrets", "watched-env", []string{"DATABASE_URL"}))
	h.waitReady(watched, "watched-secrets", metav1.ConditionTrue, controller.ReasonSynced)
}

func TestQASection17_ClusterCredentials(t *testing.T) {
	h := setup(t)
	const ns = "e2e-kryptic-cluster-creds"
	h.ns(ns)
	h.startOperatorWith("", controller.ClusterCredentials{
		ClientID:     platformClientID,
		ClientSecret: platformClientSecret,
		BaseURL:      h.platform.URL(),
	})

	if err := h.applyCRRaw(ns, "cluster-auth-secrets", map[string]any{
		"projectId":       "proj_e2e000000001",
		"environment":     "development",
		"secretName":      "cluster-auth-env",
		"refreshInterval": "30s",
		"keys":            []string{"DATABASE_URL"},
	}); err != nil {
		t.Fatal(err)
	}
	h.waitReady(ns, "cluster-auth-secrets", metav1.ConditionTrue, controller.ReasonSynced)
	data := h.secretData(ns, "cluster-auth-env")
	if data["DATABASE_URL"] == "" || data["REDIS_URL"] != "" {
		t.Fatalf("cluster credentials sync mismatch: %v", keysOf(data))
	}
}

func unstructuredString(obj map[string]any, fields ...string) (string, bool, error) {
	cur := any(obj)
	for _, field := range fields {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false, nil
		}
		cur, ok = m[field]
		if !ok {
			return "", false, nil
		}
	}
	s, ok := cur.(string)
	return s, ok, nil
}

func unstructuredInt(obj map[string]any, fields ...string) (int64, bool, error) {
	cur := any(obj)
	for _, field := range fields {
		m, ok := cur.(map[string]any)
		if !ok {
			return 0, false, nil
		}
		cur, ok = m[field]
		if !ok {
			return 0, false, nil
		}
	}
	switch n := cur.(type) {
	case int64:
		return n, true, nil
	case float64:
		return int64(n), true, nil
	default:
		return 0, false, nil
	}
}
