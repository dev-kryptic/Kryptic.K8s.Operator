package controller

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/dev-kryptic/k8s-operator/internal/krypticapi"
)

type stubFetcher struct {
	bundle krypticapi.Bundle
	err    error

	gotCredentials krypticapi.Credentials
	gotProject     string
	gotEnvironment string
	calls          int
}

func (s *stubFetcher) Fetch(_ context.Context, creds krypticapi.Credentials, projectID, environment string) (krypticapi.Bundle, error) {
	s.calls++
	s.gotCredentials = creds
	s.gotProject = projectID
	s.gotEnvironment = environment
	return s.bundle, s.err
}

func newReconciler(t *testing.T, fetcher krypticapi.Fetcher, objects ...runtime.Object) (*Reconciler, *fake.Clientset) {
	t.Helper()

	kube := fake.NewSimpleClientset(objects...)
	return &Reconciler{
		Kube:    kube,
		Fetcher: fetcher,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, kube
}

func credentialsSecret(namespace, name string, extra map[string]string) *corev1.Secret {
	data := map[string][]byte{
		"clientId":     []byte("kmi_test"),
		"clientSecret": []byte("shhh"),
	}
	for key, value := range extra {
		data[key] = []byte(value)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Data:       data,
	}
}

func testCR() *KrypticSecret {
	return &KrypticSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend-secrets",
			Namespace: "default",
			UID:       "uid-1",
		},
		Spec: KrypticSecretSpec{
			ProjectID:   "proj_a1b2c3d4e5f6",
			Environment: "production",
			SecretName:  "backend-env",
			Auth:        KrypticSecretAuth{SecretRef: KrypticSecretRef{Name: "creds"}},
		},
	}
}

func TestCreatesSecretFromBundle(t *testing.T) {
	fetcher := &stubFetcher{bundle: krypticapi.Bundle{
		"DATABASE_URL": "postgres://db/app",
		"REDIS_URL":    "redis://cache",
	}}
	reconciler, kube := newReconciler(t, fetcher, credentialsSecret("default", "creds", nil))
	cr := testCR()

	result := reconciler.Reconcile(context.Background(), cr)

	if result.Condition.Status != metav1.ConditionTrue {
		t.Fatalf("expected Ready=True, got %s (%s: %s)",
			result.Condition.Status, result.Condition.Reason, result.Condition.Message)
	}
	if result.SyncedKeys != 2 {
		t.Fatalf("synced %d keys, want 2", result.SyncedKeys)
	}

	secret, err := kube.CoreV1().Secrets("default").Get(context.Background(), "backend-env", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("target secret not created: %v", err)
	}
	if string(secret.Data["DATABASE_URL"]) != "postgres://db/app" {
		t.Fatalf("wrong value: %q", secret.Data["DATABASE_URL"])
	}
	if secret.Type != corev1.SecretTypeOpaque {
		t.Fatalf("type = %s, want Opaque", secret.Type)
	}
	if secret.Labels[ManagedByLabel] != ManagedByValue {
		t.Fatal("managed-by label missing")
	}

	// The owner reference is what makes Kubernetes garbage-collect the Secret
	// when the KrypticSecret is deleted.
	if len(secret.OwnerReferences) != 1 ||
		secret.OwnerReferences[0].Kind != Kind ||
		secret.OwnerReferences[0].Name != cr.Name ||
		secret.OwnerReferences[0].UID != cr.UID {
		t.Fatalf("owner reference not set correctly: %+v", secret.OwnerReferences)
	}

	// Credentials must come from the referenced secret.
	if fetcher.gotCredentials.ClientID != "kmi_test" || fetcher.gotCredentials.ClientSecret != "shhh" {
		t.Fatalf("wrong credentials passed: %+v", fetcher.gotCredentials)
	}
	if fetcher.gotCredentials.BaseURL != krypticapi.DefaultBaseURL {
		t.Fatalf("base url = %q, want the hosted default", fetcher.gotCredentials.BaseURL)
	}
	if fetcher.gotProject != "proj_a1b2c3d4e5f6" || fetcher.gotEnvironment != "production" {
		t.Fatalf("wrong project/environment: %s/%s", fetcher.gotProject, fetcher.gotEnvironment)
	}
}

func TestUpdatesExistingSecretAndRemovesDeletedKeys(t *testing.T) {
	cr := testCR()
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend-env",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: APIVersion, Kind: Kind, Name: cr.Name, UID: cr.UID,
			}},
		},
		Data: map[string][]byte{
			"DATABASE_URL": []byte("stale"),
			"REMOVED_KEY":  []byte("should disappear"),
		},
	}

	fetcher := &stubFetcher{bundle: krypticapi.Bundle{"DATABASE_URL": "postgres://fresh"}}
	reconciler, kube := newReconciler(t, fetcher, credentialsSecret("default", "creds", nil), existing)

	result := reconciler.Reconcile(context.Background(), cr)
	if result.Condition.Status != metav1.ConditionTrue {
		t.Fatalf("expected Ready=True, got %s", result.Condition.Reason)
	}

	secret, _ := kube.CoreV1().Secrets("default").Get(context.Background(), "backend-env", metav1.GetOptions{})
	if string(secret.Data["DATABASE_URL"]) != "postgres://fresh" {
		t.Fatalf("value not refreshed: %q", secret.Data["DATABASE_URL"])
	}
	if _, present := secret.Data["REMOVED_KEY"]; present {
		t.Fatal("key deleted in Kryptic still present in the Secret")
	}
}

func TestRefusesToHijackForeignSecret(t *testing.T) {
	cr := testCR()
	// A hand-managed Secret with the same name, no owner reference.
	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "backend-env", Namespace: "default"},
		Data:       map[string][]byte{"HAND_MANAGED": []byte("precious")},
	}

	fetcher := &stubFetcher{bundle: krypticapi.Bundle{"DATABASE_URL": "x"}}
	reconciler, kube := newReconciler(t, fetcher, credentialsSecret("default", "creds", nil), foreign)

	result := reconciler.Reconcile(context.Background(), cr)

	if result.Condition.Status != metav1.ConditionFalse || result.Condition.Reason != ReasonSecretWriteFail {
		t.Fatalf("expected a write failure condition, got %s/%s", result.Condition.Status, result.Condition.Reason)
	}

	secret, _ := kube.CoreV1().Secrets("default").Get(context.Background(), "backend-env", metav1.GetOptions{})
	if string(secret.Data["HAND_MANAGED"]) != "precious" {
		t.Fatal("operator overwrote a Secret it does not own")
	}
}

func TestKeyFilterSyncsOnlyRequestedKeys(t *testing.T) {
	cr := testCR()
	cr.Spec.Keys = []string{"DATABASE_URL", "MISSING_KEY"}

	fetcher := &stubFetcher{bundle: krypticapi.Bundle{
		"DATABASE_URL": "postgres://db",
		"REDIS_URL":    "redis://cache",
		"API_KEY":      "secret",
	}}
	reconciler, kube := newReconciler(t, fetcher, credentialsSecret("default", "creds", nil))

	result := reconciler.Reconcile(context.Background(), cr)
	if result.SyncedKeys != 1 {
		t.Fatalf("synced %d keys, want 1", result.SyncedKeys)
	}

	secret, _ := kube.CoreV1().Secrets("default").Get(context.Background(), "backend-env", metav1.GetOptions{})
	if len(secret.Data) != 1 {
		t.Fatalf("secret has %d keys, want only the filtered one: %v", len(secret.Data), SortedKeys(secret.Data))
	}
	if _, present := secret.Data["REDIS_URL"]; present {
		t.Fatal("unfiltered key leaked into the Secret")
	}
}

func TestSelfHostedApiUrlIsHonored(t *testing.T) {
	fetcher := &stubFetcher{bundle: krypticapi.Bundle{"K": "v"}}
	reconciler, _ := newReconciler(t, fetcher,
		credentialsSecret("default", "creds", map[string]string{"apiUrl": "https://pipelines.internal"}))

	reconciler.Reconcile(context.Background(), testCR())

	if fetcher.gotCredentials.BaseURL != "https://pipelines.internal" {
		t.Fatalf("base url = %q, want the self-hosted override", fetcher.gotCredentials.BaseURL)
	}
}

func TestMissingCredentialsSecretIsNotReady(t *testing.T) {
	fetcher := &stubFetcher{bundle: krypticapi.Bundle{"K": "v"}}
	reconciler, _ := newReconciler(t, fetcher) // no credentials secret

	result := reconciler.Reconcile(context.Background(), testCR())

	if result.Condition.Status != metav1.ConditionFalse || result.Condition.Reason != ReasonAuthSecret {
		t.Fatalf("expected AuthSecretInvalid, got %s/%s", result.Condition.Status, result.Condition.Reason)
	}
	if fetcher.calls != 0 {
		t.Fatal("fetched from the platform despite unusable credentials")
	}
}

func TestIncompleteCredentialsSecretIsNotReady(t *testing.T) {
	blank := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "default"},
		Data:       map[string][]byte{"clientId": []byte("kmi_test")}, // no clientSecret
	}
	fetcher := &stubFetcher{}
	reconciler, _ := newReconciler(t, fetcher, blank)

	result := reconciler.Reconcile(context.Background(), testCR())

	if result.Condition.Reason != ReasonAuthSecret {
		t.Fatalf("expected AuthSecretInvalid, got %s", result.Condition.Reason)
	}
	if fetcher.calls != 0 {
		t.Fatal("fetched with incomplete credentials")
	}
}

func TestPermanentApiErrorBacksOffHard(t *testing.T) {
	fetcher := &stubFetcher{err: &krypticapi.APIError{Status: 404, Message: "Unknown project."}}
	reconciler, kube := newReconciler(t, fetcher, credentialsSecret("default", "creds", nil))

	result := reconciler.Reconcile(context.Background(), testCR())

	if result.Condition.Reason != ReasonPermanentError {
		t.Fatalf("expected ConfigurationError, got %s", result.Condition.Reason)
	}
	if result.RequeueAfter < 10*time.Minute {
		t.Fatalf("requeue after %s - a misconfiguration must not be retried aggressively", result.RequeueAfter)
	}
	if _, err := kube.CoreV1().Secrets("default").Get(context.Background(), "backend-env", metav1.GetOptions{}); err == nil {
		t.Fatal("secret created despite a failed fetch")
	}
}

func TestTransientErrorRetriesSooner(t *testing.T) {
	fetcher := &stubFetcher{err: errors.New("connection reset")}
	reconciler, _ := newReconciler(t, fetcher, credentialsSecret("default", "creds", nil))

	cr := testCR()
	cr.Spec.RefreshInterval = "20m"

	result := reconciler.Reconcile(context.Background(), cr)

	if result.Condition.Reason != ReasonFetchFailed {
		t.Fatalf("expected FetchFailed, got %s", result.Condition.Reason)
	}
	if result.RequeueAfter != 5*time.Minute {
		t.Fatalf("requeue after %s, want a quarter of the interval", result.RequeueAfter)
	}
}

func TestExistingSecretIsNotWipedWhenFetchFails(t *testing.T) {
	cr := testCR()
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend-env",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: APIVersion, Kind: Kind, Name: cr.Name, UID: cr.UID,
			}},
		},
		Data: map[string][]byte{"DATABASE_URL": []byte("last known good")},
	}

	fetcher := &stubFetcher{err: errors.New("platform unreachable")}
	reconciler, kube := newReconciler(t, fetcher, credentialsSecret("default", "creds", nil), existing)

	reconciler.Reconcile(context.Background(), cr)

	secret, _ := kube.CoreV1().Secrets("default").Get(context.Background(), "backend-env", metav1.GetOptions{})
	if string(secret.Data["DATABASE_URL"]) != "last known good" {
		t.Fatal("a platform outage emptied the running workload's secret")
	}
}

func TestSecretNameDefaultsToResourceName(t *testing.T) {
	cr := testCR()
	cr.Spec.SecretName = ""

	fetcher := &stubFetcher{bundle: krypticapi.Bundle{"K": "v"}}
	reconciler, kube := newReconciler(t, fetcher, credentialsSecret("default", "creds", nil))

	reconciler.Reconcile(context.Background(), cr)

	if _, err := kube.CoreV1().Secrets("default").Get(context.Background(), "backend-secrets", metav1.GetOptions{}); err != nil {
		t.Fatalf("secret not created under the resource name: %v", err)
	}
}

func TestRefreshIntervalParsing(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Duration
	}{
		{"", DefaultRefreshInterval},
		{"90s", 90 * time.Second},
		{"1h", time.Hour},
		{"nonsense", DefaultRefreshInterval},
		{"1s", DefaultRefreshInterval}, // below the floor: ignored, not honored
	}

	for _, testCase := range cases {
		spec := KrypticSecretSpec{RefreshInterval: testCase.raw}
		if got := spec.RefreshIntervalOrDefault(); got != testCase.want {
			t.Errorf("interval %q = %s, want %s", testCase.raw, got, testCase.want)
		}
	}
}

func TestCustomSecretTypeAndLabels(t *testing.T) {
	cr := testCR()
	cr.Spec.Template.Type = "kubernetes.io/dockerconfigjson"
	cr.Spec.Template.Labels = map[string]string{"team": "backend"}
	cr.Spec.Template.Annotations = map[string]string{"reloader.stakater.com/match": "true"}

	fetcher := &stubFetcher{bundle: krypticapi.Bundle{".dockerconfigjson": "{}"}}
	reconciler, kube := newReconciler(t, fetcher, credentialsSecret("default", "creds", nil))

	reconciler.Reconcile(context.Background(), cr)

	secret, _ := kube.CoreV1().Secrets("default").Get(context.Background(), "backend-env", metav1.GetOptions{})
	if secret.Type != corev1.SecretType("kubernetes.io/dockerconfigjson") {
		t.Fatalf("type = %s", secret.Type)
	}
	if secret.Labels["team"] != "backend" {
		t.Fatal("template labels not applied")
	}
	if secret.Labels[ManagedByLabel] != ManagedByValue {
		t.Fatal("template labels clobbered the managed-by label")
	}
	if secret.Annotations["reloader.stakater.com/match"] != "true" {
		t.Fatal("template annotations not applied")
	}
}
