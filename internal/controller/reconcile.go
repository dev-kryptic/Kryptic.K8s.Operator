package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/dev-kryptic/k8s-operator/internal/krypticapi"
)

const (
	ConditionReady = "Ready"

	ReasonSynced          = "Synced"
	ReasonAuthSecret      = "AuthSecretInvalid"
	ReasonFetchFailed     = "FetchFailed"
	ReasonPermanentError  = "ConfigurationError"
	ReasonSecretWriteFail = "SecretWriteFailed"
)

// Reconciler syncs one KrypticSecret into one Kubernetes Secret.
type Reconciler struct {
	Kube    kubernetes.Interface
	Fetcher krypticapi.Fetcher
	Log     *slog.Logger
	Cluster ClusterCredentials
}

// Result reports what the reconcile did and when to come back.
type Result struct {
	RequeueAfter time.Duration
	SyncedKeys   int
	Condition    metav1.Condition
}

// Reconcile brings the target Secret in line with the Kryptic bundle. It never
// returns an error for conditions the user must fix (bad credentials, unknown
// project) - those become a not-Ready condition and a slow requeue, so a typo
// does not turn into a retry storm.
func (r *Reconciler) Reconcile(ctx context.Context, cr *KrypticSecret) Result {
	interval := cr.Spec.RefreshIntervalOrDefault()

	creds, err := r.credentials(ctx, cr)
	if err != nil {
		return failed(ReasonAuthSecret, err.Error(), interval)
	}

	bundle, err := r.Fetcher.Fetch(ctx, creds, cr.Spec.ProjectID, cr.Spec.Environment)
	if err != nil {
		var apiError *krypticapi.APIError
		if errors.As(err, &apiError) && apiError.Permanent() {
			// Misconfiguration: back off hard instead of hammering the platform.
			return failed(ReasonPermanentError, apiError.Error(), longBackoff(interval))
		}
		return failed(ReasonFetchFailed, err.Error(), shortBackoff(interval))
	}

	data := selectKeys(bundle, cr.Spec.Keys)

	if err := r.applySecret(ctx, cr, data); err != nil {
		return failed(ReasonSecretWriteFail, err.Error(), shortBackoff(interval))
	}

	return Result{
		RequeueAfter: interval,
		SyncedKeys:   len(data),
		Condition: metav1.Condition{
			Type:    ConditionReady,
			Status:  metav1.ConditionTrue,
			Reason:  ReasonSynced,
			Message: fmt.Sprintf("Synced %d key(s) into secret %q", len(data), cr.TargetSecretName()),
		},
	}
}

// credentials prefers spec.auth.secretRef in the CR's namespace. If that name
// is empty, it uses optional cluster credentials. A named Secret that is
// missing or incomplete is an error; it does not fall back to the cluster
// identity.
func (r *Reconciler) credentials(ctx context.Context, cr *KrypticSecret) (krypticapi.Credentials, error) {
	name := cr.Spec.AuthSecretName()
	if name != "" {
		return r.credentialsFromSecret(ctx, cr.Namespace, name)
	}
	if r.Cluster.Configured() {
		return r.Cluster.Credentials(), nil
	}
	return krypticapi.Credentials{}, errors.New(
		"spec.auth.secretRef.name is empty and the operator has no cluster credentials " +
			"(set KRYPTIC_CLIENT_ID and KRYPTIC_CLIENT_SECRET, or add spec.auth)")
}

func (r *Reconciler) credentialsFromSecret(ctx context.Context, namespace, name string) (krypticapi.Credentials, error) {
	secret, err := r.Kube.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return krypticapi.Credentials{}, fmt.Errorf("reading credentials secret %q: %w", name, err)
	}

	clientID := string(secret.Data["clientId"])
	clientSecret := string(secret.Data["clientSecret"])
	if clientID == "" || clientSecret == "" {
		return krypticapi.Credentials{}, fmt.Errorf(
			"credentials secret %q must contain non-empty clientId and clientSecret keys", name)
	}

	baseURL := string(secret.Data["apiUrl"])
	if baseURL == "" {
		baseURL = krypticapi.DefaultBaseURL
	}

	return krypticapi.Credentials{BaseURL: baseURL, ClientID: clientID, ClientSecret: clientSecret}, nil
}

// applySecret creates or updates the target Secret, taking ownership so it is
// garbage-collected with the CR.
func (r *Reconciler) applySecret(ctx context.Context, cr *KrypticSecret, data map[string][]byte) error {
	name := cr.TargetSecretName()
	secrets := r.Kube.CoreV1().Secrets(cr.Namespace)

	desired := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   cr.Namespace,
			Labels:      mergeLabels(cr.Spec.Template.Labels),
			Annotations: cr.Spec.Template.Annotations,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion:         APIVersion,
				Kind:               Kind,
				Name:               cr.Name,
				UID:                cr.UID,
				Controller:         pointerTo(true),
				BlockOwnerDeletion: pointerTo(true),
			}},
		},
		Type: secretType(cr.Spec.Template.Type),
		Data: data,
	}

	existing, err := secrets.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, createErr := secrets.Create(ctx, desired, metav1.CreateOptions{})
		return createErr
	}
	if err != nil {
		return err
	}

	// Refuse to hijack a Secret the operator does not own - that would silently
	// destroy hand-managed data.
	if !ownedByThisCR(existing, cr) {
		return fmt.Errorf("secret %q already exists and is not owned by this KrypticSecret", name)
	}

	existing.Data = desired.Data
	existing.Type = desired.Type
	existing.Labels = mergeInto(existing.Labels, desired.Labels)
	existing.Annotations = mergeInto(existing.Annotations, desired.Annotations)
	existing.OwnerReferences = desired.OwnerReferences

	_, err = secrets.Update(ctx, existing, metav1.UpdateOptions{})
	return err
}

// selectKeys turns a bundle into Secret data, honoring an explicit key filter.
func selectKeys(bundle krypticapi.Bundle, keys []string) map[string][]byte {
	data := map[string][]byte{}

	if len(keys) == 0 {
		for key, value := range bundle {
			data[key] = []byte(value)
		}
		return data
	}

	for _, key := range keys {
		if value, ok := bundle[key]; ok {
			data[key] = []byte(value)
		}
	}
	return data
}

func ownedByThisCR(secret *corev1.Secret, cr *KrypticSecret) bool {
	for _, owner := range secret.OwnerReferences {
		if owner.Kind == Kind && owner.Name == cr.Name {
			return true
		}
	}
	return false
}

func mergeLabels(extra map[string]string) map[string]string {
	labels := map[string]string{ManagedByLabel: ManagedByValue}
	for key, value := range extra {
		labels[key] = value
	}
	return labels
}

func mergeInto(target, source map[string]string) map[string]string {
	if target == nil {
		target = map[string]string{}
	}
	for key, value := range source {
		target[key] = value
	}
	return target
}

func secretType(raw string) corev1.SecretType {
	if raw == "" {
		return corev1.SecretTypeOpaque
	}
	return corev1.SecretType(raw)
}

func failed(reason, message string, requeueAfter time.Duration) Result {
	return Result{
		RequeueAfter: requeueAfter,
		Condition: metav1.Condition{
			Type:    ConditionReady,
			Status:  metav1.ConditionFalse,
			Reason:  reason,
			Message: message,
		},
	}
}

// shortBackoff retries transient failures sooner than the refresh interval,
// but never faster than the floor.
func shortBackoff(interval time.Duration) time.Duration {
	if interval/4 < MinRefreshInterval {
		return MinRefreshInterval
	}
	return interval / 4
}

// longBackoff waits out configuration errors - they need a human, not a retry.
func longBackoff(interval time.Duration) time.Duration {
	if interval < 10*time.Minute {
		return 10 * time.Minute
	}
	return interval
}

func pointerTo[T any](value T) *T {
	return &value
}

// SortedKeys is a helper for stable logging/status output.
func SortedKeys(data map[string][]byte) []string {
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
