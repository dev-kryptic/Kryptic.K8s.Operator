package controller

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupVersionResource of the KrypticSecret custom resource.
var KrypticSecretGVR = schema.GroupVersionResource{
	Group:    "kryptic.dev",
	Version:  "v1",
	Resource: "krypticsecrets",
}

const (
	// APIVersion / Kind as they appear on the CR, used for owner references.
	APIVersion = "kryptic.dev/v1"
	Kind       = "KrypticSecret"

	// ManagedByLabel marks the Secrets this operator owns.
	ManagedByLabel = "app.kubernetes.io/managed-by"
	ManagedByValue = "kryptic-operator"

	DefaultRefreshInterval = 5 * time.Minute
	MinRefreshInterval     = 30 * time.Second
)

// KrypticSecret is the custom resource: "keep this Kubernetes Secret in sync
// with this Kryptic project + environment".
type KrypticSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KrypticSecretSpec   `json:"spec"`
	Status KrypticSecretStatus `json:"status,omitempty"`
}

type KrypticSecretSpec struct {
	// ProjectID is the project public id ("proj_…") from kryptic.json.
	ProjectID string `json:"projectId"`
	// Environment slug - development, staging, production, or a custom one.
	Environment string `json:"environment"`
	// SecretName is the target Kubernetes Secret; defaults to the CR's name.
	SecretName string `json:"secretName,omitempty"`
	// RefreshInterval as a Go duration string ("5m"). Defaults to 5m, floor 30s.
	RefreshInterval string `json:"refreshInterval,omitempty"`
	// Keys optionally restricts which secret keys are synced; empty means all.
	Keys []string `json:"keys,omitempty"`
	// Auth points at a Secret in the same namespace holding machine identity
	// credentials. Omit it only when the operator has cluster credentials
	// (KRYPTIC_CLIENT_ID / KRYPTIC_CLIENT_SECRET). Per-namespace auth is the
	// recommended production path.
	Auth *KrypticSecretAuth `json:"auth,omitempty"`
	// Template customizes the produced Secret.
	Template KrypticSecretTemplate `json:"template,omitempty"`
}

type KrypticSecretAuth struct {
	SecretRef KrypticSecretRef `json:"secretRef"`
}

// AuthSecretName is the per-namespace credentials Secret, or empty when the
// CR relies on optional cluster credentials.
func (s KrypticSecretSpec) AuthSecretName() string {
	if s.Auth == nil {
		return ""
	}
	return s.Auth.SecretRef.Name
}

// KrypticSecretRef names a Secret in the same namespace holding the keys
// clientId, clientSecret and (optionally) apiUrl.
type KrypticSecretRef struct {
	Name string `json:"name"`
}

type KrypticSecretTemplate struct {
	// Type of the produced Secret. Defaults to Opaque.
	Type string `json:"type,omitempty"`
	// Labels and Annotations are merged onto the produced Secret.
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type KrypticSecretStatus struct {
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	LastSyncTime       *metav1.Time       `json:"lastSyncTime,omitempty"`
	SyncedKeyCount     int                `json:"syncedKeyCount,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
}

// RefreshIntervalOrDefault parses the spec interval, clamping to the floor so a
// typo cannot turn the operator into a request flood.
func (s KrypticSecretSpec) RefreshIntervalOrDefault() time.Duration {
	if s.RefreshInterval == "" {
		return DefaultRefreshInterval
	}
	parsed, err := time.ParseDuration(s.RefreshInterval)
	if err != nil || parsed < MinRefreshInterval {
		return DefaultRefreshInterval
	}
	return parsed
}

// TargetSecretName is the Secret this CR manages.
func (k *KrypticSecret) TargetSecretName() string {
	if k.Spec.SecretName != "" {
		return k.Spec.SecretName
	}
	return k.Name
}
