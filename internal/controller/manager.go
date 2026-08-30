package controller

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/util/workqueue"
)

// Manager watches KrypticSecret resources and drives the reconciler. It uses a
// plain list-watch + rate-limited work queue rather than a framework: the whole
// controller is one resource type and a few hundred lines, and staying
// dependency-light keeps the audit surface small.
type Manager struct {
	Dynamic    dynamic.Interface
	Reconciler *Reconciler
	Namespace  string // empty means all namespaces
	Log        *slog.Logger
}

type queueItem struct {
	namespace string
	name      string
}

func (m *Manager) Run(ctx context.Context) error {
	queue := workqueue.NewTypedRateLimitingQueue(
		workqueue.DefaultTypedControllerRateLimiter[queueItem]())
	defer queue.ShutDown()

	go m.watch(ctx, queue)

	for {
		item, shuttingDown := queue.Get()
		if shuttingDown {
			return nil
		}

		requeueAfter := m.reconcileOne(ctx, item)
		queue.Done(item)

		if requeueAfter > 0 {
			queue.AddAfter(item, requeueAfter)
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

// watch feeds the queue from the API server, restarting the watch when it drops.
func (m *Manager) watch(ctx context.Context, queue workqueue.TypedRateLimitingInterface[queueItem]) {
	for ctx.Err() == nil {
		watcher, err := m.watched().Watch(ctx, metav1.ListOptions{})
		if err != nil {
			m.Log.Error("watch failed, retrying", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		for event := range watcher.ResultChan() {
			object, ok := event.Object.(*unstructured.Unstructured)
			if !ok {
				continue
			}
			// Deletes are handled by Kubernetes garbage collection via the
			// owner reference on the produced Secret.
			if event.Type == "DELETED" {
				continue
			}
			if !m.accepts(object.GetNamespace()) {
				continue
			}
			queue.Add(queueItem{namespace: object.GetNamespace(), name: object.GetName()})
		}
		m.Log.Info("watch channel closed, re-establishing")
	}
}

func (m *Manager) reconcileOne(ctx context.Context, item queueItem) time.Duration {
	if !m.accepts(item.namespace) {
		m.Log.Debug("dropping KrypticSecret outside WATCH_NAMESPACE",
			"namespace", item.namespace, "name", item.name, "watching", m.Namespace)
		return 0
	}

	raw, err := m.resource().Namespace(item.namespace).Get(ctx, item.name, metav1.GetOptions{})
	if err != nil {
		// Deleted between enqueue and processing: nothing to do.
		m.Log.Debug("KrypticSecret not found, dropping", "namespace", item.namespace, "name", item.name)
		return 0
	}

	cr, err := fromUnstructured(raw)
	if err != nil {
		m.Log.Error("cannot decode KrypticSecret", "namespace", item.namespace, "name", item.name, "error", err)
		return time.Minute
	}

	result := m.Reconciler.Reconcile(ctx, cr)

	m.Log.Info("reconciled",
		"namespace", cr.Namespace, "name", cr.Name,
		"ready", result.Condition.Status, "reason", result.Condition.Reason,
		"keys", result.SyncedKeys, "requeueAfter", result.RequeueAfter)

	if err := m.updateStatus(ctx, raw, cr, result); err != nil {
		m.Log.Error("status update failed", "namespace", cr.Namespace, "name", cr.Name, "error", err)
	}

	return result.RequeueAfter
}

func (m *Manager) updateStatus(ctx context.Context, raw *unstructured.Unstructured, cr *KrypticSecret, result Result) error {
	now := metav1.Now()
	condition := result.Condition
	condition.LastTransitionTime = now
	condition.ObservedGeneration = cr.Generation

	status := map[string]any{
		"observedGeneration": cr.Generation,
		"syncedKeyCount":     int64(result.SyncedKeys),
		"conditions": []any{map[string]any{
			"type":               condition.Type,
			"status":             string(condition.Status),
			"reason":             condition.Reason,
			"message":            condition.Message,
			"lastTransitionTime": now.UTC().Format(time.RFC3339),
			"observedGeneration": cr.Generation,
		}},
	}
	if condition.Status == metav1.ConditionTrue {
		status["lastSyncTime"] = now.UTC().Format(time.RFC3339)
	} else if cr.Status.LastSyncTime != nil {
		status["lastSyncTime"] = cr.Status.LastSyncTime.UTC().Format(time.RFC3339)
	}

	updated := raw.DeepCopy()
	if err := unstructured.SetNestedMap(updated.Object, status, "status"); err != nil {
		return err
	}

	_, err := m.resource().Namespace(cr.Namespace).
		UpdateStatus(ctx, updated, metav1.UpdateOptions{})
	return err
}

func (m *Manager) resource() dynamic.NamespaceableResourceInterface {
	return m.Dynamic.Resource(KrypticSecretGVR)
}

// watched is the list/watch client: cluster-wide when Namespace is empty,
// otherwise only that namespace (WATCH_NAMESPACE / -namespace).
func (m *Manager) watched() dynamic.ResourceInterface {
	if m.Namespace != "" {
		return m.resource().Namespace(m.Namespace)
	}
	return m.resource()
}

// accepts reports whether a KrypticSecret in namespace is in this manager's
// watch scope. An empty Namespace watches every namespace.
func (m *Manager) accepts(namespace string) bool {
	return m.Namespace == "" || m.Namespace == namespace
}

// fromUnstructured decodes a CR through JSON so the typed struct stays the
// single source of truth for field names.
func fromUnstructured(raw *unstructured.Unstructured) (*KrypticSecret, error) {
	encoded, err := json.Marshal(raw.Object)
	if err != nil {
		return nil, err
	}

	var cr KrypticSecret
	if err := json.Unmarshal(encoded, &cr); err != nil {
		return nil, err
	}
	return &cr, nil
}

// ToUnstructured is the inverse, used by tests and by any tooling that needs to
// create CRs programmatically.
func ToUnstructured(cr *KrypticSecret) (*unstructured.Unstructured, error) {
	encoded, err := json.Marshal(cr)
	if err != nil {
		return nil, err
	}

	object := map[string]any{}
	if err := json.Unmarshal(encoded, &object); err != nil {
		return nil, err
	}

	result := &unstructured.Unstructured{Object: object}
	result.SetAPIVersion(APIVersion)
	result.SetKind(Kind)
	stripEmptyAuth(result.Object)
	return result, nil
}

// stripEmptyAuth drops spec.auth when no secret name is set. encoding/json
// omitempty does not skip zero structs, and the CRD rejects an empty name.
func stripEmptyAuth(object map[string]any) {
	spec, ok := object["spec"].(map[string]any)
	if !ok {
		return
	}
	auth, ok := spec["auth"].(map[string]any)
	if !ok {
		return
	}
	ref, _ := auth["secretRef"].(map[string]any)
	name, _ := ref["name"].(string)
	if name == "" {
		delete(spec, "auth")
	}
}

var _ runtime.Object = &unstructured.Unstructured{}
