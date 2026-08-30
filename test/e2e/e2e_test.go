//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/dev-kryptic/k8s-operator/internal/controller"
	"github.com/dev-kryptic/k8s-operator/internal/krypticapi"
)

var crdGVR = schema.GroupVersionResource{
	Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions",
}

type harness struct {
	t        *testing.T
	cfg      *rest.Config
	kube     kubernetes.Interface
	dyn      dynamic.Interface
	platform *fakePlatform
}

func setup(t *testing.T) *harness {
	t.Helper()

	config, err := loadKubeconfig()
	if err != nil {
		t.Fatalf("e2e tests need a Kubernetes cluster (kind create cluster --name kryptic-test): %v", err)
	}

	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	dyn, err := dynamic.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	platform, err := startFakePlatform()
	if err != nil {
		t.Fatalf("fake platform: %v", err)
	}
	t.Cleanup(platform.Close)

	h := &harness{t: t, cfg: config, kube: kube, dyn: dyn, platform: platform}
	h.applyCRD()
	return h
}

func loadKubeconfig() (*rest.Config, error) {
	if config, err := rest.InClusterConfig(); err == nil {
		return config, nil
	}
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		kubeconfig = filepath.Join(home, ".kube", "config")
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig},
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
}

func (h *harness) applyCRD() {
	h.t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		h.t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(file), "..", "..", "deploy", "crd.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		h.t.Fatal(err)
	}

	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
	var crd unstructured.Unstructured
	if err := decoder.Decode(&crd); err != nil {
		h.t.Fatalf("decode CRD: %v", err)
	}

	_, err = h.dyn.Resource(crdGVR).Create(context.Background(), &crd, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		existing, getErr := h.dyn.Resource(crdGVR).Get(context.Background(), crd.GetName(), metav1.GetOptions{})
		if getErr != nil {
			h.t.Fatal(getErr)
		}
		crd.SetResourceVersion(existing.GetResourceVersion())
		if _, err = h.dyn.Resource(crdGVR).Update(context.Background(), &crd, metav1.UpdateOptions{}); err != nil {
			h.t.Fatalf("update CRD: %v", err)
		}
	} else if err != nil {
		h.t.Fatalf("create CRD: %v", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		got, err := h.dyn.Resource(crdGVR).Get(context.Background(), "krypticsecrets.kryptic.dev", metav1.GetOptions{})
		if err == nil && crdEstablished(got) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	h.t.Fatal("CRD did not become Established")
}

func crdEstablished(obj *unstructured.Unstructured) bool {
	conditions, _, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
	for _, condition := range conditions {
		item, _ := condition.(map[string]any)
		if item["type"] == "Established" && item["status"] == "True" {
			return true
		}
	}
	return false
}

func (h *harness) startOperator(namespace string) context.CancelFunc {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := &controller.Manager{
		Dynamic: h.dyn,
		Reconciler: &controller.Reconciler{
			Kube:    h.kube,
			Fetcher: krypticapi.NewClient(),
			Log:     logger,
		},
		Namespace: namespace,
		Log:       logger,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = manager.Run(ctx)
	}()
	time.Sleep(400 * time.Millisecond)
	h.t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})
	return cancel
}

func (h *harness) ns(name string) {
	h.t.Helper()
	_, err := h.kube.CoreV1().Namespaces().Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() {
		_ = h.kube.CoreV1().Namespaces().Delete(context.Background(), name, metav1.DeleteOptions{})
	})
}

func (h *harness) credentials(namespace, name, clientID, clientSecret string) {
	h.t.Helper()
	_, err := h.kube.CoreV1().Secrets(namespace).Create(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		StringData: map[string]string{
			"clientId":     clientID,
			"clientSecret": clientSecret,
			"apiUrl":       h.platform.URL(),
		},
	}, metav1.CreateOptions{})
	if err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) applyCR(cr *controller.KrypticSecret) {
	h.t.Helper()
	cr.APIVersion = controller.APIVersion
	cr.Kind = controller.Kind
	obj, err := controller.ToUnstructured(cr)
	if err != nil {
		h.t.Fatal(err)
	}
	_, err = h.dyn.Resource(controller.KrypticSecretGVR).Namespace(cr.Namespace).
		Create(context.Background(), obj, metav1.CreateOptions{})
	if err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) applyCRRaw(namespace, name string, spec map[string]any) error {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": controller.APIVersion,
		"kind":       controller.Kind,
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec":       spec,
	}}
	_, err := h.dyn.Resource(controller.KrypticSecretGVR).Namespace(namespace).
		Create(context.Background(), obj, metav1.CreateOptions{})
	return err
}

func (h *harness) deleteCR(namespace, name string) {
	h.t.Helper()
	err := h.dyn.Resource(controller.KrypticSecretGVR).Namespace(namespace).
		Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		h.t.Fatal(err)
	}
}

func (h *harness) touchCR(namespace, name string) {
	h.t.Helper()
	// The operator writes status on every reconcile, which bumps resourceVersion.
	// A single Get/Update races that write on GitHub runners.
	var last error
	for attempt := 0; attempt < 12; attempt++ {
		obj, err := h.dyn.Resource(controller.KrypticSecretGVR).Namespace(namespace).
			Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			h.t.Fatal(err)
		}
		ann := obj.GetAnnotations()
		if ann == nil {
			ann = map[string]string{}
		}
		ann["e2e.kryptic.dev/tick"] = fmt.Sprintf("%d", time.Now().UnixNano())
		obj.SetAnnotations(ann)
		_, err = h.dyn.Resource(controller.KrypticSecretGVR).Namespace(namespace).
			Update(context.Background(), obj, metav1.UpdateOptions{})
		if err == nil {
			return
		}
		if !apierrors.IsConflict(err) {
			h.t.Fatal(err)
		}
		last = err
		time.Sleep(50 * time.Millisecond)
	}
	h.t.Fatalf("touch CR after retries: %v", last)
}

func (h *harness) waitReady(namespace, name string, want metav1.ConditionStatus, reason string) {
	h.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var lastStatus, lastReason string
	for time.Now().Before(deadline) {
		lastStatus, lastReason = h.ready(namespace, name)
		if lastStatus == string(want) && (reason == "" || lastReason == reason) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	h.t.Fatalf("timed out waiting for Ready=%s reason=%s (last %s/%s)", want, reason, lastStatus, lastReason)
}

func (h *harness) ready(namespace, name string) (status, reason string) {
	obj, err := h.dyn.Resource(controller.KrypticSecretGVR).Namespace(namespace).
		Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return "", ""
	}
	conditions, _, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
	for _, condition := range conditions {
		item, _ := condition.(map[string]any)
		if item["type"] == "Ready" {
			return fmt.Sprint(item["status"]), fmt.Sprint(item["reason"])
		}
	}
	return "", ""
}

func (h *harness) secretData(namespace, name string) map[string]string {
	h.t.Helper()
	secret, err := h.kube.CoreV1().Secrets(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		h.t.Fatal(err)
	}
	out := map[string]string{}
	for key, value := range secret.Data {
		out[key] = string(value)
	}
	return out
}

func (h *harness) secretExists(namespace, name string) bool {
	_, err := h.kube.CoreV1().Secrets(namespace).Get(context.Background(), name, metav1.GetOptions{})
	return err == nil
}

func (h *harness) cr(namespace, name, secretName string, keys []string) *controller.KrypticSecret {
	return &controller.KrypticSecret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: controller.KrypticSecretSpec{
			ProjectID:       "proj_e2e000000001",
			Environment:     "development",
			SecretName:      secretName,
			RefreshInterval: "30s",
			Keys:            keys,
			Auth:            controller.KrypticSecretAuth{SecretRef: controller.KrypticSecretRef{Name: "kryptic-machine-credentials"}},
		},
	}
}

func keysOf(data map[string]string) []string {
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	return keys
}
