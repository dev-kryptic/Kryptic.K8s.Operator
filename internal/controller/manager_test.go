package controller

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAcceptsNamespaceScope(t *testing.T) {
	all := &Manager{}
	if !all.accepts("kryptic-qa") || !all.accepts("kryptic-qa-other") {
		t.Fatal("empty Namespace must accept every namespace")
	}

	scoped := &Manager{Namespace: "kryptic-qa"}
	if !scoped.accepts("kryptic-qa") {
		t.Fatal("WATCH_NAMESPACE must accept its own namespace")
	}
	if scoped.accepts("kryptic-qa-other") {
		t.Fatal("WATCH_NAMESPACE must ignore other namespaces")
	}
}

func TestStatusUnchangedSkipsNoOpWrites(t *testing.T) {
	cr := &KrypticSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "backend-secrets", Generation: 2},
		Status: KrypticSecretStatus{
			ObservedGeneration: 2,
			SyncedKeyCount:     3,
			Conditions: []metav1.Condition{{
				Type:    ConditionReady,
				Status:  metav1.ConditionTrue,
				Reason:  ReasonSynced,
				Message: `Synced 3 key(s) into secret "backend-env"`,
			}},
		},
	}
	result := Result{
		SyncedKeys: 3,
		Condition: metav1.Condition{
			Type:    ConditionReady,
			Status:  metav1.ConditionTrue,
			Reason:  ReasonSynced,
			Message: `Synced 3 key(s) into secret "backend-env"`,
		},
	}
	if !statusUnchanged(cr, result) {
		t.Fatal("identical Ready/Synced status must not be rewritten")
	}

	result.SyncedKeys = 2
	if statusUnchanged(cr, result) {
		t.Fatal("a changed key count must be written")
	}
}

func TestToUnstructuredOmitsEmptyAuth(t *testing.T) {
	cr := &KrypticSecret{
		ObjectMeta: metav1.ObjectMeta{Name: "backend-secrets", Namespace: "default"},
		Spec: KrypticSecretSpec{
			ProjectID:   "proj_a1b2c3d4e5f6",
			Environment: "development",
		},
	}
	obj, err := ToUnstructured(cr)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := obj.Object["spec"].(map[string]any)
	if _, present := spec["auth"]; present {
		t.Fatalf("empty auth must be omitted so the CRD does not reject name=\"\": %#v", spec["auth"])
	}
}
