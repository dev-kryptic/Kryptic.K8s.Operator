package controller

import "testing"

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
