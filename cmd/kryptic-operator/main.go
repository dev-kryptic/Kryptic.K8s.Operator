// The Kryptic Kubernetes operator: keeps native Kubernetes Secrets in sync with
// Kryptic projects, authenticating as a machine identity against the Pipelines BFF.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/dev-kryptic/k8s-operator/internal/controller"
	"github.com/dev-kryptic/k8s-operator/internal/krypticapi"
)

var version = "1.0.0"

func main() {
	var (
		kubeconfig = flag.String("kubeconfig", os.Getenv("KUBECONFIG"), "path to kubeconfig (out-of-cluster runs)")
		namespace  = flag.String("namespace", os.Getenv("WATCH_NAMESPACE"), "namespace to watch; empty watches all")
		logLevel   = flag.String("log-level", "info", "debug, info, warn or error")
	)
	flag.Parse()

	logger := newLogger(*logLevel)

	config, err := loadConfig(*kubeconfig)
	if err != nil {
		logger.Error("cannot build Kubernetes client config", "error", err)
		os.Exit(1)
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		logger.Error("cannot build Kubernetes client", "error", err)
		os.Exit(1)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		logger.Error("cannot build dynamic client", "error", err)
		os.Exit(1)
	}

	cluster := controller.ClusterCredentialsFromEnv()

	manager := &controller.Manager{
		Dynamic: dynamicClient,
		Reconciler: &controller.Reconciler{
			Kube:    kubeClient,
			Fetcher: krypticapi.NewClient(),
			Log:     logger,
			Cluster: cluster,
		},
		Namespace: *namespace,
		Log:       logger,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	scope := *namespace
	if scope == "" {
		scope = "all namespaces"
	}
	logger.Info("kryptic-operator starting",
		"version", version,
		"watching", scope,
		"clusterCredentials", cluster.Configured())

	if err := manager.Run(ctx); err != nil && ctx.Err() == nil {
		logger.Error("operator stopped", "error", err)
		os.Exit(1)
	}
	logger.Info("kryptic-operator stopped")
}

// loadConfig prefers in-cluster credentials and falls back to a kubeconfig so
// the same binary runs locally against a dev cluster.
func loadConfig(kubeconfig string) (*rest.Config, error) {
	if config, err := rest.InClusterConfig(); err == nil {
		return config, nil
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig},
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
}

func newLogger(level string) *slog.Logger {
	var parsed slog.Level
	if err := parsed.UnmarshalText([]byte(level)); err != nil {
		parsed = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parsed}))
}
