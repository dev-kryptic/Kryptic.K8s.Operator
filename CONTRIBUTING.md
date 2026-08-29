# Contributing

This repository is the Kubernetes operator that syncs Kryptic projects into
native `Secret` objects.

## What we accept

- Bug fixes in reconcile, decrypt, or deploy manifests
- Test coverage (`go test ./...`)
- Documentation and example YAML corrections
- Compatibility fixes for supported Kubernetes versions

## What we do not accept

- Writing decrypted values into logs or events
- Overwriting a Secret the operator does not own
- Emptying a Secret on a platform outage (last-known-good must stay)
- Public GitHub issues for vulnerabilities (email security@kryptic.dev)

## Development

```bash
go test ./...
go build ./...
```

Against a local cluster:

```bash
kind create cluster --name kryptic-test
kubectl apply -f deploy/crd.yaml
go run ./cmd/kryptic-operator -kubeconfig=$HOME/.kube/config -log-level=debug
```

## Licensing of contributions

This repository is Apache-2.0. By opening a pull request you confirm the
contribution is your own work (or you have the right to submit it) and you
license it under Apache-2.0. There is no CLA.

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
