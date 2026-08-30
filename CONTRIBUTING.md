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
go test ./test/e2e -tags=e2e -count=1 -timeout 10m   # needs kind or any cluster
go build ./...
```

Against a local cluster:

```bash
kind create cluster --name kryptic-test
kubectl apply -f deploy/crd.yaml
go run ./cmd/kryptic-operator -kubeconfig=$HOME/.kube/config -log-level=debug
```

## Releasing

A merge to `main` is the release. After unit tests and section 17 QA pass,
the Release workflow bumps the patch version (or minor / major if a commit
since the last tag contains `#minor` or `#major`), tags `vX.Y.Z`, pushes
`ghcr.io/dev-kryptic/kryptic-operator:X.Y.Z`, and creates a GitHub Release
with `crd.yaml` and `operator.yaml`. A failing test skips the tag.

The first successful run on `main` ships `0.1.0` from `VERSION` without a bump.

## Licensing of contributions

This repository is Apache-2.0. By opening a pull request you confirm the
contribution is your own work (or you have the right to submit it) and you
license it under Apache-2.0. There is no CLA.

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
