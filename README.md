# Kryptic Kubernetes Operator

Keeps native Kubernetes `Secret`s in sync with Kryptic projects. Declare a
`KrypticSecret`, and the operator authenticates as a machine identity, pulls the
environment's ciphertext bundle, decrypts it inside the cluster, and writes the
values into a Secret your workloads consume with `envFrom` - no init containers,
no sidecars, no secrets in your manifests.

Kryptic secrets are end-to-end encrypted: the platform stores and serves only
ciphertext. The machine's client secret unwraps its private key (Argon2id), the
private key opens the org key sealed to that machine, and the org key decrypts
each value - all inside the operator process. The Kryptic servers never hold a
key that can read your secrets.

```yaml
apiVersion: kryptic.dev/v1
kind: KrypticSecret
metadata:
  name: backend-secrets
spec:
  projectId: proj_a1b2c3d4e5f6
  environment: production
  secretName: backend-env
  refreshInterval: 5m
  auth:
    secretRef:
      name: kryptic-machine-credentials
```

## Install

Prefer the latest GitHub Release so the image tag matches a published build:

```bash
kubectl apply -f https://github.com/dev-kryptic/Kryptic.K8s.Operator/releases/latest/download/crd.yaml
kubectl apply -f https://github.com/dev-kryptic/Kryptic.K8s.Operator/releases/latest/download/operator.yaml
```

From a clone (image tag is whatever is in `deploy/operator.yaml`):

```bash
kubectl apply -f deploy/crd.yaml
kubectl apply -f deploy/operator.yaml
```

Then create a machine identity in the Kryptic dashboard (Machine identities ->
New identity) and store its credentials in the namespace where your
`KrypticSecret`s live. This per-namespace Secret is the recommended production
path: each app rotates and revokes on its own.

```bash
kubectl create secret generic kryptic-machine-credentials \
  --from-literal=clientId=kmi_xxxxxxxxxxxxxxxx \
  --from-literal=clientSecret=<the one-time secret>
```

Self-hosted platforms add `--from-literal=apiUrl=https://pipelines.kryptic.example.com`.

`deploy/example.yaml` is a complete working example including a Deployment that
consumes the produced Secret.

### Optional cluster machine identity

For non-production clusters you can set one machine identity on the operator
instead of a Secret in every namespace. Create the Secret once in
`kryptic-system`, uncomment the `KRYPTIC_CLIENT_ID` / `KRYPTIC_CLIENT_SECRET`
env block in `deploy/operator.yaml`, and omit `spec.auth` on the CR:

```yaml
apiVersion: kryptic.dev/v1
kind: KrypticSecret
metadata:
  name: backend-secrets
spec:
  projectId: proj_a1b2c3d4e5f6
  environment: development
  secretName: backend-env
```

```bash
kubectl create secret generic kryptic-machine-credentials \
  --namespace kryptic-system \
  --from-literal=clientId=kmi_xxxxxxxxxxxxxxxx \
  --from-literal=clientSecret=<the one-time secret>
```

Self-hosted platforms add `--from-literal=apiUrl=...`. The operator reads that
as `KRYPTIC_API_URL`.

This is a convenience for labs and single-operator clusters. It is not the
recommended production path: every `KrypticSecret` in the cluster then shares
one identity, so a leak or a curious CR can read any project that identity can
decrypt. When `spec.auth.secretRef` is set, that namespace Secret always wins
and a missing or incomplete named Secret does not fall back to the cluster
identity.

## Behavior

- **Ownership.** The produced Secret carries an owner reference to its
  `KrypticSecret`, so deleting the CR garbage-collects the Secret. The operator
  refuses to overwrite a Secret it does not own.
- **Drift.** Keys removed in Kryptic are removed from the Secret on the next sync.
- **Failure.** A platform outage never empties a running workload's Secret - the
  last known good values stay until a fetch succeeds. Configuration errors
  (bad credentials, unknown project) back off for 10 minutes rather than
  hammering the API; transient errors retry at a quarter of the refresh interval.
- **Status.** `kubectl get krypticsecrets` shows project, environment, key count
  and readiness; the `Ready` condition carries the failure reason when not synced.

## Configuration

| Field | Default | Notes |
| --- | --- | --- |
| `spec.projectId` | required | Project public id from `kryptic.json` |
| `spec.environment` | required | Environment slug |
| `spec.secretName` | CR name | Target Kubernetes Secret |
| `spec.refreshInterval` | `5m` | Values below 30s are ignored |
| `spec.auth.secretRef` | cluster env, if set | Per-namespace credentials. Recommended in production. |
| `spec.keys` | all | Restrict which keys are synced |
| `spec.template.type` | `Opaque` | Type of the produced Secret |
| `spec.template.labels` / `.annotations` | - | Merged onto the produced Secret |

The operator watches all namespaces by default; set `WATCH_NAMESPACE` to scope it.

## Development

```bash
go test ./...                    # reconciler unit tests (fake clientset)
go build ./...

# section 17 QA against a real cluster (kind is enough)
kind create cluster --name kryptic-test
go test ./test/e2e -tags=e2e -count=1 -timeout 10m

# run the operator by hand
kubectl apply -f deploy/crd.yaml
go run ./cmd/kryptic-operator -kubeconfig=$HOME/.kube/config -log-level=debug
```

A merge to `main` that passes unit tests and section 17 QA tags that commit,
publishes `ghcr.io/dev-kryptic/kryptic-operator`, and opens a GitHub Release.
The workflow does not push commits to `main`. After the first image lands, make
that GHCR package public or cluster pulls will 401.

License: Apache 2.0.
