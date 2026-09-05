# Changelog

Notes for each release. The release workflow copies the matching section into
the GitHub Release (with the container image URL prepended).

## Unreleased

### Changed

- `github.com/dev-kryptic/Kryptic.Encryption.Go` v1.0.2.

## 1.0.0

First production release of the Kubernetes operator.

### Added

- Optional cluster machine identity via `KRYPTIC_CLIENT_ID`,
  `KRYPTIC_CLIENT_SECRET`, and `KRYPTIC_API_URL`. A `KrypticSecret` may omit
  `spec.auth` when those are set. Per-namespace `spec.auth.secretRef` remains
  the recommended production path and always wins when present.

### Changed

- Release workflow commits `VERSION` and `deploy/operator.yaml` with the
  Kryptic Release Bot, then tags `vX.Y.Z` and uploads pinned manifests.
