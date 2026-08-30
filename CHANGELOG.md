# Changelog

## Unreleased

### Changed

- Release workflow tags the tested SHA and uploads pinned manifests. It no
  longer pushes `chore(release)` commits to `main`, so branch rulesets stay
  intact.

### Added

- Optional cluster machine identity via `KRYPTIC_CLIENT_ID`,
  `KRYPTIC_CLIENT_SECRET`, and `KRYPTIC_API_URL`. A `KrypticSecret` may omit
  `spec.auth` when those are set. Per-namespace `spec.auth.secretRef` remains
  the recommended production path and always wins when present.
