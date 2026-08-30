#!/usr/bin/env bash
# Prints version=X.Y.Z and bump=true|false for the next release.
# No tags: ship VERSION as-is. After that: patch, or #minor / #major in the
# commits since the last tag.
set -euo pipefail

last="$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -n 1 || true)"

if [[ -z "$last" ]]; then
  if [[ -f VERSION ]]; then
    version="$(tr -d '[:space:]' < VERSION)"
  else
    version="0.1.0"
  fi
  echo "version=$version"
  echo "bump=false"
  exit 0
fi

log="$(git log --format='%s%n%b' "${last}..HEAD")"
if grep -qE '(^|[[:space:]])#major([[:space:]]|$)' <<<"$log"; then
  kind=major
elif grep -qE '(^|[[:space:]])#minor([[:space:]]|$)' <<<"$log"; then
  kind=minor
else
  kind=patch
fi

ver="${last#v}"
IFS=. read -r major minor patch <<<"$ver"
case "$kind" in
  major) major=$((major + 1)); minor=0; patch=0 ;;
  minor) minor=$((minor + 1)); patch=0 ;;
  patch) patch=$((patch + 1)) ;;
esac

echo "version=${major}.${minor}.${patch}"
echo "bump=true"
