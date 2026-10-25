#!/bin/sh
# Statement coverage of the production code, measured across packages (-coverpkg: a package exercised by another
# package's tests counts), and a gate: it fails when coverage drops below the floor in scripts/coverage-floor.
# Development tools, test helpers and the UI demo server are left out. Raise the floor as coverage grows.
set -eu
cd "$(dirname "$0")/.."
exclude='/conformance/|/internal/loadtest$|/internal/store/storetest$|/internal/upstream/upstreamtest$|/internal/webtest$|/tools/'
pkgs=$(go list ./... | grep -Ev "$exclude" | paste -sd, -)
out=${COVER_OUT:-coverage.out}
go test -coverpkg="$pkgs" -coverprofile="$out" ./... >/dev/null
total=$(go tool cover -func="$out" | awk '/^total:/ {sub("%", "", $3); print $3}')
floor=$(cat scripts/coverage-floor)
echo "production statement coverage: ${total}% (floor ${floor}%)"
awk -v t="$total" -v f="$floor" 'BEGIN { exit (t + 0 < f + 0) }' || { echo "coverage fell below the floor" >&2; exit 1; }
