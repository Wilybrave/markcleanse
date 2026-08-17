#!/usr/bin/env bash
#
# Fetch the official C2PA Conformance Program trust lists.
#
#   bash tools/update-trust-list.sh
#   markcleanse ~/assets --trust c2pa
#
# Deliberately not vendored into the repo: a trust list is a security decision
# with an expiry date, and a stale copy committed to git is how a revoked CA
# stays trusted. Re-run this periodically.

set -eu

HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
DEST="$HERE/trust"
BASE="https://raw.githubusercontent.com/c2pa-org/conformance-public/main/trust-list"

mkdir -p "$DEST"

for name in C2PA-TRUST-LIST.pem C2PA-TSA-TRUST-LIST.pem; do
    tmp="$(mktemp)"
    if curl -fsSL "$BASE/$name" -o "$tmp" && grep -q "BEGIN CERTIFICATE" "$tmp"; then
        mv "$tmp" "$DEST/$name"
        echo "  $name — $(grep -c 'BEGIN CERTIFICATE' "$DEST/$name") certificates"
    else
        rm -f "$tmp"
        echo "  $name — FAILED to fetch (previous copy kept, if any)" >&2
    fi
done

echo
echo "Fetched $(date -u +%Y-%m-%dT%H:%MZ) from c2pa-org/conformance-public"
echo "Use with:  markcleanse <paths> --trust c2pa"
