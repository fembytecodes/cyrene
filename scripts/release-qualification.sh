#!/usr/bin/env bash
set -euo pipefail

cyrene_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$cyrene_root"

cyrene_evidence_dir=${EVIDENCE_DIR:-target/release-evidence}
cyrene_packages=(
  cyrene-core cyrene-crdt cyrene-identity cyrene-sync cyrene-authority
  cyrene-net cyrene-store cyrene-trust cyrene-macros cyrene
  cyrene-relay cyrene-cli
)

mkdir -p "$cyrene_evidence_dir"
if cyrene_commit=$(git rev-parse --verify HEAD 2>/dev/null); then
  :
else
  cyrene_commit=uncommitted
fi
{
  printf 'commit=%s\n' "$cyrene_commit"
  printf 'rustc=%s\n' "$(rustc --version)"
  printf 'cargo=%s\n' "$(cargo --version)"
  printf 'host=%s\n' "$(rustc -vV | sed -n 's/^host: //p')"
  printf 'os=%s\n' "$(uname -a)"
} > "$cyrene_evidence_dir/environment.txt"

"$cyrene_root/scripts/quality-gate.sh" \
  >"$cyrene_evidence_dir/quality-gate.log" 2>&1

printf '%s\n' '→ release benchmark'
cargo bench -p cyrene --bench local_store \
  >"$cyrene_evidence_dir/benchmark.log" 2>&1

printf '%s\n' '→ package file sets'
: > "$cyrene_evidence_dir/packages.txt"
for cyrene_package in "${cyrene_packages[@]}"; do
  cargo package -p "$cyrene_package" --allow-dirty --list \
    > "$cyrene_evidence_dir/package-$cyrene_package.txt"
  printf 'valid %s\n' "$cyrene_package" >> "$cyrene_evidence_dir/packages.txt"
done

printf '%s\n' '→ release binary sizes'
cargo build --release -p cyrene-cli -p cyrene-relay
wc -c target/release/cyrene target/release/cyrene-relay \
  > "$cyrene_evidence_dir/binary-sizes.txt"

if [[ ${SKIP_FUZZ:-0} == 1 ]]; then
  printf '%s\n' 'skipped by SKIP_FUZZ=1' > "$cyrene_evidence_dir/fuzz-skipped.txt"
else
  EVIDENCE_DIR="$cyrene_evidence_dir/fuzz" \
    "$cyrene_root/scripts/fuzz-all.sh"
fi

printf '✓ release qualification passed; evidence: %s\n' "$cyrene_evidence_dir"
