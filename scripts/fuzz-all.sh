#!/usr/bin/env bash
set -euo pipefail

cyrene_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$cyrene_root"

cyrene_fuzz_seconds=${FUZZ_SECONDS:-300}
cyrene_evidence_dir=${EVIDENCE_DIR:-target/release-evidence/fuzz}
cyrene_targets=(relay_request recovery_bundle replicated_change share_invitation)

if ! [[ "$cyrene_fuzz_seconds" =~ ^[1-9][0-9]*$ ]]; then
  printf 'FUZZ_SECONDS must be a positive integer, got %s\n' "$cyrene_fuzz_seconds" >&2
  exit 2
fi

if ! rustup run nightly rustc --version >/dev/null 2>&1; then
  printf '%s\n' 'Nightly Rust is required: rustup toolchain install nightly --profile minimal' >&2
  exit 2
fi

if ! cargo fuzz --help >/dev/null 2>&1; then
  printf '%s\n' 'cargo-fuzz is required: cargo install cargo-fuzz --locked' >&2
  exit 2
fi

mkdir -p "$cyrene_evidence_dir"
if cyrene_commit=$(git rev-parse --verify HEAD 2>/dev/null); then
  :
else
  cyrene_commit=uncommitted
fi
{
  printf 'commit=%s\n' "$cyrene_commit"
  printf 'stable=%s\n' "$(rustc --version)"
  printf 'nightly=%s\n' "$(rustup run nightly rustc --version)"
  printf 'seconds_per_target=%s\n' "$cyrene_fuzz_seconds"
} > "$cyrene_evidence_dir/environment.txt"

for cyrene_target in "${cyrene_targets[@]}"; do
  printf '→ fuzzing %s for %ss\n' "$cyrene_target" "$cyrene_fuzz_seconds"
  cargo +nightly fuzz run "$cyrene_target" -- \
    "-max_total_time=$cyrene_fuzz_seconds" \
    -print_final_stats=1 \
    >"$cyrene_evidence_dir/$cyrene_target.log" 2>&1
  printf 'passed %s\n' "$cyrene_target" >> "$cyrene_evidence_dir/summary.txt"
done

printf '✓ all fuzz targets passed; evidence: %s\n' "$cyrene_evidence_dir"
