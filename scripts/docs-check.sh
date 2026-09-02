#!/usr/bin/env bash
set -euo pipefail

cyrene_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$cyrene_root"

if ! command -v npx >/dev/null 2>&1; then
  printf '%s\n' 'Documentation checks require Node.js/npm so npx is available.' >&2
  exit 2
fi

printf '%s\n' '→ Markdown style'
npx --yes markdownlint-cli2

printf '%s\n' '→ Markdown links'
while IFS= read -r -d '' cyrene_doc; do
  npx --yes markdown-link-check --quiet \
    --config .markdown-link-check.json "$cyrene_doc"
done < <(rg --files -0 -g '*.md')

printf '%s\n' '✓ documentation checks passed'
