#!/usr/bin/env bash
# Installs the pre-push security gate into this clone (symlink, so updates to
# .githooks/pre-push apply automatically; other hooks are left untouched).
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
HOOKS="$(git rev-parse --git-path hooks)"
mkdir -p "$HOOKS"
if [ -e "$HOOKS/pre-push" ] && [ ! -L "$HOOKS/pre-push" ]; then
  echo "existing $HOOKS/pre-push found - moved to pre-push.bak"
  mv "$HOOKS/pre-push" "$HOOKS/pre-push.bak"
fi
ln -sf "$ROOT/.githooks/pre-push" "$HOOKS/pre-push"
echo "pre-push security gate installed -> $HOOKS/pre-push"
for t in semgrep cargo-audit cargo-deny gitleaks; do
  command -v "$t" >/dev/null || echo "  missing tool: $t  (macOS: brew install semgrep cargo-audit cargo-deny gitleaks)"
done
