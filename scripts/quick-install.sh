#!/usr/bin/env bash
# Mobile-ReverseSkill — quick install (curl | bash).
#
# Downloads the repo tarball and installs skills + slash commands user-globally
# via scripts/sync-providers.sh --user. Nothing is kept afterwards.
#
#   curl -fsSL https://raw.githubusercontent.com/alvinhayy/Mobile-ReverseSkill/main/scripts/quick-install.sh | bash
#
# Env overrides: REPO (default alvinhayy/Mobile-ReverseSkill), BRANCH (default main).
set -euo pipefail

REPO="${REPO:-alvinhayy/Mobile-ReverseSkill}"
BRANCH="${BRANCH:-main}"

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl not found" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "[*] downloading ${REPO}@${BRANCH}"
curl -fsSL "https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz" -o "$TMP/repo.tar.gz"
tar -xzf "$TMP/repo.tar.gz" -C "$TMP"
SRC="$TMP/${REPO##*/}-${BRANCH}"
if [ ! -f "$SRC/scripts/sync-providers.sh" ]; then
  echo "error: unexpected archive layout ($SRC missing)" >&2
  exit 1
fi

"$SRC/scripts/sync-providers.sh" --user

echo
echo "[*] done — restart your agent (Claude Code / Codex / opencode / Gemini / Cursor) to pick up the new skills + slash commands."
