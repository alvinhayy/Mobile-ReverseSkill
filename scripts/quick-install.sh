#!/usr/bin/env bash
# Mobile-ReverseSkill — quick install (curl | bash).
#
# Two modes:
#   piped (curl | bash ...)   — downloads the repo tarball into a temp dir,
#                               installs, then always removes it (EXIT trap)
#   run from a clone          — uses that checkout directly; nothing is
#                               downloaded or left behind
#
#   curl -fsSL https://raw.githubusercontent.com/alvinhayy/Mobile-ReverseSkill/main/scripts/quick-install.sh | bash
#
# Providers (optional args — no args = every provider):
#
#   curl -fsSL .../quick-install.sh | bash -s -- codex
#   curl -fsSL .../quick-install.sh | bash -s -- codex claude
#
# Providers: all claude codex opencode zcode cursor gemini copilot windsurf
# (codex = skills only — Codex has no user-defined slash commands; its skills
#  are model-invoked, so typing e.g. "/re-static app.apk" as text still works)
#
# From a clone, the equivalent is: scripts/sync-providers.sh --user [providers...]
# Env overrides: REPO (default alvinhayy/Mobile-ReverseSkill), BRANCH (default main).
set -euo pipefail

REPO="${REPO:-alvinhayy/Mobile-ReverseSkill}"
BRANCH="${BRANCH:-main}"

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl not found" >&2
  exit 1
fi

PROVIDERS=()
for a in "$@"; do
  case "$a" in
    all|claude|codex|opencode|zcode|cursor|gemini|copilot|windsurf)
      PROVIDERS+=("$a");;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *)
      echo "error: unknown provider '$a'" >&2
      echo "valid: all claude codex opencode zcode cursor gemini copilot windsurf" >&2
      exit 2;;
  esac
done

# Reuse the checkout this script lives in when it is a full repo clone
# (has skills/ + commands/) — no download, nothing temporary to clean up.
# When piped from curl, BASH_SOURCE/$0 point at stdin and this check fails,
# so the tarball path below is used and cleaned up by the EXIT trap.
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
SRC=""

if [ -n "$SELF_DIR" ] && [ -f "$SELF_DIR/sync-providers.sh" ] \
   && [ -d "$SELF_DIR/../skills" ] && [ -d "$SELF_DIR/../commands" ]; then
  SRC="$(dirname "$SELF_DIR")"
  echo "[*] using local checkout: $SRC (no download)"
else
  echo "[*] downloading ${REPO}@${BRANCH}"
  curl -fsSL "https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz" -o "$TMP/repo.tar.gz"
  tar -xzf "$TMP/repo.tar.gz" -C "$TMP"
  SRC="$TMP/${REPO##*/}-${BRANCH}"
fi

if [ ! -f "$SRC/scripts/sync-providers.sh" ]; then
  echo "error: unexpected layout ($SRC missing scripts/sync-providers.sh)" >&2
  exit 1
fi

if [ ${#PROVIDERS[@]} -gt 0 ]; then
  echo "[*] installing skills + slash commands for: ${PROVIDERS[*]}"
else
  echo "[*] installing skills + slash commands (all providers)"
fi
"$SRC/scripts/sync-providers.sh" --user ${PROVIDERS[@]+"${PROVIDERS[@]}"}

echo
echo "[*] done — restart your agent (Claude Code / Codex / opencode / Gemini / Cursor) to pick up the new skills + slash commands."
