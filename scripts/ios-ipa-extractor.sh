#!/usr/bin/env bash
# Thin launcher for iw00tr00t/ios-ipa-extractor's isolated Python environment.
set -euo pipefail

tool_dir="${IOS_IPA_EXTRACTOR_HOME:-$HOME/tools/ios-ipa-extractor}"
if [ ! -f "$tool_dir/extract_ipa.sh" ] || [ ! -x "$tool_dir/.venv/bin/python3" ]; then
  printf 'ios-ipa-extractor is incomplete at %s; run scripts/install-tools.sh --stack ios.\n' "$tool_dir" >&2
  exit 1
fi

export PATH="$tool_dir/.venv/bin:$PATH"
exec bash "$tool_dir/extract_ipa.sh" "$@"
