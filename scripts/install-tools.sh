#!/usr/bin/env bash
# Mobile-ReverseSkill — tool installer (macOS). Idempotent. Written in stages.
#
#   ./install-tools.sh --check                 # report availability, install nothing
#   ./install-tools.sh --stack android         # install one stack's tools
#   ./install-tools.sh --stack all             # everything implemented so far
#
# Stacks (build order): android → flutter → rn → ios  (+ cross disassemblers)
set -uo pipefail

STACK="all"; CHECK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --stack) STACK="${2:-all}"; shift 2;;
    --check) CHECK=1; shift;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

have(){ command -v "$1" >/dev/null 2>&1; }
ok(){   printf '  \033[32m✓\033[0m %-22s %s\n' "$1" "${2:-}"; }
miss(){ printf '  \033[31m✗\033[0m %-22s %s\n' "$1" "${2:-not found}"; }
note(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }

need_brew(){ have brew || { echo "Homebrew required: https://brew.sh"; exit 1; }; }
brew_install(){ have "$1" || { note "brew install $2"; brew install "$2"; }; }
brew_cask(){ note "brew install --cask $2 (skip if present)"; brew install --cask "$2" 2>/dev/null || true; }
pip_install(){ have "$1" || { note "pip install $2"; python3 -m pip install --user "$2"; }; }

dexdump_path(){ ls "$HOME"/Library/Android/sdk/build-tools/*/dexdump 2>/dev/null | tail -1; }

check_android(){
  have jadx        && ok jadx      "$(jadx --version 2>/dev/null | head -1)" || miss jadx    "brew install jadx"
  have apktool     && ok apktool   "$(apktool --version 2>/dev/null)"        || miss apktool "brew install apktool"
  have baksmali    && ok baksmali                                            || miss baksmali "brew install smali"
  have d2j-dex2jar && ok dex2jar                                             || miss dex2jar  "brew install dex2jar"
  [ -n "$(dexdump_path)" ] && ok dexdump "$(dexdump_path)"                   || miss dexdump  "Android build-tools"
  have apkleaks    && ok apkleaks  "(optional)"                              || miss apkleaks "pip install apkleaks (optional)"
}
install_android(){
  need_brew
  brew_install jadx jadx
  brew_install apktool apktool
  brew_install baksmali smali          # provides baksmali + smali
  brew_install d2j-dex2jar dex2jar
  [ -n "$(dexdump_path)" ] || note "dexdump: install Android build-tools via sdkmanager 'build-tools;<ver>'"
  pip_install apkleaks apkleaks || true
}

check_cross(){
  { have ghidraRun || [ -d "/Applications/ghidra"* ] 2>/dev/null; } && ok ghidra || miss ghidra "brew install --cask ghidra"
  have r2    && ok radare2 "$(r2 -v 2>/dev/null | head -1)" || miss radare2 "brew install radare2"
  have rizin && ok rizin || miss rizin "brew install rizin (optional)"
}
install_cross(){ need_brew; brew_cask ghidra ghidra; brew_install r2 radare2; }

# --- flutter (stage 2) ---
BLUTTER_DIR="${BLUTTER_HOME:-$HOME/tools/blutter}"
R2FLUTTER_DIR="${R2FLUTTER_HOME:-$HOME/tools/r2flutter}"
r2_version(){ have r2 || return 1; r2 -v 2>/dev/null | awk 'NR == 1 && NF >= 2 { print $2; found=1; exit } END { if (!found) exit 1 }'; }
version_at_least(){
  awk -v got="$1" -v need="$2" 'BEGIN {
    split(got, g, "."); split(need, n, ".");
    for (i = 1; i <= 3; i++) {
      gv = g[i] + 0; nv = n[i] + 0;
      if (gv > nv) exit 0;
      if (gv < nv) exit 1;
    }
    exit 0;
  }'
}
r2_supported(){ have r2 && version_at_least "$(r2_version)" "6.2.2"; }
r2flutter_path(){
  if have r2flutter; then command -v r2flutter; return 0; fi
  [ -x "$R2FLUTTER_DIR/bin/r2flutter" ] && { printf '%s\n' "$R2FLUTTER_DIR/bin/r2flutter"; return 0; }
  return 1
}
check_flutter(){
  local r2f
  r2f="$(r2flutter_path 2>/dev/null || true)"
  if [ -n "$r2f" ]; then
    ok r2flutter "$("$r2f" -V 2>/dev/null || printf '%s' "$r2f")"
  else
    miss r2flutter "install_flutter (git clone radareorg/r2flutter)"
  fi
  if r2_supported; then
    ok radare2 "$(r2 -v 2>/dev/null | head -1)"
  elif have r2; then
    miss radare2 "$(r2 -v 2>/dev/null | head -1) — r2flutter needs >= 6.2.2"
  else
    miss radare2 "install >= 6.2.2 before r2flutter"
  fi
  { [ -f "$BLUTTER_DIR/blutter.py" ] || [ -f "$HOME/blutter/blutter.py" ]; } && ok blutter "$BLUTTER_DIR" || miss blutter "install_flutter (git clone worawit/blutter)"
  have reflutter && ok reflutter || miss reflutter "pip install reflutter"
  have cmake && ok cmake || miss cmake "brew install cmake (blutter build)"
  have ninja && ok ninja || miss ninja "brew install ninja (blutter build)"
}
install_flutter(){
  need_brew
  brew_install cmake cmake
  brew_install ninja ninja
  brew_install r2 radare2
  have python3 || brew_install python3 python
  if [ -z "$(r2flutter_path 2>/dev/null || true)" ]; then
    if r2_supported; then
      if [ ! -d "$R2FLUTTER_DIR/.git" ]; then
        note "git clone radareorg/r2flutter -> $R2FLUTTER_DIR"
        mkdir -p "$(dirname "$R2FLUTTER_DIR")"
        git clone --depth 1 https://github.com/radareorg/r2flutter "$R2FLUTTER_DIR"
      else
        note "using existing r2flutter checkout at $R2FLUTTER_DIR"
      fi
      if [ -f "$R2FLUTTER_DIR/Makefile" ]; then
        make -C "$R2FLUTTER_DIR"
        make -C "$R2FLUTTER_DIR" user-install
        note "export PATH=$R2FLUTTER_DIR/bin:\$PATH   # so analyze-flutter.sh finds it"
      else
        note "skip r2flutter build: $R2FLUTTER_DIR is not a valid checkout"
      fi
    else
      note "skip r2flutter: radare2 $(r2_version 2>/dev/null || echo 'not found') is too old; install/upgrade to >= 6.2.2 and rerun"
    fi
  fi
  if [ ! -f "$BLUTTER_DIR/blutter.py" ]; then
    note "git clone worawit/blutter -> $BLUTTER_DIR"
    mkdir -p "$(dirname "$BLUTTER_DIR")"
    git clone --depth 1 https://github.com/worawit/blutter "$BLUTTER_DIR"
  fi
  note "blutter builds its Dart VM on first run against the target's snapshot version"
  note "export BLUTTER_HOME=$BLUTTER_DIR   # so analyze-flutter.sh finds it"
  pip_install reflutter reflutter || true
}

npm_g(){ have "$1" || { note "npm i -g $2"; npm install -g "$2"; }; }

# --- react-native (stage 3) ---
check_rn(){
  { have hbc-decompiler || have hbc-disassembler; } && ok hermes-dec || miss hermes-dec "pip install hermes-dec"
  have hbctool && ok hbctool || miss hbctool "pip install hbctool (Hermes, version-locked)"
  have react-native-decompiler && ok react-native-decompiler || miss react-native-decompiler "npm i -g react-native-decompiler"
  have js-beautify && ok js-beautify || miss js-beautify "npm i -g js-beautify"
}
install_rn(){
  pip_install hbc-decompiler hermes-dec || true   # provides hbc-decompiler / hbc-disassembler
  pip_install hbctool hbctool || true
  have npm && { npm_g react-native-decompiler react-native-decompiler; npm_g js-beautify js-beautify; } || note "npm not found — install Node for react-native-decompiler / js-beautify"
}

# --- ios (stage 4) ---
IOS_IPA_EXTRACTOR_DIR="${IOS_IPA_EXTRACTOR_HOME:-$HOME/tools/ios-ipa-extractor}"
check_ios(){
  have ios-ipa-extractor && ok ios-ipa-extractor "$IOS_IPA_EXTRACTOR_DIR" || miss ios-ipa-extractor "install_ios (iw00tr00t/ios-ipa-extractor)"
  have ipatool && ok ipatool "$(ipatool --version 2>&1 | head -1)" || miss ipatool "brew install ipatool"
  if [ -x "$IOS_IPA_EXTRACTOR_DIR/.venv/bin/frida" ]; then
    ok frida "$($IOS_IPA_EXTRACTOR_DIR/.venv/bin/frida --version 2>/dev/null) (ios-ipa-extractor venv)"
  elif have frida; then
    ok frida "$(frida --version 2>/dev/null)"
  else
    miss frida "installed into ios-ipa-extractor's isolated venv"
  fi
  have class-dump && ok class-dump || miss class-dump "brew install class-dump"
  have otool && ok otool || miss otool "xcode-select --install (Command Line Tools)"
  have nm && ok nm || miss nm "xcode-select --install"
  have codesign && ok codesign || miss codesign "xcode-select --install"
  have plutil && ok plutil || miss plutil "(bundled with macOS)"
  { have swift-demangle || xcrun --find swift-demangle >/dev/null 2>&1; } && ok swift-demangle || miss swift-demangle "Xcode (xcrun swift-demangle)"
}
install_ios(){
  need_brew
  have otool || { note "Xcode Command Line Tools (otool/nm/codesign/swift-demangle)"; xcode-select --install 2>/dev/null || true; }
  have python3 || brew_install python3 python
  brew_install ipatool ipatool
  if [ ! -d "$IOS_IPA_EXTRACTOR_DIR/.git" ]; then
    note "git clone iw00tr00t/ios-ipa-extractor -> $IOS_IPA_EXTRACTOR_DIR"
    mkdir -p "$(dirname "$IOS_IPA_EXTRACTOR_DIR")"
    git clone --depth 1 https://github.com/iw00tr00t/ios-ipa-extractor.git "$IOS_IPA_EXTRACTOR_DIR"
  else
    note "using existing ios-ipa-extractor checkout at $IOS_IPA_EXTRACTOR_DIR"
  fi
  if [ -f "$IOS_IPA_EXTRACTOR_DIR/requirements.txt" ] && [ -f "$IOS_IPA_EXTRACTOR_DIR/extract_ipa.sh" ]; then
    [ -x "$IOS_IPA_EXTRACTOR_DIR/.venv/bin/python3" ] || python3 -m venv "$IOS_IPA_EXTRACTOR_DIR/.venv"
    "$IOS_IPA_EXTRACTOR_DIR/.venv/bin/python" -m pip install -r "$IOS_IPA_EXTRACTOR_DIR/requirements.txt"
    mkdir -p "$HOME/.local/bin"
    cp "$ROOT/scripts/ios-ipa-extractor.sh" "$HOME/.local/bin/ios-ipa-extractor"
    chmod +x "$HOME/.local/bin/ios-ipa-extractor"
    note "ios-ipa-extractor launcher: $HOME/.local/bin/ios-ipa-extractor"
  else
    note "skip ios-ipa-extractor setup: checkout is incomplete at $IOS_IPA_EXTRACTOR_DIR"
  fi
  brew_install class-dump class-dump
  note "swift-demangle comes with Xcode: 'xcrun swift-demangle'"
  note "ios-ipa-extractor downloads the Apple CDN IPA; its executable remains FairPlay-encrypted"
  note "decrypt on an authorized compatible jailbroken device (frida-ios-dump / bagbak) before class-dump/nm"
}

case "$STACK" in
  android) [ $CHECK = 1 ] && check_android || install_android;;
  flutter) [ $CHECK = 1 ] && check_flutter || install_flutter;;
  rn)      [ $CHECK = 1 ] && check_rn      || install_rn;;
  ios)     [ $CHECK = 1 ] && check_ios     || install_ios;;
  cross)   [ $CHECK = 1 ] && check_cross   || install_cross;;
  all)
    if [ $CHECK = 1 ]; then
      echo "== Android =="; check_android
      echo "== Cross ==";   check_cross
      echo "== Flutter =="; check_flutter
      echo "== RN ==";      check_rn
      echo "== iOS ==";     check_ios
    else
      install_android; install_cross; install_flutter; install_rn; install_ios
    fi;;
  *) echo "unknown stack: $STACK (android|flutter|rn|ios|cross|all)"; exit 2;;
esac
