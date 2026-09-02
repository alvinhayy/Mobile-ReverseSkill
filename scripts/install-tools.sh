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
check_flutter(){
  { [ -f "$BLUTTER_DIR/blutter.py" ] || [ -f "$HOME/blutter/blutter.py" ]; } && ok blutter "$BLUTTER_DIR" || miss blutter "install_flutter (git clone worawit/blutter)"
  have reflutter && ok reflutter || miss reflutter "pip install reflutter"
  have cmake && ok cmake || miss cmake "brew install cmake (blutter build)"
  have ninja && ok ninja || miss ninja "brew install ninja (blutter build)"
}
install_flutter(){
  need_brew
  brew_install cmake cmake
  brew_install ninja ninja
  have python3 || brew_install python3 python
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
check_ios(){
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
  brew_install class-dump class-dump
  note "swift-demangle comes with Xcode: 'xcrun swift-demangle'"
  note "App Store IPAs are FairPlay-encrypted — decrypt on a jailbroken device (frida-ios-dump / bagbak) before class-dump/nm"
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
