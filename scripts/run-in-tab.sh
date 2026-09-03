#!/usr/bin/env bash
# run-in-tab.sh <label> <command...>
# Open <command> in a NEW terminal tab (iTerm2, else Terminal.app) so a human can watch and
# interact with it, while mirroring the full session to a log the agent can tail:
#     ~/.mre-runs/<label>-<timestamp>.log
# Uses `script -q` so interactive tools (e.g. the frida REPL) keep their TTY *and* get logged.
# If no GUI tab can be opened (Automation not permitted), it runs the command in the background,
# still logging — so the process always runs and is always monitorable.
# Prints the log path on stdout.
set -uo pipefail

LABEL="${1:?usage: run-in-tab.sh <label> <command...>}"; shift || true
[ $# -gt 0 ] || { echo "usage: run-in-tab.sh <label> <command...>" >&2; exit 2; }
CMD="$*"
CWD="$(pwd)"
RUNDIR="${MRE_RUN_DIR:-$HOME/.mre-runs}"; mkdir -p "$RUNDIR"
TS="$(date +%Y%m%d-%H%M%S)"
BASE="$RUNDIR/${LABEL}-${TS}"
LOG="$BASE.log"; CMDF="$BASE.cmd.sh"; RUN="$BASE.run.sh"; MARK="$BASE.started"

{ printf 'cd %q\n' "$CWD"; printf '%s\n' "$CMD"; } > "$CMDF"
: > "$LOG"

cat > "$RUN" <<RUNNER
#!/bin/sh
: > "$MARK"                                   # signal: the tab actually started
printf '\033]0;mre:%s\007' "$LABEL"
echo "[run-in-tab] $LABEL   log: $LOG"
echo "\$ $CMD"; echo "----------------------------------------"
script -q "$LOG" /bin/sh "$CMDF"
echo "----------------------------------------"; echo "[run-in-tab] $LABEL finished. log: $LOG"
exec "\$SHELL" -il
RUNNER
chmod +x "$RUN" "$CMDF"

open_iterm(){ /usr/bin/osascript >/dev/null 2>&1 <<OSA
tell application "iTerm"
  activate
  if (count of windows) = 0 then
    create window with default profile
  else
    tell current window to create tab with default profile
  end if
  tell current session of current window to write text "sh \"$RUN\""
end tell
OSA
}
open_terminal(){ /usr/bin/osascript >/dev/null 2>&1 <<OSA
tell application "Terminal"
  activate
  do script "sh \"$RUN\""
end tell
OSA
}

# try GUI tab
if /usr/bin/osascript -e 'id of application "iTerm"' >/dev/null 2>&1; then open_iterm
else open_terminal; fi

# confirm the tab really started (marker); else fall back to background (still logged)
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do [ -f "$MARK" ] && break; sleep 0.2; done
if [ ! -f "$MARK" ]; then
  echo "[run-in-tab] GUI tab did not start (Automation not permitted?) — running in background" >&2
  nohup sh "$CMDF" >"$LOG" 2>&1 &
fi

echo "$LOG"
