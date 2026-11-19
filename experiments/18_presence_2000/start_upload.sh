#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
B=${1:-}
if [[ ! "$B" =~ ^(03|04|05|06|07|08|09|10)$ ]]; then
  printf '%s\n' 'Usage: bash start_upload.sh {03..10}'; exit 2
fi
WORK="/home/Hecate_2/hecate-app/private/presence/presence-p100-1k-$B"
test -f "$WORK/public-manifest.json"
if pgrep -af '[p]resence.py.*upload'; then
  printf '%s\n' 'An uploader is running; inspect it before starting another.'; exit 1
fi
LOG="$WORK/upload-console-$(date +%Y%m%d-%H%M%S)-$$.log"
nohup bash "$HERE/run.sh" upload "$B" > "$LOG" 2>&1 < /dev/null &
PID=$!
printf 'Started PID=%s\nLog=%s\nUse tail -f on that log. Ctrl+C stops only tail.\n' "$PID" "$LOG"
