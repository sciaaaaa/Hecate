#!/usr/bin/env bash
set -eu
cd /home/Hecate_2/hecate-app/hecate-im576-n10-v1
PY=/home/Hecate_2/.venv-chain/bin/python
LOG="/home/ubuntu/hecate-im576-$1-$(date +%Y%m%d-%H%M%S)-$$.log"
nohup bash -c '
  "$1" -u pilot.py "${@:2}"
  rc=$?
  printf "\nEXIT_CODE=%s\n" "$rc"
  exit "$rc"
' _ "$PY" "$@" >"$LOG" 2>&1 < /dev/null &
printf 'PID=%s LOG=%s\n' "$!" "$LOG"
