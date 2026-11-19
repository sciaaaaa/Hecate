#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
ROOT=/home/Hecate_2/hecate-app
PY=/home/Hecate_2/.venv-chain/bin/python
MLPY=/home/ubuntu/.venv-presence-ml/bin/python
export HECATE_RPC_HOST=172.31.27.238
BASE="$ROOT/private/presence"
STEP=${1:-help}
case "$STEP" in
  init|check|freeze|gate|evaluate)
    exec "$MLPY" -u study.py "$STEP" --base "$BASE"
    ;;
esac
B=${2:-}
if [[ ! "$B" =~ ^(03|04|05|06|07|08|09|10)$ ]]; then
  printf '%s\n' 'Usage: bash run.sh {init|check|freeze|gate|evaluate}' 'Or: bash run.sh {batch|prepare|fund|upload|collect} {03..10}'
  exit 2
fi
N=$((10#$B))
EXP="presence-p100-1k-$B"
SEED=$((20261020+N))
if (( N >= 8 )); then
  case "$STEP" in
    batch|fund)
      "$PY" check_release.py /home/ubuntu/presence-study2000-test-release.json
      ;;
    prepare|upload|collect)
      "$MLPY" -u study.py gate --base "$BASE"
      ;;
  esac
fi
case "$STEP" in
  batch)
    "$PY" "$ROOT/batch-v1/hecate_batch.py" preflight --root "$ROOT"
    "$PY" "$ROOT/batch-v1/hecate_batch.py" generate --root "$ROOT" --batch "$EXP" --planned-records 200
    "$PY" "$ROOT/batch-v1/hecate_batch.py" publish --root "$ROOT" --batch "$EXP" --timeout 600 --confirmations 2
    ;;
  prepare|upload|collect)
    exec "$PY" -u presence.py "$STEP" --experiment "$EXP" --seed "$SEED"
    ;;
  fund)
    exec "$PY" -u presence.py fund --experiment "$EXP" --seed "$SEED" --manifest "/home/ubuntu/$EXP-manifest.json" --amount-eth 20
    ;;
  *) printf '%s\n' 'Unknown command'; exit 2;;
esac
