#!/usr/bin/env bash
# Generic cell launcher: build a container, mount scripts+data, run one runner.
#   bash launch/run_cell.sh <container-name> <image> <env-file> <runner.py> [args...]
# POOL_MIB controls the tmpfs pool size (default 256; 1024 for the 1GiB rungs).
set -u
NAME="$1"; IMG="$2"; ENVF="$3"; RUNNER="$4"; shift 4
POOL_MIB="${POOL_MIB:-256}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/data/_runs}"

mkdir -p "$OUT_DIR"
MSYS_NO_PATHCONV=1 docker rm -f "$NAME" >/dev/null 2>&1 || true
MSYS_NO_PATHCONV=1 docker run -d --name "$NAME" \
  --env-file "$ENVF" \
  --tmpfs /data/shared:rw,size=$((POOL_MIB * 1048576)) \
  -v "$ROOT/src/runners:/work/scripts" \
  -v "$OUT_DIR:/work/out" \
  -w /work "$IMG" python "/work/scripts/$RUNNER" "$@" \
  && echo "started $NAME ($ENVF $RUNNER $*)"

# Example (canonical 256MB cell):
#   POOL_MIB=256 bash launch/run_cell.sh rdoc-cell rdoc-autogen:0.1 env.env run_autogen.py \
#       --template copy-C3 --trial 1
