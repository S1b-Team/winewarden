#!/usr/bin/env bash
set -euo pipefail

WINEWARDEN_BIN="${WINEWARDEN_BIN:-winewarden}"
GAME_EXE="$1"
shift || true

"${WINEWARDEN_BIN}" run "${GAME_EXE}" -- "$@"
