#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

BRANCH="${1:-beta}"
MODE="${2:-tui}"

case "$MODE" in
  tui|gui|both) ;;
  *)
    echo "[ERROR] MODE must be one of: tui, gui, both" >&2
    exit 2
    ;;
esac

if ! command -v git >/dev/null 2>&1; then
  echo "[ERROR] git is required for installer smoke test" >&2
  exit 2
fi

TMP_HOME="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_HOME"
}
trap cleanup EXIT

export HOME="$TMP_HOME"
unset DISPLAY || true
unset WAYLAND_DISPLAY || true

echo "[INFO] Smoke install start: branch=$BRANCH mode=$MODE home=$HOME"

bash scripts/install.sh -b "$BRANCH" -m "$MODE"

LAUNCHER="$HOME/.local/bin/seedpass"
APP_DIR="$HOME/.seedpass/app"
if [[ ! -x "$LAUNCHER" ]]; then
  echo "[ERROR] launcher missing: $LAUNCHER" >&2
  exit 1
fi
if [[ ! -d "$APP_DIR/.git" ]]; then
  echo "[ERROR] install dir missing git checkout: $APP_DIR" >&2
  exit 1
fi

actual_branch="$(git -C "$APP_DIR" rev-parse --abbrev-ref HEAD)"
if [[ "$actual_branch" != "$BRANCH" ]]; then
  echo "[ERROR] expected branch '$BRANCH', got '$actual_branch'" >&2
  exit 1
fi

"$LAUNCHER" --help >/tmp/seedpass-installer-smoke-help.txt

echo "[INFO] Re-running installer to validate idempotence"
bash scripts/install.sh -b "$BRANCH" -m "$MODE"
"$LAUNCHER" --help >/tmp/seedpass-installer-smoke-help-2.txt

echo "[SUCCESS] Installer smoke test passed (branch=$BRANCH mode=$MODE)"
