#!/usr/bin/env bash
set -euo pipefail

CODER_REF_DIR="$(cd "$(dirname "$0")/.." && pwd)/coder"

if [ -d "$CODER_REF_DIR/.git" ]; then
  echo "Go reference already cloned at $CODER_REF_DIR"
  cd "$CODER_REF_DIR" && git pull --ff-only
  exit 0
fi

echo "Cloning Coder Go reference into $CODER_REF_DIR ..."
rm -rf "$CODER_REF_DIR"
git clone --depth 1 https://github.com/coder/coder.git "$CODER_REF_DIR"

# Restore the guard file that gitignore keeps tracked
GUARD_FILE="$CODER_REF_DIR/AGENTS.md"
if [ ! -f "$GUARD_FILE" ]; then
  cd "$(dirname "$0")/.." && git checkout -- coder/AGENTS.md 2>/dev/null || true
fi

echo "Done. Go reference available at $CODER_REF_DIR"
