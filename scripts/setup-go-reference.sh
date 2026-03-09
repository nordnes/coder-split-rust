#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Initialize the Go reference submodule
if [ ! -f "coder/go.mod" ]; then
  echo "Initializing Go reference submodule..."
  git submodule update --init --depth 1 coder
else
  echo "Go reference submodule already initialized."
fi

echo "Go reference available at $REPO_ROOT/coder"

# Pre-warm the Rust build cache (speeds up first compile in new sessions)
echo "Pre-warming cargo build cache..."
cargo check --workspace 2>&1 | tail -3
echo "Setup complete."
