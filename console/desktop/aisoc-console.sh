#!/bin/sh
# Launcher for the packaged AI SOC desktop app (Electron, loads ui/dist).
# Keep the console backend running on 127.0.0.1:4319 — the built UI talks to it.
DIR="$(cd "$(dirname "$0")/.." && pwd)"
export DISPLAY="${DISPLAY:-:0}"
exec "$DIR/desktop/node_modules/.bin/electron" "$DIR/desktop" --disable-gpu "$@"
