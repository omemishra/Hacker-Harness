#!/usr/bin/env sh
set -eu

if command -v uv >/dev/null 2>&1; then
  uv tool install --force "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
  printf '%s\n' "Installed Hacker-Harness. Run: hacker-harness --help"
  exit 0
fi

python3 -m venv "$HOME/.local/share/hacker-harness/venv"
"$HOME/.local/share/hacker-harness/venv/bin/pip" install --upgrade pip
"$HOME/.local/share/hacker-harness/venv/bin/pip" install "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p "$HOME/.local/bin"
ln -sf "$HOME/.local/share/hacker-harness/venv/bin/hacker-harness" "$HOME/.local/bin/hacker-harness"
ln -sf "$HOME/.local/share/hacker-harness/venv/bin/hh" "$HOME/.local/bin/hh"
printf '%s\n' "Installed into $HOME/.local/bin."
printf '%s\n' 'Add it to PATH with: export PATH="$HOME/.local/bin:$PATH"'
printf '%s\n' 'Do not source $HOME/.local/bin/env; Hacker-Harness does not create that file.'
