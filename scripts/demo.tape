# vhs script for recording demo.gif on the README.
#
# This tape produces a *fast scan* recording (real, reproducible) — runs
# `inkog .` against the demo_agent fixture in /tmp/inkog-demo-record/agent.
# Completes in seconds.
#
# The README's current demo.gif is a hand-curated *deep scan* recording
# generated from a saved 8-minute deep-scan output via a replay wrapper.
# To regenerate the deep variant: capture `inkog -deep .` output to a file,
# point a wrapper script at it, and re-run vhs against this tape with the
# wrapper on PATH ahead of the real binary. See scripts/record-demo.sh.
#
# Prereqs:
#   - vhs (https://github.com/charmbracelet/vhs)  — brew install vhs
#   - INKOG_API_KEY in the shell environment
#   - A built `./inkog` binary (run `make build`)
#
# Run from the repo root:
#   scripts/record-demo.sh
#
# Output: demo.gif in the repo root (overwrites the existing one).

Output demo.gif

Set Shell "bash"
Set FontFamily "Menlo"
Set FontSize 13
Set Width 980
Set Height 680
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set PlaybackSpeed 1.0
Set Framerate 24

Hide
Type "export PATH=$(pwd):$PATH"
Enter
Type "cd /tmp/inkog-demo-record/agent"
Enter
Type "clear"
Enter
Show

Sleep 600ms
Type "# Scan an AI agent for security flaws and EU AI Act compliance gaps"
Sleep 400ms
Enter
Type "inkog ."
Sleep 500ms
Enter

# Real scan completes in ~2s; let output stream in
Sleep 5s

# Hold the final summary
Sleep 4s
