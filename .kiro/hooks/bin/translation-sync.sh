#!/usr/bin/env bash
# PostFileSave check for GUI sources: keep the translation pipeline honest.
#
#   1. A file with i18n() calls must be listed in po/POTFILES.in, or its strings
#      are never extracted and stay untranslated in every locale.
#   2. No Rust-only \u{...} escape inside a translatable literal. xgettext runs
#      with --language=C, cannot decode it, and copies it verbatim into the
#      msgid — so the runtime lookup never matches and the string renders
#      untranslated everywhere while the .po files still report 100% complete.
#
# Reads the PostFileSave JSON on stdin. Silent and exit 0 when clean.
#
# Delivery goes through target/.kiro-session-report, NOT stdout: a command hook's
# stdout is forwarded to the agent only on SessionStart, UserPromptSubmit and
# PreToolUse, and this fires on PostFileSave, where it is discarded. Until
# 2026-09-28 it printed to stdout and the finding was silently lost — the very
# "add a POTFILES line" reminder it exists to raise never reached the agent. It
# now appends to the shared report channel that the UserPromptSubmit flush hook
# prints on the next turn, the same contract flatpak-manifest-check.sh uses.
#
# Was an agent prompt once, which meant the model ran these greps by hand after
# every single .rs save. Nothing here needs judgement except adding a POTFILES
# line, which is the one thing left to the agent.

set -uo pipefail

trap 'exit 0' ERR

payload=$(cat) || exit 0
command -v jq >/dev/null 2>&1 || exit 0

file=$(printf '%s' "$payload" | jq -r '.file_path // ""' 2>/dev/null) || exit 0
[ -n "$file" ] || exit 0

# Anchor at the git root, the way edit-journal.sh does. The old
# `rel=${rel##*/RustConn/}` broke for a clone not named RustConn and cut the path
# at a second `/RustConn/` component; crate-boundary-guard.sh already carries the
# write-up of that trap.
abs=$file
case "$abs" in
/*) ;;
*) abs=$PWD/$abs ;;
esac
anchor=$(dirname "$abs")
while [ "$anchor" != "/" ] && [ ! -d "$anchor" ]; do anchor=$(dirname "$anchor"); done
[ -d "$anchor" ] || anchor=$PWD
repo=$(git -C "$anchor" rev-parse --show-toplevel 2>/dev/null || true)
[ -n "$repo" ] || exit 0
cd "$repo" 2>/dev/null || exit 0
rel=${abs#"$repo"/}

# Only GUI sources carry translatable strings.
case "$rel" in
rustconn/src/*.rs) ;;
*) exit 0 ;;
esac

[ -f "$rel" ] || exit 0

# No translatable strings -> nothing to keep in sync.
grep -q 'i18n(' "$rel" || exit 0

# Delivery through the report channel, not stdout (see the header). Build the
# message first, emit nothing if there is none.
msg=""
if [ -f po/POTFILES.in ] && ! grep -qxF "$rel" po/POTFILES.in; then
    msg="${msg}translation-sync: ${rel} calls i18n() but is not listed in po/POTFILES.in.
  Its strings will never be extracted. Add it in alphabetical order, then run:
  bash po/update-pot.sh
  (Skip if this is a scratch file about to be deleted — a POTFILES entry pointing
  at a missing file breaks po/update-pot.sh.)
"
fi

if [ -x scripts/check-i18n-escapes.sh ] && ! escapes=$(./scripts/check-i18n-escapes.sh 2>&1); then
    msg="${msg}translation-sync: check-i18n-escapes.sh FAILED
${escapes}
  Put the character directly in the literal instead of a \\u{...} escape
  (ASCII apostrophe is the project convention, cf. the Save prompt in alert.rs).
"
fi

[ -n "$msg" ] || exit 0

report="target/.kiro-session-report"
mkdir -p target 2>/dev/null || exit 0
printf '%s' "$msg" >>"$report" 2>/dev/null || true

exit 0
