#!/usr/bin/env bash
# PostToolUse: record every path THIS agent wrote, so later hooks can scope to
# the agent's own work instead of guessing.
#
# Why this replaces hash comparison. The Stop hook used to decide "did this
# session change it?" by comparing a SessionStart content hash against the file
# on disk. That answers a different question — "did anything change it?" — and
# the two answers diverge whenever something else touches the tree: a second Kiro
# session in the same checkout, the maintainer editing in the IDE while an ACP
# session runs, or a hook of our own like translation-sync rewriting every
# po/*.po. On 2026-09-06 that produced five consecutive Stop reports naming 29
# .rs files in a session whose agent wrote nothing at all. Each report cost an
# agent loop to conclude nothing was wrong.
#
# A journal cannot make that mistake: a path is in it because a write tool was
# called on it, which is the actual question every consumer wants answered.
#
# Which tools, and where their paths live. fs_write, fs_append, str_replace and
# semantic_rename carry `path`; delete_file `targetFile`; the KiroGraph write
# tools `file`; smart_relocate `sourcePath` and `destinationPath`, both recorded,
# since a move deletes one file and creates the other. Until 2026-09-28 only the
# first four were matched at all, so moves, renames and KiroGraph edits never
# reached the journal and a journal-scoped `git add` left them out. Two limits
# remain: semantic_rename also rewrites every file that references the symbol,
# and only its own `path` is known here; and shell writes (cargo fmt, msgmerge,
# the repo scripts) are journaled by scripts/lib/journal.sh where the script
# supports it, not by this hook.
#
# Consumers: session-report.sh (leftover scan), commit-review-gate.sh (which
# reviews a change needs), the commit rule in
# core-rules.md (exact `git add` list — never `git add -A`, which in a shared
# checkout would stage another session's half-finished work), and
# scripts/change-inventory.sh (handoff for a fresh verification session).
#
# Reset at SessionStart by session-reset.sh. Append-only within a session,
# deduplicated, order preserved. Silent always; PostToolUse stdout is not
# forwarded to the agent anyway, and a journal is not news.
#
# Fails OPEN: a broken journal must never block or delay a write. Every failure
# path just skips the record.

set -uo pipefail

trap 'exit 0' ERR

payload=$(cat) || exit 0
command -v jq >/dev/null 2>&1 || exit 0

paths=$(printf '%s' "$payload" | jq -r '
    .tool_input | [.path, .targetFile, .file, .sourcePath, .destinationPath]
    | map(select(type == "string" and . != "")) | unique | .[]' 2>/dev/null) || exit 0
[ -n "$paths" ] || exit 0

# record <path>: normalise to repo-relative, the same way crate-boundary-guard.sh
# does and for the same reason: the tools accept absolute or relative paths, and
# every consumer wants one spelling. Anchor at the nearest existing ancestor — for
# delete_file the file is already gone, and for a fresh file its directory may
# not exist yet.
record() {
    local abs=$1 anchor repo_root rel journal
    case "$abs" in
    /*) ;;
    *) abs=$PWD/$abs ;;
    esac

    anchor=$(dirname "$abs")
    while [ "$anchor" != "/" ] && [ ! -d "$anchor" ]; do
        anchor=$(dirname "$anchor")
    done
    [ -d "$anchor" ] || anchor=$PWD

    repo_root=$(git -C "$anchor" rev-parse --show-toplevel 2>/dev/null || true)
    [ -n "$repo_root" ] || return 0

    rel=${abs#"$repo_root"/}
    # Still absolute -> the write landed outside the repo. Not our business.
    case "$rel" in
    /*) return 0 ;;
    esac

    # Never journal our own bookkeeping: the report file and the journal itself
    # are written by hooks, not by the agent.
    case "$rel" in
    target/*) return 0 ;;
    esac

    # The journal lives beside the other session state, under target/:
    # gitignored, visible to sub-agents and to the developer in the same
    # checkout, and wiped by `cargo clean` — acceptable, since a wiped journal
    # only costs one session's scoping. KIRO_EDIT_JOURNAL exists for
    # scripts/test-hooks.sh, so its probe payloads land in a scratch file.
    journal="${KIRO_EDIT_JOURNAL:-$repo_root/target/.kiro-session-edits}"
    mkdir -p "$(dirname "$journal")" 2>/dev/null || return 0

    # Deduplicate. -x so `rustconn/src/lib.rs` does not match
    # `rustconn/src/lib.rs.bak`, -F so a path with regex metacharacters is
    # compared literally.
    if [ -f "$journal" ] && grep -qxF -- "$rel" "$journal" 2>/dev/null; then
        return 0
    fi
    printf '%s\n' "$rel" >>"$journal" 2>/dev/null || return 0
}

while IFS= read -r p; do
    record "$p"
done <<<"$paths"

exit 0
