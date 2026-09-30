#!/usr/bin/env bash
# PreToolUse on the shell tool: at `git commit`, if the edit journal contains a
# behavioural source change (a non-test .rs under a crate's src/) but CHANGELOG.md
# is NOT in the journal, ask whether the CHANGELOG entry was intentionally
# skipped.
#
# Why this exists. Every fix in the 0.22.12 audit-fix pass needed a matching
# CHANGELOG entry, and keeping them in step was a purely manual discipline
# repeated commit after commit — exactly the kind of deterministic obligation a
# command hook should carry instead of a human. The project's changelog-format.md
# documents that every user-visible change gets an entry.
#
# `ask`, never a block, and the same reasoning as commit-review-gate: a code-only
# internal refactor legitimately needs no CHANGELOG entry, and a guard cannot tell
# a refactor from a behaviour change. So it surfaces the question once, at the
# commit, and lets the human decide. It also stays quiet for changes that are
# obviously not user-visible on their own — test files and pure doc-comment churn
# are excluded from what counts as "behavioural".
#
# Scope comes from target/.kiro-session-edits (bin/edit-journal.sh) — the paths
# this agent wrote — never the dirty tree, so another session's edits do not
# trigger it. Same command-segment parser as commit-review-gate / the release
# guard, so `GIT_EDITOR=… git commit` and `git add … && git commit` are seen.
#
# Fails OPEN: no journal, no jq, no git, nothing recognised -> allow.

set -uo pipefail

trap 'exit 0' ERR

payload=$(cat) || exit 0
command -v jq >/dev/null 2>&1 || exit 0

cmd=$(printf '%s' "$payload" | jq -r '.tool_input.command // ""' 2>/dev/null) || exit 0
[ -n "$cmd" ] || exit 0

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd) || exit 0
committing=0
while IFS=$'\t' read -r kind verb args; do
    [ "$kind" = GIT ] && [ "$verb" = commit ] || continue
    case " $args " in *" --dry-run "*) continue ;; esac
    committing=1
done < <(printf '%s' "$cmd" | awk -f "$here/lib/command-segments.awk" 2>/dev/null)
[ "$committing" -eq 1 ] || exit 0

repo=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
journal="${KIRO_EDIT_JOURNAL:-$repo/target/.kiro-session-edits}"
[ -s "$journal" ] || exit 0

# A behavioural source change: a .rs under some crate's src/, excluding test
# files (tests/ dir, *_tests.rs, mod tests) which do not themselves ship a
# user-visible change worth a CHANGELOG line on their own.
has_src_change=0
while IFS= read -r path; do
    case "$path" in
    */tests/*) continue ;;
    *_tests.rs) continue ;;
    esac
    if printf '%s' "$path" | grep -qE '^[^/]*/src/.*\.rs$|^src/.*\.rs$'; then
        has_src_change=1
        break
    fi
done <"$journal"
[ "$has_src_change" -eq 1 ] || exit 0

# CHANGELOG touched in the same session? Then nothing to ask.
if grep -qxF 'CHANGELOG.md' -- "$journal" 2>/dev/null; then
    exit 0
fi

reason="This commit changes source code (a non-test .rs under a crate's src/) but CHANGELOG.md is not among this session's edits. The project keeps a CHANGELOG entry per user-visible change (changelog-format.md). Add an entry under the [Unreleased] section, or confirm this is an internal-only change (refactor/test) that needs none. Scope is the agent's own edits from target/.kiro-session-edits, not the dirty tree."

jq -cn --arg r "$reason" \
    '{hookSpecificOutput:{permissionDecision:"ask",permissionDecisionReason:$r}}' 2>/dev/null ||
    exit 0

exit 0
