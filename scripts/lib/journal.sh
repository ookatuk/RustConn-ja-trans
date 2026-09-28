#!/usr/bin/env bash
# journal_add: record files a script wrote into the agent edit journal, the same
# one .kiro/hooks/bin/edit-journal.sh keeps for the write tools.
#
# Why a script needs this at all. The journal is the scope for the commit rule's
# `git add` (never `git add -A` in a checkout shared with the IDE), for
# commit-review-gate, and for the Stop report. The PostToolUse hook only sees the
# built-in write tools, so anything a *script* rewrites — bump-version.sh across
# 19 packaging files, po/update-pot.sh regenerating the template, the two
# cargo-sources.json — is invisible to it. On 2026-09-28 a release prep left all
# of those out of the journal, so a journal-scoped commit would have dropped the
# POT and the packaging bumps. A script that writes tracked files calls this so
# they are staged with the rest of the change.
#
# Contract, matching edit-journal.sh: repo-relative paths, deduplicated, anything
# under target/ skipped, silent, and it never fails its caller — a journal is
# bookkeeping, not the job. Honours KIRO_EDIT_JOURNAL so scripts/test-hooks.sh
# and a dry run can redirect it.
#
# Usage:  . scripts/lib/journal.sh ;  journal_add path [path...]
# Only records on a real write: a caller in --check/--dry-run mode must not call
# it, because nothing changed on disk.

journal_add() {
    local repo journal p abs rel
    repo=$(git rev-parse --show-toplevel 2>/dev/null) || return 0
    journal="${KIRO_EDIT_JOURNAL:-$repo/target/.kiro-session-edits}"
    mkdir -p "$(dirname "$journal")" 2>/dev/null || return 0

    for p in "$@"; do
        [ -n "$p" ] || continue
        abs=$p
        case "$abs" in
        /*) ;;
        *) abs=$PWD/$abs ;;
        esac
        rel=${abs#"$repo"/}
        case "$rel" in
        /* | target/*) continue ;; # outside the repo, or our own bookkeeping
        esac
        if [ -f "$journal" ] && grep -qxF -- "$rel" "$journal" 2>/dev/null; then
            continue
        fi
        printf '%s\n' "$rel" >>"$journal" 2>/dev/null || return 0
    done
}
