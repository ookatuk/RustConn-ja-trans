#!/usr/bin/env bash
# Regenerate the Flatpak cargo-sources.json from Cargo.lock and copy it to the
# Flathub manifest, so both offline-vendoring manifests match the lockfile.
#
# Why this exists: the regenerate-then-copy pair was a two-line snippet
# duplicated in `scripts/release.sh`'s failure message, `release-version.md`
# step 8, and `packaging/AGENTS.md`. Every copy is a chance to bump one manifest
# and forget the other — the exact drift `packaging/AGENTS.md` warns about, and
# the exact gate `release.sh` section 11b fails a release on. `cargo update`
# during release preparation invalidates both files, and nothing bridged that
# step to this one, so the first `release.sh --dry-run` after a dependency bump
# reliably failed on a stale cargo-sources.json. Run this straight after
# `cargo update` / `cargo generate-lockfile` and the gate stays green.
#
# It does NOT do git. No add, no commit — same contract as bump-version.sh. The
# merge/tag/push is scripts/release.sh, run by the maintainer.
#
# Needs python3 and network (the generator fetches per-crate checksums). On a
# box without either — a macOS release host, say — this cannot run, which is why
# `release.sh`'s check degrades to a warning there rather than a hard failure;
# regenerate on Linux before handing the release over.
#
# Usage:
#   scripts/sync-cargo-sources.sh            regenerate + copy
#   scripts/sync-cargo-sources.sh --check    verify both match Cargo.lock without
#                                            writing (exit 1 if stale)

set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

CHECK=0
for arg in "$@"; do
    case "$arg" in
    --check) CHECK=1 ;;
    -h | --help)
        sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *)
        printf 'unknown option: %s (see --help)\n' "$arg" >&2
        exit 2
        ;;
    esac
done

FCG="packaging/flatpak/flatpak-cargo-generator.py"
FLATPAK_SOURCES="packaging/flatpak/cargo-sources.json"
FLATHUB_SOURCES="packaging/flathub/cargo-sources.json"

# The paths are the single source of truth here; release.sh section 11b greps
# the same two files, so keep the names in step if they ever move.
[ -f "$FCG" ] || {
    printf 'FAIL: %s not found\n' "$FCG" >&2
    exit 1
}
[ -f Cargo.lock ] || {
    printf 'FAIL: Cargo.lock not found — run from a checked-out workspace\n' >&2
    exit 1
}
command -v python3 >/dev/null 2>&1 || {
    printf 'FAIL: python3 is not installed — cannot run the generator\n' >&2
    exit 1
}

if [ "$CHECK" -eq 1 ]; then
    tmp=$(mktemp) || exit 1
    trap 'rm -f "$tmp"' EXIT
    if ! python3 "$FCG" Cargo.lock -o "$tmp" >/dev/null 2>&1; then
        printf 'WARN: generator failed (most likely no network) — cannot verify\n' >&2
        exit 0
    fi
    stale=0
    if ! diff -q "$tmp" "$FLATPAK_SOURCES" >/dev/null 2>&1; then
        printf 'stale: %s does not match Cargo.lock\n' "$FLATPAK_SOURCES" >&2
        stale=1
    fi
    if ! diff -q "$tmp" "$FLATHUB_SOURCES" >/dev/null 2>&1; then
        printf 'stale: %s does not match Cargo.lock\n' "$FLATHUB_SOURCES" >&2
        stale=1
    fi
    if [ "$stale" -eq 0 ]; then
        printf 'OK: both cargo-sources.json match Cargo.lock\n'
        exit 0
    fi
    printf 'Regenerate with: %s\n' "$0" >&2
    exit 1
fi

printf 'Regenerating %s from Cargo.lock...\n' "$FLATPAK_SOURCES"
if ! python3 "$FCG" Cargo.lock -o "$FLATPAK_SOURCES"; then
    printf 'FAIL: generator failed (network? python deps?)\n' >&2
    exit 1
fi
cp "$FLATPAK_SOURCES" "$FLATHUB_SOURCES"
printf 'Wrote %s and copied it to %s\n' "$FLATPAK_SOURCES" "$FLATHUB_SOURCES"
printf 'Both manifests now match Cargo.lock. Commit them with the version bump.\n'

# Record both regenerated files in the agent edit journal, so a journal-scoped
# `git add` stages them with the version bump instead of leaving them behind.
if [ -f scripts/lib/journal.sh ]; then
    . scripts/lib/journal.sh
    journal_add "$FLATPAK_SOURCES" "$FLATHUB_SOURCES"
fi
