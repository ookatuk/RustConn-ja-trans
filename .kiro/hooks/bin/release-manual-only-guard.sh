#!/usr/bin/env bash
# PreToolUse guard on the shell tool: an agent may validate a release, never cut
# one.
#
# `scripts/release.sh` ends with an interactive confirmation and *refuses* to run
# without a TTY unless it is handed `--yes`:
#
#     if [[ ! -t 0 ]]; then
#         fail "stdin is not a TTY — pass --yes to confirm non-interactively"
#     fi
#     read -r -p "Proceed? [y/N] " ans
#
# That is not an obstacle to route around. It is the one point in the process
# where a human decides, and an agent shell has no TTY, so `--yes` is the only
# way an agent ever reaches the merge/tag/push — which is exactly why passing it
# is the thing being forbidden here.
#
# What went wrong once, and is the reason this file exists: v0.20.1 was cut by an
# agent with `./scripts/release.sh --yes`. It merged to main, pushed a tag and
# published a GitHub release with five artifacts — carrying a red CI (the Hygiene
# job, which release.sh did not run at the time) and carrying code deletions the
# maintainer had never seen. Undoing it meant deleting a published release.
#
# Rules:
#   R1  `release.sh` without `--dry-run` is refused.
#   R2  `--yes` / `-y` is refused, with or without `--dry-run`.
#   R3  creating a `v<semver>` tag by hand is refused too, otherwise R1 just
#       moves the problem to `git tag`.
#   R4  `git push` is refused outright — any remote, any ref, tag or branch.
#
# R4 replaced a narrower rule on 2026-09-06 at the maintainer's instruction. It
# used to refuse only a push that carried a version tag, on the reasoning that the
# tag push is the irreversible act. That is true and it was the wrong boundary:
# publishing is the maintainer's call regardless of what is being published, and
# an agent that may push a branch is an agent deciding when work becomes visible
# to CI, to reviewers and to anything watching the remote. Committing stays
# allowed — a local commit is reversible and is where the work is recorded.
#
# `--dry-run` is not merely allowed, it is the expected agent action: it runs
# every gate and stops before the plan is executed.
#
# How invocations are found. lib/command-segments.awk splits the command line
# into simple commands — on `;`, `&&`, `||`, pipes, subshells, `$( … )` — and sees
# through NAME=value assignments, env/timeout/nice/nohup wrappers, `bash -c` and
# `eval`. Flags are then read from that one invocation's own words. Until
# 2026-09-28 both steps were regexes over the whole line, and an audit found the
# gap the hard way: `PATH="$HOME/.cargo/bin:$PATH" ./scripts/release.sh --yes` —
# the very form shell-environment.md prescribes, since release.sh needs cargo on
# PATH — passed, as did `env …` and `timeout …` wrappers; `-h` in a later
# `df -h` counted as release.sh's `--help`; `--dry-run` belonging to one command
# excused another; `-n` in `echo -n` excused a `git push`. Every one of those is a
# row in scripts/test-hooks.sh now. Add a row before you change a rule here.
#
# Fails OPEN on anything unexpected. A guard that blocks every shell call because
# jq changed its output shape would be worse than the problem it prevents. The
# regression suite is what catches a guard that fails open when it should not.

set -uo pipefail

trap 'exit 0' ERR

payload=$(cat) || exit 0
command -v jq >/dev/null 2>&1 || exit 0
command -v awk >/dev/null 2>&1 || exit 0

cmd=$(printf '%s' "$payload" | jq -r '.tool_input.command // ""' 2>/dev/null) || exit 0
[ -n "$cmd" ] || exit 0

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd) || exit 0
segments=$(printf '%s' "$cmd" | awk -f "$here/lib/command-segments.awk" 2>/dev/null) || exit 0
[ -n "$segments" ] || exit 0

block() {
    printf 'release-manual-only-guard: %s\n' "$1" >&2
    shift
    printf '%s\n' "$@" >&2
    exit 2
}

hand_back=(
    ''
    '  Cutting the release is the maintainer'"'"'s action, in the maintainer'"'"'s'
    '  terminal, with the live "Proceed? [y/N]" prompt. Prepare it, validate it,'
    '  report it — then stop and hand over.'
)

# has_word "<args>" <word>... : true when any <word> is one of the words in args.
has_word() {
    local args=" $1 " w
    shift
    for w in "$@"; do
        case "$args" in *" $w "*) return 0 ;; esac
    done
    return 1
}

# A version ref in any of the spellings a push or a tag takes: v1.2.3,
# refs/tags/v1.2.3, HEAD:v1.2.3.
names_version() {
    local w
    local -a words
    read -r -a words <<<"$1"
    for w in "${words[@]}"; do
        [[ $w =~ (^|[:/])v[0-9]+\.[0-9]+\.[0-9]+ ]] && return 0
    done
    return 1
}

# `git tag` that only reads or deletes: listing, verifying, filtering, `-d`.
# Deleting stays allowed because undoing a bad tag needs it.
tag_is_readonly() {
    local w
    local -a words
    read -r -a words <<<"$1"
    for w in "${words[@]}"; do
        case "$w" in
        -l | --list | -d | --delete | -v | --verify | -n | -n[0-9]* | \
            --contains | --contains=* | --no-contains | --no-contains=* | \
            --points-at | --points-at=* | --merged | --merged=* | \
            --no-merged | --no-merged=* | --sort | --sort=* | --format=* | --column*)
            return 0
            ;;
        esac
    done
    return 1
}

while IFS=$'\t' read -r kind first rest; do
    case "$kind" in
    RELEASE)
        args=$first
        # --help prints the header comment and exits 0 before any gate or git
        # operation. Reading the script's own usage is not cutting a release.
        has_word "$args" --help -h && continue

        if has_word "$args" --yes -y; then
            block '--yes on release.sh is never the agent'"'"'s to pass.' \
                '  It exists so a human can confirm non-interactively. An agent shell has no' \
                '  TTY, so passing it is the agent standing in for the person who should be' \
                '  deciding — which is how a release once went out with a red CI and unreviewed' \
                '  code deletions in it.' \
                "${hand_back[@]}"
        fi

        if ! has_word "$args" --dry-run; then
            block 'release.sh without --dry-run performs merge → tag → push.' \
                '  Run the validation instead — it executes every gate and stops before the' \
                '  plan is carried out:' \
                '    PATH="$HOME/.cargo/bin:$PATH" ./scripts/release.sh --dry-run' \
                "${hand_back[@]}"
        fi
        ;;
    GIT)
        verb=$first
        args=$rest
        case "$verb" in
        tag)
            # R3: creating a release tag by hand is the same act release.sh performs.
            if ! tag_is_readonly "$args" && names_version "$args"; then
                block 'creating a release tag by hand is the same action release.sh performs.' \
                    '  Releases go through ./scripts/release.sh so the gates cannot be skipped and' \
                    '  the tag cannot disagree with the version in Cargo.toml and the changelogs.' \
                    "${hand_back[@]}"
            fi
            ;;
        push)
            # R4: `--dry-run` / `-n` shows what would be pushed and updates nothing;
            # it is the push equivalent of `release.sh --dry-run`.
            has_word "$args" --dry-run -n && continue

            # A tag push gets the specific explanation, because the consequence is
            # specific: it is what publishes a release.
            if has_word "$args" --tags --follow-tags || names_version "$args"; then
                block 'pushing a release tag is what publishes the release.' \
                    '  The tag push triggers the Release workflow, the artifact build and the' \
                    '  Flathub/OBS/Snap updates — none of which can be taken back cleanly.' \
                    "${hand_back[@]}"
            fi

            block 'pushing is never the agent'"'"'s action — not a branch, not a tag, not any remote.' \
                '  Commit locally, then hand over. Say what is ready and let the maintainer push,' \
                '  or point at the release path:' \
                '    git push -u origin <branch>      the maintainer'"'"'s call' \
                '    ./scripts/release.sh --dry-run   validate a release, then hand over' \
                '' \
                '  A commit is local and reversible. A push is not: it is the point where work' \
                '  becomes visible to CI, to reviewers and to anything watching the remote, and' \
                '  deciding when that happens belongs to the maintainer.' \
                '  `git push --dry-run` is allowed if you need to show what would go.'
            ;;
        esac
        ;;
    esac
done <<<"$segments"

exit 0
