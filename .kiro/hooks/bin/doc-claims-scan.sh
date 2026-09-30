#!/usr/bin/env bash
# PostFileSave check for Rust sources: flag doc-comment claims that reference a
# `snake_case` identifier which does not exist as a definition anywhere in the
# two source crates.
#
# Why this exists. The 0.22.12 audit found three doc claims that named things the
# code did not have: the `search` module advised using `search_parallel` (no such
# function), a `PropertyType::Url` claim about clickable rendering (not
# implemented), and a module header promising "all downloads are verified using
# SHA256" for a path that skipped the check. The compiler and clippy never catch
# this — a doc comment is not type-checked against the code it describes. This is
# the "class C" gap from the audit: the doc lies and nothing notices.
#
# Scope is deliberately narrow to keep the false-positive rate low:
#   - only doc comments (`///` or `//!`), never ordinary comments or code;
#   - only backticked `snake_case` identifiers of >= 4 chars (skips `id`, `ok`);
#   - flagged only when NO `fn`/`struct`/`enum`/`const`/`trait`/`type`/`macro`
#     definition of that name exists in rustconn-core/src or rustconn/src.
# A method-only or field-only name will false-positive; that is why this is a
# NOTE to the session report, never a block. A human reads it next turn at zero
# model cost.
#
# Reads the PostFileSave JSON on stdin. Silent and exit 0 when clean.
#
# Delivery goes through target/.kiro-session-report, NOT stdout: a command hook's
# stdout is forwarded to the agent only on SessionStart, UserPromptSubmit and
# PreToolUse, and this fires on PostFileSave, where it is discarded. This is the
# same shared-report contract translation-sync.sh and flatpak-manifest-check.sh
# use; session-report.sh flush prints it on the next UserPromptSubmit.
#
# Fails OPEN: no jq, no git, no rg, unreadable file -> allow, say nothing.

set -uo pipefail

trap 'exit 0' ERR

payload=$(cat) || exit 0
command -v jq >/dev/null 2>&1 || exit 0

file=$(printf '%s' "$payload" | jq -r '.file_path // ""' 2>/dev/null) || exit 0
[ -n "$file" ] || exit 0

# Anchor at the git root the way translation-sync.sh / edit-journal.sh do.
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

# Only Rust sources carry doc comments we can check against Rust definitions.
case "$rel" in
*.rs) ;;
*) exit 0 ;;
esac

[ -f "$rel" ] || exit 0

# Search roots: the two source crates. A definition anywhere in them clears the
# claim (a public API referenced cross-crate is legitimate).
roots=()
[ -d "$repo/rustconn-core/src" ] && roots+=("$repo/rustconn-core/src")
[ -d "$repo/rustconn/src" ] && roots+=("$repo/rustconn/src")
[ "${#roots[@]}" -gt 0 ] || exit 0

msg=""
# Collect the backticked snake_case identifiers that appear in doc comments.
# `grep` for doc-comment lines, then pull each `token` out of them.
while IFS= read -r ident; do
    [ -n "$ident" ] || continue
    # Definition keywords cover the Rust item kinds a doc comment would name.
    # grep -rE (not rg): ripgrep is not guaranteed on the hook's PATH; grep is.
    if ! grep -rhoE "\\b(fn|struct|enum|const|static|trait|type|macro_rules!)[[:space:]]+${ident}\\b" \
        "${roots[@]}" 2>/dev/null | grep -q .; then
        msg="${msg}doc-claims: ${rel} doc comment mentions \`${ident}\` but no fn/struct/enum/const/trait/type/macro of that name exists in rustconn-core/src or rustconn/src. Verify the doc still matches the code.
"
    fi
done < <(
    grep -nE '^[[:space:]]*//[/!]' "$rel" 2>/dev/null |
        grep -oE '`[a-z][a-z0-9_]{3,}`' 2>/dev/null |
        tr -d '`' | sort -u
)

[ -n "$msg" ] || exit 0

report="target/.kiro-session-report"
mkdir -p target 2>/dev/null || exit 0
printf '%s' "$msg" >>"$report" 2>/dev/null || true

exit 0
