# command-segments.awk: find the simple commands in a shell command line that
# the hook guards care about, however they are wrapped.
#
# Input:  the command line on stdin (it may span several lines).
# Output: one line per simple command whose program is release.sh or git:
#     RELEASE<TAB> arg arg ...       a release.sh invocation
#     GIT<TAB>verb<TAB> arg arg ...  a git invocation; verb = first non-option word
# Args are the words after the program (after the verb for git), quotes removed,
# each preceded by one space, so a caller can test " --yes " as a whole word.
#
# What it sees through: `;` `&&` `||` `|` `&` `(` `)` `{` `}`, backquotes and
# newlines outside quotes; `$( … )` and backquotes inside double quotes;
# NAME=value assignments; the wrappers env, nohup, exec, time, command, builtin,
# setsid, stdbuf, sudo, doas, nice and timeout; bash/sh/dash/zsh running a
# script; and the body of any `-c '…'` and of `eval …`, which is analysed again
# as a command line of its own.
#
# What it is not: a shell. Variable expansion, aliases, functions and
# here-documents are out of scope. The guards that use it fail open, so a
# construct this misses calls for a new row in scripts/test-hooks.sh, not for a
# cleverer parser.
#
# Written for POSIX awk (mawk is Ubuntu's default): no recursion, no gawk
# extensions. Re-analysis goes through a small queue instead of recursion.

function trim(s) {
    sub(/^[ \t\r\n]+/, "", s)
    sub(/[ \t\r\n]+$/, "", s)
    return s
}

function enqueue(s) {
    if (qn < 32) queue[++qn] = s
}

# Split `s` into seg[1..nseg] on unquoted separators. Quotes stay in the text,
# and a newline inside quotes becomes `;`, so a quoted `-c` body that spans lines
# is split once it is analysed again.
function split_segments(s,    n, i, k, c, q, cur, prev, nxt, depth, inner, ch) {
    n = length(s); q = ""; cur = ""; nseg = 0
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (q != "") {
            if (q == "\"" && c == "$" && substr(s, i + 1, 1) == "(") {
                depth = 0; inner = ""
                for (k = i + 2; k <= n; k++) {
                    ch = substr(s, k, 1)
                    if (ch == "(") depth++
                    else if (ch == ")") { if (depth == 0) break; depth-- }
                    inner = inner ch
                }
                enqueue(inner)
                cur = cur substr(s, i, k - i + 1)
                i = k
                continue
            }
            if (q == "\"" && c == "`") {
                k = index(substr(s, i + 1), "`")
                if (k > 0) {
                    enqueue(substr(s, i + 1, k - 1))
                    cur = cur substr(s, i, k + 1)
                    i = i + k
                    continue
                }
            }
            if (c == "\\" && q == "\"" && i < n) { cur = cur c substr(s, i + 1, 1); i++; continue }
            if (c == q) q = ""
            else if (c == "\n") c = ";"
            cur = cur c
            continue
        }
        if (c == "\\" && i < n) { cur = cur c substr(s, i + 1, 1); i++; continue }
        if (c == "'" || c == "\"") { q = c; cur = cur c; continue }
        if (c == "&") {
            prev = (i > 1) ? substr(s, i - 1, 1) : ""
            nxt = (i < n) ? substr(s, i + 1, 1) : ""
            # 2>&1, >&2, &> and &>> are redirections, not separators.
            if (prev == ">" || prev == "<" || nxt == ">") { cur = cur c; continue }
        }
        if (index(";&|(){}`\n", c) > 0) { seg[++nseg] = cur; cur = ""; continue }
        cur = cur c
    }
    seg[++nseg] = cur
}

# Split one segment into w[1..nw], removing quotes.
function split_words(s,    n, i, c, q, cur, inword) {
    n = length(s); q = ""; cur = ""; nw = 0; inword = 0
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (q == "'") {
            if (c == "'") q = ""
            else cur = cur c
            continue
        }
        if (q == "\"") {
            if (c == "\\" && i < n) { cur = cur substr(s, i + 1, 1); i++; continue }
            if (c == "\"") q = ""
            else cur = cur c
            continue
        }
        if (c == "'" || c == "\"") { q = c; inword = 1; continue }
        if (c == "\\" && i < n) { cur = cur substr(s, i + 1, 1); i++; inword = 1; continue }
        if (c == " " || c == "\t") {
            if (inword) { w[++nw] = cur; cur = ""; inword = 0 }
            continue
        }
        cur = cur c; inword = 1
    }
    if (inword) w[++nw] = cur
}

function join_from(k,    out, a) {
    out = ""
    for (a = k; a <= nw; a++) out = out " " w[a]
    return out
}

function analyse(s,    j, i, t, a, noexec) {
    split_segments(s)
    for (j = 1; j <= nseg; j++) {
        split_words(trim(seg[j]))
        # Every `-c <body>` runs <body>: bash -c, sh -c, nohup sh -c, script -c.
        for (t = 1; t < nw; t++) if (w[t] == "-c") enqueue(w[t + 1])
        i = 1; noexec = 0
        while (i <= nw) {
            if (w[i] ~ /^[A-Za-z_][A-Za-z0-9_]*=/) { i++; continue }
            # `command -v x` and `command -V x` look a name up; they run nothing.
            if (w[i] == "command" && (w[i + 1] == "-v" || w[i + 1] == "-V")) { i = nw + 1; break }
            if (w[i] ~ /^(nohup|exec|time|command|builtin|setsid|stdbuf|sudo|doas)$/) {
                i++
                while (i <= nw && w[i] ~ /^-/) i++
                continue
            }
            if (w[i] == "env") {
                i++
                while (i <= nw && (w[i] ~ /^-/ || w[i] ~ /^[A-Za-z_][A-Za-z0-9_]*=/)) {
                    if (w[i] == "-u" || w[i] == "-C" || w[i] == "-S") i++
                    i++
                }
                continue
            }
            if (w[i] == "nice") {
                i++
                while (i <= nw && w[i] ~ /^-/) { if (w[i] == "-n") i++; i++ }
                continue
            }
            if (w[i] == "timeout") {
                i++
                while (i <= nw && w[i] ~ /^-/) { if (w[i] == "-s" || w[i] == "-k") i++; i++ }
                i++  # the duration
                continue
            }
            if (w[i] ~ /^(bash|sh|dash|zsh)$/) {
                i++
                while (i <= nw && w[i] ~ /^-/) {
                    # -c: the body was queued above. -n: parse only, run nothing.
                    if (w[i] == "-c" || w[i] == "-n") noexec = 1
                    i++
                }
                if (noexec) i = nw + 1
                continue
            }
            if (w[i] == "eval") { enqueue(join_from(i + 1)); i = nw + 1 }
            break
        }
        if (i > nw) continue
        if (w[i] ~ /(^|\/)release\.sh$/) {
            printf "RELEASE\t%s\n", join_from(i + 1)
            continue
        }
        if (w[i] ~ /(^|\/)git$/) {
            a = i + 1
            # git's own options come before the verb; -C and -c take a value.
            while (a <= nw && w[a] ~ /^-/) {
                if (w[a] == "-C" || w[a] == "-c") a++
                a++
            }
            if (a <= nw) printf "GIT\t%s\t%s\n", w[a], join_from(a + 1)
        }
    }
}

{ buf = (NR > 1) ? buf "\n" $0 : $0 }

END {
    qn = 0; qi = 0
    enqueue(buf)
    while (qi < qn) analyse(queue[++qi])
}
