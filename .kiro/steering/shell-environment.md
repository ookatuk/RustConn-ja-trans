---
inclusion: always
---
# Shell Environment

`inclusion: always` on purpose — terminal discipline is cheap to carry and
expensive to omit. This file holds the **rules only**. Every measurement, war
story and worked example behind them is in `shell-environment-why.md`
(`inclusion: manual`, load with `#shell-environment-why`); read it once, or when a
rule here looks arbitrary. Nothing is duplicated between the two.

If you ever set a steering file to `inclusion: auto`, give it both `name` and
`description` — without them it matches nothing and silently never loads.

## Terminal profile

`bash --noprofile --norc` with PATH injected by the terminal profile:

- No `.bashrc`, `.profile` or `/etc/profile` is sourced
- `~/.local/bin/` in PATH (`uv`, `pipx`, `kiro-cli`, user scripts)
- `direnv` is **not** active

**`~/.cargo/bin` is not in PATH.** Not "unreliably", not "only for sub-agents" —
it is absent, so a bare `cargo`, `rustfmt`, `clippy` or `typos` is
`command not found` in the main agent's own bash. Always write the absolute path.

That sentence used to read "sub-agents do not reliably inherit that PATH", which
put the blame in the wrong place and cost a misdiagnosis: a `release.sh` run
failing with `[fail] Missing tool: cargo` was written off as a `nohup`/`sh`
quirk. Measured, `$PATH` is byte-identical in bash, in `sh -c` and under
`nohup sh -c`; none of them has `~/.cargo/bin`. A sub-agent reporting
`cargo: command not found` is the same single cause, not a second one.

| Tool | Path |
|------|------|
| cargo | `~/.cargo/bin/cargo` |
| typos | `~/.cargo/bin/typos` |
| gh | system, authenticated |
| flatpak-builder | system |
| kirograph | `~/.local/bin/kirograph` (when `.kirograph/` exists) |

`typos` is in that table because `AGENTS.md` and `core-rules.md` both list the
Definition-of-Done gate as a bare `typos`. Unlike a missing `cargo`, a missing
`typos` does not stop anything: it looks like a gate that ran and found nothing.

**A script that calls `cargo` itself needs the PATH prepended**, because the
absolute path cannot be written on its behalf. `scripts/release.sh` is the one
that matters, and it fails its very first gate without it:

```bash
PATH="$HOME/.cargo/bin:$PATH" ./scripts/release.sh --dry-run
```

Left as the caller's job on purpose. `release.sh` refusing to run when `cargo` is
not on PATH is correct — a release should build with the toolchain the operator
put there, not one a script went looking for.

## Multiline text in shell commands

**Never pass multiline text inline** (e.g. `--body '…'` with newlines). Write it to
a temp file with `fs_write`, pass the file (`gh issue comment --body-file …`), then
delete the file.

## Terminal discipline

- **Never pipe cargo output** through `tail`, `grep`, `head` or any filter.
  Redirect to a file and read the file.
- **Logs go under `target/`, not `/tmp`** — gitignored, visible to sub-agents and
  to the developer in the same checkout, and they survive the session. `cargo
  clean` wipes them, so copy a log you still need first.
- **One cargo at a time.** `pgrep -f cargo` before any build or test.
- **One terminal owner.** Do not run bash while a sub-agent is working.
- **Stop background processes when done.** `list_processes`, then stop what you
  started.
- **The shell tool can lose its working directory** between calls. Start anything
  that depends on the repo root with
  `cd /home/totoshko88/Documents/RustConn || exit 1`.
- **No `rc=` line twice in a row** — the terminal is busy or wedged. Stop sending
  it commands; read the log with the file-reading tool, or start a fresh terminal
  (option 4 below).
- **A full `cargo test --workspace` is ~2.5 min wall** (~1m49s compile + ~45s of
  tests); `verify.sh --tests` takes about 4 min, because it cleans the workspace
  crates first. That is normal, not a hang. The run's own `test result:` lines
  give the count — do not write one into a rule, it goes stale.
- **Never wait with `sleep`.** A sleep cannot observe another terminal, and if the
  terminal is busy the line queues behind the running job instead of executing.
- **Pass an explicit `timeout`** to any cargo build or test — the tool default is
  120 000 ms, below the measured wall time. Use `timeout=900000`. Not 180 000;
  that is also below it.

The `bash-serialization-guard` hook enforces the five of these that are
mechanically checkable: sleep waiting, piped cargo output, a second concurrent
cargo, a second `verify.sh`/`release.sh` runner, and a cargo run without timeout
headroom; `scripts/test-hooks.sh` asserts each one. It fails open — a faster
failure, never a substitute for knowing the rules.

## Waiting without blocking the terminal

**Once a terminal has a live foreground job, it is not yours.** Do not send it
another command — not a status check, not an `echo`, not a `^C`. Read the log file.

**Wait for a command's own output before sending the next one — the tool
returning is not the command finishing.** A `cargo` build or test regularly
returns to you with an empty body while the process is still alive in the tty.
Firing the next command then queues it behind the running one, its output lands
interleaved or lost, and you end up reasoning from a half-finished run — the exact
mistake that made a fully green `verify.sh` look ambiguous and cost a round of
re-runs.

**`Exit Code: -1` carries no information here.** This client reports it on
nearly every call, finished or not — measured 2026-09-28, `echo done` printed its
line and still came back `-1`. It means neither "timed out" nor "failed". The
completion signal is one you put in the command yourself: end it with
`; echo "rc=$?"`. An `rc=` line in the output means the command finished and
gives its real status; no `rc=` line means it was still running when the tool
returned. For anything long, the `.rc` sentinel file (option 2) is the signal.
Never treat `-1`, empty output or a prompt line as completion, and never send a
follow-up command on that assumption — read the log or the `.rc` file. Read it in
a *later* call than the one that writes it: a read issued in the same parallel
batch can run first and find nothing.

Waiting on a background PID with `tail --pid=<pid> -f /dev/null` (or `wait`) is
**not** a way around this: the call still returns with an empty body while the
process runs on, and burns a call each time. The `.rc` sentinel is the completion
signal — read it (option 2), do not spin on the PID.

Four ways out, cheapest first.

**1. Wait inside the one tool call.** Right for anything that finishes in a
minute or two.

```bash
cd /home/totoshko88/Documents/RustConn || exit 1
~/.cargo/bin/cargo test --workspace > target/rc-test.log 2>&1; echo "rc=$?"
```

with `timeout=900000`, then read `target/rc-test.log` (the file-reading tool takes
line ranges, so a 20 k-line log costs nothing). No `rc=` line in the output means
the call came back early — carry on as in option 2 and read the log.

**2. Take a handle when you want to keep working.** Poll the filesystem, never the
clock — the run is done exactly when the `.rc` file appears.

```bash
cd /home/totoshko88/Documents/RustConn || exit 1
rm -f target/rc-test.log target/rc-test.rc
nohup sh -c 'cargo test --workspace > target/rc-test.log 2>&1; echo $? > target/rc-test.rc' >/dev/null 2>&1 &
```

Pass `timeout=900000` here too: the call returns immediately so it is never
reached, but the guard cannot tell a detached run from a foreground one and blocks
the form without it.

**3. Delegate.** `rust-quality-check` runs `verify.sh` detached and polls its
`.rc` with the file-reading tool, so a long run costs you one call. It does **not**
get a terminal of its own — sub-agents share the main one (`project-rules.md`), so
delegating does not escape a wedged tty; that is what option 4 is for.

**4. Start it in its own terminal with `control_bash_process`.** Reach for this
when the main shell tty has *wedged* — not merely returned `Exit Code: -1`, but
stopped running anything: a redirect that should create a file leaves none, and
option 2's `nohup … & echo $? > …rc` never even writes its log, because the queued
line is sitting in a busy tty and has not run yet. `control_bash_process` opens a
fresh terminal that does not share that buffer, so the run actually starts.

```
control_bash_process(action="start",
  command="cd /home/totoshko88/Documents/RustConn && rm -f target/rc-test.log target/rc-test.rc && PATH=\"$HOME/.cargo/bin:$PATH\" cargo test --workspace > target/rc-test.log 2>&1; echo $? > target/rc-test.rc")
```

Poll `target/rc-test.rc` with the file-reading tool exactly as in option 2, or read
progress with `get_process_output`; `stop` the terminal when the `.rc` appears. It
runs cargo directly rather than through the main shell, so **prepend the PATH
yourself** — `~/.cargo/bin` is not on it (see the terminal-profile section). The
tool warns that the command "does not appear to be a long-running process"; for a
cargo build or a `verify.sh` run that warning is wrong — proceed. This is what
recovered a wedged tty on 2026-09-28 after a queued `nohup verify.sh` refused to
start; note the queued copy can still fire later, so R5 in
`bash-serialization-guard` now refuses a second runner (see `hooks-map.md`).

## Cargo traps in this workspace

`scripts/verify.sh` exists precisely to keep you out of the two traps below: it
forces a real clippy re-check and never passes `--all-features`. Prefer it (see
`core-rules.md` Quick Commands) over a hand-assembled cargo chain — an inline
`sh -c` gate also trips on `${PIPESTATUS}` under `/bin/sh`, which the script,
being `#!/usr/bin/env bash`, does not.

- **A cached clippy run hides warnings.** With nothing changed it prints
  `Finished … in 0.2s` and reports zero warnings *even when warnings exist*. Force
  a real re-check (`touch` the `.rs` files, or `cargo clean -p <crate>`) and
  confirm from the output that compilation happened.
- **Never `--all-features`.** It enables a gtk3 path that fails on missing
  `gdk-3.0.pc`. Use `--all-targets`.

## Never judge GUI behaviour from an app launched in this terminal

A `cargo run -p rustconn` started here produces a process the desktop portal
refuses (`Unable to open /proc/<pid>/root`). Two measured consequences: a
`GtkFileDialog` **never completes** — no result, no error, no `Dismissed`, no
warning, indistinguishable from an unwired button — and light/dark plus the icon
theme resolve wrongly, because the portal is where they come from.

This terminal is fine for `cargo build`, `clippy` and `test`. It is **not evidence**
about anything a portal touches: file choosers, the light/dark preference, the icon
theme, screen casting, notifications, the monitor list. Reproduce that class of bug
in an ordinary terminal before chasing it.

Corollary worth keeping: **when a GTK callback can fail three ways, log all three.**
The absence of a line is then evidence too.
