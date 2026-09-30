//! `KeePass` integration status detection
//!
//! This module provides functionality to detect the status of `KeePass` integration,
//! including `KeePassXC` installation detection, version parsing, and KDBX file validation.

// Allow missing errors documentation - status detection functions have straightforward errors
#![allow(
    clippy::missing_errors_doc,
    reason = "module-wide override for legacy code; refactored case by case"
)]

use std::path::Path;
use std::process::{Child, Command, Output};
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};

use crate::error::{SecretError, SecretResult};
use crate::proc::{Waited, wait_bounded};

/// How long any single `keepassxc-cli` invocation is given before it is killed.
///
/// Every invocation in this module used an unbounded `wait_with_output`, at a
/// dozen call sites, against a project that bounds a credential resolution at
/// 30 s overall and every other vault operation at 10 s. `keepassxc-cli` opens
/// the database on each run, so it can block on a locked file, on a network
/// share that has gone away, or on a KDBX whose Argon2 parameters are hostile —
/// and until 0.21.0 the answer to any of those was that the calling thread never
/// came back. Only the bulk-transfer path in the GUI wrapped these calls, which
/// bounded the transfer rather than the child.
///
/// Ten seconds is the project's standard vault budget, and the value the Secret
/// Service wrapper in `keyring.rs` uses for the same reason: far longer than a
/// healthy run, short enough to fail while the user is still watching.
const KEEPASSXC_TIMEOUT: Duration = Duration::from_secs(10);

/// The budget for an invocation that *writes* to the database.
///
/// Longer than [`KEEPASSXC_TIMEOUT`] because the consequence of expiry is worse,
/// not because a write is expected to be slower. A read that is killed costs a
/// lookup; a `SIGKILL` delivered to `add`, `mkdir` or `rm` lands in the middle of
/// rewriting the KDBX. So the mutating calls get the 30 s credential-resolution
/// tier, and the trade is deliberate: a longer wait in exchange for a much
/// smaller window in which the database can be interrupted mid-write.
///
/// The KDF cost is paid *per invocation*, because every `keepassxc-cli` run
/// reopens the database — so a KDBX with KeePassXC's high-security Argon2
/// settings does not overrun once, it overruns at every call site. A single save
/// is four invocations (the group check, the parent-group check, the delete and
/// the add), each paying it in full.
const KEEPASSXC_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The budget for a *read* invocation that also waits on a YubiKey touch.
///
/// A Challenge-Response unlock (`-y <slot>`) blocks until the user physically
/// touches the key, and a touch-required slot is the common configuration. The
/// standard [`KEEPASSXC_TIMEOUT`] of 10 s is measured for the KDF alone and is
/// too short once a human has to notice the key blink and reach for it, so a
/// `-y` read gets a longer budget. It stays well under a minute so a genuinely
/// stuck run (unplugged key, wrong slot) still fails while the user is watching.
const KEEPASSXC_YUBIKEY_TIMEOUT: Duration = Duration::from_secs(30);

/// Appends the shared credential-unlock arguments to a `keepassxc-cli` argv.
///
/// One place for the three that every DB-opening invocation shares, so the
/// readers cannot drift apart on how they compose:
/// - `--no-password` when there is no master password (key file and/or YubiKey
///   only), because the CLI otherwise still reads an empty line from stdin as an
///   empty password;
/// - `--key-file <path>` when a key file is configured;
/// - `-y <slot[:serial]>` when a YubiKey Challenge-Response slot is configured.
///
/// The slot is not a secret (a slot number and serial identify the key, they do
/// not authenticate as it), so it goes on the command line; the master password
/// never does — it stays on stdin at the call site.
fn push_unlock_args(
    args: &mut Vec<String>,
    has_password: bool,
    key_file: Option<&Path>,
    yubikey_slot: Option<&str>,
) {
    if !has_password && (key_file.is_some() || yubikey_slot.is_some()) {
        args.push("--no-password".to_string());
    }
    if let Some(kf) = key_file {
        args.push("--key-file".to_string());
        args.push(kf.display().to_string());
    }
    if let Some(slot) = yubikey_slot {
        args.push("-y".to_string());
        args.push(slot.to_string());
    }
}

/// Assembles the argv for a `keepassxc-cli add`, without spawning anything.
///
/// Extracted from [`KeePassStatus::save_password_to_kdbx`] so the write path's
/// unlock composition — the `-y <slot>` that issue #350 found missing, and the
/// `--no-password` that must accompany a key-file/YubiKey-only unlock — can be
/// asserted in a unit test, the way the read side is exercised through
/// [`push_unlock_args`]. The entry password is not here: it travels on stdin, so
/// it never reaches the argv this builds.
fn build_add_args(
    has_password: bool,
    key_file: Option<&Path>,
    yubikey_slot: Option<&str>,
    username: &str,
    url: Option<&str>,
    kdbx_path: &Path,
    entry_path: &str,
) -> Vec<String> {
    let mut args = vec!["add".to_string(), "-q".to_string()];

    // Compose --no-password / --key-file / -y consistently with the read path.
    push_unlock_args(&mut args, has_password, key_file, yubikey_slot);

    // Add username if not empty
    if !username.is_empty() {
        args.push("-u".to_string());
        args.push(username.to_string());
    }

    // Add URL if provided
    if let Some(u) = url
        && !u.is_empty()
    {
        args.push("--url".to_string());
        args.push(u.to_string());
    }

    // Password prompt flag — tells keepassxc-cli to read the entry password from stdin.
    args.push("-p".to_string());

    // Database path and entry name last.
    args.push(kdbx_path.display().to_string());
    args.push(entry_path.to_string());

    args
}

/// Waits for a `keepassxc-cli` child, reporting a timeout as an error.
///
/// `what` names the invocation in the log and in the error. It is
/// `&'static str` on purpose: it is user-visible, and a `&str` would let a
/// caller interpolate an entry name — or a credential — into it.
fn wait_for_cli(child: Child, what: &'static str) -> SecretResult<Output> {
    wait_for_cli_with(child, what, KEEPASSXC_TIMEOUT)
}

/// [`wait_for_cli`] with the write budget, for an invocation that modifies the
/// database.
fn wait_for_cli_write(child: Child, what: &'static str) -> SecretResult<Output> {
    wait_for_cli_with(child, what, KEEPASSXC_WRITE_TIMEOUT)
}

/// [`wait_for_cli`] with the YubiKey budget, for a read that waits on a touch.
///
/// A `-y` unlock cannot complete until the key is touched, so it gets the longer
/// [`KEEPASSXC_YUBIKEY_TIMEOUT`] instead of the KDF-only [`KEEPASSXC_TIMEOUT`].
fn wait_for_cli_yubikey(child: Child, what: &'static str) -> SecretResult<Output> {
    wait_for_cli_with(child, what, KEEPASSXC_YUBIKEY_TIMEOUT)
}

fn wait_for_cli_with(child: Child, what: &'static str, budget: Duration) -> SecretResult<Output> {
    match wait_bounded(child, budget, what) {
        Ok(Waited::Exited(output)) => Ok(output),
        Ok(Waited::TimedOut) => Err(SecretError::KeePassXC(format!(
            "keepassxc-cli ({what}) did not respond within {}s and was stopped. \
             The database may be locked by another process, on storage that is not \
             responding, or configured with key-derivation parameters too heavy for \
             this machine — each run of keepassxc-cli pays that cost again.",
            budget.as_secs()
        ))),
        Err(e) => Err(SecretError::KeePassXC(format!(
            "Failed to wait for keepassxc-cli: {e}"
        ))),
    }
}

/// Why a `keepassxc-cli show` exited non-zero.
///
/// The three readers in this file each classified this inline, and all three drew
/// the same line in the wrong place: anything that was not recognisably a
/// credential error became `Ok(None)`, i.e. "there is no such entry". So a corrupt
/// or unsupported database, an unreadable or wrong `--key-file`, and a
/// hardware-key database waiting for a touch all reported the same thing as an
/// empty database — and `Ok(None)` reaches the user as "Vault entry not found.
/// You will be prompted for a password", which names the wrong problem and offers
/// no way to act on the real one.
///
/// One classifier for all three readers, so they cannot drift apart again.
enum ShowFailure {
    /// The database opened and the entry is genuinely not in it.
    EntryMissing,
    /// The database did not open with the password or key file supplied.
    BadCredentials,
    /// Anything else. The database may be unreadable, of an unsupported version,
    /// or waiting on something nobody answered — but it was not opened, so
    /// "the entry is not there" is not a conclusion available to us.
    Unusable,
}

/// Classifies a failed `keepassxc-cli show` from its stderr.
///
/// String matching, because `keepassxc-cli` distinguishes these cases only in
/// prose and returns exit code 1 for all of them. That makes the wording a
/// dependency: a KeePassXC release that rephrases "Could not find entry" turns a
/// missing entry into [`ShowFailure::Unusable`], which is a dialog saying the
/// database could not be read rather than a prompt. That is the safe direction to
/// fail — the old behaviour failed the other way, turning an unopenable database
/// into "no such password" — but it is worth knowing which way it breaks.
fn classify_show_failure(stderr: &str) -> ShowFailure {
    if stderr.contains("Could not find entry")
        || stderr.contains("Entry not found")
        || stderr.contains("No entry found")
    {
        return ShowFailure::EntryMissing;
    }
    if stderr.contains("Invalid credentials") || stderr.contains("wrong password") {
        return ShowFailure::BadCredentials;
    }
    ShowFailure::Unusable
}

/// The entry paths a lookup tries, in order, for RustConn's own naming schemes.
///
/// Each one costs a separate `keepassxc-cli` invocation, and every invocation
/// reopens the database and pays its Argon2 cost again — around 700 ms on a
/// default KDBX. So the list is not free: a lookup that finds nothing pays for
/// every entry in it before the user sees a password prompt. It is extracted from
/// [`KeePassStatus::get_password_from_kdbx_with_key`] so the order is pinned by
/// tests rather than by reading the loop, since a `keepassxc-cli` is needed to
/// exercise the loop at all.
///
/// The candidates, in order:
///
/// 1. `RustConn/{entry_name}` — where this version writes.
/// 2. `RustConn/{entry_name without its " (protocol)" suffix}` — the older
///    format, before entries carried the protocol.
/// 3. `RustConn/{entry_name} ({protocol})` — only when the caller passes the
///    protocol separately instead of having it in the name already.
/// 4. `{entry_name}` — a root-level entry, from before entries were grouped
///    under `RustConn/` at all.
///
/// Candidate 4 is skipped when `entry_name` already carries a group path.
/// [`KeePassHierarchy::build_entry_path`](super::hierarchy::KeePassHierarchy::build_entry_path)
/// starts every path it builds at `RustConn`, so no release has ever written
/// `Group/name` at the database root — the un-prefixed form can only match the
/// ungrouped case, where the name is a bare entry name. Trying it for a grouped
/// connection was a full database open that could not succeed, on every lookup.
/// A path the *user* chose is not resolved through here: that is
/// [`KeePassStatus::get_password_from_kdbx_exact`], which queries it as-is.
fn candidate_entry_paths(entry_name: &str, protocol: Option<&str>) -> Vec<String> {
    let mut entry_paths = Vec::new();

    // First try exact entry name (may already include protocol suffix)
    entry_paths.push(format!("RustConn/{entry_name}"));

    // If entry_name contains protocol suffix like "name (ssh)", also try without it (legacy)
    // This handles migration from old format where entries were stored without protocol
    if let Some(base_name) = entry_name
        .strip_suffix(')')
        .and_then(|s| s.rfind(" (").map(|pos| &entry_name[..pos]))
    {
        entry_paths.push(format!("RustConn/{base_name}"));
    }

    // If protocol provided separately, try with it (for backward compatibility)
    if let Some(proto) = protocol {
        entry_paths.push(format!("RustConn/{entry_name} ({proto})"));
    }

    // Finally the un-prefixed name, but only where it could ever have been
    // written — see the note above.
    if !entry_name.contains('/') {
        entry_paths.push(entry_name.to_string());
    }

    entry_paths
}

/// Status of `KeePass` integration
///
/// This struct provides information about the current state of `KeePass` integration,
/// including whether `KeePassXC` is installed, its version, and KDBX file accessibility.
#[derive(Debug, Clone, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "settings/flags struct mirrors persisted config 1:1; bools represent independent toggles, not a state machine"
)]
pub struct KeePassStatus {
    /// Whether `KeePassXC` application is installed
    pub keepassxc_installed: bool,
    /// `KeePassXC` version if installed
    pub keepassxc_version: Option<String>,
    /// Path to `KeePassXC` CLI binary
    pub keepassxc_path: Option<std::path::PathBuf>,
    /// Whether KDBX file is configured
    pub kdbx_configured: bool,
    /// Whether KDBX file exists and is accessible
    pub kdbx_accessible: bool,
    /// Whether integration is currently active (unlocked)
    pub integration_active: bool,
}

impl KeePassStatus {
    /// Detects current `KeePass` status by checking for `KeePassXC` installation
    ///
    /// This method searches for the `keepassxc-cli` binary in common locations
    /// and attempts to determine its version.
    #[must_use]
    pub fn detect() -> Self {
        let mut status = Self::default();

        // Try to find keepassxc-cli in PATH or common locations
        if let Some(path) = Self::find_keepassxc_cli() {
            status.keepassxc_installed = true;
            status.keepassxc_path = Some(path.clone());

            // Try to get version
            if let Some(version) = Self::get_keepassxc_version(&path) {
                status.keepassxc_version = Some(version);
            }
        }

        status
    }

    /// Detects status with a configured KDBX path
    ///
    /// # Arguments
    /// * `kdbx_path` - Optional path to the KDBX database file
    #[must_use]
    pub fn detect_with_kdbx(kdbx_path: Option<&Path>) -> Self {
        let mut status = Self::detect();

        if let Some(path) = kdbx_path {
            status.kdbx_configured = true;
            status.kdbx_accessible = path.exists() && path.is_file();
        }

        status
    }

    /// Validates a KDBX file path
    ///
    /// # Arguments
    /// * `path` - Path to validate
    ///
    /// # Returns
    /// * `Ok(())` if the path is valid (ends with .kdbx and file exists)
    /// * `Err(String)` with a description of the validation failure
    ///
    /// # Errors
    /// Returns an error if:
    /// - The path does not have a .kdbx extension (case-insensitive)
    /// - The file does not exist
    /// - The path points to a directory instead of a file
    pub fn validate_kdbx_path(path: &Path) -> SecretResult<()> {
        // Check extension (case-insensitive)
        let extension = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(str::to_lowercase);

        if extension.as_deref() != Some("kdbx") {
            return Err(SecretError::KeePassXC(
                "File must have .kdbx extension".to_string(),
            ));
        }

        // Check if file exists
        if !path.exists() {
            return Err(SecretError::KeePassXC(format!(
                "File does not exist: {}",
                path.display()
            )));
        }

        // Check if it's a file (not a directory)
        if !path.is_file() {
            return Err(SecretError::KeePassXC(format!(
                "Path is not a file: {}",
                path.display()
            )));
        }

        Ok(())
    }

    /// Finds the `keepassxc-cli` binary, searching once per process.
    ///
    /// Every reader and writer in this module called this, and each call redid
    /// the whole search: a PATH walk plus up to six `stat`s natively, and inside
    /// a Flatpak sandbox **an extra child process** — `find_on_host` runs
    /// `sh -lc 'command -v …'` on the host. A single credential lookup is one of
    /// those, a single save is four, and all of them answer the same question
    /// about where a binary lives.
    ///
    /// Only a *successful* find is remembered. Caching the negative answer too
    /// would be the tidier `OnceLock<Option<_>>`, and it would be wrong: the
    /// Flatpak branch probes the host with a two-second budget, so one slow probe
    /// would leave the whole session convinced KeePassXC is not installed, with
    /// "keepassxc-cli not found. Please install KeePassXC." as the only symptom
    /// and a restart as the only cure. A guard that can outlast the condition it
    /// describes is worse than the cost it saves. A miss re-searches.
    fn find_keepassxc_cli() -> Option<std::path::PathBuf> {
        static LOCATION: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

        if let Some(cached) = LOCATION.get() {
            return Some(cached.clone());
        }
        let found = Self::locate_keepassxc_cli()?;
        // A lost race means another thread found the same binary first.
        Some(LOCATION.get_or_init(|| found).clone())
    }

    /// Performs the actual search behind [`Self::find_keepassxc_cli`].
    ///
    /// Searches in PATH and common installation locations. Inside a Flatpak
    /// sandbox, KeePassXC cannot be bundled (it is the user's host GUI app),
    /// so the host binary is located via `flatpak-spawn --host`.
    fn locate_keepassxc_cli() -> Option<std::path::PathBuf> {
        // In Flatpak, resolve and run keepassxc-cli on the host (see #182). The
        // probe used to live here; it is now `which::find_on_host`, which does the
        // same `sh -lc 'command -v …'` for every host binary and bounds the wait.
        if crate::flatpak::is_flatpak() {
            return crate::which::find_on_host("keepassxc-cli");
        }

        // PATH, extended with the Homebrew and KeePassXC.app directories a macOS
        // `.app` does not inherit. Resolved in process — spawning `which` made
        // the answer depend on a binary that need not be installed (#303).
        if let Some(path) = crate::which::find_in_path("keepassxc-cli") {
            return Some(path);
        }

        // Check common installation paths
        let common_paths = [
            "/usr/bin/keepassxc-cli",
            "/usr/local/bin/keepassxc-cli",
            "/snap/bin/keepassxc-cli",
            "/var/lib/flatpak/exports/bin/org.keepassxc.KeePassXC.cli",
            // macOS: Homebrew (Apple Silicon and Intel)
            "/opt/homebrew/bin/keepassxc-cli",
            // macOS: KeePassXC.app bundle
            "/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli",
        ];

        for path_str in &common_paths {
            let path = std::path::PathBuf::from(path_str);
            if path.exists() {
                return Some(path);
            }
        }

        None
    }

    /// Builds a [`Command`] for running `keepassxc-cli`.
    ///
    /// The returned command has no arguments yet — callers append `.arg(...)` as needed.
    ///
    /// Inside a Flatpak sandbox the invocation is routed through
    /// `flatpak-spawn --host` so the host's KeePassXC is used (it cannot be
    /// bundled in the sandbox). flatpak-spawn forwards stdin/stdout/stderr to
    /// the host process by default, so piped database/entry passwords reach it.
    /// Appending args then yields `flatpak-spawn --host <cli> <args...>`.
    ///
    /// Otherwise the binary is run directly with the extended PATH injected so
    /// that child processes (e.g. GPG invoked by keepassxc-cli) can also be
    /// found on macOS where GUI apps have minimal PATH.
    ///
    /// The child also gets a neutralised *message* locale, which
    /// [`classify_show_failure`] depends on. `keepassxc-cli` is a Qt program and
    /// translates its diagnostics, while this process exports `LANGUAGE` at
    /// startup to honour the application's own language setting (see
    /// `rustconn::i18n`). So with a non-English UI the CLI answered in that
    /// language, none of the English needles matched, and a missing entry was
    /// classified as an unreadable database: the user saw "Could not read the
    /// password from KeePassXC — it may be locked, not logged in, or not set up on
    /// this computer" about a database that was open and healthy, and because that
    /// path returns `Err`, the **Also read from the encrypted file** fallback was
    /// skipped as well. The wording of the CLI's prose was already documented as a
    /// dependency; what was missed is that we localise it ourselves.
    ///
    /// `C` is forced for messages only, and the character encoding is deliberately
    /// left as the user had it: entry paths and the database path are passed as
    /// arguments, and a Qt 5 build derives its argv codec from the locale's
    /// charset, so forcing the C locale wholesale would mangle a non-ASCII group
    /// name or database path — trading this bug for a worse one. `LC_ALL` outranks
    /// `LC_MESSAGES` in POSIX, so it cannot simply be left in place; when it is set
    /// its value is copied to `LC_CTYPE` first, which preserves exactly the
    /// encoding it was providing, and only then is `LC_ALL` dropped. That copy is
    /// the one write to `LC_CTYPE` here, and it changes no behaviour by itself.
    fn keepassxc_command(cli_path: &Path) -> Command {
        if crate::flatpak::is_flatpak() {
            let mut cmd = Command::new("flatpak-spawn");
            // Forwarded explicitly: the host process does not take these from the
            // sandbox. Blanked rather than unset because `--unset-env` is newer
            // than the oldest flatpak this runs under, and an empty value is what
            // gettext and Qt both read as "no preference". A host that exports
            // `LC_ALL` still outranks this; that is left alone rather than
            // guessed at, since the sandbox cannot see the host's encoding.
            cmd.arg("--host")
                .arg("--env=LC_MESSAGES=C")
                .arg("--env=LANGUAGE=")
                .arg(cli_path);
            return cmd;
        }
        let mut cmd = Command::new(cli_path);
        cmd.env("PATH", crate::cli_download::get_extended_path());
        cmd.env("LC_MESSAGES", "C");
        cmd.env_remove("LANGUAGE");
        if let Ok(lc_all) = std::env::var("LC_ALL") {
            if !lc_all.is_empty() {
                cmd.env("LC_CTYPE", lc_all);
            }
            cmd.env_remove("LC_ALL");
        }
        cmd
    }

    /// Gets the `KeePassXC` version from the CLI
    ///
    /// # Arguments
    /// * `cli_path` - Path to the `keepassxc-cli` binary
    fn get_keepassxc_version(cli_path: &Path) -> Option<String> {
        // Spawned and waited rather than `.output()`, which has no deadline. This
        // one runs from `detect()`, i.e. while the Settings dialog is being built,
        // so an unresponsive binary here freezes the window.
        let child = match Self::keepassxc_command(cli_path)
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                tracing::warn!(?e, cli = %cli_path.display(), "failed to run keepassxc-cli --version");
                return None;
            }
        };
        let output = match wait_for_cli(child, "--version") {
            Ok(output) => output,
            Err(e) => {
                tracing::warn!(?e, cli = %cli_path.display(), "keepassxc-cli --version did not answer");
                return None;
            }
        };

        let version = if output.status.success() {
            parse_keepassxc_version(&String::from_utf8_lossy(&output.stdout))
        } else {
            // Some versions output to stderr
            parse_keepassxc_version(&String::from_utf8_lossy(&output.stderr))
        };

        if version.is_none() {
            tracing::warn!(
                exit_code = ?output.status.code(),
                stdout = %String::from_utf8_lossy(&output.stdout).trim(),
                stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                "could not parse keepassxc-cli version"
            );
        }
        version
    }

    /// Retrieves a password from KDBX database using `keepassxc-cli`
    ///
    /// # Arguments
    /// * `kdbx_path` - Path to the KDBX database file
    /// * `db_password` - Password to unlock the database
    /// * `entry_name` - Name of the entry to look up (connection name or host)
    ///
    /// # Returns
    /// * `Ok(Some(String))` if the password is found
    /// * `Ok(None)` if the entry is not found
    /// * `Err(String)` with error description if retrieval fails
    ///
    /// # Errors
    /// Returns an error if:
    /// - `keepassxc-cli` is not installed
    /// - The KDBX file path is invalid
    /// - The database password is incorrect
    pub fn get_password_from_kdbx(
        kdbx_path: &Path,
        db_password: &SecretString,
        entry_name: &str,
    ) -> SecretResult<Option<SecretString>> {
        use std::io::Write as IoWrite;
        use std::process::Stdio;

        // First validate the path
        Self::validate_kdbx_path(kdbx_path)?;

        // Find keepassxc-cli
        let cli_path = Self::find_keepassxc_cli().ok_or_else(|| {
            SecretError::KeePassXC("keepassxc-cli not found. Please install KeePassXC.".to_string())
        })?;

        // Use keepassxc-cli show command to get the password
        // Format: keepassxc-cli show -q -s -a Password <database> <entry>
        let mut child = Self::keepassxc_command(&cli_path)
            .arg("show")
            .arg("-q") // Quiet mode — suppress password prompt
            .arg("-s") // Show password attribute
            .arg("-a")
            .arg("Password") // Get password attribute
            .arg(kdbx_path)
            .arg(entry_name)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| SecretError::KeePassXC(format!("Failed to run keepassxc-cli: {e}")))?;

        // Write database password to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(db_password.expose_secret().as_bytes())
                .map_err(|e| SecretError::KeePassXC(format!("Failed to send password: {e}")))?;
            stdin
                .write_all(b"\n")
                .map_err(|e| SecretError::KeePassXC(format!("Failed to send password: {e}")))?;
        }

        let output = wait_for_cli(child, "show")?;

        if output.status.success() {
            // Wiped on drop: this is the credential itself, in the clear, on its
            // way into the `SecretString`. `get_password_from_kdbx_exact` already
            // did this; the other two readers in this file did not.
            let password =
                zeroize::Zeroizing::new(String::from_utf8_lossy(&output.stdout).trim().to_string());
            if password.is_empty() {
                Ok(None)
            } else {
                Ok(Some(SecretString::from(password.as_str())))
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            match classify_show_failure(&stderr) {
                ShowFailure::EntryMissing => Ok(None),
                ShowFailure::BadCredentials => Err(SecretError::KeePassXC(
                    "Invalid database password".to_string(),
                )),
                // Was `Ok(None)` after a warning, which told the log the truth and
                // the user something else.
                ShowFailure::Unusable => {
                    tracing::warn!(
                        entry_name,
                        exit_code = ?output.status.code(),
                        stderr = %stderr.trim(),
                        "keepassxc-cli could not read the database"
                    );
                    Err(SecretError::KeePassXC(format!(
                        "Could not read the database: {}",
                        stderr.trim()
                    )))
                }
            }
        }
    }

    /// Saves a password to KDBX database using `keepassxc-cli`
    ///
    /// # Arguments
    /// * `kdbx_path` - Path to the KDBX database file
    /// * `db_password` - Password to unlock the database (None if using key file)
    /// * `key_file` - Optional path to key file for authentication
    /// * `entry_name` - Name of the entry (connection name or host)
    /// * `username` - Username for the entry
    /// * `password` - Password to save
    /// * `url` - Optional URL for the entry
    /// * `yubikey_slot` - Optional `YubiKey` Challenge-Response slot as
    ///   `slot[:serial]`; when `Some`, passed to `keepassxc-cli` as `-y` and
    ///   composed with the password and/or key file. `None` preserves the
    ///   historical password/key-file-only unlock.
    ///
    /// # Returns
    /// * `Ok(())` if the password is saved successfully
    /// * `Err(String)` with error description if saving fails
    ///
    /// # Errors
    /// Returns an error if:
    /// - `keepassxc-cli` is not installed
    /// - The KDBX file path is invalid
    /// - The database password/key file is incorrect
    /// - The entry cannot be created
    ///
    /// Note: Entry names include protocol suffix to allow same name for different protocols.
    /// Format: `RustConn/{entry_name} ({protocol})` where protocol is extracted from URL.
    #[expect(
        clippy::too_many_lines,
        reason = "long match/dispatch over many enum variants; splitting per variant only relocates the boilerplate"
    )]
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors the read path get_password_from_kdbx_with_key; the KDBX write needs every unlock factor plus the entry fields"
    )]
    pub fn save_password_to_kdbx(
        kdbx_path: &Path,
        db_password: Option<&SecretString>,
        key_file: Option<&Path>,
        entry_name: &str,
        username: &str,
        password: &SecretString,
        url: Option<&str>,
        yubikey_slot: Option<&str>,
    ) -> SecretResult<()> {
        use std::io::Write as IoWrite;
        use std::process::Stdio;

        // First validate the path
        Self::validate_kdbx_path(kdbx_path)?;

        // Find keepassxc-cli
        let cli_path = Self::find_keepassxc_cli().ok_or_else(|| {
            SecretError::KeePassXC("keepassxc-cli not found. Please install KeePassXC.".to_string())
        })?;

        // Ensure RustConn group exists
        Self::ensure_rustconn_group(kdbx_path, db_password, key_file, &cli_path, yubikey_slot)?;

        // Build the entry path under RustConn group
        // entry_name should already include protocol suffix if needed (e.g., "server (rdp)")
        let entry_path = format!("RustConn/{entry_name}");

        // Ensure all parent groups in the path exist (e.g., RustConn/Groups for group passwords)
        Self::ensure_parent_groups(
            kdbx_path,
            db_password,
            key_file,
            &cli_path,
            entry_name,
            yubikey_slot,
        )?;

        // First, try to remove existing entry (ignore errors if it doesn't exist)
        let _ =
            Self::delete_kdbx_entry(kdbx_path, db_password, key_file, &entry_path, yubikey_slot);

        // Build command arguments for keepassxc-cli add
        // Format: keepassxc-cli add [options] <database> <entry>
        // -p/--password-prompt prompts for entry password via stdin (after db password)
        // Assembled by a free function so a test can assert the argv without a
        // real keepassxc-cli or database — see `build_add_args`.
        let args = build_add_args(
            db_password.is_some(),
            key_file,
            yubikey_slot,
            username,
            url,
            kdbx_path,
            &entry_path,
        );

        tracing::debug!("Running keepassxc-cli with args: {args:?}");

        let mut child = Self::keepassxc_command(&cli_path)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| SecretError::KeePassXC(format!("Failed to run keepassxc-cli: {e}")))?;

        // Write passwords to stdin
        // When using --no-password (key file only): only entry password is needed
        // When using password: database password first, then entry password
        if let Some(mut stdin) = child.stdin.take() {
            // Database password (only if not using --no-password)
            if let Some(db_pwd) = db_password {
                stdin
                    .write_all(db_pwd.expose_secret().as_bytes())
                    .map_err(|e| {
                        SecretError::KeePassXC(format!("Failed to send database password: {e}"))
                    })?;
                stdin
                    .write_all(b"\n")
                    .map_err(|e| SecretError::KeePassXC(format!("Failed to send newline: {e}")))?;
            }

            // Entry password (prompted by -p flag)
            tracing::debug!("Sending entry password to keepassxc-cli");
            stdin
                .write_all(password.expose_secret().as_bytes())
                .map_err(|e| {
                    SecretError::KeePassXC(format!("Failed to send entry password: {e}"))
                })?;
            stdin
                .write_all(b"\n")
                .map_err(|e| SecretError::KeePassXC(format!("Failed to send newline: {e}")))?;

            // Close stdin to signal end of input
            drop(stdin);
        }

        // A `-y` unlock blocks on a physical touch, so give the write the longer
        // touch budget; a password/key-file-only write keeps the write budget.
        let output = if yubikey_slot.is_some() {
            wait_for_cli_yubikey(child, "add")?
        } else {
            wait_for_cli_write(child, "add")?
        };

        tracing::debug!(
            "keepassxc-cli exit code: {:?}, stdout: '{}', stderr: '{}'",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stderr.contains("Invalid credentials")
                || stderr.contains("wrong password")
                || stderr.contains("Error while reading the database")
            {
                Err(SecretError::KeePassXC(
                    "Invalid database password or key file".to_string(),
                ))
            } else if stderr.contains("Could not find group") {
                Err(SecretError::KeePassXC(
                    "RustConn group not found in database. Please create a group \
                     named 'RustConn' in your KeePass database."
                        .to_string(),
                ))
            } else if stderr.contains("already exists") {
                Err(SecretError::KeePassXC(format!(
                    "Entry '{entry_name}' already exists"
                )))
            } else if stderr.is_empty() && stdout.is_empty() {
                // The reproduction command the user can paste, mirroring the exact
                // unlock factors this call used — including `-y <slot>`, whose
                // absence is what the #350 reporter flagged.
                let yubikey_hint = match yubikey_slot {
                    Some(slot) => format!(" -y {slot}"),
                    None => String::new(),
                };
                Err(SecretError::KeePassXC(format!(
                    "Failed to save password to KeePass database (exit code: {:?}). \
                     Try running: keepassxc-cli add -p{} {} 'RustConn/{}'",
                    output.status.code(),
                    yubikey_hint,
                    kdbx_path.display(),
                    entry_name
                )))
            } else {
                let error_msg = if stderr.is_empty() { stdout } else { stderr };
                Err(SecretError::KeePassXC(format!(
                    "KeePass error: {}",
                    error_msg.trim()
                )))
            }
        }
    }

    /// Ensures the `RustConn` group exists in the database
    fn ensure_rustconn_group(
        kdbx_path: &Path,
        db_password: Option<&SecretString>,
        key_file: Option<&Path>,
        cli_path: &Path,
        yubikey_slot: Option<&str>,
    ) -> SecretResult<()> {
        use std::io::Write as IoWrite;
        use std::process::Stdio;

        tracing::debug!("Checking if RustConn group exists...");

        // First check if RustConn group exists using ls command
        let mut args = vec!["ls".to_string(), "-q".to_string()];

        push_unlock_args(&mut args, db_password.is_some(), key_file, yubikey_slot);

        args.push(kdbx_path.display().to_string());
        args.push("RustConn".to_string());

        let mut child = Self::keepassxc_command(cli_path)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| SecretError::KeePassXC(format!("Failed to run keepassxc-cli: {e}")))?;

        // Only send password if we have one
        if let Some(mut stdin) = child.stdin.take()
            && let Some(db_pwd) = db_password
        {
            stdin.write_all(db_pwd.expose_secret().as_bytes()).ok();
            stdin.write_all(b"\n").ok();
        }

        // The group probe opens the database, so with a `-y` slot it too can block
        // on a touch; give it the touch budget then.
        let output = if yubikey_slot.is_some() {
            wait_for_cli_yubikey(child, "ls (group probe)").ok()
        } else {
            wait_for_cli(child, "ls (group probe)").ok()
        };

        // If group exists, we're done
        if let Some(ref o) = output {
            tracing::debug!(
                "ls RustConn result: exit={:?}, stdout='{}', stderr='{}'",
                o.status.code(),
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            if o.status.success() {
                tracing::debug!("RustConn group exists");
                return Ok(());
            }
        }

        tracing::debug!("RustConn group doesn't exist, creating...");

        // Group doesn't exist, create it using mkdir command
        let mut args = vec!["mkdir".to_string(), "-q".to_string()];

        push_unlock_args(&mut args, db_password.is_some(), key_file, yubikey_slot);

        args.push(kdbx_path.display().to_string());
        args.push("RustConn".to_string());

        let mut child = Self::keepassxc_command(cli_path)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                SecretError::KeePassXC(format!("Failed to run keepassxc-cli mkdir: {e}"))
            })?;

        // Only send password if we have one
        if let Some(mut stdin) = child.stdin.take()
            && let Some(db_pwd) = db_password
        {
            stdin.write_all(db_pwd.expose_secret().as_bytes()).ok();
            stdin.write_all(b"\n").ok();
        }

        let output = if yubikey_slot.is_some() {
            wait_for_cli_yubikey(child, "mkdir")?
        } else {
            wait_for_cli_write(child, "mkdir")?
        };

        tracing::debug!(
            "mkdir RustConn result: exit={:?}, stdout='{}', stderr='{}'",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        if output.status.success() {
            tracing::debug!("RustConn group created successfully");
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // If group already exists, that's fine
            if stderr.contains("already exists") {
                tracing::debug!("RustConn group already exists");
                Ok(())
            } else if stderr.contains("Invalid credentials") || stderr.contains("wrong password") {
                Err(SecretError::KeePassXC(
                    "Invalid database password or key file".to_string(),
                ))
            } else {
                // Don't fail if we can't create the group
                tracing::debug!("Failed to create group, but continuing: {stderr}");
                Ok(())
            }
        }
    }

    /// Ensures all parent groups in a path exist
    ///
    /// For path "Groups/Production/Web", creates:
    /// - RustConn/Groups
    /// - RustConn/Groups/Production
    /// - RustConn/Groups/Production/Web
    fn ensure_parent_groups(
        kdbx_path: &Path,
        db_password: Option<&SecretString>,
        key_file: Option<&Path>,
        cli_path: &Path,
        entry_path: &str,
        yubikey_slot: Option<&str>,
    ) -> SecretResult<()> {
        use std::io::Write as IoWrite;
        use std::process::Stdio;

        // Extract parent path (everything except the last component which is the entry name)
        let parts: Vec<&str> = entry_path.split('/').collect();
        if parts.len() <= 1 {
            // No parent groups needed
            return Ok(());
        }

        // Build cumulative paths for all parent groups
        let mut current_path = String::from("RustConn");
        for part in &parts[..parts.len() - 1] {
            current_path = format!("{current_path}/{part}");

            tracing::debug!("Ensuring group exists: {}", current_path);

            // Try to create the group (ignore if already exists)
            let mut args = vec!["mkdir".to_string(), "-q".to_string()];

            push_unlock_args(&mut args, db_password.is_some(), key_file, yubikey_slot);

            args.push(kdbx_path.display().to_string());
            args.push(current_path.clone());

            let mut child = Self::keepassxc_command(cli_path)
                .args(&args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| {
                    SecretError::KeePassXC(format!("Failed to run keepassxc-cli mkdir: {e}"))
                })?;

            if let Some(mut stdin) = child.stdin.take()
                && let Some(db_pwd) = db_password
            {
                stdin.write_all(db_pwd.expose_secret().as_bytes()).ok();
                stdin.write_all(b"\n").ok();
            }

            let output = if yubikey_slot.is_some() {
                wait_for_cli_yubikey(child, "mkdir (parent group)").ok()
            } else {
                wait_for_cli_write(child, "mkdir (parent group)").ok()
            };

            // A failed intermediate group must abort: previously any failure
            // here (or a swallowed wait error) only logged at debug! and the
            // function still returned Ok, so `add` would then target a group
            // that was never created — the save appeared to "succeed" while the
            // nested groups silently never appeared (issue observed via #350
            // write-path follow-up). Treat success and "already exists" as fine,
            // and surface anything else as an error so the caller can report it.
            match output {
                Some(ref o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    if o.status.success() || stderr.contains("already exists") {
                        tracing::debug!("Group '{}' ready", current_path);
                    } else {
                        return Err(SecretError::KeePassXC(format!(
                            "Failed to create parent group '{current_path}': {}",
                            stderr.trim()
                        )));
                    }
                }
                None => {
                    return Err(SecretError::KeePassXC(format!(
                        "Failed to create parent group '{current_path}': keepassxc-cli mkdir did not complete"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Deletes an entry from KDBX database
    fn delete_kdbx_entry(
        kdbx_path: &Path,
        db_password: Option<&SecretString>,
        key_file: Option<&Path>,
        entry_path: &str,
        yubikey_slot: Option<&str>,
    ) -> SecretResult<()> {
        use std::io::Write as IoWrite;
        use std::process::Stdio;

        let cli_path = Self::find_keepassxc_cli()
            .ok_or_else(|| SecretError::KeePassXC("keepassxc-cli not found".to_string()))?;

        let mut args = vec!["rm".to_string(), "-q".to_string()];

        push_unlock_args(&mut args, db_password.is_some(), key_file, yubikey_slot);

        args.push(kdbx_path.display().to_string());
        args.push(entry_path.to_string());

        let mut child = Self::keepassxc_command(&cli_path)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| SecretError::KeePassXC(format!("Failed to run keepassxc-cli: {e}")))?;

        // Only send password if we have one
        if let Some(mut stdin) = child.stdin.take()
            && let Some(db_pwd) = db_password
        {
            stdin.write_all(db_pwd.expose_secret().as_bytes()).ok();
            stdin.write_all(b"\n").ok();
        }

        // Best-effort by design: the caller deletes before adding and does not
        // care whether the entry existed. Bounded all the same — "does not care
        // about the result" is not the same as "may block for ever". A `-y`
        // unlock waits on a touch, so it gets the touch budget.
        if yubikey_slot.is_some() {
            let _ = wait_for_cli_yubikey(child, "rm");
        } else {
            let _ = wait_for_cli_write(child, "rm");
        }
        Ok(())
    }

    /// Deletes an entry from KDBX database (public API)
    ///
    /// # Arguments
    /// * `kdbx_path` - Path to the KDBX database file
    /// * `db_password` - Password to unlock the database (None if using key file)
    /// * `key_file` - Optional path to key file for authentication
    /// * `entry_path` - Full path of the entry to delete (e.g., "RustConn/Group/Name (rdp)")
    /// * `yubikey_slot` - Optional `YubiKey` Challenge-Response slot as
    ///   `slot[:serial]`; when `Some`, passed to `keepassxc-cli` as `-y` and
    ///   composed with the password and/or key file.
    ///
    /// # Returns
    /// * `Ok(())` if the entry is deleted or doesn't exist
    /// * `Err(String)` if the operation fails
    ///
    /// # Errors
    /// Returns an error if:
    /// - `keepassxc-cli` is not installed
    /// - The KDBX file path is invalid
    /// - The database password/key file is incorrect
    pub fn delete_entry_from_kdbx(
        kdbx_path: &Path,
        db_password: Option<&SecretString>,
        key_file: Option<&Path>,
        entry_path: &str,
        yubikey_slot: Option<&str>,
    ) -> SecretResult<()> {
        // First validate the path
        Self::validate_kdbx_path(kdbx_path)?;

        // Find keepassxc-cli
        Self::find_keepassxc_cli().ok_or_else(|| {
            SecretError::KeePassXC("keepassxc-cli not found. Please install KeePassXC.".to_string())
        })?;

        Self::delete_kdbx_entry(kdbx_path, db_password, key_file, entry_path, yubikey_slot)
    }

    /// Retrieves a password from KDBX database using `keepassxc-cli` with key file support
    ///
    /// # Arguments
    /// * `kdbx_path` - Path to the KDBX database file
    /// * `db_password` - Password to unlock the database (None if using key file only)
    /// * `key_file` - Optional path to key file for authentication
    /// * `entry_name` - Name of the entry to look up (connection name or host)
    /// * `protocol` - Optional protocol (ssh, rdp, vnc, spice) for more specific lookup
    /// * `yubikey_slot` - Optional `YubiKey` Challenge-Response slot as
    ///   `slot[:serial]`; when `Some`, passed to `keepassxc-cli` as `-y` and
    ///   composed with the password and/or key file. `None` preserves the
    ///   historical password/key-file-only unlock.
    ///
    /// # Returns
    /// * `Ok(Some(String))` if the password is found
    /// * `Ok(None)` if the entry is not found
    ///
    /// Note: Searches in order: `RustConn/{name}`, `RustConn/{base_name}` (without protocol suffix), `{name}`
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::Backend`] if `keepassxc-cli` cannot be spawned,
    /// the database cannot be unlocked (wrong password or key file), or the
    /// CLI returns a non-zero exit code for any reason other than "entry not
    /// found".
    pub fn get_password_from_kdbx_with_key(
        kdbx_path: &Path,
        db_password: Option<&SecretString>,
        key_file: Option<&Path>,
        entry_name: &str,
        protocol: Option<&str>,
        yubikey_slot: Option<&str>,
    ) -> SecretResult<Option<SecretString>> {
        use std::io::Write as IoWrite;
        use std::process::Stdio;

        // First validate the path
        Self::validate_kdbx_path(kdbx_path)?;

        // Find keepassxc-cli
        let cli_path = Self::find_keepassxc_cli().ok_or_else(|| {
            SecretError::KeePassXC("keepassxc-cli not found. Please install KeePassXC.".to_string())
        })?;

        let entry_paths = candidate_entry_paths(entry_name, protocol);

        tracing::debug!(
            "get_password: entry_name='{}', protocol={:?}, has_password={}, has_key_file={}, has_yubikey={}",
            entry_name,
            protocol,
            db_password.is_some(),
            key_file.is_some(),
            yubikey_slot.is_some()
        );

        // First "the database would not open" seen while walking the candidate
        // paths. Kept so that a run which finds nothing can say *why* it found
        // nothing; see the end of the loop.
        let mut unusable: Option<String> = None;

        for entry_path in &entry_paths {
            let mut args = vec![
                "show".to_string(),
                "-q".to_string(),
                "-s".to_string(),
                "-a".to_string(),
                "Password".to_string(),
            ];

            push_unlock_args(&mut args, db_password.is_some(), key_file, yubikey_slot);

            args.push(kdbx_path.display().to_string());
            args.push(entry_path.clone());

            tracing::debug!("get_password: trying path '{entry_path}'");

            let mut child = Self::keepassxc_command(&cli_path)
                .args(&args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| SecretError::KeePassXC(format!("Failed to run keepassxc-cli: {e}")))?;

            // Only send password if we have one (not using --no-password)
            if let Some(mut stdin) = child.stdin.take()
                && let Some(db_pwd) = db_password
            {
                stdin
                    .write_all(db_pwd.expose_secret().as_bytes())
                    .map_err(|e| SecretError::KeePassXC(format!("Failed to send password: {e}")))?;
                stdin
                    .write_all(b"\n")
                    .map_err(|e| SecretError::KeePassXC(format!("Failed to send password: {e}")))?;
            }

            // A Challenge-Response unlock blocks on a physical touch, so give it
            // the longer budget; a password/key-file-only read keeps the tight one.
            let output = if yubikey_slot.is_some() {
                wait_for_cli_yubikey(child, "show (with key file)")?
            } else {
                wait_for_cli(child, "show (with key file)")?
            };

            tracing::debug!(
                "get_password: exit={:?}, stderr='{}'",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            );

            if output.status.success() {
                // Same wipe as `get_password_from_kdbx_exact`. This is the reader
                // the bulk credential transfer goes through, so a plaintext copy
                // left in the allocator here is one per entry rather than one per
                // connection attempt.
                let password = zeroize::Zeroizing::new(
                    String::from_utf8_lossy(&output.stdout).trim().to_string(),
                );
                if !password.is_empty() {
                    tracing::debug!("get_password: found password at '{entry_path}'");
                    return Ok(Some(SecretString::from(password.as_str())));
                }
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                match classify_show_failure(&stderr) {
                    // Wrong key for the database — no later candidate path can
                    // succeed, so stop rather than retrying the same refusal.
                    ShowFailure::BadCredentials => {
                        return Err(SecretError::KeePassXC(
                            "Invalid database password".to_string(),
                        ));
                    }
                    // This path is not in the database; the next candidate may be.
                    ShowFailure::EntryMissing => {
                        tracing::debug!("get_password: no entry at '{entry_path}'");
                    }
                    // The database was not opened. Remembered rather than returned
                    // immediately, because the candidate list exists to cope with
                    // several historical key formats and a later one may still
                    // work; but if none does, this is what gets reported instead of
                    // "no such entry".
                    ShowFailure::Unusable => {
                        tracing::warn!(
                            entry_path = %entry_path,
                            exit_code = ?output.status.code(),
                            stderr = %stderr.trim(),
                            "keepassxc-cli could not read the database"
                        );
                        if unusable.is_none() {
                            unusable = Some(stderr.trim().to_string());
                        }
                    }
                }
            }
        }

        // No candidate produced a password. Whether that means "the entry is not
        // there" or "the database could not be read" is the distinction the caller
        // needs: the first is a password prompt, the second is a dialog naming the
        // database. Reporting the first for both is what made a corrupt database
        // look like an empty one.
        if let Some(stderr) = unusable {
            return Err(SecretError::KeePassXC(format!(
                "Could not read the database: {stderr}"
            )));
        }

        tracing::debug!("get_password: password not found");
        Ok(None)
    }

    /// Retrieves a password from KDBX database at an exact path (no fallbacks).
    ///
    /// Unlike [`get_password_from_kdbx_with_key`] which tries multiple path
    /// variants with `RustConn/` prefix, this function queries the entry at
    /// `entry_path` **as-is**. Use for user-specified custom KeePass paths.
    ///
    /// # Arguments
    /// * `kdbx_path` - Path to the KDBX database file
    /// * `db_password` - Password to unlock the database (None if using key file)
    /// * `key_file` - Optional path to key file for authentication
    /// * `entry_path` - Exact path of the entry (e.g., "Internet/MyRouter" or "RustConn/RADIUS")
    /// * `yubikey_slot` - Optional `YubiKey` Challenge-Response slot as
    ///   `slot[:serial]`; when `Some`, passed to `keepassxc-cli` as `-y` and
    ///   composed with the password and/or key file. Without it a custom-path
    ///   read of a CR-protected database fails the same way the write path did
    ///   before issue #350's follow-up fix.
    ///
    /// # Returns
    /// * `Ok(Some(SecretString))` if the password is found
    /// * `Ok(None)` if the entry is not found
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::Backend`] if `keepassxc-cli` cannot be spawned,
    /// the database cannot be unlocked (wrong password or key file), or the
    /// CLI returns a non-zero exit code for any reason other than "entry not
    /// found".
    pub fn get_password_from_kdbx_exact(
        kdbx_path: &Path,
        db_password: Option<&SecretString>,
        key_file: Option<&Path>,
        entry_path: &str,
        yubikey_slot: Option<&str>,
    ) -> SecretResult<Option<SecretString>> {
        use std::io::Write as IoWrite;
        use std::process::Stdio;

        Self::validate_kdbx_path(kdbx_path)?;

        let cli_path = Self::find_keepassxc_cli().ok_or_else(|| {
            SecretError::KeePassXC("keepassxc-cli not found. Please install KeePassXC.".to_string())
        })?;

        let mut args = vec![
            "show".to_string(),
            "-q".to_string(),
            "-s".to_string(),
            "-a".to_string(),
            "Password".to_string(),
        ];

        push_unlock_args(&mut args, db_password.is_some(), key_file, yubikey_slot);

        args.push(kdbx_path.display().to_string());
        args.push(entry_path.to_string());

        tracing::debug!("get_password_exact: trying path '{entry_path}'");

        let mut child = Self::keepassxc_command(&cli_path)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| SecretError::KeePassXC(format!("Failed to run keepassxc-cli: {e}")))?;

        if let Some(mut stdin) = child.stdin.take()
            && let Some(db_pwd) = db_password
        {
            stdin
                .write_all(db_pwd.expose_secret().as_bytes())
                .map_err(|e| SecretError::KeePassXC(format!("Failed to send password: {e}")))?;
            stdin
                .write_all(b"\n")
                .map_err(|e| SecretError::KeePassXC(format!("Failed to send password: {e}")))?;
        }

        // A `-y` read blocks on a physical touch, so give it the touch budget.
        let output = if yubikey_slot.is_some() {
            wait_for_cli_yubikey(child, "show (exact entry)")?
        } else {
            wait_for_cli(child, "show (exact entry)")?
        };

        if output.status.success() {
            let password =
                zeroize::Zeroizing::new(String::from_utf8_lossy(&output.stdout).trim().to_string());
            if password.is_empty() {
                Ok(None)
            } else {
                tracing::debug!("get_password_exact: found password at '{entry_path}'");
                Ok(Some(SecretString::from(password.as_str())))
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            match classify_show_failure(&stderr) {
                ShowFailure::EntryMissing => {
                    tracing::debug!("get_password_exact: no entry at '{entry_path}'");
                    Ok(None)
                }
                ShowFailure::BadCredentials => Err(SecretError::KeePassXC(
                    "Invalid database password".to_string(),
                )),
                ShowFailure::Unusable => {
                    tracing::warn!(
                        entry_path = %entry_path,
                        exit_code = ?output.status.code(),
                        stderr = %stderr.trim(),
                        "keepassxc-cli could not read the database"
                    );
                    Err(SecretError::KeePassXC(format!(
                        "Could not read the database: {}",
                        stderr.trim()
                    )))
                }
            }
        }
    }

    /// Renames an entry in KDBX database by moving it from old path to new path
    ///
    /// This method retrieves the entry from the old path, creates a new entry at the new path
    /// with the same credentials, and deletes the old entry.
    ///
    /// # Arguments
    /// * `kdbx_path` - Path to the KDBX database file
    /// * `db_password` - Password to unlock the database (None if using key file)
    /// * `key_file` - Optional path to key file for authentication
    /// * `old_entry_path` - Current path of the entry (e.g., "RustConn/Group/OldName (rdp)")
    /// * `new_entry_path` - New path for the entry (e.g., "RustConn/Group/NewName (rdp)")
    /// * `yubikey_slot` - Optional `YubiKey` Challenge-Response slot as
    ///   `slot[:serial]`; when `Some`, passed to `keepassxc-cli` as `-y` and
    ///   composed with the password and/or key file for every read and write
    ///   this rename performs.
    ///
    /// # Returns
    /// * `Ok(())` if the rename is successful or entry doesn't exist
    /// * `Err(SecretError)` if the operation fails
    ///
    /// # Errors
    /// Returns an error if:
    /// - `keepassxc-cli` is not installed
    /// - The KDBX file path is invalid
    /// - The database password/key file is incorrect
    pub fn rename_entry_in_kdbx(
        kdbx_path: &Path,
        db_password: Option<&SecretString>,
        key_file: Option<&Path>,
        old_entry_path: &str,
        new_entry_path: &str,
        yubikey_slot: Option<&str>,
    ) -> SecretResult<()> {
        // If paths are the same, nothing to do
        if old_entry_path == new_entry_path {
            return Ok(());
        }

        // First validate the path
        Self::validate_kdbx_path(kdbx_path)?;

        // Find keepassxc-cli
        let cli_path = Self::find_keepassxc_cli().ok_or_else(|| {
            SecretError::KeePassXC("keepassxc-cli not found. Please install KeePassXC.".to_string())
        })?;

        // get_password_from_kdbx_with_key adds "RustConn/" prefix, so we need to strip it
        // from old_entry_path if present to avoid double prefix
        let old_entry_name = old_entry_path
            .strip_prefix("RustConn/")
            .unwrap_or(old_entry_path);

        // First, try to get the password from the old entry
        let password = Self::get_password_from_kdbx_with_key(
            kdbx_path,
            db_password,
            key_file,
            old_entry_name,
            None,
            yubikey_slot,
        )?;

        // If no password found at old path, nothing to rename
        let Some(password) = password else {
            tracing::debug!("No entry found at '{}', nothing to rename", old_entry_path);
            return Ok(());
        };

        // Get username from old entry (use full path for direct CLI call)
        let username = Self::get_username_from_kdbx(
            kdbx_path,
            db_password,
            key_file,
            &cli_path,
            old_entry_path,
            yubikey_slot,
        )
        .unwrap_or_default();

        // Get URL from old entry (use full path for direct CLI call)
        let url = Self::get_url_from_kdbx(
            kdbx_path,
            db_password,
            key_file,
            &cli_path,
            old_entry_path,
            yubikey_slot,
        );

        // Ensure parent groups exist for new path
        // Extract entry name from new path (everything after "RustConn/")
        let new_entry_name = new_entry_path
            .strip_prefix("RustConn/")
            .unwrap_or(new_entry_path);

        Self::ensure_parent_groups(
            kdbx_path,
            db_password,
            key_file,
            &cli_path,
            new_entry_name,
            yubikey_slot,
        )?;

        // Create new entry with the password
        Self::save_password_to_kdbx(
            kdbx_path,
            db_password,
            key_file,
            new_entry_name,
            &username,
            &password,
            url.as_deref(),
            yubikey_slot,
        )?;

        // Delete old entry (use full path for direct CLI call)
        let _ = Self::delete_kdbx_entry(
            kdbx_path,
            db_password,
            key_file,
            old_entry_path,
            yubikey_slot,
        );

        tracing::info!(
            "Renamed KeePass entry from '{}' to '{}'",
            old_entry_path,
            new_entry_path
        );

        Ok(())
    }

    /// Gets username from a KDBX entry
    fn get_username_from_kdbx(
        kdbx_path: &Path,
        db_password: Option<&SecretString>,
        key_file: Option<&Path>,
        cli_path: &Path,
        entry_path: &str,
        yubikey_slot: Option<&str>,
    ) -> Option<String> {
        use std::io::Write as IoWrite;
        use std::process::Stdio;

        let mut args = vec![
            "show".to_string(),
            "-q".to_string(),
            "-s".to_string(),
            "-a".to_string(),
            "UserName".to_string(),
        ];

        push_unlock_args(&mut args, db_password.is_some(), key_file, yubikey_slot);

        args.push(kdbx_path.display().to_string());
        args.push(entry_path.to_string());

        let mut child = Self::keepassxc_command(cli_path)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .ok()?;

        if let Some(mut stdin) = child.stdin.take()
            && let Some(db_pwd) = db_password
        {
            stdin.write_all(db_pwd.expose_secret().as_bytes()).ok()?;
            stdin.write_all(b"\n").ok()?;
        }

        // A `-y` read blocks on a touch, so give it the touch budget.
        let output = if yubikey_slot.is_some() {
            wait_for_cli_yubikey(child, "show (username)").ok()?
        } else {
            wait_for_cli(child, "show (username)").ok()?
        };

        if output.status.success() {
            let username = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if username.is_empty() {
                None
            } else {
                Some(username)
            }
        } else {
            tracing::debug!(
                entry_path,
                exit_code = ?output.status.code(),
                stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                "get_username_from_kdbx: keepassxc-cli show failed"
            );
            None
        }
    }

    /// Gets URL from a KDBX entry
    fn get_url_from_kdbx(
        kdbx_path: &Path,
        db_password: Option<&SecretString>,
        key_file: Option<&Path>,
        cli_path: &Path,
        entry_path: &str,
        yubikey_slot: Option<&str>,
    ) -> Option<String> {
        use std::io::Write as IoWrite;
        use std::process::Stdio;

        let mut args = vec![
            "show".to_string(),
            "-q".to_string(),
            "-s".to_string(),
            "-a".to_string(),
            "URL".to_string(),
        ];

        push_unlock_args(&mut args, db_password.is_some(), key_file, yubikey_slot);

        args.push(kdbx_path.display().to_string());
        args.push(entry_path.to_string());

        let mut child = Self::keepassxc_command(cli_path)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .ok()?;

        if let Some(mut stdin) = child.stdin.take()
            && let Some(db_pwd) = db_password
        {
            stdin.write_all(db_pwd.expose_secret().as_bytes()).ok()?;
            stdin.write_all(b"\n").ok()?;
        }

        // A `-y` read blocks on a touch, so give it the touch budget.
        let output = if yubikey_slot.is_some() {
            wait_for_cli_yubikey(child, "show (url)").ok()?
        } else {
            wait_for_cli(child, "show (url)").ok()?
        };

        if output.status.success() {
            let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if url.is_empty() { None } else { Some(url) }
        } else {
            tracing::debug!(
                entry_path,
                exit_code = ?output.status.code(),
                stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                "get_url_from_kdbx: keepassxc-cli show failed"
            );
            None
        }
    }

    /// Verifies a KDBX database password using `keepassxc-cli`
    ///
    /// # Arguments
    /// * `kdbx_path` - Path to the KDBX database file
    /// * `password` - Password to verify
    ///
    /// # Returns
    /// * `Ok(())` if the password is correct
    /// * `Err(String)` with error description if verification fails
    ///
    /// # Errors
    /// Returns an error if:
    /// - `keepassxc-cli` is not installed
    /// - The KDBX file path is invalid
    /// - The password is incorrect
    /// - The database cannot be opened
    pub fn verify_kdbx_password(kdbx_path: &Path, password: &SecretString) -> SecretResult<()> {
        Self::verify_kdbx_credentials(kdbx_path, Some(password), None, None)
    }

    /// Verifies KDBX database credentials (password and/or key file) using `keepassxc-cli`
    ///
    /// # Arguments
    /// * `kdbx_path` - Path to the KDBX database file
    /// * `password` - Password to verify (None if using key file only)
    /// * `key_file` - Optional path to key file
    /// * `yubikey_slot` - Optional `YubiKey` Challenge-Response slot as
    ///   `slot[:serial]`; when `Some`, passed to `keepassxc-cli` as `-y` and
    ///   composed with the password and/or key file.
    ///
    /// # Returns
    /// * `Ok(())` if the credentials are correct
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::KeePassXC`] if `keepassxc-cli` is not installed
    /// or fails, or [`SecretError::Backend`] if the password / key file is
    /// rejected by the database.
    pub fn verify_kdbx_credentials(
        kdbx_path: &Path,
        password: Option<&SecretString>,
        key_file: Option<&Path>,
        yubikey_slot: Option<&str>,
    ) -> SecretResult<()> {
        use std::io::Write as IoWrite;
        use std::process::Stdio;

        // First validate the path
        Self::validate_kdbx_path(kdbx_path)?;

        // Find keepassxc-cli
        let cli_path = Self::find_keepassxc_cli().ok_or_else(|| {
            SecretError::KeePassXC("keepassxc-cli not found. Please install KeePassXC.".to_string())
        })?;

        // Build command arguments
        let mut args = vec!["ls".to_string(), "-q".to_string()];

        push_unlock_args(&mut args, password.is_some(), key_file, yubikey_slot);

        args.push(kdbx_path.display().to_string());

        let mut child = Self::keepassxc_command(&cli_path)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| SecretError::KeePassXC(format!("Failed to run keepassxc-cli: {e}")))?;

        // Write password to stdin (only if we have one)
        if let Some(mut stdin) = child.stdin.take()
            && let Some(pwd) = password
        {
            stdin
                .write_all(pwd.expose_secret().as_bytes())
                .map_err(|e| SecretError::KeePassXC(format!("Failed to send password: {e}")))?;
            stdin
                .write_all(b"\n")
                .map_err(|e| SecretError::KeePassXC(format!("Failed to send password: {e}")))?;
        }

        // A Challenge-Response check blocks on a physical touch, so give it the
        // longer budget; a password/key-file-only check keeps the tight one.
        let output = if yubikey_slot.is_some() {
            wait_for_cli_yubikey(child, "ls (credential check)")?
        } else {
            wait_for_cli(child, "ls (credential check)")?
        };

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("Invalid credentials")
                || stderr.contains("wrong password")
                || stderr.contains("Error while reading the database")
            {
                Err(SecretError::KeePassXC(
                    "Invalid password or key file".to_string(),
                ))
            } else if stderr.is_empty() {
                Err(SecretError::KeePassXC(
                    "Failed to open database. Check your credentials.".to_string(),
                ))
            } else {
                Err(SecretError::KeePassXC(format!(
                    "Database error: {}",
                    stderr.trim()
                )))
            }
        }
    }

    /// Validates a key file path
    ///
    /// # Arguments
    /// * `path` - Path to validate
    ///
    /// # Returns
    /// * `Ok(())` if the path is valid
    ///
    /// Note: `KeePassXC` creates key files without extension by default,
    /// so we don't require a specific extension.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::Backend`] when the file does not exist, is not a
    /// regular file, or is not readable.
    pub fn validate_key_file_path(path: &Path) -> SecretResult<()> {
        // Check if file exists
        if !path.exists() {
            return Err(SecretError::KeePassXC(format!(
                "Key file does not exist: {}",
                path.display()
            )));
        }

        // Check if it's a file (not a directory)
        if !path.is_file() {
            return Err(SecretError::KeePassXC(format!(
                "Path is not a file: {}",
                path.display()
            )));
        }

        Ok(())
    }
}

/// Parses a version string from `KeePassXC` CLI output
///
/// The output format is typically: "keepassxc-cli 2.7.6"
/// or just "2.7.6" on some systems.
///
/// # Arguments
/// * `output` - The raw output from `keepassxc-cli --version`
///
/// # Returns
/// * `Some(String)` containing the version number if found
/// * `None` if no valid version could be extracted
#[must_use]
pub fn parse_keepassxc_version(output: &str) -> Option<String> {
    let output = output.trim();

    if output.is_empty() {
        return None;
    }

    // Try to find a version pattern (digits and dots)
    // Common formats:
    // - "keepassxc-cli 2.7.6"
    // - "2.7.6"
    // - "KeePassXC 2.7.6"

    // Split by whitespace and look for version-like strings
    for part in output.split_whitespace() {
        // Check if this part looks like a version (starts with digit, contains dots)
        if part.chars().next().is_some_and(|c| c.is_ascii_digit())
            && part.contains('.')
            && part.chars().all(|c| c.is_ascii_digit() || c == '.')
        {
            return Some(part.to_string());
        }
    }

    // If no version found with dots, try to find any digit sequence
    // This handles edge cases like "2" or "2.7"
    for part in output.split_whitespace() {
        if part.chars().next().is_some_and(|c| c.is_ascii_digit())
            && part.chars().all(|c| c.is_ascii_digit() || c == '.')
        {
            return Some(part.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_unlock_args_password_only_adds_nothing() {
        // A master-password-only unlock: no --no-password, no --key-file, no -y.
        let mut args = vec!["show".to_string()];
        push_unlock_args(&mut args, true, None, None);
        assert_eq!(args, vec!["show".to_string()]);
    }

    #[test]
    fn push_unlock_args_key_file_only_uses_no_password() {
        let mut args: Vec<String> = Vec::new();
        let kf = Path::new("/tmp/db.keyx");
        push_unlock_args(&mut args, false, Some(kf), None);
        assert_eq!(
            args,
            vec![
                "--no-password".to_string(),
                "--key-file".to_string(),
                "/tmp/db.keyx".to_string(),
            ]
        );
    }

    #[test]
    fn push_unlock_args_yubikey_composes_with_password_and_key_file() {
        // Password present (so no --no-password) + key file + YubiKey slot.
        let mut args: Vec<String> = Vec::new();
        let kf = Path::new("/tmp/db.keyx");
        push_unlock_args(&mut args, true, Some(kf), Some("2:12345678"));
        assert_eq!(
            args,
            vec![
                "--key-file".to_string(),
                "/tmp/db.keyx".to_string(),
                "-y".to_string(),
                "2:12345678".to_string(),
            ]
        );
    }

    #[test]
    fn push_unlock_args_yubikey_only_uses_no_password() {
        // Hardware-key-only unlock: --no-password plus -y, no key file.
        let mut args: Vec<String> = Vec::new();
        push_unlock_args(&mut args, false, None, Some("1"));
        assert_eq!(
            args,
            vec![
                "--no-password".to_string(),
                "-y".to_string(),
                "1".to_string(),
            ]
        );
    }

    /// The write path threads the YubiKey slot — the regression #350 was about.
    /// A password-protected KDBX that also requires a Challenge-Response touch:
    /// the master password is present (so NO `--no-password`), and `-y <slot>`
    /// must appear on the `add` argv or the write cannot unlock the database.
    #[test]
    fn build_add_args_password_plus_yubikey_carries_the_slot() {
        let args = build_add_args(
            true,
            None,
            Some("2:12345678"),
            "alice",
            Some("ssh://host"),
            Path::new("/tmp/db.kdbx"),
            "RustConn/host (ssh)",
        );
        // No --no-password when a master password is present.
        assert!(!args.iter().any(|a| a == "--no-password"), "argv: {args:?}");
        // The slot must be threaded as `-y <slot>`.
        let y = args.iter().position(|a| a == "-y").expect("-y present");
        assert_eq!(args[y + 1], "2:12345678");
        assert_eq!(
            args,
            vec![
                "add".to_string(),
                "-q".to_string(),
                "-y".to_string(),
                "2:12345678".to_string(),
                "-u".to_string(),
                "alice".to_string(),
                "--url".to_string(),
                "ssh://host".to_string(),
                "-p".to_string(),
                "/tmp/db.kdbx".to_string(),
                "RustConn/host (ssh)".to_string(),
            ]
        );
    }

    /// Key file + YubiKey, no master password: `--no-password` is emitted (the
    /// CLI would otherwise read an empty stdin line as an empty password), the
    /// key file is passed, and the slot is threaded.
    #[test]
    fn build_add_args_key_file_plus_yubikey_no_password() {
        let args = build_add_args(
            false,
            Some(Path::new("/tmp/db.keyx")),
            Some("1"),
            "",
            None,
            Path::new("/tmp/db.kdbx"),
            "RustConn/entry",
        );
        assert_eq!(
            args,
            vec![
                "add".to_string(),
                "-q".to_string(),
                "--no-password".to_string(),
                "--key-file".to_string(),
                "/tmp/db.keyx".to_string(),
                "-y".to_string(),
                "1".to_string(),
                // no -u (empty username), no --url (None)
                "-p".to_string(),
                "/tmp/db.kdbx".to_string(),
                "RustConn/entry".to_string(),
            ]
        );
    }

    /// YubiKey-only unlock (no master password, no key file): `--no-password`
    /// plus `-y <slot>`, and nothing else on the unlock side.
    #[test]
    fn build_add_args_yubikey_only_no_password() {
        let args = build_add_args(
            false,
            None,
            Some("2"),
            "",
            None,
            Path::new("/tmp/db.kdbx"),
            "RustConn/entry",
        );
        assert_eq!(
            args,
            vec![
                "add".to_string(),
                "-q".to_string(),
                "--no-password".to_string(),
                "-y".to_string(),
                "2".to_string(),
                "-p".to_string(),
                "/tmp/db.kdbx".to_string(),
                "RustConn/entry".to_string(),
            ]
        );
    }

    /// Without a YubiKey slot the write argv is unchanged from before #350: a
    /// master password alone emits no unlock flags beyond `-p`.
    #[test]
    fn build_add_args_password_only_has_no_yubikey() {
        let args = build_add_args(
            true,
            None,
            None,
            "",
            None,
            Path::new("/tmp/db.kdbx"),
            "RustConn/entry",
        );
        assert!(!args.iter().any(|a| a == "-y"), "argv: {args:?}");
        assert!(!args.iter().any(|a| a == "--no-password"), "argv: {args:?}");
        assert_eq!(
            args,
            vec![
                "add".to_string(),
                "-q".to_string(),
                "-p".to_string(),
                "/tmp/db.kdbx".to_string(),
                "RustConn/entry".to_string(),
            ]
        );
    }

    #[test]
    fn test_validate_kdbx_path_valid_extension() {
        // Create a temp file with .kdbx extension
        let temp_dir = tempfile::tempdir().unwrap();
        let kdbx_path = temp_dir.path().join("test.kdbx");
        std::fs::write(&kdbx_path, b"dummy content").unwrap();

        assert!(KeePassStatus::validate_kdbx_path(&kdbx_path).is_ok());
    }

    #[test]
    fn test_validate_kdbx_path_uppercase_extension() {
        let temp_dir = tempfile::tempdir().unwrap();
        let kdbx_path = temp_dir.path().join("test.KDBX");
        std::fs::write(&kdbx_path, b"dummy content").unwrap();

        assert!(KeePassStatus::validate_kdbx_path(&kdbx_path).is_ok());
    }

    #[test]
    fn test_validate_kdbx_path_wrong_extension() {
        let temp_dir = tempfile::tempdir().unwrap();
        let txt_path = temp_dir.path().join("test.txt");
        std::fs::write(&txt_path, b"dummy content").unwrap();

        let result = KeePassStatus::validate_kdbx_path(&txt_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains(".kdbx extension"));
    }

    #[test]
    fn test_validate_kdbx_path_nonexistent() {
        let path = std::path::PathBuf::from("/nonexistent/path/test.kdbx");
        let result = KeePassStatus::validate_kdbx_path(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }

    #[test]
    fn test_validate_kdbx_path_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        // Create a directory with .kdbx name
        let dir_path = temp_dir.path().join("test.kdbx");
        std::fs::create_dir(&dir_path).unwrap();

        let result = KeePassStatus::validate_kdbx_path(&dir_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not a file"));
    }

    #[test]
    fn test_parse_version_standard_format() {
        assert_eq!(
            parse_keepassxc_version("keepassxc-cli 2.7.6"),
            Some("2.7.6".to_string())
        );
    }

    #[test]
    fn test_parse_version_just_number() {
        assert_eq!(parse_keepassxc_version("2.7.6"), Some("2.7.6".to_string()));
    }

    #[test]
    fn test_parse_version_with_prefix() {
        assert_eq!(
            parse_keepassxc_version("KeePassXC 2.7.6"),
            Some("2.7.6".to_string())
        );
    }

    #[test]
    fn test_parse_version_empty() {
        assert_eq!(parse_keepassxc_version(""), None);
    }

    #[test]
    fn test_parse_version_whitespace() {
        assert_eq!(parse_keepassxc_version("   "), None);
    }

    #[test]
    fn test_parse_version_no_version() {
        assert_eq!(parse_keepassxc_version("keepassxc-cli"), None);
    }

    #[test]
    fn test_parse_version_with_newline() {
        assert_eq!(
            parse_keepassxc_version("keepassxc-cli 2.7.6\n"),
            Some("2.7.6".to_string())
        );
    }

    #[test]
    fn test_default_status() {
        let status = KeePassStatus::default();
        assert!(!status.keepassxc_installed);
        assert!(status.keepassxc_version.is_none());
        assert!(status.keepassxc_path.is_none());
        assert!(!status.kdbx_configured);
        assert!(!status.kdbx_accessible);
        assert!(!status.integration_active);
    }

    /// The three outcomes the readers branch on, in the CLI's own English.
    ///
    /// `keepassxc-cli` exits 1 for all of them, so this prose is the only signal
    /// there is — which is why [`KeePassStatus::keepassxc_command`] has to keep it
    /// in English. These are the wordings from 2.7.x.
    #[test]
    fn classify_show_failure_reads_english_diagnostics() {
        assert!(matches!(
            classify_show_failure("Could not find entry with path RustConn/example (ssh)."),
            ShowFailure::EntryMissing
        ));
        assert!(matches!(
            classify_show_failure("Invalid credentials were provided, please try again."),
            ShowFailure::BadCredentials
        ));
        // Anything unrecognised stays Unusable: the database was not opened, so
        // "the entry is not there" is not a conclusion available to us.
        assert!(matches!(
            classify_show_failure("Error while reading the database: Not a KeePass database."),
            ShowFailure::Unusable
        ));
    }

    /// The candidate order, pinned. Nothing could test this before: exercising
    /// the loop needs a `keepassxc-cli` and a real database on the machine
    /// running the tests, so the sequence was only visible by reading it.
    #[test]
    fn the_current_naming_scheme_is_tried_first() {
        let paths = candidate_entry_paths("Production/nginx-01 (ssh)", None);
        assert_eq!(paths[0], "RustConn/Production/nginx-01 (ssh)");
    }

    #[test]
    fn the_protocol_suffix_is_dropped_for_the_older_format() {
        let paths = candidate_entry_paths("nginx-01 (ssh)", None);
        assert_eq!(
            paths,
            vec![
                "RustConn/nginx-01 (ssh)",
                "RustConn/nginx-01",
                "nginx-01 (ssh)",
            ]
        );
    }

    /// The saving: each candidate is a full database open, and this one could
    /// never match a grouped connection.
    ///
    /// `build_entry_path` starts every path at `RustConn`, so `Production/x` at
    /// the database root is not a location any release has written. Trying it
    /// cost an Argon2 open — about 700 ms — on every lookup for every connection
    /// that lives in a group.
    #[test]
    fn a_grouped_name_does_not_get_searched_at_the_database_root() {
        let paths = candidate_entry_paths("Production/nginx-01 (ssh)", None);
        assert!(
            !paths.iter().any(|p| !p.starts_with("RustConn/")),
            "a name carrying a group path must only be looked for under RustConn/: {paths:?}"
        );
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn an_ungrouped_name_is_still_searched_at_the_root() {
        // Where a pre-hierarchy release did write it, so this one stays.
        let paths = candidate_entry_paths("nginx-01", None);
        assert_eq!(paths, vec!["RustConn/nginx-01", "nginx-01"]);
    }

    #[test]
    fn a_separately_supplied_protocol_adds_its_own_candidate() {
        let paths = candidate_entry_paths("nginx-01", Some("ssh"));
        assert_eq!(
            paths,
            vec!["RustConn/nginx-01", "RustConn/nginx-01 (ssh)", "nginx-01",]
        );
    }

    /// Why the message locale is pinned, stated as a test.
    ///
    /// This is the stderr from the bug report — `keepassxc-cli` 2.7.12 answering a
    /// missing entry in Ukrainian, because RustConn had exported `LANGUAGE=uk` for
    /// its own UI. The classifier cannot read it, and the resulting
    /// [`ShowFailure::Unusable`] became "Could not read the password from
    /// KeePassXC" for a healthy database. The fix is upstream of this function: the
    /// child never gets a translated locale in the first place.
    #[test]
    fn classify_show_failure_cannot_read_a_translated_diagnostic() {
        let translated = "Неможливо знайти запис із шляхом RustConn/kiro-cli (zerotrust).";
        assert!(
            matches!(classify_show_failure(translated), ShowFailure::Unusable),
            "if this ever classifies correctly, the locale pinning is no longer \
             load-bearing and this test should say so"
        );
    }

    /// The fix: diagnostics must arrive untranslated, and the encoding must not be
    /// collateral damage.
    #[test]
    fn keepassxc_command_pins_the_message_locale_only() {
        if crate::flatpak::is_flatpak() {
            // The sandbox branch forwards `--env=` arguments to flatpak-spawn
            // instead, so `get_envs` would report nothing either way.
            return;
        }

        let cmd = KeePassStatus::keepassxc_command(std::path::Path::new("/usr/bin/keepassxc-cli"));
        let envs: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        let lookup = |name: &str| envs.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());

        assert_eq!(
            lookup("LC_MESSAGES"),
            Some(Some("C".to_string())),
            "messages must be pinned to C or classify_show_failure cannot read them"
        );
        assert_eq!(
            lookup("LANGUAGE"),
            Some(None),
            "LANGUAGE must be cleared for the child: this process exports it, and \
             it outranks LC_MESSAGES"
        );
        assert!(
            lookup("LC_ALL").is_none_or(|value| value.is_none()),
            "LC_ALL must never be handed to the child set: it outranks LC_MESSAGES"
        );
        // Encoding is deliberately not forced — entry paths and the database path
        // travel as argv, and a Qt 5 build takes its codec from the locale charset.
        assert_ne!(
            lookup("LC_CTYPE"),
            Some(Some("C".to_string())),
            "forcing a C charset would mangle non-ASCII entry paths"
        );
        // Unchanged behaviour: macOS GUI launches still need the extended PATH so
        // keepassxc-cli can find its own children (e.g. GPG).
        assert!(
            matches!(lookup("PATH"), Some(Some(_))),
            "the extended PATH must still be injected"
        );
    }
}
