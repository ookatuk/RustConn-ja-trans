//! Config version-skew safety.
//!
//! Two RustConn versions share one config directory whenever a user upgrades
//! and then downgrades, or runs a distribution package next to a Flatpak. An
//! older version that meets a value it does not know — a new enum variant above
//! all — fails to parse the whole file, and the fallbacks that keep the app
//! running (defaults for `config.toml`, an empty list for clusters or history)
//! are what the next routine save writes back. This module holds the pieces of
//! that defence that are not `ConfigManager` state:
//!
//! - the `written_by` marker every save stamps, and [`is_newer_than_running`],
//!   which lets a load notice a file a newer version wrote, so that the file is
//!   backed up before this version first changes it;
//! - [`quarantine_file`], which copies a file that does not parse aside before a
//!   caller falls back to defaults.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::error::{ConfigError, ConfigResult};

/// Version of the running `RustConn`, stamped into every marked file it saves.
///
/// `rustconn-core` takes its version from the workspace, so this is the number
/// the GUI and the CLI print.
pub(super) const RUNNING_VERSION: &str = env!("CARGO_PKG_VERSION");

/// How many names within one second [`quarantine_file`] tries before giving up.
///
/// A second copy within the same second needs the file rewritten with
/// *different* unreadable bytes in that second — identical bytes reuse the
/// first copy — so the bound is never reached in practice. It keeps the loop
/// finite.
const QUARANTINE_NAME_ATTEMPTS: u32 = 10;

/// Returns whether `written_by` names a newer `RustConn` release than the running one.
///
/// Compares `major.minor.patch` numerically, so `0.22.10` is newer than
/// `0.22.9`. A pre-release suffix, a missing component, or anything else that
/// is not three plain numbers is *not* newer: a marker this version cannot read
/// is treated like no marker at all, which is how every file looked before
/// markers existed.
#[must_use]
pub fn is_newer_than_running(written_by: &str) -> bool {
    is_newer(written_by, RUNNING_VERSION)
}

/// Returns whether release `candidate` is newer than release `running`.
fn is_newer(candidate: &str, running: &str) -> bool {
    match (parse_release(candidate), parse_release(running)) {
        (Some(candidate), Some(running)) => candidate > running,
        _ => false,
    }
}

/// Parses a plain `major.minor.patch` release version.
///
/// Strict on purpose. Only ASCII digits are accepted — `str::parse` alone would
/// also take a leading `+` — and a version that passes ends up in a backup file
/// name, so it must never carry a path separator.
fn parse_release(version: &str) -> Option<[u64; 3]> {
    let mut parts = version.split('.');
    let mut release = [0_u64; 3];
    for number in &mut release {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *number = part.parse().ok()?;
    }
    parts.next().is_none().then_some(release)
}

/// Reads only the `written_by` marker of a TOML config file.
///
/// Serde skips every other key, so a value elsewhere that this version does not
/// understand — the reason to probe at all — does not fail the probe.
#[derive(serde::Deserialize)]
struct WrittenByProbe {
    #[serde(default)]
    written_by: Option<String>,
}

/// Returns the `written_by` marker of a TOML config file's `content`.
///
/// # Errors
///
/// Returns the TOML error when `content` is not a TOML document at all, or its
/// marker is not a string.
pub(super) fn probe_written_by(content: &[u8]) -> Result<Option<String>, toml::de::Error> {
    toml::from_slice::<WrittenByProbe>(content).map(|probe| probe.written_by)
}

/// What [`write_owner_only`] does when its target already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Existing {
    /// Truncate it and write over it.
    Replace,
    /// Fail with [`io::ErrorKind::AlreadyExists`].
    Refuse,
}

/// Writes `bytes` to `path` as an owner-only (`0600`) file and syncs it to disk.
///
/// The config files hold encrypted credentials, so every copy of one gets the
/// permissions the original has.
pub(super) fn write_owner_only(path: &Path, bytes: &[u8], existing: Existing) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true);
    match existing {
        Existing::Replace => {
            options.create(true).truncate(true);
        }
        Existing::Refuse => {
            options.create_new(true);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    // `mode` covers only a file this call creates, and only through the umask; a
    // replaced file keeps the mode it had. Set it outright either way.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    io::Write::write_all(&mut file, bytes)?;
    file.sync_all()
}

/// Copies the file at `path`, byte for byte, to `<file>.unreadable-<UTC timestamp>` beside it.
///
/// For a file that exists but does not parse, just before the caller falls back
/// to defaults: that fallback is what the next routine save writes over the
/// file, so without the copy whatever it held is gone. The copy is owner-only.
/// An earlier copy holding the same bytes is returned instead of adding another,
/// because a file nothing rewrites — clusters, tombstones, custom themes — fails
/// the same way on every start.
///
/// # Errors
///
/// Returns [`ConfigError::Parse`] if `path` cannot be read and
/// [`ConfigError::Write`] if the copy cannot be created.
pub(crate) fn quarantine_file(path: &Path) -> ConfigResult<PathBuf> {
    let content = fs::read(path)
        .map_err(|e| ConfigError::Parse(format!("Failed to read {}: {e}", path.display())))?;
    let file_name = path.file_name().and_then(std::ffi::OsStr::to_str);
    let (Some(dir), Some(file_name)) = (path.parent(), file_name) else {
        return Err(ConfigError::Write(format!(
            "Cannot place a copy of {} beside it",
            path.display()
        )));
    };
    let prefix = format!("{file_name}.unreadable-");

    if let Some(earlier) = find_identical_copy(dir, &prefix, &content) {
        return Ok(earlier);
    }

    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    for attempt in 1..=QUARANTINE_NAME_ATTEMPTS {
        let target = if attempt == 1 {
            dir.join(format!("{prefix}{stamp}"))
        } else {
            dir.join(format!("{prefix}{stamp}-{attempt}"))
        };
        match write_owner_only(&target, &content, Existing::Refuse) {
            Ok(()) => return Ok(target),
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => {
                return Err(ConfigError::Write(format!(
                    "Failed to copy {} to {}: {e}",
                    path.display(),
                    target.display()
                )));
            }
            // Taken this same second by other bytes: try the next name.
            Err(_) => {}
        }
    }
    Err(ConfigError::Write(format!(
        "No free name for a copy of {}",
        path.display()
    )))
}

/// Finds an earlier copy in `dir`, named `<prefix>…`, that holds exactly `content`.
fn find_identical_copy(dir: &Path, prefix: &str, content: &[u8]) -> Option<PathBuf> {
    for entry in fs::read_dir(dir).ok()?.flatten() {
        let candidate = entry.path();
        let named = candidate
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| name.starts_with(prefix));
        if named && fs::read(&candidate).is_ok_and(|existing| existing == content) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table the maintainer asked for, against the version actually running.
    #[test]
    fn only_a_higher_plain_release_is_newer_than_running() {
        let cases = [
            ("99.0.0", true),
            ("0.0.1", false),
            (RUNNING_VERSION, false),
            ("0.22", false),
            ("abc", false),
            ("1.2.3-beta", false),
            ("", false),
        ];
        for (written_by, expected) in cases {
            assert_eq!(
                is_newer_than_running(written_by),
                expected,
                "written_by = {written_by:?}"
            );
        }
    }

    /// Numeric, not lexicographic: `10` sorts before `9` as text.
    #[test]
    fn releases_compare_numerically() {
        assert!(is_newer("0.22.10", "0.22.9"));
        assert!(!is_newer("0.22.9", "0.22.10"));
        assert!(is_newer("0.23.0", "0.22.99"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(!is_newer("0.22.13", "0.22.13"));
    }

    /// Anything but three plain numbers is never newer, and so never reaches a
    /// backup file name.
    #[test]
    fn markers_that_are_not_plain_releases_are_never_newer() {
        for written_by in [
            "+99.0.0",
            "99.0.0.0",
            " 99.0.0",
            "99.0.0 ",
            "v99.0.0",
            "99..0",
            "99.0.0/..",
            "99999999999999999999999.0.0",
        ] {
            assert!(!is_newer(written_by, "0.22.13"), "{written_by:?}");
        }
    }

    /// Markers are compared against this: a pre-release version string would make
    /// every file look "not newer" and silently switch the backups off.
    #[test]
    fn the_running_version_is_a_plain_release() {
        assert!(
            parse_release(RUNNING_VERSION).is_some(),
            "{RUNNING_VERSION} is not major.minor.patch"
        );
    }

    /// The probe reads the marker even where the full parse would fail.
    #[test]
    fn the_probe_reads_the_marker_past_values_it_does_not_know() {
        let content = b"written_by = \"99.0.0\"\n[secrets]\npreferred_backend = \"nope\"\n";
        let marker = probe_written_by(content).unwrap();
        assert_eq!(marker.as_deref(), Some("99.0.0"));

        let unmarked = probe_written_by(b"[terminal]\nfont_size = 12\n").unwrap();
        assert_eq!(unmarked, None);

        assert!(probe_written_by(b"not = [toml").is_err());
    }
}
