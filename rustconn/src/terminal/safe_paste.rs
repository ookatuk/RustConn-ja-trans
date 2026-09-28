//! Safe paste — confirm before a multi-line paste reaches the terminal.
//!
//! A multi-line clipboard paste runs every line the moment its newline is
//! delivered to the shell, so text copied from a web page can carry a hidden
//! second command (`curl … | sh` after an innocent-looking first line) that
//! executes before the user can read it — the "pastejacking" trap. This module
//! routes every paste path through [`paste_into_terminal`], which pastes a
//! single-line clipboard straight away and, for a multi-line one, shows a
//! preview and waits for confirmation.
//!
//! The behaviour is governed by one global flag rather than a per-terminal one:
//! `confirm_multiline_paste` is a global Terminal setting, and the paste paths
//! (Ctrl+V, the context menu, the split-view and detached-window paste actions)
//! do not all have an `AppState` handle. [`set_confirm_multiline_paste`] is
//! called from `configure_terminal_with_settings`, which the settings dialog
//! already re-runs on save, so the flag tracks the setting without threading it
//! through every call site.

use std::cell::Cell;

use adw::prelude::*;
use gtk4::prelude::*;
use libadwaita as adw;
use vte4::{Terminal, TerminalExt};

use crate::i18n::{i18n, i18n_f};

thread_local! {
    /// Whether a multi-line paste must be confirmed. Mirrors
    /// `TerminalSettings::confirm_multiline_paste`; updated whenever terminal
    /// settings are applied. GTK is single-threaded, so a thread-local is the
    /// whole-process value here.
    static CONFIRM_MULTILINE_PASTE: Cell<bool> = const { Cell::new(true) };
}

/// Records whether multi-line pastes must be confirmed.
///
/// Called from `configure_terminal_with_settings` so the flag follows the
/// `confirm_multiline_paste` terminal setting, including after a live change in
/// Preferences.
pub fn set_confirm_multiline_paste(confirm: bool) {
    CONFIRM_MULTILINE_PASTE.with(|c| c.set(confirm));
}

/// Number of preview lines shown in the confirmation dialog before eliding.
const PREVIEW_LINES: usize = 12;

/// Pastes the clipboard into `terminal`, confirming first if it is multi-line.
///
/// A single-line clipboard (or an empty one) is pasted immediately through
/// VTE's own `paste_clipboard`, so the common case is unchanged. A clipboard
/// holding a newline is shown in a preview dialog first, unless confirmation is
/// switched off in settings; only "Paste" sends it on.
///
/// Reading the clipboard is asynchronous, so this returns immediately and the
/// paste (or the dialog) happens once the text has arrived.
pub fn paste_into_terminal(terminal: &Terminal) {
    if !CONFIRM_MULTILINE_PASTE.with(Cell::get) {
        terminal.paste_clipboard();
        return;
    }

    // `Terminal` is a `Widget`; use its own display rather than the root's, to
    // avoid the RootExt/WidgetExt `display()` ambiguity.
    let clipboard = terminal.display().clipboard();

    let terminal = terminal.clone();
    clipboard.read_text_async(gtk4::gio::Cancellable::NONE, move |result| {
        // No text on the clipboard, or the read failed: fall back to VTE's own
        // paste, which handles the empty/non-text case gracefully.
        let Ok(Some(text)) = result else {
            terminal.paste_clipboard();
            return;
        };
        let text = text.to_string();

        if is_multiline(&text) {
            confirm_and_paste(&terminal, &text);
        } else {
            terminal.paste_clipboard();
        }
    });
}

/// Returns `true` when pasting `text` would send more than one line to the
/// shell — i.e. it contains a line break somewhere other than a single
/// trailing newline.
///
/// A lone trailing newline is the ordinary "copied a whole line" case and is
/// not treated as multi-line: it submits one command, which is what the user
/// selected. An interior newline, or several, is what warrants a look.
fn is_multiline(text: &str) -> bool {
    let without_trailing = text.strip_suffix('\n').unwrap_or(text);
    without_trailing.contains('\n') || without_trailing.contains('\r')
}

/// Builds the preview body: the first [`PREVIEW_LINES`] lines, with a note when
/// more were elided, and always the total line count.
fn preview_body(text: &str) -> String {
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = normalized.split('\n').collect();
    // A trailing newline yields a final empty element; do not count it as a line.
    let line_count = if normalized.ends_with('\n') {
        lines.len().saturating_sub(1)
    } else {
        lines.len()
    };

    let shown: String = lines
        .iter()
        .take(PREVIEW_LINES)
        .copied()
        .collect::<Vec<_>>()
        .join("\n");

    if line_count > PREVIEW_LINES {
        format!(
            "{shown}\n{}",
            i18n_f(
                "…and {} more lines",
                &[&(line_count - PREVIEW_LINES).to_string()]
            )
        )
    } else {
        shown
    }
}

/// Shows the multi-line paste confirmation dialog and pastes on approval.
fn confirm_and_paste(terminal: &Terminal, text: &str) {
    let dialog = adw::AlertDialog::new(
        Some(&i18n("Paste multiple lines?")),
        Some(&i18n(
            "The clipboard holds more than one line. Each line runs as soon as it is pasted — check it before continuing.",
        )),
    );
    // This dialog exists to be read: the whole point is that the user scans the
    // pasted text before it runs. The default AlertDialog is sized for a short
    // question and left the preview cramped, so the preview below sets its own
    // width and the dialog grows to fit it — in line with the wider text-editing
    // dialogs (the connection editor is 600 wide). GNOME HIG allows a wider
    // message dialog when the content warrants it.

    // The preview is a read-only, scrollable, monospace view so a long or wide
    // paste stays legible. It sets its own content width so the dialog opens
    // wide enough to read a command line without wrapping every token, and only
    // scrolls horizontally for the occasional over-long line.
    let buffer = gtk4::TextBuffer::builder().text(preview_body(text)).build();
    let text_view = gtk4::TextView::builder()
        .buffer(&buffer)
        .editable(false)
        .monospace(true)
        .cursor_visible(false)
        .build();
    text_view.set_accessible_role(gtk4::AccessibleRole::Label);
    let scrolled = gtk4::ScrolledWindow::builder()
        .min_content_width(520)
        .max_content_width(560)
        .min_content_height(120)
        .max_content_height(280)
        .child(&text_view)
        .build();
    scrolled.add_css_class("card");
    dialog.set_extra_child(Some(&scrolled));

    dialog.add_response("cancel", &i18n("Cancel"));
    dialog.add_response("paste", &i18n("Paste"));
    dialog.set_response_appearance("paste", adw::ResponseAppearance::Suggested);
    dialog.set_default_response(Some("cancel"));
    dialog.set_close_response("cancel");

    let terminal_for_response = terminal.clone();
    dialog.connect_response(None, move |_, response| {
        if response == "paste" {
            terminal_for_response.paste_clipboard();
        }
    });

    // Present relative to the terminal's own window so the dialog is modal to
    // the right window even for a detached session. `AlertDialog::present`
    // takes any widget in the target window; the terminal itself is one.
    dialog.present(Some(terminal));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_line_is_not_multiline() {
        assert!(!is_multiline("ls -la"));
    }

    #[test]
    fn empty_is_not_multiline() {
        assert!(!is_multiline(""));
    }

    #[test]
    fn a_single_trailing_newline_is_not_multiline() {
        // Copying one whole line submits one command — not a multi-line paste.
        assert!(!is_multiline("sudo reboot\n"));
    }

    #[test]
    fn interior_newline_is_multiline() {
        assert!(is_multiline("echo one\necho two"));
    }

    #[test]
    fn trailing_plus_interior_newline_is_multiline() {
        assert!(is_multiline("echo one\necho two\n"));
    }

    #[test]
    fn carriage_return_alone_is_multiline() {
        // Some sources use bare CR; it still submits a line to the shell.
        assert!(is_multiline("echo one\recho two"));
    }

    #[test]
    fn preview_shows_every_line_when_short() {
        let body = preview_body("a\nb\nc");
        assert!(body.contains('a') && body.contains('b') && body.contains('c'));
        assert!(!body.contains("more lines"));
    }

    #[test]
    fn preview_elides_and_counts_when_long() {
        let text: String = (0..20)
            .map(|i| format!("line{i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let body = preview_body(&text);
        assert!(body.contains("line0"));
        assert!(body.contains("line11")); // 12th line (index 11) is the last shown
        assert!(!body.contains("line12")); // 13th line is elided
        // 20 total − 12 shown = 8 elided.
        assert!(body.contains('8'));
    }

    #[test]
    fn preview_normalizes_crlf_for_counting() {
        // 3 CRLF lines must count as 3, not double-count the \r.
        let body = preview_body("a\r\nb\r\nc");
        assert!(!body.contains('\r'));
    }
}
