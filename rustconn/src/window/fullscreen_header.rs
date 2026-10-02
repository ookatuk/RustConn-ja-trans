//! The main window's header bar while the window is fullscreen (issue #354).
//!
//! Fullscreen hides the header bar, so an embedded RDP or VNC session is not
//! cut by a fixed strip of application chrome. Only the header bar goes: the
//! banners stacked under it in the same [`adw::ToolbarView`] stay where they
//! are, because two of them must never be missed — the group broadcast banner
//! (#329: keystrokes are reaching tabs the user cannot see) and the hardware-key
//! touch cue (#350: without it an unlock looks hung). That is why this hides the
//! one widget rather than calling `set_reveal_top_bars(false)`, which takes every
//! top bar with it.
//!
//! The header comes back without leaving fullscreen in two ways:
//!
//! - the pointer touching the top edge of the screen, the pattern GNOME apps use
//!   for a fullscreen header; it hides again once the pointer moves below the top
//!   bars, unless one of the header's menus is open;
//! - F10, the primary-menu key, which would otherwise have no visible button to
//!   open. It is left alone while keyboard passthrough has cleared the menu
//!   button's `primary` flag, so the key still reaches the remote session.
//!
//! While fullscreen the content extends under the top bars, so revealing the
//! header overlays the session instead of shrinking it. An embedded RDP session
//! resizes the remote desktop on every allocation change, and a header that
//! reflowed the content would trigger one on every hover.
//!
//! Touch has no hover, so on a touch screen without a keyboard the top-edge
//! reveal does not fire and F11 remains the way out of fullscreen.

use std::cell::Cell;
use std::rc::Rc;

use adw::prelude::*;
use gtk4::{gdk, glib};
use libadwaita as adw;

use crate::embedded_toolbar_overflow::contains_active_menu;

/// How close to the top edge, in logical pixels, the pointer has to come to
/// reveal the header. Small on purpose: the top rows of a remote desktop are
/// real targets (its own title bars, a browser's tab strip), and a wide hot zone
/// would cover them with the header every time the user aimed there.
const REVEAL_EDGE_PX: f64 = 2.0;

/// Wires the fullscreen header behaviour onto the main window.
///
/// Reacts to the window's `fullscreened` property rather than to the menu
/// action, so every path into fullscreen is covered — `win.toggle-fullscreen`,
/// F11 and a window-manager fullscreen alike. The current state is applied once
/// here as well, in case the window is already fullscreen.
pub(super) fn install(
    window: &adw::ApplicationWindow,
    toolbar_view: &adw::ToolbarView,
    header_bar: &adw::HeaderBar,
    menu_button: &gtk4::MenuButton,
) {
    // Last pointer height over the window. Starts "far below the top bars", so a
    // header opened with F10 before the pointer has moved hides when its menu
    // closes instead of staying up indefinitely.
    let last_pointer_y = Rc::new(Cell::new(f64::INFINITY));

    apply_fullscreen(toolbar_view, header_bar, window.is_fullscreen());
    {
        let toolbar_view = toolbar_view.clone();
        let header_bar = header_bar.clone();
        window.connect_fullscreened_notify(move |win| {
            apply_fullscreen(&toolbar_view, &header_bar, win.is_fullscreen());
        });
    }

    // Capture phase: the session widgets underneath (VTE, the RDP/VNC drawing
    // area) consume pointer events in the bubble phase. A motion controller
    // never claims anything, so watching here does not take events from them.
    let motion = gtk4::EventControllerMotion::new();
    motion.set_propagation_phase(gtk4::PropagationPhase::Capture);
    {
        let window = window.downgrade();
        let toolbar_view = toolbar_view.clone();
        let header_bar = header_bar.clone();
        let last_pointer_y = Rc::clone(&last_pointer_y);
        motion.connect_motion(move |_, _x, y| {
            last_pointer_y.set(y);
            let Some(window) = window.upgrade() else {
                return;
            };
            if !window.is_fullscreen() {
                return;
            }
            if y <= REVEAL_EDGE_PX {
                header_bar.set_visible(true);
            } else if below_top_bars(&toolbar_view, y) && !header_in_use(&header_bar) {
                header_bar.set_visible(false);
            }
        });
    }
    window.add_controller(motion);

    // F10 with the header hidden: show it and let the key carry on to GTK's own
    // primary-menu binding, which needs a visible button to open.
    let keys = gtk4::EventControllerKey::new();
    keys.set_propagation_phase(gtk4::PropagationPhase::Capture);
    {
        let window = window.downgrade();
        let header_bar = header_bar.clone();
        let menu_button = menu_button.clone();
        keys.connect_key_pressed(move |_, key, _, modifiers| {
            let unmodified = (modifiers & gtk4::accelerator_get_default_mod_mask()).is_empty();
            if key == gdk::Key::F10
                && unmodified
                && menu_button.is_primary()
                && window.upgrade().is_some_and(|w| w.is_fullscreen())
            {
                header_bar.set_visible(true);
            }
            glib::Propagation::Proceed
        });
    }
    window.add_controller(keys);

    // A header opened for its menu goes away again when the menu closes, unless
    // the pointer is still up in the top bars.
    {
        let window = window.downgrade();
        let toolbar_view = toolbar_view.clone();
        let header_bar = header_bar.clone();
        menu_button.connect_active_notify(move |button| {
            if button.is_active() {
                return;
            }
            let Some(window) = window.upgrade() else {
                return;
            };
            if window.is_fullscreen()
                && below_top_bars(&toolbar_view, last_pointer_y.get())
                && !header_in_use(&header_bar)
            {
                header_bar.set_visible(false);
            }
        });
    }
}

/// Puts the header and the content layout into their fullscreen or windowed
/// shape.
///
/// The top-bar style has to change with the layout. Under the default `Flat`
/// style a toolbar view's top bars have no background of their own — they rely
/// on the content starting below them. Once the content extends under them, a
/// flat header is drawn straight over the tab bar and the session, and both
/// show through it. `Raised` gives the top bars the opaque header-bar
/// background and a shadow, so a revealed header covers what is beneath it.
fn apply_fullscreen(
    toolbar_view: &adw::ToolbarView,
    header_bar: &adw::HeaderBar,
    fullscreen: bool,
) {
    toolbar_view.set_top_bar_style(if fullscreen {
        adw::ToolbarStyle::Raised
    } else {
        adw::ToolbarStyle::Flat
    });
    toolbar_view.set_extend_content_to_top_edge(fullscreen);
    header_bar.set_visible(!fullscreen);
}

/// Whether `y` is below everything stacked at the top of the window — the
/// header while it is shown, plus any revealed banner.
fn below_top_bars(toolbar_view: &adw::ToolbarView, y: f64) -> bool {
    y > f64::from(toolbar_view.top_bar_height())
}

/// Whether the header must stay up regardless of where the pointer is, because
/// one of its menus is open.
///
/// Keyboard focus is deliberately not a reason: GTK hands focus back to the
/// menu button when its popover closes, so a focus rule would keep the header
/// pinned after every menu use until the user clicked somewhere else.
fn header_in_use(header_bar: &adw::HeaderBar) -> bool {
    contains_active_menu(header_bar.upcast_ref::<gtk4::Widget>())
}
