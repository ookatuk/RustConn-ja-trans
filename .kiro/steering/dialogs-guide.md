---
inclusion: fileMatch
fileMatchPattern: "rustconn/src/dialogs/**/*.rs"
---

# Dialogs — Development Rules

You are editing a file in `rustconn/src/dialogs/`.

## Widgets

- Use `adw::` widgets over `gtk::` equivalents (AdwPreferencesGroup, AdwEntryRow, AdwComboRow, AdwSpinRow, AdwExpanderRow)
- Wrap content in `adw::Clamp` (max 600px) for consistent width
- Spacing: 12px margins, 6px between related elements (GNOME HIG)

## Accessible Labels

Every icon-only button MUST have:
1. `.set_tooltip_text(Some(&i18n("...")))` — for mouse users
2. `.update_property(&[gtk4::accessible::Property::Label(&i18n("..."))])` — for screen readers

## i18n

- All user-facing strings → `i18n()` or `i18n_f()`
- Placeholders → `{}` (NOT `%1`, `%2`)
- Ignore: icon names, CSS classes, action names, tracing messages

## Large Function Parameters

- If a function has >6 parameters → create a struct (like `BasicTabWidgets`, `RdpConnectionContext`)
- Tuple type aliases → named structs with fields

## Registration

New dialog → add `pub mod` in `dialogs/mod.rs`

Dialog width (`adw::Dialog` `content_width` vs widening an `AlertDialog` through
its `extra_child`) is in `gnome-hig.md`, which loads for every `rustconn/src/**`
file — most `AlertDialog`s are built under `window/` and `terminal/`, not here.
