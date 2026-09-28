//! Remembers where each connection last actually went, to catch a silent
//! re-point of a shared connection.
//!
//! In a shared, synced catalog (group sync, a team `.rcn`), a user who may
//! *edit* a connection but not *reveal* its password can change where it points
//! — its host, port, account or jump host — to a machine of their own, then
//! wait for someone else to connect with the stored secret. The saved password
//! then travels to the attacker's machine.
//!
//! This module records, **on this computer only**, the route each connection
//! took the last time it connected successfully. Before a later connection it
//! compares the current route against the remembered one and reports a change,
//! so the user is asked before a moved connection carries their credentials
//! somewhere new. The record is deliberately local — kept out of the synced
//! catalog — because the same person who could re-point the connection could
//! also edit a record that travelled with it.
//!
//! It is a warning, not encryption: it cannot stop a determined change, only
//! make a silent one visible. A local-only catalog and a personal PostgreSQL
//! database have no third party between the user and the catalog, so a caller
//! may skip the check there; that policy lives in the GUI, not here.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The routing-relevant fields of a connection: where it goes and who it
/// authenticates as, plus the bastion in front of it.
///
/// Everything here is compared verbatim. `password_source` and `jump` are
/// stored as already-resolved strings so the record does not depend on model
/// enums whose representation may change; a change in any field is a change in
/// route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// Target host as configured.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// Account name, or empty when none is set.
    #[serde(default)]
    pub username: String,
    /// A stable description of where the password comes from (e.g. `vault`,
    /// `prompt`, `variable:NAME`), so re-pointing the credential is caught.
    #[serde(default)]
    pub password_source: String,
    /// The effective bastion in front of the target, as an opaque resolved
    /// string (the `-J` value, or a jump-host id), or empty when direct.
    #[serde(default)]
    pub jump: String,
}

/// The outcome of comparing a connection's current route to what was last
/// remembered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteVerdict {
    /// No route was remembered for this connection — the first connection is
    /// recorded silently, with nothing to warn about.
    FirstSeen,
    /// The current route matches the remembered one.
    Unchanged,
    /// The route differs from the one last connected to. Carries the previous
    /// route so the caller can show "was → now".
    Changed(Box<Route>),
}

/// A local, per-connection record of last-known routes.
///
/// Keyed by connection id. Persisted as JSON in the app data directory, never
/// in the synced catalog.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoutingMemory {
    #[serde(default)]
    routes: HashMap<Uuid, Route>,
}

/// The file name under the app data directory.
const ROUTING_FILE: &str = "connection-routes.json";

/// Returns the path to the routing-memory file, or `None` when no data
/// directory can be determined.
#[must_use]
pub fn routing_memory_path() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("rustconn").join(ROUTING_FILE))
}

impl RoutingMemory {
    /// Loads the routing memory from `path`.
    ///
    /// A missing file is not an error — it yields an empty memory, which is the
    /// correct state for a fresh install where every connection is first-seen.
    /// A corrupt file is treated the same way rather than failing a connection.
    #[must_use]
    pub fn load(path: &std::path::Path) -> Self {
        let Ok(contents) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        serde_json::from_str(&contents).unwrap_or_default()
    }

    /// Loads from the default [`routing_memory_path`], or an empty memory when
    /// no data directory exists.
    #[must_use]
    pub fn load_default() -> Self {
        routing_memory_path().map_or_else(Self::default, |p| Self::load(&p))
    }

    /// Writes the routing memory to `path`, creating the parent directory.
    ///
    /// # Errors
    ///
    /// Returns an [`std::io::Error`] if the directory cannot be created or the
    /// file cannot be written.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }

    /// Saves to the default [`routing_memory_path`].
    ///
    /// # Errors
    ///
    /// Returns an [`std::io::Error`] on a write failure, or one of kind
    /// [`std::io::ErrorKind::NotFound`] when no data directory is available.
    pub fn save_default(&self) -> std::io::Result<()> {
        let path = routing_memory_path().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no data directory for routing memory",
            )
        })?;
        self.save(&path)
    }

    /// Compares `current` against the remembered route for `id`.
    ///
    /// Returns [`RouteVerdict::FirstSeen`] when nothing is remembered,
    /// [`RouteVerdict::Unchanged`] when it matches, or
    /// [`RouteVerdict::Changed`] with the previous route otherwise. Does not
    /// mutate; call [`Self::remember`] after a successful connection.
    #[must_use]
    pub fn check(&self, id: Uuid, current: &Route) -> RouteVerdict {
        match self.routes.get(&id) {
            None => RouteVerdict::FirstSeen,
            Some(previous) if previous == current => RouteVerdict::Unchanged,
            Some(previous) => RouteVerdict::Changed(Box::new(previous.clone())),
        }
    }

    /// Records `route` as the last-known route for `id`.
    ///
    /// Call only after a connection actually succeeds, so a failed attempt
    /// cannot launder a re-point into the record.
    pub fn remember(&mut self, id: Uuid, route: Route) {
        self.routes.insert(id, route);
    }

    /// Drops the remembered route for `id` (e.g. when the connection is
    /// deleted). A no-op when none is stored.
    pub fn forget(&mut self, id: Uuid) {
        self.routes.remove(&id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(host: &str, jump: &str) -> Route {
        Route {
            host: host.to_string(),
            port: 22,
            username: "me".to_string(),
            password_source: "vault".to_string(),
            jump: jump.to_string(),
        }
    }

    #[test]
    fn first_connection_is_first_seen() {
        let mem = RoutingMemory::default();
        assert_eq!(
            mem.check(Uuid::nil(), &route("host.example.com", "")),
            RouteVerdict::FirstSeen
        );
    }

    #[test]
    fn same_route_is_unchanged() {
        let mut mem = RoutingMemory::default();
        let id = Uuid::new_v4();
        let r = route("host.example.com", "");
        mem.remember(id, r.clone());
        assert_eq!(mem.check(id, &r), RouteVerdict::Unchanged);
    }

    #[test]
    fn a_changed_host_is_reported_with_the_previous_route() {
        let mut mem = RoutingMemory::default();
        let id = Uuid::new_v4();
        mem.remember(id, route("old.example.com", ""));
        let verdict = mem.check(id, &route("new.example.com", ""));
        match verdict {
            RouteVerdict::Changed(prev) => assert_eq!(prev.host, "old.example.com"),
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn a_changed_jump_host_is_a_change() {
        let mut mem = RoutingMemory::default();
        let id = Uuid::new_v4();
        mem.remember(id, route("host.example.com", "bastion-a"));
        assert!(matches!(
            mem.check(id, &route("host.example.com", "bastion-b")),
            RouteVerdict::Changed(_)
        ));
    }

    #[test]
    fn a_changed_credential_source_is_a_change() {
        let mut mem = RoutingMemory::default();
        let id = Uuid::new_v4();
        let mut before = route("host.example.com", "");
        before.password_source = "vault".to_string();
        mem.remember(id, before);
        let mut after = route("host.example.com", "");
        after.password_source = "prompt".to_string();
        assert!(matches!(mem.check(id, &after), RouteVerdict::Changed(_)));
    }

    #[test]
    fn remember_overwrites_and_clears_the_change() {
        let mut mem = RoutingMemory::default();
        let id = Uuid::new_v4();
        mem.remember(id, route("old.example.com", ""));
        // Accept the new route (user confirmed) and record it.
        mem.remember(id, route("new.example.com", ""));
        assert_eq!(
            mem.check(id, &route("new.example.com", "")),
            RouteVerdict::Unchanged
        );
    }

    #[test]
    fn forget_removes_the_record() {
        let mut mem = RoutingMemory::default();
        let id = Uuid::new_v4();
        mem.remember(id, route("host.example.com", ""));
        mem.forget(id);
        assert_eq!(
            mem.check(id, &route("host.example.com", "")),
            RouteVerdict::FirstSeen
        );
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("rustconn-routing-test-{}", Uuid::new_v4()));
        let path = dir.join("routes.json");
        let mut mem = RoutingMemory::default();
        let id = Uuid::new_v4();
        mem.remember(id, route("host.example.com", "bastion"));
        mem.save(&path).expect("save");

        let loaded = RoutingMemory::load(&path);
        assert_eq!(
            loaded.check(id, &route("host.example.com", "bastion")),
            RouteVerdict::Unchanged
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_loads_empty() {
        let path =
            std::env::temp_dir().join(format!("rustconn-nonexistent-{}.json", Uuid::new_v4()));
        let mem = RoutingMemory::load(&path);
        assert_eq!(
            mem.check(Uuid::nil(), &route("h", "")),
            RouteVerdict::FirstSeen
        );
    }
}
