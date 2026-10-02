//! Monitoring settings for remote host metrics collection
//!
//! Global settings live in `AppSettings.monitoring` and control defaults.
//! Per-connection overrides use `MonitoringConfig` on the `Connection` struct.
//! [`MonitoringOverride`] is the three-way choice its `enabled` field stores, and
//! [`effective_monitoring`] is the one place the two are combined into the
//! settings a session actually runs with.

use serde::{Deserialize, Serialize};

/// Global monitoring settings (stored in `config.toml` under `[monitoring]`)
#[expect(
    clippy::struct_excessive_bools,
    reason = "settings/flags struct mirrors persisted config 1:1; bools represent independent toggles, not a state machine"
)] // Settings struct — bools are independent toggles, not a state machine
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitoringSettings {
    /// Whether remote monitoring is enabled globally (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Polling interval in seconds (1–60, default: 3)
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u8,
    /// Show CPU usage in the monitoring bar
    #[serde(default = "default_true")]
    pub show_cpu: bool,
    /// Show memory usage in the monitoring bar
    #[serde(default = "default_true")]
    pub show_memory: bool,
    /// Show disk usage in the monitoring bar
    #[serde(default = "default_true")]
    pub show_disk: bool,
    /// Show network throughput in the monitoring bar
    #[serde(default = "default_true")]
    pub show_network: bool,
    /// Show load average in the monitoring bar
    #[serde(default = "default_true")]
    pub show_load: bool,
    /// Show system info (distro, kernel, uptime) in the monitoring bar
    #[serde(default = "default_true")]
    pub show_system_info: bool,
}

const fn default_interval_secs() -> u8 {
    3
}

const fn default_true() -> bool {
    true
}

impl Default for MonitoringSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: default_interval_secs(),
            show_cpu: true,
            show_memory: true,
            show_disk: true,
            show_network: true,
            show_load: true,
            show_system_info: true,
        }
    }
}

impl MonitoringSettings {
    /// Returns the interval clamped to the valid range (1–60 seconds)
    #[must_use]
    pub const fn effective_interval_secs(&self) -> u8 {
        if self.interval_secs == 0 {
            1
        } else if self.interval_secs > 60 {
            60
        } else {
            self.interval_secs
        }
    }
}

/// Per-connection monitoring override (stored on `Connection`)
///
/// When `None` on a connection, the global `MonitoringSettings` apply.
/// When `Some`, these values override the global defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Override the global enabled flag for this connection
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Override the polling interval for this connection
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_secs: Option<u8>,
}

impl MonitoringConfig {
    /// Returns whether monitoring is enabled, falling back to global setting
    #[must_use]
    pub fn is_enabled(&self, global: &MonitoringSettings) -> bool {
        self.enabled.unwrap_or(global.enabled)
    }

    /// Returns the effective interval, falling back to global setting
    #[must_use]
    pub fn effective_interval(&self, global: &MonitoringSettings) -> u8 {
        let secs = self
            .interval_secs
            .unwrap_or_else(|| global.effective_interval_secs());
        secs.clamp(1, 60)
    }
}

/// Whether one connection follows the global monitoring switch or sets its own.
///
/// This is the `enabled` field of [`MonitoringConfig`] as a choice: `None` is
/// [`Self::Inherit`]. The connection editor's picker and `rustconn-cli monitor
/// reset` speak in these three values, so neither collapses "no override" into
/// "on" — the collapse that made every saved connection pin itself on and stop
/// following the global switch (issue #352).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MonitoringOverride {
    /// Follow the global switch in [`MonitoringSettings`] (the default)
    #[default]
    Inherit,
    /// Run monitoring for this connection even when the global switch is off
    Enabled,
    /// Never run monitoring for this connection
    Disabled,
}

impl MonitoringOverride {
    /// Reads the choice a stored per-connection config makes.
    ///
    /// A config that only overrides the interval still follows the global
    /// switch, so it reads as [`Self::Inherit`], as does no config at all.
    #[must_use]
    pub fn from_config(config: Option<&MonitoringConfig>) -> Self {
        match config.and_then(|c| c.enabled) {
            None => Self::Inherit,
            Some(true) => Self::Enabled,
            Some(false) => Self::Disabled,
        }
    }

    /// Writes this choice into a per-connection config.
    ///
    /// Only `enabled` changes. An `interval_secs` override in `existing`
    /// survives: it can come from `rustconn-cli monitor enable --interval`, and
    /// the editor has no control that could set it again. Returns `None` when
    /// neither field is left set, so a connection with nothing to override
    /// stores no config at all and keeps following the global settings.
    #[must_use]
    pub fn apply(self, existing: Option<&MonitoringConfig>) -> Option<MonitoringConfig> {
        let enabled = match self {
            Self::Inherit => None,
            Self::Enabled => Some(true),
            Self::Disabled => Some(false),
        };
        let interval_secs = existing.and_then(|c| c.interval_secs);
        if enabled.is_none() && interval_secs.is_none() {
            return None;
        }
        Some(MonitoringConfig {
            enabled,
            interval_secs,
        })
    }
}

/// Returns the polling interval monitoring would use for one connection.
///
/// The connection's own `interval_secs` wins when it has one, otherwise the
/// global interval applies; either way the result is clamped to 1–60 seconds.
#[must_use]
pub fn effective_monitoring_interval(
    config: Option<&MonitoringConfig>,
    global: &MonitoringSettings,
) -> u8 {
    config.map_or_else(
        || global.effective_interval_secs(),
        |mc| mc.effective_interval(global),
    )
}

/// Resolves the settings a monitoring session for one connection runs with.
///
/// Returns `None` when monitoring must not start: the connection is switched
/// off (`enabled = Some(false)`, issue #106), or it has no on/off value of its
/// own and the global switch is off. A connection switched on runs even with
/// the global switch off — that is what the override is for (issue #125).
///
/// The settings returned have `enabled` set, the interval from
/// [`effective_monitoring_interval`], and the global metric visibility flags.
/// Both the initial SSH connect and the in-place reconnect start monitoring
/// from this, so the two cannot disagree.
#[must_use]
pub fn effective_monitoring(
    config: Option<&MonitoringConfig>,
    global: &MonitoringSettings,
) -> Option<MonitoringSettings> {
    let enabled = config.map_or(global.enabled, |mc| mc.is_enabled(global));
    if !enabled {
        return None;
    }
    Some(MonitoringSettings {
        enabled: true,
        interval_secs: effective_monitoring_interval(config, global),
        ..global.clone()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings() {
        let s = MonitoringSettings::default();
        assert!(s.enabled);
        assert_eq!(s.interval_secs, 3);
        assert!(s.show_cpu);
        assert!(s.show_memory);
        assert!(s.show_disk);
        assert!(s.show_network);
        assert!(s.show_load);
        assert!(s.show_system_info);
    }

    #[test]
    fn test_effective_interval_clamping() {
        let s = MonitoringSettings {
            interval_secs: 0,
            ..Default::default()
        };
        assert_eq!(s.effective_interval_secs(), 1);

        let s = MonitoringSettings {
            interval_secs: 255,
            ..Default::default()
        };
        assert_eq!(s.effective_interval_secs(), 60);

        let s = MonitoringSettings {
            interval_secs: 5,
            ..Default::default()
        };
        assert_eq!(s.effective_interval_secs(), 5);
    }

    #[test]
    fn test_per_connection_override() {
        let global = MonitoringSettings {
            enabled: true,
            interval_secs: 5,
            ..Default::default()
        };
        let config = MonitoringConfig {
            enabled: Some(false),
            interval_secs: Some(10),
        };
        assert!(!config.is_enabled(&global));
        assert_eq!(config.effective_interval(&global), 10);
    }

    #[test]
    fn test_per_connection_fallback() {
        let global = MonitoringSettings {
            enabled: true,
            interval_secs: 7,
            ..Default::default()
        };
        let config = MonitoringConfig {
            enabled: None,
            interval_secs: None,
        };
        assert!(config.is_enabled(&global));
        assert_eq!(config.effective_interval(&global), 7);
    }

    #[test]
    fn test_serde_roundtrip() {
        let settings = MonitoringSettings {
            enabled: true,
            interval_secs: 10,
            show_cpu: true,
            show_memory: false,
            show_disk: true,
            show_network: false,
            show_load: true,
            show_system_info: false,
        };
        let json = serde_json::to_string(&settings).unwrap();
        let deserialized: MonitoringSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(settings, deserialized);
    }

    const ALL_OVERRIDES: [MonitoringOverride; 3] = [
        MonitoringOverride::Inherit,
        MonitoringOverride::Enabled,
        MonitoringOverride::Disabled,
    ];

    #[test]
    fn every_override_round_trips_through_a_stored_config() {
        let with_interval = MonitoringConfig {
            enabled: Some(true),
            interval_secs: Some(10),
        };
        for choice in ALL_OVERRIDES {
            let fresh = choice.apply(None);
            assert_eq!(
                MonitoringOverride::from_config(fresh.as_ref()),
                choice,
                "{choice:?} does not survive a save from scratch"
            );
            let edited = choice.apply(Some(&with_interval));
            assert_eq!(
                MonitoringOverride::from_config(edited.as_ref()),
                choice,
                "{choice:?} does not survive a save over an existing config"
            );
        }
    }

    #[test]
    fn no_config_and_an_interval_only_config_read_as_inherit() {
        assert_eq!(MonitoringOverride::default(), MonitoringOverride::Inherit);
        assert_eq!(
            MonitoringOverride::from_config(None),
            MonitoringOverride::Inherit
        );
        let interval_only = MonitoringConfig {
            enabled: None,
            interval_secs: Some(10),
        };
        assert_eq!(
            MonitoringOverride::from_config(Some(&interval_only)),
            MonitoringOverride::Inherit
        );
    }

    #[test]
    fn inherit_with_nothing_left_to_override_stores_no_config() {
        // A brand-new connection left at "Use global setting" saves `None`, and
        // so does an existing one whose only override was the switch.
        assert_eq!(MonitoringOverride::Inherit.apply(None), None);
        let switched_on = MonitoringConfig {
            enabled: Some(true),
            interval_secs: None,
        };
        assert_eq!(MonitoringOverride::Inherit.apply(Some(&switched_on)), None);
    }

    #[test]
    fn inherit_keeps_an_interval_override() {
        let existing = MonitoringConfig {
            enabled: Some(true),
            interval_secs: Some(10),
        };
        assert_eq!(
            MonitoringOverride::Inherit.apply(Some(&existing)),
            Some(MonitoringConfig {
                enabled: None,
                interval_secs: Some(10),
            })
        );
    }

    #[test]
    fn enabled_and_disabled_set_the_switch_and_keep_the_interval() {
        let interval_only = MonitoringConfig {
            enabled: None,
            interval_secs: Some(10),
        };
        assert_eq!(
            MonitoringOverride::Enabled.apply(Some(&interval_only)),
            Some(MonitoringConfig {
                enabled: Some(true),
                interval_secs: Some(10),
            })
        );
        assert_eq!(
            MonitoringOverride::Disabled.apply(Some(&interval_only)),
            Some(MonitoringConfig {
                enabled: Some(false),
                interval_secs: Some(10),
            })
        );
        assert_eq!(
            MonitoringOverride::Enabled.apply(None),
            Some(MonitoringConfig {
                enabled: Some(true),
                interval_secs: None,
            })
        );
        assert_eq!(
            MonitoringOverride::Disabled.apply(None),
            Some(MonitoringConfig {
                enabled: Some(false),
                interval_secs: None,
            })
        );
    }

    #[test]
    fn without_an_override_the_global_switch_and_interval_apply() {
        let global_on = MonitoringSettings {
            enabled: true,
            interval_secs: 7,
            ..Default::default()
        };
        let global_off = MonitoringSettings {
            enabled: false,
            ..global_on
        };

        let effective = effective_monitoring(None, &global_on).expect("global on runs");
        assert!(effective.enabled);
        assert_eq!(effective.interval_secs, 7);
        assert_eq!(effective_monitoring(None, &global_off), None);

        // An interval-only override changes the interval, never the switch.
        let interval_only = MonitoringConfig {
            enabled: None,
            interval_secs: Some(20),
        };
        assert_eq!(
            effective_monitoring(Some(&interval_only), &global_off),
            None
        );
        let effective =
            effective_monitoring(Some(&interval_only), &global_on).expect("global on runs");
        assert_eq!(effective.interval_secs, 20);
    }

    #[test]
    fn a_connection_switched_on_runs_with_the_global_switch_off() {
        // Issue #125: the per-connection override exists for exactly this.
        let global_off = MonitoringSettings {
            enabled: false,
            interval_secs: 5,
            show_cpu: false,
            ..Default::default()
        };
        let switched_on = MonitoringConfig {
            enabled: Some(true),
            interval_secs: None,
        };
        let effective =
            effective_monitoring(Some(&switched_on), &global_off).expect("the override runs");
        assert!(effective.enabled);
        assert_eq!(effective.interval_secs, 5);
        assert!(
            !effective.show_cpu,
            "metric visibility still comes from the global settings"
        );
    }

    #[test]
    fn a_connection_switched_off_never_runs() {
        // Issue #106: no monitoring SSH session at all for this connection.
        let switched_off = MonitoringConfig {
            enabled: Some(false),
            interval_secs: Some(10),
        };
        for global_enabled in [true, false] {
            let global = MonitoringSettings {
                enabled: global_enabled,
                ..Default::default()
            };
            assert_eq!(effective_monitoring(Some(&switched_off), &global), None);
        }
    }

    #[test]
    fn the_effective_interval_is_clamped_to_one_to_sixty_seconds() {
        let too_short = MonitoringSettings {
            interval_secs: 0,
            ..Default::default()
        };
        let too_long = MonitoringSettings {
            interval_secs: 200,
            ..Default::default()
        };
        assert_eq!(
            effective_monitoring(None, &too_short).map(|s| s.interval_secs),
            Some(1)
        );
        assert_eq!(
            effective_monitoring(None, &too_long).map(|s| s.interval_secs),
            Some(60)
        );

        let global = MonitoringSettings::default();
        for (stored, expected) in [(0, 1), (30, 30), (255, 60)] {
            let config = MonitoringConfig {
                enabled: Some(true),
                interval_secs: Some(stored),
            };
            assert_eq!(
                effective_monitoring_interval(Some(&config), &global),
                expected
            );
            assert_eq!(
                effective_monitoring(Some(&config), &global).map(|s| s.interval_secs),
                Some(expected)
            );
        }
    }
}
