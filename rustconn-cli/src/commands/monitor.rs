//! Per-connection monitoring commands.

use std::path::Path;

use rustconn_core::monitoring::{
    MonitoringConfig, MonitoringOverride, effective_monitoring, effective_monitoring_interval,
};

use crate::cli::{MonitorCommands, OutputFormat};
use crate::color;
use crate::error::CliError;
use crate::util::{create_config_manager, find_connection};

/// Monitor command dispatcher
///
/// # Errors
///
/// Returns:
/// - [`CliError::Config`] when connections cannot be loaded or saved
/// - [`CliError::ConnectionNotFound`] when no connection matches the supplied name
pub(super) fn cmd_monitor(
    config_path: Option<&Path>,
    subcmd: MonitorCommands,
) -> Result<(), CliError> {
    match subcmd {
        MonitorCommands::Enable { name, interval } => {
            cmd_monitor_enable(config_path, &name, interval)
        }
        MonitorCommands::Disable { name } => cmd_monitor_disable(config_path, &name),
        MonitorCommands::Metrics { name, format } => {
            cmd_monitor_metrics(config_path, &name, format.effective())
        }
        MonitorCommands::Reset { name, all } => match (name, all) {
            (_, true) => cmd_monitor_reset_all(config_path),
            (Some(name), false) => cmd_monitor_reset(config_path, &name),
            // clap requires a name unless --all is given
            (None, false) => Err(CliError::Config(
                "Give a connection name or --all".to_string(),
            )),
        },
    }
}

/// Make one connection follow the global monitoring switch again (issue #352)
fn cmd_monitor_reset(config_path: Option<&Path>, name: &str) -> Result<(), CliError> {
    let config_manager = create_config_manager(config_path)?;

    let mut connections = config_manager
        .load_connections()
        .map_err(|e| CliError::Config(format!("Failed to load connections: {e}")))?;

    let conn_id = find_connection(&connections, name)?.id;
    let target = connections
        .iter_mut()
        .find(|c| c.id == conn_id)
        .ok_or_else(|| CliError::ConnectionNotFound(name.to_string()))?;
    let conn_name = target.name.clone();

    if !target.reset_monitoring_override() {
        println!("Connection '{conn_name}' already follows the global monitoring setting.");
        return Ok(());
    }

    config_manager
        .save_connections(&connections)
        .map_err(|e| CliError::Config(format!("Failed to save connections: {e}")))?;

    println!(
        "{}Reset{} monitoring for connection '{}': it follows the global setting now.",
        color::green(),
        color::reset(),
        conn_name
    );
    Ok(())
}

/// Make every connection follow the global monitoring switch again (issue #352)
fn cmd_monitor_reset_all(config_path: Option<&Path>) -> Result<(), CliError> {
    let config_manager = create_config_manager(config_path)?;

    let mut connections = config_manager
        .load_connections()
        .map_err(|e| CliError::Config(format!("Failed to load connections: {e}")))?;

    let mut reset = 0_usize;
    for conn in &mut connections {
        if conn.reset_monitoring_override() {
            reset += 1;
        }
    }

    if reset > 0 {
        config_manager
            .save_connections(&connections)
            .map_err(|e| CliError::Config(format!("Failed to save connections: {e}")))?;
    }

    println!(
        "{}Reset{} monitoring on {} connection(s); every connection follows the global setting now.",
        color::green(),
        color::reset(),
        reset
    );
    Ok(())
}

/// Machine-readable name of a per-connection monitoring choice
const fn override_name(choice: MonitoringOverride) -> &'static str {
    match choice {
        MonitoringOverride::Inherit => "inherit",
        MonitoringOverride::Enabled => "enabled",
        MonitoringOverride::Disabled => "disabled",
    }
}

/// Enable monitoring for a connection
fn cmd_monitor_enable(
    config_path: Option<&Path>,
    name: &str,
    interval: Option<u8>,
) -> Result<(), CliError> {
    let config_manager = create_config_manager(config_path)?;

    let mut connections = config_manager
        .load_connections()
        .map_err(|e| CliError::Config(format!("Failed to load connections: {e}")))?;

    let conn = find_connection(&connections, name)?;
    let conn_id = conn.id;
    let conn_name = conn.name.clone();

    let target = connections
        .iter_mut()
        .find(|c| c.id == conn_id)
        .ok_or_else(|| CliError::ConnectionNotFound(name.to_string()))?;

    target.monitoring_config = Some(MonitoringConfig {
        enabled: Some(true),
        interval_secs: interval,
    });
    target.touch();

    config_manager
        .save_connections(&connections)
        .map_err(|e| CliError::Config(format!("Failed to save connections: {e}")))?;

    let interval_msg = interval
        .map(|i| format!(" (interval: {i}s)"))
        .unwrap_or_default();

    println!(
        "{}Enabled{} monitoring for connection '{}'.{}",
        color::green(),
        color::reset(),
        conn_name,
        interval_msg
    );
    Ok(())
}

/// Disable monitoring for a connection
fn cmd_monitor_disable(config_path: Option<&Path>, name: &str) -> Result<(), CliError> {
    let config_manager = create_config_manager(config_path)?;

    let mut connections = config_manager
        .load_connections()
        .map_err(|e| CliError::Config(format!("Failed to load connections: {e}")))?;

    let conn = find_connection(&connections, name)?;
    let conn_id = conn.id;
    let conn_name = conn.name.clone();

    let target = connections
        .iter_mut()
        .find(|c| c.id == conn_id)
        .ok_or_else(|| CliError::ConnectionNotFound(name.to_string()))?;

    target.monitoring_config = Some(MonitoringConfig {
        enabled: Some(false),
        interval_secs: None,
    });
    target.touch();

    config_manager
        .save_connections(&connections)
        .map_err(|e| CliError::Config(format!("Failed to save connections: {e}")))?;

    println!(
        "{}Disabled{} monitoring for connection '{}'.",
        color::yellow(),
        color::reset(),
        conn_name
    );
    Ok(())
}

/// Show monitoring metrics/config for a connection
fn cmd_monitor_metrics(
    config_path: Option<&Path>,
    name: &str,
    format: OutputFormat,
) -> Result<(), CliError> {
    let config_manager = create_config_manager(config_path)?;

    let connections = config_manager
        .load_connections()
        .map_err(|e| CliError::Config(format!("Failed to load connections: {e}")))?;

    let conn = find_connection(&connections, name)?;

    let settings = config_manager
        .load_settings()
        .map_err(|e| CliError::Config(format!("Failed to load settings: {e}")))?;
    let global = &settings.monitoring;

    // Resolved the way an SSH session resolves it, so a connection with no
    // on/off value of its own reports the global switch. It used to report
    // "disabled" whatever the global switch said (issue #352).
    let monitoring = conn.monitoring_config.as_ref();
    let enabled = effective_monitoring(monitoring, global).is_some();
    let choice = conn.monitoring_override();
    let interval = monitoring.and_then(|m| m.interval_secs);
    let effective_interval = effective_monitoring_interval(monitoring, global);
    // Where the on/off value comes from. An interval-only override still
    // follows the global switch.
    let config_source = if choice == MonitoringOverride::Inherit {
        "global"
    } else {
        "per-connection"
    };

    match format {
        OutputFormat::Json => {
            let output = serde_json::json!({
                "connection": conn.name,
                "monitoring_enabled": enabled,
                "interval_secs": interval,
                "config_source": config_source,
                "override": override_name(choice),
                "effective_interval_secs": effective_interval,
            });
            let json = serde_json::to_string_pretty(&output)
                .map_err(|e| CliError::Config(format!("JSON serialization failed: {e}")))?;
            println!("{json}");
        }
        OutputFormat::Csv => {
            // New columns go at the end, so scripts reading by position keep working.
            println!(
                "connection,monitoring_enabled,interval_secs,config_source,override,effective_interval_secs"
            );
            println!(
                "{},{},{},{},{},{}",
                conn.name,
                enabled,
                interval.map(|i| i.to_string()).unwrap_or_default(),
                config_source,
                override_name(choice),
                effective_interval,
            );
        }
        OutputFormat::Table => {
            println!(
                "{}Monitoring: {}{}",
                color::bold(),
                conn.name,
                color::reset()
            );
            println!("{}", "=".repeat(40));
            println!(
                "Status:          {}",
                if enabled {
                    format!("{}enabled{}", color::green(), color::reset())
                } else {
                    format!("{}disabled{}", color::yellow(), color::reset())
                }
            );
            println!(
                "Setting:         {}",
                match choice {
                    MonitoringOverride::Inherit => "use global setting",
                    MonitoringOverride::Enabled => "enabled for this connection",
                    MonitoringOverride::Disabled => "disabled for this connection",
                }
            );
            println!(
                "Interval:        {effective_interval}s ({})",
                if interval.is_some() {
                    "this connection"
                } else {
                    "global setting"
                }
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use rustconn_core::config::ConfigManager;
    use rustconn_core::models::Connection;
    use rustconn_core::monitoring::{MonitoringConfig, MonitoringOverride};

    use super::{cmd_monitor_reset, cmd_monitor_reset_all};

    fn ssh(name: &str, monitoring: Option<MonitoringConfig>) -> Connection {
        let mut conn = Connection::new_ssh(name.to_string(), "host.example".to_string(), 22);
        conn.monitoring_config = monitoring;
        conn
    }

    const fn config(enabled: Option<bool>, interval_secs: Option<u8>) -> MonitoringConfig {
        MonitoringConfig {
            enabled,
            interval_secs,
        }
    }

    fn saved(dir: &std::path::Path, name: &str) -> Connection {
        ConfigManager::with_config_dir(dir.to_path_buf())
            .load_connections()
            .unwrap()
            .into_iter()
            .find(|c| c.name == name)
            .unwrap()
    }

    #[test]
    fn reset_all_clears_every_on_off_value_and_keeps_intervals() {
        let dir = tempfile::tempdir().unwrap();
        let connections = [
            ssh("pinned-on", Some(config(Some(true), None))),
            ssh("pinned-off", Some(config(Some(false), Some(7)))),
            ssh("interval-only", Some(config(None, Some(9)))),
            ssh("plain", None),
        ];
        ConfigManager::with_config_dir(dir.path().to_path_buf())
            .save_connections(&connections)
            .unwrap();

        cmd_monitor_reset_all(Some(dir.path())).unwrap();

        // Nothing left to override: no config at all.
        assert_eq!(saved(dir.path(), "pinned-on").monitoring_config, None);
        // The on/off value goes, a CLI-set interval stays.
        assert_eq!(
            saved(dir.path(), "pinned-off").monitoring_config,
            Some(config(None, Some(7)))
        );
        assert_eq!(
            saved(dir.path(), "interval-only").monitoring_config,
            Some(config(None, Some(9)))
        );
        assert_eq!(saved(dir.path(), "plain").monitoring_config, None);
    }

    #[test]
    fn reset_by_name_touches_only_that_connection() {
        let dir = tempfile::tempdir().unwrap();
        let connections = [
            ssh("first", Some(config(Some(true), None))),
            ssh("second", Some(config(Some(false), None))),
        ];
        ConfigManager::with_config_dir(dir.path().to_path_buf())
            .save_connections(&connections)
            .unwrap();

        cmd_monitor_reset(Some(dir.path()), "first").unwrap();

        assert_eq!(
            saved(dir.path(), "first").monitoring_override(),
            MonitoringOverride::Inherit
        );
        assert_eq!(
            saved(dir.path(), "second").monitoring_override(),
            MonitoringOverride::Disabled
        );
    }

    #[test]
    fn resetting_an_unknown_connection_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        ConfigManager::with_config_dir(dir.path().to_path_buf())
            .save_connections(&[ssh("only", None)])
            .unwrap();

        assert!(cmd_monitor_reset(Some(dir.path()), "missing").is_err());
    }
}
