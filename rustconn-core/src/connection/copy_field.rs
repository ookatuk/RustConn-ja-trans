//! The fields a connection's "Copy" menu offers, and the text each one copies.
//!
//! The menu shows only what this particular connection actually has: a serial
//! line has no port, a connection with no stored credential has no password to
//! copy, and a custom property appears only once it has a value. Deciding that
//! here, from the model alone, keeps the sidebar and the session-tab menus in
//! agreement and makes the rules testable without GTK.
//!
//! Secrets are not resolved here. [`CopyField::Password`] is offered when the
//! connection has a password source, but its value comes from the credential
//! resolver at click time; [`copy_text`] returns `None` for it.

use crate::models::{Connection, PasswordSource, ProtocolType};
use crate::ssh_tunnel::format_argv_for_display;

/// Key prefix of a custom-property field in [`CopyField::key`].
const PROPERTY_KEY_PREFIX: &str = "property:";

/// One entry of a connection's "Copy" menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyField {
    /// The host name or address as stored.
    Host,
    /// The port number.
    Port,
    /// `host:port`, with an IPv6 address in brackets.
    Address,
    /// The user name.
    Username,
    /// The password. Resolved by the caller; see the module docs.
    Password,
    /// An `ssh` command line that reaches the connection, for SSH and SFTP.
    SshCommand,
    /// The custom property with this name.
    Property(String),
}

impl CopyField {
    /// Returns a stable string key, used as the target of a menu action.
    #[must_use]
    pub fn key(&self) -> String {
        match self {
            Self::Host => "host".to_string(),
            Self::Port => "port".to_string(),
            Self::Address => "address".to_string(),
            Self::Username => "username".to_string(),
            Self::Password => "password".to_string(),
            Self::SshCommand => "ssh-command".to_string(),
            Self::Property(name) => format!("{PROPERTY_KEY_PREFIX}{name}"),
        }
    }

    /// Parses a key produced by [`Self::key`].
    #[must_use]
    pub fn from_key(key: &str) -> Option<Self> {
        if let Some(name) = key.strip_prefix(PROPERTY_KEY_PREFIX) {
            return Some(Self::Property(name.to_string()));
        }
        match key {
            "host" => Some(Self::Host),
            "port" => Some(Self::Port),
            "address" => Some(Self::Address),
            "username" => Some(Self::Username),
            "password" => Some(Self::Password),
            "ssh-command" => Some(Self::SshCommand),
            _ => None,
        }
    }

    /// Whether the copied value is a secret, which the caller must clear from
    /// the clipboard after a while and never show in a label.
    #[must_use]
    pub fn is_sensitive(&self, connection: &Connection) -> bool {
        match self {
            Self::Password => true,
            Self::Property(name) => connection
                .get_custom_property(name)
                .is_some_and(crate::models::CustomProperty::is_protected),
            _ => false,
        }
    }
}

/// Returns the fields worth offering for `connection`, in menu order.
///
/// Built-in fields first, then one entry per custom property that has both a
/// name and a value, in the order the properties are stored.
#[must_use]
pub fn copy_fields(connection: &Connection) -> Vec<CopyField> {
    let mut fields = Vec::new();
    let has_host = !connection.host.trim().is_empty();
    if has_host {
        fields.push(CopyField::Host);
    }
    if has_port(connection) {
        fields.push(CopyField::Port);
        if has_host {
            fields.push(CopyField::Address);
        }
    }
    if has_username(connection) {
        fields.push(CopyField::Username);
    }
    if has_password(connection) {
        fields.push(CopyField::Password);
    }
    if has_host && matches!(connection.protocol, ProtocolType::Ssh | ProtocolType::Sftp) {
        fields.push(CopyField::SshCommand);
    }
    fields.extend(
        connection
            .custom_properties
            .iter()
            .filter(|p| !p.name.trim().is_empty() && !p.value.is_empty())
            .map(|p| CopyField::Property(p.name.clone())),
    );
    fields
}

/// Returns the text `field` copies for `connection`, or `None` when there is
/// nothing to copy.
///
/// `proxy_jump` is the resolved `-J` value for [`CopyField::SshCommand`]
/// (see [`crate::connection::resolve_proxy_jump_value`]); it is ignored for
/// every other field. [`CopyField::Password`] always returns `None`.
#[must_use]
pub fn copy_text(
    connection: &Connection,
    field: &CopyField,
    proxy_jump: Option<&str>,
) -> Option<String> {
    let host = connection.host.trim();
    match field {
        CopyField::Host => non_empty(host),
        CopyField::Port => has_port(connection).then(|| connection.port.to_string()),
        CopyField::Address => (has_port(connection) && !host.is_empty())
            .then(|| format_address(host, connection.port)),
        CopyField::Username => connection
            .username
            .as_deref()
            .and_then(|u| non_empty(u.trim())),
        CopyField::Password => None,
        CopyField::SshCommand => {
            if host.is_empty()
                || !matches!(connection.protocol, ProtocolType::Ssh | ProtocolType::Sftp)
            {
                return None;
            }
            Some(ssh_command(connection, host, proxy_jump))
        }
        CopyField::Property(name) => connection
            .get_custom_property(name)
            .filter(|p| !p.value.is_empty())
            .map(|p| p.value.clone()),
    }
}

/// Formats `host:port`, bracketing an IPv6 address as `[::1]:22`.
///
/// A host that is already bracketed is left alone.
#[must_use]
pub fn format_address(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Builds `ssh [-p PORT] [-J JUMP] [user@]host`, quoted for a POSIX shell.
///
/// ponytail: only the options needed to *reach* the host — port, bastion,
/// user. Identity files, `-o` options and the startup command are left out,
/// because they are either the local machine's business or would put a
/// command into the clipboard that runs something on paste. Add them behind a
/// "full command" variant if users ask for it.
fn ssh_command(connection: &Connection, host: &str, proxy_jump: Option<&str>) -> String {
    let mut argv = vec!["ssh".to_string()];
    if connection.port != 22 && connection.port != 0 {
        argv.push("-p".to_string());
        argv.push(connection.port.to_string());
    }
    if let Some(jump) = proxy_jump.map(str::trim).filter(|j| !j.is_empty()) {
        argv.push("-J".to_string());
        argv.push(jump.to_string());
    }
    // OpenSSH does not strip brackets from a plain destination, so `[::1]`
    // (which `format_address` accepts as stored) would not resolve.
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let destination = match connection.username.as_deref().map(str::trim) {
        Some(user) if !user.is_empty() => format!("{user}@{host}"),
        _ => host.to_string(),
    };
    // Shell quoting does not stop ssh's getopt from reading a leading `-` as
    // an option: a host or user of `-oProxyCommand=…` would run a local
    // command on paste. `--` makes it a destination, which then just fails.
    if destination.starts_with('-') {
        argv.push("--".to_string());
    }
    argv.push(destination);
    format_argv_for_display(&argv)
}

/// Whether the protocol has a meaningful port.
///
/// Zero Trust, Serial and Kubernetes have none (their default port is 0). Web
/// stores a URL in `host`, so a separate port would be misleading.
fn has_port(connection: &Connection) -> bool {
    connection.port != 0
        && connection.protocol.default_port() != 0
        && connection.protocol != ProtocolType::Web
}

/// Whether a user name may be available: stored on the connection, or
/// supplied together with the password by a vault, a variable, a script or a
/// parent group.
fn has_username(connection: &Connection) -> bool {
    connection
        .username
        .as_deref()
        .is_some_and(|u| !u.trim().is_empty())
        || password_may_supply_credentials(&connection.password_source)
}

/// Whether a password can be produced without asking the user.
fn has_password(connection: &Connection) -> bool {
    password_may_supply_credentials(&connection.password_source)
}

/// Sources that resolve credentials without a prompt. `None` stores nothing
/// and `Prompt` asks on every connect, so neither has anything to copy.
const fn password_may_supply_credentials(source: &PasswordSource) -> bool {
    matches!(
        source,
        PasswordSource::Vault
            | PasswordSource::Inherit
            | PasswordSource::Variable(_)
            | PasswordSource::Script(_)
    )
}

fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CustomProperty, ProtocolConfig};

    fn ssh(host: &str, port: u16) -> Connection {
        Connection::new_ssh("router".to_string(), host.to_string(), port)
    }

    #[test]
    fn every_key_round_trips() {
        for field in [
            CopyField::Host,
            CopyField::Port,
            CopyField::Address,
            CopyField::Username,
            CopyField::Password,
            CopyField::SshCommand,
            CopyField::Property("SNMP community".to_string()),
            CopyField::Property("with:colon".to_string()),
        ] {
            assert_eq!(CopyField::from_key(&field.key()), Some(field));
        }
        assert_eq!(CopyField::from_key("nonsense"), None);
    }

    #[test]
    fn a_plain_ssh_connection_offers_host_port_address_and_command() {
        let conn = ssh("10.0.0.1", 2222);
        assert_eq!(
            copy_fields(&conn),
            vec![
                CopyField::Host,
                CopyField::Port,
                CopyField::Address,
                CopyField::SshCommand
            ]
        );
    }

    #[test]
    fn the_port_is_offered_even_when_it_is_the_default() {
        // Routers on 22 sit next to routers on 2222; an entry that appears and
        // disappears with the value would be harder to find than one that stays.
        let conn = ssh("10.0.0.1", 22);
        assert!(copy_fields(&conn).contains(&CopyField::Port));
        assert_eq!(
            copy_text(&conn, &CopyField::Port, None).as_deref(),
            Some("22")
        );
    }

    #[test]
    fn a_connection_without_a_port_offers_neither_port_nor_address() {
        let mut conn = ssh("/dev/ttyUSB0", 0);
        conn.protocol = ProtocolType::Serial;
        let fields = copy_fields(&conn);
        assert!(!fields.contains(&CopyField::Port));
        assert!(!fields.contains(&CopyField::Address));
        assert!(!fields.contains(&CopyField::SshCommand));
        assert_eq!(copy_text(&conn, &CopyField::Port, None), None);
    }

    #[test]
    fn an_empty_host_offers_no_host_address_or_command() {
        let conn = ssh("  ", 22);
        let fields = copy_fields(&conn);
        assert!(!fields.contains(&CopyField::Host));
        assert!(!fields.contains(&CopyField::Address));
        assert!(!fields.contains(&CopyField::SshCommand));
        assert!(fields.contains(&CopyField::Port));
    }

    #[test]
    fn username_and_password_follow_what_can_actually_be_copied() {
        let mut conn = ssh("h", 22);
        assert!(!copy_fields(&conn).contains(&CopyField::Username));
        assert!(!copy_fields(&conn).contains(&CopyField::Password));

        conn.password_source = PasswordSource::Prompt;
        assert!(!copy_fields(&conn).contains(&CopyField::Password));

        conn.username = Some("admin".to_string());
        assert!(copy_fields(&conn).contains(&CopyField::Username));
        assert!(!copy_fields(&conn).contains(&CopyField::Password));

        conn.username = None;
        conn.password_source = PasswordSource::Vault;
        let fields = copy_fields(&conn);
        assert!(fields.contains(&CopyField::Username), "a vault may hold it");
        assert!(fields.contains(&CopyField::Password));
        assert_eq!(copy_text(&conn, &CopyField::Password, None), None);
    }

    #[test]
    fn an_ipv6_address_is_bracketed() {
        assert_eq!(format_address("::1", 22), "[::1]:22");
        assert_eq!(format_address("[::1]", 22), "[::1]:22");
        assert_eq!(format_address("router.lan", 8291), "router.lan:8291");
    }

    #[test]
    fn the_ssh_command_carries_port_bastion_and_user() {
        let mut conn = ssh("10.0.0.1", 2222);
        conn.username = Some("admin".to_string());
        assert_eq!(
            copy_text(&conn, &CopyField::SshCommand, Some("ops@jump.lan")).as_deref(),
            Some("ssh -p 2222 -J ops@jump.lan admin@10.0.0.1")
        );
        let plain = ssh("host.lan", 22);
        assert_eq!(
            copy_text(&plain, &CopyField::SshCommand, None).as_deref(),
            Some("ssh host.lan")
        );
    }

    #[test]
    fn the_ssh_command_quotes_what_the_shell_would_split() {
        let mut conn = ssh("host", 22);
        conn.username = Some("o'brien".to_string());
        assert_eq!(
            copy_text(&conn, &CopyField::SshCommand, None).as_deref(),
            Some("ssh 'o'\\''brien@host'")
        );
    }

    #[test]
    fn a_leading_dash_in_the_destination_cannot_become_an_ssh_option() {
        let host_first = ssh("-oProxyCommand=touch /tmp/x", 22);
        assert_eq!(
            copy_text(&host_first, &CopyField::SshCommand, None).as_deref(),
            Some("ssh -- '-oProxyCommand=touch /tmp/x'")
        );
        let mut user_first = ssh("host", 22);
        user_first.username = Some("-oProxyCommand=id".to_string());
        assert_eq!(
            copy_text(&user_first, &CopyField::SshCommand, None).as_deref(),
            Some("ssh -- -oProxyCommand=id@host")
        );
    }

    #[test]
    fn the_ssh_command_unbrackets_an_ipv6_host_and_keeps_a_zone_id() {
        let mut bracketed = ssh("[2001:db8::1]", 2222);
        bracketed.username = Some("admin".to_string());
        assert_eq!(
            copy_text(&bracketed, &CopyField::SshCommand, None).as_deref(),
            Some("ssh -p 2222 admin@2001:db8::1")
        );
        let zoned = ssh("fe80::1%eth0", 22);
        assert_eq!(
            copy_text(&zoned, &CopyField::SshCommand, None).as_deref(),
            Some("ssh fe80::1%eth0")
        );
        assert_eq!(
            copy_text(&zoned, &CopyField::Address, None).as_deref(),
            Some("[fe80::1%eth0]:22")
        );
    }

    #[test]
    fn the_ssh_command_never_includes_custom_options_or_startup_command() {
        let mut conn = ssh("host", 22);
        if let ProtocolConfig::Ssh(ref mut cfg) = conn.protocol_config {
            cfg.startup_command = Some("rm -rf ~".to_string());
            cfg.custom_options
                .insert("ProxyCommand".to_string(), "evil".to_string());
        }
        let cmd = copy_text(&conn, &CopyField::SshCommand, None).unwrap_or_default();
        assert_eq!(cmd, "ssh host");
    }

    #[test]
    fn rdp_offers_no_ssh_command() {
        let mut conn = ssh("win.lan", 3389);
        conn.protocol = ProtocolType::Rdp;
        assert!(!copy_fields(&conn).contains(&CopyField::SshCommand));
        assert_eq!(copy_text(&conn, &CopyField::SshCommand, None), None);
    }

    #[test]
    fn custom_properties_appear_only_with_a_value() {
        let mut conn = ssh("h", 22);
        conn.custom_properties = vec![
            CustomProperty::new_url("Admin URL", "https://10.0.0.1:8443"),
            CustomProperty::new_text("Empty", ""),
            CustomProperty::new_protected("SNMP community", "s3cret"),
        ];
        let props: Vec<_> = copy_fields(&conn)
            .into_iter()
            .filter(|f| matches!(f, CopyField::Property(_)))
            .collect();
        assert_eq!(
            props,
            vec![
                CopyField::Property("Admin URL".to_string()),
                CopyField::Property("SNMP community".to_string()),
            ]
        );
        let community = CopyField::Property("SNMP community".to_string());
        assert!(community.is_sensitive(&conn));
        assert!(!CopyField::Property("Admin URL".to_string()).is_sensitive(&conn));
        assert_eq!(
            copy_text(&conn, &community, None).as_deref(),
            Some("s3cret")
        );
    }

    #[test]
    fn web_offers_its_url_but_no_port() {
        let mut conn = ssh("https://nas.lan", 443);
        conn.protocol = ProtocolType::Web;
        let fields = copy_fields(&conn);
        assert!(fields.contains(&CopyField::Host));
        assert!(!fields.contains(&CopyField::Port));
        assert!(!fields.contains(&CopyField::Address));
    }
}
