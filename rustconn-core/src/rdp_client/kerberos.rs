//! Kerberos for embedded RDP NLA: the KDC address, the realm and pre-connect hints.
//!
//! Issue [#351]: an account in the Active Directory "Protected Users" group may
//! not sign in with NTLM, so the embedded client has to negotiate Kerberos inside
//! CredSSP. What sspi — the SSPI implementation under IronRDP — actually does
//! there, because the 0.22.12 notes got it wrong in three places:
//!
//! * **The password stored in RustConn is what signs in.** sspi sends its own
//!   AS-REQ with it; a ticket obtained with `kinit` is never read.
//! * **The KDC is looked up in a fixed order:** the connection's KDC Address,
//!   then the `SSPI_KDC_URL_<REALM>` and `SSPI_KDC_URL` environment variables,
//!   then the `[realms] <REALM> kdc` entry of `krb5.conf`. sspi's DNS SRV lookup
//!   is compiled out of the IronRDP build on Linux, so when none of those names a
//!   KDC RustConn tries the realm's own DNS name (`tcp://example.com:88`), which
//!   in Active Directory resolves to the domain controllers — see
//!   [`kerberos_settings_for`].
//! * **A KDC that is not found or not reached fails the sign-in.** CredSSP asks
//!   for a session key, so sspi only talks to the KDC after the first SPNEGO
//!   round, where it no longer falls back to NTLM; it switches to NTLM only when
//!   the server itself picks NTLM, and a Protected Users account is refused there
//!   anyway.
//!
//! The service principal is `TERMSRV/<host>`, so the host must be the server's
//! DNS name — sspi even switches to NTLM on its own for an IP address — and the
//! realm is the DNS domain, not the NetBIOS name. [`kerberos_preflight`] checks
//! both before connecting.
//!
//! Everything here is pure and feature-independent: the connection editor
//! validates with [`normalize_kdc_url`] in builds without the embedded client.
//!
//! [#351]: https://github.com/totoshko88/RustConn/issues/351

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::RdpClientConfig;

/// Port a KDC listens on when an address names none (RFC 4120, section 7.2.1).
pub const KDC_DEFAULT_PORT: u16 = 88;

/// Name the KDC sees for this computer when the system reports none.
///
/// The same fallback the embedded client uses for its RDP and RD Gateway
/// client names.
const FALLBACK_CLIENT_NAME: &str = "RustConn";

/// Why a KDC address cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KdcUrlError {
    /// The address contains a space or another whitespace character.
    #[error("the KDC address contains whitespace")]
    Whitespace,
    /// The scheme is not one sspi can send a Kerberos message over.
    #[error("unsupported KDC address scheme `{0}`; use tcp, udp, http or https")]
    UnsupportedScheme(String),
    /// The address names no host.
    #[error("the KDC address has no host")]
    MissingHost,
    /// The host is neither a host name, an IPv4 address nor a bracketed IPv6
    /// address, or it carries credentials (`user@host`).
    #[error("the KDC address host is not a host name or an IP address")]
    InvalidHost,
    /// The port is not a number from 1 to 65535.
    #[error("the KDC address port must be a number from 1 to 65535")]
    InvalidPort,
    /// A `tcp://` or `udp://` address has a path, which a KDC socket cannot use.
    #[error("a tcp:// or udp:// KDC address cannot have a path")]
    UnexpectedPath,
}

/// Checks a KDC address and puts it in the form the embedded client hands to sspi.
///
/// Accepted forms, after trimming:
///
/// * empty → `Ok(None)`: no address, the KDC is looked up instead;
/// * `host`, `host:port`, `[v6]` or `[v6]:port` → `tcp://host:port`, with port
///   88 when none is given;
/// * `tcp://` and `udp://` with the same authority → the port is filled in the
///   same way;
/// * `http://` and `https://` → kept as typed, scheme lower-cased: an MS-KKDCP
///   KDC proxy such as `https://gateway.example.com/KdcProxy`.
///
/// Credentials in the address (`user@host`) are refused rather than stored.
///
/// # Errors
///
/// Returns the [`KdcUrlError`] for the first problem found: whitespace inside the
/// address, an unsupported scheme, a missing or malformed host, a port outside
/// 1–65535, or a path on a `tcp://` or `udp://` address.
pub fn normalize_kdc_url(input: &str) -> Result<Option<String>, KdcUrlError> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(None);
    }
    if input.chars().any(char::is_whitespace) {
        return Err(KdcUrlError::Whitespace);
    }

    let (scheme, rest) = match input.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => (String::from("tcp"), input),
    };

    match scheme.as_str() {
        "tcp" | "udp" => {
            // A trailing slash is harmless (`tcp://dc:88/`); anything after it
            // is a path, which a raw KDC socket has no use for.
            let authority = match rest.split_once('/') {
                Some((authority, "")) => authority,
                Some(_) => return Err(KdcUrlError::UnexpectedPath),
                None => rest,
            };
            let (host, port) = parse_authority(authority)?;
            let port = port.unwrap_or(KDC_DEFAULT_PORT);
            Ok(Some(format!("{scheme}://{host}:{port}")))
        }
        "http" | "https" => {
            let (authority, path) = match rest.find(['/', '?', '#']) {
                Some(index) => rest.split_at(index),
                None => (rest, ""),
            };
            let (host, port) = parse_authority(authority)?;
            let port = port.map(|port| format!(":{port}")).unwrap_or_default();
            Ok(Some(format!("{scheme}://{host}{port}{path}")))
        }
        _ => Err(KdcUrlError::UnsupportedScheme(scheme)),
    }
}

/// Splits `host`, `host:port`, `[v6]` or `[v6]:port` and checks both halves.
///
/// The host comes back in the form a URL needs: an IPv6 address bracketed.
fn parse_authority(authority: &str) -> Result<(String, Option<u16>), KdcUrlError> {
    if authority.contains('@') {
        return Err(KdcUrlError::InvalidHost);
    }

    if let Some(bracketed) = authority.strip_prefix('[') {
        let (address, after) = bracketed.split_once(']').ok_or(KdcUrlError::InvalidHost)?;
        if address.is_empty() {
            return Err(KdcUrlError::MissingHost);
        }
        let address: Ipv6Addr = address.parse().map_err(|_| KdcUrlError::InvalidHost)?;
        let port = if after.is_empty() {
            None
        } else {
            let port = after.strip_prefix(':').ok_or(KdcUrlError::InvalidHost)?;
            Some(parse_port(port)?)
        };
        return Ok((format!("[{address}]"), port));
    }

    // An IPv6 address typed without brackets has several colons and no port.
    if authority.matches(':').count() > 1 {
        let address: Ipv6Addr = authority.parse().map_err(|_| KdcUrlError::InvalidHost)?;
        return Ok((format!("[{address}]"), None));
    }

    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(parse_port(port)?)),
        None => (authority, None),
    };
    if host.is_empty() {
        return Err(KdcUrlError::MissingHost);
    }
    if !host.chars().all(is_host_name_char) {
        return Err(KdcUrlError::InvalidHost);
    }
    // Digits and dots only must be a real IPv4 address: `999.1.1.1` is not a
    // name, and a URL parser would reject it later with a vaguer error.
    let looks_numeric = host.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    if looks_numeric && host.parse::<Ipv4Addr>().is_err() {
        return Err(KdcUrlError::InvalidHost);
    }
    Ok((host.to_owned(), port))
}

/// Characters a host name may contain: letters, digits, `-` and `.`, plus `_`,
/// which some internal names use.
fn is_host_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_')
}

/// Parses a URL port: decimal digits only, 1 to 65535.
fn parse_port(text: &str) -> Result<u16, KdcUrlError> {
    // `u16::from_str` would also accept a leading `+`, which a URL port may not have.
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(KdcUrlError::InvalidPort);
    }
    match text.parse::<u16>() {
        Ok(0) | Err(_) => Err(KdcUrlError::InvalidPort),
        Ok(port) => Ok(port),
    }
}

/// The Kerberos realm sspi signs in to, before any `krb5.conf` remapping.
///
/// sspi takes it from the Domain field when one is set, otherwise from the user
/// name: the NetBIOS prefix of `DOMAIN\user`, or what follows the last `@` of
/// `user@example.com`. It is upper-cased, as sspi does. `None` when neither
/// names a domain.
#[must_use]
pub fn kerberos_realm(username: Option<&str>, domain: Option<&str>) -> Option<String> {
    let domain = domain.map(str::trim).unwrap_or_default();
    let username = username.map(str::trim).unwrap_or_default();
    let source = if domain.is_empty() {
        if let Some((netbios, _)) = username.split_once('\\') {
            netbios
        } else if let Some((_, suffix)) = username.rsplit_once('@') {
            suffix
        } else {
            ""
        }
    } else {
        domain
    };
    let source = source.trim();
    (!source.is_empty()).then(|| source.to_uppercase())
}

/// What the embedded client hands to IronRDP's `KerberosConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosSettings {
    /// KDC to use, already normalized; `None` leaves the lookup to sspi.
    pub kdc_url: Option<String>,
    /// This computer's name, as the KDC sees it in the AS-REQ.
    pub client_hostname: String,
}

/// Decides the Kerberos settings for one connection attempt; `None` means NTLM.
///
/// `None` unless both NLA and [`RdpClientConfig::kerberos_enabled`] are on: with
/// NLA off there is no CredSSP exchange to carry Kerberos. Otherwise the KDC is,
/// in this order:
///
/// 1. the stored KDC Address, normalized — a malformed one is logged and
///    ignored, so a typo does not block the connection;
/// 2. none at all when `discover` reports that sspi finds a KDC for the realm by
///    itself (the environment or `krb5.conf`), so that result is never
///    overridden;
/// 3. `tcp://<realm>:88`, the realm's own DNS name, logged at info.
///
/// `discover` receives the upper-cased realm from [`kerberos_realm`]. It is a
/// parameter so that tests do not depend on the host's environment or
/// `/etc/krb5.conf`. Without a realm nothing is looked up, and sspi reports the
/// failure.
#[must_use]
pub fn kerberos_settings_for(
    config: &RdpClientConfig,
    discover: impl FnOnce(&str) -> bool,
) -> Option<KerberosSettings> {
    if !(config.nla_enabled && config.kerberos_enabled) {
        return None;
    }
    let kdc_url = configured_kdc_url(config).or_else(|| fallback_kdc_url(config, discover));
    Some(KerberosSettings {
        kdc_url,
        client_hostname: local_client_name(),
    })
}

/// The stored KDC Address, normalized; `None` when unset, blank or malformed.
fn configured_kdc_url(config: &RdpClientConfig) -> Option<String> {
    let stored = config.kdc_proxy_url.as_deref()?;
    match normalize_kdc_url(stored) {
        Ok(url) => url,
        Err(error) => {
            tracing::warn!(
                protocol = "rdp",
                host = %config.host,
                %error,
                "Stored KDC address is not valid; ignoring it and looking the KDC up instead"
            );
            None
        }
    }
}

/// The realm's own DNS name as the KDC, unless sspi finds one by itself.
fn fallback_kdc_url(
    config: &RdpClientConfig,
    discover: impl FnOnce(&str) -> bool,
) -> Option<String> {
    let realm = kerberos_realm(config.username.as_deref(), config.domain.as_deref())?;
    if discover(&realm) {
        tracing::debug!(
            protocol = "rdp",
            %realm,
            "sspi finds the KDC for this realm in the environment or krb5.conf"
        );
        return None;
    }
    // ponytail: built from the realm as the profile spells it. A krb5.conf
    // [domain_realm] entry that remaps it to a different realm with no `kdc`
    // line still dials the profile's domain; pass sspi's mapped realm through
    // here if that combination is ever reported.
    let fallback = normalize_kdc_url(&realm.to_lowercase()).ok().flatten();
    if let Some(kdc) = &fallback {
        tracing::info!(
            protocol = "rdp",
            %realm,
            %kdc,
            "No KDC configured for the realm; trying the realm's own DNS name"
        );
    } else {
        tracing::warn!(
            protocol = "rdp",
            %realm,
            "The realm is not a usable host name; leaving the KDC lookup to sspi"
        );
    }
    fallback
}

/// This computer's host name, or [`FALLBACK_CLIENT_NAME`] when it has none.
fn local_client_name() -> String {
    hostname::get().map_or_else(
        |_| FALLBACK_CLIENT_NAME.to_owned(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// A connection setting that keeps Kerberos from working, found before connecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KerberosHint {
    /// The host is an IP address or `localhost`, an SSH tunnel's local end among
    /// them. The service principal is `TERMSRV/<host>`, which the domain only
    /// knows under the server's DNS name, and sspi switches an IP target to NTLM.
    HostNotDnsName,
    /// The realm has no dot: a NetBIOS name such as `EXAMPLE` rather than the DNS
    /// domain `EXAMPLE.COM`. An Active Directory realm is a DNS name.
    ShortDomainName,
    /// Neither the Domain field nor the user name names a domain, so there is no
    /// realm to sign in to.
    MissingDomain,
}

/// Checks a connection's host and domain for settings Kerberos cannot work with.
///
/// The realm is derived as in [`kerberos_realm`]. The hints come in a stable
/// order, host first, and the list is empty when nothing is wrong. They are
/// advisory: the caller warns and connects anyway.
#[must_use]
pub fn kerberos_preflight(
    host: &str,
    username: Option<&str>,
    domain: Option<&str>,
) -> Vec<KerberosHint> {
    let mut hints = Vec::new();
    if is_address_not_name(host) {
        hints.push(KerberosHint::HostNotDnsName);
    }
    match kerberos_realm(username, domain) {
        None => hints.push(KerberosHint::MissingDomain),
        Some(realm) if !realm.contains('.') => hints.push(KerberosHint::ShortDomainName),
        Some(_) => {}
    }
    hints
}

/// Whether `host` is an IP literal or a loopback name rather than a DNS name.
fn is_address_not_name(host: &str) -> bool {
    let host = host.trim().trim_end_matches('.');
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return true;
    }
    let bare = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    // A zone index (`fe80::1%eth0`) is not part of the address.
    let bare = bare.split_once('%').map_or(bare, |(address, _)| address);
    bare.parse::<IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::RdpConfig;

    fn kerberos_profile(username: &str, domain: Option<&str>) -> RdpClientConfig {
        let config = RdpClientConfig::new("rdp1.aag.local")
            .with_username(username)
            .with_password("pw")
            .with_kerberos(true);
        match domain {
            Some(domain) => config.with_domain(domain),
            None => config,
        }
    }

    fn not_consulted(_realm: &str) -> bool {
        unreachable!("KDC discovery must not run for this profile")
    }

    #[test]
    fn kdc_addresses_are_normalized() {
        for (input, expected) in [
            ("", None),
            ("   ", None),
            ("dc1.aag.local", Some("tcp://dc1.aag.local:88")),
            ("  dc1.aag.local  ", Some("tcp://dc1.aag.local:88")),
            ("dc1.aag.local:1088", Some("tcp://dc1.aag.local:1088")),
            ("10.0.0.5", Some("tcp://10.0.0.5:88")),
            ("[::1]:88", Some("tcp://[::1]:88")),
            ("[::1]", Some("tcp://[::1]:88")),
            ("::1", Some("tcp://[::1]:88")),
            ("tcp://dc1.aag.local", Some("tcp://dc1.aag.local:88")),
            ("tcp://dc1.aag.local:88/", Some("tcp://dc1.aag.local:88")),
            ("TCP://DC1.aag.local:88", Some("tcp://DC1.aag.local:88")),
            ("udp://dc1.aag.local", Some("udp://dc1.aag.local:88")),
            ("udp://dc1.aag.local:750", Some("udp://dc1.aag.local:750")),
            (
                "https://gw.aag.local/KdcProxy",
                Some("https://gw.aag.local/KdcProxy"),
            ),
            (
                "https://gw.aag.local:8443/KdcProxy",
                Some("https://gw.aag.local:8443/KdcProxy"),
            ),
            (
                "http://gw.aag.local/KdcProxy",
                Some("http://gw.aag.local/KdcProxy"),
            ),
        ] {
            assert_eq!(
                normalize_kdc_url(input),
                Ok(expected.map(str::to_owned)),
                "input: {input:?}"
            );
        }
    }

    #[test]
    fn unusable_kdc_addresses_are_rejected() {
        for (input, expected) in [
            (
                "ldap://dc1.aag.local",
                KdcUrlError::UnsupportedScheme("ldap".to_owned()),
            ),
            (
                "://dc1.aag.local",
                KdcUrlError::UnsupportedScheme(String::new()),
            ),
            ("tcp://", KdcUrlError::MissingHost),
            ("tcp://:88", KdcUrlError::MissingHost),
            ("https:///KdcProxy", KdcUrlError::MissingHost),
            ("[]:88", KdcUrlError::MissingHost),
            ("dc1.aag.local:0", KdcUrlError::InvalidPort),
            ("dc1.aag.local:70000", KdcUrlError::InvalidPort),
            ("dc1.aag.local:", KdcUrlError::InvalidPort),
            ("dc1.aag.local:+88", KdcUrlError::InvalidPort),
            ("dc1 aag.local", KdcUrlError::Whitespace),
            ("https://gw.aag.local/Kdc Proxy", KdcUrlError::Whitespace),
            ("tcp://dc1.aag.local:88/kdc", KdcUrlError::UnexpectedPath),
            ("dc1.aag.local/kdc", KdcUrlError::UnexpectedPath),
            ("admin@dc1.aag.local", KdcUrlError::InvalidHost),
            ("https://u@gw.aag.local/KdcProxy", KdcUrlError::InvalidHost),
            ("[not-an-address]:88", KdcUrlError::InvalidHost),
            ("dc1.aag.local:88:99", KdcUrlError::InvalidHost),
            ("999.1.1.1", KdcUrlError::InvalidHost),
            ("dc1.aag.local;rm", KdcUrlError::InvalidHost),
        ] {
            assert_eq!(normalize_kdc_url(input), Err(expected), "input: {input:?}");
        }
    }

    #[test]
    fn realm_comes_from_the_domain_then_the_user_name() {
        for (username, domain, expected) in [
            ("me", Some("aag.local"), Some("AAG.LOCAL")),
            ("me@aag.local", None, Some("AAG.LOCAL")),
            ("me@AAG.LOCAL", Some("  "), Some("AAG.LOCAL")),
            ("first@dept@aag.local", None, Some("AAG.LOCAL")),
            ("AAG\\me", None, Some("AAG")),
            // The Domain field wins over the user name.
            ("me@other.example", Some("AAG.LOCAL"), Some("AAG.LOCAL")),
            ("me", None, None),
            ("", Some(""), None),
        ] {
            assert_eq!(
                kerberos_realm(Some(username), domain).as_deref(),
                expected,
                "user {username:?}, domain {domain:?}"
            );
        }
        assert_eq!(kerberos_realm(None, None), None);
    }

    #[test]
    fn kerberos_needs_both_the_switch_and_nla() {
        let off = kerberos_profile("me", Some("AAG.LOCAL")).with_kerberos(false);
        assert_eq!(kerberos_settings_for(&off, not_consulted), None);

        let no_nla = kerberos_profile("me", Some("AAG.LOCAL")).with_nla(false);
        assert_eq!(kerberos_settings_for(&no_nla, not_consulted), None);
    }

    #[test]
    fn a_configured_kdc_address_is_used_as_normalized() {
        let profile = kerberos_profile("me", Some("AAG.LOCAL"));

        let config = profile.clone().with_kdc_proxy_url("dc1.aag.local");
        let settings = kerberos_settings_for(&config, not_consulted).expect("Kerberos is on");
        assert_eq!(settings.kdc_url.as_deref(), Some("tcp://dc1.aag.local:88"));
        assert!(!settings.client_hostname.is_empty());

        let config = profile.with_kdc_proxy_url("https://gw.aag.local/KdcProxy");
        let settings = kerberos_settings_for(&config, not_consulted).expect("Kerberos is on");
        assert_eq!(
            settings.kdc_url.as_deref(),
            Some("https://gw.aag.local/KdcProxy")
        );
    }

    #[test]
    fn a_kdc_that_sspi_finds_itself_is_not_overridden() {
        let config = kerberos_profile("me", Some("aag.local"));
        let mut asked = None;
        let settings = kerberos_settings_for(&config, |realm: &str| {
            asked = Some(realm.to_owned());
            true
        })
        .expect("Kerberos is on");
        assert_eq!(settings.kdc_url, None);
        assert_eq!(asked.as_deref(), Some("AAG.LOCAL"));
    }

    #[test]
    fn without_a_kdc_the_realm_name_is_tried() {
        for (username, domain, expected) in [
            ("me", Some("AAG.LOCAL"), "tcp://aag.local:88"),
            ("me@AAG.LOCAL", None, "tcp://aag.local:88"),
            // A NetBIOS name gets the same treatment; the pre-connect hint is
            // what tells the user it is the wrong kind of name.
            ("me", Some("AAG"), "tcp://aag:88"),
        ] {
            let config = kerberos_profile(username, domain);
            let settings = kerberos_settings_for(&config, |_| false).expect("Kerberos is on");
            assert_eq!(
                settings.kdc_url.as_deref(),
                Some(expected),
                "user {username:?}, domain {domain:?}"
            );
        }
    }

    #[test]
    fn a_malformed_stored_address_is_ignored_not_fatal() {
        for stored in ["ldap://dc1.aag.local", "dc1 aag.local", "   "] {
            let mut config = kerberos_profile("me", Some("AAG.LOCAL"));
            config.kdc_proxy_url = Some(stored.to_owned());
            let settings = kerberos_settings_for(&config, |_| false).expect("Kerberos is on");
            assert_eq!(
                settings.kdc_url.as_deref(),
                Some("tcp://aag.local:88"),
                "stored: {stored:?}"
            );
        }
    }

    #[test]
    fn without_a_realm_nothing_is_looked_up() {
        let config = kerberos_profile("me", None);
        let settings = kerberos_settings_for(&config, not_consulted).expect("Kerberos is on");
        assert_eq!(settings.kdc_url, None);
    }

    #[test]
    fn preflight_flags_an_address_instead_of_a_dns_name() {
        for host in [
            "10.0.0.5",
            "127.0.0.1",
            "::1",
            "[::1]",
            "fe80::1%eth0",
            "localhost",
            "LOCALHOST",
            "localhost.",
        ] {
            assert_eq!(
                kerberos_preflight(host, Some("me"), Some("AAG.LOCAL")),
                [KerberosHint::HostNotDnsName],
                "host: {host}"
            );
        }
        for host in ["rdp1.aag.local", "rdp1", "rdp-01.example.com."] {
            assert!(
                kerberos_preflight(host, Some("me"), Some("AAG.LOCAL")).is_empty(),
                "host: {host}"
            );
        }
    }

    #[test]
    fn preflight_flags_a_short_or_missing_domain() {
        use super::KerberosHint::{HostNotDnsName, MissingDomain, ShortDomainName};

        let hints = |user, domain| kerberos_preflight("rdp1.aag.local", Some(user), domain);
        assert_eq!(hints("me", Some("AAG")), [ShortDomainName]);
        assert_eq!(hints("AAG\\me", None), [ShortDomainName]);
        assert!(hints("me", Some("aag.local")).is_empty());
        assert!(hints("me@aag.local", None).is_empty());
        assert_eq!(hints("me", None), [MissingDomain]);

        let both = kerberos_preflight("10.0.0.5", Some("me"), Some("AAG"));
        assert_eq!(both, [HostNotDnsName, ShortDomainName]);
    }

    /// The KDC Address lives in the existing `kdc_proxy_url` field, and an
    /// unset one must keep the saved profile free of the key.
    #[test]
    fn an_unset_kdc_address_stays_out_of_the_saved_profile() {
        let rendered = toml::to_string(&RdpConfig::default()).expect("RdpConfig must serialize");
        assert!(!rendered.contains("kdc_proxy_url"), "{rendered}");

        let config = RdpConfig {
            kerberos_enabled: true,
            kdc_proxy_url: Some("tcp://dc1.aag.local:88".to_owned()),
            ..RdpConfig::default()
        };
        let rendered = toml::to_string(&config).expect("RdpConfig must serialize");
        let parsed: RdpConfig = toml::from_str(&rendered).expect("RdpConfig must deserialize");
        assert!(parsed.kerberos_enabled);
        assert_eq!(
            parsed.kdc_proxy_url.as_deref(),
            Some("tcp://dc1.aag.local:88")
        );
    }
}
