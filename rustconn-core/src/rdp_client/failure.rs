//! Classification of embedded RDP connection failures.
//!
//! The embedded IronRDP client reports failures to the GUI as plain strings
//! (`RdpClientEvent::Error`), because the error crosses a thread channel and
//! upstream `ironrdp` error types are not `Clone`. The GUI has to decide what
//! to do with each failure:
//!
//! * retry with a different graphics mode,
//! * hand the session over to the external `FreeRDP` client,
//! * or surface an authentication error and stop.
//!
//! Historically that decision was a list of `msg.contains(..)` checks inlined
//! in the GTK layer, which silently broke every time an upstream error string
//! changed (issues [#199], [#234], [#235]). The matching now lives here as a
//! pure, unit-tested function so the GUI only switches on the resulting
//! [`RdpFailureClass`].
//!
//! What to *tell* the user about a rejected sign-in is a separate, finer
//! question, answered by [`classify_auth_failure`]: a Kerberos KDC that cannot
//! be found needs different advice from a wrong password (issue [#351]). It
//! never changes the fallback decision.
//!
//! [#199]: https://github.com/totoshko88/RustConn/issues/199
//! [#234]: https://github.com/totoshko88/RustConn/issues/234
//! [#235]: https://github.com/totoshko88/RustConn/issues/235
//! [#351]: https://github.com/totoshko88/RustConn/issues/351

/// What kind of failure ended (or prevented) an embedded RDP session.
///
/// Ordered from "most specific" to "least specific"; [`classify_rdp_failure`]
/// returns the first matching class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdpFailureClass {
    /// The server rejected the supplied credentials (CredSSP/NLA `NTSTATUS`
    /// logon failure, disabled or locked account, expired password).
    Authentication,
    /// The MS-TSGU tunnel to the RD Gateway could not be established.
    GatewayFailure,
    /// The GFX pipeline produced no decodable frame or failed to decode.
    GraphicsPipeline,
    /// The server offers only a security protocol IronRDP does not implement.
    SecurityUnsupported,
    /// IronRDP and the server disagree on the wire protocol.
    ProtocolIncompatible,
    /// Anything else: unreachable host, timeout, TLS failure, local error.
    Other,
}

impl RdpFailureClass {
    /// Returns `true` when handing the session to external `FreeRDP` can help.
    #[must_use]
    pub const fn warrants_freerdp_fallback(self) -> bool {
        matches!(
            self,
            Self::SecurityUnsupported
                | Self::ProtocolIncompatible
                | Self::GraphicsPipeline
                | Self::GatewayFailure
        )
    }

    /// Returns `true` when fallback would weaken the negotiated security.
    #[must_use]
    pub const fn requires_explicit_consent(self) -> bool {
        matches!(self, Self::SecurityUnsupported)
    }
}

/// `NTSTATUS` codes CredSSP/NLA returns for credential problems.
const AUTH_NSTATUS_CODES: &[&str] = &[
    "0xc0000064", // STATUS_NO_SUCH_USER
    "0xc000006d", // STATUS_LOGON_FAILURE
    "0xc000006a", // STATUS_WRONG_PASSWORD
    "0xc000006e", // STATUS_ACCOUNT_RESTRICTION
    "0xc000006f", // STATUS_INVALID_LOGON_HOURS
    "0xc0000070", // STATUS_INVALID_WORKSTATION
    "0xc0000071", // STATUS_PASSWORD_EXPIRED
    "0xc0000072", // STATUS_ACCOUNT_DISABLED
    "0xc000015b", // STATUS_LOGON_TYPE_NOT_GRANTED
    "0xc0000193", // STATUS_ACCOUNT_EXPIRED
    "0xc0000224", // STATUS_PASSWORD_MUST_CHANGE
    "0xc0000234", // STATUS_ACCOUNT_LOCKED_OUT
];

/// Symbolic `NTSTATUS` names and other markers of a credential rejection.
const AUTH_MARKERS: &[&str] = &[
    "authentication failed",
    "status_no_such_user",
    "status_logon_failure",
    "status_wrong_password",
    "status_password_expired",
    "status_password_must_change",
    "status_account_disabled",
    "status_account_expired",
    "status_account_locked_out",
    "status_account_restriction",
    "status_logon_type_not_granted",
    "accessdenied",
];

/// Markers of a failed MS-TSGU tunnel to the RD Gateway.
///
/// Produced by the gateway branch of the embedded connect path; the external
/// FreeRDP client speaks the same protocol with a wider set of authentication
/// methods (`ironrdp-mstsgu` only offers HTTP Basic), so it is worth a try.
const GATEWAY_MARKERS: &[&str] = &["rd gateway connection failed"];

/// TLS, certificate, and transport failures that must not trigger fallback.
const NON_FALLBACK_MARKERS: &[&str] = &[
    "tls",
    "certificate",
    "ssl_cert_not_on_server",
    "unknown issuer",
    "x509",
    "transport",
    "connection refused",
    "connection reset",
    "connection timed out",
    "operation timed out",
    "dns_name_not_found",
    "host not found",
    "network is unreachable",
    "no route to host",
];

/// Markers of a GFX/EGFX pipeline problem.
///
/// `gfx unsupported codec` covers the case where the server sends surface
/// content in a codec `ironrdp-egfx` cannot decode. Retrying without GFX is the
/// right response: the RemoteFX/bitmap path has no such gap (issue [#262]).
///
/// [#262]: https://github.com/totoshko88/RustConn/issues/262
const GRAPHICS_MARKERS: &[&str] = &[
    "no-frame-watchdog",
    "gfx pipeline decode failure",
    "gfx unsupported codec",
];

/// Explicit security protocols IronRDP cannot speak.
const SECURITY_MARKERS: &[&str] = &[
    "standard rdp security",
    "ssl_not_allowed_by_server",
    "hybrid_required_by_server",
    "unsupported security protocol",
];

/// Specific IronRDP/server protocol mismatches that justify fallback.
/// Generic finalize and negotiation wrappers are intentionally excluded.
const PROTOCOL_MARKERS: &[&str] = &[
    "serverdemandactive",
    "serverdeactivateall",
    "invalid state (this is a bug)",
    "unexpected share control pdu",
    "unsupported pdu",
    "decode error",
    "unsupported fast-path update code",
    // A rejected `BasicSecurityHeader`. Kept here rather than in
    // [`LICENSE_MARKERS`] because the header is common to every Standard RDP
    // Security PDU, so it identifies the fallback but not the phase.
    "securityheaderflags",
];

/// Markers naming the RDP licensing exchange as the phase that failed.
///
/// A subset of [`PROTOCOL_MARKERS`] rather than a class of its own: handing the
/// session to the external client is still the right response, so the *decision*
/// does not change. What changes is what the user is told — `"decode error"` is
/// broad enough to swallow this case, and "server incompatible" says nothing
/// about a server that is merely running RDS licensing.
///
/// Both entries name the phase itself. `securityHeaderFlags` — the field the
/// decoder actually rejects — is deliberately **not** here: it is a field of
/// `BasicSecurityHeader`, which every Standard RDP Security PDU carries, so a
/// decode failure mentioning it says nothing about *where* in the connection it
/// happened. Matching on it would report an unrelated header failure as "the
/// server requires RDS licensing". It stays in [`PROTOCOL_MARKERS`] instead,
/// where it only affects the fallback decision, which is the same either way.
///
/// The cause is upstream and open:
/// [IronRDP #1629](https://github.com/Devolutions/IronRDP/issues/1629). A
/// Windows host with RDS licensing sends `SEC_AUTODETECT_REQ` (an RTT probe,
/// flag `0x1000`) during the licensing exchange; `ironrdp-connector` feeds
/// whatever arrives to the licensing decoder without checking the channel or the
/// security header, and `LicenseHeader::decode` rejects it because
/// `SEC_LICENSE_PKT` (`0x0080`) is absent. Not to be confused with
/// [#1457](https://github.com/Devolutions/IronRDP/issues/1457) /
/// [#1458](https://github.com/Devolutions/IronRDP/pull/1458), which relaxed
/// `BasicSecurityHeader` and does not touch this check — and is in any case not
/// yet published (`ironrdp-pdu` on crates.io is still 0.9.0).
const LICENSE_MARKERS: &[&str] = &["server_new_license", "licenseexchangestate"];

/// Returns `true` when the failure happened in the RDP licensing exchange.
///
/// Used only to choose the message shown to the user; see [`LICENSE_MARKERS`].
#[must_use]
pub fn is_license_exchange_failure(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    LICENSE_MARKERS.iter().any(|m| lower.contains(m))
}

/// Classifies an embedded RDP failure message into a [`RdpFailureClass`].
///
/// Authentication is checked first, then RD Gateway tunnel failures. TLS,
/// certificate, and transport roots take precedence over fallback-worthy
/// protocol markers.
#[must_use]
pub fn classify_rdp_failure(msg: &str) -> RdpFailureClass {
    let lower = msg.to_ascii_lowercase();

    if is_authentication_failure_lower(&lower) {
        return RdpFailureClass::Authentication;
    }
    // Checked before the transport markers on purpose: a gateway failure wraps
    // the underlying cause ("TCP connect", "TLS connect", "WS Upgrade"), and
    // those words would otherwise classify the whole message as a plain
    // transport error and strand the session (issue #246). The external client
    // implements the same tunnel with more authentication methods, so handing
    // it over is worthwhile whatever the inner cause was.
    if GATEWAY_MARKERS.iter().any(|m| lower.contains(m)) {
        return RdpFailureClass::GatewayFailure;
    }
    if NON_FALLBACK_MARKERS.iter().any(|m| lower.contains(m)) {
        return RdpFailureClass::Other;
    }
    if GRAPHICS_MARKERS.iter().any(|m| lower.contains(m)) {
        return RdpFailureClass::GraphicsPipeline;
    }
    if SECURITY_MARKERS.iter().any(|m| lower.contains(m)) {
        return RdpFailureClass::SecurityUnsupported;
    }
    if PROTOCOL_MARKERS.iter().any(|m| lower.contains(m))
        || LICENSE_MARKERS.iter().any(|m| lower.contains(m))
    {
        return RdpFailureClass::ProtocolIncompatible;
    }
    RdpFailureClass::Other
}

/// Returns `true` when the message describes a rejected credential.
#[must_use]
pub fn is_authentication_failure(msg: &str) -> bool {
    is_authentication_failure_lower(&msg.to_ascii_lowercase())
}

fn is_authentication_failure_lower(lower: &str) -> bool {
    AUTH_NSTATUS_CODES.iter().any(|c| lower.contains(c))
        || AUTH_MARKERS.iter().any(|m| lower.contains(m))
}

/// What a rejected CredSSP/NLA sign-in was rejected for, as far as the message says.
///
/// Finer than [`RdpFailureClass::Authentication`]: that class decides that no
/// external client is tried, this one picks the advice shown to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthFailureKind {
    /// sspi found no KDC for the realm: no KDC Address, nothing in the
    /// environment and nothing in `krb5.conf`.
    NoKdc {
        /// The realm, when sspi's message names one, as it does for a
        /// cross-realm referral.
        realm: Option<String>,
    },
    /// A KDC was named but could not be reached over TCP or UDP, or the KDC
    /// proxy failed.
    KdcUnreachable,
    /// `STATUS_ACCOUNT_RESTRICTION`: an account restriction refused the sign-in,
    /// such as the NTLM ban on members of AD "Protected Users".
    AccountRestriction,
    /// Logon hours or workstation restrictions, or a KDC policy refusal.
    LogonRestriction,
    /// A wrong user name or password, or a user the domain does not know.
    InvalidCredentials,
    /// The password has expired.
    PasswordExpired,
    /// The password must be changed before the first sign-in.
    PasswordMustChange,
    /// The account is disabled.
    AccountDisabled,
    /// The account is locked out.
    AccountLockedOut,
    /// The account has expired.
    AccountExpired,
    /// The KDC revoked the account's credentials: disabled, locked out or
    /// expired, without saying which.
    AccountRevoked,
    /// The account may not sign in to this server, for example without the
    /// Remote Desktop logon right.
    LogonTypeNotGranted,
    /// The clocks of this computer and of the domain differ by more than
    /// Kerberos allows.
    ClockSkew,
    /// The KDC does not know the service principal `TERMSRV/<host>`, usually
    /// because the host is not the server's DNS name.
    UnknownServerPrincipal,
    /// Any other CredSSP/NLA failure.
    Generic,
}

/// `NTSTATUS` codes a CredSSP server returns, and what each says about the sign-in.
///
/// `0xc0000070` is `STATUS_INVALID_WORKSTATION`. The GUI used to word it as
/// "password must be changed", which is `0xc0000224`.
static NTSTATUS_KINDS: &[(&str, AuthFailureKind)] = &[
    ("0xc000006d", AuthFailureKind::InvalidCredentials), // STATUS_LOGON_FAILURE
    ("0xc000006a", AuthFailureKind::InvalidCredentials), // STATUS_WRONG_PASSWORD
    ("0xc0000064", AuthFailureKind::InvalidCredentials), // STATUS_NO_SUCH_USER
    ("0xc000006e", AuthFailureKind::AccountRestriction), // STATUS_ACCOUNT_RESTRICTION
    ("0xc000006f", AuthFailureKind::LogonRestriction),   // STATUS_INVALID_LOGON_HOURS
    ("0xc0000070", AuthFailureKind::LogonRestriction),   // STATUS_INVALID_WORKSTATION
    ("0xc0000071", AuthFailureKind::PasswordExpired),    // STATUS_PASSWORD_EXPIRED
    ("0xc0000072", AuthFailureKind::AccountDisabled),    // STATUS_ACCOUNT_DISABLED
    ("0xc000015b", AuthFailureKind::LogonTypeNotGranted), // STATUS_LOGON_TYPE_NOT_GRANTED
    ("0xc0000193", AuthFailureKind::AccountExpired),     // STATUS_ACCOUNT_EXPIRED
    ("0xc0000224", AuthFailureKind::PasswordMustChange), // STATUS_PASSWORD_MUST_CHANGE
    ("0xc0000234", AuthFailureKind::AccountLockedOut),   // STATUS_ACCOUNT_LOCKED_OUT
    ("status_logon_failure", AuthFailureKind::InvalidCredentials),
];

/// `KRB-ERROR` texts as sspi 0.21 words them (its `utils.rs` error-code table).
static KERBEROS_KINDS: &[(&str, AuthFailureKind)] = &[
    // KRB_AP_ERR_SKEW (37), which sspi files under `ErrorKind::TimeSkew`.
    ("clock skew too great", AuthFailureKind::ClockSkew),
    ("timeskew", AuthFailureKind::ClockSkew),
    // KDC_ERR_S_PRINCIPAL_UNKNOWN (7): the domain has no `TERMSRV/<host>`.
    (
        "server not found in kerberos database",
        AuthFailureKind::UnknownServerPrincipal,
    ),
    // KDC_ERR_C_PRINCIPAL_UNKNOWN (6)
    (
        "client not found in kerberos database",
        AuthFailureKind::InvalidCredentials,
    ),
    // KDC_ERR_PREAUTH_FAILED (24): the password did not decrypt the timestamp.
    (
        "pre-authentication information was invalid",
        AuthFailureKind::InvalidCredentials,
    ),
    // KDC_ERR_KEY_EXPIRED (23)
    ("password has expired", AuthFailureKind::PasswordExpired),
    // KDC_ERR_CLIENT_REVOKED (18)
    (
        "clients credentials have been revoked",
        AuthFailureKind::AccountRevoked,
    ),
    // KDC_ERR_POLICY (12)
    (
        "kdc policy rejects request",
        AuthFailureKind::LogonRestriction,
    ),
];

/// sspi's wording when neither the configuration nor its own lookup names a KDC.
const NO_KDC_MARKER: &str = "no kdc server found";

/// Contexts of the KDC transport errors raised by `ironrdp-tokio`'s
/// `ReqwestNetworkClient` (0.10). Its `Display` carries the context only, not
/// the underlying I/O error.
const KDC_TRANSPORT_MARKERS: &[&str] = &[
    "failed to send kdc request",
    "failed to receive kdc response",
    "[kdcproxy @",
    "cannot bind udp socket",
    "failed to send udp request",
    "failed to receive udp request",
];

/// Says what a CredSSP/NLA failure was about, to pick the advice shown to the user.
///
/// `None` when the message is not about the NLA sign-in at all — a refused TCP
/// connection, a TLS failure, a timeout — which the caller words itself.
/// Checked from the most specific to the least: server `NTSTATUS` codes,
/// Kerberos `KRB-ERROR` texts, a KDC that is missing or unreachable, an early
/// user authorization refusal, and finally any other CredSSP failure as
/// [`AuthFailureKind::Generic`].
///
/// Never consulted for the fallback decision: whether an external client is
/// tried is [`classify_rdp_failure`]'s call alone.
#[must_use]
pub fn classify_auth_failure(msg: &str) -> Option<AuthFailureKind> {
    let lower = msg.to_ascii_lowercase();
    if let Some(kind) = first_listed(&lower, NTSTATUS_KINDS) {
        return Some(kind);
    }
    if let Some(kind) = first_listed(&lower, KERBEROS_KINDS) {
        return Some(kind);
    }
    if lower.contains(NO_KDC_MARKER) {
        return Some(AuthFailureKind::NoKdc {
            realm: realm_named_in(msg, &lower),
        });
    }
    if KDC_TRANSPORT_MARKERS.iter().any(|m| lower.contains(m)) {
        return Some(AuthFailureKind::KdcUnreachable);
    }
    // `EarlyUserAuthResult::AccessDenied`: the server turned the account away
    // after CredSSP succeeded, which is what a missing Remote Desktop logon
    // right does.
    if lower.contains("accessdenied") {
        return Some(AuthFailureKind::LogonTypeNotGranted);
    }
    lower
        .contains("credssp")
        .then_some(AuthFailureKind::Generic)
}

/// The kind of the first table entry whose marker occurs in `lower`.
fn first_listed(lower: &str, table: &[(&str, AuthFailureKind)]) -> Option<AuthFailureKind> {
    table
        .iter()
        .find(|(marker, _)| lower.contains(marker))
        .map(|(_, kind)| kind.clone())
}

/// The realm in sspi's ``No KDC server found for realm `X` `` wording, if any.
fn realm_named_in(msg: &str, lower: &str) -> Option<String> {
    const PREFIX: &str = "for realm `";
    // `lower` is `msg` lower-cased byte for byte, so offsets carry over.
    let start = lower.find(PREFIX)? + PREFIX.len();
    let rest = msg.get(start..)?;
    let realm = rest.get(..rest.find('`')?)?.trim();
    (!realm.is_empty()).then(|| realm.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUE_235: &str = "Connection failed: Connection begin failed: \
         negotiation failure: server only supports Standard RDP Security";

    const CREDSSP_LOGON_FAILURE: &str = "Connection failed: Connection finalize failed: \
         CredSSP server returned an error status; \
         nstatus: Some(NStatusCode(0xc000006d))";

    #[test]
    fn standard_rdp_security_is_security_unsupported() {
        let class = classify_rdp_failure(ISSUE_235);
        assert_eq!(class, RdpFailureClass::SecurityUnsupported);
        assert!(class.warrants_freerdp_fallback());
    }

    #[test]
    fn classification_is_case_insensitive() {
        assert_eq!(
            classify_rdp_failure("UNEXPECTED SHARE CONTROL PDU"),
            RdpFailureClass::ProtocolIncompatible
        );
        assert_eq!(
            classify_rdp_failure("GfX PiPeLiNe DeCoDe FaIlUrE"),
            RdpFailureClass::GraphicsPipeline
        );
        assert_eq!(
            classify_rdp_failure("SERVER ONLY SUPPORTS STANDARD RDP SECURITY"),
            RdpFailureClass::SecurityUnsupported
        );
    }

    #[test]
    fn credssp_logon_failure_is_authentication() {
        let class = classify_rdp_failure(CREDSSP_LOGON_FAILURE);
        assert_eq!(class, RdpFailureClass::Authentication);
        assert!(!class.warrants_freerdp_fallback());
    }

    #[test]
    fn missing_account_statuses_are_authentication() {
        for marker in [
            "nstatus: Some(NStatusCode(0xC0000064))",
            "nstatus: Some(NStatusCode(0xc0000193))",
            "STATUS_NO_SUCH_USER",
            "status_account_expired",
        ] {
            assert_eq!(
                classify_rdp_failure(marker),
                RdpFailureClass::Authentication,
                "marker was not classified as authentication: {marker}"
            );
        }
    }

    #[test]
    fn tls_and_certificate_failures_never_fall_back() {
        for msg in [
            "Connection finalize failed: TLS handshake failed: invalid peer certificate",
            "Unexpected Share Control Pdu after certificate verification failed",
            "SSL_CERT_NOT_ON_SERVER during negotiation",
        ] {
            let class = classify_rdp_failure(msg);
            assert_eq!(class, RdpFailureClass::Other, "message: {msg}");
            assert!(!class.warrants_freerdp_fallback(), "message: {msg}");
        }
    }

    #[test]
    fn transport_failures_never_fall_back() {
        for msg in [
            "negotiation failed: ERRCONNECT_CONNECT_TRANSPORT_FAILED",
            "ServerDemandActive: connection reset by peer",
            "Connection refused (os error 111)",
        ] {
            let class = classify_rdp_failure(msg);
            assert_eq!(class, RdpFailureClass::Other, "message: {msg}");
            assert!(!class.warrants_freerdp_fallback(), "message: {msg}");
        }
    }

    #[test]
    fn generic_finalize_and_negotiation_are_not_protocol_markers() {
        for msg in [
            "Connection finalize failed",
            "connect_finalize failed",
            "negotiation failure",
            "NegotiationError",
        ] {
            assert_eq!(classify_rdp_failure(msg), RdpFailureClass::Other);
        }
    }

    #[test]
    fn specific_protocol_and_graphics_markers_still_fall_back() {
        assert_eq!(
            classify_rdp_failure("invalid state (this is a bug)"),
            RdpFailureClass::ProtocolIncompatible
        );
        assert_eq!(
            classify_rdp_failure("NO-FRAME-WATCHDOG: no decodable frame"),
            RdpFailureClass::GraphicsPipeline
        );
    }

    /// Exact message built by the GFX unsupported-codec branch of the GUI event
    /// loop; it must reach the Legacy retry rather than being reported as-is.
    #[test]
    fn unsupported_gfx_codec_retries_without_gfx() {
        let class =
            classify_rdp_failure("gfx unsupported codec: Avc444v2 (5 surface updates dropped)");
        assert_eq!(class, RdpFailureClass::GraphicsPipeline);
        assert!(class.warrants_freerdp_fallback());
        assert!(!class.requires_explicit_consent());
    }

    #[test]
    fn gateway_tunnel_failure_falls_back_to_external_client() {
        // Exact message built by the gateway branch of `establish_connection`.
        let class = classify_rdp_failure("RD Gateway connection failed: WS Upgrade error");
        assert_eq!(class, RdpFailureClass::GatewayFailure);
        assert!(class.warrants_freerdp_fallback());
        assert!(!class.requires_explicit_consent());
    }

    #[test]
    fn gateway_failure_wins_over_wrapped_transport_cause() {
        // The wrapped cause carries transport/TLS wording; the gateway class
        // must still win so the session reaches the external client (#246).
        for msg in [
            "RD Gateway connection failed: TCP connect: connection refused (os error 111)",
            "RD Gateway connection failed: TLS connect: invalid peer certificate",
            "RD Gateway connection failed: custom error: host not found",
        ] {
            let class = classify_rdp_failure(msg);
            assert_eq!(class, RdpFailureClass::GatewayFailure, "message: {msg}");
            assert!(class.warrants_freerdp_fallback(), "message: {msg}");
        }
    }

    #[test]
    fn rejected_gateway_credentials_stay_authentication() {
        // Credential rejection outranks the gateway marker: the external client
        // would be refused by the same account.
        let class = classify_rdp_failure(
            "RD Gateway connection failed: nstatus: Some(NStatusCode(0xc000006d))",
        );
        assert_eq!(class, RdpFailureClass::Authentication);
        assert!(!class.warrants_freerdp_fallback());
    }

    #[test]
    fn direct_transport_failures_are_not_gateway_failures() {
        assert_eq!(
            classify_rdp_failure("Failed to connect to host.internal:3389: connection refused"),
            RdpFailureClass::Other
        );
    }

    #[test]
    fn only_legacy_security_fallback_requires_explicit_consent() {
        assert!(RdpFailureClass::SecurityUnsupported.requires_explicit_consent());
        for class in [
            RdpFailureClass::Authentication,
            RdpFailureClass::GatewayFailure,
            RdpFailureClass::GraphicsPipeline,
            RdpFailureClass::ProtocolIncompatible,
            RdpFailureClass::Other,
        ] {
            assert!(!class.requires_explicit_consent(), "class: {class:?}");
        }
    }

    #[test]
    fn auth_wins_over_non_fallback_and_protocol_markers() {
        let msg = "TLS handshake; unexpected Share Control Pdu; \
                   nstatus: Some(NStatusCode(0xc000006d))";
        assert_eq!(classify_rdp_failure(msg), RdpFailureClass::Authentication);
    }

    /// Verbatim from a user report against a Windows host with RDS licensing.
    const LICENSE_EXCHANGE_FAILURE: &str = "Connection failed: Connection finalize failed: \
         [decode during SERVER_NEW_LICENSE/LicenseExchangeState::UpgradeLicense] decode error \
         [kind: Decode(Error { context: \"<ironrdp_pdu::rdp::server_license::LicenseHeader as \
         ironrdp_core::decode::Decode<'_>>::decode\", kind: InvalidField { field: \
         \"securityHeaderFlags\", reason: \"invalid security header flags\" }, source: None })]";

    #[test]
    fn license_exchange_failure_is_recognised() {
        assert!(is_license_exchange_failure(LICENSE_EXCHANGE_FAILURE));
    }

    #[test]
    fn license_exchange_failure_still_falls_back() {
        // The class must not change: the external client connects to these hosts.
        let class = classify_rdp_failure(LICENSE_EXCHANGE_FAILURE);
        assert_eq!(class, RdpFailureClass::ProtocolIncompatible);
        assert!(class.warrants_freerdp_fallback());
        assert!(!class.requires_explicit_consent());
    }

    #[test]
    fn license_markers_are_classified_without_the_generic_decode_wording() {
        // `"decode error"` is what catches this message today; the licensing
        // markers have to stand on their own so a reworded upstream error still
        // reaches the fallback.
        let class = classify_rdp_failure(
            "[decode during SERVER_NEW_LICENSE/LicenseExchangeState::UpgradeLicense]",
        );
        assert_eq!(class, RdpFailureClass::ProtocolIncompatible);
    }

    #[test]
    fn unrelated_failures_are_not_license_failures() {
        for msg in [
            ISSUE_235,
            CREDSSP_LOGON_FAILURE,
            "unexpected Share Control Pdu",
            "gfx unsupported codec: Avc444v2",
        ] {
            assert!(
                !is_license_exchange_failure(msg),
                "wrongly reported as a licensing failure: {msg}"
            );
        }
    }

    #[test]
    fn a_security_header_failure_outside_licensing_is_not_a_license_failure() {
        // `BasicSecurityHeader` is common to every Standard RDP Security PDU, so
        // its field name alone cannot say the licensing exchange was the phase
        // that failed — but it must still reach the external client.
        let msg = "decode error [kind: Decode(Error { context: \
                   \"<ironrdp_pdu::rdp::BasicSecurityHeader as \
                   ironrdp_core::decode::Decode<'_>>::decode\", kind: InvalidField { field: \
                   \"securityHeaderFlags\", reason: \"invalid security header flags\" } })]";

        assert!(
            !is_license_exchange_failure(msg),
            "a BasicSecurityHeader failure must not be reported as RDS licensing"
        );
        let class = classify_rdp_failure(msg);
        assert_eq!(class, RdpFailureClass::ProtocolIncompatible);
        assert!(class.warrants_freerdp_fallback());
    }

    /// Verbatim from issue #351: the core log line, NLA with Kerberos on.
    const ISSUE_351_NO_KDC_LOG: &str = "CredSSP error_kind=Credssp(Error { error_type: \
         NoAuthenticatingAuthority, description: \"No KDC server found\", nstatus: None })";

    /// Verbatim from issue #351: what the GUI received for the same failure.
    const ISSUE_351_NO_KDC_GUI: &str = "Connection failed: Connection finalize failed: [CredSSP @ \
         /usr/src/packages/BUILD/vendor/ironrdp-async-0.10.0/src/connector.rs:107] CredSSP \
         [kind: Credssp(Error { error_type: NoAuthenticatingAuthority, description: \
         \"No KDC server found\", nstatus: None })]";

    /// Verbatim from issue #351: the core log line, NLA with NTLM, refused because
    /// the account is in Protected Users.
    const ISSUE_351_NTLM_LOG: &str = "CredSSP error_kind=Credssp(Error { error_type: \
         InvalidToken, description: \"CredSSP server returned an error status\", \
         nstatus: Some(NStatusCode(0xc000006e)) })";

    /// Verbatim from issue #351: what the GUI received for the same failure.
    const ISSUE_351_NTLM_GUI: &str = "Authentication failed: Connection finalize failed: \
         [CredSSP @ /usr/src/packages/BUILD/vendor/ironrdp-async-0.10.0/src/connector.rs:107] \
         CredSSP [kind: Credssp(Error { error_type: InvalidToken, description: \
         \"CredSSP server returned an error status\", nstatus: Some(NStatusCode(0xc000006e)) })]";

    /// A CredSSP failure the way `map_connector_error` words a server status.
    fn credssp_status(code: &str) -> String {
        format!(
            "Authentication failed: Connection finalize failed: [CredSSP @ connector.rs:107] \
             CredSSP [kind: Credssp(Error {{ error_type: InvalidToken, description: \
             \"CredSSP server returned an error status\", nstatus: Some(NStatusCode({code})) }})]"
        )
    }

    /// A Kerberos failure the way `map_connector_error` words an sspi error.
    fn sspi_error(error_type: &str, description: &str) -> String {
        format!(
            "Connection failed: Connection finalize failed: [CredSSP @ connector.rs:107] \
             CredSSP [kind: Credssp(Error {{ error_type: {error_type}, description: \
             \"{description}\", nstatus: None }})]"
        )
    }

    #[test]
    fn issue_351_missing_kdc_is_named_and_still_does_not_fall_back() {
        for msg in [ISSUE_351_NO_KDC_LOG, ISSUE_351_NO_KDC_GUI] {
            assert_eq!(
                classify_auth_failure(msg),
                Some(AuthFailureKind::NoKdc { realm: None }),
                "message: {msg}"
            );
        }
        let class = classify_rdp_failure(ISSUE_351_NO_KDC_GUI);
        assert_eq!(class, RdpFailureClass::Other);
        assert!(!class.warrants_freerdp_fallback());
    }

    #[test]
    fn issue_351_ntlm_refusal_is_an_account_restriction() {
        for msg in [ISSUE_351_NTLM_LOG, ISSUE_351_NTLM_GUI] {
            assert_eq!(
                classify_auth_failure(msg),
                Some(AuthFailureKind::AccountRestriction),
                "message: {msg}"
            );
        }
        let class = classify_rdp_failure(ISSUE_351_NTLM_GUI);
        assert_eq!(class, RdpFailureClass::Authentication);
        assert!(!class.warrants_freerdp_fallback());
    }

    #[test]
    fn every_handled_ntstatus_code_has_its_own_kind() {
        for (code, expected) in [
            ("0xc000006d", AuthFailureKind::InvalidCredentials),
            ("0xc000006a", AuthFailureKind::InvalidCredentials),
            ("0xc0000064", AuthFailureKind::InvalidCredentials),
            ("0xc000006e", AuthFailureKind::AccountRestriction),
            ("0xc000006f", AuthFailureKind::LogonRestriction),
            ("0xc0000070", AuthFailureKind::LogonRestriction),
            ("0xc0000071", AuthFailureKind::PasswordExpired),
            ("0xc0000072", AuthFailureKind::AccountDisabled),
            ("0xc000015b", AuthFailureKind::LogonTypeNotGranted),
            ("0xc0000193", AuthFailureKind::AccountExpired),
            ("0xc0000224", AuthFailureKind::PasswordMustChange),
            ("0xc0000234", AuthFailureKind::AccountLockedOut),
        ] {
            let msg = credssp_status(code);
            assert_eq!(
                classify_auth_failure(&msg),
                Some(expected.clone()),
                "code: {code}"
            );
            assert_eq!(
                classify_auth_failure(&msg.to_ascii_uppercase()),
                Some(expected),
                "upper-case code: {code}"
            );
            // The finer kind never changes the fallback decision.
            assert!(
                !classify_rdp_failure(&msg).warrants_freerdp_fallback(),
                "code: {code}"
            );
        }
    }

    #[test]
    fn a_rejected_password_keeps_its_message_and_never_falls_back() {
        let msg = credssp_status("0xc000006d");
        assert_eq!(
            classify_auth_failure(&msg),
            Some(AuthFailureKind::InvalidCredentials)
        );
        assert_eq!(classify_rdp_failure(&msg), RdpFailureClass::Authentication);
        assert_eq!(
            classify_auth_failure("STATUS_LOGON_FAILURE"),
            Some(AuthFailureKind::InvalidCredentials)
        );
    }

    #[test]
    fn kerberos_errors_have_their_own_kinds() {
        for (error_type, description, expected) in [
            (
                "TimeSkew",
                "clock skew too great",
                AuthFailureKind::ClockSkew,
            ),
            (
                "TimeSkew",
                "clock skew too great. Additional error text: \\\"skew\\\"",
                AuthFailureKind::ClockSkew,
            ),
            (
                "UnknownCredentials",
                "server not found in Kerberos database",
                AuthFailureKind::UnknownServerPrincipal,
            ),
            (
                "UnknownCredentials",
                "client not found in Kerberos database",
                AuthFailureKind::InvalidCredentials,
            ),
            (
                "KdcInvalidRequest",
                "pre-authentication information was invalid",
                AuthFailureKind::InvalidCredentials,
            ),
            (
                "InvalidParameter",
                "password has expired; change password to reset",
                AuthFailureKind::PasswordExpired,
            ),
            (
                "UnknownCredentials",
                "clients credentials have been revoked",
                AuthFailureKind::AccountRevoked,
            ),
            (
                "KdcInvalidRequest",
                "KDC policy rejects request",
                AuthFailureKind::LogonRestriction,
            ),
        ] {
            let msg = sspi_error(error_type, description);
            assert_eq!(
                classify_auth_failure(&msg),
                Some(expected),
                "description: {description}"
            );
        }
    }

    #[test]
    fn a_cross_realm_kdc_miss_names_the_realm() {
        let msg = sspi_error(
            "NoAuthenticatingAuthority",
            "No KDC server found for realm `DEV.AAG.LOCAL`",
        );
        assert_eq!(
            classify_auth_failure(&msg),
            Some(AuthFailureKind::NoKdc {
                realm: Some("DEV.AAG.LOCAL".to_owned()),
            })
        );
    }

    #[test]
    fn an_unreachable_kdc_is_not_reported_as_a_bad_password() {
        for msg in [
            "Connection failed: Connection finalize failed: \
             [failed to send KDC request over TCP @ \
             /usr/src/packages/BUILD/vendor/ironrdp-tokio-0.10.0/src/reqwest.rs:47] \
             custom error [kind: Custom]",
            "Connection failed: Connection finalize failed: [KdcProxy @ reqwest.rs:113] \
             custom error [kind: Custom]",
            "Connection failed: Connection finalize failed: [failed to send UDP request @ \
             reqwest.rs:91] custom error [kind: Custom]",
        ] {
            assert_eq!(
                classify_auth_failure(msg),
                Some(AuthFailureKind::KdcUnreachable),
                "message: {msg}"
            );
            assert!(
                !classify_rdp_failure(msg).warrants_freerdp_fallback(),
                "message: {msg}"
            );
        }
    }

    #[test]
    fn an_early_authorization_refusal_is_a_missing_logon_right() {
        let msg = "Authentication failed: Connection finalize failed: [CredSSP @ connector.rs:166] \
                   access denied [kind: AccessDenied]";
        assert_eq!(
            classify_auth_failure(msg),
            Some(AuthFailureKind::LogonTypeNotGranted)
        );
    }

    #[test]
    fn other_credssp_failures_are_generic() {
        for msg in [
            sspi_error("InternalError", "unexpected status: CompleteNeeded"),
            "CredSSP [kind: Credssp(Error { error_type: OutOfSequence })]".to_owned(),
            "Credssp failure".to_owned(),
        ] {
            assert_eq!(
                classify_auth_failure(&msg),
                Some(AuthFailureKind::Generic),
                "message: {msg}"
            );
        }
    }

    #[test]
    fn failures_outside_the_sign_in_have_no_auth_kind() {
        for msg in [
            ISSUE_235,
            "Failed to connect to host.internal:3389: connection refused",
            "TLS upgrade failed: invalid peer certificate",
            "Operation timed out",
            LICENSE_EXCHANGE_FAILURE,
        ] {
            assert_eq!(classify_auth_failure(msg), None, "message: {msg}");
        }
    }
}
