use super::{
    ChecksumPolicy, CliDownloadError, CliDownloadResult, DownloadCancellation, DownloadProgress,
    ProgressCallback,
};

/// Download file with progress reporting
pub(super) async fn download_with_progress(
    url: &str,
    progress_callback: &ProgressCallback,
    cancel_token: &DownloadCancellation,
) -> CliDownloadResult<Vec<u8>> {
    use futures::StreamExt;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .map_err(|e| CliDownloadError::DownloadFailed(e.to_string()))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| CliDownloadError::DownloadFailed(e.to_string()))?;

    // Check for HTTP errors
    let status = response.status();
    if !status.is_success() {
        return Err(CliDownloadError::DownloadFailed(format!(
            "HTTP {} - {}",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Unknown error")
        )));
    }

    let total_size = response.content_length();
    let mut downloaded: u64 = 0;
    let mut data = Vec::with_capacity(total_size.unwrap_or(1_000_000) as usize);

    let mut stream = response.bytes_stream();

    while let Some(chunk_result) = stream.next().await {
        // Check for cancellation
        if cancel_token.is_cancelled() {
            return Err(CliDownloadError::Cancelled);
        }

        let chunk = chunk_result.map_err(|e| CliDownloadError::DownloadFailed(e.to_string()))?;
        downloaded += chunk.len() as u64;
        data.extend_from_slice(&chunk);

        if let Some(cb) = progress_callback {
            cb(DownloadProgress {
                downloaded,
                total: total_size,
                status: format!("Downloading... {:.1} MB", downloaded as f64 / 1_000_000.0),
            });
        }
    }

    Ok(data)
}

/// Verify SHA256 checksum of downloaded data
pub(super) fn verify_checksum(data: &[u8], expected: &str) -> CliDownloadResult<()> {
    use ring::digest::{Context, SHA256};

    let mut context = Context::new(&SHA256);
    context.update(data);
    let digest = context.finish();
    let actual = hex::encode(digest.as_ref());

    if actual != expected {
        return Err(CliDownloadError::ChecksumMismatch {
            expected: expected.to_string(),
            actual,
        });
    }

    Ok(())
}

/// Enforce a component's [`ChecksumPolicy`] against freshly downloaded bytes.
///
/// This is the single decision point that `install.rs`, `install_cloud.rs` and
/// the custom (`install_custom.rs`) installers all funnel through, so every
/// download path treats checksums identically:
/// - `Static` → verified against the pinned SHA256 (hard failure on mismatch),
/// - `SkipLatest` → allowed, but logged with a `warn!` so the skip is visible
///   in the logs rather than silent (these are "latest" URLs with no stable
///   published hash to pin against),
/// - `None` → refused ([`CliDownloadError::NoChecksum`]).
///
/// The custom installers previously never consulted the policy at all, so the
/// module's "all downloads are verified" claim was false for kubectl, tsh,
/// tailscale, boundary and hoop; routing them here fixes that.
pub(super) fn enforce_checksum_policy(
    policy: ChecksumPolicy,
    component_name: &str,
    bytes: &[u8],
) -> CliDownloadResult<()> {
    match policy {
        ChecksumPolicy::Static(expected) => verify_checksum(bytes, expected),
        ChecksumPolicy::SkipLatest => {
            tracing::warn!(
                "Skipping checksum for {component_name} (latest URL, no stable hash) — \
                 the download is not integrity-verified"
            );
            Ok(())
        }
        ChecksumPolicy::None => Err(CliDownloadError::NoChecksum),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SHA256 of the ASCII bytes "hello" — precomputed, so a Static policy over
    // exactly this input must verify and any other hash must be a mismatch.
    const HELLO_SHA256: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    #[test]
    fn verify_checksum_accepts_matching_hash() {
        assert!(verify_checksum(b"hello", HELLO_SHA256).is_ok());
    }

    #[test]
    fn verify_checksum_rejects_wrong_hash() {
        // A mismatch (different bytes, same expected hash) must fail.
        assert!(matches!(
            verify_checksum(b"goodbye", HELLO_SHA256),
            Err(CliDownloadError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn enforce_static_policy_verifies() {
        assert!(
            enforce_checksum_policy(ChecksumPolicy::Static(HELLO_SHA256), "test", b"hello").is_ok()
        );
        assert!(matches!(
            enforce_checksum_policy(ChecksumPolicy::Static(HELLO_SHA256), "test", b"tampered"),
            Err(CliDownloadError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn enforce_skip_latest_allows_any_bytes() {
        // SkipLatest is not integrity-verified: it must succeed regardless of
        // content (the warning is a side effect we don't assert here).
        assert!(enforce_checksum_policy(ChecksumPolicy::SkipLatest, "test", b"anything").is_ok());
    }

    #[test]
    fn enforce_none_policy_refuses() {
        assert!(matches!(
            enforce_checksum_policy(ChecksumPolicy::None, "test", b"anything"),
            Err(CliDownloadError::NoChecksum)
        ));
    }
}
