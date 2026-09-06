//! DNTLS program attestation carried by the Buzz executable.
//!
//! The Local Trust Resolver identifies a program that calls its local socket
//! API by its code signature plus one attestation marker
//! (`DNTLS-ATTEST-BEGIN…DNTLS-ATTEST-END`) found in the executable's bytes.
//! The marker binds the signing identity (Team ID + signing identifier on
//! macOS) to a DNTLS name whose service key signed it. It is generated with
//! `dntls attest macos` and committed at `desktop/src-tauri/dntls-attest.marker`;
//! re-mint it whenever the signing identity or `buzz.dntls`'s service key
//! changes (the resolver verifies it against the live record). `build.rs`
//! embeds that file, or the `BUZZ_DNTLS_ATTEST` environment variable for
//! development builds signed with a different identity.
//!
//! The marker must appear exactly once in the executable; `#[used]` keeps the
//! static in release builds and nothing else may copy the string.

/// Attestation marker for this build's signing identity; empty when unset.
#[used]
static DNTLS_ATTEST: &str = env!("BUZZ_DESKTOP_BUILD_DNTLS_ATTEST");

/// Whether this build carries an attestation marker at all.
///
/// A build without one is never admitted by the resolver, so callers can
/// explain that up front instead of surfacing a generic refusal.
pub(crate) fn attested() -> bool {
    !DNTLS_ATTEST.is_empty()
}
