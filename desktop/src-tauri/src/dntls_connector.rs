//! In-process DNTLS community connector.
//!
//! A DNTLS community is reached by its registered name alone: the name's
//! verified record lists numeric `buzz_endpoints` and the relay's Nostr key.
//! This module discovers the community with the DNTLS SDK, proves the relay's
//! identity with mutual TLS, and exposes it to the webview and to managed
//! agents as a Tauri-owned loopback listener. Every accepted loopback
//! connection is spliced onto its own DNTLS TLS connection to the relay, so
//! the existing Buzz client keeps speaking plain `ws://127.0.0.1:<port>`
//! while the relay sees the user's DNTLS identity.
//!
//! The relay's DNTLS listener selects the community from the identity it
//! presented, so no HTTP rewriting happens here.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, State};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;
use url::{Host, Url};

use dntls_sdk::portal::{BuzzEndpoint, RecordFields};
use dntls_sdk::{identity, resolver, tls};

use crate::dntls_credentials::{credentials_bundle_path, credentials_data_dir};

const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_ENDPOINTS: usize = 8;
const MAX_NIP11_BYTES: usize = 64 * 1024;
const BUZZ_EXTENSION: &str = "buzz";

/// One verified community and the loopback listener serving it.
struct RunningConnector {
    /// Verified local relay projection returned to the webview.
    ready: ConnectorReady,
    /// Accept loop; aborted when the connector table is dropped.
    task: tauri::async_runtime::JoinHandle<()>,
}

/// Desktop-owned connectors keyed by normalized DNTLS community name.
#[derive(Default)]
pub(crate) struct DntlsConnectors {
    /// Shared connector table.
    running: Arc<Mutex<HashMap<String, RunningConnector>>>,
}

impl Drop for DntlsConnectors {
    fn drop(&mut self) {
        let Ok(mut running) = self.running.lock() else {
            return;
        };
        for connector in running.values() {
            connector.task.abort();
        }
        running.clear();
    }
}

/// Verified connector startup response returned to the webview.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct ConnectorReady {
    /// Normalized DNTLS community authority.
    community: String,
    /// Loopback WebSocket URL used by the existing Buzz client.
    relay_url: String,
}

/// Verified dial target for one community: the endpoint whose DNTLS identity
/// and NIP-11 document both checked out.
#[derive(Clone)]
struct Verified {
    /// Numeric relay address.
    addr: SocketAddr,
    /// SDK handshaker presenting the user's credentials.
    handshaker: tls::Handshaker,
}

/// Starts or reuses the in-process connector for one DNTLS community.
#[tauri::command]
pub(crate) async fn start_dntls_connector(
    app: AppHandle,
    community: String,
    state: State<'_, DntlsConnectors>,
) -> Result<ConnectorReady, String> {
    let community = normalize_dntls_name(&community)?;
    if let Some(ready) = lookup(&state.running, &community)? {
        return Ok(ready);
    }
    let credentials = credentials_bundle_path(&app)?;
    if !credentials.is_file() {
        return Err("choose a DNTLS credentials file before adding this community".to_string());
    }
    let data_dir = credentials_data_dir(&app)?;

    let (resolver, handshaker) = clients(&credentials, data_dir)?;
    let verified = discover(&community, resolver, handshaker).await?;
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .map_err(|error| format!("could not open the DNTLS loopback listener: {error}"))?;
    let local = listener
        .local_addr()
        .map_err(|error| format!("DNTLS loopback listener address: {error}"))?;
    let ready = validate_ready(
        &community,
        ConnectorReady {
            community: community.clone(),
            relay_url: format!("ws://{local}"),
        },
    )?;

    let mut running = state
        .running
        .lock()
        .map_err(|_| "DNTLS connector state is unavailable".to_string())?;
    if let Some(existing) = running.get(&community) {
        // A concurrent start won; serve that listener and drop ours.
        return Ok(existing.ready.clone());
    }
    let task = tauri::async_runtime::spawn(accept_loop(listener, community.clone(), verified));
    running.insert(
        community,
        RunningConnector {
            ready: ready.clone(),
            task,
        },
    );
    Ok(ready)
}

fn lookup(
    running: &Mutex<HashMap<String, RunningConnector>>,
    community: &str,
) -> Result<Option<ConnectorReady>, String> {
    let running = running
        .lock()
        .map_err(|_| "DNTLS connector state is unavailable".to_string())?;
    Ok(running.get(community).map(|c| c.ready.clone()))
}

/// Loads the stored credential bundle and builds the resolver client for
/// record reads plus a handshaker that presents the bundle and verifies
/// relays through that same resolver.
fn clients(
    bundle: &std::path::Path,
    data_dir: std::path::PathBuf,
) -> Result<(Arc<resolver::Client>, tls::Handshaker), String> {
    let data = std::fs::read(bundle).map_err(|error| format!("read DNTLS credentials: {error}"))?;
    let credentials = identity::decode_credentials(&data)
        .map_err(|error| format!("decode DNTLS credentials: {error}"))?;
    let endpoint = credentials
        .resolver_endpoint("")
        .map_err(|error| format!("select DNTLS resolver: {error}"))?;
    let store = identity::Store::open(Some(data_dir))
        .map_err(|error| format!("open DNTLS data dir: {error}"))?;
    let resolver = resolver::Client::new(
        &endpoint.url,
        [
            resolver::with_pins(store.pins()),
            resolver::with_trusted_service_key(endpoint.service_public_key),
        ],
    )
    .map_err(|error| format!("create DNTLS resolver client: {error}"))?;
    let resolver = Arc::new(resolver);
    let handshaker = tls::new(tls::Config {
        credentials: Some(credentials),
        resolver: Some(resolver.clone()),
        validity: time::Duration::ZERO,
        next_protos: vec!["http/1.1".to_string()],
    })
    .map_err(|error| format!("create DNTLS handshaker: {error}"))?;
    Ok((resolver, handshaker))
}

/// Resolves the community's verified record and returns the first endpoint
/// whose relay proves the community identity and advertises Buzz under the
/// record-bound Nostr key.
///
/// `BUZZ_DNTLS_ENDPOINT_OVERRIDE=<ip>:<port>` replaces the record's dial
/// targets, for a relay that is not yet published (local development, a
/// self-hosted relay behind NAT). The name, the relay's identity, and the
/// NIP-11 key binding are verified exactly as before; only routing changes.
async fn discover(
    community: &str,
    resolver: Arc<resolver::Client>,
    handshaker: tls::Handshaker,
) -> Result<Verified, String> {
    let record = resolver
        .resolve_record(community)
        .await
        .map_err(|error| format!("resolve {community}: {error}"))?;
    let (mut endpoints, relay_key) = parse_record(&record)?;
    if let Some(raw) = std::env::var_os("BUZZ_DNTLS_ENDPOINT_OVERRIDE") {
        let addr: SocketAddr = raw
            .to_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| "BUZZ_DNTLS_ENDPOINT_OVERRIDE must be <ip>:<port>".to_string())?;
        endpoints = vec![BuzzEndpoint {
            family: String::new(),
            address: addr.ip().to_string(),
            port: addr.port(),
            priority: 0,
        }];
    }
    let mut failures = Vec::new();
    for endpoint in endpoints {
        let addr = match endpoint.address.parse::<IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, endpoint.effective_port()),
            Err(_) => {
                failures.push(format!(
                    "{}: address is not an IP literal",
                    endpoint.address
                ));
                continue;
            }
        };
        match probe(community, addr, &handshaker, &relay_key).await {
            Ok(()) => {
                return Ok(Verified { addr, handshaker });
            }
            Err(error) => failures.push(format!("{addr}: {error}")),
        }
    }
    Err(format!(
        "no Buzz endpoint for {community} verified: {}",
        failures.join("; ")
    ))
}

/// Validates the public resolve-record projection and returns the endpoints
/// in priority order plus the relay's Nostr key.
fn parse_record(data: &[u8]) -> Result<(Vec<BuzzEndpoint>, String), String> {
    #[derive(Deserialize)]
    struct Response {
        record: Projection,
    }
    #[derive(Deserialize)]
    struct Projection {
        fields: RecordFields,
    }
    let response: Response =
        serde_json::from_slice(data).map_err(|error| format!("decode record: {error}"))?;
    let fields = response.record.fields;
    let mut endpoints = fields.buzz_endpoints.unwrap_or_default();
    if endpoints.is_empty() {
        return Err("record has no Buzz endpoints".to_string());
    }
    if endpoints.len() > MAX_ENDPOINTS {
        return Err(format!(
            "record has more than {MAX_ENDPOINTS} Buzz endpoints"
        ));
    }
    let relay_key = fields
        .nostr
        .map(|binding| binding.public_key)
        .filter(|key| {
            key.len() == 64 && key.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
        .ok_or_else(|| "record has no valid Nostr public key".to_string())?;
    endpoints.sort_by_key(|endpoint| endpoint.priority);
    Ok((endpoints, relay_key))
}

/// Dials one endpoint over DNTLS TLS, requires it to identify as the
/// community, and checks its NIP-11 document.
async fn probe(
    community: &str,
    addr: SocketAddr,
    handshaker: &tls::Handshaker,
    relay_key: &str,
) -> Result<(), String> {
    let mut stream = dial(community, addr, handshaker).await?;
    stream
        .write_all(
            format!(
                "GET / HTTP/1.1\r\nHost: {community}\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .map_err(|error| format!("write NIP-11 request: {error}"))?;
    let mut raw = Vec::new();
    stream
        .take(MAX_NIP11_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .await
        .map_err(|error| format!("read NIP-11 response: {error}"))?;
    if raw.len() > MAX_NIP11_BYTES {
        return Err(format!("NIP-11 response exceeds {MAX_NIP11_BYTES} bytes"));
    }
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "NIP-11 response has no body".to_string())?;
    let status = head.lines().next().unwrap_or("");
    if !status.starts_with("HTTP/1.1 200") {
        return Err(format!("NIP-11 returned {status}"));
    }
    #[derive(Deserialize)]
    struct Nip11 {
        #[serde(default)]
        supported_extensions: Vec<String>,
        #[serde(default, rename = "self")]
        self_key: Option<String>,
    }
    let doc: Nip11 = serde_json::from_str(body.trim())
        .map_err(|error| format!("decode NIP-11 document: {error}"))?;
    if !doc.supported_extensions.iter().any(|e| e == BUZZ_EXTENSION) {
        return Err("NIP-11 does not advertise Buzz capability".to_string());
    }
    if doc.self_key.as_deref() != Some(relay_key) {
        return Err("NIP-11 self does not match the record-bound Nostr key".to_string());
    }
    Ok(())
}

/// Opens one DNTLS TLS connection to `addr` and requires the relay to
/// identify as `community`.
async fn dial(
    community: &str,
    addr: SocketAddr,
    handshaker: &tls::Handshaker,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let connector = TlsConnector::from(handshaker.client_config());
    // SNI is disabled in the SDK configuration; rustls still needs a name.
    let placeholder = ServerName::try_from("localhost")
        .map_err(|error| format!("placeholder server name: {error}"))?
        .to_owned();
    let tcp = tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|error| format!("connect: {error}"))?;
    let stream = tokio::time::timeout(DIAL_TIMEOUT, connector.connect(placeholder, tcp))
        .await
        .map_err(|_| "DNTLS handshake timed out".to_string())?
        .map_err(|error| format!("DNTLS handshake: {error}"))?;
    let remote = handshaker
        .identity(stream.get_ref().1.peer_certificates().unwrap_or(&[]))
        .ok_or_else(|| "relay presented no DNTLS identity".to_string())?;
    if !remote.verified || !remote.fqdn.eq_ignore_ascii_case(community) {
        return Err(format!("connected service identified as {:?}", remote.fqdn));
    }
    Ok(stream)
}

/// Splices each accepted loopback connection onto its own DNTLS TLS
/// connection to the verified relay endpoint.
async fn accept_loop(listener: TcpListener, community: String, verified: Verified) {
    loop {
        let (local, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                eprintln!("buzz-desktop: dntls_connector {community}: accept failed: {error}");
                continue;
            }
        };
        let community = community.clone();
        let verified = verified.clone();
        tauri::async_runtime::spawn(async move {
            let mut local = local;
            let mut remote = match dial(&community, verified.addr, &verified.handshaker).await {
                Ok(stream) => stream,
                Err(error) => {
                    eprintln!(
                        "buzz-desktop: dntls_connector {community}: relay unavailable: {error}"
                    );
                    return;
                }
            };
            // Ordinary disconnects surface here too; nothing to report.
            let _ = tokio::io::copy_bidirectional(&mut local, &mut remote).await;
        });
    }
}

/// Normalizes one exact DNTLS FQDN and rejects URLs or partial names.
pub(crate) fn normalize_dntls_name(raw: &str) -> Result<String, String> {
    let name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if !name.ends_with(".dntls") || name.len() <= ".dntls".len() {
        return Err("enter a complete DNTLS community name ending in .dntls".to_string());
    }
    if name.split('.').any(|label| {
        label.is_empty()
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }) {
        return Err("DNTLS community name is not valid".to_string());
    }
    Ok(name)
}

/// Requires the ready response to match the requested name and a loopback URL.
fn validate_ready(community: &str, ready: ConnectorReady) -> Result<ConnectorReady, String> {
    if ready.community != community {
        return Err("DNTLS connector returned a different community name".to_string());
    }
    let relay = Url::parse(&ready.relay_url)
        .map_err(|_| "DNTLS connector returned an invalid relay URL".to_string())?;
    let loopback = match relay.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(_)) | None => false,
    };
    if relay.scheme() != "ws"
        || !loopback
        || relay.port().is_none()
        || relay.path() != "/"
        || relay.query().is_some()
        || relay.fragment().is_some()
    {
        return Err("DNTLS connector returned a non-loopback relay URL".to_string());
    }
    Ok(ready)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_exact_dntls_names() {
        assert_eq!(
            normalize_dntls_name("Relay.Example.DNTLS.").as_deref(),
            Ok("relay.example.dntls")
        );
        for value in ["dntls", ".dntls", "https://relay.dntls", "-relay.dntls"] {
            assert!(normalize_dntls_name(value).is_err(), "{value}");
        }
    }

    #[test]
    fn accepts_only_matching_loopback_ready_responses() {
        let community = "relay.example.dntls";
        assert!(validate_ready(
            community,
            ConnectorReady {
                community: community.to_string(),
                relay_url: "ws://127.0.0.1:4100".to_string(),
            }
        )
        .is_ok());
        assert!(validate_ready(
            community,
            ConnectorReady {
                community: "other.example.dntls".to_string(),
                relay_url: "ws://127.0.0.1:4100".to_string(),
            }
        )
        .is_err());
        assert!(validate_ready(
            community,
            ConnectorReady {
                community: community.to_string(),
                relay_url: "wss://relay.example.dntls".to_string(),
            }
        )
        .is_err());
    }

    #[test]
    fn parses_record_endpoints_in_priority_order() {
        let key = "ab".repeat(32);
        let data = format!(
            r#"{{"record":{{"fields":{{"buzz_endpoints":[
                {{"family":"ipv4","address":"203.0.113.9","priority":5}},
                {{"family":"ipv4","address":"203.0.113.10","port":8443}}
            ],"nostr":{{"public_key":"{key}","signature":"sig"}}}}}}}}"#
        );
        let (endpoints, relay_key) = parse_record(data.as_bytes()).expect("record");
        assert_eq!(relay_key, key);
        assert_eq!(endpoints[0].address, "203.0.113.10");
        assert_eq!(endpoints[0].effective_port(), 8443);
        assert_eq!(endpoints[1].address, "203.0.113.9");
        assert_eq!(endpoints[1].effective_port(), 443);
    }

    #[test]
    fn rejects_records_without_endpoints_or_relay_key() {
        let key = "ab".repeat(32);
        assert!(parse_record(br#"{"record":{"fields":{}}}"#).is_err());
        let no_key = r#"{"record":{"fields":{"buzz_endpoints":[{"family":"ipv4","address":"203.0.113.9"}]}}}"#;
        assert!(parse_record(no_key.as_bytes()).is_err());
        let bad_key = format!(
            r#"{{"record":{{"fields":{{"buzz_endpoints":[{{"family":"ipv4","address":"203.0.113.9"}}],"nostr":{{"public_key":"{}"}}}}}}}}"#,
            key.to_ascii_uppercase()
        );
        assert!(parse_record(bad_key.as_bytes()).is_err());
    }
}
