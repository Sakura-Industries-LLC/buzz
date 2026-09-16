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
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;
use url::{Host, Url};

use dntls_sdk::portal::{AddressFamily, BuzzEndpoint, RecordFields};
use dntls_sdk::{identity, resolver, tls};

use crate::dntls_credentials::{
    credentials_bundle_path, credentials_data_dir, refresh_credentials, DntlsError,
};

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

/// Desktop-owned connectors keyed by community and credential bundle.
#[derive(Default)]
pub(crate) struct DntlsConnectors {
    /// Shared connector table.
    running: Arc<Mutex<HashMap<(String, PathBuf), RunningConnector>>>,
    /// Serializes identity changes with connector startup and credential refresh.
    pub(crate) operation: tokio::sync::Mutex<()>,
    /// Serializes managed-agent create, replace and remove across Portal requests.
    pub(crate) agent_identity_operation: tokio::sync::Mutex<()>,
}

impl DntlsConnectors {
    /// Aborts every running connector so the next community start presents
    /// the credentials stored at that time.
    pub(crate) fn reset(&self) {
        let Ok(mut running) = self.running.lock() else {
            return;
        };
        for connector in running.values() {
            connector.task.abort();
        }
        running.clear();
    }

    /// Retires only listeners and streams presenting this bundle.
    pub(crate) fn remove_bundle(&self, bundle: &Path) -> Result<(), String> {
        let mut running = self
            .running
            .lock()
            .map_err(|_| "DNTLS connector state is unavailable")?;
        running.retain(|(_, path), connector| {
            if path == bundle {
                connector.task.abort();
                false
            } else {
                true
            }
        });
        Ok(())
    }

    /// Resolves a transport URL without depending on the currently selected community.
    pub(crate) fn community_for_url(&self, relay_url: &str) -> Option<String> {
        let target = Url::parse(relay_url).ok()?;
        self.running.lock().ok()?.values().find_map(|connector| {
            let local = Url::parse(&connector.ready.relay_url).ok()?;
            (local.host_str() == target.host_str() && local.port() == target.port())
                .then(|| connector.ready.community.clone())
        })
    }
}

impl Drop for DntlsConnectors {
    fn drop(&mut self) {
        self.reset();
    }
}

/// Verified connector startup response returned to the webview.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct ConnectorReady {
    /// Normalized DNTLS community authority.
    pub(crate) community: String,
    /// Loopback WebSocket URL used by the existing Buzz client.
    pub(crate) relay_url: String,
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
) -> Result<ConnectorReady, DntlsError> {
    let community = normalize_dntls_name(&community)?;
    let _guard = state.operation.lock().await;
    let bundle = credentials_bundle_path(&app)?;
    let data_dir = credentials_data_dir(&app)?;
    let key = (community.clone(), bundle.clone());
    if let Some(ready) = lookup(&state.running, &key)? {
        return Ok(ready);
    }
    let verified = discover_with_refresh(&bundle, data_dir.clone(), &community).await?;
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
    let task = tauri::async_runtime::spawn(accept_loop(
        app,
        listener,
        community.clone(),
        bundle,
        data_dir,
        Some(verified),
    ));
    running.insert(
        key,
        RunningConnector {
            ready: ready.clone(),
            task,
        },
    );
    Ok(ready)
}

fn lookup(
    running: &Mutex<HashMap<(String, PathBuf), RunningConnector>>,
    key: &(String, PathBuf),
) -> Result<Option<ConnectorReady>, String> {
    let running = running
        .lock()
        .map_err(|_| "DNTLS connector state is unavailable".to_string())?;
    Ok(running.get(key).map(|c| c.ready.clone()))
}

/// Tries the stored identity, refreshing only when its own fresh certificate
/// no longer matches the authenticated network record. Transport failures do
/// not establish staleness and never cause a Portal sign-in.
async fn discover_with_refresh(
    path: &Path,
    data_dir: PathBuf,
    community: &str,
) -> Result<Verified, DntlsError> {
    if !path.is_file() {
        return Err(DntlsError::new(
            "credentials_changed",
            "Connect your DNTLS name before adding this community.",
        ));
    }
    let (resolver, handshaker) = clients(&path, data_dir.clone())?;
    let failure = match discover(community, resolver.clone(), handshaker).await {
        Ok(verified) => return Ok(verified),
        Err(error) => error,
    };
    let data = zeroize::Zeroizing::new(
        std::fs::read(&path).map_err(|error| format!("read DNTLS credentials: {error}"))?,
    );
    let credentials = identity::decode_credentials(&data)
        .map_err(|_| "Stored credentials are not a valid DNTLS bundle.".to_string())?;
    let certificate = credentials
        .tls_certificate(None, time::Duration::ZERO)
        .map_err(|error| error.to_string())?;
    let freshness = identity::verify_certificate(resolver.as_ref(), certificate.der(), None).await;
    if !matches!(&freshness, Err(error) if error.classification() == Some(identity::Classification::CertificateUnverified))
    {
        return Err(failure.into());
    }
    refresh_credentials(&path, &credentials).await?;
    let (resolver, handshaker) = clients(&path, data_dir)?;
    discover(community, resolver, handshaker)
        .await
        .map_err(Into::into)
}

/// Loads the stored credential bundle and builds the resolver client for
/// record reads plus a handshaker that presents the bundle and verifies
/// relays through that same resolver.
fn clients(
    bundle: &std::path::Path,
    data_dir: std::path::PathBuf,
) -> Result<(Arc<resolver::Client>, tls::Handshaker), String> {
    let data = zeroize::Zeroizing::new(
        std::fs::read(bundle).map_err(|error| format!("read DNTLS credentials: {error}"))?,
    );
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
            family: match addr.ip() {
                IpAddr::V4(_) => AddressFamily::Ipv4,
                IpAddr::V6(_) => AddressFamily::Ipv6,
            },
            address: addr.ip().to_string(),
            port: std::num::NonZeroU16::new(addr.port()),
            priority: None,
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
        match tokio::time::timeout(
            DIAL_TIMEOUT,
            probe(community, addr, &handshaker, &relay_key),
        )
        .await
        {
            Ok(Ok(())) => return Ok(Verified { addr, handshaker }),
            Ok(Err(error)) => failures.push(format!("{addr}: {error}")),
            Err(_) => failures.push(format!("{addr}: community response timed out")),
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
async fn accept_loop(
    app: AppHandle,
    listener: TcpListener,
    community: String,
    bundle: PathBuf,
    data_dir: PathBuf,
    verified: Option<Verified>,
) {
    let verified = Arc::new(tokio::sync::RwLock::new(verified));
    // Dropping the accept loop also aborts established streams on Replace/Remove.
    let mut connections = tokio::task::JoinSet::new();
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            Some(_) = connections.join_next(), if !connections.is_empty() => continue,
        };
        let (mut local, _) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                eprintln!("buzz-desktop: dntls_connector {community}: accept failed: {error}");
                continue;
            }
        };
        let app = app.clone();
        let community = community.clone();
        let verified = verified.clone();
        let bundle = bundle.clone();
        let data_dir = data_dir.clone();
        connections.spawn(async move {
            let mut current = verified.read().await.clone();
            if current.is_none() {
                let state = app.state::<DntlsConnectors>();
                let _guard = state.operation.lock().await;
                match discover_with_refresh(&bundle, data_dir.clone(), &community).await {
                    Ok(ready) => {
                        *verified.write().await = Some(ready.clone());
                        current = Some(ready);
                    }
                    Err(error) => {
                        let _ = app.emit("dntls-agent-credentials-error", serde_json::json!({
                            "pubkey": bundle.parent().and_then(|p| p.file_name()).and_then(|p| p.to_str()),
                            "message": error.message,
                        }));
                        return;
                    }
                }
            }
            let current = current.expect("connector discovered above");
            let mut remote = match dial(&community, current.addr, &current.handshaker).await {
                Ok(stream) => stream,
                Err(_) => {
                    let state = app.state::<DntlsConnectors>();
                    let _guard = state.operation.lock().await;
                    let updated = match discover_with_refresh(&bundle, data_dir.clone(), &community).await {
                        Ok(updated) => updated,
                        Err(error) => {
                            if error.code == "credentials_changed" {
                                emit_credentials_changed(&app, &bundle, &error.message);
                            }
                            eprintln!("buzz-desktop: DNTLS connection unavailable: {}", error.code);
                            return;
                        }
                    };
                    let result = dial(&community, updated.addr, &updated.handshaker).await;
                    *verified.write().await = Some(updated);
                    match result {
                        Ok(stream) => stream,
                        Err(_) => return,
                    }
                }
            };
            // TLS 1.3 can report a refused client certificate on the first read,
            // after connect returns. Refresh for the next connection; never replay
            // application bytes that may already have reached the community.
            if tokio::io::copy_bidirectional(&mut local, &mut remote)
                .await
                .is_err()
            {
                let state = app.state::<DntlsConnectors>();
                let _guard = state.operation.lock().await;
                match discover_with_refresh(&bundle, data_dir, &community).await {
                    Ok(updated) => *verified.write().await = Some(updated),
                    Err(error) if error.code == "credentials_changed" => {
                        emit_credentials_changed(&app, &bundle, &error.message);
                    }
                    Err(_) => {}
                }
            }
        });
    }
}

fn emit_credentials_changed(app: &AppHandle, bundle: &Path, message: &str) {
    if credentials_bundle_path(app).ok().as_deref() == Some(bundle) {
        let _ = app.emit("dntls-credentials-changed", ());
    } else {
        let _ = app.emit(
            "dntls-agent-credentials-error",
            serde_json::json!({
                "pubkey": bundle.parent().and_then(|p| p.file_name()).and_then(|p| p.to_str()),
                "message": message,
            }),
        );
    }
}

/// Creates an identity-isolated listener without blocking synchronous spawn paths
/// on network I/O. Discovery and refresh happen before forwarding any bytes.
pub(crate) fn connector_for_agent(
    app: &AppHandle,
    community: &str,
    pubkey: &str,
) -> Result<ConnectorReady, String> {
    let community = normalize_dntls_name(community)?;
    let bundle = crate::dntls_credentials::agent_credentials_bundle_path(app, pubkey)?;
    let data_dir = bundle
        .parent()
        .ok_or("Agent credentials directory is unavailable")?
        .join("data");
    let state = app.state::<DntlsConnectors>();
    let mut running = state
        .running
        .lock()
        .map_err(|_| "DNTLS connector state is unavailable")?;
    if !bundle.is_file() {
        return Err("Connect a name for this agent with a new one-time code.".into());
    }
    let key = (community.clone(), bundle.clone());
    if let Some(connector) = running.get(&key) {
        return Ok(connector.ready.clone());
    }
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let ready = ConnectorReady {
        community: community.clone(),
        relay_url: format!("ws://{}", listener.local_addr().map_err(|e| e.to_string())?),
    };
    let app = app.clone();
    let task = tauri::async_runtime::spawn(async move {
        match TcpListener::from_std(listener) {
            Ok(listener) => accept_loop(app, listener, community, bundle, data_dir, None).await,
            Err(error) => eprintln!("buzz-desktop: agent connector listener failed: {error}"),
        }
    });
    running.insert(
        key,
        RunningConnector {
            ready: ready.clone(),
            task,
        },
    );
    Ok(ready)
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
