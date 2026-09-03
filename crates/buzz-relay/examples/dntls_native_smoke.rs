//! Smoke test for the relay's native DNTLS listener.
//!
//! Dials `ADDR` with the DNTLS SDK client configuration built from a
//! Portal-exported credential bundle, verifies the relay identifies as
//! `COMMUNITY`, fetches the NIP-11 document over the authenticated
//! connection, then opens a WebSocket on a second connection and completes
//! NIP-42 AUTH with a fresh Nostr key signed for `wss://COMMUNITY`. With
//! `BUZZ_DNTLS_ADMISSION=auto` the relay binds that key to the bundle's name
//! and admits it; the relay log and `dntls_applications` show the binding.
//!
//! ```sh
//! cargo run -p buzz-relay --example dntls_native_smoke -- \
//!     127.0.0.1:3443 buzz.dntls ~/newcomer.bundle /tmp/smoke-data
//! ```

use std::sync::Arc;

use dntls_sdk::{identity, resolver, tls};
use futures_util::{SinkExt, StreamExt};
use nostr::{EventBuilder, JsonUtil, Keys, RelayUrl};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let [_, addr, community, bundle, data_dir] = args.as_slice() else {
        anyhow::bail!("usage: dntls_native_smoke ADDR COMMUNITY BUNDLE DATA_DIR");
    };

    let credentials = identity::decode_credentials(&std::fs::read(bundle)?)?;
    let endpoint = credentials.resolver_endpoint("")?;
    let store = identity::Store::open(Some(data_dir.into()))?;
    let resolver = resolver::Client::new(
        &endpoint.url,
        [
            resolver::with_pins(store.pins()),
            resolver::with_trusted_service_key(endpoint.service_public_key),
        ],
    )?;
    println!("caller identity: {}", credentials.fqdn());
    let handshaker = tls::new(tls::Config {
        credentials: Some(credentials),
        resolver: Some(Arc::new(resolver)),
        validity: time::Duration::ZERO,
        next_protos: vec!["http/1.1".into()],
    })?;
    let connector = TlsConnector::from(handshaker.client_config());
    let placeholder = ServerName::try_from("localhost")?.to_owned();

    // 1. NIP-11 over the authenticated connection.
    let tcp = TcpStream::connect(addr.as_str()).await?;
    let mut stream = connector.connect(placeholder.clone(), tcp).await?;
    let server = handshaker
        .identity(stream.get_ref().1.peer_certificates().unwrap_or(&[]))
        .ok_or_else(|| anyhow::anyhow!("relay presented no identity"))?;
    println!(
        "relay identity: {} (verified={})",
        server.fqdn, server.verified
    );
    anyhow::ensure!(
        server.fqdn.eq_ignore_ascii_case(community),
        "relay identified as {} not {community}",
        server.fqdn
    );
    stream
        .write_all(
            format!(
                "GET / HTTP/1.1\r\nHost: 127.0.0.1:9\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await?;
    let text = String::from_utf8_lossy(&body);
    let (head, json) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("no HTTP body"))?;
    println!("NIP-11 status line: {}", head.lines().next().unwrap_or(""));
    let doc: serde_json::Value = serde_json::from_str(json.trim())?;
    println!(
        "NIP-11 name={} self={} supported_extensions={}",
        doc["name"], doc["self"], doc["supported_extensions"]
    );

    // 2. NIP-42 AUTH over WebSocket on a second authenticated connection.
    let tcp = TcpStream::connect(addr.as_str()).await?;
    let stream = connector.connect(placeholder, tcp).await?;
    let request = tokio_tungstenite::tungstenite::http::Request::builder()
        .uri(format!("wss://{community}/"))
        .header("Host", community.as_str())
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tokio_tungstenite::tungstenite::handshake::client::generate_key(),
        )
        .body(())?;
    let (mut ws, _) = tokio_tungstenite::client_async(request, stream).await?;
    let keys = Keys::generate();
    println!("nostr pubkey: {}", keys.public_key().to_hex());
    let relay_url: RelayUrl = format!("wss://{community}").parse()?;
    loop {
        let Some(frame) = ws.next().await else {
            anyhow::bail!("relay closed before AUTH completed");
        };
        let Message::Text(text) = frame? else {
            continue;
        };
        println!("<- {text}");
        let value: serde_json::Value = serde_json::from_str(&text)?;
        match value[0].as_str() {
            Some("AUTH") => {
                let challenge = value[1]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("AUTH without challenge"))?;
                let event =
                    EventBuilder::auth(challenge, relay_url.clone()).sign_with_keys(&keys)?;
                let msg = format!("[\"AUTH\",{}]", event.as_json());
                println!("-> {msg}");
                ws.send(Message::Text(msg.into())).await?;
            }
            Some("OK") => {
                anyhow::ensure!(value[2].as_bool() == Some(true), "AUTH rejected: {text}");
                println!(
                    "AUTH accepted as {} via DNTLS mutual TLS",
                    keys.public_key().to_hex()
                );
                break;
            }
            _ => {}
        }
    }
    ws.close(None).await.ok();
    Ok(())
}
