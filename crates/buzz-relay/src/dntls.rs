//! Native DNTLS mutual TLS for the relay's main listener.
//!
//! When `BUZZ_DNTLS_CREDENTIALS` is set, the main listener terminates
//! identity-authenticated TLS 1.3 with the DNTLS SDK instead of speaking
//! plain TCP behind a gateway. The relay presents the community name's own
//! credentials, and every caller must present a DNTLS identity that the
//! network verifies during the handshake; anonymous callers never reach HTTP.
//!
//! The verified caller name is the connection's [`DntlsPeer`]. Admission
//! (`api::dntls`) reads it from the internal `x-dntls-name` header, which
//! [`stamp_identity`] writes from the connection info after deleting any
//! inbound copy. The middleware runs on every listener, so nothing outside
//! this process can supply that header.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::connect_info::Connected;
use axum::extract::{ConnectInfo, Request};
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use axum::serve::{IncomingStream, Listener};
use dntls_sdk::tls::ClientIdentityMode;
use dntls_sdk::{identity, resolver, tls};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::config::DntlsTlsConfig;

/// Internal header carrying the verified caller name from the listener to
/// admission. Written only by [`stamp_identity`].
pub const NAME_HEADER: &str = "x-dntls-name";

/// Accepted-but-not-yet-served connections buffered between the TLS accept
/// loop and Axum's serve loop.
const READY_BACKLOG: usize = 64;

/// Connection info for one DNTLS-authenticated connection.
#[derive(Clone, Debug)]
pub struct DntlsPeer {
    /// Remote TCP address.
    pub addr: SocketAddr,
    /// Network-verified caller name, lowercased.
    pub name: String,
}

impl Connected<IncomingStream<'_, DntlsListener>> for DntlsPeer {
    fn connect_info(stream: IncomingStream<'_, DntlsListener>) -> Self {
        stream.remote_addr().clone()
    }
}

/// Axum listener that yields DNTLS-authenticated connections.
///
/// A background task accepts TCP connections and completes each handshake on
/// its own task, so a slow or failing caller never blocks the others. Live
/// identity verification runs inside the rustls verifier and briefly blocks
/// the worker thread driving that handshake; fine at demo scale.
pub struct DntlsListener {
    local: SocketAddr,
    ready: mpsc::Receiver<(TlsStream<TcpStream>, DntlsPeer)>,
}

impl DntlsListener {
    /// Builds the SDK handshaker from `cfg` and starts accepting on `tcp`.
    pub fn start(cfg: &DntlsTlsConfig, tcp: TcpListener) -> anyhow::Result<Self> {
        let local = tcp.local_addr()?;
        let handshaker = handshaker(cfg)?;
        let acceptor =
            TlsAcceptor::from(handshaker.server_config(ClientIdentityMode::RequireIdentity)?);
        let (tx, ready) = mpsc::channel(READY_BACKLOG);
        tokio::spawn(accept_loop(tcp, acceptor, handshaker, tx));
        Ok(Self { local, ready })
    }
}

impl Listener for DntlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = DntlsPeer;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(conn) => conn,
            None => {
                // The accept loop only exits on a listener error it already
                // logged; keep Axum's serve loop alive until shutdown.
                std::future::pending().await
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(DntlsPeer {
            addr: self.local,
            name: String::new(),
        })
    }
}

/// Loads the credential bundle and builds a handshaker whose resolver is the
/// bundle's first trusted endpoint.
fn handshaker(cfg: &DntlsTlsConfig) -> anyhow::Result<tls::Handshaker> {
    let bundle = std::fs::read(&cfg.credentials_path)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", cfg.credentials_path.display()))?;
    let credentials = identity::decode_credentials(&bundle)
        .map_err(|e| anyhow::anyhow!("decode DNTLS credentials: {e}"))?;
    let endpoint = credentials
        .resolver_endpoint("")
        .map_err(|e| anyhow::anyhow!("select DNTLS resolver: {e}"))?;
    let store = identity::Store::open(cfg.data_dir.clone())
        .map_err(|e| anyhow::anyhow!("open DNTLS data dir: {e}"))?;
    let resolver = resolver::Client::new(
        &endpoint.url,
        [
            resolver::with_pins(store.pins()),
            resolver::with_trusted_service_key(endpoint.service_public_key),
        ],
    )
    .map_err(|e| anyhow::anyhow!("create DNTLS resolver client: {e}"))?;
    info!(
        name = credentials.fqdn(),
        resolver = %endpoint.url,
        "DNTLS identity loaded for the main listener"
    );
    tls::new(tls::Config {
        credentials: Some(credentials),
        resolver: Some(Arc::new(resolver)),
        validity: time::Duration::ZERO,
        next_protos: vec!["http/1.1".to_string()],
    })
    .map_err(|e| anyhow::anyhow!("create DNTLS handshaker: {e}"))
}

async fn accept_loop(
    tcp: TcpListener,
    acceptor: TlsAcceptor,
    handshaker: tls::Handshaker,
    tx: mpsc::Sender<(TlsStream<TcpStream>, DntlsPeer)>,
) {
    loop {
        let (stream, addr) = match tcp.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                warn!(error = %e, "DNTLS listener accept failed; stopping");
                return;
            }
        };
        let acceptor = acceptor.clone();
        let handshaker = handshaker.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    warn!(addr = %addr, error = %e, "DNTLS handshake refused");
                    return;
                }
            };
            let certs = stream.get_ref().1.peer_certificates().unwrap_or(&[]);
            let Some(caller) = handshaker.identity(certs) else {
                warn!(addr = %addr, "DNTLS handshake completed without a caller identity");
                return;
            };
            let peer = DntlsPeer {
                addr,
                name: caller.fqdn.to_ascii_lowercase(),
            };
            info!(addr = %addr, name = %peer.name, "DNTLS caller verified");
            if tx.send((stream, peer)).await.is_err() {
                warn!(addr = %addr, "DNTLS listener closed before the connection was served");
            }
        });
    }
}

/// Deletes any inbound `x-dntls-name` and, on a DNTLS-authenticated
/// connection, writes the verified name and the plain socket address the rest
/// of the relay expects in `ConnectInfo<SocketAddr>`.
pub async fn stamp_identity(mut req: Request, next: Next) -> Response {
    req.headers_mut().remove(NAME_HEADER);
    if let Some(ConnectInfo(peer)) = req.extensions().get::<ConnectInfo<DntlsPeer>>().cloned() {
        req.extensions_mut().insert(ConnectInfo(peer.addr));
        if let Ok(value) = HeaderValue::from_str(&peer.name) {
            req.headers_mut().insert(NAME_HEADER, value);
        }
    }
    next.run(req).await
}
