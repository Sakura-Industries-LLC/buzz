//! Exercise the production loopback connector with the SDK's synthetic identity.
//! A persistent fixture resolver runs independently, while the warmed HTTP
//! client's I/O remains on the application's two-worker runtime.

use super::*;
use base64::Engine as _;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Barrier;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

const COMMUNITY: &str = "relay.dntls";
const CONNECTIONS: usize = 8;

#[derive(Debug)]
struct FixtureCertificate(Arc<CertifiedKey>);

impl ResolvesServerCert for FixtureCertificate {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// Owns the remote resolver's independent runtime and its verification counts.
struct FixtureResolver {
    addr: SocketAddr,
    requests: Arc<AtomicUsize>,
    warmed_requests: Arc<AtomicUsize>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for FixtureResolver {
    fn drop(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.thread.take().unwrap().join().unwrap();
    }
}

/// Serve the SDK fixture's record through a real pinned HTTPS resolver client.
fn fixture_resolver(
    fixture: &identity::identitytest::Fixture,
    certificate: identity::TlsCertificate,
) -> FixtureResolver {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(FixtureCertificate(certificate.certified_key())));
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    // Same public projection as SDK tests/tls_concurrent_verify.rs.
    let record = serde_json::json!({
        "root_hash": base64::engine::general_purpose::STANDARD.encode(&fixture.hash),
        "record": {
            "service_key": base64::engine::general_purpose::STANDARD.encode(&fixture.service_public_key),
            "fields": {}
        }
    })
    .to_string();
    let requests = Arc::new(AtomicUsize::new(0));
    let warmed_requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let warm_count = warmed_requests.clone();
    let (stop, mut stopped) = tokio::sync::oneshot::channel();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = TcpListener::from_std(listener).unwrap();
            let mut handlers = JoinSet::new();
            let overlap = Arc::new(Barrier::new(2));
            let mut first = true;
            loop {
                let (tcp, _) = tokio::select! {
                    _ = &mut stopped => break,
                    accepted = listener.accept() => accepted.unwrap(),
                    Some(result) = handlers.join_next(), if !handlers.is_empty() => {
                        result.unwrap();
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let record = record.clone();
                let count = count.clone();
                let warm_count = warm_count.clone();
                let overlap = overlap.clone();
                let warmed = first;
                first = false;
                handlers.spawn(async move {
                    let stream = acceptor.accept(tcp).await.unwrap();
                    let mut stream = BufReader::new(stream);
                    loop {
                        let mut line = String::new();
                        if stream.read_line(&mut line).await.unwrap() == 0 {
                            break;
                        }
                        assert_eq!(line, "POST /v1/resolve-record HTTP/1.1\r\n");
                        let mut length = 0;
                        loop {
                            line.clear();
                            assert_ne!(stream.read_line(&mut line).await.unwrap(), 0);
                            if line == "\r\n" {
                                break;
                            }
                            if let Some((name, value)) = line.split_once(':') {
                                if name.eq_ignore_ascii_case("content-length") {
                                    length = value.trim().parse::<usize>().unwrap();
                                }
                            }
                        }
                        let mut body = vec![0; length];
                        stream.read_exact(&mut body).await.unwrap();
                        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        assert_eq!(body["address"], COMMUNITY);
                        let request = count.fetch_add(1, Ordering::SeqCst);
                        if warmed {
                            warm_count.fetch_add(1, Ordering::SeqCst);
                        }
                        // Do not answer either of the first two certificate
                        // checks until both arrive. Request zero is discovery.
                        if matches!(request, 1 | 2) {
                            overlap.wait().await;
                        }
                        stream.write_all(format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{record}",
                            record.len()
                        ).as_bytes()).await.unwrap();
                        stream.flush().await.unwrap();
                    }
                });
            }
        });
    });
    FixtureResolver {
        addr,
        requests,
        warmed_requests,
        stop: Some(stop),
        thread: Some(thread),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn eight_loopback_connections_verify_on_two_workers() {
    let fixture = identity::identitytest::new(COMMUNITY, "").unwrap();
    let credentials = identity::decode_credentials(&fixture.bundle).unwrap();
    let certificate = credentials
        .tls_certificate(None, time::Duration::ZERO)
        .unwrap();
    let mut servers = JoinSet::new();
    let remote_resolver = fixture_resolver(&fixture, certificate);
    let data = tempfile::tempdir().unwrap();
    let store = identity::Store::open(Some(data.path().to_path_buf())).unwrap();
    let resolver = Arc::new(
        resolver::Client::new(
            format!("https://{}", remote_resolver.addr),
            [
                resolver::with_pins(store.pins()),
                resolver::with_trusted_service_key(fixture.service_public_key.clone()),
            ],
        )
        .unwrap(),
    );
    // Start resolver I/O on the application's runtime, as discovery does.
    resolver.resolve_record(COMMUNITY).await.unwrap();
    let handshaker = tls::new(tls::Config {
        credentials: Some(credentials),
        resolver: Some(resolver),
        validity: time::Duration::ZERO,
        next_protos: vec!["http/1.1".to_string()],
    })
    .unwrap();
    let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let server_handshaker = handshaker.clone();
    let relay_task = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(
            server_handshaker
                .server_config(tls::ClientIdentityMode::RequireIdentity)
                .unwrap(),
        );
        let mut connections = JoinSet::new();
        for _ in 0..CONNECTIONS {
            let (tcp, _) = relay.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let handshaker = server_handshaker.clone();
            connections.spawn(async move {
                // The relay must not introduce the client's starvation bug.
                let runtime = tokio::runtime::Handle::current();
                let mut stream =
                    tokio::task::spawn_blocking(move || runtime.block_on(acceptor.accept(tcp)))
                        .await
                        .unwrap()
                        .unwrap();
                let caller = handshaker
                    .identity(stream.get_ref().1.peer_certificates().unwrap())
                    .unwrap();
                assert!(caller.verified);
                assert_eq!(caller.fqdn, COMMUNITY);
                let mut request = [0; 1];
                stream.read_exact(&mut request).await.unwrap();
                stream.write_all(&[request[0] + 1]).await.unwrap();
                stream.shutdown().await.unwrap();
            });
        }
        let mut verified = 0;
        while let Some(result) = connections.join_next().await {
            result.unwrap();
            verified += 1;
        }
        verified
    });
    let app = tauri::test::mock_builder()
        .manage(DntlsConnectors::default())
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    servers.spawn(accept_loop(
        app.handle().clone(),
        listener,
        COMMUNITY.to_string(),
        data.path().join("credentials.bundle"),
        data.path().to_path_buf(),
        Some(Verified {
            addr: relay_addr,
            handshaker,
        }),
    ));
    let barrier = Arc::new(Barrier::new(CONNECTIONS));
    let mut clients = JoinSet::new();
    for index in 0..CONNECTIONS {
        let barrier = barrier.clone();
        clients.spawn(async move {
            let mut stream = TcpStream::connect(local_addr).await.unwrap();
            barrier.wait().await;
            stream.write_all(&[index as u8]).await.unwrap();
            let mut response = [0; 1];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [index as u8 + 1]);
            stream.shutdown().await.unwrap();
        });
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(result) = clients.join_next().await {
            result.unwrap();
        }
        assert_eq!(relay_task.await.unwrap(), CONNECTIONS);
    })
    .await
    .expect("eight verified connector streams must complete without starving two app workers");
    assert_eq!(
        remote_resolver.requests.load(Ordering::SeqCst),
        1 + 2 * CONNECTIONS
    );
    assert!(
        remote_resolver.warmed_requests.load(Ordering::SeqCst) > 1,
        "verification must reuse the HTTP connection warmed on the app runtime"
    );
    servers.abort_all();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_dial_closes_a_pending_handshake() {
    let fixture = identity::identitytest::new(COMMUNITY, "").unwrap();
    let data = tempfile::tempdir().unwrap();
    let store = identity::Store::open(Some(data.path().to_path_buf())).unwrap();
    let resolver =
        resolver::Client::new(&fixture.endpoint, [resolver::with_pins(store.pins())]).unwrap();
    let handshaker = tls::new(tls::Config {
        credentials: Some(identity::decode_credentials(&fixture.bundle).unwrap()),
        resolver: Some(Arc::new(resolver)),
        validity: time::Duration::ZERO,
        next_protos: Vec::new(),
    })
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pending = tokio::spawn(async move { dial(COMMUNITY, addr, &handshaker).await });
    let (mut remote, _) = listener.accept().await.unwrap();
    // Observe ClientHello before cancelling, so the blocking worker has started.
    tokio::time::timeout(Duration::from_secs(2), remote.read_u8())
        .await
        .unwrap()
        .unwrap();
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    let mut remaining = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(2), remote.read_to_end(&mut remaining))
        .await
        .expect("cancelling dial must close the socket, not wait for the handshake deadline");
    if let Err(error) = closed {
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    }
}
