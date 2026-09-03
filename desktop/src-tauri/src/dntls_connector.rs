use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, State};
use url::{Host, Url};

use crate::dntls_credentials::{credentials_bundle_path, credentials_data_dir};

const START_TIMEOUT: Duration = Duration::from_secs(30);
const STDERR_TAIL_LINES: usize = 10;
const CONNECTOR_BIN: &str = "dntls-demo-buzz";

/// One running local connector and the URL assigned to its DNTLS community.
struct RunningConnector {
    /// Child process kept alive for the desktop session.
    child: Child,
    /// Verified local relay projection returned by the connector.
    ready: ConnectorReady,
}

/// Desktop-owned connector processes keyed by normalized DNTLS community name.
#[derive(Default)]
pub(crate) struct DntlsConnectors {
    /// Shared process table used by blocking command workers.
    children: Arc<Mutex<HashMap<String, RunningConnector>>>,
}

impl Drop for DntlsConnectors {
    fn drop(&mut self) {
        let Ok(mut children) = self.children.lock() else {
            return;
        };
        for connector in children.values_mut() {
            let _ = connector.child.kill();
            let _ = connector.child.wait();
        }
        children.clear();
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

/// Starts or reuses the local connector for one DNTLS community.
#[tauri::command]
pub(crate) async fn start_dntls_connector(
    app: AppHandle,
    community: String,
    state: State<'_, DntlsConnectors>,
) -> Result<ConnectorReady, String> {
    let community = normalize_dntls_name(&community)?;
    let executable = resolve_connector_executable()?;
    let credentials = credentials_bundle_path(&app)?;
    if !credentials.is_file() {
        return Err(
            "choose a DNTLS credentials file before adding this community".to_string(),
        );
    }
    let data_dir = credentials_data_dir(&app)?;
    let children = Arc::clone(&state.children);
    tauri::async_runtime::spawn_blocking(move || {
        start_connector(children, community, executable, credentials, data_dir)
    })
    .await
    .map_err(|error| format!("DNTLS connector task failed: {error}"))?
}

/// Starts one connector while serializing duplicate requests for the same name.
fn start_connector(
    children: Arc<Mutex<HashMap<String, RunningConnector>>>,
    community: String,
    executable: PathBuf,
    credentials: PathBuf,
    data_dir: PathBuf,
) -> Result<ConnectorReady, String> {
    let mut children = children
        .lock()
        .map_err(|_| "DNTLS connector state is unavailable".to_string())?;
    if let Some(running) = children.get_mut(&community) {
        match running.child.try_wait() {
            Ok(None) => return Ok(running.ready.clone()),
            Ok(Some(_)) | Err(_) => {
                children.remove(&community);
            }
        }
    }

    let mut command = Command::new(&executable);
    command
        .arg("connect")
        .arg(&community)
        .arg("--credentials")
        .arg(&credentials)
        .arg("--data-dir")
        .arg(&data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    crate::util::configure_no_window(&mut command);
    let mut child = command.spawn().map_err(|error| {
        format!(
            "could not start {CONNECTOR_BIN} at {}: {error}",
            executable.display()
        )
    })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "DNTLS connector did not expose its startup response".to_string())?;
    let stderr_tail = match child.stderr.take() {
        Some(stderr) => spawn_stderr_tail(stderr),
        None => Arc::new(Mutex::new(VecDeque::new())),
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout)
            .read_line(&mut line)
            .map(|_| line)
            .map_err(|error| error.to_string());
        let _ = sender.send(result);
    });

    let ready = match receiver.recv_timeout(START_TIMEOUT) {
        Ok(Ok(line)) => serde_json::from_str::<ConnectorReady>(&line)
            .map_err(|error| format!("invalid DNTLS connector response: {error}")),
        Ok(Err(error)) => Err(format!("could not read DNTLS connector response: {error}")),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            Err("DNTLS connector did not become ready within 30 seconds".to_string())
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err("DNTLS connector exited before reporting readiness".to_string())
        }
    };
    let ready = match ready.and_then(|value| validate_ready(&community, value)) {
        Ok(value) => value,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(with_stderr(error, &stderr_tail));
        }
    };
    children.insert(
        community,
        RunningConnector {
            child,
            ready: ready.clone(),
        },
    );
    Ok(ready)
}

/// Resolves the bundled `dntls-demo-buzz` sidecar the same way other desktop
/// binaries are found: next to the app executable, then `src-tauri/binaries/`.
pub(crate) fn resolve_connector_executable() -> Result<PathBuf, String> {
    resolve_connector_executable_from(&connector_candidates())
}

fn connector_candidates() -> Vec<PathBuf> {
    let exe_name = connector_file_name(false);
    let triple_name = connector_file_name(true);
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join(&exe_name));
            candidates.push(parent.join(&triple_name));
        }
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("binaries");
    candidates.push(manifest.join(&triple_name));
    candidates.push(manifest.join(&exe_name));
    candidates
}

fn connector_file_name(with_triple: bool) -> String {
    let mut name = CONNECTOR_BIN.to_string();
    if with_triple {
        name.push('-');
        name.push_str(&host_triple());
    }
    if cfg!(windows) {
        name.push_str(".exe");
    }
    name
}

fn host_triple() -> &'static str {
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        "aarch64-apple-darwin"
    }
    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    {
        "x86_64-apple-darwin"
    }
    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
    {
        "x86_64-unknown-linux-gnu"
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"))]
    {
        "aarch64-unknown-linux-gnu"
    }
    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
    {
        "x86_64-unknown-linux-musl"
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_env = "musl"))]
    {
        "aarch64-unknown-linux-musl"
    }
    #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
    {
        "x86_64-pc-windows-msvc"
    }
    #[cfg(all(target_arch = "aarch64", target_os = "windows"))]
    {
        "aarch64-pc-windows-msvc"
    }
    #[cfg(not(any(
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "linux"),
        all(target_arch = "aarch64", target_os = "linux"),
        all(target_arch = "x86_64", target_os = "windows"),
        all(target_arch = "aarch64", target_os = "windows"),
    )))]
    {
        compile_error!("unsupported host for the dntls-demo-buzz sidecar")
    }
}

fn resolve_connector_executable_from(candidates: &[PathBuf]) -> Result<PathBuf, String> {
    for path in candidates {
        if path.is_file() {
            return Ok(path.clone());
        }
    }
    Err(format!(
        "{CONNECTOR_BIN} is not bundled; run desktop/scripts/fetch-dntls-connector.sh"
    ))
}

fn spawn_stderr_tail(stderr: std::process::ChildStderr) -> Arc<Mutex<VecDeque<String>>> {
    let lines = Arc::new(Mutex::new(VecDeque::new()));
    let captured = Arc::clone(&lines);
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let Ok(mut guard) = captured.lock() else {
                return;
            };
            if guard.len() == STDERR_TAIL_LINES {
                guard.pop_front();
            }
            guard.push_back(line);
        }
    });
    lines
}

fn with_stderr(error: String, lines: &Arc<Mutex<VecDeque<String>>>) -> String {
    match format_stderr_tail(lines) {
        Some(stderr) => format!("{error}\n{stderr}"),
        None => error,
    }
}

fn format_stderr_tail(lines: &Arc<Mutex<VecDeque<String>>>) -> Option<String> {
    let guard = lines.lock().ok()?;
    if guard.is_empty() {
        return None;
    }
    Some(guard.iter().cloned().collect::<Vec<_>>().join("\n"))
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

/// Requires the child response to match the requested name and a loopback URL.
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
    fn resolves_the_first_existing_sidecar_candidate() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing");
        let present = temp.path().join("dntls-demo-buzz-aarch64-apple-darwin");
        std::fs::write(&present, b"#!/bin/sh\n").unwrap();
        let resolved =
            resolve_connector_executable_from(&[missing, present.clone()]).expect("sidecar");
        assert_eq!(resolved, present);
    }

    #[test]
    fn appends_the_last_stderr_lines() {
        let lines = Arc::new(Mutex::new(VecDeque::from([
            "one".to_string(),
            "name not found".to_string(),
        ])));
        assert_eq!(
            with_stderr("could not start connector".to_string(), &lines),
            "could not start connector\none\nname not found"
        );
    }

    #[test]
    fn host_triple_is_a_known_tauri_target() {
        let triple = host_triple();
        assert!(
            triple.contains("apple-darwin")
                || triple.contains("unknown-linux")
                || triple.contains("pc-windows"),
            "{triple}"
        );
    }
}
