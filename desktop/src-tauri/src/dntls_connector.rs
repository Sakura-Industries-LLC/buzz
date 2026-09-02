use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use tauri::State;
use url::{Host, Url};

const DEFAULT_CONNECTOR: &str = "dntls-demo-buzz";
const CONNECTOR_ENV: &str = "DNTLS_DEMO_BUZZ_CONNECTOR";
const START_TIMEOUT: Duration = Duration::from_secs(30);

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
    community: String,
    state: State<'_, DntlsConnectors>,
) -> Result<ConnectorReady, String> {
    let community = normalize_dntls_name(&community)?;
    let children = Arc::clone(&state.children);
    tauri::async_runtime::spawn_blocking(move || start_connector(children, community))
        .await
        .map_err(|error| format!("DNTLS connector task failed: {error}"))?
}

/// Starts one connector while serializing duplicate requests for the same name.
fn start_connector(
    children: Arc<Mutex<HashMap<String, RunningConnector>>>,
    community: String,
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

    let executable = std::env::var_os(CONNECTOR_ENV).unwrap_or_else(|| DEFAULT_CONNECTOR.into());
    let mut command = Command::new(executable);
    command
        .arg("connect")
        .arg(&community)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    crate::util::configure_no_window(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start {DEFAULT_CONNECTOR}: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "DNTLS connector did not expose its startup response".to_string())?;
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
            return Err(error);
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

/// Normalizes one exact DNTLS FQDN and rejects URLs or partial names.
fn normalize_dntls_name(raw: &str) -> Result<String, String> {
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
}
