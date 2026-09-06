//! DNTLS identity for this Buzz installation.
//!
//! Buzz obtains the user's credential bundle from the DNTLS Local Trust
//! Resolver over its local program API: it lists the names stored on this
//! machine, the user picks one, and the resolver's own prompt lets the user
//! give Buzz either that name's key or a Buzz-owned subname under it. The
//! returned bundle is stored at `<app-data>/dntls/credentials.bundle` (mode
//! `0600`) and presented by the community connector on every relay
//! connection. Every resolver call is subject to the resolver's consent
//! prompts and to program identification (see `dntls_attest`).

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tauri::{AppHandle, Manager, State};

use dntls_sdk::identity;
use dntls_sdk::local::{self, Classification, ExportRequest, Scope};

use crate::dntls_attest;
use crate::dntls_connector::DntlsConnectors;

const CREDENTIALS_FILE: &str = "credentials.bundle";
const DATA_DIR_NAME: &str = "data";
/// Subname label proposed to the resolver; the user may edit it on the prompt.
const SUBNAME_LABEL: &str = "buzz";
/// Longest wait for the user to answer a resolver prompt.
const PROMPT_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Stored DNTLS identity shown in settings and used before connector start.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct DntlsCredentialsStatus {
    /// Verified FQDN from the stored credentials file, if one is present.
    pub name: Option<String>,
}

/// Whether the Local Trust Resolver can serve Buzz right now.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct DntlsResolverStatus {
    /// `ready`, `no_identity` (resolver runs but has no active name), or
    /// `unavailable` (socket absent or not answering).
    pub state: &'static str,
    /// Whether this Buzz build carries a program attestation marker.
    pub attested: bool,
    /// Socket path Buzz dials, for troubleshooting copy.
    pub socket: String,
}

/// One name the resolver stores on this machine.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct DntlsIdentity {
    /// Resolver store key; pass back to `bind_dntls_identity`.
    pub name: String,
    /// Full name to display.
    pub fqdn: String,
    /// Whether the resolver holds this name's private key (required to export).
    pub has_private_identity: bool,
    /// Whether this is the resolver's active name.
    pub active: bool,
}

/// Outcome of binding Buzz to a name.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct DntlsBound {
    /// FQDN the stored bundle carries: the chosen name or a subname under it.
    pub name: String,
    /// `root` or `subname`, whichever key the user gave.
    pub scope: String,
}

/// Failure the webview can branch on.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct DntlsError {
    /// Stable code: `resolver_unavailable`, `not_attested`, `unverified`,
    /// `denied`, `no_identity`, `timeout`, or the resolver's own code.
    pub code: String,
    /// Human-readable detail.
    pub message: String,
}

impl DntlsError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }
}

impl From<String> for DntlsError {
    fn from(message: String) -> Self {
        Self::new("unavailable", message)
    }
}

impl From<local::Error> for DntlsError {
    fn from(error: local::Error) -> Self {
        let code = match error.classification() {
            Some(Classification::Unverified) => "unverified",
            Some(Classification::Denied) => "denied",
            Some(Classification::NoIdentity) => "no_identity",
            Some(Classification::UnknownIdentity) => "unknown_identity",
            Some(Classification::LabelTaken) => "label_taken",
            Some(Classification::Pending) => "pending",
            Some(Classification::PortalUnavailable) => "portal_unavailable",
            Some(Classification::NetworkUnavailable) => "network_unavailable",
            Some(Classification::NotFound) => "not_found",
            Some(Classification::InvalidRequest) => "invalid_request",
            Some(_) | None => "unavailable",
        };
        Self::new(code, error.to_string())
    }
}

/// App-data directory that holds the credentials file and resolver pins.
pub(crate) fn dntls_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("app data dir: {error}"))?
        .join("dntls");
    std::fs::create_dir_all(&dir).map_err(|error| format!("create DNTLS data dir: {error}"))?;
    Ok(dir)
}

/// Path of the stored credentials bundle.
pub(crate) fn credentials_bundle_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(dntls_dir(app)?.join(CREDENTIALS_FILE))
}

/// Connector data directory used for resolver pins.
pub(crate) fn credentials_data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = dntls_dir(app)?.join(DATA_DIR_NAME);
    std::fs::create_dir_all(&dir).map_err(|error| format!("create DNTLS pin dir: {error}"))?;
    Ok(dir)
}

/// Returns the stored identity name, or `name: None` when no file is present.
#[tauri::command]
pub(crate) fn dntls_credentials_status(app: AppHandle) -> Result<DntlsCredentialsStatus, String> {
    let path = credentials_bundle_path(&app)?;
    if !path.is_file() {
        return Ok(DntlsCredentialsStatus { name: None });
    }
    let name = credentials_name_from_path(&path)?;
    Ok(DntlsCredentialsStatus { name: Some(name) })
}

/// Probes the resolver's public trust-root route: no consent, no attestation.
#[tauri::command]
pub(crate) async fn dntls_resolver_status() -> Result<DntlsResolverStatus, DntlsError> {
    let client = local::Client::open(None).map_err(DntlsError::from)?;
    let socket = client.socket().display().to_string();
    let attested = dntls_attest::attested();
    if !client.socket().exists() {
        return Ok(DntlsResolverStatus {
            state: "unavailable",
            attested,
            socket,
        });
    }
    let state = match client.trust_root().await {
        Ok(_) => "ready",
        Err(error) if error.classification() == Some(Classification::NoIdentity) => "no_identity",
        Err(_) => "unavailable",
    };
    Ok(DntlsResolverStatus {
        state,
        attested,
        socket,
    })
}

/// Lists the names stored by the resolver. The resolver prompts the user
/// unless a remembered grant applies.
#[tauri::command]
pub(crate) async fn list_dntls_identities() -> Result<Vec<DntlsIdentity>, DntlsError> {
    let client = admitted_client()?;
    let identities = tokio::time::timeout(PROMPT_TIMEOUT, client.identities())
        .await
        .map_err(|_| DntlsError::new("timeout", "the resolver prompt was not answered"))??;
    Ok(identities
        .into_iter()
        .map(|identity| DntlsIdentity {
            name: identity.name,
            fqdn: identity.fqdn,
            has_private_identity: identity.has_private_identity,
            active: identity.active,
        })
        .collect())
}

/// Asks the resolver for a key under `name` and stores the returned bundle.
///
/// The resolver prompt offers the name's own key or a Buzz subname
/// (proposed label `buzz`, editable). Running connectors are dropped so the
/// next community start presents the new identity.
#[tauri::command]
pub(crate) async fn bind_dntls_identity(
    app: AppHandle,
    name: String,
    connectors: State<'_, DntlsConnectors>,
) -> Result<DntlsBound, DntlsError> {
    let client = admitted_client()?;
    let request = ExportRequest {
        identity: Some(name.clone()),
        scope: Some(Scope::Any),
        label: Some(SUBNAME_LABEL.to_string()),
        wait: true,
    };
    let export = tokio::time::timeout(PROMPT_TIMEOUT, client.export(request))
        .await
        .map_err(|_| DntlsError::new("timeout", "the resolver prompt was not answered"))??;
    let fqdn = export.credentials.fqdn().to_string();
    if fqdn != export.identity {
        return Err(DntlsError::new(
            "invalid_bundle",
            format!(
                "the resolver returned a bundle for {fqdn} while naming {}",
                export.identity
            ),
        ));
    }
    let dest = credentials_bundle_path(&app)?;
    write_restricted(&dest, &export.bundle)?;
    connectors.reset();
    Ok(DntlsBound {
        name: fqdn,
        scope: export.scope.to_string(),
    })
}

/// Deletes the stored credentials file and drops running connectors.
/// Resolver pin data is left in place.
#[tauri::command]
pub(crate) fn remove_dntls_credentials(
    app: AppHandle,
    connectors: State<'_, DntlsConnectors>,
) -> Result<(), String> {
    let path = credentials_bundle_path(&app)?;
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("could not remove DNTLS credentials: {error}")),
    }
    connectors.reset();
    Ok(())
}

/// Client for routes that require program identification.
fn admitted_client() -> Result<local::Client, DntlsError> {
    if !dntls_attest::attested() {
        return Err(DntlsError::new(
            "not_attested",
            "this Buzz build carries no DNTLS program attestation",
        ));
    }
    let client = local::Client::open(None)?;
    if !client.socket().exists() {
        return Err(DntlsError::new(
            "resolver_unavailable",
            format!(
                "the DNTLS Local Trust Resolver is not running (no socket at {})",
                client.socket().display()
            ),
        ));
    }
    Ok(client)
}

fn credentials_name_from_path(path: &Path) -> Result<String, String> {
    let data = std::fs::read(path).map_err(|error| {
        format!(
            "could not read stored credentials {}: {error}",
            path.display()
        )
    })?;
    credentials_fqdn(&data)
}

/// Reads the selected identity FQDN from a stored credentials bundle.
pub(crate) fn credentials_fqdn(data: &[u8]) -> Result<String, String> {
    let credentials = identity::decode_credentials(data)
        .map_err(|error| format!("stored credentials are not a DNTLS bundle: {error}"))?;
    Ok(credentials.fqdn().to_string())
}

fn write_restricted(path: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create credentials dir: {error}"))?;
    }
    let tmp = path.with_extension("bundle.tmp");
    {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .map_err(|error| format!("open credentials temp file: {error}"))?;
        file.write_all(data)
            .map_err(|error| format!("write credentials: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync credentials: {error}"))?;
    }
    std::fs::rename(&tmp, path).map_err(|error| format!("install credentials: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("set credentials permissions: {error}"))?;
    }
    Ok(())
}
