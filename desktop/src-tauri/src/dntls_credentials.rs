//! Portal credentials for this Buzz installation.
//!
//! The one-time code is redeemed without signing in. Only the validated bundle
//! is retained, at `<app-data>/dntls/credentials.bundle`, with owner-only access.

use atomic_write_file::AtomicWriteFile;
use dntls_sdk::{identity, portal};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroizing;

use crate::dntls_connector::DntlsConnectors;

const CREDENTIALS_FILE: &str = "credentials.bundle";
const PINS_FILE: &str = "pins.json";
const PORTAL_ORIGIN: &str = "https://preview.dntls.net";

/// Stored identity shown in settings and published as the display name.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct DntlsCredentialsStatus {
    /// Exact FQDN in the bundle, including every subname label.
    pub name: Option<String>,
}

/// Successfully connected identity returned to the webview.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct DntlsConnected {
    pub name: String,
}

/// Public failure the webview can branch on without inspecting error text.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct DntlsError {
    pub code: String,
    pub message: String,
}

impl DntlsError {
    pub(crate) fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }

    pub(crate) fn credentials_changed() -> Self {
        Self::new(
            "credentials_changed",
            "Your name's credentials changed. Export a new one-time code.",
        )
    }
}

impl From<String> for DntlsError {
    fn from(message: String) -> Self {
        Self::new("unavailable", message)
    }
}

impl From<portal::Error> for DntlsError {
    fn from(error: portal::Error) -> Self {
        // Never forward Portal-provided detail: it can echo request secrets.
        match error.classification() {
            Some(
                portal::Classification::CredentialCodeInvalid
                | portal::Classification::InvalidRequest,
            ) => Self::new(
                "credential_code_invalid",
                "That code is not valid. Codes work once and expire; export a new one.",
            ),
            Some(portal::Classification::RateLimited) => {
                Self::new("rate_limited", "Too many attempts, wait a minute.")
            }
            _ => Self::new(
                "unavailable",
                "Could not reach the DNTLS Portal. Please try again.",
            ),
        }
    }
}

/// Portal origin overrides are limited to development builds.
fn portal_origin() -> String {
    #[cfg(debug_assertions)]
    if let Ok(origin) = std::env::var("BUZZ_DNTLS_PORTAL_URL") {
        return origin;
    }
    PORTAL_ORIGIN.to_string()
}

/// App data shared by credential storage and the community connector.
pub(crate) fn dntls_dir<R: tauri::Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("app data dir: {error}"))?
        .join("dntls");
    std::fs::create_dir_all(&dir).map_err(|error| format!("create DNTLS data dir: {error}"))?;
    Ok(dir)
}

pub(crate) fn credentials_bundle_path<R: tauri::Runtime>(
    app: &AppHandle<R>,
) -> Result<PathBuf, String> {
    Ok(dntls_dir(app)?.join(CREDENTIALS_FILE))
}

/// Credential location for one managed agent; no caller-controlled path segments.
pub(crate) fn agent_credentials_bundle_path(
    app: &AppHandle,
    pubkey: &str,
) -> Result<PathBuf, String> {
    if pubkey.len() != 64
        || !pubkey
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("Invalid agent identity.".into());
    }
    Ok(dntls_dir(app)?
        .join("agents")
        .join(pubkey)
        .join(CREDENTIALS_FILE))
}

/// Reads the actual stored identity, rather than trusting UI metadata.
pub(crate) fn agent_name(app: &AppHandle, pubkey: &str) -> Option<String> {
    let bytes =
        Zeroizing::new(std::fs::read(agent_credentials_bundle_path(app, pubkey).ok()?).ok()?);
    credentials_fqdn(&bytes).ok()
}

/// Redeems only an agent subname on the owner's network. The code is never saved.
pub(crate) async fn redeem_agent_credentials(
    app: &AppHandle,
    pubkey: &str,
    code: String,
) -> Result<String, DntlsError> {
    let code = Zeroizing::new(code);
    let dest = agent_credentials_bundle_path(app, pubkey)?;
    let connectors = app.state::<DntlsConnectors>();
    let _guard = connectors.operation.lock().await;
    let owner_bytes = Zeroizing::new(
        std::fs::read(credentials_bundle_path(app)?)
            .map_err(|_| "Connect your DNTLS name before connecting an agent.".to_string())?,
    );
    let owner = identity::decode_credentials(&owner_bytes).map_err(|e| e.to_string())?;
    let client = portal::Client::new(&portal_origin(), [])?;
    let bundle = client.redeem_credential_code(code.trim()).await?;
    let bytes = Zeroizing::new(bundle.bytes);
    let credentials = identity::decode_credentials(&bytes)
        .map_err(|_| "The Portal returned invalid credentials.".to_string())?;
    let name = credentials.fqdn().to_string();
    validate_agent_name(owner.fqdn(), &name)?;
    if credentials.network_id() != owner.network_id() {
        return Err("The agent's name must belong to your DNTLS network."
            .to_string()
            .into());
    }
    let agents_dir = dntls_dir(app)?.join("agents");
    if agents_dir.is_dir() {
        for entry in std::fs::read_dir(&agents_dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let other = entry.file_name().to_string_lossy().into_owned();
            if other != pubkey && agent_name(app, &other).as_deref() == Some(&name) {
                return Err("That name is already connected to another agent."
                    .to_string()
                    .into());
            }
        }
    }
    let dir = dest
        .parent()
        .ok_or_else(|| "Agent credentials directory is unavailable".to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let staged = stage_restricted(&dest, &bytes)?;
    remove_if_present(&dir.join("data").join(PINS_FILE))?;
    connectors.remove_bundle(&dest)?;
    staged
        .commit()
        .map_err(|e| format!("install agent credentials: {e}"))?;
    Ok(name)
}

fn validate_agent_name(owner: &str, agent: &str) -> Result<(), String> {
    if !agent
        .strip_suffix(owner)
        .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
    {
        return Err("Export a one-time code for a subname of your name, not your own name.".into());
    }
    Ok(())
}

/// Removes all local credentials and live connections for exactly one agent.
pub(crate) async fn remove_agent_credentials(app: &AppHandle, pubkey: &str) -> Result<(), String> {
    let path = agent_credentials_bundle_path(app, pubkey)?;
    let connectors = app.state::<DntlsConnectors>();
    let _guard = connectors.operation.lock().await;
    remove_if_present(&path)?;
    connectors.remove_bundle(&path)?;
    if let Some(dir) = path.parent() {
        match std::fs::remove_dir_all(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("Remove agent credentials: {e}")),
        }
    }
    Ok(())
}

/// Network endpoint pins authenticated by the bundle's trust root.
pub(crate) fn credentials_data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = dntls_dir(app)?.join("data");
    std::fs::create_dir_all(&dir).map_err(|error| format!("create DNTLS data dir: {error}"))?;
    Ok(dir)
}

/// Deletes obsolete onboarding sidecars without changing an existing bundle.
pub(crate) fn remove_obsolete_state(app: &AppHandle) -> Result<(), String> {
    remove_obsolete_files(&dntls_dir(app)?)
}

fn remove_obsolete_files(dir: &Path) -> Result<(), String> {
    for file in ["binding.json", "resolver-credential"] {
        remove_if_present(&dir.join(file))?;
    }
    Ok(())
}

#[tauri::command]
pub(crate) fn dntls_credentials_status(
    app: AppHandle,
) -> Result<DntlsCredentialsStatus, DntlsError> {
    let path = credentials_bundle_path(&app)?;
    match std::fs::read(path) {
        Ok(data) => Ok(DntlsCredentialsStatus {
            name: Some(credentials_fqdn(&Zeroizing::new(data))?),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(DntlsCredentialsStatus { name: None })
        }
        Err(error) => Err(format!("Could not read DNTLS credentials: {error}").into()),
    }
}

/// Redeems the code once, then replaces the installation's identity.
#[tauri::command]
pub(crate) async fn redeem_dntls_credential_code(
    app: AppHandle,
    code: String,
    connectors: State<'_, DntlsConnectors>,
) -> Result<DntlsConnected, DntlsError> {
    let code = Zeroizing::new(code);
    let _guard = connectors.operation.lock().await;
    let client = portal::Client::new(&portal_origin(), [])?;
    let bundle = client.redeem_credential_code(code.trim()).await?;
    let bytes = Zeroizing::new(bundle.bytes);
    let name = credentials_fqdn(&bytes)?;
    // Prepare every fallible storage operation before retiring live connections.
    let dest = credentials_bundle_path(&app)?;
    let pins = credentials_data_dir(&app)?.join(PINS_FILE);
    let staged = stage_restricted(&dest, &bytes)?;
    remove_if_present(&pins)?;
    staged
        .commit()
        .map_err(|error| format!("install DNTLS credentials: {error}"))?;
    connectors.remove_bundle(&credentials_bundle_path(&app)?)?;
    Ok(DntlsConnected { name })
}

/// Removes credentials and terminates connections presenting that identity.
#[tauri::command]
pub(crate) async fn remove_dntls_credentials(
    app: AppHandle,
    connectors: State<'_, DntlsConnectors>,
) -> Result<(), DntlsError> {
    let _guard = connectors.operation.lock().await;
    remove_if_present(&credentials_bundle_path(&app)?)?;
    connectors.remove_bundle(&credentials_bundle_path(&app)?)?;
    Ok(())
}

/// Downloads renewed credentials with proof of the currently held identity.
/// Callers serialize this with replacement/removal and verify freshness first.
pub(crate) async fn refresh_credentials(
    path: &Path,
    credentials: &identity::Credentials,
) -> Result<(), DntlsError> {
    let client = portal::Client::new(&portal_origin(), [])?;
    let session = client
        .authenticate_service_key(credentials)
        .await
        .map_err(refresh_error)?;
    let authenticated =
        portal::Client::new(&portal_origin(), [portal::with_api_key(session.token)])?;
    let bundle = match session.subname_id {
        Some(subname_id) => {
            authenticated
                .download_subname_credentials(&session.name_id, &subname_id)
                .await
        }
        None => authenticated.download_credentials(&session.name_id).await,
    }
    .map_err(refresh_error)?;
    let bytes = Zeroizing::new(bundle.bytes);
    let renewed = identity::decode_credentials(&bytes).map_err(|_| {
        DntlsError::new(
            "unavailable",
            "The Portal returned invalid credentials. Please try again.",
        )
    })?;
    if renewed.fqdn() != credentials.fqdn()
        || renewed.service_public_key() != credentials.service_public_key()
        || renewed.network_id() != credentials.network_id()
    {
        return Err(DntlsError::credentials_changed());
    }
    stage_restricted(path, &bytes)?
        .commit()
        .map_err(|error| format!("install DNTLS credentials: {error}"))?;
    Ok(())
}

fn refresh_error(error: portal::Error) -> DntlsError {
    if error.classification() == Some(portal::Classification::Unauthorized) {
        DntlsError::credentials_changed()
    } else {
        error.into()
    }
}

/// Decodes the exact identity selected by the person exporting the code.
pub(crate) fn credentials_fqdn(data: &[u8]) -> Result<String, String> {
    let credentials = identity::decode_credentials(data)
        .map_err(|_| "Stored credentials are not a valid DNTLS bundle.".to_string())?;
    Ok(credentials.fqdn().to_string())
}

fn remove_if_present(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("Could not remove DNTLS state: {error}")),
    }
}

/// Stages an owner-only file before an atomic rename, using the app's writer.
fn stage_restricted(path: &Path, data: &[u8]) -> Result<AtomicWriteFile, String> {
    let mut file = AtomicWriteFile::open(path)
        .map_err(|error| format!("open DNTLS credentials for atomic write: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("set DNTLS credentials permissions: {error}"))?;
    }
    file.write_all(data)
        .map_err(|error| format!("write DNTLS credentials: {error}"))?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_name_must_be_strictly_below_the_owner() {
        assert!(validate_agent_name("alice.dntls", "fizz.alice.dntls").is_ok());
        assert!(validate_agent_name("alice.example.dntls", "fizz.alice.example.dntls").is_ok());
        for name in [
            "alice.dntls",
            "fizz.malice.dntls",
            "fizz.bob.dntls",
            "alice.dntls.attacker.dntls",
        ] {
            assert!(validate_agent_name("alice.dntls", name).is_err(), "{name}");
        }
        assert!(validate_agent_name("alice.example.dntls", "fizz.example.dntls").is_err());
    }

    #[test]
    fn staged_replacement_preserves_previous_bundle_until_commit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CREDENTIALS_FILE);
        std::fs::write(&path, b"previous").unwrap();
        {
            let staged = stage_restricted(&path, b"replacement").unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), b"previous");
            drop(staged);
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"previous");
        stage_restricted(&path, b"replacement")
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn obsolete_sidecars_are_removed_without_touching_credentials_or_pins() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("data")).unwrap();
        for file in [
            CREDENTIALS_FILE,
            "binding.json",
            "resolver-credential",
            "data/pins.json",
        ] {
            std::fs::write(dir.path().join(file), file).unwrap();
        }
        remove_obsolete_files(dir.path()).unwrap();
        assert!(!dir.path().join("binding.json").exists());
        assert!(!dir.path().join("resolver-credential").exists());
        assert_eq!(
            std::fs::read(dir.path().join(CREDENTIALS_FILE)).unwrap(),
            CREDENTIALS_FILE.as_bytes()
        );
        assert!(dir.path().join("data/pins.json").exists());
        remove_obsolete_files(dir.path()).unwrap();
    }

    #[test]
    fn credential_name_keeps_every_subname_label() {
        let fixture = identity::identitytest::new("buzz.alice.dntls", "").unwrap();
        assert_eq!(
            credentials_fqdn(&fixture.bundle).unwrap(),
            "buzz.alice.dntls"
        );
        assert!(credentials_fqdn(b"not a bundle").is_err());
    }
}
