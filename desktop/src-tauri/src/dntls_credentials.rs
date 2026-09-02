use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;

use crate::dntls_connector::normalize_dntls_name;

const CREDENTIALS_FILE: &str = "credentials.bundle";
const DATA_DIR_NAME: &str = "data";
const MAX_BUNDLE_SIZE: usize = 256 * 1024;

/// Stored DNTLS identity shown in settings and used before connector start.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct DntlsCredentialsStatus {
    /// Verified FQDN from the stored credentials file, if one is present.
    pub name: Option<String>,
}

/// App-data directory that holds the copied credentials file and resolver pins.
pub(crate) fn dntls_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("app data dir: {error}"))?
        .join("dntls");
    std::fs::create_dir_all(&dir).map_err(|error| format!("create DNTLS data dir: {error}"))?;
    Ok(dir)
}

/// Path of the copied Portal-exported credentials bundle.
pub(crate) fn credentials_bundle_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(dntls_dir(app)?.join(CREDENTIALS_FILE))
}

/// Connector `--data-dir` used for resolver pins.
pub(crate) fn credentials_data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = dntls_dir(app)?.join(DATA_DIR_NAME);
    std::fs::create_dir_all(&dir).map_err(|error| format!("create DNTLS pin dir: {error}"))?;
    Ok(dir)
}

/// Returns the stored identity name, or `name: None` when no file is present.
#[tauri::command]
pub(crate) fn dntls_credentials_status(
    app: AppHandle,
) -> Result<DntlsCredentialsStatus, String> {
    let path = credentials_bundle_path(&app)?;
    if !path.is_file() {
        return Ok(DntlsCredentialsStatus { name: None });
    }
    let name = credentials_name_from_path(&path)?;
    Ok(DntlsCredentialsStatus { name: Some(name) })
}

/// Opens a native file picker, copies the chosen bundle, and returns its name.
///
/// `Ok(None)` means the user cancelled the picker.
#[tauri::command]
pub(crate) async fn import_dntls_credentials(
    app: AppHandle,
) -> Result<Option<DntlsCredentialsStatus>, String> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .add_filter("DNTLS credentials", &["bundle", "dntls-credentials"])
        .pick_file(move |path| {
            let _ = sender.send(path);
        });
    let selected = receiver
        .await
        .map_err(|_| "credentials dialog was interrupted".to_string())?;
    let Some(file) = selected else {
        return Ok(None);
    };
    let source = file
        .as_path()
        .ok_or_else(|| "credentials dialog returned an invalid path".to_string())?
        .to_path_buf();
    let dest = credentials_bundle_path(&app)?;
    install_credentials_file(&source, &dest)?;
    let name = credentials_name_from_path(&dest)?;
    Ok(Some(DntlsCredentialsStatus { name: Some(name) }))
}

/// Deletes the stored credentials file. Resolver pin data is left in place.
#[tauri::command]
pub(crate) fn remove_dntls_credentials(app: AppHandle) -> Result<(), String> {
    let path = credentials_bundle_path(&app)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("could not remove DNTLS credentials: {error}")),
    }
}

/// Copies `source` to `dest` after confirming it is a credentials bundle.
pub(crate) fn install_credentials_file(source: &Path, dest: &Path) -> Result<String, String> {
    let data = std::fs::read(source).map_err(|error| {
        format!(
            "could not read credentials file {}: {error}",
            source.display()
        )
    })?;
    let name = credentials_fqdn(&data)?;
    write_restricted(dest, &data)?;
    Ok(name)
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

/// Reads the selected identity FQDN from a Portal-exported CBOR credentials bundle.
pub(crate) fn credentials_fqdn(data: &[u8]) -> Result<String, String> {
    if data.is_empty() || data.len() > MAX_BUNDLE_SIZE {
        return Err("credentials file is not a DNTLS credentials bundle".to_string());
    }
    let envelope = parse_int_key_map(data)?;
    let nested = match envelope.get(&2) {
        Some(CborVal::Bytes(bytes)) => *bytes,
        _ => return Err("credentials file is missing the nested identity".to_string()),
    };
    let service = parse_int_key_map(nested)?;
    let fqdn = match service.get(&6) {
        Some(CborVal::Text(text)) => *text,
        _ => return Err("credentials file does not include a DNTLS name".to_string()),
    };
    normalize_dntls_name(fqdn)
}

#[derive(Clone, Copy)]
enum CborVal<'a> {
    Bytes(&'a [u8]),
    Text(&'a str),
    Other,
}

struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(n)
            .filter(|value| *value <= self.data.len())
            .ok_or_else(|| "credentials file is truncated".to_string())?;
        let slice = &self.data[self.offset..end];
        self.offset = end;
        Ok(slice)
    }


    fn take_u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
}

fn parse_int_key_map(data: &[u8]) -> Result<HashMap<u64, CborVal<'_>>, String> {
    let mut cursor = Cursor { data, offset: 0 };
    let (major, argument) = read_head(&mut cursor)?;
    if major != 5 {
        return Err("credentials file is not a DNTLS credentials bundle".to_string());
    }
    let mut map = HashMap::new();
    for _ in 0..argument {
        let (key_major, key) = read_head(&mut cursor)?;
        if key_major != 0 {
            skip_value_body(&mut cursor, key_major, key)?;
            skip_value(&mut cursor)?;
            continue;
        }
        let value = read_value(&mut cursor)?;
        map.insert(key, value);
    }
    if cursor.offset != cursor.data.len() {
        return Err("credentials file has trailing data".to_string());
    }
    Ok(map)
}

fn read_value<'a>(cursor: &mut Cursor<'a>) -> Result<CborVal<'a>, String> {
    let (major, argument) = read_head(cursor)?;
    match major {
        2 => {
            let bytes = cursor.take(usize_from_u64(argument)?)?;
            Ok(CborVal::Bytes(bytes))
        }
        3 => {
            let bytes = cursor.take(usize_from_u64(argument)?)?;
            let text = std::str::from_utf8(bytes)
                .map_err(|_| "credentials file contains a non-UTF-8 name".to_string())?;
            Ok(CborVal::Text(text))
        }
        _ => {
            skip_value_body(cursor, major, argument)?;
            Ok(CborVal::Other)
        }
    }
}

fn skip_value(cursor: &mut Cursor<'_>) -> Result<(), String> {
    let (major, argument) = read_head(cursor)?;
    skip_value_body(cursor, major, argument)
}

fn skip_value_body(cursor: &mut Cursor<'_>, major: u8, argument: u64) -> Result<(), String> {
    match major {
        0 | 1 | 7 => Ok(()),
        2 | 3 => {
            cursor.take(usize_from_u64(argument)?)?;
            Ok(())
        }
        4 => {
            for _ in 0..argument {
                skip_value(cursor)?;
            }
            Ok(())
        }
        5 => {
            for _ in 0..argument {
                skip_value(cursor)?;
                skip_value(cursor)?;
            }
            Ok(())
        }
        6 => {
            skip_value(cursor)?;
            Ok(())
        }
        _ => Err("credentials file uses an unsupported CBOR value".to_string()),
    }
}

fn read_head(cursor: &mut Cursor<'_>) -> Result<(u8, u64), String> {
    let initial = cursor.take_u8()?;
    let major = initial >> 5;
    let additional = initial & 0x1f;
    let argument = match additional {
        0..=23 => additional as u64,
        24 => cursor.take_u8()? as u64,
        25 => {
            let bytes = cursor.take(2)?;
            u16::from_be_bytes([bytes[0], bytes[1]]) as u64
        }
        26 => {
            let bytes = cursor.take(4)?;
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
        }
        27 => {
            let bytes = cursor.take(8)?;
            u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])
        }
        _ => {
            return Err("credentials file uses indefinite-length CBOR".to_string());
        }
    };
    Ok((major, argument))
}

fn usize_from_u64(value: u64) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| "credentials file is truncated".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_unsigned(value: u64) -> Vec<u8> {
        if value < 24 {
            vec![value as u8]
        } else if value <= u8::MAX as u64 {
            vec![24, value as u8]
        } else {
            panic!("test integer too large")
        }
    }

    fn encode_text(text: &str) -> Vec<u8> {
        let mut out = encode_unsigned(text.len() as u64);
        out[0] |= 3 << 5;
        out.extend(text.as_bytes());
        out
    }

    fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
        let mut out = encode_unsigned(bytes.len() as u64);
        out[0] |= 2 << 5;
        out.extend(bytes);
        out
    }

    fn encode_map(entries: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut out = encode_unsigned(entries.len() as u64);
        out[0] |= 5 << 5;
        for (key, value) in entries {
            out.extend(encode_unsigned(*key));
            out.extend(value);
        }
        out
    }

    fn sample_bundle(fqdn: &str) -> Vec<u8> {
        let nested = encode_map(&[
            (1, encode_bytes(&[0u8; 8])),
            (6, encode_text(fqdn)),
        ]);
        encode_map(&[
            (1, encode_text("dntls-lab-service-credentials")),
            (2, encode_bytes(&nested)),
            (3, encode_bytes(b"trust")),
        ])
    }

    #[test]
    fn reads_fqdn_from_cbor_bundle() {
        let bundle = sample_bundle("Demo-Alice.DNTLS.");
        assert_eq!(credentials_fqdn(&bundle).as_deref(), Ok("demo-alice.dntls"));
    }

    #[test]
    fn reads_portal_exported_alice_bundle() {
        let path = "/tmp/buzz-e2e/demo-alice.dntls.bundle";
        let Ok(data) = std::fs::read(path) else {
            return;
        };
        assert_eq!(
            credentials_fqdn(&data).as_deref(),
            Ok("demo-alice.dntls")
        );
    }

    #[test]
    fn rejects_missing_name() {
        let nested = encode_map(&[(1, encode_bytes(&[0u8; 8]))]);
        let bundle = encode_map(&[(2, encode_bytes(&nested))]);
        assert!(credentials_fqdn(&bundle).is_err());
    }

    #[test]
    fn copies_bundle_owner_only() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("alice.bundle");
        let dest = temp.path().join("dntls").join("credentials.bundle");
        let bundle = sample_bundle("demo-alice.dntls");
        std::fs::write(&source, &bundle).unwrap();
        assert_eq!(
            install_credentials_file(&source, &dest).as_deref(),
            Ok("demo-alice.dntls")
        );
        assert_eq!(std::fs::read(&dest).unwrap(), bundle);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
