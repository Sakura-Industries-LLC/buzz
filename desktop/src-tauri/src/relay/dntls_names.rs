//! Relay-attested DNTLS identities, separate from self-authored metadata.

use std::collections::HashMap;

use serde::Deserialize;

use crate::app_state::AppState;

/// A name admitted by the active community.
#[derive(Deserialize)]
pub(crate) struct VerifiedName {
    pub pubkey: String,
    pub fqdn: String,
    #[serde(default)]
    pub agent: bool,
    pub owner: Option<String>,
}

#[derive(Deserialize)]
struct NamesResponse {
    names: Vec<VerifiedName>,
}

/// Read only over the active DNTLS transport; failures do not trust profile tags.
pub(crate) async fn fetch(state: &AppState) -> Result<Option<Vec<VerifiedName>>, String> {
    let transport = super::relay_ws_url_with_override(state);
    if super::dntls_community_for_transport(state, &transport).is_none() {
        return Ok(None);
    }
    let response: NamesResponse = super::get_relay_json(state, "/api/dntls/names").await?;
    Ok(Some(response.names))
}

/// Resolve the persisted parent name through the same community snapshot.
pub(crate) fn owners(names: &[VerifiedName]) -> HashMap<String, String> {
    let by_name: HashMap<_, _> = names
        .iter()
        .map(|name| (name.fqdn.as_str(), name.pubkey.as_str()))
        .collect();
    names
        .iter()
        .filter(|name| name.agent)
        .filter_map(|name| {
            let owner = by_name.get(name.owner.as_deref()?)?;
            Some((name.pubkey.clone(), (*owner).to_string()))
        })
        .collect()
}
