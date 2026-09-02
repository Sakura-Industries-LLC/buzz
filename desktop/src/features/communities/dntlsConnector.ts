import { invoke } from "@tauri-apps/api/core";

export type DntlsConnectorReady = {
  community: string;
  relayUrl: string;
};

export type DntlsCredentialsStatus = {
  name: string | null;
};

type DntlsConnectorWire = {
  community: string;
  relay_url: string;
};

/** Return the normalized name when input is an exact DNTLS FQDN. */
export function dntlsCommunityName(input: string): string | null {
  const name = input.trim().replace(/\.$/, "").toLowerCase();
  if (!name.endsWith(".dntls") || name.length <= ".dntls".length) return null;
  const labels = name.split(".");
  if (
    labels.some(
      (label) =>
        label.length === 0 ||
        label.startsWith("-") ||
        label.endsWith("-") ||
        !/^[a-z0-9-]+$/.test(label),
    )
  ) {
    return null;
  }
  return name;
}

/** True when the desktop has not yet copied a Portal-exported credentials file. */
export function needsCredentialsImport(status: DntlsCredentialsStatus): boolean {
  return status.name == null || status.name.length === 0;
}

/** Start or reuse the desktop-owned local connector for a DNTLS community. */
export async function startDntlsConnector(
  community: string,
): Promise<DntlsConnectorReady> {
  const ready = await invoke<DntlsConnectorWire>("start_dntls_connector", {
    community,
  });
  return { community: ready.community, relayUrl: ready.relay_url };
}

/** Return the stored DNTLS identity name, if a credentials file is present. */
export function dntlsCredentialsStatus(): Promise<DntlsCredentialsStatus> {
  return invoke<DntlsCredentialsStatus>("dntls_credentials_status");
}

/**
 * Prompt for a Portal-exported credentials file and copy it into app data.
 * Returns null when the user cancels the picker.
 */
export function importDntlsCredentials(): Promise<DntlsCredentialsStatus | null> {
  return invoke<DntlsCredentialsStatus | null>("import_dntls_credentials");
}

/** Delete the stored credentials file. */
export function removeDntlsCredentials(): Promise<void> {
  return invoke("remove_dntls_credentials");
}

/**
 * Prompt for a credentials file when none is stored.
 * Returns false when the user cancels the picker.
 */
export async function ensureDntlsCredentials(): Promise<boolean> {
  const status = await dntlsCredentialsStatus();
  if (!needsCredentialsImport(status)) return true;
  const imported = await importDntlsCredentials();
  return imported != null && !needsCredentialsImport(imported);
}
