import { invoke } from "@tauri-apps/api/core";

export type DntlsConnectorReady = {
  community: string;
  relayUrl: string;
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

/** Start or reuse the desktop-owned local connector for a DNTLS community. */
export async function startDntlsConnector(
  community: string,
): Promise<DntlsConnectorReady> {
  const ready = await invoke<DntlsConnectorWire>("start_dntls_connector", {
    community,
  });
  return { community: ready.community, relayUrl: ready.relay_url };
}
