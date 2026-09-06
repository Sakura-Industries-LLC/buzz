import { invoke } from "@tauri-apps/api/core";

export type DntlsConnectorReady = {
  community: string;
  relayUrl: string;
};

export type DntlsCredentialsStatus = {
  name: string | null;
};

export type DntlsResolverStatus = {
  state: "ready" | "no_identity" | "unavailable";
  attested: boolean;
  socket: string;
};

export type DntlsIdentity = {
  name: string;
  fqdn: string;
  has_private_identity: boolean;
  active: boolean;
};

export type DntlsBound = {
  name: string;
  scope: "root" | "subname";
};

export type DntlsError = {
  code: string;
  message: string;
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

/** True when this Buzz install has not bound a DNTLS name yet. */
export function needsCredentialsImport(
  status: DntlsCredentialsStatus,
): boolean {
  return status.name == null || status.name.length === 0;
}

export function isDntlsError(error: unknown): error is DntlsError {
  if (typeof error !== "object" || error === null) return false;
  if (!("code" in error) || !("message" in error)) return false;
  return typeof error.code === "string" && typeof error.message === "string";
}

function normalizeDntlsError(error: unknown): DntlsError {
  if (isDntlsError(error)) return error;
  if (typeof error === "string") {
    try {
      const parsed: unknown = JSON.parse(error);
      if (isDntlsError(parsed)) return parsed;
    } catch {
      // Plain string from Tauri, not a serialized DntlsError.
    }
    return { code: "unavailable", message: error };
  }
  if (error instanceof Error) {
    try {
      const parsed: unknown = JSON.parse(error.message);
      if (isDntlsError(parsed)) return parsed;
    } catch {
      // Error.message is the human-readable fallback.
    }
    return { code: "unavailable", message: error.message };
  }
  return {
    code: "unavailable",
    message: "Something went wrong talking to the Local Trust Resolver.",
  };
}

async function invokeDntls<T>(
  command: string,
  args?: Record<string, unknown>,
): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    throw normalizeDntlsError(error);
  }
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

/** Probe whether the Local Trust Resolver can serve this Buzz install. */
export function getDntlsResolverStatus(): Promise<DntlsResolverStatus> {
  return invokeDntls<DntlsResolverStatus>("dntls_resolver_status");
}

/** List names stored on this machine. Blocks on the resolver consent prompt. */
export function listDntlsIdentities(): Promise<DntlsIdentity[]> {
  return invokeDntls<DntlsIdentity[]>("list_dntls_identities");
}

/**
 * Bind Buzz to `name` (the resolver store key, not the FQDN).
 * Blocks on the resolver's Give Key prompt.
 */
export function bindDntlsIdentity(name: string): Promise<DntlsBound> {
  return invokeDntls<DntlsBound>("bind_dntls_identity", { name });
}

/** Delete the stored credentials file. */
export function removeDntlsCredentials(): Promise<void> {
  return invoke("remove_dntls_credentials");
}
