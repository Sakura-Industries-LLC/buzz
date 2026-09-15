import { invoke } from "@tauri-apps/api/core";

export type DntlsConnectorReady = {
  community: string;
  relayUrl: string;
};

export type DntlsCredentialsStatus = {
  /** FQDN the stored bundle carries, or null when none is stored. */
  name: string | null;
};

export type DntlsRedeemed = {
  name: string;
};

export type DntlsError = {
  code: string;
  message: string;
};

type DntlsConnectorWire = {
  community: string;
  relay_url: string;
};

export const DNTLS_CREDENTIALS_CHANGED_EVENT = "dntls-credentials-changed";
export const DNTLS_CREDENTIALS_CHANGED_MESSAGE =
  "Your name's credentials changed. Export a new one-time code.";

const recoveryListeners = new Set<() => void>();

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

export function isCredentialsChangedError(error: unknown): boolean {
  if (isDntlsError(error)) {
    return (
      error.code === "credentials_changed" ||
      error.message === DNTLS_CREDENTIALS_CHANGED_MESSAGE
    );
  }
  if (error instanceof Error) {
    return error.message === DNTLS_CREDENTIALS_CHANGED_MESSAGE;
  }
  return error === DNTLS_CREDENTIALS_CHANGED_MESSAGE;
}

function normalizeDntlsError(error: unknown): DntlsError {
  if (isDntlsError(error)) {
    if (
      error.code !== "credentials_changed" &&
      error.message === DNTLS_CREDENTIALS_CHANGED_MESSAGE
    ) {
      return { code: "credentials_changed", message: error.message };
    }
    return error;
  }
  if (typeof error === "string") {
    try {
      const parsed: unknown = JSON.parse(error);
      if (isDntlsError(parsed)) return normalizeDntlsError(parsed);
    } catch {
      // Plain string from Tauri, not a serialized DntlsError.
    }
    return {
      code:
        error === DNTLS_CREDENTIALS_CHANGED_MESSAGE
          ? "credentials_changed"
          : "unavailable",
      message: error,
    };
  }
  if (error instanceof Error) {
    try {
      const parsed: unknown = JSON.parse(error.message);
      if (isDntlsError(parsed)) return normalizeDntlsError(parsed);
    } catch {
      // Error.message is the human-readable fallback.
    }
    return {
      code:
        error.message === DNTLS_CREDENTIALS_CHANGED_MESSAGE
          ? "credentials_changed"
          : "unavailable",
      message: error.message,
    };
  }
  return {
    code: "unavailable",
    message: "Something went wrong. Try again.",
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
  const ready = await invokeDntls<DntlsConnectorWire>("start_dntls_connector", {
    community,
  });
  return { community: ready.community, relayUrl: ready.relay_url };
}

/** Return the stored DNTLS identity name, if a credentials file is present. */
export function dntlsCredentialsStatus(): Promise<DntlsCredentialsStatus> {
  return invoke<DntlsCredentialsStatus>("dntls_credentials_status");
}

/**
 * Redeem a Portal one-time code and store the resulting credentials bundle.
 * Callers must not log `code`.
 */
export function redeemDntlsCredentialCode(
  code: string,
): Promise<DntlsRedeemed> {
  return invokeDntls<DntlsRedeemed>("redeem_dntls_credential_code", { code });
}

/** Delete the stored credentials file. */
export function removeDntlsCredentials(): Promise<void> {
  return invoke("remove_dntls_credentials");
}

/** Ask the shared recovery UI to collect a new one-time code. */
export function requestDntlsCredentialsRecovery(): void {
  for (const listener of recoveryListeners) listener();
}

export function subscribeDntlsCredentialsRecovery(
  listener: () => void,
): () => void {
  recoveryListeners.add(listener);
  return () => {
    recoveryListeners.delete(listener);
  };
}
