import { getRelayHttpUrl, signRelayEvent } from "@/shared/api/tauri";
import { normalizePubkey } from "@/shared/lib/pubkey";

const NIP98_KIND = 27235;
const NAMES_PATH = "/api/dntls/names";
const NAMES_REQUEST_TIMEOUT_MS = 15_000;

export type DntlsVerifiedName = {
  fqdn: string;
  approvedAt: number;
};

export type DntlsNamesMap = Map<string, DntlsVerifiedName>;

type RawDntlsName = {
  pubkey?: unknown;
  fqdn?: unknown;
  approved_at?: unknown;
};

type RawDntlsNamesResponse = {
  names?: unknown;
};

async function nip98GetHeader(url: string): Promise<string> {
  const authEvent = await signRelayEvent({
    kind: NIP98_KIND,
    content: "",
    tags: [
      ["u", url],
      ["method", "GET"],
      ["nonce", crypto.randomUUID()],
    ],
  });
  // NIP-98 events carry empty content and ASCII-only tags, so btoa is safe here.
  return `Nostr ${btoa(JSON.stringify(authEvent))}`;
}

function parseNames(payload: RawDntlsNamesResponse): DntlsNamesMap {
  const names = new Map<string, DntlsVerifiedName>();
  if (!Array.isArray(payload.names)) {
    return names;
  }
  for (const entry of payload.names as RawDntlsName[]) {
    if (typeof entry?.pubkey !== "string" || typeof entry?.fqdn !== "string") {
      continue;
    }
    const fqdn = entry.fqdn.trim();
    if (!fqdn) {
      continue;
    }
    const pubkey = normalizePubkey(entry.pubkey);
    if (!pubkey) {
      continue;
    }
    const approvedAt =
      typeof entry.approved_at === "number" && Number.isFinite(entry.approved_at)
        ? entry.approved_at
        : 0;
    names.set(pubkey, { fqdn, approvedAt });
  }
  return names;
}

/**
 * Member-gated NIP-98 GET of relay-attested DNTLS pubkey→name mappings.
 *
 * Fail-safe: 404 (surface disabled), transport errors, and non-OK responses
 * all resolve to an empty map. Callers render as if DNTLS were absent.
 */
export async function fetchDntlsNames(): Promise<DntlsNamesMap> {
  try {
    const base = (await getRelayHttpUrl()).replace(/\/+$/, "");
    const url = `${base}${NAMES_PATH}`;
    const authorization = await nip98GetHeader(url);
    const response = await fetch(url, {
      headers: { Authorization: authorization },
      signal: AbortSignal.timeout(NAMES_REQUEST_TIMEOUT_MS),
    });
    if (response.status === 404) {
      console.debug("dntls names: surface disabled");
      return new Map();
    }
    if (!response.ok) {
      console.debug(`dntls names: fetch failed (${response.status})`);
      return new Map();
    }
    const json = (await response.json().catch(() => ({}))) as RawDntlsNamesResponse;
    return parseNames(json);
  } catch (error) {
    console.debug("dntls names: fetch failed", error);
    return new Map();
  }
}
