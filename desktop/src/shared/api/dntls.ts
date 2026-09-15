import {
  canonicalAuthUrl,
  getRelayHttpUrl,
  signRelayEvent,
} from "@/shared/api/tauri";
import { normalizePubkey } from "@/shared/lib/pubkey";

const NIP98_KIND = 27235;
const NAMES_PATH = "/api/dntls/names";
const PENDING_PATH = "/api/dntls/pending";
const APPROVE_PATH = "/api/dntls/approve";
const REJECT_PATH = "/api/dntls/reject";
const DNTLS_REQUEST_TIMEOUT_MS = 15_000;

export type DntlsVerifiedName = {
  fqdn: string;
  approvedAt: number;
};

export type DntlsNamesMap = Map<string, DntlsVerifiedName>;

export type DntlsPendingApplication = {
  pubkey: string;
  fqdn: string;
  createdAt: number;
};

export type ListPendingDntlsApplicationsResult =
  | { status: "ok"; applications: DntlsPendingApplication[] }
  | { status: "unavailable" }
  | { status: "forbidden" };

type RawDntlsName = {
  pubkey?: unknown;
  fqdn?: unknown;
  approved_at?: unknown;
};

type RawDntlsNamesResponse = {
  names?: unknown;
};

type RawPendingApplication = {
  pubkey?: unknown;
  fqdn?: unknown;
  created_at?: unknown;
};

type RawPendingResponse = {
  applications?: unknown;
  error?: unknown;
};

type RawErrorResponse = {
  error?: unknown;
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

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Build the NIP-98 `Authorization` header for a POST with a body.
 *
 * The relay requires a `payload` tag carrying sha256(body) for signed POSTs
 * (`api/dntls.rs` passes `require_payload: true`), and verifies the `u` tag
 * against the exact request URL — so the caller finalizes both before signing.
 */
async function nip98PostHeader(url: string, body: string): Promise<string> {
  const authEvent = await signRelayEvent({
    kind: NIP98_KIND,
    content: "",
    tags: [
      ["u", url],
      ["method", "POST"],
      ["payload", await sha256Hex(body)],
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
      typeof entry.approved_at === "number" &&
      Number.isFinite(entry.approved_at)
        ? entry.approved_at
        : 0;
    names.set(pubkey, { fqdn, approvedAt });
  }
  return names;
}

function parseApplications(
  payload: RawPendingResponse,
): DntlsPendingApplication[] {
  if (!Array.isArray(payload.applications)) {
    return [];
  }
  const applications: DntlsPendingApplication[] = [];
  for (const entry of payload.applications as RawPendingApplication[]) {
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
    const createdAt =
      typeof entry.created_at === "number" && Number.isFinite(entry.created_at)
        ? entry.created_at
        : 0;
    applications.push({ pubkey, fqdn, createdAt });
  }
  return applications;
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
    const authorization = await nip98GetHeader(await canonicalAuthUrl(url));
    const response = await fetch(url, {
      headers: { Authorization: authorization },
      signal: AbortSignal.timeout(DNTLS_REQUEST_TIMEOUT_MS),
    });
    if (response.status === 404) {
      console.debug("dntls names: surface disabled");
      return new Map();
    }
    if (!response.ok) {
      console.debug(`dntls names: fetch failed (${response.status})`);
      return new Map();
    }
    const json = (await response
      .json()
      .catch(() => ({}))) as RawDntlsNamesResponse;
    return parseNames(json);
  } catch (error) {
    console.debug("dntls names: fetch failed", error);
    return new Map();
  }
}

/**
 * Owner/admin NIP-98 GET of pending DNTLS join requests.
 *
 * 404 `dntls_not_configured` is feature-absent; 403 is not-allowed. Callers
 * hide the Requests UI for both instead of surfacing an error.
 */
export async function listPendingDntlsApplications(): Promise<ListPendingDntlsApplicationsResult> {
  const base = (await getRelayHttpUrl()).replace(/\/+$/, "");
  const url = `${base}${PENDING_PATH}`;
  const authorization = await nip98GetHeader(await canonicalAuthUrl(url));
  const response = await fetch(url, {
    headers: { Authorization: authorization },
    signal: AbortSignal.timeout(DNTLS_REQUEST_TIMEOUT_MS),
  });
  if (response.status === 404) {
    return { status: "unavailable" };
  }
  if (response.status === 403) {
    return { status: "forbidden" };
  }
  const json = (await response.json().catch(() => ({}))) as RawPendingResponse;
  if (!response.ok) {
    throw new Error(
      typeof json.error === "string" ? json.error : `HTTP ${response.status}`,
    );
  }
  return { status: "ok", applications: parseApplications(json) };
}

async function postDntlsDecision(path: string, pubkey: string): Promise<void> {
  const base = (await getRelayHttpUrl()).replace(/\/+$/, "");
  const url = `${base}${path}`;
  const body = JSON.stringify({ pubkey });
  const authorization = await nip98PostHeader(
    await canonicalAuthUrl(url),
    body,
  );
  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: authorization,
      "Content-Type": "application/json",
    },
    body,
    signal: AbortSignal.timeout(DNTLS_REQUEST_TIMEOUT_MS),
  });
  const json = (await response.json().catch(() => ({}))) as RawErrorResponse;
  if (!response.ok) {
    throw new Error(
      typeof json.error === "string" ? json.error : `HTTP ${response.status}`,
    );
  }
}

/** Owner/admin NIP-98 POST admitting a pending or rejected DNTLS application. */
export async function approveDntlsApplication(pubkey: string): Promise<void> {
  await postDntlsDecision(APPROVE_PATH, pubkey);
}

/** Owner/admin NIP-98 POST rejecting a pending DNTLS application. */
export async function rejectDntlsApplication(pubkey: string): Promise<void> {
  await postDntlsDecision(REJECT_PATH, pubkey);
}
