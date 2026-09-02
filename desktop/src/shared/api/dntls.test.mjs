import assert from "node:assert/strict";
import test from "node:test";

import { fetchDntlsNames } from "./dntls.ts";

function setupTauriStubs(
  httpBase,
  authEvent = {
    id: "x",
    sig: "y",
    pubkey: "z",
    kind: 27235,
    created_at: 1,
    tags: [],
  },
) {
  globalThis.window = globalThis.window ?? {};
  globalThis.window.__TAURI_INTERNALS__ = {
    invoke: async (command) => {
      if (command === "get_relay_http_url") return httpBase;
      if (command === "sign_event") return JSON.stringify(authEvent);
      throw new Error(`Unexpected Tauri command: ${command}`);
    },
  };
}

function teardownTauriStubs() {
  delete globalThis.window.__TAURI_INTERNALS__;
}

async function withFetch(handler, run) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = handler;
  try {
    return await run();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

const PUBKEY = "aa".repeat(32);

test("fetchDntlsNames maps pubkey to fqdn and approvedAt", async () => {
  setupTauriStubs("https://relay.example");
  try {
    await withFetch(
      async (url, init) => {
        assert.equal(url, "https://relay.example/api/dntls/names");
        assert.equal(init.method ?? "GET", "GET");
        assert.match(init.headers.Authorization, /^Nostr /);
        return new Response(
          JSON.stringify({
            names: [
              {
                pubkey: PUBKEY.toUpperCase(),
                fqdn: "alice.example",
                approved_at: 1700000000,
              },
            ],
          }),
        );
      },
      async () => {
        const names = await fetchDntlsNames();
        assert.deepEqual(
          [...names.entries()],
          [[PUBKEY, { fqdn: "alice.example", approvedAt: 1700000000 }]],
        );
      },
    );
  } finally {
    teardownTauriStubs();
  }
});

test("fetchDntlsNames fail-safe returns empty map on 404", async () => {
  setupTauriStubs("https://relay.example");
  try {
    await withFetch(
      async () => new Response("{}", { status: 404 }),
      async () => {
        const names = await fetchDntlsNames();
        assert.equal(names.size, 0);
      },
    );
  } finally {
    teardownTauriStubs();
  }
});

test("fetchDntlsNames fail-safe returns empty map on fetch failure", async () => {
  setupTauriStubs("https://relay.example");
  try {
    await withFetch(
      async () => {
        throw new Error("network down");
      },
      async () => {
        const names = await fetchDntlsNames();
        assert.equal(names.size, 0);
      },
    );
  } finally {
    teardownTauriStubs();
  }
});
