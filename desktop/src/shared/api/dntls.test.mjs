import assert from "node:assert/strict";
import test from "node:test";

import {
  approveDntlsApplication,
  fetchDntlsNames,
  listPendingDntlsApplications,
  rejectDntlsApplication,
} from "./dntls.ts";

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
    invoke: async (command, args) => {
      if (command === "get_relay_http_url") return httpBase;
      if (command === "canonical_auth_url") return args.url;
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
                agent: true,
                owner: "owner.example",
              },
            ],
          }),
        );
      },
      async () => {
        const names = await fetchDntlsNames();
        assert.deepEqual(
          [...names.entries()],
          [
            [
              PUBKEY,
              {
                fqdn: "alice.example",
                approvedAt: 1700000000,
                agent: true,
                owner: "owner.example",
              },
            ],
          ],
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

test("fetchDntlsNames signs the DNTLS origin while fetching the loopback URL", async () => {
  const signed = [];
  globalThis.window = globalThis.window ?? {};
  globalThis.window.__TAURI_INTERNALS__ = {
    invoke: async (command, args) => {
      if (command === "get_relay_http_url") return "http://127.0.0.1:63330";
      if (command === "canonical_auth_url") {
        return args.url.replace(
          "http://127.0.0.1:63330",
          "https://buzzdemo.dntls",
        );
      }
      if (command === "sign_event") {
        signed.push(args);
        return JSON.stringify({
          id: "x",
          sig: "y",
          pubkey: "z",
          kind: 27235,
          created_at: 1,
          tags: args.tags,
        });
      }
      throw new Error(`Unexpected Tauri command: ${command}`);
    },
  };
  try {
    await withFetch(
      async (url) => {
        assert.equal(url, "http://127.0.0.1:63330/api/dntls/names");
        return new Response(JSON.stringify({ names: [] }));
      },
      async () => {
        await fetchDntlsNames();
      },
    );
    assert.equal(signed.length, 1);
    assert.equal(signed[0].tags[0][0], "u");
    assert.equal(
      signed[0].tags[0][1],
      "https://buzzdemo.dntls/api/dntls/names",
    );
  } finally {
    teardownTauriStubs();
  }
});

function tagValue(tags, name) {
  const tag = tags.find((entry) => entry[0] === name);
  return tag?.[1];
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function setupSigningStubs(httpBase, canonicalFrom) {
  const signed = [];
  globalThis.window = globalThis.window ?? {};
  globalThis.window.__TAURI_INTERNALS__ = {
    invoke: async (command, args) => {
      if (command === "get_relay_http_url") return httpBase;
      if (command === "canonical_auth_url") {
        return canonicalFrom
          ? args.url.replace(httpBase, canonicalFrom)
          : args.url;
      }
      if (command === "sign_event") {
        signed.push(args);
        return JSON.stringify({
          id: "x",
          sig: "y",
          pubkey: "z",
          kind: 27235,
          created_at: 1,
          tags: args.tags,
        });
      }
      throw new Error(`Unexpected Tauri command: ${command}`);
    },
  };
  return signed;
}

test("listPendingDntlsApplications maps applications and signs GET without payload", async () => {
  const signed = setupSigningStubs("https://relay.example");
  try {
    await withFetch(
      async (url, init) => {
        assert.equal(url, "https://relay.example/api/dntls/pending");
        assert.equal(init.method ?? "GET", "GET");
        assert.match(init.headers.Authorization, /^Nostr /);
        return new Response(
          JSON.stringify({
            applications: [
              {
                pubkey: PUBKEY.toUpperCase(),
                fqdn: "alice.example",
                created_at: 1700000000,
              },
            ],
          }),
        );
      },
      async () => {
        const result = await listPendingDntlsApplications();
        assert.deepEqual(result, {
          status: "ok",
          applications: [
            {
              pubkey: PUBKEY,
              fqdn: "alice.example",
              createdAt: 1700000000,
            },
          ],
        });
      },
    );
    assert.equal(signed.length, 1);
    assert.equal(
      tagValue(signed[0].tags, "u"),
      "https://relay.example/api/dntls/pending",
    );
    assert.equal(tagValue(signed[0].tags, "method"), "GET");
    assert.equal(tagValue(signed[0].tags, "payload"), undefined);
  } finally {
    teardownTauriStubs();
  }
});

test("listPendingDntlsApplications maps 404 dntls_not_configured to unavailable", async () => {
  setupTauriStubs("https://relay.example");
  try {
    await withFetch(
      async () =>
        new Response(JSON.stringify({ error: "dntls_not_configured" }), {
          status: 404,
        }),
      async () => {
        const result = await listPendingDntlsApplications();
        assert.deepEqual(result, { status: "unavailable" });
      },
    );
  } finally {
    teardownTauriStubs();
  }
});

test("listPendingDntlsApplications maps 403 to forbidden", async () => {
  setupTauriStubs("https://relay.example");
  try {
    await withFetch(
      async () =>
        new Response(
          JSON.stringify({
            error: "only relay owners and admins can manage DNTLS applications",
          }),
          { status: 403 },
        ),
      async () => {
        const result = await listPendingDntlsApplications();
        assert.deepEqual(result, { status: "forbidden" });
      },
    );
  } finally {
    teardownTauriStubs();
  }
});

test("listPendingDntlsApplications signs the DNTLS origin while fetching the loopback URL", async () => {
  const signed = setupSigningStubs(
    "http://127.0.0.1:63330",
    "https://buzzdemo.dntls",
  );
  try {
    await withFetch(
      async (url) => {
        assert.equal(url, "http://127.0.0.1:63330/api/dntls/pending");
        return new Response(JSON.stringify({ applications: [] }));
      },
      async () => {
        await listPendingDntlsApplications();
      },
    );
    assert.equal(
      tagValue(signed[0].tags, "u"),
      "https://buzzdemo.dntls/api/dntls/pending",
    );
    assert.equal(tagValue(signed[0].tags, "method"), "GET");
  } finally {
    teardownTauriStubs();
  }
});

async function assertSignedPost(path, run) {
  const signed = setupSigningStubs(
    "http://127.0.0.1:63330",
    "https://buzzdemo.dntls",
  );
  const body = JSON.stringify({ pubkey: PUBKEY });
  try {
    await withFetch(async (url, init) => {
      assert.equal(url, `http://127.0.0.1:63330${path}`);
      assert.equal(init.method, "POST");
      assert.equal(init.body, body);
      assert.equal(init.headers["Content-Type"], "application/json");
      assert.match(init.headers.Authorization, /^Nostr /);
      return new Response(JSON.stringify({ status: "ok" }));
    }, run);
    assert.equal(signed.length, 1);
    assert.equal(
      tagValue(signed[0].tags, "u"),
      `https://buzzdemo.dntls${path}`,
    );
    assert.equal(tagValue(signed[0].tags, "method"), "POST");
    assert.equal(tagValue(signed[0].tags, "payload"), await sha256Hex(body));
  } finally {
    teardownTauriStubs();
  }
}

test("approveDntlsApplication signs POST payload against the canonical URL", async () => {
  await assertSignedPost("/api/dntls/approve", () =>
    approveDntlsApplication(PUBKEY),
  );
});

test("rejectDntlsApplication signs POST payload against the canonical URL", async () => {
  await assertSignedPost("/api/dntls/reject", () =>
    rejectDntlsApplication(PUBKEY),
  );
});

test("approveDntlsApplication throws on forbidden instead of hiding", async () => {
  setupTauriStubs("https://relay.example");
  try {
    await withFetch(
      async () =>
        new Response(JSON.stringify({ error: "forbidden" }), { status: 403 }),
      async () => {
        await assert.rejects(
          () => approveDntlsApplication(PUBKEY),
          /forbidden/,
        );
      },
    );
  } finally {
    teardownTauriStubs();
  }
});
