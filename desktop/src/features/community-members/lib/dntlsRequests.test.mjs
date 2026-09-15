import assert from "node:assert/strict";
import test from "node:test";

import {
  beginDntlsRequestAction,
  canShowDntlsRequestsSection,
  DNTLS_PENDING_REFETCH_INTERVAL_MS,
  dntlsPendingApplicationsQueryKey,
  dntlsRequestJoinCopy,
  endDntlsRequestAction,
  formatDntlsRequestedAt,
  relayMemberDisplayName,
  removePendingDntlsApplication,
  seedApprovedDntlsName,
} from "./dntlsRequests.ts";

const PUBKEY = "aa".repeat(32);
const OTHER = "bb".repeat(32);

const okList = {
  status: "ok",
  applications: [
    { pubkey: PUBKEY.toUpperCase(), fqdn: "alice.example", createdAt: 1 },
    { pubkey: OTHER, fqdn: "bob.example", createdAt: 2 },
  ],
};

test("Requests section is owner/admin only and hides empty, unavailable, and forbidden lists", () => {
  assert.equal(
    canShowDntlsRequestsSection({
      role: "owner",
      isSuccess: true,
      result: okList,
    }),
    true,
  );
  assert.equal(
    canShowDntlsRequestsSection({
      role: "admin",
      isSuccess: true,
      result: okList,
    }),
    true,
  );
  assert.equal(
    canShowDntlsRequestsSection({
      role: "member",
      isSuccess: true,
      result: okList,
    }),
    false,
  );
  assert.equal(
    canShowDntlsRequestsSection({
      role: "owner",
      isSuccess: true,
      result: { status: "ok", applications: [] },
    }),
    false,
  );
  assert.equal(
    canShowDntlsRequestsSection({
      role: "owner",
      isSuccess: true,
      result: { status: "unavailable" },
    }),
    false,
  );
  assert.equal(
    canShowDntlsRequestsSection({
      role: "owner",
      isSuccess: true,
      result: { status: "forbidden" },
    }),
    false,
  );
  assert.equal(
    canShowDntlsRequestsSection({
      role: "owner",
      isSuccess: false,
      result: okList,
    }),
    false,
  );
});

test("pending query key is community-scoped by relay URL", () => {
  assert.deepEqual(dntlsPendingApplicationsQueryKey("wss://a.example"), [
    "dntls-pending",
    "wss://a.example",
  ]);
  assert.notDeepEqual(
    dntlsPendingApplicationsQueryKey("wss://a.example"),
    dntlsPendingApplicationsQueryKey("wss://b.example"),
  );
});

test("pending list polls every 5 seconds while mounted", () => {
  assert.equal(DNTLS_PENDING_REFETCH_INTERVAL_MS, 5_000);
});

test("request copy matches the issue and stays off public vocabulary", () => {
  const copy = dntlsRequestJoinCopy("alice.example");
  assert.equal(copy, "alice.example wants to join");
  assert.equal(copy.includes("pubkey"), false);
  assert.equal(copy.includes("relay"), false);
  assert.equal(copy.includes("AUTH"), false);
});

test("requested relative time uses roster-style buckets", () => {
  const now = Date.UTC(2026, 0, 15, 12, 0, 0);
  assert.equal(formatDntlsRequestedAt(now / 1000, now), "requested just now");
  assert.equal(
    formatDntlsRequestedAt(now / 1000 - 5 * 60, now),
    "requested 5m ago",
  );
  assert.equal(
    formatDntlsRequestedAt(now / 1000 - 3 * 60 * 60, now),
    "requested 3h ago",
  );
});

test("optimistic removal drops the matching request and restores the rest", () => {
  const next = removePendingDntlsApplication(okList, PUBKEY);
  assert.deepEqual(next, {
    status: "ok",
    applications: [{ pubkey: OTHER, fqdn: "bob.example", createdAt: 2 }],
  });
  assert.equal(removePendingDntlsApplication({ status: "unavailable" }, PUBKEY)
    .status, "unavailable");
});

test("approve seeds the verified-name cache so the roster can show it", () => {
  const names = seedApprovedDntlsName(
    new Map(),
    { pubkey: PUBKEY.toUpperCase(), fqdn: "alice.example" },
    1700000000,
  );
  assert.deepEqual(names.get(PUBKEY), {
    fqdn: "alice.example",
    approvedAt: 1700000000,
  });
});

test("in-flight lock ignores a second Approve/Reject for the same request", () => {
  const inFlight = new Set();
  assert.equal(beginDntlsRequestAction(inFlight, PUBKEY), true);
  assert.equal(beginDntlsRequestAction(inFlight, PUBKEY.toUpperCase()), false);
  assert.equal(beginDntlsRequestAction(inFlight, OTHER), true);
  endDntlsRequestAction(inFlight, PUBKEY);
  assert.equal(beginDntlsRequestAction(inFlight, PUBKEY), true);
});

test("roster display prefers the verified DNTLS name over kind-0", () => {
  assert.equal(
    relayMemberDisplayName(
      { role: "member" },
      { displayName: "Ada", verifiedDntlsName: "alice.example" },
    ),
    "alice.example",
  );
  assert.equal(
    relayMemberDisplayName({ role: "member" }, { displayName: "Ada" }),
    "Ada",
  );
  assert.equal(
    relayMemberDisplayName({ role: "owner" }, { displayName: "npub1abc" }),
    "Community owner",
  );
});
