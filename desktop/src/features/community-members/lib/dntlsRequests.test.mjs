import assert from "node:assert/strict";
import test from "node:test";

import {
  beginDntlsRequestAction,
  canShowDntlsRequestsSection,
  endDntlsRequestAction,
  relayMemberDisplayName,
  removePendingDntlsApplication,
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

test("optimistic removal drops the matching request and restores the rest", () => {
  const next = removePendingDntlsApplication(okList, PUBKEY);
  assert.deepEqual(next, {
    status: "ok",
    applications: [{ pubkey: OTHER, fqdn: "bob.example", createdAt: 2 }],
  });
  assert.equal(
    removePendingDntlsApplication({ status: "unavailable" }, PUBKEY).status,
    "unavailable",
  );
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
