import assert from "node:assert/strict";
import test from "node:test";

import {
  formatOwnerLabel,
  mergeVerifiedDntlsNames,
  profileLookupsEqual,
  resolveUserLabel,
} from "./identity.ts";

const OWNER_PUBKEY =
  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

const summary = (over = {}) => ({
  displayName: "Ada",
  avatarUrl: "https://x/a.png",
  nip05Handle: "ada@x",
  ownerPubkey: null,
  isAgent: false,
  ...over,
});

test("formatOwnerLabel resolves a known owner's display name", () => {
  assert.equal(
    formatOwnerLabel(OWNER_PUBKEY, null, {
      [OWNER_PUBKEY]: summary({ displayName: "baxen" }),
    }),
    "baxen",
  );
});

test("formatOwnerLabel calls the viewer-owned agent's owner you", () => {
  assert.equal(formatOwnerLabel(OWNER_PUBKEY, OWNER_PUBKEY, {}), "you");
});

test("formatOwnerLabel returns null when verified ownership is absent", () => {
  assert.equal(formatOwnerLabel(null, OWNER_PUBKEY, {}), null);
});

test("profileLookupsEqual: same reference is equal", () => {
  const a = { p1: summary() };
  assert.equal(profileLookupsEqual(a, a), true);
});

test("profileLookupsEqual: distinct objects, identical values are equal", () => {
  assert.equal(profileLookupsEqual({ p1: summary() }, { p1: summary() }), true);
});

test("profileLookupsEqual: different key count is not equal", () => {
  assert.equal(
    profileLookupsEqual({ p1: summary() }, { p1: summary(), p2: summary() }),
    false,
  );
});

test("profileLookupsEqual: same count, different keys is not equal", () => {
  assert.equal(
    profileLookupsEqual({ p1: summary() }, { p2: summary() }),
    false,
  );
});

test("profileLookupsEqual: a changed field is not equal", () => {
  for (const field of [
    "displayName",
    "avatarUrl",
    "nip05Handle",
    "ownerPubkey",
    "isAgent",
    "verifiedDntlsName",
    "dntlsApprovedAt",
  ]) {
    assert.equal(
      profileLookupsEqual(
        { p1: summary() },
        { p1: summary({ [field]: field === "isAgent" ? true : "changed" }) },
      ),
      false,
      `field ${field} should break equality`,
    );
  }
});

test("profileLookupsEqual: two empty lookups are equal", () => {
  assert.equal(profileLookupsEqual({}, {}), true);
});

// Render-count proof for the Tier-1 typing-storm fix (#1533 discipline).
// MessageRow re-renders iff `prev.profiles === next.profiles` fails, so the
// stabiliser's job is: hold the reference across value-equal re-derives (the
// per-keystroke churn) and release it only on a real value change. This
// replays the exact ChannelScreen ref idiom against a sequence of freshly
// built lookups and asserts reference identity == render decision.
function makeStabiliser() {
  let ref;
  let first = true;
  return (raw) => {
    if (first || !profileLookupsEqual(ref, raw)) {
      ref = raw;
    }
    first = false;
    return ref;
  };
}

test("stabiliser: value-equal re-derives keep the same reference (no re-render)", () => {
  const stabilise = makeStabiliser();
  // Each entry is a fresh object identity — exactly what a users-batch re-key
  // produces on every keystroke-adjacent typing event.
  const first = stabilise({ p1: summary() });
  const churnA = stabilise({ p1: summary() });
  const churnB = stabilise({ p1: summary() });
  assert.equal(churnA, first, "value-equal churn must not swap the reference");
  assert.equal(churnB, first, "repeated churn must not swap the reference");
});

test("stabiliser: a real profile change swaps the reference (re-render fires)", () => {
  const stabilise = makeStabiliser();
  const first = stabilise({ p1: summary() });
  const changed = stabilise({ p1: summary({ displayName: "Grace" }) });
  assert.notEqual(
    changed,
    first,
    "a real value change must swap the reference",
  );
  // ...and then re-stabilises around the new value.
  const held = stabilise({ p1: summary({ displayName: "Grace" }) });
  assert.equal(held, changed, "must re-stabilise around the new value");
});

const USER_PUBKEY =
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

test("resolveUserLabel: verified DNTLS name wins over displayName and nip05", () => {
  assert.equal(
    resolveUserLabel({
      pubkey: USER_PUBKEY,
      profiles: {
        [USER_PUBKEY]: summary({
          displayName: "Ada",
          nip05Handle: "ada@x",
          verifiedDntlsName: "alice.example",
        }),
      },
    }),
    "alice.example",
  );
});

test("resolveUserLabel: unverified users keep existing label behavior", () => {
  assert.equal(
    resolveUserLabel({
      pubkey: USER_PUBKEY,
      fallbackName: "Channel Nick",
      profiles: { [USER_PUBKEY]: summary() },
    }),
    "Ada",
  );
  assert.equal(
    resolveUserLabel({
      pubkey: USER_PUBKEY,
      fallbackName: "Channel Nick",
      profiles: { [USER_PUBKEY]: summary({ displayName: null }) },
    }),
    "ada@x",
  );
  assert.equal(
    resolveUserLabel({
      pubkey: USER_PUBKEY,
      fallbackName: "Channel Nick",
      profiles: {
        [USER_PUBKEY]: summary({ displayName: null, nip05Handle: null }),
      },
    }),
    "Channel Nick",
  );
});

test("resolveUserLabel: You still wins for the current user", () => {
  assert.equal(
    resolveUserLabel({
      pubkey: USER_PUBKEY,
      currentPubkey: USER_PUBKEY,
      profiles: {
        [USER_PUBKEY]: summary({ verifiedDntlsName: "alice.example" }),
      },
    }),
    "You",
  );
});

test("resolveUserLabel: verified current user shows DNTLS name when preferring resolved self", () => {
  assert.equal(
    resolveUserLabel({
      pubkey: USER_PUBKEY,
      currentPubkey: USER_PUBKEY,
      preferResolvedSelfLabel: true,
      profiles: {
        [USER_PUBKEY]: summary({
          displayName: "Ada",
          verifiedDntlsName: "alice.example",
        }),
      },
    }),
    "alice.example",
  );
});

test("mergeVerifiedDntlsNames overlays attested names without changing unverified rows", () => {
  const other =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
  const merged = mergeVerifiedDntlsNames(
    {
      [USER_PUBKEY]: summary({ displayName: "Ada" }),
      [other]: summary({ displayName: "Bea" }),
    },
    new Map([[USER_PUBKEY, { fqdn: "alice.example", approvedAt: 1700000000 }]]),
  );
  assert.equal(merged[USER_PUBKEY].verifiedDntlsName, "alice.example");
  assert.equal(merged[USER_PUBKEY].dntlsApprovedAt, 1700000000);
  assert.equal(merged[USER_PUBKEY].displayName, "Ada");
  assert.equal(merged[other].verifiedDntlsName, undefined);
  assert.equal(merged[other].displayName, "Bea");
});
