import assert from "node:assert/strict";
import test from "node:test";

import { mergeVerifiedDntlsNames } from "../../profile/lib/identity.ts";
import { truncatePubkey } from "../../../shared/lib/pubkey.ts";
import { resolveChannelDisplayLabel } from "./channelLabels.ts";

const self = "a".repeat(64);
const other = "b".repeat(64);
const dm = {
  channelType: "dm",
  name: "DM",
  participantPubkeys: [self, other],
  participants: [self, other],
};

test("DM labels use relay names without any published profiles", () => {
  const names = new Map([
    [self, { fqdn: "b.a.dntls", approvedAt: 1 }],
    [other, { fqdn: "cobra.dntls", approvedAt: 1 }],
  ]);
  const profiles = mergeVerifiedDntlsNames({}, names, [self, other]);
  assert.equal(resolveChannelDisplayLabel(dm, self, profiles), "cobra.dntls");
  assert.equal(resolveChannelDisplayLabel(dm, other, profiles), "b.a.dntls");
});

test("DM labels refresh attestations independently of stale nicknames", () => {
  const profiles = {
    [other]: {
      displayName: "a.dntls",
      avatarUrl: null,
      nip05Handle: null,
      ownerPubkey: null,
    },
  };
  const label = (names) =>
    resolveChannelDisplayLabel(
      dm,
      self,
      mergeVerifiedDntlsNames(profiles, names, [self, other]),
    );
  assert.equal(
    label(new Map([[other, { fqdn: "b.a.dntls", approvedAt: 2 }]])),
    "b.a.dntls",
  );
  assert.equal(label(new Map()), "a.dntls");
  assert.equal(profiles[other].verifiedDntlsName, undefined);
});

test("unnamed DM participants use truncated keys, not raw p-tag hex", () => {
  assert.equal(resolveChannelDisplayLabel(dm, self, {}), truncatePubkey(other));
  assert.equal(
    resolveChannelDisplayLabel({ ...dm, name: "Planning" }, self, {}),
    "Planning",
  );
});
